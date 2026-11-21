// Threat feed contents and download status, pulled live from the devices and stored in
// PostgreSQL (feed_pulls / feed_status / feed_entries, see db/schema.sql), so IP lookup can
// tell which feeds hold an address and the Threat feeds tab can show how long one has failed.
//
// The feeds to ask about come from the device's newest backup. Every pull keeps the status
// of each feed for FEEDS_KEEP_DAYS; only the newest pull of a device keeps the entries.
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const { testConnection } = require('./fortigate');
const push = require('./push');
const threatfeeds = require('./threatfeeds');
const { getPool } = require('./db');
const { insertRows, upsertDevice } = require('./inventory');

const BACKUP_DIR = path.join(__dirname, '..', 'backups');
const KEEP_DAYS = Math.max(1, Number(process.env.FEEDS_KEEP_DAYS) || 30);
// FortiOS 7.4 accepts up to 300000 entries per feed; anything past this is not stored.
const MAX_ENTRIES = 300000;

const safeName = (s) => s.replace(/[^a-zA-Z0-9._-]/g, '_');

// Newest backup file of a firewall (files are named "<name>_<host>_<time>.conf").
function newestBackup(fw) {
  let best = null;
  for (const f of fs.readdirSync(BACKUP_DIR)) {
    if (!f.endsWith('.conf') || !f.includes(`_${safeName(fw.host)}_`)) continue;
    const mtime = fs.statSync(path.join(BACKUP_DIR, f)).mtimeMs;
    if (!best || mtime > best.mtime) best = { file: f, mtime };
  }
  return best && best.file;
}

// "10.0.0.1", "10.0.0.0/24", "10.0.0.1-10.0.0.9" (IPv4 or IPv6) -> inet columns.
function ipColumns(entry) {
  const s = entry.trim();
  const range = s.split('-').map((x) => x.trim());
  if (range.length === 2 && net.isIP(range[0]) && net.isIP(range[0]) === net.isIP(range[1])) {
    return { subnet: null, start_ip: range[0], end_ip: range[1] };
  }
  const [addr, len] = s.split('/');
  const max = net.isIPv4(addr) ? 32 : net.isIPv6(addr) ? 128 : 0;
  if (max && (len === undefined || (/^\d+$/.test(len) && Number(len) <= max))) {
    return { subnet: `${addr}/${len ?? max}`, start_ip: null, end_ip: null };
  }
  return { subnet: null, start_ip: null, end_ip: null };
}

// Pulls the status and entries of every feed in the firewall's newest backup and stores
// them. Returns what the Threat feeds tab shows (status + samples), or null without a backup.
async function pull(fw) {
  const file = newestBackup(fw);
  if (!file) return null;
  const analysis = threatfeeds.forBackup(path.join(BACKUP_DIR, file));
  const status = await testConnection(fw);
  let vdoms = ['root'];
  if (analysis.device.multiVdom) {
    try {
      vdoms = await push.vdoms(fw);
    } catch {}  // a VDOM-scoped admin: global feeds are then read through root
  }
  const live = await threatfeeds.live(fw, analysis, vdoms, { full: true });
  const scope = (f) => f.scope || 'root';

  const statusRows = live.feeds.map((f) => ({
    vdom: scope(f), name: f.name, type: f.type || null, ok: !f.failed && f.ok,
    error: f.failed || f.error, error_code: f.errorCode ?? null, file_status: f.fileStatus || null,
    last_attempt: f.lastAttempt || null, last_update: f.lastUpdate || null,
    entries: f.failed ? null : f.entries, invalid: f.failed ? null : f.invalid, overflow: !!f.overflow,
  }));
  const entryRows = live.feeds.flatMap((f) => (f.list || []).slice(0, MAX_ENTRIES).map((e) => ({
    vdom: scope(f), name: f.name, entry: e.entry, valid: e.valid,
    ...(f.type === 'address' ? ipColumns(e.entry) : { subnet: null, start_ip: null, end_ip: null }),
  })));

  const client = await getPool().connect();
  let pullId;
  try {
    await client.query('BEGIN');
    const deviceId = await upsertDevice(client, {
      serial: status.serial || null, hostname: status.hostname || fw.name, model: status.model || null,
    });
    const { rows: [p] } = await client.query(
      `INSERT INTO feed_pulls (device_id, firewall_id, host, backup_file) VALUES ($1, $2, $3, $4) RETURNING id, taken_at`,
      [deviceId, fw.id, fw.host, file]);
    pullId = p.id;
    await insertRows(client, 'feed_status', p.id, statusRows, 'pull_id');
    await insertRows(client, 'feed_entries', p.id, entryRows, 'pull_id');
    // Entries are only kept for the newest pull; statuses for KEEP_DAYS.
    await client.query('DELETE FROM feed_entries e USING feed_pulls fp WHERE e.pull_id = fp.id AND fp.device_id = $1 AND fp.id <> $2', [deviceId, p.id]);
    await client.query('DELETE FROM feed_pulls WHERE device_id = $1 AND taken_at < now() - make_interval(days => $2)', [deviceId, KEEP_DAYS]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
  const since = await failingSince([pullId]);
  return {
    file, checkedAt: live.checkedAt, stored: true,
    feeds: live.feeds.map(({ list, ...f }) => ({ ...f, failingSince: since.get(`${pullId}|${scope(f)}|${f.name}`) || null })),
  };
}

// For each failing feed of these pulls: the first pull of the current run of failures.
async function failingSince(pullIds) {
  const { rows } = await getPool().query(`
    SELECT s.pull_id, s.vdom, s.name,
           (SELECT min(p2.taken_at) FROM feed_pulls p2 JOIN feed_status s2 ON s2.pull_id = p2.id AND s2.vdom = s.vdom AND s2.name = s.name
            WHERE p2.device_id = p.device_id AND p2.taken_at <= p.taken_at
              AND p2.taken_at > coalesce((SELECT max(p3.taken_at) FROM feed_pulls p3 JOIN feed_status s3 ON s3.pull_id = p3.id
                AND s3.vdom = s.vdom AND s3.name = s.name WHERE p3.device_id = p.device_id AND s3.ok), '-infinity')) AS since
    FROM feed_status s JOIN feed_pulls p ON p.id = s.pull_id
    WHERE s.pull_id = ANY($1) AND NOT s.ok`, [pullIds]);
  return new Map(rows.map((r) => [`${r.pull_id}|${r.vdom}|${r.name}`, r.since]));
}

// Newest stored pull of each of these firewalls, in the same shape as pull() returns.
async function latest(firewallIds) {
  if (!firewallIds.length) return new Map();
  const db = getPool();
  const { rows: pulls } = await db.query(`
    SELECT DISTINCT ON (firewall_id) id, firewall_id, backup_file, taken_at FROM feed_pulls
    WHERE firewall_id = ANY($1) ORDER BY firewall_id, taken_at DESC`, [firewallIds]);
  if (!pulls.length) return new Map();
  const ids = pulls.map((p) => p.id);
  const [{ rows: status }, { rows: samples }, since] = await Promise.all([
    db.query('SELECT * FROM feed_status WHERE pull_id = ANY($1)', [ids]),
    db.query(`SELECT pull_id, vdom, name, valid, entry FROM (
      SELECT e.*, row_number() OVER (PARTITION BY pull_id, vdom, name, valid ORDER BY entry) AS n
      FROM feed_entries e WHERE pull_id = ANY($1)) x WHERE n <= 20`, [ids]),
    failingSince(ids),
  ]);
  return new Map(pulls.map((p) => [p.firewall_id, {
    file: p.backup_file, checkedAt: p.taken_at, stored: true,
    feeds: status.filter((s) => s.pull_id === p.id).map((s) => {
      const mine = samples.filter((x) => x.pull_id === p.id && x.vdom === s.vdom && x.name === s.name);
      // Statuses that could not be asked have no entry counts.
      const asked = s.entries != null;
      return {
        scope: s.vdom, name: s.name, type: s.type,
        ...(asked ? {
          ok: s.ok, error: s.error, errorCode: s.error_code, fileStatus: s.file_status, lastAttempt: s.last_attempt,
          lastUpdate: s.last_update, entries: s.entries, invalid: s.invalid, overflow: s.overflow,
          sample: mine.filter((x) => x.valid).map((x) => x.entry), invalidSample: mine.filter((x) => !x.valid).map((x) => x.entry),
        } : { failed: s.error }),
        failingSince: since.get(`${p.id}|${s.vdom}|${s.name}`) || null,
      };
    }),
  }]));
}

// Firewall id (web UI entry) -> time of its newest pull, for the scheduler.
async function lastPulls() {
  const { rows } = await getPool().query(
    'SELECT firewall_id, max(taken_at) AS at FROM feed_pulls WHERE firewall_id IS NOT NULL GROUP BY firewall_id');
  return new Map(rows.map((r) => [r.firewall_id, new Date(r.at).getTime()]));
}

module.exports = { pull, latest, lastPulls, ipColumns };
