// Loads extracted config inventory into PostgreSQL (see db/schema.sql).
const fs = require('node:fs');
const path = require('node:path');
const { extract } = require('./extract');
const { getPool, closePool } = require('./db');

// Sidecar written next to each backup with device info from the REST API (serial etc).
const metaPath = (file) => file.replace(/\.conf$/, '.meta.json');
function readMeta(file) {
  try {
    return JSON.parse(fs.readFileSync(metaPath(file), 'utf8'));
  } catch {
    return {};
  }
}

// `idCol` is the column holding snapshotId (routes reference route_snapshots instead).
async function insertRows(client, table, snapshotId, rows, idCol = 'snapshot_id') {
  // Stay well below PostgreSQL's 65535 bind-parameter limit per statement.
  for (let i = 0; i < rows.length; i += 500) {
    await insertChunk(client, table, snapshotId, rows.slice(i, i + 500), idCol);
  }
}

async function insertChunk(client, table, snapshotId, rows, idCol) {
  if (!rows.length) return;
  const cols = Object.keys(rows[0]);
  const values = [];
  const tuples = rows.map((r) => {
    values.push(snapshotId, ...cols.map((c) => r[c]));
    const base = values.length - cols.length - 1;
    return `(${Array.from({ length: cols.length + 1 }, (_, i) => `$${base + i + 1}`).join(',')})`;
  });
  await client.query(
    `INSERT INTO ${table} (${idCol},${cols.join(',')}) VALUES ${tuples.join(',')}`,
    values
  );
}

const STATS_TABLES = ['object_refs', 'firewall_policies', 'addresses', 'addrgrps', 'services', 'service_groups'];

const analyze = (db = getPool()) => db.query(`ANALYZE ${STATS_TABLES.join(', ')}`);

// Finds the device by serial, falling back to hostname for backups without metadata.
async function upsertDevice(client, { serial, hostname, model }) {
  let { rows } = serial
    ? await client.query('SELECT id FROM devices WHERE serial = $1', [serial])
    : { rows: [] };
  if (!rows.length) {
    ({ rows } = await client.query(
      'SELECT id FROM devices WHERE hostname = $1 AND ($2::text IS NULL OR serial IS NULL) LIMIT 1',
      [hostname, serial]
    ));
  }
  if (rows.length) {
    await client.query(
      `UPDATE devices SET hostname = $2, model = COALESCE($3, model),
         serial = COALESCE(serial, $4), updated_at = now() WHERE id = $1`,
      [rows[0].id, hostname, model, serial]
    );
    return rows[0].id;
  }
  ({ rows } = await client.query(
    'INSERT INTO devices (serial, hostname, model) VALUES ($1, $2, $3) RETURNING id',
    [serial, hostname, model]
  ));
  return rows[0].id;
}

// Parses one backup file and stores it as a snapshot. Re-ingesting the same file replaces it.
// Bulk loads pass { analyze: false } and call analyze() once at the end.
async function ingestFile(file, { analyze: refreshStats = true } = {}) {
  const inv = extract(fs.readFileSync(file, 'utf8'));
  const meta = readMeta(file);
  const backupFile = path.basename(file);
  const d = inv.device;
  const hostname = d.hostname || meta.hostname || backupFile;

  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const deviceId = await upsertDevice(client, { serial: meta.serial || null, hostname, model: d.model });
    await client.query('DELETE FROM snapshots WHERE backup_file = $1', [backupFile]);
    const { rows } = await client.query(
      `INSERT INTO snapshots (device_id, backup_file, fw_version, fw_build, multi_vdom, conf_file_ver, taken_at, host)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
      [deviceId, backupFile, d.version, d.build, d.multiVdom, d.confFileVer,
       meta.takenAt || fs.statSync(file).mtime, meta.host || null]
    );
    const sid = rows[0].id;
    await insertRows(client, 'vdoms', sid, inv.vdoms.map((name) => ({ name })));
    await insertRows(client, 'interfaces', sid, inv.interfaces);
    await insertRows(client, 'ipsec_phase1', sid, inv.phase1);
    await insertRows(client, 'ipsec_phase2', sid, inv.phase2);
    await insertRows(client, 'vpn_ssl_settings', sid, inv.sslvpn);
    await insertRows(client, 'vips', sid, inv.vips);
    await insertRows(client, 'ippools', sid, inv.ippools);
    await insertRows(client, 'router_policies', sid, inv.routerPolicies);
    await insertRows(client, 'firewall_policies', sid, inv.policies);
    await insertRows(client, 'addresses', sid, inv.addresses);
    await insertRows(client, 'addrgrps', sid, inv.addrgrps);
    await insertRows(client, 'services', sid, inv.services);
    await insertRows(client, 'service_groups', sid, inv.servicegrps);
    await insertRows(client, 'object_refs', sid, inv.refs);
    await client.query('COMMIT');
    // Refresh planner statistics: with stale ones (e.g. right after a bulk load) the
    // "used by" joins can pick nested loops that take minutes instead of milliseconds.
    if (refreshStats) await analyze(client);
    return {
      snapshotId: sid, hostname, vdoms: inv.vdoms.length, interfaces: inv.interfaces.length,
      phase1: inv.phase1.length, phase2: inv.phase2.length, vips: inv.vips.length, ippools: inv.ippools.length,
      routerPolicies: inv.routerPolicies.length, policies: inv.policies.length,
      addresses: inv.addresses.length, addrgrps: inv.addrgrps.length,
      services: inv.services.length, servicegrps: inv.servicegrps.length, refs: inv.refs.length,
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ---------- read side (web UI) ----------
// `lite` sections are large: their rows come without `raw`, which xref() returns per object.
// `refs` (the object kind in object_refs) adds how many groups / policies reference each
// object directly (0 = unused).
const SECTIONS = {
  interfaces: { table: 'interfaces', order: 'vdom, name' },
  policies: { table: 'firewall_policies', order: 'vdom, seq', lite: true, key: 'policyid', refType: 'policy' },
  addresses: { table: 'addresses', order: 'vdom, name', lite: true, key: 'name', refs: 'address' },
  addrgrps: { table: 'addrgrps', order: 'vdom, name', lite: true, key: 'name', refs: 'addrgrp', refType: 'addrgrp' },
  services: { table: 'services', order: 'vdom, name', lite: true, key: 'name', refs: 'service' },
  servicegrps: { table: 'service_groups', order: 'vdom, name', lite: true, key: 'name', refs: 'servicegrp', refType: 'servicegrp' },
  routepolicies: { table: 'router_policies', order: 'vdom, seq_num', key: 'seq_num', refType: 'routepolicy' },
  phase1: { table: 'ipsec_phase1', order: 'vdom, name' },
  phase2: { table: 'ipsec_phase2', order: 'vdom, phase1name, name' },
  vips: { table: 'vips', order: 'vdom, name', key: 'name', refs: 'vip' },
  ippools: { table: 'ippools', order: 'vdom, name', key: 'name', refs: 'ippool' },
  sslvpn: { table: 'vpn_ssl_settings', order: 'vdom' },
};

// Routing tables are pulled live, not taken from the config. A config snapshot shows the
// newest route pull taken before the device's next config snapshot (for the latest
// snapshot: the newest pull). SQL expressions on snapshot `s`.
const PERIOD_END = `coalesce((SELECT min(n.taken_at) FROM snapshots n
  WHERE n.device_id = s.device_id AND n.taken_at > s.taken_at), 'infinity')`;
const ROUTE_SNAP = `(SELECT rs.id FROM route_snapshots rs WHERE rs.device_id = s.device_id
  AND rs.taken_at <= ${PERIOD_END} ORDER BY rs.taken_at DESC LIMIT 1)`;

async function routeRows(snapshotId) {
  const { rows } = await getPool().query(`
    SELECT r.vdom, r.ip_version, r.type, host(r.dst) || '/' || masklen(r.dst) AS dst, host(r.gateway) AS gateway,
           r.interface, r.distance, r.metric, r.priority, r.vrf, r.tunnel, r.tunnel_parent, r.installed_at,
           rs.taken_at AS pulled_at, r.raw
    FROM snapshots s JOIN route_snapshots rs ON rs.id = ${ROUTE_SNAP}
    JOIN routes r ON r.route_snapshot_id = rs.id
    WHERE s.id = $1
    ORDER BY r.vdom, r.ip_version, r.dst, r.distance, r.priority`, [snapshotId]);
  return rows;
}

async function listSnapshots() {
  const counts = Object.entries(SECTIONS)
    .map(([k, v]) => `(SELECT count(*) FROM ${v.table} t WHERE t.snapshot_id = s.id)::int AS ${k}`)
    .concat(`(SELECT count(*) FROM routes r WHERE r.route_snapshot_id = ${ROUTE_SNAP})::int AS routes`,
      `(SELECT json_build_object('id', rs.id, 'taken_at', rs.taken_at, 'errors', rs.errors)
        FROM route_snapshots rs WHERE rs.id = ${ROUTE_SNAP}) AS route_pull`)
    .join(',\n           ');
  const { rows } = await getPool().query(`
    SELECT s.id, s.backup_file, s.fw_version, s.fw_build, s.multi_vdom, s.taken_at,
           -- Snapshots ingested before the host column existed: take it from the file name
           -- ("<name>_<host>_<timestamp>.conf").
           coalesce(s.host, substring(s.backup_file from '_([^_]+)_\\d{4}-\\d\\d-\\d\\dT[\\d-]+\\.conf$')) AS host,
           d.id AS device_id, d.hostname, d.serial, d.model,
           (SELECT array_agg(name ORDER BY name) FROM vdoms v WHERE v.snapshot_id = s.id) AS vdoms,
           ${counts}
    FROM snapshots s JOIN devices d ON d.id = s.device_id
    ORDER BY d.hostname, s.taken_at DESC`);
  return rows;
}

async function snapshotRows(snapshotId, section) {
  if (section === 'routes') return routeRows(snapshotId);
  const sec = SECTIONS[section];
  if (!sec) throw new Error(`Unknown section: ${section}`);
  const refs = sec.refs ? ` || jsonb_build_object('refs', coalesce(r.n, 0))` : '';
  const join = sec.refs
    ? `LEFT JOIN (SELECT vdom, name, count(*)::int AS n FROM object_refs
         WHERE snapshot_id = $1 AND kind = '${sec.refs}' GROUP BY vdom, name) r USING (vdom, name)`
    : '';
  // to_jsonb keeps every column without having to list them, minus raw for lite sections.
  const { rows } = await getPool().query(
    `SELECT to_jsonb(t)${sec.lite ? " - 'raw'" : ''}${refs} AS row
     FROM ${sec.table} t ${join} WHERE t.snapshot_id = $1 ORDER BY ${sec.order.replace(/\b(\w+)/g, 't.$1')}`,
    [snapshotId]
  );
  return rows.map((r) => r.row);
}

// Correlation for one object (policy, policy route, address, service, group, VIP, IP pool):
//  - raw:     all of its settings
//  - members: the objects it references (addresses, services, ...), groups expanded
//             recursively, with their values
//  - usedBy:  every group / policy / policy route referencing it, directly or through
//             (nested) groups; `via` lists the groups in between, nearest first
async function xref(snapshotId, section, vdom, name) {
  const sec = SECTIONS[section];
  if (!sec?.key) throw new Error(`No cross-references for section: ${section}`);
  const db = getPool();
  const args = [snapshotId, vdom, String(name)];
  const { rows: [obj] } = await db.query(
    `SELECT raw FROM ${sec.table} WHERE snapshot_id = $1 AND vdom = $2 AND ${sec.key}::text = $3`, args);
  if (!obj) throw new Error('Object not found');

  const members = !sec.refType ? [] : (await db.query(`
    WITH RECURSIVE down AS (
      SELECT r.field, r.name, r.kind, 0 AS depth, ARRAY[r.name] AS path
      FROM object_refs r
      WHERE r.snapshot_id = $1 AND r.vdom = $2 AND r.ref_type = $4 AND r.ref_id = $3
      UNION ALL
      SELECT d.field, r.name, r.kind, d.depth + 1, d.path || r.name
      FROM down d JOIN object_refs r
        ON r.snapshot_id = $1 AND r.vdom = $2 AND r.ref_type = d.kind AND r.ref_id = d.name
      WHERE d.kind IN ('addrgrp', 'vipgrp', 'servicegrp') AND r.name <> ALL (d.path) AND d.depth < 16
    )
    SELECT d.field, d.name, d.kind, d.depth,
           a.type, host(a.subnet) || '/' || masklen(a.subnet) AS subnet, host(a.start_ip) AS start_ip,
           host(a.end_ip) AS end_ip, a.fqdn, a.country,
           v.extip, v.mappedip, host(p.startip) AS pool_start, host(p.endip) AS pool_end,
           s.protocol, s.tcp_portrange, s.udp_portrange, s.sctp_portrange, s.protocol_number,
           s.icmptype, s.icmpcode, coalesce(a.comment, s.comment) AS comment
    FROM down d
    LEFT JOIN addresses a ON d.kind = 'address' AND a.snapshot_id = $1 AND a.vdom = $2 AND a.name = d.name
    LEFT JOIN vips v ON d.kind = 'vip' AND v.snapshot_id = $1 AND v.vdom = $2 AND v.name = d.name
    LEFT JOIN ippools p ON d.kind = 'ippool' AND p.snapshot_id = $1 AND p.vdom = $2 AND p.name = d.name
    LEFT JOIN services s ON d.kind = 'service' AND s.snapshot_id = $1 AND s.vdom = $2 AND s.name = d.name
    ORDER BY d.field, d.path`, [...args, sec.refType])).rows;

  const usedBy = !sec.refs ? [] : (await db.query(`
    WITH RECURSIVE up AS (
      SELECT $3::text AS name, $4::text AS kind, ARRAY[]::text[] AS via
      UNION
      SELECT r.ref_id, r.ref_type, up.via || r.ref_id
      FROM up JOIN object_refs r ON r.snapshot_id = $1 AND r.vdom = $2 AND r.name = up.name AND r.kind = up.kind
      WHERE r.ref_type IN ('addrgrp', 'vipgrp', 'servicegrp') AND r.ref_id <> ALL (up.via) AND cardinality(up.via) < 16
    )
    SELECT r.ref_type, r.ref_id, r.field, up.via,
           p.name AS policy_name, p.uuid, p.action, p.status, p.srcintf, p.dstintf, rp.comments
    FROM up JOIN object_refs r ON r.snapshot_id = $1 AND r.vdom = $2 AND r.name = up.name AND r.kind = up.kind
    LEFT JOIN firewall_policies p ON r.ref_type = 'policy' AND p.snapshot_id = $1 AND p.vdom = $2
      AND p.policyid::text = r.ref_id
    LEFT JOIN router_policies rp ON r.ref_type = 'routepolicy' AND rp.snapshot_id = $1 AND rp.vdom = $2
      AND rp.seq_num::text = r.ref_id
    ORDER BY r.ref_type, p.seq, rp.seq_num, r.ref_id, cardinality(up.via)`, [...args, sec.refs])).rows;

  return { raw: obj.raw, members, usedBy };
}

module.exports = { PERIOD_END, insertRows, upsertDevice, ingestFile, analyze, metaPath, closePool, listSnapshots, snapshotRows, xref };
