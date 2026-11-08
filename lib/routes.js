// Active routing tables: pulled live from the device over the REST monitor API, stored in
// PostgreSQL (route_snapshots / routes, see db/schema.sql) and queried from there.
const net = require('node:net');
const { testConnection, getRoutes } = require('./fortigate');
const push = require('./push');
const { getPool } = require('./db');
const { insertRows, upsertDevice, PERIOD_END } = require('./inventory');
const { parseQuery } = require('./iplookup');

const MAX_ROWS = 5000;
const KEEP_DAYS = Math.max(1, Number(process.env.ROUTES_KEEP_DAYS) || 30);

// "10.0.0.0/24" -> "10.0.0.0/24"; null when it is not a valid prefix.
function prefix(v) {
  const [addr, len] = String(v || '').split('/');
  const max = net.isIPv4(addr) ? 32 : net.isIPv6(addr) ? 128 : 0;
  if (!max) return null;
  if (len === undefined) return `${addr}/${max}`;
  return /^\d+$/.test(len) && Number(len) <= max ? `${addr}/${len}` : null;
}

// Connected routes have no next hop: FortiOS reports 0.0.0.0 / ::.
const gateway = (v) => (net.isIP(v || '') && !/^(0\.0\.0\.0|::)$/.test(v) ? v : null);
const int = (v) => (v === undefined || v === null || v === '' || isNaN(Number(v)) ? null : Math.trunc(Number(v)));
// install_date is epoch seconds on the versions that report it.
const epoch = (v) => (Number(v) > 1e9 ? new Date(Number(v) * 1000) : null);

function toRow(vdom, ipVersion, r) {
  const dst = prefix(r.ip_mask);
  if (!dst) return null;
  return {
    vdom,
    ip_version: ipVersion,
    type: r.type || null,
    dst,
    gateway: gateway(r.gateway),
    interface: r.interface || null,
    distance: int(r.distance),
    metric: int(r.metric),
    priority: int(r.priority),
    vrf: int(r.vrf),
    tunnel: !!r.is_tunnel_route,
    tunnel_parent: r.tunnel_parent || null,
    installed_at: epoch(r.install_date),
    raw: r,
  };
}

// Reads the IPv4 and IPv6 routing table of every VDOM and stores them as one route snapshot.
// A VDOM / IP version that fails is recorded in `errors`; if every read fails, nothing is saved.
// `status` (from testConnection) can be passed when the caller already has it.
async function pull(fw, status) {
  status ||= await testConnection(fw);
  let vdoms;
  try {
    vdoms = await push.vdoms(fw);
  } catch {
    vdoms = ['root'];  // no access to the VDOM list: single-VDOM device, or a VDOM-scoped admin
  }

  const rows = [];
  const errors = [];
  let skipped = 0;
  for (const vdom of vdoms) {
    for (const ipVersion of [4, 6]) {
      try {
        for (const r of await getRoutes(fw, vdom, ipVersion)) {
          const row = toRow(vdom, ipVersion, r);
          if (row) rows.push(row);
          else skipped++;
        }
      } catch (err) {
        errors.push({ vdom, ipVersion, error: err.message });
      }
    }
  }
  if (errors.length === vdoms.length * 2) throw new Error(`Could not read the routing table: ${errors[0].error}`);

  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const deviceId = await upsertDevice(client, {
      serial: status.serial || null, hostname: status.hostname || fw.name, model: status.model || null,
    });
    const { rows: [snap] } = await client.query(
      `INSERT INTO route_snapshots (device_id, firewall_id, host, fw_version, fw_build, vdoms, errors)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, taken_at`,
      [deviceId, fw.id, fw.host, status.version || null, int(status.build), vdoms, JSON.stringify(errors)]
    );
    await insertRows(client, 'routes', snap.id, rows, 'route_snapshot_id');
    // Hourly pulls add up: keep KEEP_DAYS of history, plus the pull that each config
    // snapshot of the device shows in the inventory.
    await client.query(`
      DELETE FROM route_snapshots rs WHERE rs.device_id = $1 AND rs.taken_at < now() - make_interval(days => $2)
        AND NOT EXISTS (SELECT 1 FROM snapshots s WHERE s.device_id = rs.device_id AND rs.id = (
          SELECT r2.id FROM route_snapshots r2 WHERE r2.device_id = s.device_id AND r2.taken_at <= ${PERIOD_END}
          ORDER BY r2.taken_at DESC LIMIT 1))`, [deviceId, KEEP_DAYS]);
    await client.query('COMMIT');
    const perVdom = {};
    for (const r of rows) perVdom[r.vdom] = (perVdom[r.vdom] || 0) + 1;
    return {
      routeSnapshotId: snap.id, takenAt: snap.taken_at, hostname: status.hostname || fw.name,
      routes: rows.length, perVdom, skipped, errors,
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ---------- read side ----------
const COLS = `r.vdom, r.ip_version, r.type, host(r.dst) || '/' || masklen(r.dst) AS dst, host(r.gateway) AS gateway,
  r.interface, r.distance, r.metric, r.priority, r.vrf, r.tunnel, r.tunnel_parent, r.installed_at`;

async function listSnapshots() {
  const { rows } = await getPool().query(`
    SELECT rs.id, rs.taken_at, rs.host, rs.fw_version, rs.fw_build, rs.vdoms, rs.errors, rs.firewall_id,
           d.id AS device_id, d.hostname, d.model, d.serial,
           (SELECT count(*) FROM routes r WHERE r.route_snapshot_id = rs.id)::int AS routes,
           rs.id IN (SELECT id FROM latest_route_snapshots) AS latest
    FROM route_snapshots rs JOIN devices d ON d.id = rs.device_id
    ORDER BY d.hostname, rs.taken_at DESC
    LIMIT 1000`);
  return rows;
}

// Routes of one snapshot. `q` is an IP / prefix (routes containing it or inside it) or
// text matched against interface, gateway, type and tunnel parent.
async function snapshotRoutes(id, { vdom, type, q, limit } = {}) {
  const db = getPool();
  const { rows: [snap] } = await db.query(`
    SELECT rs.id, rs.taken_at, rs.host, rs.fw_version, rs.vdoms, rs.errors, d.hostname, d.model
    FROM route_snapshots rs JOIN devices d ON d.id = rs.device_id WHERE rs.id = $1`, [id]);
  if (!snap) throw new Error('Route snapshot not found');

  const where = ['r.route_snapshot_id = $1'];
  const args = [id];
  // Every `?` in sql is the same parameter.
  const add = (sql, v) => { args.push(v); where.push(sql.replaceAll('?', `$${args.length}`)); };
  if (vdom) add('r.vdom = ?', vdom);
  if (type) add('r.type = ?', type);
  q = String(q || '').trim();
  if (q) {
    let cidr = null;
    try { cidr = parseQuery(q); } catch {}
    if (cidr) add('(r.dst >>= ?::inet OR r.dst << ?::inet)', cidr);
    else add('(r.interface ILIKE ? OR host(r.gateway) LIKE ? OR r.type ILIKE ? OR r.tunnel_parent ILIKE ?)',
      `%${q.replace(/[\\%_]/g, '\\$&')}%`);
  }
  const max = Math.min(Number(limit) || MAX_ROWS, 50000);
  const { rows } = await db.query(`
    SELECT ${COLS} FROM routes r WHERE ${where.join(' AND ')}
    ORDER BY r.vdom, r.ip_version, r.dst, r.distance, r.priority
    LIMIT ${max + 1}`, args);
  const { rows: types } = await db.query(
    'SELECT type, count(*)::int AS n FROM routes WHERE route_snapshot_id = $1 GROUP BY type ORDER BY n DESC', [id]);
  return { snapshot: snap, types, truncated: rows.length > max, routes: rows.slice(0, max) };
}

// Which route each firewall / VDOM uses for an IP or network, from the stored tables.
//  best:     longest prefix containing it, lowest distance / priority (several rows = ECMP)
//  covering: every route containing it
//  inside:   routes more specific than the queried network
async function lookup(query, { mode = 'best', all = false } = {}) {
  const cidr = parseQuery(query);
  const family = net.isIPv6(cidr.split('/')[0]) ? 6 : 4;
  if (!['best', 'covering', 'inside'].includes(mode)) throw new Error('Invalid mode');
  const db = getPool();
  const snaps = all ? 'route_snapshots' : 'latest_route_snapshots';
  const cond = mode === 'inside' ? 'r.dst << $1::inet' : 'r.dst >>= $1::inet';
  const { rows } = await db.query(`
    WITH m AS (
      SELECT r.route_snapshot_id, ${COLS}, masklen(r.dst) AS len,
             rank() OVER (PARTITION BY r.route_snapshot_id, r.vdom, coalesce(r.vrf, 0)
                          ORDER BY masklen(r.dst) DESC, r.distance NULLS LAST, r.priority NULLS LAST) AS rk
      FROM routes r JOIN ${snaps} s ON s.id = r.route_snapshot_id
      WHERE ${cond} AND family(r.dst) = family($1::inet)
    )
    SELECT * FROM m ${mode === 'best' ? 'WHERE rk = 1' : ''}
    ORDER BY route_snapshot_id, vdom, len DESC, distance, priority
    LIMIT ${MAX_ROWS + 1}`, [cidr]);

  const { rows: meta } = await db.query(`
    SELECT s.id, s.taken_at, s.host, s.vdoms, s.errors, d.hostname, d.model
    FROM ${snaps} s JOIN devices d ON d.id = s.device_id
    ORDER BY d.hostname, s.taken_at DESC`);

  const devices = meta.map((s) => {
    const routes = rows.filter((r) => r.route_snapshot_id === s.id)
      .map(({ route_snapshot_id, rk, len, ...r }) => ({ ...r, best: Number(rk) === 1 && mode !== 'inside' }));
    const withRoute = new Set(routes.filter((r) => !r.vrf).map((r) => r.vdom));
    // A VDOM whose table for this IP version could not be read is unknown, not routeless.
    const unread = new Set(s.errors.filter((e) => e.ipVersion === family).map((e) => e.vdom));
    return {
      routeSnapshotId: s.id, hostname: s.hostname, model: s.model, host: s.host, takenAt: s.taken_at,
      errors: s.errors, routes,
      // VDOMs with no route at all in the default VRF: traffic to the query is dropped there.
      noRoute: mode === 'inside' ? [] : s.vdoms.filter((v) => !withRoute.has(v) && !unread.has(v)),
      unread: [...unread],
    };
  });
  return {
    query: cidr, mode, scope: all ? 'all' : 'latest', truncated: rows.length > MAX_ROWS,
    totals: { devices: devices.length, routes: Math.min(rows.length, MAX_ROWS) },
    devices,
  };
}

const deleteSnapshot = (id) => getPool().query('DELETE FROM route_snapshots WHERE id = $1', [id]);

// Firewall id (web UI entry) -> time of its newest pull, for the scheduler.
async function lastPulls() {
  const { rows } = await getPool().query(
    'SELECT firewall_id, max(taken_at) AS at FROM route_snapshots WHERE firewall_id IS NOT NULL GROUP BY firewall_id');
  return new Map(rows.map((r) => [r.firewall_id, new Date(r.at).getTime()]));
}

module.exports = { pull, listSnapshots, snapshotRoutes, lookup, deleteSnapshot, lastPulls, toRow };
