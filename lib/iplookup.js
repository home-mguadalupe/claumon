// IP / network lookup: address objects matching an IP or subnet and the firewall
// policies using them, directly or through nested address groups.
const net = require('node:net');
const { getPool } = require('./db');

const MAX_OBJECTS = 2000;

// "10.1.2.3", "10.1.2.0/24", "10.1.2.0 255.255.255.0" -> "10.1.2.0/24" (CIDR text for inet).
function parseQuery(q) {
  q = String(q || '').trim();
  let [ip, mask] = q.split(/\s*\/\s*|\s+/);
  if (!net.isIPv4(ip) && !net.isIPv6(ip)) throw new Error('Enter an IP or network, e.g. 10.1.2.3 or 10.1.2.0/24');
  if (mask === undefined) return ip;
  if (net.isIPv4(mask)) {
    const bits = mask.split('.').reduce((a, o) => a * 256 + Number(o), 0).toString(2).padStart(32, '0');
    if (!/^1*0*$/.test(bits)) throw new Error('Invalid netmask');
    mask = bits.indexOf('0') === -1 ? 32 : bits.indexOf('0');
  }
  const max = net.isIPv4(ip) ? 32 : 128;
  if (!/^\d+$/.test(String(mask)) || Number(mask) > max) throw new Error('Invalid prefix length');
  return `${ip}/${mask}`;
}

// exact: same network; inside: object lies within the query; broader: object contains the query.
const relation = (lo, hi, q) => `CASE WHEN ${lo} = network(${q}) AND ${hi} = broadcast(${q}) THEN 'exact'
  WHEN ${lo} >= network(${q}) AND ${hi} <= broadcast(${q}) THEN 'inside' ELSE 'broader' END`;

async function lookup(query, { all = false, includeAny = false, broader = false } = {}) {
  const cidr = parseQuery(query);
  const db = getPool();
  const snaps = all ? 'snapshots' : 'latest_snapshots';
  // Overlap: the object contains the query, or lies inside the queried network.
  const anyFilter = includeAny ? '' : 'AND masklen(a.subnet) > 0';
  const params = [cidr];
  const q = '$1::inet';

  const addr = await db.query(`
      SELECT a.snapshot_id, a.vdom, a.name, 'address' AS kind, a.type,
        CASE WHEN a.type = 'iprange' THEN host(a.start_ip) || '-' || host(a.end_ip)
             ELSE host(a.subnet) || '/' || masklen(a.subnet) END AS value,
        a.interface, a.comment,
        ${relation('coalesce(a.start_ip, network(a.subnet))', 'coalesce(a.end_ip, broadcast(a.subnet))', q)} AS match
      FROM addresses a JOIN ${snaps} s ON s.id = a.snapshot_id
      WHERE ((a.subnet IS NOT NULL AND ${broader ? `a.subnet && ${q} ${anyFilter}` : `a.subnet <<= ${q}`})
         OR (a.start_ip IS NOT NULL AND ${broader ? `a.start_ip <= broadcast(${q}) AND a.end_ip >= network(${q})`
           : `a.start_ip >= network(${q}) AND a.end_ip <= broadcast(${q})`}))
      LIMIT ${MAX_OBJECTS}`, params);

  const objects = addr.rows;

  // Walk up through (nested) groups to every policy / policy route using the objects.
  let usedBy = [];
  if (objects.length) {
    const seed = {
      sid: objects.map((o) => o.snapshot_id), vdom: objects.map((o) => o.vdom),
      name: objects.map((o) => o.name), kind: objects.map((o) => o.kind),
    };
    usedBy = (await db.query(`
      WITH RECURSIVE up AS (
        SELECT sid, vdom, name, kind, name AS origin, ARRAY[]::text[] AS via
        FROM unnest($1::int[], $2::text[], $3::text[], $4::text[]) AS t(sid, vdom, name, kind)
        UNION
        SELECT up.sid, up.vdom, r.ref_id, r.ref_type, up.origin, up.via || r.ref_id
        FROM up JOIN object_refs r ON r.snapshot_id = up.sid AND r.vdom = up.vdom AND r.name = up.name AND r.kind = up.kind
        WHERE r.ref_type = 'addrgrp' AND r.ref_id <> ALL (up.via) AND cardinality(up.via) < 16
      )
      SELECT up.sid AS snapshot_id, up.vdom, up.origin, up.via, r.ref_type, r.ref_id, r.field,
        p.seq, p.name AS policy_name, p.action, p.status, p.srcintf, p.dstintf, p.srcaddr, p.dstaddr,
        p.service, p.nat, p.comments
      FROM up JOIN object_refs r ON r.snapshot_id = up.sid AND r.vdom = up.vdom AND r.name = up.name AND r.kind = up.kind
      LEFT JOIN firewall_policies p ON r.ref_type = 'policy' AND p.snapshot_id = up.sid AND p.vdom = up.vdom AND p.policyid::text = r.ref_id
      WHERE r.ref_type = 'policy'
      ORDER BY up.sid, up.vdom, r.ref_type, p.seq, r.ref_id`,
      [seed.sid, seed.vdom, seed.name, seed.kind])).rows;
  }

  // Group everything per snapshot (device).
  const snapIds = new Set([...objects, ...usedBy].map((r) => r.snapshot_id));
  const { rows: meta } = snapIds.size ? await db.query(`
    SELECT s.id, s.backup_file, s.taken_at, d.hostname, d.model FROM snapshots s JOIN devices d ON d.id = s.device_id
    WHERE s.id = ANY($1) ORDER BY d.hostname, s.taken_at DESC`, [[...snapIds]]) : { rows: [] };

  const pick = (rows, id) => rows.filter((r) => r.snapshot_id === id).map(({ snapshot_id, ...r }) => r);
  const devices = meta.map((m) => {
    // One row per policy: merge the objects / fields through which it matches.
    const pols = new Map();
    for (const u of pick(usedBy, m.id)) {
      const k = `${u.vdom}|${u.ref_type}|${u.ref_id}`;
      if (!pols.has(k)) {
        const { origin, via, field, ...rest } = u;
        pols.set(k, { ...rest, matches: [] });
      }
      const pm = pols.get(k).matches;
      if (!pm.some((x) => x.origin === u.origin && x.field === u.field && x.via.join() === u.via.join())) {
        pm.push({ origin: u.origin, field: u.field, via: u.via.slice(0, -1) });
      }
    }
    return {
      snapshotId: m.id, hostname: m.hostname, model: m.model, backupFile: m.backup_file, takenAt: m.taken_at,
      objects: pick(objects, m.id), policies: [...pols.values()],
    };
  });

  return {
    query: cidr, broader, scope: all ? 'all' : 'latest', truncated: addr.rows.length >= MAX_OBJECTS,
    totals: {
      devices: devices.length, objects: objects.length,
      policies: devices.reduce((n, d) => n + d.policies.length, 0),
    },
    devices,
  };
}

module.exports = { lookup, parseQuery };
