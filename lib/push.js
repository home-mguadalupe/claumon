// Creates / updates firewall objects over the FortiGate CMDB API: addresses, address
// groups, custom services, service groups and policies. Every push is appended to
// data/push-log.jsonl.
const fs = require('node:fs');
const path = require('node:path');
const { request } = require('./fortigate');

const LOG_FILE = path.join(__dirname, '..', 'data', 'push-log.jsonl');

// ---------- input helpers ----------
const str = (v) => String(v ?? '').trim();

function objName(v, what = 'Name') {
  const s = str(v);
  if (!s) throw new Error(`${what} is required`);
  if (s.length > 79) throw new Error(`${what} is longer than 79 characters`);
  if (/["\\]/.test(s)) throw new Error(`${what} must not contain " or \\`);
  return s;
}

// Lists arrive as arrays (UI) or comma / newline separated strings. Names may contain spaces.
function names(v, what, required = true) {
  const list = (Array.isArray(v) ? v : str(v).split(/[,\n]/)).map(str).filter(Boolean);
  if (required && !list.length) throw new Error(`${what}: at least one entry is required`);
  return [...new Set(list)].map((name) => ({ name: objName(name, what) }));
}

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

function ip(v, what) {
  const s = str(v);
  if (!IPV4.test(s)) throw new Error(`${what}: invalid IPv4 address "${s}"`);
  return s;
}

// "10.1.0.0/16", "10.1.0.0 255.255.0.0" or a bare host IP -> "10.1.0.0 255.255.0.0".
function subnet(v) {
  const [addr, mask = '32', extra] = str(v).split(/\s*\/\s*|\s+/);
  if (extra !== undefined) throw new Error(`Subnet: cannot parse "${str(v)}"`);
  ip(addr, 'Subnet');
  if (/^\d{1,2}$/.test(mask)) {
    const bits = Number(mask);
    if (bits > 32) throw new Error(`Subnet: invalid prefix length /${bits}`);
    const n = bits ? (~0 << (32 - bits)) >>> 0 : 0;
    return `${addr} ${[24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.')}`;
  }
  ip(mask, 'Subnet mask');
  return `${addr} ${mask}`;
}

// "443 8080-8090 1000:2000" (dst[-dst][:src[-src]]), space or comma separated.
function portRange(v, what) {
  const tokens = str(v).split(/[\s,]+/).filter(Boolean);
  for (const t of tokens) {
    const m = t.match(/^(\d+)(?:-(\d+))?(?::(\d+)(?:-(\d+))?)?$/);
    if (!m || m.slice(1).some((p) => p !== undefined && (+p < 0 || +p > 65535))) {
      throw new Error(`${what}: invalid port range "${t}"`);
    }
  }
  return tokens.join(' ');
}

const pick = (v, allowed, what) => {
  const s = str(v) || allowed[0];
  if (!allowed.includes(s)) throw new Error(`${what} must be one of: ${allowed.join(', ')}`);
  return s;
};
const onOff = (v) => (v === true || v === 'enable' ? 'enable' : 'disable');
const withComment = (body, key, v) => (str(v) ? { ...body, [key]: str(v).slice(0, 1023) } : body);

// ---------- object types ----------
// path: CMDB table. key: the field identifying an entry (policies are matched by name).
const TYPES = {
  address: {
    label: 'Address',
    path: 'firewall/address',
    build(d) {
      const type = pick(d.type, ['ipmask', 'iprange', 'fqdn'], 'Type');
      let body = { name: objName(d.name), type };
      if (type === 'ipmask') body.subnet = subnet(d.subnet);
      if (type === 'iprange') Object.assign(body, { 'start-ip': ip(d['start-ip'], 'Start IP'), 'end-ip': ip(d['end-ip'], 'End IP') });
      if (type === 'fqdn') {
        body.fqdn = str(d.fqdn);
        if (!/^[a-zA-Z0-9*]([a-zA-Z0-9.*-]*[a-zA-Z0-9])?$/.test(body.fqdn)) throw new Error('FQDN is invalid');
      }
      if (str(d['associated-interface'])) body['associated-interface'] = objName(d['associated-interface'], 'Interface');
      return withComment(body, 'comment', d.comment);
    },
  },
  addrgrp: {
    label: 'Address group',
    path: 'firewall/addrgrp',
    build: (d) => withComment({ name: objName(d.name), member: names(d.member, 'Members') }, 'comment', d.comment),
  },
  service: {
    label: 'Service',
    path: 'firewall.service/custom',
    build(d) {
      const protocol = pick(d.protocol, ['TCP/UDP/SCTP', 'ICMP', 'IP'], 'Protocol');
      let body = { name: objName(d.name), protocol };
      if (protocol === 'TCP/UDP/SCTP') {
        for (const p of ['tcp', 'udp', 'sctp']) {
          const r = portRange(d[`${p}-portrange`], `${p.toUpperCase()} ports`);
          if (r) body[`${p}-portrange`] = r;
        }
        if (!body['tcp-portrange'] && !body['udp-portrange'] && !body['sctp-portrange']) {
          throw new Error('Enter at least one TCP, UDP or SCTP port range');
        }
      }
      if (protocol === 'ICMP' && str(d.icmptype) !== '') {
        const t = Number(d.icmptype);
        if (!Number.isInteger(t) || t < 0 || t > 255) throw new Error('ICMP type must be 0-255');
        body.icmptype = t;
      }
      if (protocol === 'IP') {
        const n = Number(d['protocol-number']);
        if (!Number.isInteger(n) || n < 0 || n > 254) throw new Error('Protocol number must be 0-254');
        body['protocol-number'] = n;
      }
      if (str(d.category)) body.category = objName(d.category, 'Category');
      return withComment(body, 'comment', d.comment);
    },
  },
  servicegrp: {
    label: 'Service group',
    path: 'firewall.service/group',
    build: (d) => withComment({ name: objName(d.name), member: names(d.member, 'Members') }, 'comment', d.comment),
  },
  policy: {
    label: 'Policy',
    path: 'firewall/policy',
    build(d) {
      const action = pick(d.action, ['accept', 'deny'], 'Action');
      let body = {
        ...(str(d.name) && { name: objName(d.name) }),
        srcintf: names(d.srcintf, 'Incoming interface'),
        dstintf: names(d.dstintf, 'Outgoing interface'),
        srcaddr: names(d.srcaddr, 'Source'),
        dstaddr: names(d.dstaddr, 'Destination'),
        service: names(d.service, 'Service'),
        action,
        schedule: str(d.schedule) || 'always',
        logtraffic: pick(d.logtraffic, ['all', 'utm', 'disable'], 'Log traffic'),
        status: onOff(d.status),
      };
      if (action === 'accept') body.nat = onOff(d.nat);
      return withComment(body, 'comments', d.comments);
    },
  },
};

// Optional policy placement: move the new policy above this policy ID.
function placement(type, d) {
  if (type !== 'policy' || !str(d.before)) return null;
  const id = Number(d.before);
  if (!Number.isInteger(id) || id < 1) throw new Error('"Place before policy ID" must be a policy ID');
  return id;
}

function buildPayload(type, data) {
  const t = TYPES[type];
  if (!t) throw new Error(`Unknown object type "${type}"`);
  return { path: t.path, body: t.build(data || {}), before: placement(type, data || {}) };
}

function vdomName(v) {
  const s = str(v) || 'root';
  if (!/^[\w.-]{1,31}$/.test(s)) throw new Error('Invalid VDOM name');
  return s;
}

// ---------- FortiGate CMDB calls ----------
const ERRORS = {
  '-3': 'entry not found',
  '-5': 'an entry with this name already exists',
  '-651': 'invalid value (check object names, interfaces and ranges)',
};

async function cmdb(fw, method, p, vdom, { query = '', body } = {}) {
  const res = await request(fw, method, `/api/v2/cmdb/${p}?vdom=${encodeURIComponent(vdom)}${query}`, body);
  let json = {};
  try {
    json = JSON.parse(res.body.toString('utf8'));
  } catch {}
  return { status: res.status, json };
}

function cmdbError(r) {
  if (r.status === 401) return new Error('HTTP 401: Unauthorized - check the API key and trusted hosts');
  if (r.status === 403) return new Error('HTTP 403: Forbidden - the API admin profile needs read-write access to Firewall configuration (and to this VDOM)');
  const j = r.json || {};
  const detail = j.cli_error || ERRORS[j.error] || (j.error != null ? `FortiOS error ${j.error}` : '');
  return new Error(`HTTP ${r.status}${detail ? `: ${String(detail).trim()}` : ''}`);
}

// Returns the key (name / policy ID) of the existing entry, or null.
async function findExisting(fw, type, vdom, body) {
  const { path: p } = TYPES[type];
  if (type === 'policy') {
    if (!body.name) return null;
    const r = await cmdb(fw, 'GET', p, vdom, { query: `&filter=name==${encodeURIComponent(body.name)}&format=policyid|name` });
    if (r.status !== 200) throw cmdbError(r);
    return r.json.results?.[0]?.policyid ?? null;
  }
  const r = await cmdb(fw, 'GET', `${p}/${encodeURIComponent(body.name)}`, vdom, { query: '&format=name' });
  if (r.status === 404) return null;
  if (r.status !== 200) throw cmdbError(r);
  return r.json.results?.length ? body.name : null;
}

// dryRun: only checks whether the object exists (read-only).
async function pushOne(fw, { type, vdom, payload, update, dryRun }) {
  const existing = await findExisting(fw, type, vdom, payload.body);
  const action = existing == null ? 'create' : update ? 'update' : 'conflict';
  if (dryRun) return { action, existing };
  if (action === 'conflict') {
    throw new Error(`${TYPES[type].label} "${payload.body.name}" already exists${type === 'policy' ? ` (ID ${existing})` : ''} - tick the "Update … if it exists" option to overwrite it`);
  }

  let r, key = existing;
  if (action === 'update') {
    r = await cmdb(fw, 'PUT', `${payload.path}/${encodeURIComponent(existing)}`, vdom, { body: payload.body });
  } else {
    r = await cmdb(fw, 'POST', payload.path, vdom, { body: payload.body });
    key = r.json.mkey ?? payload.body.name;
  }
  if (r.status !== 200 || r.json.status === 'error') throw cmdbError(r);

  let moved = null;
  if (payload.before != null && key != null && Number(key) !== payload.before) {
    const m = await cmdb(fw, 'PUT', `firewall/policy/${encodeURIComponent(key)}`, vdom, {
      query: `&action=move&before=${payload.before}`,
    });
    moved = m.status === 200 && m.json.status !== 'error'
      ? `moved before policy ${payload.before}`
      : `created, but moving it failed: ${cmdbError(m).message}`;
  }
  return { action, key, moved };
}

// ---------- audit log ----------
function log(entry) {
  fs.appendFileSync(LOG_FILE, JSON.stringify(entry) + '\n', { mode: 0o600 });
}

function history(limit = 100) {
  let lines;
  try {
    lines = fs.readFileSync(LOG_FILE, 'utf8').trim().split('\n');
  } catch {
    return [];
  }
  return lines.slice(-limit).reverse().map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  }).filter(Boolean);
}

// Pushes (or with dryRun, plans) one object to several firewall + VDOM targets in parallel.
async function push(targets, { type, data, update, dryRun }) {
  targets = targets.map(({ fw, vdom }) => ({ fw, vdom: vdomName(vdom) }));
  const payload = buildPayload(type, data);
  const results = await Promise.all(targets.map(async ({ fw, vdom }) => {
    const base = { firewallId: fw.id, firewall: fw.name, host: fw.host, vdom };
    try {
      return { ...base, ok: true, ...(await pushOne(fw, { type, vdom, payload, update: !!update, dryRun })) };
    } catch (err) {
      return { ...base, ok: false, error: err.message };
    }
  }));
  if (!dryRun) {
    const at = new Date().toISOString();
    for (const r of results) {
      log({ at, type, name: payload.body.name ?? null, body: payload.body, before: payload.before, ...r });
    }
  }
  return { type, payload, results };
}

// VDOM names of a firewall (["root"] when VDOMs are disabled).
async function vdoms(fw) {
  const r = await cmdb(fw, 'GET', 'system/vdom', 'root', { query: '&format=name' });
  if (r.status !== 200) throw cmdbError(r);
  const list = (r.json.results || []).map((x) => x.name).filter(Boolean);
  return list.length ? list : ['root'];
}

// Names that exist on the device, for autocompletion in the UI. Failures give empty lists.
async function suggestions(fw, vdom) {
  vdom = vdomName(vdom);
  const get = async (p) => {
    try {
      const r = await cmdb(fw, 'GET', p, vdom, { query: '&format=name' });
      return r.status === 200 ? (r.json.results || []).map((x) => x.name).filter(Boolean) : [];
    } catch {
      return [];
    }
  };
  const [intf, zones, addr, grp, vip, vipgrp, svc, svcgrp, sched, schedGrp, cat] = await Promise.all([
    'system/interface', 'system/zone', 'firewall/address', 'firewall/addrgrp', 'firewall/vip',
    'firewall/vipgrp', 'firewall.service/custom', 'firewall.service/group', 'firewall.schedule/recurring',
    'firewall.schedule/group', 'firewall.service/category',
  ].map(get));
  return {
    interfaces: [...zones, ...intf],
    addresses: [...grp, ...addr, ...vipgrp, ...vip],
    services: [...svcgrp, ...svc],
    schedules: [...sched, ...schedGrp],
    categories: cat,
  };
}

module.exports = { TYPES, push, history, vdoms, suggestions, buildPayload };
