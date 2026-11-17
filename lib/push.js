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

// "10.1.0.0 255.255.0.0" -> "10.1.0.0/16" (a host without "/32"); null for the unset 0.0.0.0.
function cidr(v) {
  const [addr, mask = '255.255.255.255'] = str(v).split(/\s+/);
  if (!IPV4.test(addr) || !IPV4.test(mask) || (addr === '0.0.0.0' && mask === '0.0.0.0')) return null;
  const bits = mask.split('.').reduce((n, o) => n + Number(o).toString(2).replaceAll('0', '').length, 0);
  return bits === 32 ? addr : `${addr}/${bits}`;
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

const DAYS = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];

// ---------- object types ----------
// path: CMDB table. key: the field identifying an entry (policies are matched by name).
// global: not per VDOM, pushed once per firewall. secret: body fields never logged or echoed.
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
  schedule: {
    label: 'Recurring schedule',
    path: 'firewall.schedule/recurring',
    build(d) {
      const picked = (Array.isArray(d.day) ? d.day : str(d.day).split(/[\s,]+/)).map((x) => str(x).toLowerCase()).filter(Boolean);
      const bad = picked.find((x) => !DAYS.includes(x));
      if (bad) throw new Error(`Days: unknown day "${bad}"`);
      if (!picked.length) throw new Error('Days: pick at least one day');
      const time = (v, what) => {
        const s = str(v) || '00:00';
        if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(s)) throw new Error(`${what} must be HH:MM`);
        return s;
      };
      return { name: objName(d.name), day: DAYS.filter((x) => picked.includes(x)).join(' '), start: time(d.start, 'Start time'), end: time(d.end, 'Stop time') };
    },
  },
  schedonce: {
    label: 'One-time schedule',
    path: 'firewall.schedule/onetime',
    build(d) {
      // "2026-11-17T08:30" (datetime-local) -> "08:30 2026/11/17".
      const at = (v, what) => {
        const m = str(v).match(/^(\d{4})-(\d\d)-(\d\d)[T ]([01]\d|2[0-3]):([0-5]\d)/);
        if (!m) throw new Error(`${what}: pick a date and time`);
        return { sort: m.slice(1).join(''), text: `${m[4]}:${m[5]} ${m[1]}/${m[2]}/${m[3]}` };
      };
      const start = at(d.start, 'Start');
      const end = at(d.end, 'End');
      if (end.sort <= start.sort) throw new Error('End must be after Start');
      return { name: objName(d.name), start: start.text, end: end.text };
    },
  },
  admin: {
    label: 'Administrator',
    path: 'system/admin',
    global: true,
    secret: ['password'],
    // ctx.vdoms: the VDOMs ticked for the firewall, which the administrator gets access to.
    build(d, ctx = {}) {
      const kind = pick(d.kind, ['local', 'remote'], 'Type');
      const name = objName(d.name, 'Username');
      if (name.length > 64 || /\s/.test(name)) throw new Error('Username: at most 64 characters, no spaces');
      const profile = objName(d.accprofile, 'Administrator profile');
      let body = { name, accprofile: profile };
      const password = String(d.password ?? '');
      if (password && password.length < 8) throw new Error('Password: at least 8 characters');
      if (password) body.password = password;
      if (kind === 'local') {
        Object.assign(body, { 'remote-auth': 'disable', 'force-password-change': onOff(d['force-password-change']) });
      } else {
        Object.assign(body, { 'remote-auth': 'enable', 'remote-group': objName(d['remote-group'], 'Remote user group'), wildcard: onOff(d.wildcard) });
        if (body.wildcard === 'enable') delete body.password;
      }
      // With one trusted host set, the unused slots are cleared so an update replaces the list.
      const hosts = str(d.trusthost).split(/[,;\n]+/).map(str).filter(Boolean);
      if (hosts.length > 10) throw new Error('Trusted hosts: at most 10');
      if (hosts.length) for (let i = 0; i < 10; i++) body[`trusthost${i + 1}`] = hosts[i] ? subnet(hosts[i]) : '0.0.0.0 0.0.0.0';
      if (!/^super_admin/.test(profile) && ctx.vdoms?.length) body.vdom = ctx.vdoms.map((v) => ({ name: v }));
      return withComment(body, 'comments', d.comments);
    },
    // An entry of the device as form data (the password cannot be read back).
    read(e) {
      const hosts = [];
      for (let i = 1; i <= 10; i++) if (cidr(e[`trusthost${i}`])) hosts.push(cidr(e[`trusthost${i}`]));
      return {
        name: str(e.name),
        kind: e['remote-auth'] === 'enable' ? 'remote' : 'local',
        'remote-group': str(e['remote-group']),
        wildcard: e.wildcard === 'enable',
        accprofile: str(e.accprofile),
        'force-password-change': e['force-password-change'] === 'enable',
        trusthost: hosts.join(', '),
        comments: str(e.comments),
        vdoms: (Array.isArray(e.vdom) ? e.vdom : []).map((v) => str(v?.name)).filter(Boolean),
      };
    },
    // Deleting the last full administrator would lock everyone out of the firewall.
    canDelete(name, list) {
      const me = list.find((a) => a.name === name);
      if (!me) throw new Error(`Administrator "${name}" does not exist here`);
      if (me.accprofile === 'super_admin' && !list.some((a) => a.name !== name && a.accprofile === 'super_admin')) {
        throw new Error(`"${name}" is the only super_admin account on this firewall, so it is not deleted`);
      }
    },
    // An update may leave the password as it is; a new account must get one.
    onCreate(body) {
      if (!body.password && body.wildcard !== 'enable') throw new Error(`Administrator "${body.name}" does not exist here yet: enter a password to create it`);
    },
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

function buildPayload(type, data, ctx) {
  const t = TYPES[type];
  if (!t) throw new Error(`Unknown object type "${type}"`);
  return { path: t.path, body: t.build(data || {}, ctx), before: placement(type, data || {}) };
}

// The body without its secrets, for logs and for what goes back to the browser.
function redact(type, body) {
  const out = { ...body };
  for (const k of TYPES[type].secret || []) if (k in out) out[k] = '********';
  return out;
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
  if (r.status === 403) return new Error('HTTP 403: Forbidden - the API admin profile needs read-write access to this part of the configuration (Firewall for policies and objects, System for administrators) and to this VDOM');
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
  if (action === 'create') TYPES[type].onCreate?.(payload.body);
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

// Objects a policy (or group) needs that may not exist yet. They are created first, in this
// order (members before groups); the ones a target already has are used as they are.
const DEP_ORDER = ['address', 'service', 'schedule', 'schedonce', 'addrgrp', 'servicegrp'];

function buildDeps(objects) {
  const seen = new Set();
  return (Array.isArray(objects) ? objects : []).map((o) => {
    if (!DEP_ORDER.includes(o?.type)) throw new Error('Only addresses, services, their groups and schedules can be created along the way');
    const payload = buildPayload(o.type, o.data);
    const key = `${payload.path}|${payload.body.name}`;
    if (seen.has(key)) throw new Error(`${TYPES[o.type].label} "${payload.body.name}" is defined twice`);
    seen.add(key);
    return { type: o.type, payload };
  }).sort((a, b) => DEP_ORDER.indexOf(a.type) - DEP_ORDER.indexOf(b.type));
}

// Stops at the first failure: what comes after may depend on it.
async function pushDeps(fw, vdom, deps, dryRun) {
  const out = [];
  for (const { type, payload } of deps) {
    const item = { type, name: payload.body.name, body: payload.body };
    try {
      if (await findExisting(fw, type, vdom, payload.body) != null) item.action = 'exists';
      else {
        item.action = 'create';
        if (!dryRun) {
          const r = await cmdb(fw, 'POST', payload.path, vdom, { body: payload.body });
          if (r.status !== 200 || r.json.status === 'error') throw cmdbError(r);
        }
      }
      item.ok = true;
    } catch (err) {
      item.ok = false;
      item.error = err.message;
    }
    out.push(item);
    if (!item.ok) break;
  }
  return out;
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
// `objects` ({ type, data }) are created on each target before it, when they are missing.
// A global type (administrators) goes once to each firewall, whatever VDOMs are ticked.
async function push(targets, { type, data, update, dryRun, objects }) {
  const t = TYPES[type];
  if (!t) throw new Error(`Unknown object type "${type}"`);
  targets = targets.map(({ fw, vdom }) => ({ fw, vdom: vdomName(vdom) }));
  if (t.global) {
    if (objects?.length) throw new Error(`${t.label}: no other objects can be created along the way`);
    const byFw = new Map();
    for (const { fw, vdom } of targets) {
      if (!byFw.has(fw.id)) byFw.set(fw.id, { fw, vdom: 'global', via: 'root', vdoms: [] });
      byFw.get(fw.id).vdoms.push(vdom);
    }
    targets = [...byFw.values()];
  }
  // Everything is validated before the first firewall is touched.
  targets = targets.map((x) => ({ ...x, payload: buildPayload(type, data, { vdoms: x.vdoms }) }));
  const deps = buildDeps(objects);
  const at = new Date().toISOString();
  const results = await Promise.all(targets.map(async ({ fw, vdom, via = vdom, payload }) => {
    const base = { firewallId: fw.id, firewall: fw.name, host: fw.host, vdom };
    let objs = [];
    let result;
    try {
      objs = await pushDeps(fw, via, deps, dryRun);
      const failed = objs.find((o) => !o.ok);
      if (failed) throw new Error(`${TYPES[failed.type].label} "${failed.name}" failed, so the ${t.label.toLowerCase()} was not pushed: ${failed.error}`);
      result = { ...base, ok: true, ...(await pushOne(fw, { type, vdom: via, payload, update: !!update, dryRun })) };
    } catch (err) {
      result = { ...base, ok: false, error: err.message };
    }
    if (!dryRun) {
      for (const o of objs) {
        if (o.action === 'create') log({ at, type: o.type, name: o.name, body: o.body, ...base, ok: o.ok, action: 'create', ...(o.error && { error: o.error }) });
      }
      log({ at, type, name: payload.body.name ?? null, body: redact(type, payload.body), before: payload.before, ...result });
    }
    return { ...result, objects: objs.map(({ body, ...o }) => o) };
  }));
  const shown = targets[0].payload;
  return { type, payload: { ...shown, body: redact(type, shown.body) }, objects: deps, results };
}

// What a firewall has of a type today, as form data, for editing (types with `read` only).
async function existing(fw, type) {
  const t = TYPES[type];
  if (!t?.read) throw new Error('Entries of this type cannot be listed');
  const r = await cmdb(fw, 'GET', t.path, 'root');
  if (r.status !== 200) throw cmdbError(r);
  return (r.json.results || []).map((e) => t.read(e)).filter((d) => d.name);
}

// Deletes one entry (types with `read` only) from several firewalls. Every attempt is logged.
async function remove(fws, type, name) {
  const t = TYPES[type];
  if (!t?.read) throw new Error('Entries of this type cannot be deleted here');
  name = objName(name);
  const at = new Date().toISOString();
  return Promise.all(fws.map(async (fw) => {
    const result = { firewallId: fw.id, firewall: fw.name, host: fw.host, vdom: t.global ? 'global' : 'root', action: 'delete' };
    try {
      t.canDelete?.(name, await existing(fw, type));
      const r = await cmdb(fw, 'DELETE', `${t.path}/${encodeURIComponent(name)}`, 'root');
      if (r.status !== 200 || r.json.status === 'error') throw cmdbError(r);
      result.ok = true;
    } catch (err) {
      Object.assign(result, { ok: false, error: err.message });
    }
    log({ at, type, name, ...result });
    return result;
  }));
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
  const [intf, zones, addr, grp, vip, vipgrp, svc, svcgrp, sched, schedGrp, cat, schedOnce, prof, ugrp] = await Promise.all([
    'system/interface', 'system/zone', 'firewall/address', 'firewall/addrgrp', 'firewall/vip',
    'firewall/vipgrp', 'firewall.service/custom', 'firewall.service/group', 'firewall.schedule/recurring',
    'firewall.schedule/group', 'firewall.service/category', 'firewall.schedule/onetime', 'system/accprofile', 'user/group',
  ].map(get));
  return {
    interfaces: [...zones, ...intf],
    addresses: [...grp, ...addr, ...vipgrp, ...vip],
    services: [...svcgrp, ...svc],
    schedules: [...sched, ...schedOnce, ...schedGrp],
    categories: cat,
    // The same names by kind, for the entry picker ("any" is not in the interface table).
    groups: {
      interfaces: [['Interface', ['any', ...intf]], ['Zone', zones]],
      addresses: [['Address', addr], ['Address Group', grp], ['Virtual IP', vip], ['Virtual IP Group', vipgrp]],
      services: [['Service', svc], ['Service Group', svcgrp]],
      accprofiles: [['Administrator Profile', [...new Set(['super_admin', ...prof])]]],
      usergroups: [['User Group', ugrp]],
      schedules: [['Recurring Schedule', sched], ['One-Time Schedule', schedOnce], ['Schedule Group', schedGrp]],
    },
  };
}

module.exports = { TYPES, push, history, vdoms, suggestions, buildPayload, existing, remove };
