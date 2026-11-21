// Threat feeds (Security Fabric > External Connectors > Threat Feeds): the external lists
// of IPs, domains, URLs, malware hashes or MAC addresses each firewall downloads.
//
// 1. From the newest backup: every `config system external-resource` entry (global and per
//    VDOM), what it is used by (policies, address groups, web / DNS filter and antivirus
//    profiles, and the policies those profiles are applied in) and what looks wrong.
// 2. Live, on request: what the firewall says about each feed right now (last fetch,
//    error, number of entries), from /api/v2/monitor/system/external-resource/entry-list.
const fs = require('node:fs');
const { parse } = require('./fgtparse');
const { request } = require('./fortigate');
const { parseHeader, splitVdoms, entriesOf, one, list } = require('./audit');

const TYPES = {
  category: 'FortiGuard category',
  address: 'IP address',
  domain: 'Domain name',
  malware: 'Malware hash',
  'mac-address': 'MAC address',
};

const ISSUES = {
  disabled: { level: 'warn', title: 'Feed disabled', detail: 'The firewall does not download it; whatever uses it matches the last list it had, or nothing.' },
  unused: { level: 'warn', title: 'Not used', detail: 'No policy, address group or security profile refers to it: it is downloaded but blocks nothing.' },
  'profile-unused': { level: 'warn', title: 'Profile not applied', detail: 'It is in a security profile, but no enabled policy applies that profile.' },
  'monitor-only': { level: 'info', title: 'Monitor only', detail: 'The filter that uses this category logs matches but lets them through.' },
  'policy-disabled': { level: 'info', title: 'Only in disabled policies', detail: 'Every policy that refers to it is disabled.' },
  'cleartext-auth': { level: 'err', title: 'Credentials over HTTP', detail: 'The feed has a username and password but is fetched over plain HTTP: anyone on the path can read them.' },
  cleartext: { level: 'warn', title: 'Fetched over HTTP', detail: 'The list can be read or altered on the way; use HTTPS.' },
  'no-cert-check': { level: 'info', title: 'Certificate not checked', detail: 'server-identity-check is off: a server with any certificate can serve the list. Set it to basic or full.' },
  'url-credentials': { level: 'err', title: 'Password in the URL', detail: 'The URL carries user:password. Use the username / password settings instead.' },
};

// Shows the URL without any user:password in it.
function safeUrl(s) {
  try {
    const u = new URL(s);
    if (!u.username && !u.password) return { url: s, inUrl: false };
    u.username = '';
    u.password = '';
    return { url: u.toString(), inUrl: true };
  } catch {
    return { url: s, inUrl: false };
  }
}

function feedOf(e, scope) {
  const type = one(e, 'type') || 'category';
  const { url, inUrl } = safeUrl(one(e, 'resource') || '');
  return {
    scope,
    name: e.name,
    type,
    typeLabel: TYPES[type] || type,
    category: type === 'category' || type === 'domain' ? Number(one(e, 'category')) || null : null,
    status: one(e, 'status') || 'enable',
    updateMethod: one(e, 'update-method') || 'feed',
    resource: url,
    urlCredentials: inUrl,
    refreshRate: Number(one(e, 'refresh-rate')) || 5,
    // Only whether there is a login: the username is not shown, the password is never kept.
    auth: !!one(e, 'username'),
    serverIdentityCheck: one(e, 'server-identity-check') || 'none',
    interface: one(e, 'interface-select-method') === 'specify' ? one(e, 'interface') : null,
    sourceIp: one(e, 'source-ip') && one(e, 'source-ip') !== '0.0.0.0' ? one(e, 'source-ip') : null,
    userAgent: one(e, 'user-agent') || null,
    comments: one(e, 'comments') || '',
    usedBy: { policies: [], groups: [], profiles: [] },
  };
}

const POLICY_TABLES = {
  'firewall policy': 'Firewall policy',
  'firewall policy6': 'Firewall policy (IPv6)',
  'firewall proxy-policy': 'Proxy policy',
  'firewall local-in-policy': 'Local-in policy',
  'firewall local-in-policy6': 'Local-in policy (IPv6)',
  'firewall shaping-policy': 'Shaping policy',
  'firewall DoS-policy': 'DoS policy',
  'firewall DoS-policy6': 'DoS policy (IPv6)',
};
const ADDR_FIELDS = { srcaddr: 'source', dstaddr: 'destination', srcaddr6: 'source', dstaddr6: 'destination' };
const PROFILE_FIELDS = { webfilter: 'webfilter-profile', dnsfilter: 'dnsfilter-profile', antivirus: 'av-profile' };
const PROFILE_LABEL = { webfilter: 'Web filter', dnsfilter: 'DNS filter', antivirus: 'Antivirus' };

// FortiOS leaves `action deny` out of the backup: it is the default.
const NO_ACTION = new Set(['firewall shaping-policy', 'firewall DoS-policy', 'firewall DoS-policy6']);
const policyRef = (vdom, table, p) => ({
  vdom, table: POLICY_TABLES[table], id: p.name, name: one(p, 'name') || '',
  action: one(p, 'action') || (NO_ACTION.has(table) ? '' : 'deny'),
  enabled: one(p, 'status') !== 'disable',
});

// Fills feed.usedBy for every feed visible in one VDOM (its own and the global ones).
function scanVdom(vdom, node, visible) {
  const byName = new Map(visible.map((f) => [f.name, f]));
  const byCategory = new Map(visible.filter((f) => f.category).map((f) => [f.category, f]));

  // Address groups, nested to any depth: group name -> feeds inside it.
  const groups = new Map([...entriesOf(node, 'firewall addrgrp'), ...entriesOf(node, 'firewall addrgrp6')].map((g) => [g.name, list(g, 'member')]));
  const memo = new Map();
  const feedsIn = (name, seen = new Set()) => {
    if (byName.has(name)) return [byName.get(name)];
    if (!groups.has(name) || seen.has(name)) return [];
    if (memo.has(name)) return memo.get(name);
    seen.add(name);
    const out = [...new Set(groups.get(name).flatMap((m) => feedsIn(m, seen)))];
    memo.set(name, out);
    return out;
  };
  for (const [g, members] of groups) {
    for (const f of new Set(members.flatMap((m) => feedsIn(m)))) f.usedBy.groups.push({ vdom, name: g });
  }

  // Profiles that use a feed: "<kind>|<profile>" -> [{ feed, action }].
  const profileFeeds = new Map();
  const addProfile = (kind, prof, feed, action) => {
    const k = `${kind}|${prof}`;
    if (!profileFeeds.has(k)) profileFeeds.set(k, []);
    profileFeeds.get(k).push({ feed, action });
  };
  for (const [kind, path, sub] of [['webfilter', 'webfilter profile', 'ftgd-wf'], ['dnsfilter', 'dnsfilter profile', 'ftgd-dns']]) {
    for (const p of entriesOf(node, path)) {
      const ftgd = p.configs.find((c) => c.path === sub);
      const filters = ftgd ? entriesOf(ftgd, 'filters') : [];
      for (const flt of filters) {
        const f = byCategory.get(Number(one(flt, 'category')));
        if (f) addProfile(kind, p.name, f, one(flt, 'action') || 'monitor');
      }
    }
  }
  const malware = visible.filter((f) => f.type === 'malware');
  for (const p of entriesOf(node, 'antivirus profile')) {
    const all = one(p, 'external-blocklist-enable-all') === 'enable';
    const named = new Set(list(p, 'external-blocklist'));
    for (const f of malware) if (all || named.has(f.name)) addProfile('antivirus', p.name, f, all ? 'all feeds' : 'block');
  }

  const profileGroups = new Map(entriesOf(node, 'firewall profile-group').map((g) => [g.name, g]));
  const applied = new Map([...profileFeeds.keys()].map((k) => [k, []]));

  for (const table of Object.keys(POLICY_TABLES)) {
    for (const p of entriesOf(node, table)) {
      for (const [field, dir] of Object.entries(ADDR_FIELDS)) {
        for (const v of list(p, field)) {
          for (const f of feedsIn(v)) f.usedBy.policies.push({ ...policyRef(vdom, table, p), field: dir, via: v === f.name ? null : v });
        }
      }
      if (!['firewall policy', 'firewall proxy-policy'].includes(table) || one(p, 'utm-status') !== 'enable') continue;
      const holder = one(p, 'profile-type') === 'group' ? profileGroups.get(one(p, 'profile-group')) : p;
      if (!holder) continue;
      for (const [kind, key] of Object.entries(PROFILE_FIELDS)) {
        const k = `${kind}|${one(holder, key)}`;
        if (applied.has(k)) applied.get(k).push(policyRef(vdom, table, p));
      }
    }
  }

  for (const [k, hits] of profileFeeds) {
    const [kind, name] = k.split('|');
    for (const { feed, action } of hits) {
      feed.usedBy.profiles.push({ vdom, kind: PROFILE_LABEL[kind], name, action, policies: applied.get(k) });
    }
  }
}

function issuesOf(f) {
  const out = [];
  const http = /^http:/i.test(f.resource);
  if (f.status === 'disable') out.push('disabled');
  if (f.urlCredentials) out.push('url-credentials');
  if (http && (f.auth || f.urlCredentials)) out.push('cleartext-auth');
  else if (http) out.push('cleartext');
  if (/^https:/i.test(f.resource) && f.serverIdentityCheck === 'none') out.push('no-cert-check');
  const u = f.usedBy;
  const refs = [...u.policies, ...u.profiles.flatMap((p) => p.policies)];
  // A feed only in an address group that no policy uses is as unused as one in nothing.
  if (!u.policies.length && !u.profiles.length) out.push('unused');
  else if (!refs.length) out.push('profile-unused');
  else if (!refs.some((p) => p.enabled)) out.push('policy-disabled');
  if (u.profiles.length && u.profiles.every((p) => p.action === 'monitor')) out.push('monitor-only');
  return out;
}

// Threat feeds in one backup, with where each is used and what looks wrong.
function analyze(text) {
  const { header, root } = parse(text);
  const info = parseHeader(header);
  const { global, vdoms } = splitVdoms(root, info.multiVdom);

  const globalFeeds = entriesOf(global, 'system external-resource').map((e) => feedOf(e, info.multiVdom ? 'global' : null));
  const feeds = [...globalFeeds];
  for (const { name, node } of vdoms) {
    const own = info.multiVdom ? entriesOf(node, 'system external-resource').map((e) => feedOf(e, name)) : [];
    feeds.push(...own);
    // A VDOM feed hides a global one with the same name.
    const names = new Set(own.map((f) => f.name));
    scanVdom(name, node, [...own, ...globalFeeds.filter((f) => !names.has(f.name))]);
  }
  for (const f of feeds) f.issues = issuesOf(f);

  const count = (fn) => feeds.filter(fn).length;
  return {
    device: { model: info.model, version: info.version, multiVdom: info.multiVdom },
    feeds,
    counts: {
      total: feeds.length,
      enabled: count((f) => f.status !== 'disable'),
      inUse: count((f) => !f.issues.some((i) => ['unused', 'profile-unused', 'policy-disabled'].includes(i))),
      attention: count((f) => f.issues.some((i) => ISSUES[i].level !== 'info')),
    },
  };
}

// Backup files never change once written, so each one is analysed only once.
const cache = new Map();
function forBackup(full) {
  const st = fs.statSync(full);
  const key = `${full}|${st.mtimeMs}|${st.size}`;
  if (!cache.has(key)) {
    if (cache.size > 500) cache.clear();
    cache.set(key, analyze(fs.readFileSync(full, 'utf8')));
  }
  return cache.get(key);
}

// ---------- live status ----------
const SAMPLE = 20;

// Everything the firewall reports for one feed, every entry included.
async function fetchFeed(fw, vdom, name) {
  const res = await request(fw, 'GET', `/api/v2/monitor/system/external-resource/entry-list?mkey=${encodeURIComponent(name)}&vdom=${encodeURIComponent(vdom)}`);
  if (res.status === 403) throw new Error('HTTP 403: the API admin profile needs read access to Security Fabric (and to this VDOM)');
  if (res.status === 404) throw new Error('Not found on the device (deleted since the backup?)');
  if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
  let r;
  try {
    r = JSON.parse(res.body.toString('utf8')).results || {};
  } catch {
    throw new Error('Unexpected non-JSON response');
  }
  // FortiOS 7.4: { status, resource_file_status, conn_attempt_time, last_content_update_time,
  // overflow, entries: [{ entry, valid }] }; other shapes are read leniently.
  const raw = Array.isArray(r.entries) ? r.entries : Array.isArray(r) ? r : [];
  const text = (e) => String(typeof e === 'string' ? e : e.entry ?? e.value ?? e.name ?? JSON.stringify(e));
  const bad = (e) => typeof e === 'object' && (e.valid === false || /invalid/i.test(String(e.status || '')));
  const t = (s) => (Number(s) > 0 ? new Date(Number(s) * 1000) : null);
  return {
    ok: r.status ? r.status !== 'error' : true,
    error: r.error || null,
    errorCode: r.error_code ?? null,
    fileStatus: r.resource_file_status || null,
    lastAttempt: t(r.conn_attempt_time),
    lastUpdate: t(r.last_content_update_time ?? r.last_update_time),
    // The list had more lines than the firewall accepts: the rest is ignored.
    overflow: !!r.overflow,
    list: raw.map((e) => ({ entry: text(e), valid: !bad(e) })),
  };
}

// The status of a fetched feed with a sample of its entries instead of all of them.
function summary({ list, ...x }) {
  const invalid = list.filter((e) => !e.valid);
  return {
    ...x,
    entries: list.length,
    invalid: invalid.length,
    sample: list.filter((e) => e.valid).slice(0, SAMPLE).map((e) => e.entry),
    invalidSample: invalid.slice(0, SAMPLE).map((e) => e.entry),
  };
}

// What the firewall reports for each feed of its backup. Global feeds are read through
// the first VDOM; per-VDOM feeds through their own. `full` keeps every entry (`list`).
async function live(fw, analysis, vdoms, { full = false } = {}) {
  const via = (f) => (f.scope && f.scope !== 'global' ? f.scope : vdoms[0] || 'root');
  const feeds = await Promise.all(analysis.feeds.map(async (f) => {
    const base = { scope: f.scope, name: f.name, type: f.type };
    try {
      const x = await fetchFeed(fw, via(f), f.name);
      return { ...base, ...(full ? { ...summary(x), list: x.list } : summary(x)) };
    } catch (err) {
      return { ...base, failed: err.message };
    }
  }));
  return { checkedAt: new Date(), feeds };
}

module.exports = { analyze, forBackup, live, feedOf, safeUrl, ISSUES, TYPES };
