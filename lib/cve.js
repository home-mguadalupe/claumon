// Known vulnerabilities (CVEs) of the FortiOS version each firewall runs, and whether the
// affected feature is actually in use according to its backup.
//
// 1. The CVE list comes from the public NVD API (every CVE that names FortiOS), cached in
//    data/cve-cache.json. Only the product name is sent: no version, hostname or config.
// 2. A CVE applies to a version when the vendor's affected ranges (or, failing that, NVD's
//    CPE ranges or the description) include it. Vendor ranges come first because NVD takes
//    weeks to analyse new CVEs, and those are the ones that matter most.
// 3. The description is matched against FortiOS features (SSL-VPN, admin GUI, HA, BGP…) and
//    each feature is looked up in the backup. This part is a heuristic: it reads the
//    advisory text, so every verdict shows the evidence it is based on.
const fs = require('node:fs');
const path = require('node:path');
const { parse } = require('./fgtparse');
const { parseHeader, splitVdoms, entriesOf, one, list } = require('./audit');

const CACHE_FILE = path.join(__dirname, '..', 'data', 'cve-cache.json');
const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const QUERIES = ['keywordSearch=FortiOS', 'virtualMatchString=cpe:2.3:o:fortinet:fortios'];
const PAGE = 2000;
// 0 = never refresh on its own (only with the Refresh button).
const REFRESH_HOURS = process.env.CVE_REFRESH_HOURS === undefined || process.env.CVE_REFRESH_HOURS === ''
  ? 24 : Math.max(0, Number(process.env.CVE_REFRESH_HOURS) || 0);
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

// ---------- versions ----------
const ver = (s) => {
  const m = String(s || '').match(/(\d+)\.(\d+)(?:\.(\d+|\*|x))?/i);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), m[3] === undefined || /[*x]/i.test(m[3]) ? null : Number(m[3])];
};
const cmp = (a, b) => (a[0] - b[0]) || (a[1] - b[1]) || ((a[2] ?? 0) - (b[2] ?? 0));
const fmt = (v) => v.filter((x) => x != null).join('.');

// A range is { from, to, toIncl } with version triples; `branch` covers a whole X.Y.
const inRange = (v, r) => {
  if (r.branch) return v[0] === r.branch[0] && v[1] === r.branch[1];
  if (r.from && cmp(v, r.from) < 0) return false;
  if (r.to && (r.toIncl ? cmp(v, r.to) > 0 : cmp(v, r.to) >= 0)) return false;
  return !!(r.from || r.to);
};

// Vendor (CNA) data: { version, lessThan | lessThanOrEqual, status }.
function vendorRanges(cve) {
  const out = [];
  for (const d of (cve.affected || []).flatMap((a) => a.affectedData || [])) {
    if (!/^fortios$/i.test(String(d.product || '').trim())) continue;
    for (const v of d.versions || []) {
      if (v.status !== 'affected') continue;
      const from = ver(v.version);
      if (!from) continue;
      const upper = v.lessThanOrEqual || v.lessThan;
      if (!upper) {
        // "5.0.x, 5.2.x" style lists, or a single version.
        const parts = String(v.version).split(/[,;]/).map(ver).filter(Boolean);
        for (const p of parts) out.push(p[2] == null ? { branch: p } : { from: p, to: p, toIncl: true });
        continue;
      }
      const to = ver(upper);
      if (!to) continue;
      // "6.2.*" = the rest of that branch.
      if (to[2] == null) out.push({ from: [from[0], from[1], from[2] ?? 0], to: [to[0], to[1] + 1, 0], toIncl: false });
      else out.push({ from: [from[0], from[1], from[2] ?? 0], to, toIncl: !!v.lessThanOrEqual });
    }
  }
  return out;
}

// NVD analysis: CPE match criteria with optional version bounds.
function nvdRanges(cve) {
  const out = [];
  for (const m of (cve.configurations || []).flatMap((c) => c.nodes || []).flatMap((n) => n.cpeMatch || [])) {
    if (!m.vulnerable || !/^cpe:2\.3:o:fortinet:fortios:/.test(m.criteria)) continue;
    const exact = m.criteria.split(':')[5];
    const from = ver(m.versionStartIncluding) || ver(m.versionStartExcluding);
    const to = ver(m.versionEndExcluding) || ver(m.versionEndIncluding);
    if (from || to) out.push({ from: from || [0, 0, 0], to, toIncl: !!m.versionEndIncluding, fromExcl: !!m.versionStartExcluding });
    else if (ver(exact)) out.push({ from: ver(exact), to: ver(exact), toIncl: true });
  }
  return out;
}

// Advisory text: "FortiOS 7.4.0 through 7.4.11, FortiOS 7.2 all versions, FortiOS 6.4.1 …".
// Only the parts that follow the word FortiOS are read, so FortiProxy ranges are ignored.
function textRanges(desc) {
  const out = [];
  const re = /FortiOS(?:\s+versions?)?\s+((?:\d+\.\d+(?:\.\d+)?(?:\s+all versions|\s+(?:through|to|and)\s+\d+\.\d+(?:\.\d+)?|\s+and\s+(?:below|earlier|prior))?(?:\s*,\s*(?!Forti)|\s+and\s+(?=\d))?)+)/gi;
  for (const [, body] of desc.matchAll(re)) {
    for (const [, a, all, b, below] of body.matchAll(/(\d+\.\d+(?:\.\d+)?)(\s+all versions)?(?:\s+(?:through|to)\s+(\d+\.\d+(?:\.\d+)?))?(\s+and\s+(?:below|earlier|prior))?/gi)) {
      const from = ver(a);
      if (all || (from[2] == null && !b)) out.push({ branch: from });
      else if (b) out.push({ from: [from[0], from[1], from[2] ?? 0], to: ver(b), toIncl: true });
      else if (below) out.push({ from: [from[0], from[1], 0], to: from, toIncl: true });
      else out.push({ from, to: from, toIncl: true });
    }
  }
  return out.filter((r) => r.branch || (r.to && r.to[2] != null));
}

// ---------- NVD ----------
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function nvdPage(query, startIndex) {
  const headers = { Accept: 'application/json', 'User-Agent': 'fortigate-backup' };
  if (process.env.NVD_API_KEY) headers.apiKey = process.env.NVD_API_KEY;
  let last;
  // NVD answers 403 / 429 / 503 when rate-limited (5 requests per 30 s without a key).
  for (let attempt = 0; attempt < 4; attempt++) {
    if (attempt) await sleep(7000 * attempt);
    try {
      const res = await fetch(`${NVD}?${query}&resultsPerPage=${PAGE}&startIndex=${startIndex}`, { headers, signal: AbortSignal.timeout(90000) });
      if (res.ok) return await res.json();
      last = new Error(`NVD answered HTTP ${res.status}`);
      if (![403, 429, 500, 502, 503, 504].includes(res.status)) break;
    } catch (err) {
      last = new Error(`NVD not reachable: ${err.cause?.code || err.cause?.message || err.message}`);
    }
  }
  throw last;
}

// Keeps what the report needs; the full NVD record is ten times larger.
function slim(cve) {
  const desc = ((cve.descriptions || []).find((d) => d.lang === 'en') || {}).value || '';
  const metrics = Object.entries(cve.metrics || {}).filter(([k]) => /^cvssMetricV[34]/.test(k)).flatMap(([, v]) => v)
    .filter((m) => m.cvssData && typeof m.cvssData.baseScore === 'number');
  // Vendor and NVD often score differently: the higher one is shown.
  const top = metrics.sort((a, b) => b.cvssData.baseScore - a.cvssData.baseScore)[0];
  const vendor = vendorRanges(cve), text = textRanges(desc), nvd = nvdRanges(cve);
  const refs = (cve.references || []).map((r) => r.url);
  return {
    id: cve.id,
    published: cve.published,
    modified: cve.lastModified,
    status: cve.vulnStatus,
    description: desc.replace(/\s+/g, ' ').trim(),
    cvss: top ? { score: top.cvssData.baseScore, severity: String(top.cvssData.baseSeverity || '').toLowerCase(), vector: top.cvssData.vectorString, by: top.source === 'nvd@nist.gov' ? 'NVD' : 'vendor' } : null,
    kev: cve.cisaExploitAdd ? { added: cve.cisaExploitAdd, due: cve.cisaActionDue || null } : null,
    cwe: [...new Set((cve.weaknesses || []).flatMap((w) => w.description || []).map((d) => d.value).filter((v) => /^CWE-\d+$/.test(v)))],
    advisory: refs.find((u) => /fortiguard\.(fortinet\.)?com\/psirt/i.test(u)) || null,
    // Vendor ranges, plus the branches the description calls "all versions" (the vendor data
    // stops at the newest release of the day); the description alone when there are none,
    // and NVD's own ranges last.
    ranges: vendor.length ? [...vendor, ...text.filter((r) => r.branch)] : text.length ? text : nvd,
    rangesBy: vendor.length ? 'vendor' : text.length ? 'description' : nvd.length ? 'NVD' : null,
  };
}

async function download() {
  const byId = new Map();
  for (const q of QUERIES) {
    for (let start = 0; ;) {
      const page = await nvdPage(q, start);
      for (const v of page.vulnerabilities || []) byId.set(v.cve.id, v.cve);
      start += page.resultsPerPage || 0;
      if (!page.resultsPerPage || start >= page.totalResults) break;
      await sleep(1500);
    }
    await sleep(1500);
  }
  const cves = [...byId.values()].filter((c) => c.vulnStatus !== 'Rejected').map(slim).filter((c) => c.ranges.length);
  return { fetchedAt: new Date().toISOString(), source: 'NVD (nvd.nist.gov)', cves };
}

let db = null;        // { fetchedAt, source, cves }
let loading = null;   // one download at a time
let lastError = null; // { at, message } of the last failed download

function readCache() {
  if (db) return db;
  try {
    db = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
  } catch {}
  return db;
}

// The CVE list: from memory / disk while fresh, otherwise downloaded. A failed download
// keeps the old list (the caller reports the error); `cachedOnly` never downloads.
async function load({ force = false, cachedOnly = false } = {}) {
  const cur = readCache();
  const age = cur ? Date.now() - new Date(cur.fetchedAt) : Infinity;
  const due = force || !cur || (REFRESH_HOURS > 0 && age > REFRESH_HOURS * 36e5);
  // After a failure, wait before trying again on its own.
  const backoff = !force && lastError && Date.now() - lastError.at < 15 * 60 * 1000;
  if (!cachedOnly && due && !backoff) {
    loading ||= download().then((fresh) => {
      db = fresh;
      lastError = null;
      fs.writeFileSync(CACHE_FILE, JSON.stringify(fresh), { mode: 0o600 });
    }).catch((err) => {
      lastError = { at: Date.now(), message: err.message };
    }).finally(() => { loading = null; });
    await loading;
  }
  return {
    db,
    source: {
      name: 'NVD (nvd.nist.gov)', fetchedAt: db?.fetchedAt || null, total: db?.cves.length || 0,
      refreshHours: REFRESH_HOURS, error: lastError?.message || null,
    },
  };
}

// ---------- what the backup has in use ----------
// Each feature: label, the words in an advisory that point at it, and a test on the config
// that returns the evidence ([] = not in use). `always` features exist on every FortiGate.
const FEATURES = [
  { id: 'sslvpn', label: 'SSL-VPN', re: /ssl[- ]?vpn|sslvpnd|\bsslvpn\b/i, test: (f) => f.sslvpn },
  { id: 'fgfm', label: 'FortiManager (FGFM)', re: /\bfgfm|fortimanager|central[- ]management/i, test: (f) => f.fgfm },
  { id: 'ha', label: 'High availability', re: /\bHA\b|high[- ]availability|\bfgsp\b|\bfgcp\b|standalone-config-sync|cluster|autoscale|auto-scale/i, test: (f) => f.ha },
  { id: 'ospf', label: 'OSPF', re: /\bospf\b|\bLSA\b/i, test: (f) => f.ospf },
  { id: 'bgp', label: 'BGP', re: /\bi?bgp\b/i, test: (f) => f.bgp },
  { id: 'ipsec', label: 'IPsec VPN', re: /\bipsec\b|\bike(v[12])?\b|\biked\b/i, test: (f) => f.ipsec },
  { id: 'explicit-proxy', label: 'Explicit web proxy', re: /explicit (web[- ])?proxy|web[- ]proxy/i, test: (f) => f.explicitProxy },
  { id: 'ztna', label: 'ZTNA / access proxy', re: /\bztna\b|access[- ]proxy/i, test: (f) => f.ztna },
  { id: 'proxy-mode', label: 'Proxy-mode inspection (WAD)', re: /\bwad\b|proxy[- ]mode|proxy policy|proxy sessions?|deep inspection|ssl inspection/i, test: (f) => f.proxyMode },
  { id: 'captive-portal', label: 'Captive portal / user authentication', re: /captive portal|authd|fnbamd|firewall authentication|authentication portal/i, test: (f) => f.captive },
  { id: 'webfilter', label: 'Web filter', re: /web ?filter|urlfilter|override token/i, test: (f) => f.webfilter },
  { id: 'wireless', label: 'Wireless controller (CAPWAP)', re: /capwap|cw_acd|wireless controller|\bwifi\b|fortiap|\bcw_/i, test: (f) => f.wireless },
  { id: 'switch', label: 'FortiSwitch controller (FortiLink)', re: /fortilink|switch[- ]controller|managed fortiswitch/i, test: (f) => f.switchCtl },
  { id: 'csf', label: 'Security Fabric', re: /security fabric|\bcsf\b|fabric (connector|root|member|service)|downstream fortigate|upstream fortigate/i, test: (f) => f.csf },
  { id: 'snmp', label: 'SNMP', re: /\bsnmp/i, test: (f) => f.snmp },
  { id: 'saml', label: 'SAML / single sign-on', re: /\bsaml\b|single sign[- ]on|\bsso\b|forticloud sso/i, test: (f) => f.saml },
  { id: 'radius', label: 'RADIUS', re: /\bradius\b/i, test: (f) => f.radius },
  { id: 'tacacs', label: 'TACACS+', re: /tacacs/i, test: (f) => f.tacacs },
  { id: 'ldap', label: 'LDAP', re: /\bldaps?\b/i, test: (f) => f.ldap },
  { id: 'fsso', label: 'FSSO', re: /\bfsso\b|fortinet single sign/i, test: (f) => f.fsso },
  { id: 'dhcp', label: 'DHCP server', re: /\bdhcp/i, test: (f) => f.dhcp },
  { id: 'dns', label: 'DNS server / filter', re: /\bdns\b|dnsproxy/i, test: (f) => f.dns },
  { id: 'ips', label: 'IPS engine', re: /\bips\b|ips engine|ipsengine|intrusion prevention/i, test: (f) => f.ips },
  { id: 'antivirus', label: 'Antivirus', re: /anti-?virus|\bav engine|scanunit/i, test: (f) => f.antivirus },
  { id: 'sdwan', label: 'SD-WAN', re: /sd-?wan/i, test: (f) => f.sdwan },
  { id: 'extender', label: 'FortiExtender', re: /fortiextender|extension[- ]controller/i, test: (f) => f.extender },
  { id: 'vip', label: 'Virtual IP / load balancing', re: /virtual server|load[- ]balanc|\bvip\b/i, test: (f) => f.vip },
  { id: 'automation', label: 'Automation stitches', re: /automation (stitch|action|trigger)/i, test: (f) => f.automation },
  { id: 'gui', label: 'Admin GUI / REST API', always: true,
    re: /\bgui\b|web (interface|ui|console|server)|administrative interface|management interface|admin(istrative)? (panel|login|web)|rest api|\bhttpsd\b|node\.?js|websocket|jsconsole|web-based management|login page|dashboard/i,
    test: (f) => f.gui },
  { id: 'cli', label: 'CLI', always: true, re: /\bcli\b|command line|diagnose command|crafted commands?/i, test: (f) => f.cli },
  { id: 'ssh', label: 'SSH administration', re: /\bsshd?\b/i, test: (f) => f.ssh },
];

const plural = (n, w) => `${n} ${n === 1 ? w : /[^aeiou]y$/.test(w) ? `${w.slice(0, -1)}ies` : /(ch|s|x)$/.test(w) ? `${w}es` : `${w}s`}`;
const some = (names, max = 4) => names.slice(0, max).join(', ') + (names.length > max ? ` +${names.length - max} more` : '');

// Evidence per feature, as short strings. Empty array = nothing in the backup uses it.
function facts(text) {
  const { header, root } = parse(text);
  const info = parseHeader(header);
  const { global, vdoms } = splitVdoms(root, info.multiVdom);
  const cfg = (node, p) => node.configs.find((c) => c.path === p);
  const nodes = [global, ...(info.multiVdom ? vdoms.map((v) => v.node) : [])];
  const inVdoms = (fn) => vdoms.flatMap(({ name, node }) => fn(node).map((e) => (vdoms.length > 1 ? `${e} (VDOM ${name})` : e)));
  const count = (p, label) => inVdoms((n) => (entriesOf(n, p).length ? [plural(entriesOf(n, p).length, label)] : []));
  const anywhere = (p, label) => {
    const n = nodes.reduce((t, x) => t + entriesOf(x, p).length, 0);
    return n ? [plural(n, label)] : [];
  };
  const enabled = (p, label, key = 'status') => nodes.some((n) => one(cfg(n, p), key) === 'enable') ? [label] : [];

  const ifaces = entriesOf(global, 'system interface');
  const access = (proto) => ifaces.filter((i) => list(i, 'allowaccess').includes(proto)).map((i) => i.name);
  const isWan = (i) => one(i, 'role') === 'wan' || ['dhcp', 'pppoe'].includes(one(i, 'mode'));
  const wan = new Set(ifaces.filter(isWan).map((i) => i.name));
  const policies = vdoms.flatMap(({ node }) => entriesOf(node, 'firewall policy').filter((p) => one(p, 'status') !== 'disable'));
  const used = (key) => new Set(policies.map((p) => one(p, key)).filter(Boolean)).size;

  const web = [...new Set([...access('https'), ...access('http')])];
  const webWan = web.filter((n) => wan.has(n));
  const admins = entriesOf(global, 'system admin');
  const open = admins.filter((a) => !Object.keys(a.settings).some((k) => /^(ip6-)?trusthost\d+$/.test(k)));
  const gui = web.length ? [
    `HTTPS/HTTP administration on ${some(web)}`,
    webWan.length ? `reachable from the internet: ${some(webWan)}` : 'not enabled on a WAN-role interface',
    admins.length ? (open.length ? `${open.length} of ${plural(admins.length, 'administrator')} without trusted hosts` : 'all administrators limited to trusted hosts') : null,
  ].filter(Boolean) : [];

  const ha = cfg(global, 'system ha');
  const haMode = one(ha, 'mode');
  const haEv = [];
  if (haMode && haMode !== 'standalone') haEv.push(`HA mode ${haMode}`);
  if (one(ha, 'standalone-config-sync') === 'enable') haEv.push('standalone-config-sync enabled');
  if (nodes.some((n) => entriesOf(n, 'system cluster-sync').length || entriesOf(n, 'system standalone-cluster').length || one(cfg(n, 'system standalone-cluster'), 'standalone-group-id'))) haEv.push('FGSP cluster-sync peers');
  if (nodes.some((n) => one(cfg(n, 'system auto-scale'), 'status') === 'enable')) haEv.push('auto-scale enabled');

  const sslvpn = inVdoms((n) => {
    const s = cfg(n, 'vpn ssl settings');
    return s && list(s, 'source-interface').length && one(s, 'status') !== 'disable'
      ? [`listening on ${list(s, 'source-interface').join(', ')} port ${one(s, 'port') || '443'}`] : [];
  });

  // Every backup has empty `router ospf` / `router bgp` blocks: only areas, networks,
  // interfaces or neighbours mean the protocol runs.
  const ospf = inVdoms((n) => [['router ospf', 'OSPF', ['area', 'network', 'ospf-interface']], ['router ospf6', 'OSPFv3', ['area', 'ospf6-interface']]]
    .flatMap(([p, label, keys]) => {
      const o = cfg(n, p);
      const parts = o ? keys.map((k) => [k, entriesOf(o, k).length]).filter(([, c]) => c) : [];
      return parts.length ? [`${label} configured (${parts.map(([k, c]) => plural(c, k)).join(', ')})`] : [];
    }));
  const bgp = inVdoms((n) => {
    const b = cfg(n, 'router bgp');
    const nb = b ? entriesOf(b, 'neighbor') : [];
    const dyn = b ? entriesOf(b, 'neighbor-group').length + entriesOf(b, 'neighbor-range').length : 0;
    if (!nb.length && !dyn) return [];
    const ibgp = nb.filter((x) => one(x, 'remote-as') && one(x, 'remote-as') === one(b, 'as')).length;
    return [`${plural(nb.length, 'BGP neighbor')}${ibgp ? ` (${ibgp} iBGP)` : ''}${dyn ? `, ${plural(dyn, 'neighbor group / range')}` : ''}`];
  });

  const fgfmIf = access('fgfm');
  const cm = cfg(global, 'system central-management');
  const fgfm = [fgfmIf.length ? `fgfm allowed on ${some(fgfmIf)}` : null,
    cm && one(cm, 'type') === 'fortimanager' ? `managed by FortiManager ${one(cm, 'fmg') || ''}`.trim() : null].filter(Boolean);

  const capIf = [...new Set([...access('capwap'), ...access('fabric')])];
  const authPolicies = policies.filter((p) => list(p, 'groups').length || list(p, 'users').length).length;
  const captiveIf = ifaces.filter((i) => one(i, 'security-mode') === 'captive-portal').map((i) => i.name);
  const proxyPolicies = policies.filter((p) => one(p, 'inspection-mode') === 'proxy').length;
  const snmpOn = one(cfg(global, 'system snmp sysinfo'), 'status') === 'enable';
  const dnsIf = nodes.reduce((t, n) => t + entriesOf(n, 'system dns-server').length, 0);
  const sshIf = access('ssh');
  const profile = (key, label) => (used(key) ? [`${plural(used(key), label)} applied to policies`] : []);
  const groupProfiles = policies.some((p) => one(p, 'profile-group')) ? ['profile groups applied to policies'] : [];

  return {
    device: { model: info.model, version: info.version, build: (header.join(' ').match(/build(\d+)/) || [])[1] || null },
    f: {
      sslvpn, fgfm, ha: haEv, ospf, bgp, gui,
      cli: [`${plural(admins.length, 'administrator account')} can log in to the CLI`],
      ssh: sshIf.length ? [`ssh allowed on ${some(sshIf)}`] : [],
      ipsec: [...count('vpn ipsec phase1-interface', 'IPsec tunnel'), ...count('vpn ipsec phase1', 'policy-based IPsec tunnel')],
      explicitProxy: [...enabled('web-proxy explicit', 'explicit web proxy enabled'), ...enabled('ftp-proxy explicit', 'explicit FTP proxy enabled')],
      ztna: [...count('firewall access-proxy', 'access proxy'), ...count('firewall access-proxy6', 'IPv6 access proxy')],
      proxyMode: [proxyPolicies ? `${plural(proxyPolicies, 'policy')} in proxy inspection mode` : null,
        ...count('firewall proxy-policy', 'proxy policy')].filter(Boolean),
      captive: [captiveIf.length ? `captive portal on ${some(captiveIf)}` : null,
        authPolicies ? `${plural(authPolicies, 'policy')} requiring user authentication` : null].filter(Boolean),
      webfilter: [...profile('webfilter-profile', 'web filter profile'), ...groupProfiles],
      wireless: [capIf.length ? `capwap / fabric allowed on ${some(capIf)}` : null, ...count('wireless-controller vap', 'SSID')].filter(Boolean),
      switchCtl: [...anywhere('switch-controller managed-switch', 'managed FortiSwitch')],
      csf: enabled('system csf', 'Security Fabric enabled'),
      snmp: snmpOn ? [`SNMP agent enabled${access('snmp').length ? ` on ${some(access('snmp'))}` : ''}`] : [],
      saml: [...enabled('system saml', 'SAML single sign-on for administrators'), ...count('user saml', 'SAML server'),
        ...(one(cfg(global, 'system global'), 'admin-forticloud-sso-login') === 'enable' ? ['FortiCloud SSO admin login enabled'] : [])],
      radius: count('user radius', 'RADIUS server'),
      tacacs: count('user tacacs+', 'TACACS+ server'),
      ldap: count('user ldap', 'LDAP server'),
      fsso: count('user fsso', 'FSSO agent'),
      dhcp: count('system dhcp server', 'DHCP server'),
      dns: [dnsIf ? `DNS server on ${plural(dnsIf, 'interface')}` : null, ...profile('dnsfilter-profile', 'DNS filter profile')].filter(Boolean),
      ips: [...profile('ips-sensor', 'IPS sensor'), ...groupProfiles],
      antivirus: [...profile('av-profile', 'antivirus profile'), ...groupProfiles],
      sdwan: nodes.some((n) => one(cfg(n, 'system sdwan'), 'status') === 'enable') ? ['SD-WAN enabled'] : [],
      extender: [...anywhere('extension-controller extender', 'FortiExtender'), ...anywhere('extender-controller extender', 'FortiExtender')],
      vip: count('firewall vip', 'virtual IP'),
      automation: anywhere('system automation-stitch', 'automation stitch'),
    },
  };
}

// ---------- report ----------
const VECTOR = { N: 'over the network', A: 'from an adjacent network', L: 'with local access', P: 'with physical access' };
const PRIVS = { N: 'no login needed', L: 'needs a low-privileged account', H: 'needs an administrator account' };

// What an attacker needs, from the CVSS vector.
function needs(vector) {
  const kv = Object.fromEntries(String(vector || '').split('/').map((p) => p.split(':')));
  return [VECTOR[kv.AV], PRIVS[kv.PR], kv.UI && kv.UI !== 'N' ? 'needs a user to act' : null].filter(Boolean);
}

// Where the fix is, from the range that matched this version.
function fixFor(cve, v) {
  const hit = cve.ranges.filter((r) => inRange(v, r));
  const same = hit.find((r) => !r.branch && r.to && r.to[0] === v[0] && r.to[1] === v[1]);
  const branch = `${v[0]}.${v[1]}`;
  if (same) return same.toIncl ? `Upgrade to a ${branch} release newer than ${fmt(same.to)}` : `Upgrade to ${fmt(same.to)} or later`;
  if (hit.some((r) => r.branch)) return `No fix listed for the ${branch} branch: migrate to a fixed release (see the advisory)`;
  const next = hit.find((r) => r.to);
  return next ? `Upgrade to ${next.toIncl ? `a release newer than ${fmt(next.to)}` : `${fmt(next.to)} or later`}` : 'See the vendor advisory';
}

// Verdict for one CVE on one config:
//   exposed     - a feature the advisory names is in use
//   not-exposed - the advisory names features and none is in use
//   review      - the advisory names no feature this tool can look up
function assess(cve, f) {
  let hits = FEATURES.filter((x) => x.re.test(cve.description));
  // Cross-site scripting / request forgery with no feature named: the admin web interface.
  if (!hits.length && cve.cwe.some((w) => w === 'CWE-79' || w === 'CWE-352')) hits = FEATURES.filter((x) => x.id === 'gui');
  // The GUI and CLI exist everywhere: when the advisory also names an optional feature,
  // that feature decides (e.g. "SSL-VPN web interface" is about SSL-VPN, not the admin GUI).
  const specific = hits.filter((x) => !x.always);
  const judged = specific.length ? specific : hits;
  const components = judged.map((x) => {
    const evidence = x.test(f) || [];
    return { id: x.id, label: x.label, inUse: evidence.length > 0, evidence };
  });
  const verdict = !components.length ? 'review' : components.some((c) => c.inUse) ? 'exposed' : 'not-exposed';
  return { verdict, components };
}

const factsCache = new Map();
function factsOf(full) {
  const st = fs.statSync(full);
  const key = `${full}|${st.mtimeMs}|${st.size}`;
  if (!factsCache.has(key)) {
    if (factsCache.size > 200) factsCache.clear();
    factsCache.set(key, facts(fs.readFileSync(full, 'utf8')));
  }
  return factsCache.get(key);
}

const sevOf = (c) => (c.cvss && SEVERITIES.includes(c.cvss.severity) ? c.cvss.severity : 'info');
const VERDICT_ORDER = ['exposed', 'review', 'not-exposed'];

// CVEs of one backup file: those whose affected versions include the backup's FortiOS
// version, each with a verdict from the config.
function forBackup(full, cves) {
  const { device, f } = factsOf(full);
  const v = ver(device.version);
  if (!v || v[2] == null) return { device, error: 'The backup header has no FortiOS version' };
  const rows = [];
  for (const c of cves) {
    if (!c.ranges.some((r) => inRange(v, r))) continue;
    const { ranges, ...pub } = c;
    rows.push({ ...pub, severity: sevOf(c), ...assess(c, f), needs: needs(c.cvss?.vector), fix: fixFor(c, v) });
  }
  rows.sort((a, b) => VERDICT_ORDER.indexOf(a.verdict) - VERDICT_ORDER.indexOf(b.verdict)
    || (b.kev ? 1 : 0) - (a.kev ? 1 : 0) || (b.cvss?.score || 0) - (a.cvss?.score || 0) || b.published.localeCompare(a.published));
  const n = (fn) => rows.filter(fn).length;
  return {
    device,
    cves: rows,
    counts: {
      total: rows.length,
      exposed: n((r) => r.verdict === 'exposed'),
      review: n((r) => r.verdict === 'review'),
      notExposed: n((r) => r.verdict === 'not-exposed'),
      // Critical / high that are not ruled out by the config.
      urgent: n((r) => r.verdict !== 'not-exposed' && ['critical', 'high'].includes(r.severity)),
      exploited: n((r) => r.kev && r.verdict !== 'not-exposed'),
    },
  };
}

module.exports = { load, forBackup, facts, assess, textRanges, vendorRanges, nvdRanges, inRange, ver, slim, FEATURES };
