// Extracts inventory (interfaces, VPNs, VIPs, IP pools, policy routes, firewall
// policies, address and service objects, threat feeds) from a parsed FortiOS
// config, tagging every record with the VDOM it belongs to.
const { parse, toPlain } = require('./fgtparse');
const { feedOf, safeUrl } = require('./threatfeeds');

// Never copy secrets (PSKs, passwords, private keys) into the database.
const SECRET_KEY = /psk|secret|passw|private-key/i;
function redact(obj) {
  for (const [k, v] of Object.entries(obj)) {
    const first = Array.isArray(v) ? v[0] : v;
    if (SECRET_KEY.test(k) || (typeof first === 'string' && first.startsWith('ENC '))) {
      obj[k] = '<redacted>';
    } else if (v && typeof v === 'object' && !Array.isArray(v)) {
      redact(v);
    }
  }
  return obj;
}

const one = (e, k) => (e.settings[k] ? e.settings[k].join(' ') : null);
const list = (e, k) => e.settings[k] || null;

function maskToPrefix(mask) {
  return mask
    .split('.')
    .reduce((n, o) => n + (Number(o) >>> 0).toString(2).replace(/0/g, '').length, 0);
}

// "10.0.0.1 255.255.255.0" -> "10.0.0.1/24"; also accepts "10.0.0.0/24".
function toCidr(v) {
  if (!v || !v.length) return null;
  const [addr, mask] = v.length === 1 ? v[0].split('/') : v;
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(addr)) return null;
  const prefix = mask === undefined ? 32 : /^\d+$/.test(mask) ? Number(mask) : maskToPrefix(mask);
  return `${addr}/${prefix}`;
}

// Router policy subnets: each value is "addr/mask" on its own.
const subnets = (v) => v && v.map((x) => toCidr([x]) || x);

const findConfig = (node, path) => node.configs.find((c) => c.path === path);
const entriesOf = (node, path) => (findConfig(node, path) || { entries: [] }).entries;
const raw = (e) => redact(toPlain(e));

// Header: "config-version=FG1K1F-7.4.12-FW-build2902-260505:opmode=0:vdom=1:user=..."
function parseHeader(header) {
  const kv = Object.fromEntries(
    header.flatMap((h) => h.split(':')).map((p) => p.split('=')).filter((p) => p.length === 2)
  );
  const m = (kv['config-version'] || '').match(/^([^-]+)-([\d.]+)-FW-build(\d+)/) || [];
  return {
    model: m[1] || null,
    version: m[2] || null,
    build: m[3] ? Number(m[3]) : null,
    multiVdom: kv.vdom === '1',
    confFileVer: kv.conf_file_ver || null,
  };
}

function extract(text) {
  const { header, root } = parse(text);
  const info = parseHeader(header);

  // Global scope + one config node per VDOM (single-VDOM configs: everything is "root").
  let global = root;
  const vdoms = [];
  if (info.multiVdom) {
    global = findConfig(root, 'global') || root;
    for (const c of root.configs.filter((c) => c.path === 'vdom')) {
      for (const e of c.entries) if (e.configs.length) vdoms.push({ name: e.name, node: e });
    }
  } else {
    vdoms.push({ name: 'root', node: root });
  }

  const sysGlobal = findConfig(global, 'system global');
  const device = { ...info, hostname: sysGlobal ? one(sysGlobal, 'hostname') : null };

  // Interfaces live in global scope; their VDOM comes from `set vdom`.
  const interfaces = entriesOf(global, 'system interface').map((e) => ({
    vdom: one(e, 'vdom') || 'root',
    name: e.name,
    type: one(e, 'type') || (e.settings.vlanid ? 'vlan' : null),
    alias: one(e, 'alias'),
    description: one(e, 'description'),
    status: one(e, 'status') || 'up',
    mode: one(e, 'mode') || 'static',
    ip: toCidr(list(e, 'ip')),
    allowaccess: list(e, 'allowaccess'),
    role: one(e, 'role'),
    parent: one(e, 'interface'),
    vlanid: e.settings.vlanid ? Number(one(e, 'vlanid')) : null,
    raw: raw(e),
  }));

  const phase1 = [];
  const phase2 = [];
  const vips = [];
  const ippools = [];
  const sslvpn = [];
  const routerPolicies = [];
  const policies = [];
  const addresses = [];
  const addrgrps = [];
  const services = [];
  const servicegrps = [];
  const refs = [];
  const feeds = [];

  // Threat feeds: global ones are visible in every VDOM, a VDOM's own one hides a global
  // one with the same name. Single-VDOM configs keep them under "root".
  const feedRow = (e, vdom) => {
    const f = feedOf(e, vdom);
    const r = raw(e);
    if (r.resource) r.resource = safeUrl(r.resource).url;
    if (r.username) r.username = '<redacted>';
    return {
      vdom, name: e.name, type: f.type, category: f.category, status: f.status, update_method: f.updateMethod,
      resource: f.resource, refresh_rate: f.refreshRate, auth: f.auth, server_identity_check: f.serverIdentityCheck,
      comments: f.comments || null, raw: r,
    };
  };
  const globalFeeds = entriesOf(global, 'system external-resource').map((e) => feedRow(e, info.multiVdom ? 'global' : 'root'));
  feeds.push(...globalFeeds);

  for (const { name: vdom, node } of vdoms) {
    for (const [path, kind] of [['vpn ipsec phase1-interface', 'interface'], ['vpn ipsec phase1', 'policy']]) {
      for (const e of entriesOf(node, path)) {
        phase1.push({
          vdom, kind, name: e.name,
          type: one(e, 'type') || 'static',
          interface: one(e, 'interface'),
          remote_gw: one(e, 'remote-gw'),
          ike_version: Number(one(e, 'ike-version') || 1),
          mode: one(e, 'mode') || 'main',
          proposal: list(e, 'proposal'),
          dhgrp: list(e, 'dhgrp'),
          comments: one(e, 'comments'),
          raw: raw(e),
        });
      }
    }
    for (const [path, kind] of [['vpn ipsec phase2-interface', 'interface'], ['vpn ipsec phase2', 'policy']]) {
      for (const e of entriesOf(node, path)) {
        phase2.push({
          vdom, kind, name: e.name,
          phase1name: one(e, 'phase1name'),
          src_subnet: toCidr(list(e, 'src-subnet')),
          dst_subnet: toCidr(list(e, 'dst-subnet')),
          src_name: one(e, 'src-name'),
          dst_name: one(e, 'dst-name'),
          proposal: list(e, 'proposal'),
          dhgrp: list(e, 'dhgrp'),
          pfs: one(e, 'pfs') || 'enable',
          comments: one(e, 'comments'),
          raw: raw(e),
        });
      }
    }
    for (const e of entriesOf(node, 'firewall vip')) {
      vips.push({
        vdom, name: e.name,
        type: one(e, 'type') || 'static-nat',
        extip: one(e, 'extip'),
        mappedip: list(e, 'mappedip'),
        extintf: one(e, 'extintf') || 'any',
        portforward: one(e, 'portforward') === 'enable',
        protocol: one(e, 'protocol') || (one(e, 'portforward') === 'enable' ? 'tcp' : null),
        extport: one(e, 'extport'),
        mappedport: one(e, 'mappedport'),
        comment: one(e, 'comment'),
        raw: raw(e),
      });
    }
    for (const e of entriesOf(node, 'firewall ippool')) {
      ippools.push({
        vdom, name: e.name,
        type: one(e, 'type') || 'overload',
        startip: one(e, 'startip'),
        endip: one(e, 'endip'),
        source_startip: one(e, 'source-startip'),
        source_endip: one(e, 'source-endip'),
        comments: one(e, 'comments'),
        raw: raw(e),
      });
    }
    const own = info.multiVdom ? entriesOf(node, 'system external-resource').map((e) => feedRow(e, vdom)) : [];
    feeds.push(...own);
    const visible = [...own, ...globalFeeds.filter((g) => !own.some((f) => f.name === g.name))];

    // What each object name in this VDOM is, so references can be typed.
    const kinds = new Map(visible.map((f) => [f.name, 'external']));
    for (const [path, kind] of [['firewall address', 'address'], ['firewall addrgrp', 'addrgrp'],
      ['firewall vip', 'vip'], ['firewall vipgrp', 'vipgrp'], ['firewall ippool', 'ippool']]) {
      for (const e of entriesOf(node, path)) kinds.set(e.name, kind);
    }
    // Services have their own namespace: a service may share its name with an address.
    const svcKinds = new Map();
    for (const [path, kind] of [['firewall service custom', 'service'], ['firewall service group', 'servicegrp']]) {
      for (const e of entriesOf(node, path)) svcKinds.set(e.name, kind);
    }
    const ref = (refType, refId, field, names, map = kinds) => {
      for (const name of names || []) {
        refs.push({ vdom, name, kind: map.get(name) || 'unknown', ref_type: refType, ref_id: String(refId), field });
      }
    };

    for (const e of entriesOf(node, 'firewall address')) {
      const type = one(e, 'type') || 'ipmask';
      addresses.push({
        vdom, name: e.name, type,
        // An ipmask address without a subnet is 0.0.0.0/0 (e.g. "all").
        subnet: type === 'ipmask' || type === 'interface-subnet' ? toCidr(list(e, 'subnet')) || '0.0.0.0/0' : null,
        start_ip: one(e, 'start-ip'),
        end_ip: one(e, 'end-ip'),
        fqdn: one(e, 'fqdn'),
        country: one(e, 'country'),
        interface: one(e, 'associated-interface') || one(e, 'interface'),
        comment: one(e, 'comment'),
        raw: raw(e),
      });
    }
    for (const e of entriesOf(node, 'firewall addrgrp')) {
      addrgrps.push({ vdom, name: e.name, members: list(e, 'member'), comment: one(e, 'comment'), raw: raw(e) });
      ref('addrgrp', e.name, 'member', list(e, 'member'));
    }
    for (const e of entriesOf(node, 'firewall vipgrp')) ref('vipgrp', e.name, 'member', list(e, 'member'));

    const num = (e, k) => (e.settings[k] ? Number(one(e, k)) : null);
    for (const e of entriesOf(node, 'firewall service custom')) {
      services.push({
        vdom, name: e.name,
        protocol: one(e, 'protocol') || 'TCP/UDP/SCTP',
        tcp_portrange: list(e, 'tcp-portrange'),
        udp_portrange: list(e, 'udp-portrange'),
        sctp_portrange: list(e, 'sctp-portrange'),
        protocol_number: num(e, 'protocol-number'),
        icmptype: num(e, 'icmptype'),
        icmpcode: num(e, 'icmpcode'),
        category: one(e, 'category'),
        proxy: one(e, 'proxy') === 'enable',
        comment: one(e, 'comment'),
        raw: raw(e),
      });
    }
    for (const e of entriesOf(node, 'firewall service group')) {
      servicegrps.push({ vdom, name: e.name, members: list(e, 'member'), comment: one(e, 'comment'), raw: raw(e) });
      ref('servicegrp', e.name, 'member', list(e, 'member'), svcKinds);
    }

    // Security profiles that use threat feeds (web / DNS filter by category number,
    // antivirus by name), and which policies / profile groups apply each profile.
    const byCategory = new Map(visible.filter((f) => f.category).map((f) => [f.category, f.name]));
    for (const [kind, path, sub] of [['webfilter', 'webfilter profile', 'ftgd-wf'], ['dnsfilter', 'dnsfilter profile', 'ftgd-dns']]) {
      for (const p of entriesOf(node, path)) {
        const ftgd = findConfig(p, sub);
        const names = (ftgd ? entriesOf(ftgd, 'filters') : []).map((f) => byCategory.get(Number(one(f, 'category')))).filter(Boolean);
        ref(kind, p.name, 'category', [...new Set(names)]);
      }
    }
    const malware = visible.filter((f) => f.type === 'malware').map((f) => f.name);
    for (const p of entriesOf(node, 'antivirus profile')) {
      ref('antivirus', p.name, 'external-blocklist', one(p, 'external-blocklist-enable-all') === 'enable' ? malware : list(p, 'external-blocklist'));
    }
    const profKinds = new Map();
    for (const [kind, path] of [['webfilter', 'webfilter profile'], ['dnsfilter', 'dnsfilter profile'], ['antivirus', 'antivirus profile'], ['profile-group', 'firewall profile-group']]) {
      profKinds.set(kind, new Set(entriesOf(node, path).map((e) => e.name)));
    }
    const profileRefs = (refType, refId, holder) => {
      for (const [kind, key] of [['webfilter', 'webfilter-profile'], ['dnsfilter', 'dnsfilter-profile'], ['antivirus', 'av-profile']]) {
        const name = one(holder, key);
        if (name) ref(refType, refId, key, [name], new Map([[name, profKinds.get(kind).has(name) ? kind : 'unknown']]));
      }
    };
    for (const g of entriesOf(node, 'firewall profile-group')) profileRefs('profile-group', g.name, g);

    entriesOf(node, 'firewall policy').forEach((e, seq) => {
      policies.push({
        vdom, policyid: Number(e.name), seq,
        name: one(e, 'name'),
        uuid: one(e, 'uuid'),
        status: one(e, 'status') || 'enable',
        action: one(e, 'action') || 'deny',
        srcintf: list(e, 'srcintf'),
        dstintf: list(e, 'dstintf'),
        srcaddr: list(e, 'srcaddr'),
        dstaddr: list(e, 'dstaddr'),
        service: list(e, 'service'),
        internet_service: list(e, 'internet-service-name'),
        schedule: one(e, 'schedule'),
        nat: one(e, 'nat') === 'enable',
        poolname: list(e, 'poolname'),
        groups: list(e, 'groups'),
        users: list(e, 'users'),
        logtraffic: one(e, 'logtraffic') || 'utm',
        comments: one(e, 'comments'),
        raw: raw(e),
      });
      for (const f of ['srcaddr', 'dstaddr', 'poolname']) ref('policy', e.name, f, list(e, f));
      ref('policy', e.name, 'service', list(e, 'service'), svcKinds);
      if (one(e, 'utm-status') === 'enable') {
        const grp = one(e, 'profile-type') === 'group' ? one(e, 'profile-group') : null;
        if (grp) ref('policy', e.name, 'profile-group', [grp], new Map([[grp, profKinds.get('profile-group').has(grp) ? 'profile-group' : 'unknown']]));
        else profileRefs('policy', e.name, e);
      }
    });

    for (const e of entriesOf(node, 'router policy')) {
      for (const f of ['srcaddr', 'dstaddr']) ref('routepolicy', e.name, f, list(e, f));
      routerPolicies.push({
        vdom, seq_num: Number(e.name),
        status: one(e, 'status') || 'enable',
        action: one(e, 'action') || 'permit',
        input_device: list(e, 'input-device'),
        src: subnets(list(e, 'src')),
        srcaddr: list(e, 'srcaddr'),
        dst: subnets(list(e, 'dst')),
        dstaddr: list(e, 'dstaddr'),
        protocol: Number(one(e, 'protocol') || 0),
        start_port: e.settings['start-port'] ? Number(one(e, 'start-port')) : null,
        end_port: e.settings['end-port'] ? Number(one(e, 'end-port')) : null,
        gateway: one(e, 'gateway'),
        output_device: one(e, 'output-device'),
        comments: one(e, 'comments'),
        raw: raw(e),
      });
    }
    const ssl = findConfig(node, 'vpn ssl settings');
    if (ssl) {
      sslvpn.push({
        vdom,
        status: one(ssl, 'status') || 'enable',
        port: one(ssl, 'port') ? Number(one(ssl, 'port')) : null,
        source_interface: list(ssl, 'source-interface'),
        servercert: one(ssl, 'servercert'),
        raw: raw(ssl),
      });
    }
  }

  return { device, vdoms: vdoms.map((v) => v.name), interfaces, phase1, phase2, vips, ippools, sslvpn, routerPolicies,
    policies, addresses, addrgrps, services, servicegrps, feeds, refs };
}

module.exports = { extract, toCidr, SECRET_KEY };
