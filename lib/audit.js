// Security audit of a FortiOS backup: flags settings that weaken the firewall's own
// protection (management exposure, admin accounts, weak crypto, permissive policies, logging).
//
// Backups only contain settings that differ from the default, so a missing `set` means
// the FortiOS default applies; every check below is written with that in mind.
// Findings never contain secret values, only object names and setting names.
const { X509Certificate } = require('node:crypto');
const { parse } = require('./fgtparse');

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

// Every check the audit runs, so the UI can also list what passed.
const CHECKS = {
  'admin-trusthost': {
    severity: 'high', category: 'Administrators', title: 'Administrator without trusted hosts',
    why: 'The account can log in from any IP address that reaches a management interface.',
    fix: 'config system admin › edit <name> › set trusthost1 <mgmt subnet> <mask>',
  },
  'apiuser-trusthost': {
    severity: 'high', category: 'Administrators', title: 'REST API user without trusted hosts',
    why: 'Anyone holding the API key can use it from any IP address.',
    fix: 'config system api-user › edit <name> › config trusthost › edit 1 › set ipv4-trusthost <subnet> <mask>',
  },
  'apiuser-superadmin': {
    severity: 'medium', category: 'Administrators', title: 'REST API user with super_admin profile',
    why: 'A leaked API key gives full read-write control of the device.',
    fix: 'Give API users a dedicated profile with only the access they need (read-only for backups).',
  },
  'admin-default-name': {
    severity: 'medium', category: 'Administrators', title: 'Default "admin" account exists',
    why: 'The well-known account name is the first target of brute-force attempts.',
    fix: 'Create a named super-admin, then delete or rename "admin".',
  },
  'admin-no-mfa': {
    severity: 'medium', category: 'Administrators', title: 'Local administrator without two-factor authentication',
    why: 'A single stolen or guessed password is enough to log in.',
    fix: 'config system admin › edit <name> › set two-factor fortitoken|email|sms (or use remote auth with MFA).',
  },
  'password-policy': {
    severity: 'medium', category: 'Administrators', title: 'Administrator password policy disabled',
    why: 'Short or simple admin passwords are accepted and never expire.',
    fix: 'config system password-policy › set status enable › set minimum-length 12 …',
  },
  'lockout': {
    severity: 'low', category: 'Administrators', title: 'Weak login lockout',
    why: 'Many failed logins are allowed before the source IP is locked out, or the lockout is very short.',
    fix: 'config system global › set admin-lockout-threshold 3 › set admin-lockout-duration 300',
  },
  'admin-timeout': {
    severity: 'low', category: 'Administrators', title: 'Long admin idle timeout',
    why: 'Unattended admin sessions stay logged in for a long time.',
    fix: 'config system global › set admintimeout 15 (minutes or less)',
  },
  'local-in-missing': {
    severity: 'medium', category: 'Management access', title: 'No local-in policy',
    why: 'Traffic to the firewall itself (admin GUI/SSH, SSL-VPN, IKE, SNMP, BGP…) is only limited by interface allowaccess and trusted hosts.',
    fix: 'config firewall local-in-policy: allow management only from admin subnets and deny the rest on WAN interfaces.',
  },
  'mgmt-insecure-proto': {
    severity: 'high', category: 'Management access', title: 'Clear-text management protocol enabled',
    why: 'HTTP and Telnet send admin credentials unencrypted.',
    fix: 'config system interface › edit <port> › set allowaccess (remove http / telnet)',
  },
  'mgmt-on-wan': {
    severity: 'critical', category: 'Management access', title: 'Administrative access on an internet-facing interface',
    why: 'The admin GUI / SSH is reachable from the internet; most FortiOS mass exploits target exactly this.',
    fix: 'Remove https/ssh/http/telnet/snmp/fgfm from allowaccess on WAN interfaces; manage over a dedicated or VPN interface.',
  },
  'https-redirect': {
    severity: 'low', category: 'Management access', title: 'HTTP to HTTPS redirect disabled',
    why: 'Admins opening http:// may log in without TLS where HTTP access is allowed.',
    fix: 'config system global › set admin-https-redirect enable',
  },
  'admin-tls': {
    severity: 'medium', category: 'Crypto', title: 'Admin GUI allows old TLS versions',
    why: 'TLS 1.0 / 1.1 are deprecated and vulnerable to downgrade attacks.',
    fix: 'config system global › set admin-https-ssl-versions tlsv1-2 tlsv1-3',
  },
  'strong-crypto': {
    severity: 'medium', category: 'Crypto', title: 'Strong crypto disabled',
    why: 'Weak ciphers and hashes are accepted for HTTPS and SSH administration.',
    fix: 'config system global › set strong-crypto enable',
  },
  'maintainer': {
    severity: 'low', category: 'Administrators', title: 'Maintainer account enabled',
    why: 'Anyone with console access and the device serial can reset the admin password (default behaviour).',
    fix: 'config system global › set admin-maintainer disable (only where console access is not physically controlled).',
  },
  'private-data-encryption': {
    severity: 'low', category: 'Crypto', title: 'Private data encryption disabled',
    why: 'Secrets in config backups are encrypted with a fixed key shared by all FortiGates.',
    fix: 'config system global › set private-data-encryption enable (keep the key safe: it is needed to restore backups).',
  },
  'snmp-community': {
    severity: 'medium', category: 'Management access', title: 'Weak SNMP community',
    why: 'SNMP v1/v2c sends the community in clear text; "public"/"private" or an unrestricted host list lets anyone query the device.',
    fix: 'Use SNMPv3 with authentication + privacy, or restrict community hosts to the monitoring servers.',
  },
  'ipsec-weak': {
    severity: 'medium', category: 'VPN', title: 'IPsec tunnel with weak crypto',
    why: 'DES, 3DES, MD5, SHA-1 or Diffie-Hellman groups 1/2/5 can be broken or are deprecated.',
    fix: 'Use AES-GCM or AES with SHA-256+ and DH group 14 or higher (19/20/21 preferred).',
  },
  'ipsec-aggressive': {
    severity: 'medium', category: 'VPN', title: 'IKEv1 aggressive mode with pre-shared key',
    why: 'Aggressive mode exposes a hash of the PSK that can be cracked offline.',
    fix: 'Use main mode or IKEv2, or certificate authentication.',
  },
  'sslvpn-tls': {
    severity: 'medium', category: 'VPN', title: 'SSL-VPN allows old TLS versions',
    why: 'TLS 1.0 / 1.1 are deprecated.',
    fix: 'config vpn ssl settings › set ssl-min-proto-ver tls1-2',
  },
  'sslvpn-enabled': {
    severity: 'info', category: 'VPN', title: 'SSL-VPN portal is enabled',
    why: 'The SSL-VPN web portal has been the target of several critical FortiOS vulnerabilities; it must be patched promptly.',
    fix: 'Keep firmware current, restrict source addresses / geo where possible, or move to IPsec (dial-up) VPN.',
  },
  'policy-any-any': {
    severity: 'high', category: 'Firewall policy', title: 'Accept policy from any source to any destination on all services',
    why: 'The policy allows every service between every address on its interfaces.',
    fix: 'Narrow source, destination and service to what is really needed.',
  },
  'policy-wan-inbound-any': {
    severity: 'high', category: 'Firewall policy', title: 'Inbound policy from the internet allows any source',
    why: 'Everything on the internet can reach the destination on the allowed services.',
    fix: 'Restrict the source (geo / known peers), the services, and apply IPS.',
  },
  'policy-nolog': {
    severity: 'low', category: 'Logging', title: 'Accept policy without traffic logging',
    why: 'Allowed connections through this policy leave no trace for incident response.',
    fix: 'config firewall policy › edit <id> › set logtraffic all (or utm)',
  },
  'vip-risky-port': {
    severity: 'high', category: 'Firewall policy', title: 'VIP publishes a high-risk service',
    why: 'RDP, SMB, Telnet, SSH, databases and similar services should not be published to the internet.',
    fix: 'Put the service behind VPN, or restrict the source in the policy using the VIP.',
  },
  'vip-all-ports': {
    severity: 'medium', category: 'Firewall policy', title: 'VIP forwards all ports',
    why: 'Without port forwarding, every port of the internal host is published (only the policy limits it).',
    fix: 'config firewall vip › edit <name> › set portforward enable › set extport / mappedport',
  },
  'log-remote': {
    severity: 'medium', category: 'Logging', title: 'No remote logging',
    why: 'Logs stay on the device only: they are lost on failure and can be erased by an attacker.',
    fix: 'Enable FortiAnalyzer, FortiGate Cloud or syslog (config log fortianalyzer|syslogd setting › set status enable).',
  },
  'ntp': {
    severity: 'low', category: 'Logging', title: 'NTP synchronisation disabled',
    why: 'Wrong clocks make log correlation and certificate checks unreliable.',
    fix: 'config system ntp › set ntpsync enable',
  },
  'asymroute': {
    severity: 'high', category: 'Firewall policy', title: 'Asymmetric routing enabled (stateful inspection off)',
    why: 'With asymroute enabled the VDOM stops tracking sessions: return traffic is allowed without a matching session and security profiles are skipped.',
    fix: 'config system settings › set asymroute disable (fix the routing instead)',
  },
  'policy-shadowed': {
    severity: 'medium', category: 'Firewall policy', title: 'Shadowed policy (never matched)',
    why: 'A policy above it already matches all of its traffic, so this policy never takes effect and may hide a wrong assumption about what is allowed or denied.',
    fix: 'Move the policy above the broader one, or delete it if it is no longer needed.',
  },
  'policy-wan-noprofile': {
    severity: 'medium', category: 'Firewall policy', title: 'Inbound policy from the internet without IPS',
    why: 'Published services are reachable from the internet without intrusion prevention, so exploit attempts against them are not inspected.',
    fix: 'config firewall policy › edit <id> › set utm-status enable › set ips-sensor <profile>',
  },
  'ha-heartbeat': {
    severity: 'low', category: 'High availability', title: 'HA heartbeat without authentication or encryption',
    why: 'Anyone on the heartbeat network can read or tamper with cluster synchronisation (including configuration).',
    fix: 'config system ha › set authentication enable › set encryption enable',
  },
  'ldap-cleartext': {
    severity: 'medium', category: 'Authentication', title: 'LDAP server without TLS',
    why: 'User and bind passwords are sent in clear text to the LDAP server.',
    fix: 'config user ldap › edit <name> › set secure ldaps (or starttls) › set ca-cert <CA>',
  },
  'vpn-user-no-mfa': {
    severity: 'medium', category: 'VPN', title: 'VPN user without two-factor authentication',
    why: 'A leaked or guessed password gives network access from anywhere; credential stuffing against VPN portals is common.',
    fix: 'config user local › edit <name> › set two-factor fortitoken|email|sms (or authenticate VPN users against an IdP with MFA).',
  },
  'dialup-psk': {
    severity: 'medium', category: 'VPN', title: 'Dial-up IPsec with pre-shared key',
    why: 'Every client shares one key; whoever has it (a former employee, a stolen laptop) can try to connect.',
    fix: 'Use certificates or EAP / XAuth with MFA for dial-up clients, and restrict peer IDs.',
  },
  'sslvpn-webmode': {
    severity: 'low', category: 'VPN', title: 'SSL-VPN web mode enabled',
    why: 'Web mode exposes more attack surface than tunnel mode and has been involved in several FortiOS vulnerabilities.',
    fix: 'config vpn ssl web portal › edit <portal> › set web-mode disable (use tunnel mode).',
  },
  'default-cert': {
    severity: 'low', category: 'Crypto', title: 'Factory / self-signed certificate in use',
    why: 'Users learn to click through certificate warnings, which makes man-in-the-middle attacks easy to miss.',
    fix: 'Install a certificate from a trusted CA: set admin-server-cert (system global) / servercert (vpn ssl settings).',
  },
  'cert-expired': {
    severity: 'medium', category: 'Crypto', title: 'Expired certificate',
    why: 'Services using it show warnings or fail; an expired CA can break VPN or SSL inspection.',
    fix: 'Renew the certificate and replace it where it is used, or delete it if unused.',
  },
  'cert-expiring': {
    severity: 'low', category: 'Crypto', title: 'Certificate expires within 30 days',
    why: 'Services using it will break or show warnings soon.',
    fix: 'Renew the certificate before it expires.',
  },
  'cert-weak': {
    severity: 'medium', category: 'Crypto', title: 'Weak certificate (SHA-1 / MD5 or short key)',
    why: 'SHA-1/MD5 signatures and RSA keys under 2048 bits can be forged or broken.',
    fix: 'Re-issue with SHA-256 or better and RSA 2048+ / ECDSA P-256+.',
  },
  'firmware-eos': {
    severity: 'high', category: 'Firmware', title: 'Firmware branch out of support',
    why: 'FortiOS 6.x and older no longer receive security fixes.',
    fix: 'Upgrade to a supported FortiOS 7.x release following the upgrade path.',
  },
};

// ---------- helpers ----------
const findConfig = (node, path) => node.configs.find((c) => c.path === path);
const entriesOf = (node, path) => (findConfig(node, path) || { entries: [] }).entries;
const one = (e, k) => (e && e.settings[k] ? e.settings[k].join(' ') : null);
const list = (e, k) => (e && e.settings[k]) || [];

function parseHeader(header) {
  const kv = Object.fromEntries(
    header.flatMap((h) => h.split(':')).map((p) => p.split('=')).filter((p) => p.length === 2)
  );
  const m = (kv['config-version'] || '').match(/^([^-]+)-([\d.]+)-FW-build(\d+)/) || [];
  return { model: m[1] || null, version: m[2] || null, multiVdom: kv.vdom === '1' };
}

const ipNum = (ip) => ip.split('.').reduce((n, o) => n * 256 + Number(o), 0);
const inNet = (ip, net, bits) => Math.floor(ipNum(ip) / 2 ** (32 - bits)) === Math.floor(ipNum(net) / 2 ** (32 - bits));
const PRIVATE = [['10.0.0.0', 8], ['172.16.0.0', 12], ['192.168.0.0', 16], ['100.64.0.0', 10], ['169.254.0.0', 16], ['127.0.0.0', 8], ['0.0.0.0', 8]];
const isPublicIp = (ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip) && !PRIVATE.some(([n, b]) => inNet(ip, n, b));

// "0.0.0.0 0.0.0.0", "0.0.0.0/0" and "::/0" all mean "anywhere".
const isAnyNet = (v) => !v || /^0\.0\.0\.0(\s+0\.0\.0\.0|\/0)?$/.test(v.trim()) || /^::\/0$/.test(v.trim());

const MGMT = ['https', 'ssh', 'http', 'telnet', 'snmp', 'fgfm'];
const RISKY_PORTS = { 21: 'FTP', 22: 'SSH', 23: 'Telnet', 135: 'MS-RPC', 139: 'NetBIOS', 445: 'SMB', 1433: 'MS-SQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 5985: 'WinRM', 5986: 'WinRM', 6379: 'Redis', 9200: 'Elasticsearch', 27017: 'MongoDB' };
const WEAK_ALGOS = /(^|-)(des|3des|md5|sha1)(-|$)/;
const WEAK_DH = new Set(['1', '2', '5']);
const DEFAULT_CERTS = new Set(['self-sign', 'Fortinet_Factory', 'Fortinet_GUI_Server']);
const DAY = 86400000;

// DER OIDs of SHA-1 / MD5 signature algorithms (RSA and ECDSA).
const WEAK_SIG_OIDS = [
  Buffer.from('06092a864886f70d010105', 'hex'), // sha1WithRSAEncryption
  Buffer.from('06092a864886f70d010104', 'hex'), // md5WithRSAEncryption
  Buffer.from('06072a8648ce3d0401', 'hex'),     // ecdsa-with-SHA1
];

// Expiry, signature hash and key size of a PEM certificate stored in the config.
function certIssues(pem, now) {
  let cert;
  try { cert = new X509Certificate(pem); } catch { return null; }
  const out = [];
  const to = new Date(cert.validTo);
  if (to < now) out.push({ check: 'cert-expired', detail: `expired ${to.toISOString().slice(0, 10)}` });
  else if (to - now < 30 * DAY) out.push({ check: 'cert-expiring', detail: `expires ${to.toISOString().slice(0, 10)}` });
  const weak = [];
  if (WEAK_SIG_OIDS.some((oid) => cert.raw.includes(oid))) weak.push('SHA-1/MD5 signature');
  const bits = cert.publicKey.asymmetricKeyDetails?.modulusLength;
  if (cert.publicKey.asymmetricKeyType === 'rsa' && bits && bits < 2048) weak.push(`RSA ${bits} bit`);
  if (weak.length) out.push({ check: 'cert-weak', detail: weak.join(', ') });
  return out;
}

// True when every item of `b` is in `a`, or `a` contains the wildcard.
const covers = (a, b, any) => a.includes(any) || (b.length > 0 && b.every((x) => a.includes(x)));

// Policy A matches everything policy B matches (by object name; no address arithmetic,
// so only clear-cut cases are reported).
function shadows(a, b) {
  const L = (p, k) => list(p, k);
  if (['users', 'groups', 'fsso-groups', 'internet-service-name', 'internet-service-src-name'].some((k) => L(a, k).length)) return false;
  if (['internet-service', 'internet-service-src', 'srcaddr-negate', 'dstaddr-negate', 'service-negate'].some((k) => one(a, k) === 'enable')) return false;
  if ((one(a, 'schedule') || 'always') !== 'always') return false;
  if (!covers(L(a, 'srcintf'), L(b, 'srcintf'), 'any') || !covers(L(a, 'dstintf'), L(b, 'dstintf'), 'any')) return false;
  // Source / destination: whichever families B uses, A must cover too.
  const fam = (k) => L(b, k).length > 0;
  if (!fam('srcaddr') && !fam('srcaddr6') && one(b, 'internet-service-src') !== 'enable') return false;
  if (one(b, 'internet-service-src') === 'enable' && !L(a, 'srcaddr').includes('all')) return false;
  if (fam('srcaddr') && !covers(L(a, 'srcaddr'), L(b, 'srcaddr'), 'all')) return false;
  if (fam('srcaddr6') && !covers(L(a, 'srcaddr6'), L(b, 'srcaddr6'), 'all')) return false;
  if (one(b, 'internet-service') === 'enable') {
    if (!L(a, 'dstaddr').includes('all')) return false;
  } else {
    if (!fam('dstaddr') && !fam('dstaddr6')) return false;
    if (fam('dstaddr') && !covers(L(a, 'dstaddr'), L(b, 'dstaddr'), 'all')) return false;
    if (fam('dstaddr6') && !covers(L(a, 'dstaddr6'), L(b, 'dstaddr6'), 'all')) return false;
  }
  return one(b, 'internet-service') === 'enable' ? L(a, 'service').includes('ALL') || !L(a, 'service').length
    : covers(L(a, 'service'), L(b, 'service'), 'ALL');
}

// ---------- audit ----------
function audit(text) {
  const { header, root } = parse(text);
  const info = parseHeader(header);

  let global = root;
  const vdoms = [];
  if (info.multiVdom) {
    global = findConfig(root, 'global') || root;
    // VDOMs are declared in an empty `config vdom` block first and filled in a later one;
    // keep the block with content, but also VDOMs that have none.
    const byName = new Map();
    for (const c of root.configs.filter((c) => c.path === 'vdom')) {
      for (const e of c.entries) if (!byName.has(e.name) || e.configs.length) byName.set(e.name, e);
    }
    for (const [name, node] of byName) vdoms.push({ name, node });
  } else {
    vdoms.push({ name: 'root', node: root });
  }

  const sysGlobal = findConfig(global, 'system global') || { settings: {}, configs: [], entries: [] };
  const g = (k) => one(sysGlobal, k);
  const findings = [];
  const add = (check, { vdom = null, object = null, detail = '' } = {}) => {
    const c = CHECKS[check];
    findings.push({ check, severity: c.severity, category: c.category, title: c.title, vdom, object, detail });
  };

  // ----- administrators -----
  const admins = entriesOf(global, 'system admin');
  for (const a of admins) {
    const hosts = Object.entries(a.settings)
      .filter(([k]) => /^(ip6-)?trusthost\d+$/.test(k))
      .map(([, v]) => v.join(' '))
      .filter((v) => !isAnyNet(v));
    const profile = one(a, 'accprofile') || '';
    if (!hosts.length) add('admin-trusthost', { object: a.name, detail: `profile ${profile || '(none)'}` });
    if (a.name === 'admin') add('admin-default-name', { object: a.name });
    const remote = one(a, 'remote-auth') === 'enable' || one(a, 'wildcard') === 'enable';
    const mfa = one(a, 'two-factor');
    if (!remote && (!mfa || mfa === 'disable')) add('admin-no-mfa', { object: a.name, detail: `profile ${profile || '(none)'}` });
  }

  for (const u of entriesOf(global, 'system api-user')) {
    const th = findConfig(u, 'trusthost');
    const hosts = th ? th.entries.map((e) => one(e, 'ipv4-trusthost') || one(e, 'ipv6-trusthost')).filter((v) => !isAnyNet(v)) : [];
    if (!hosts.length) add('apiuser-trusthost', { object: u.name, detail: `profile ${one(u, 'accprofile') || '(none)'}` });
    if (one(u, 'accprofile') === 'super_admin') add('apiuser-superadmin', { object: u.name });
  }

  const pw = findConfig(global, 'system password-policy');
  if (!pw || one(pw, 'status') !== 'enable') add('password-policy');

  const threshold = Number(g('admin-lockout-threshold') || 3);
  const duration = Number(g('admin-lockout-duration') || 60);
  if (threshold > 5 || duration < 60) add('lockout', { detail: `threshold ${threshold} attempts, lockout ${duration} s` });

  const timeout = Number(g('admintimeout') || 5);
  if (timeout > 30) add('admin-timeout', { detail: `${timeout} minutes` });

  if (g('admin-maintainer') !== 'disable') add('maintainer');

  // ----- global crypto / management settings -----
  if (g('admin-https-redirect') === 'disable') add('https-redirect');
  if (g('strong-crypto') === 'disable') add('strong-crypto');
  const tls = list(sysGlobal, 'admin-https-ssl-versions');
  const oldTls = tls.filter((v) => /tlsv1-[01]$|sslv3/.test(v));
  if (oldTls.length) add('admin-tls', { detail: oldTls.join(', ') });
  if (g('private-data-encryption') !== 'enable') add('private-data-encryption');

  // ----- interfaces: management exposure -----
  for (const i of entriesOf(global, 'system interface')) {
    const access = list(i, 'allowaccess');
    if (!access.length) continue;
    const ip = (one(i, 'ip') || '').split(/[\s/]/)[0];
    const mode = one(i, 'mode');
    const wan = one(i, 'role') === 'wan' || mode === 'dhcp' || mode === 'pppoe' || isPublicIp(ip);
    const vdom = one(i, 'vdom') || 'root';
    const clear = access.filter((a) => a === 'http' || a === 'telnet');
    if (clear.length) add('mgmt-insecure-proto', { vdom, object: i.name, detail: clear.join(', ') });
    const mgmt = access.filter((a) => MGMT.includes(a));
    if (wan && mgmt.length) {
      const why = one(i, 'role') === 'wan' ? 'role wan' : mode === 'dhcp' || mode === 'pppoe' ? `mode ${mode}` : `public IP ${ip}`;
      add('mgmt-on-wan', { vdom, object: i.name, detail: `${mgmt.join(', ')} (${why})` });
    }
  }

  // ----- SNMP -----
  for (const c of entriesOf(global, 'system snmp community')) {
    if (one(c, 'status') === 'disable') continue;
    const name = one(c, 'name') || '';
    const hosts = entriesOf(c, 'hosts').map((h) => one(h, 'ip')).filter((v) => !isAnyNet(v));
    const reasons = [];
    if (/^(public|private)$/i.test(name)) reasons.push(`community "${name}"`);
    if (!hosts.length) reasons.push('no host restriction');
    if (reasons.length) add('snmp-community', { object: name || c.name, detail: reasons.join(', ') });
  }

  // ----- logging / time -----
  const logOn = (p) => [global, ...vdoms.map((v) => v.node)].some((n) => {
    const s = findConfig(n, p);
    return s && one(s, 'status') === 'enable';
  });
  const remoteLog = ['log fortianalyzer setting', 'log fortianalyzer2 setting', 'log fortianalyzer3 setting',
    'log fortianalyzer-cloud setting', 'log fortiguard setting', 'log syslogd setting', 'log syslogd2 setting',
    'log syslogd3 setting', 'log syslogd4 setting'].some(logOn);
  if (!remoteLog) add('log-remote');

  const ntp = findConfig(global, 'system ntp');
  if (ntp && one(ntp, 'ntpsync') === 'disable') add('ntp');

  // ----- firmware -----
  const major = info.version ? Number(info.version.split('.')[0]) : null;
  if (major !== null && major < 7) add('firmware-eos', { detail: `FortiOS ${info.version}` });

  // ----- HA -----
  const ha = findConfig(global, 'system ha');
  if (ha && one(ha, 'mode') && one(ha, 'mode') !== 'standalone') {
    const off = ['authentication', 'encryption'].filter((k) => one(ha, k) !== 'enable');
    if (off.length) add('ha-heartbeat', { object: one(ha, 'group-name') || 'cluster', detail: `${off.join(' and ')} off (mode ${one(ha, 'mode')})` });
  }

  // ----- certificates -----
  const adminCert = g('admin-server-cert');
  if (!adminCert || DEFAULT_CERTS.has(adminCert)) add('default-cert', { object: 'admin GUI', detail: adminCert || 'default certificate' });
  const now = new Date();
  // Single-VDOM configs: the global scope is the root VDOM, so it is scanned once.
  for (const [scope, node] of [[null, global], ...(info.multiVdom ? vdoms.map((v) => [v.name, v.node]) : [])]) {
    for (const [path, key] of [['vpn certificate local', 'certificate'], ['vpn certificate ca', 'ca'], ['vpn certificate remote', 'remote']]) {
      for (const c of entriesOf(node, path)) {
        const pem = one(c, key);
        if (!pem || !pem.includes('BEGIN CERTIFICATE')) continue;
        for (const i of certIssues(pem, now) || []) add(i.check, { vdom: scope, object: `${c.name} (${path.split(' ').pop()})`, detail: i.detail });
      }
    }
  }

  // ----- per VDOM -----
  const wanIfaces = new Set(entriesOf(global, 'system interface')
    .filter((i) => one(i, 'role') === 'wan' || ['dhcp', 'pppoe'].includes(one(i, 'mode')) || isPublicIp((one(i, 'ip') || '').split(/[\s/]/)[0]))
    .map((i) => i.name));
  const sslvpnOn = new Set();

  for (const { name: vdom, node } of vdoms) {
    const lip = entriesOf(node, 'firewall local-in-policy');
    const lip6 = entriesOf(node, 'firewall local-in-policy6');
    const vdomIfaces = entriesOf(global, 'system interface').filter((i) => (one(i, 'vdom') || 'root') === vdom);
    if (!lip.length && !lip6.length && vdomIfaces.length) add('local-in-missing', { vdom });

    const settings = findConfig(node, 'system settings');
    if (settings && (one(settings, 'asymroute') === 'enable' || one(settings, 'asymroute6') === 'enable')) {
      add('asymroute', { vdom, detail: ['asymroute', 'asymroute6'].filter((k) => one(settings, k) === 'enable').join(', ') });
    }

    for (const l of entriesOf(node, 'user ldap')) {
      if (!['ldaps', 'starttls'].includes(one(l, 'secure'))) add('ldap-cleartext', { vdom, object: l.name, detail: `${one(l, 'server') || ''}:${one(l, 'port') || '389'}` });
    }

    // Users who can log in to a VPN: SSL-VPN authentication rules, SSL-VPN policies and
    // dial-up IPsec XAuth groups. Only local password users can be judged here.
    const localUsers = new Map(entriesOf(node, 'user local').map((u) => [u.name, u]));
    const groups = new Map(entriesOf(node, 'user group').map((u) => [u.name, list(u, 'member')]));
    const vpnUsers = new Map(); // user -> where it is used
    const addUsers = (names, via) => {
      const seen = new Set();
      const walk = (n, path) => {
        if (seen.has(n)) return;
        seen.add(n);
        if (groups.has(n)) groups.get(n).forEach((m) => walk(m, `${path} › ${n}`));
        else if (localUsers.has(n) && !vpnUsers.has(n)) vpnUsers.set(n, path);
      };
      names.forEach((n) => walk(n, via));
    };

    // IPsec
    for (const p1 of [...entriesOf(node, 'vpn ipsec phase1-interface'), ...entriesOf(node, 'vpn ipsec phase1')]) {
      if (one(p1, 'type') === 'dynamic') {
        if ((one(p1, 'authmethod') || 'psk') === 'psk') add('dialup-psk', { vdom, object: p1.name, detail: one(p1, 'xauthtype') && one(p1, 'xauthtype') !== 'disable' ? `with XAuth (${one(p1, 'authusrgrp') || 'no group'})` : 'no XAuth' });
        if (one(p1, 'authusrgrp')) addUsers([one(p1, 'authusrgrp')], `IPsec ${p1.name}`);
      }
      const prop = list(p1, 'proposal');
      const weak = prop.filter((p) => WEAK_ALGOS.test(p));
      const dh = list(p1, 'dhgrp').filter((d) => WEAK_DH.has(d));
      // Default proposals of older releases include SHA-1 and DH 5; only flag what is set explicitly.
      if (weak.length || dh.length) {
        add('ipsec-weak', { vdom, object: p1.name, detail: [weak.length && `phase1 ${weak.join(' ')}`, dh.length && `DH group ${dh.join(' ')}`].filter(Boolean).join(', ') });
      }
      const ike = one(p1, 'ike-version') || '1';
      const auth = one(p1, 'authmethod') || 'psk';
      if (ike === '1' && one(p1, 'mode') === 'aggressive' && auth === 'psk') add('ipsec-aggressive', { vdom, object: p1.name });
    }
    for (const p2 of [...entriesOf(node, 'vpn ipsec phase2-interface'), ...entriesOf(node, 'vpn ipsec phase2')]) {
      const weak = list(p2, 'proposal').filter((p) => WEAK_ALGOS.test(p));
      const dh = list(p2, 'dhgrp').filter((d) => WEAK_DH.has(d));
      if (weak.length || dh.length) {
        add('ipsec-weak', { vdom, object: `${one(p2, 'phase1name') || ''} › ${p2.name}`, detail: [weak.length && `phase2 ${weak.join(' ')}`, dh.length && `DH group ${dh.join(' ')}`].filter(Boolean).join(', ') });
      }
    }

    // SSL-VPN: enabled when it listens on at least one interface.
    const ssl = findConfig(node, 'vpn ssl settings');
    if (ssl && list(ssl, 'source-interface').length && one(ssl, 'status') !== 'disable') {
      sslvpnOn.add(vdom);
      add('sslvpn-enabled', { vdom, detail: `on ${list(ssl, 'source-interface').join(', ')}, port ${one(ssl, 'port') || '443'}` });
      const min = one(ssl, 'ssl-min-proto-ver');
      if (min && /tls1-[01]$/.test(min)) add('sslvpn-tls', { vdom, detail: `minimum ${min}` });
      const cert = one(ssl, 'servercert');
      if (!cert || DEFAULT_CERTS.has(cert)) add('default-cert', { vdom, object: 'SSL-VPN', detail: cert || 'Fortinet_Factory (default)' });

      // Portals actually handed out: the default portal and those of the authentication rules.
      const rules = entriesOf(ssl, 'authentication-rule');
      const used = new Set([one(ssl, 'default-portal'), ...rules.map((r) => one(r, 'portal'))].filter(Boolean));
      for (const portal of entriesOf(node, 'vpn ssl web portal')) {
        if (used.has(portal.name) && one(portal, 'web-mode') === 'enable') add('sslvpn-webmode', { vdom, object: portal.name });
      }
      for (const r of rules) addUsers([...list(r, 'groups'), ...list(r, 'users')], 'SSL-VPN rule');
    }

    // Policies
    const active = entriesOf(node, 'firewall policy').filter((p) => one(p, 'status') !== 'disable');
    const plabel = (p) => `#${p.name}${one(p, 'name') ? ` ${one(p, 'name')}` : ''}`;
    for (let j = 1; j < active.length; j++) {
      const b = active[j];
      const a = active.slice(0, j).find((x) => shadows(x, b));
      if (a) add('policy-shadowed', { vdom, object: plabel(b), detail: `fully covered by ${plabel(a)} (${one(a, 'action') || 'deny'}) above it` });
    }
    for (const p of active) {
      if (list(p, 'srcintf').some((i) => /^ssl\./.test(i))) addUsers([...list(p, 'groups'), ...list(p, 'users')], `SSL-VPN policy #${p.name}`);
    }
    for (const p of active) {
      if (one(p, 'action') !== 'accept') continue;
      const src = list(p, 'srcaddr');
      const dst = list(p, 'dstaddr');
      const svc = list(p, 'service');
      const srcAny = src.includes('all') || list(p, 'srcaddr6').includes('all');
      const dstAny = dst.includes('all') || list(p, 'dstaddr6').includes('all');
      const svcAll = svc.includes('ALL');
      const label = `#${p.name}${one(p, 'name') ? ` ${one(p, 'name')}` : ''}`;
      const path = `${list(p, 'srcintf').join(',')} → ${list(p, 'dstintf').join(',')}`;
      if (srcAny && dstAny && svcAll) add('policy-any-any', { vdom, object: label, detail: path });
      else if (srcAny && list(p, 'srcintf').some((i) => wanIfaces.has(i)) && list(p, 'internet-service-src').length === 0
        && one(p, 'internet-service-src') !== 'enable') {
        add('policy-wan-inbound-any', { vdom, object: label, detail: `${path}, services ${svc.join(' ') || '-'}` });
      }
      if (one(p, 'logtraffic') === 'disable') add('policy-nolog', { vdom, object: label, detail: path });
      const inbound = list(p, 'srcintf').some((i) => wanIfaces.has(i)) && !list(p, 'dstintf').some((i) => wanIfaces.has(i));
      if (inbound && !one(p, 'ips-sensor') && !one(p, 'profile-group')) add('policy-wan-noprofile', { vdom, object: label, detail: `${path}, services ${svc.join(' ') || '-'}` });
    }

    for (const [name, via] of vpnUsers) {
      const u = localUsers.get(name);
      if (one(u, 'status') === 'disable' || !['password', null].includes(one(u, 'type'))) continue;
      const mfa = one(u, 'two-factor');
      if (!mfa || mfa === 'disable') add('vpn-user-no-mfa', { vdom, object: name, detail: `via ${via}` });
    }

    // VIPs
    for (const v of entriesOf(node, 'firewall vip')) {
      if (one(v, 'type') && one(v, 'type') !== 'static-nat') continue;
      const ext = one(v, 'extip') || '';
      if (one(v, 'portforward') !== 'enable') {
        add('vip-all-ports', { vdom, object: v.name, detail: `${ext} → ${one(v, 'mappedip') || ''}` });
        continue;
      }
      const [lo, hi = lo] = (one(v, 'extport') || '').split('-').map(Number);
      const mlo = Number((one(v, 'mappedport') || '').split('-')[0]);
      const hits = Object.entries(RISKY_PORTS).filter(([port]) => (port >= lo && port <= hi) || Number(port) === mlo);
      if (hits.length) add('vip-risky-port', { vdom, object: v.name, detail: `${ext}:${one(v, 'extport')} → ${one(v, 'mappedip') || ''}:${one(v, 'mappedport') || one(v, 'extport')} (${[...new Set(hits.map(([, n]) => n))].join(', ')})` });
    }
  }

  findings.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity)
    || a.category.localeCompare(b.category) || a.title.localeCompare(b.title));
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  const failed = new Set(findings.map((f) => f.check));
  return {
    device: { hostname: g('hostname'), model: info.model, version: info.version, vdoms: vdoms.map((v) => v.name), admins: admins.length },
    counts,
    findings,
    passed: Object.keys(CHECKS).filter((k) => !failed.has(k)),
    state: securityState({ global, vdoms, sysGlobal, wanIfaces }),
  };
}

// ---------- change tracking ----------
// Global settings worth an alert when they change (secrets excluded).
const WATCHED_GLOBAL = ['admin-sport', 'admin-ssh-port', 'admin-https-redirect', 'admin-https-ssl-versions', 'admin-lockout-threshold',
  'admin-lockout-duration', 'admintimeout', 'admin-maintainer', 'admin-server-cert', 'strong-crypto', 'private-data-encryption',
  'admin-telnet', 'admin-restrict-local', 'usb-auto-install'];
const AREA_SEVERITY = {
  'Administrator': 'high', 'REST API user': 'high', 'Local-in policy': 'high', 'Interface access': 'medium',
  'Local user': 'medium', 'Global setting': 'medium', 'SNMP': 'medium', 'SSL-VPN': 'medium', 'VIP': 'medium',
  'Inbound policy': 'medium', 'IPsec tunnel': 'low', 'HA': 'low',
};

// Security-relevant objects of a config as { key: { area, vdom, object, values } }, where
// values are strings so two backups can be compared field by field.
function securityState({ global, vdoms, sysGlobal, wanIfaces }) {
  const state = {};
  const pick = (e, keys) => Object.fromEntries(keys.filter((k) => e.settings[k]).map((k) => [k, [...e.settings[k]].join(' ')]));
  const put = (area, vdom, object, values) => { state[`${area}|${vdom || ''}|${object}`] = { area, vdom, object, values }; };

  for (const a of entriesOf(global, 'system admin')) {
    const v = pick(a, ['accprofile', 'vdom', 'two-factor', 'remote-auth', 'remote-group', 'wildcard']);
    const hosts = Object.entries(a.settings).filter(([k]) => /^(ip6-)?trusthost\d+$/.test(k)).map(([, x]) => x.join(' ')).filter((x) => !isAnyNet(x));
    v['trusted hosts'] = hosts.sort().join(', ') || 'any';
    put('Administrator', null, a.name, v);
  }
  for (const u of entriesOf(global, 'system api-user')) {
    const th = findConfig(u, 'trusthost');
    const hosts = th ? th.entries.map((e) => one(e, 'ipv4-trusthost') || one(e, 'ipv6-trusthost')).filter((x) => !isAnyNet(x)) : [];
    put('REST API user', null, u.name, { ...pick(u, ['accprofile', 'vdom', 'cors-allow-origin']), 'trusted hosts': hosts.sort().join(', ') || 'any' });
  }
  for (const i of entriesOf(global, 'system interface')) {
    const access = list(i, 'allowaccess');
    if (!access.length) continue;
    put('Interface access', one(i, 'vdom') || 'root', i.name, { allowaccess: [...access].sort().join(' ') || 'none', ...(wanIfaces.has(i.name) ? { wan: 'yes' } : {}) });
  }
  const gv = pick(sysGlobal, WATCHED_GLOBAL);
  for (const k of WATCHED_GLOBAL) put('Global setting', null, k, { value: gv[k] || '(default)' });
  for (const c of entriesOf(global, 'system snmp community')) {
    put('SNMP', null, one(c, 'name') || c.name, { ...pick(c, ['status', 'query-v1-status', 'query-v2c-status']), hosts: entriesOf(c, 'hosts').map((h) => one(h, 'ip')).sort().join(', ') || 'any' });
  }
  const ha = findConfig(global, 'system ha');
  if (ha) put('HA', null, 'cluster', pick(ha, ['mode', 'authentication', 'encryption', 'hbdev', 'ha-mgmt-status']));

  for (const { name: vdom, node } of vdoms) {
    for (const p of [...entriesOf(node, 'firewall local-in-policy'), ...entriesOf(node, 'firewall local-in-policy6')]) {
      put('Local-in policy', vdom, `#${p.name}`, pick(p, ['intf', 'srcaddr', 'dstaddr', 'service', 'action', 'schedule', 'status', 'srcaddr-negate', 'dstaddr-negate', 'service-negate']));
    }
    for (const u of entriesOf(node, 'user local')) put('Local user', vdom, u.name, pick(u, ['type', 'status', 'two-factor', 'ldap-server', 'radius-server']));
    for (const v of entriesOf(node, 'firewall vip')) put('VIP', vdom, v.name, pick(v, ['type', 'extip', 'extintf', 'mappedip', 'portforward', 'protocol', 'extport', 'mappedport', 'src-filter']));
    for (const p of entriesOf(node, 'firewall policy')) {
      if (one(p, 'action') !== 'accept' || !list(p, 'srcintf').some((i) => wanIfaces.has(i))) continue;
      put('Inbound policy', vdom, `#${p.name}${one(p, 'name') ? ` ${one(p, 'name')}` : ''}`, pick(p, ['status', 'srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service', 'schedule', 'ips-sensor', 'av-profile', 'profile-group', 'logtraffic']));
    }
    const ssl = findConfig(node, 'vpn ssl settings');
    if (ssl) put('SSL-VPN', vdom, 'settings', pick(ssl, ['status', 'source-interface', 'source-address', 'source-address-negate', 'port', 'servercert', 'ssl-min-proto-ver', 'default-portal']));
    for (const p1 of [...entriesOf(node, 'vpn ipsec phase1-interface'), ...entriesOf(node, 'vpn ipsec phase1')]) {
      put('IPsec tunnel', vdom, p1.name, pick(p1, ['type', 'interface', 'remote-gw', 'ike-version', 'mode', 'authmethod', 'proposal', 'dhgrp', 'peertype', 'xauthtype', 'authusrgrp']));
    }
  }
  return state;
}

// Differences between two audits of the same device: what was added, removed or changed,
// plus findings that appeared or were resolved.
function compare(before, after) {
  const items = [];
  const a = before.state || {}, b = after.state || {};
  for (const key of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const x = a[key], y = b[key];
    const ref = y || x;
    let severity = AREA_SEVERITY[ref.area] || 'low';
    const mgmtOnWan = (v) => v && v.wan && MGMT.filter((m) => v.allowaccess.split(' ').includes(m));
    if (!x) {
      if (ref.area === 'Interface access' && mgmtOnWan(y.values).length) severity = 'critical';
      items.push({ area: ref.area, vdom: ref.vdom, object: ref.object, kind: 'added', severity, fields: Object.entries(y.values).map(([field, v]) => ({ field, after: v })) });
      continue;
    }
    if (!y) {
      // Removing a protection is worse than removing an account.
      items.push({ area: ref.area, vdom: ref.vdom, object: ref.object, kind: 'removed', severity: ref.area === 'Local-in policy' ? 'high' : severity === 'high' ? 'medium' : severity, fields: [] });
      continue;
    }
    const fields = [...new Set([...Object.keys(x.values), ...Object.keys(y.values)])]
      .filter((f) => x.values[f] !== y.values[f])
      .map((f) => ({ field: f, before: x.values[f] ?? '(default)', after: y.values[f] ?? '(default)' }));
    if (!fields.length) continue;
    // Management access newly opened on an internet-facing interface.
    if (ref.area === 'Interface access' && mgmtOnWan(y.values).some((m) => !(mgmtOnWan(x.values) || []).includes(m))) severity = 'critical';
    if (fields.some((f) => f.field === 'trusted hosts' && f.after === 'any')) severity = 'critical';
    items.push({ area: ref.area, vdom: ref.vdom, object: ref.object, kind: 'changed', severity, fields });
  }
  const fkey = (f) => `${f.check}|${f.vdom || ''}|${f.object || ''}`;
  const had = new Set(before.findings.map(fkey)), has = new Set(after.findings.map(fkey));
  const strip = ({ check, severity, title, vdom, object, detail }) => ({ check, severity, title, vdom, object, detail });
  items.sort((p, q) => SEVERITIES.indexOf(p.severity) - SEVERITIES.indexOf(q.severity) || p.area.localeCompare(q.area));
  return {
    items,
    newFindings: after.findings.filter((f) => !had.has(fkey(f))).map(strip),
    resolvedFindings: before.findings.filter((f) => !has.has(fkey(f))).map(strip),
  };
}

module.exports = { audit, compare, CHECKS, SEVERITIES };
