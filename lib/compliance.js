// Compliance view of an audit: maps framework controls to audit checks and scores them.
//
// A control lists the checks that give evidence for it:
//   coverage 'full'    - the checks decide the control on their own (pass / fail);
//   coverage 'partial' - a failed check fails it, but passing checks only cover part of
//                        the requirement, so it is shown as "review" (needs a person);
//   no checks          - the control can't be judged from a config backup: "manual".
// Control titles are short paraphrases written for this tool, not the frameworks' text.
const { CHECKS, SEVERITIES } = require('./audit');

const FRAMEWORKS = {
  cis: {
    id: 'cis',
    name: 'CIS FortiGate Benchmark',
    version: '7.4.x',
    // The benchmark text is licensed by CIS: only control numbers and our own short titles
    // are stored here. Numbers follow the 7.4.x structure; check them against your copy.
    note: 'Control numbers follow the CIS FortiGate 7.4.x Benchmark structure; verify them against your licensed copy of the benchmark. Titles are summaries, not CIS text.',
    sections: [
      { id: '1', title: 'Network settings', controls: [
        { id: '1.1', title: 'DNS servers are configured', manual: 'Check config system dns: primary/secondary point to trusted resolvers.' },
        { id: '1.2', title: 'Intra-zone traffic is not always allowed', checks: ['intrazone-allow'], coverage: 'full' },
        { id: '1.3', title: 'No management services on WAN interfaces', checks: ['mgmt-on-wan'], coverage: 'full' },
      ] },
      { id: '2.1', title: 'System settings', controls: [
        { id: '2.1.1', title: 'Pre-login banner is set', checks: ['pre-login-banner'], coverage: 'full' },
        { id: '2.1.2', title: 'Post-login banner is set', checks: ['post-login-banner'], coverage: 'full' },
        { id: '2.1.3', title: 'Timezone is set correctly', manual: 'Check config system global › timezone matches the site.' },
        { id: '2.1.4', title: 'System time is synchronised (NTP)', checks: ['ntp'], coverage: 'full' },
        { id: '2.1.5', title: 'Hostname is set', manual: 'Check the hostname follows the naming standard (not the model/serial default).' },
        { id: '2.1.6', title: 'Firmware is current', checks: ['firmware-eos'], coverage: 'partial', review: 'Confirm the build is the latest recommended release of its branch.' },
        { id: '2.1.7', title: 'USB firmware / config auto-install disabled', checks: ['usb-auto-install'], coverage: 'full' },
        { id: '2.1.8', title: 'TLS static key ciphers disabled', checks: ['tls-static-keys'], coverage: 'full' },
        { id: '2.1.9', title: 'Strong crypto enabled', checks: ['strong-crypto'], coverage: 'full' },
        { id: '2.1.10', title: 'Admin GUI uses only TLS 1.2+', checks: ['admin-tls'], coverage: 'full' },
      ] },
      { id: '2.2', title: 'Password policy', controls: [
        { id: '2.2.1', title: 'Password policy is enabled', checks: ['password-policy'], coverage: 'full' },
        { id: '2.2.2', title: 'Login retries and lockout time are set', checks: ['lockout'], coverage: 'full' },
      ] },
      { id: '2.3', title: 'SNMP', controls: [
        { id: '2.3.1', title: 'Only SNMPv3 is used', checks: ['snmp-community'], coverage: 'partial', review: 'Confirm SNMPv1/v2c communities are not needed and SNMPv3 users use auth + priv.' },
        { id: '2.3.2', title: 'SNMP is limited to trusted hosts', checks: ['snmp-community'], coverage: 'partial', review: 'Check SNMPv3 users are restricted to the monitoring servers.' },
      ] },
      { id: '2.4', title: 'Administrators and admin profiles', controls: [
        { id: '2.4.1', title: 'Default admin password is changed', checks: ['admin-default-name'], coverage: 'partial', review: 'Passwords are not in the backup: confirm the default account has a strong password or is removed.' },
        { id: '2.4.2', title: 'All admin accounts have trusted hosts', checks: ['admin-trusthost', 'apiuser-trusthost'], coverage: 'full' },
        { id: '2.4.3', title: 'Admins have the least-privilege profile they need', checks: ['apiuser-superadmin'], coverage: 'partial', review: 'Review each admin account against its role.' },
        { id: '2.4.4', title: 'Admin idle timeout is set', checks: ['admin-timeout'], coverage: 'full' },
        { id: '2.4.5', title: 'Only encrypted admin access', checks: ['mgmt-insecure-proto', 'https-redirect'], coverage: 'full' },
        { id: '2.4.6', title: 'Local-in policies restrict access to the firewall', checks: ['local-in-missing'], coverage: 'partial', review: 'Check local-in policies only allow management from admin networks.' },
        { id: '2.4.7', title: 'Default admin ports are changed', checks: ['admin-default-ports'], coverage: 'full' },
        { id: '2.4.8', title: 'Two-factor authentication for administrators', checks: ['admin-no-mfa'], coverage: 'full' },
        { id: '2.4.9', title: 'Maintainer account disabled', checks: ['maintainer'], coverage: 'full' },
      ] },
      { id: '2.5', title: 'High availability', controls: [
        { id: '2.5.1', title: 'HA heartbeat is authenticated and encrypted', checks: ['ha-heartbeat'], coverage: 'full' },
        { id: '2.5.2', title: 'HA monitors traffic interfaces', checks: ['ha-monitor'], coverage: 'full' },
        { id: '2.5.3', title: 'HA reserved management interface is configured', manual: 'Check config system ha › ha-mgmt-status / ha-mgmt-interfaces on clusters.' },
      ] },
      { id: '3', title: 'Policies and objects', controls: [
        { id: '3.1', title: 'Unused policies are reviewed regularly', checks: ['policy-shadowed'], coverage: 'partial', review: 'Review policy hit counts; shadowed policies are listed as evidence.' },
        { id: '3.2', title: 'Policies do not use service ALL', checks: ['policy-any-any', 'policy-service-all'], coverage: 'full' },
        { id: '3.3', title: 'Traffic to/from Tor, malicious and scanner IPs is denied', manual: 'Check for deny policies using Internet Service DB entries for Tor / malicious / scanner sources.' },
        { id: '3.4', title: 'Logging is enabled on all policies', checks: ['policy-nolog'], coverage: 'full' },
      ] },
      { id: '4', title: 'Security profiles', controls: [
        { id: '4.1.1', title: 'IPS detects botnet connections', manual: 'Check IPS sensors have botnet C&C detection enabled (scan-botnet-connections block).' },
        { id: '4.1.2', title: 'IPS is applied to policies', checks: ['policy-wan-noprofile'], coverage: 'partial', review: 'Inbound policies are checked; confirm IPS on outbound and internal policies as required.' },
        { id: '4.2.1', title: 'Antivirus / signature updates are automatic', checks: ['fortiguard-updates'], coverage: 'full' },
        { id: '4.2.2', title: 'Antivirus is applied to policies', checks: ['policy-outbound-noprofile'], coverage: 'partial', review: 'Confirm the profiles on internet-bound policies include antivirus.' },
        { id: '4.2.3', title: 'Outbreak prevention / heuristics are enabled', manual: 'Check antivirus profiles: outbreak prevention, machine-learning detection, grayware.' },
        { id: '4.3.1', title: 'DNS filter blocks botnet C&C domains', checks: ['dnsfilter-botnet'], coverage: 'full' },
        { id: '4.3.2', title: 'DNS filter logs all queries', checks: ['dnsfilter-nolog'], coverage: 'full' },
        { id: '4.3.3', title: 'DNS filter is applied to policies', checks: ['policy-outbound-noprofile'], coverage: 'partial', review: 'Confirm internet-bound policies use a DNS filter profile.' },
        { id: '4.4.1', title: 'Application control blocks high-risk categories', manual: 'Check application control sensors block high-risk categories (P2P, proxy, botnet…).' },
        { id: '4.4.2', title: 'Application control is applied to policies', checks: ['policy-outbound-noprofile'], coverage: 'partial', review: 'Confirm internet-bound policies use an application control sensor.' },
      ] },
      { id: '5', title: 'Security Fabric', controls: [
        { id: '5.1', title: 'Compromised-host quarantine is configured', manual: 'Check automation stitches / FortiAnalyzer quarantine for compromised hosts.' },
        { id: '5.2', title: 'Security Fabric is configured', manual: 'Check config system csf where a Fabric is in use.' },
      ] },
      { id: '6', title: 'VPN', controls: [
        { id: '6.1.1', title: 'VPN portal uses a trusted certificate', checks: ['default-cert', 'cert-expired', 'cert-weak'], coverage: 'full' },
        { id: '6.1.2', title: 'SSL-VPN allows only TLS 1.2+', checks: ['sslvpn-tls'], coverage: 'full' },
        { id: '6.1.3', title: 'IPsec uses strong proposals', checks: ['ipsec-weak', 'ipsec-aggressive'], coverage: 'full' },
        { id: '6.1.4', title: 'VPN users use two-factor authentication', checks: ['vpn-user-no-mfa', 'dialup-psk'], coverage: 'partial', review: 'Remote (LDAP/RADIUS/SAML) users are not judged: confirm MFA at the identity provider.' },
      ] },
      { id: '7', title: 'Logs and reports', controls: [
        { id: '7.1.1', title: 'Event logging is enabled', checks: ['event-logging'], coverage: 'full' },
        { id: '7.2.1', title: 'Log transmission is encrypted', checks: ['log-remote-encrypted'], coverage: 'full' },
        { id: '7.3.1', title: 'Centralised logging and reporting', checks: ['log-remote'], coverage: 'full' },
      ] },
    ],
  },

  pci: {
    id: 'pci',
    name: 'PCI DSS',
    version: '4.0.1',
    note: 'Only requirements a firewall configuration can give evidence for are listed. Passing them does not make an environment PCI DSS compliant: scope, processes and the other requirements are assessed by a QSA.',
    sections: [
      { id: '1', title: 'Req. 1 – Network security controls', controls: [
        { id: '1.2.1', title: 'Configuration standards for NSCs are defined and applied', manual: 'Provide the documented firewall configuration standard and show this device follows it.' },
        { id: '1.2.5', title: 'Allowed services, protocols and ports are identified and needed', checks: ['policy-any-any', 'policy-service-all', 'vip-all-ports'], coverage: 'partial', review: 'Confirm every allowed service has a documented business need.' },
        { id: '1.2.6', title: 'Insecure services and protocols are secured', checks: ['mgmt-insecure-proto', 'snmp-community', 'ldap-cleartext'], coverage: 'full' },
        { id: '1.2.7', title: 'NSC rules are reviewed at least every six months', checks: ['policy-shadowed'], coverage: 'partial', review: 'Provide evidence of the last rule review; shadowed policies are listed as findings.' },
        { id: '1.2.8', title: 'NSC configuration files are secured', checks: ['private-data-encryption'], coverage: 'partial', review: 'Confirm backups are access-controlled (this tool stores them owner-only).' },
        { id: '1.3.1', title: 'Inbound traffic to the CDE is restricted', checks: ['policy-any-any', 'policy-wan-inbound-any'], coverage: 'partial', review: 'Confirm which interfaces / addresses form the CDE and that only needed traffic reaches it.' },
        { id: '1.3.2', title: 'Outbound traffic from the CDE is restricted', checks: ['policy-any-any'], coverage: 'partial', review: 'Confirm outbound policies from the CDE allow only needed destinations and services.' },
        { id: '1.4.1', title: 'NSCs between trusted and untrusted networks', checks: ['intrazone-allow'], coverage: 'partial', review: 'Confirm untrusted networks (internet, guest, partners) are on separate interfaces/zones.' },
        { id: '1.4.2', title: 'Inbound traffic from untrusted networks is restricted', checks: ['policy-wan-inbound-any', 'vip-risky-port', 'vip-all-ports', 'mgmt-on-wan'], coverage: 'full' },
        { id: '1.4.3', title: 'Anti-spoofing is implemented', checks: ['antispoof-off'], coverage: 'full' },
        { id: '1.4.5', title: 'Internal IP addresses are not disclosed', manual: 'Check NAT hides internal addressing on internet-facing interfaces.' },
      ] },
      { id: '2', title: 'Req. 2 – Secure configurations', controls: [
        { id: '2.2.2', title: 'Vendor default accounts are managed', checks: ['admin-default-name', 'maintainer', 'snmp-community'], coverage: 'partial', review: 'Passwords are not in the backup: confirm default passwords were changed.' },
        { id: '2.2.4', title: 'Only necessary services and functions are enabled', checks: ['sslvpn-webmode', 'mgmt-on-wan', 'usb-auto-install'], coverage: 'partial', review: 'Confirm every enabled feature (SSL-VPN, SNMP, admin access…) is needed.' },
        { id: '2.2.5', title: 'Insecure services are justified and secured', checks: ['mgmt-insecure-proto'], coverage: 'full' },
        { id: '2.2.6', title: 'Security parameters prevent misuse', checks: ['strong-crypto', 'tls-static-keys', 'private-data-encryption', 'local-in-missing'], coverage: 'full' },
        { id: '2.2.7', title: 'Non-console admin access is encrypted', checks: ['mgmt-insecure-proto', 'admin-tls', 'https-redirect', 'strong-crypto'], coverage: 'full' },
      ] },
      { id: '4', title: 'Req. 4 – Strong cryptography in transit', controls: [
        { id: '4.2.1', title: 'Strong crypto and trusted certificates over public networks', checks: ['ipsec-weak', 'ipsec-aggressive', 'sslvpn-tls', 'cert-weak', 'cert-expired', 'default-cert'], coverage: 'full' },
      ] },
      { id: '5', title: 'Req. 5 – Malicious software', controls: [
        { id: '5.2.1', title: 'Anti-malware is deployed', checks: ['policy-outbound-noprofile'], coverage: 'partial', review: 'Confirm antivirus profiles are applied where the CDE reaches the internet.' },
        { id: '5.3.1', title: 'Anti-malware is kept current', checks: ['fortiguard-updates'], coverage: 'full' },
      ] },
      { id: '6', title: 'Req. 6 – Secure systems', controls: [
        { id: '6.3.3', title: 'Security patches are installed', checks: ['firmware-eos'], coverage: 'partial', review: 'Confirm critical FortiOS patches are installed within one month of release.' },
        { id: '6.4.1', title: 'Public-facing web applications are protected', checks: ['policy-wan-noprofile'], coverage: 'partial', review: 'Confirm a WAF or equivalent protects published web applications.' },
      ] },
      { id: '7', title: 'Req. 7 – Restrict access', controls: [
        { id: '7.2.1', title: 'Access is based on least privilege', checks: ['apiuser-superadmin'], coverage: 'partial', review: 'Review admin profiles against each administrator\'s role.' },
      ] },
      { id: '8', title: 'Req. 8 – Identification and authentication', controls: [
        { id: '8.2.1', title: 'Every user has a unique ID', checks: ['admin-default-name'], coverage: 'partial', review: 'Confirm no admin account is shared between people.' },
        { id: '8.2.2', title: 'Shared / group credentials are not used', checks: ['dialup-psk'], coverage: 'partial', review: 'Confirm no shared admin or VPN accounts exist.' },
        { id: '8.2.8', title: 'Idle sessions time out after 15 minutes', checks: ['admin-timeout'], coverage: 'full' },
        { id: '8.3.2', title: 'Authentication factors are encrypted in transit', checks: ['ldap-cleartext', 'mgmt-insecure-proto'], coverage: 'full' },
        { id: '8.3.4', title: 'Accounts lock out after failed attempts', checks: ['lockout'], coverage: 'partial', review: 'PCI DSS asks for at most 10 attempts and at least 30 minutes lockout: check the values.' },
        { id: '8.3.6', title: 'Passwords have at least 12 characters', checks: ['password-policy', 'password-policy-length'], coverage: 'full' },
        { id: '8.4.2', title: 'MFA for all admin access into the CDE', checks: ['admin-no-mfa'], coverage: 'full' },
        { id: '8.4.3', title: 'MFA for remote network access', checks: ['vpn-user-no-mfa', 'dialup-psk'], coverage: 'partial', review: 'Remote (LDAP/RADIUS/SAML) VPN users are not judged: confirm MFA at the identity provider.' },
        { id: '8.6.1', title: 'System and application accounts are managed', checks: ['apiuser-trusthost', 'apiuser-superadmin'], coverage: 'partial', review: 'Confirm each API user has an owner and a documented purpose.' },
      ] },
      { id: '10', title: 'Req. 10 – Logging and monitoring', controls: [
        { id: '10.2.1', title: 'Audit logs are enabled', checks: ['event-logging', 'policy-nolog'], coverage: 'full' },
        { id: '10.3.2', title: 'Audit logs are protected from modification', checks: ['log-remote-encrypted'], coverage: 'partial', review: 'Confirm access to the log server is restricted.' },
        { id: '10.3.3', title: 'Audit logs are backed up to a central log server', checks: ['log-remote'], coverage: 'full' },
        { id: '10.5.1', title: 'Audit log history is kept for 12 months', manual: 'Check retention on the log server (FortiAnalyzer / syslog / SIEM).' },
        { id: '10.6.1', title: 'System clocks are synchronised', checks: ['ntp'], coverage: 'full' },
      ] },
      { id: '11', title: 'Req. 11 – Security testing', controls: [
        { id: '11.5.1', title: 'Intrusion detection / prevention is used', checks: ['policy-wan-noprofile'], coverage: 'partial', review: 'Confirm IPS covers traffic at the CDE perimeter and critical points.' },
      ] },
    ],
  },
};

// Sanity check at load time: every mapped check must exist in the audit.
for (const f of Object.values(FRAMEWORKS)) {
  for (const s of f.sections) for (const c of s.controls) {
    for (const id of c.checks || []) if (!CHECKS[id]) throw new Error(`compliance: ${f.id} ${c.id} maps unknown check ${id}`);
  }
}

const STATUSES = ['fail', 'review', 'pass', 'manual', 'na'];

// Status of each control of `framework` for one audit result.
function evaluate(framework, result) {
  const fw = FRAMEWORKS[framework];
  if (!fw) throw new Error(`Unknown framework ${framework}`);
  const failed = new Map();
  for (const f of result.findings || []) {
    if (!failed.has(f.check)) failed.set(f.check, []);
    failed.get(f.check).push({ vdom: f.vdom, object: f.object, detail: f.detail, severity: f.severity });
  }
  const na = new Set(result.notApplicable || []);
  const counts = Object.fromEntries(STATUSES.map((s) => [s, 0]));
  const sections = fw.sections.map((s) => ({
    id: s.id,
    title: s.title,
    controls: s.controls.map((c) => {
      const checks = (c.checks || []).map((id) => ({
        id,
        status: failed.has(id) ? 'fail' : na.has(id) ? 'na' : 'pass',
        findings: failed.get(id) || [],
      }));
      let status;
      if (!checks.length) status = 'manual';
      else if (checks.some((k) => k.status === 'fail')) status = 'fail';
      else if (checks.every((k) => k.status === 'na')) status = 'na';
      else status = c.coverage === 'partial' ? 'review' : 'pass';
      const worst = SEVERITIES.find((sev) => checks.some((k) => k.findings.some((f) => f.severity === sev))) || null;
      counts[status]++;
      return { id: c.id, title: c.title, status, severity: worst, coverage: c.coverage || null, note: c.manual || c.review || null, checks };
    }),
  }));
  // Score: controls without a failure, among those the checks could judge.
  const judged = counts.pass + counts.review + counts.fail;
  return { counts, score: judged ? Math.round(((counts.pass + counts.review) / judged) * 100) : null, sections };
}

// Framework metadata without the control lists (for pickers).
const frameworks = () => Object.values(FRAMEWORKS).map(({ id, name, version, note, sections }) => ({
  id, name, version, note, controls: sections.reduce((n, s) => n + s.controls.length, 0),
}));

module.exports = { evaluate, frameworks, FRAMEWORKS, STATUSES };
