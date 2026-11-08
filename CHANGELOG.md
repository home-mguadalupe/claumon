# Changelog

## 2026-11-08 — Policy mitigation

### New: Mitigation tab
Ranks the risky firewall policies across your firewalls and shows how to fix each one.
Guidance only: nothing is sent to the firewall.

- Fixes with their likely impact: turn on logging, add security profiles, narrow `all` /
  `ALL`, disable or move a shadowed policy.
- Each fix has pre-checks, GUI steps, CLI, how to confirm it worked and how to undo it.
- Ranking by severity, internet exposure and number of issues, with a summary per firewall.
- Filters by firewall, issue, effort and text.
- API: `GET /api/mitigation`.

## 2026-11-08 — Compliance

### New: Compliance tab
Shows how each firewall's newest backup measures up against a compliance framework. Like
the Security tab, it runs on the backup files, so nothing is read from the devices and no
database is needed.

- **CIS FortiGate Benchmark** (7.4.x numbering, 52 controls) and **PCI DSS 4.0.1** (37
  requirements a firewall configuration can give evidence for). Titles are our own short
  summaries; check the CIS numbering against your licensed copy of the benchmark.
- Each control is **Fail**, **Review** (checks passed but cover only part of it), **Pass**,
  **Manual** (can't be judged from a config) or **N/A**, with the findings behind a failure,
  the fix, and what still needs a person to confirm.
- A score per firewall, a filter by firewall, status and text, and the view kept in the URL.
- **PDF report** (`/report`): a printable report per firewall or for the fleet, with a summary,
  every control with evidence, remediation sorted by severity, and a reviewer checklist with
  sign-off lines. Saved as PDF from the browser, so no new dependency.
- API: `GET /api/compliance?framework=cis|pci&file=`.

### Security audit: 16 new checks (57 in total)
Pre-login and post-login banners, admin passwords shorter than 12 characters, default admin
ports, USB auto-install, TLS static key ciphers, anti-spoofing (`src-check`) off, intra-zone
traffic allowed, accept policies on service `ALL`, internet-bound policies without security
profiles, DNS filter not blocking botnet domains / not logging all queries, scheduled
FortiGuard updates off, event logging off, unencrypted remote logging, HA without monitored
interfaces.

### Changed
- Checks that don't apply to a config (no HA, no SSL-VPN, no VIPs, no API users…) are now
  reported as **not applicable** instead of passed (`notApplicable` in `/api/audit`).
- The admin idle timeout is flagged above 15 minutes (was 30), as PCI DSS 8.2.8 requires.

## 2026-11-08 — Security audit, routing tables, scheduled jobs

### New: Security tab
Audits the newest backup of every firewall for configuration weaknesses. Each finding
explains why it matters and how to fix it (with the FortiOS CLI). The checks run on the
backup files, so nothing extra is read from the firewalls and no database is needed.

- **Fleet summary**: one row per firewall with findings by severity (critical → info)
  and changes in the last 7 days. The **Security** tab in the menu shows the number of
  critical and high findings.
- **Findings grouped by problem**, each listing every firewall, VDOM and object where it
  occurs. Filter by firewall, minimum severity, category or text; the view is kept in
  the URL so it can be bookmarked or shared. With one firewall selected, the checks it
  passed are listed too.
- **41 checks**:
  - *Administrators*: admins and REST API users without trusted hosts, API users with
    `super_admin`, the default `admin` account, local admins without two-factor,
    password policy off, weak lockout, long idle timeout, maintainer account.
  - *Management access*: admin access (HTTPS/SSH/HTTP/Telnet/SNMP/FGFM) on
    internet-facing interfaces, HTTP/Telnet on any interface, VDOMs without a local-in
    policy, weak or unrestricted SNMP communities, HTTPS redirect off.
  - *Crypto*: TLS 1.0/1.1 on the admin GUI, strong-crypto off, private-data-encryption
    off, factory / self-signed certificates on the admin GUI or SSL-VPN, certificates
    that are expired, expire within 30 days, use SHA-1/MD5 or RSA keys under 2048 bits.
  - *VPN*: weak IPsec proposals and DH groups, IKEv1 aggressive mode with PSK, dial-up
    IPsec with PSK, VPN users without two-factor, SSL-VPN web mode, old TLS on SSL-VPN.
  - *Firewall policy*: asymmetric routing (stateful inspection off), any → any on `ALL`,
    inbound from the internet with source `all` or without IPS, shadowed policies,
    VIPs publishing RDP/SMB/SSH/databases, VIPs forwarding all ports.
  - *Authentication / HA*: LDAP without TLS, HA heartbeat without authentication or
    encryption.
  - *Logging / firmware*: no remote logging, policies without traffic logging, NTP off,
    FortiOS 6.x or older.
- **Security-relevant changes**: every backup is compared with the previous one (last 20
  per firewall). It shows what was added, removed or changed (old → new value) in
  administrators and API users, trusted hosts, local-in policies, interface admin access,
  local users, VIPs, inbound policies, SSL-VPN, IPsec, SNMP, HA and key global settings,
  plus findings that appeared or were fixed. Opening admin access on a WAN interface or
  removing a trusted-host restriction is flagged as critical.
- API: `GET /api/audit?file=&history=`.

### New: routing tables
- The live routing table of every VDOM (IPv4 and IPv6) is read from the firewall with
  each backup and refreshed hourly, stored in the database and shown under
  **Inventory → Network → Routing table**, with CSV export.
- **IP lookup** shows the route each firewall and VDOM uses for an IP or network, and
  flags VDOMs that have no route for it.

### New: automatic backups
- Every firewall is backed up automatically (`AUTO_BACKUP_HOURS`, default daily) and its
  routing table refreshed (`AUTO_ROUTES_HOURS`, default hourly). Failed firewalls are
  retried after 30 minutes and the error is shown in their row.
- Old routing tables are cleaned up after `ROUTES_KEEP_DAYS` (default 30).

### Fixes
- The Push tab no longer throws an error at page load when the firewall list loads
  before the push form.
