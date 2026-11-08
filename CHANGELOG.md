# Changelog

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
