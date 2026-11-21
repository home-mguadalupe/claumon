-- FortiGate config inventory. One snapshot per ingested backup file; every
-- inventory row belongs to a snapshot and carries the VDOM it was found in.
-- `raw` keeps all remaining (secret-redacted) settings of the object.

-- Firewalls managed by the web UI. The API key is stored only encrypted
-- (AES-256-GCM, see lib/secrets.js); the master key is kept outside the database.
CREATE TABLE IF NOT EXISTS firewalls (
  id            uuid PRIMARY KEY,
  name          text NOT NULL,
  auto_name     boolean NOT NULL DEFAULT false,  -- name still to be taken from the device hostname
  host          text NOT NULL,
  port          int NOT NULL DEFAULT 443,
  verify_tls    boolean NOT NULL DEFAULT false,
  api_key_enc   text NOT NULL,
  api_key_last4 text NOT NULL,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS devices (
  id         serial PRIMARY KEY,
  serial     text UNIQUE,                -- from the REST API at backup time (not in the .conf)
  hostname   text NOT NULL,
  model      text,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS snapshots (
  id            serial PRIMARY KEY,
  device_id     int NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  backup_file   text NOT NULL UNIQUE,
  fw_version    text,
  fw_build      int,
  multi_vdom    boolean NOT NULL,
  conf_file_ver text,
  taken_at      timestamptz NOT NULL,
  ingested_at   timestamptz NOT NULL DEFAULT now()
);
-- Management IP / hostname the backup was taken from (from the .meta.json sidecar).
ALTER TABLE snapshots ADD COLUMN IF NOT EXISTS host text;
CREATE INDEX IF NOT EXISTS snapshots_device_idx ON snapshots (device_id, taken_at DESC);

CREATE TABLE IF NOT EXISTS vdoms (
  snapshot_id int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  name        text NOT NULL,
  PRIMARY KEY (snapshot_id, name)
);

CREATE TABLE IF NOT EXISTS interfaces (
  snapshot_id int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom        text NOT NULL,
  name        text NOT NULL,
  type        text,
  alias       text,
  description text,
  status      text,
  mode        text,
  ip          inet,
  allowaccess text[],
  role        text,
  parent      text,
  vlanid      int,
  raw         jsonb NOT NULL,
  PRIMARY KEY (snapshot_id, name)
);

CREATE TABLE IF NOT EXISTS ipsec_phase1 (
  snapshot_id int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom        text NOT NULL,
  kind        text NOT NULL,             -- 'interface' (route-based) or 'policy'
  name        text NOT NULL,
  type        text,
  interface   text,
  remote_gw   text,
  ike_version int,
  mode        text,
  proposal    text[],
  dhgrp       text[],
  comments    text,
  raw         jsonb NOT NULL,
  PRIMARY KEY (snapshot_id, vdom, kind, name)
);

CREATE TABLE IF NOT EXISTS ipsec_phase2 (
  snapshot_id int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom        text NOT NULL,
  kind        text NOT NULL,
  name        text NOT NULL,
  phase1name  text,
  src_subnet  cidr,
  dst_subnet  cidr,
  src_name    text,                      -- address object when src-addr-type is name
  dst_name    text,
  proposal    text[],
  dhgrp       text[],
  pfs         text,
  comments    text,
  raw         jsonb NOT NULL,
  PRIMARY KEY (snapshot_id, vdom, kind, name)
);

CREATE TABLE IF NOT EXISTS vpn_ssl_settings (
  snapshot_id      int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom             text NOT NULL,
  status           text,
  port             int,
  source_interface text[],
  servercert       text,
  raw              jsonb NOT NULL,
  PRIMARY KEY (snapshot_id, vdom)
);

CREATE TABLE IF NOT EXISTS vips (
  snapshot_id int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom        text NOT NULL,
  name        text NOT NULL,
  type        text,
  extip       text,                      -- may be a range "a-b"
  mappedip    text[],                    -- may contain ranges
  extintf     text,
  portforward boolean NOT NULL,
  protocol    text,
  extport     text,
  mappedport  text,
  comment     text,
  raw         jsonb NOT NULL,
  PRIMARY KEY (snapshot_id, vdom, name)
);

CREATE TABLE IF NOT EXISTS ippools (
  snapshot_id    int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom           text NOT NULL,
  name           text NOT NULL,
  type           text,
  startip        inet,
  endip          inet,
  source_startip inet,
  source_endip   inet,
  comments       text,
  raw            jsonb NOT NULL,
  PRIMARY KEY (snapshot_id, vdom, name)
);

-- Policy routes (`config router policy`), per VDOM. Unset values keep FortiOS
-- defaults out of the columns: NULL gateway / protocol 0 mean "any".
CREATE TABLE IF NOT EXISTS router_policies (
  snapshot_id   int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom          text NOT NULL,
  seq_num       int NOT NULL,
  status        text,
  action        text,
  input_device  text[],
  src           text[],                  -- subnets as CIDR
  srcaddr       text[],                  -- address objects
  dst           text[],
  dstaddr       text[],
  protocol      int,
  start_port    int,
  end_port      int,
  gateway       inet,
  output_device text,
  comments      text,
  raw           jsonb NOT NULL,
  PRIMARY KEY (snapshot_id, vdom, seq_num)
);

-- Firewall policies, in evaluation order (`seq` = position in the config,
-- which is not the policy id).
CREATE TABLE IF NOT EXISTS firewall_policies (
  snapshot_id  int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom         text NOT NULL,
  policyid     int NOT NULL,
  seq          int NOT NULL,
  name         text,
  uuid         text,
  status       text,
  action       text,
  srcintf      text[],
  dstintf      text[],
  srcaddr      text[],
  dstaddr      text[],
  service      text[],
  internet_service text[],
  schedule     text,
  nat          boolean NOT NULL,
  poolname     text[],
  groups       text[],
  users        text[],
  logtraffic   text,
  comments     text,
  raw          jsonb NOT NULL,
  PRIMARY KEY (snapshot_id, vdom, policyid)
);

CREATE TABLE IF NOT EXISTS addresses (
  snapshot_id int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom        text NOT NULL,
  name        text NOT NULL,
  type        text,
  subnet      inet,                      -- ipmask / interface-subnet
  start_ip    inet,                      -- iprange
  end_ip      inet,
  fqdn        text,
  country     text,
  interface   text,
  comment     text,
  raw         jsonb NOT NULL,
  PRIMARY KEY (snapshot_id, vdom, name)
);

CREATE TABLE IF NOT EXISTS addrgrps (
  snapshot_id int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom        text NOT NULL,
  name        text NOT NULL,
  members     text[],
  comment     text,
  raw         jsonb NOT NULL,
  PRIMARY KEY (snapshot_id, vdom, name)
);

CREATE TABLE IF NOT EXISTS services (
  snapshot_id     int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom            text NOT NULL,
  name            text NOT NULL,
  protocol        text,                  -- TCP/UDP/SCTP, ICMP, ICMP6, IP, ALL
  tcp_portrange   text[],                -- "dst[-dst2][:src[-src2]]"
  udp_portrange   text[],
  sctp_portrange  text[],
  protocol_number int,                   -- protocol IP
  icmptype        int,
  icmpcode        int,
  category        text,
  proxy           boolean NOT NULL,
  comment         text,
  raw             jsonb NOT NULL,
  PRIMARY KEY (snapshot_id, vdom, name)
);

CREATE TABLE IF NOT EXISTS service_groups (
  snapshot_id int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom        text NOT NULL,
  name        text NOT NULL,
  members     text[],
  comment     text,
  raw         jsonb NOT NULL,
  PRIMARY KEY (snapshot_id, vdom, name)
);

-- Threat feeds (Security Fabric > External Connectors). `vdom` is 'global' for feeds
-- defined in config global of a multi-VDOM device; the URL never carries user:password.
CREATE TABLE IF NOT EXISTS threat_feeds (
  snapshot_id           int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom                  text NOT NULL,
  name                  text NOT NULL,
  type                  text NOT NULL,         -- category, address, domain, malware, mac-address
  category              int,                   -- category / domain feeds: number used in web / DNS filters
  status                text NOT NULL,
  update_method         text,                  -- feed (downloaded) or push (through the API)
  resource              text,
  refresh_rate          int,                   -- minutes
  auth                  boolean NOT NULL DEFAULT false,
  server_identity_check text,
  comments              text,
  raw                   jsonb NOT NULL,
  PRIMARY KEY (snapshot_id, vdom, name)
);

-- Who references which object: one row per name used in a group's members or a
-- policy's / policy route's address and service fields, plus the threat feeds in security
-- profiles and the profiles applied by policies / profile groups. `kind` is what the name
-- resolved to (address, addrgrp, vip, vipgrp, ippool, external, service, servicegrp,
-- webfilter, dnsfilter, antivirus, profile-group, unknown); `ref_type`/`ref_id` is the
-- referencing object (addrgrp, vipgrp, servicegrp, policy, routepolicy, webfilter,
-- dnsfilter, antivirus, profile-group + its name/id).
CREATE TABLE IF NOT EXISTS object_refs (
  snapshot_id int NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
  vdom        text NOT NULL,
  name        text NOT NULL,
  kind        text NOT NULL,
  ref_type    text NOT NULL,
  ref_id      text NOT NULL,
  field       text NOT NULL
);
CREATE INDEX IF NOT EXISTS object_refs_name_idx ON object_refs (snapshot_id, vdom, name);
-- IP / network lookup (overlap / containment on inet).
CREATE INDEX IF NOT EXISTS addresses_subnet_gist ON addresses USING gist (subnet inet_ops);
CREATE INDEX IF NOT EXISTS addresses_range_idx ON addresses (start_ip, end_ip) WHERE start_ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS object_refs_ref_idx ON object_refs (snapshot_id, vdom, ref_type, ref_id);

-- Active routing table pulled live from the device (REST monitor API), not from the
-- config backup: one route snapshot per pull, one row per route (ECMP routes are
-- separate rows). `raw` keeps every field FortiOS returned.
CREATE TABLE IF NOT EXISTS route_snapshots (
  id          serial PRIMARY KEY,
  device_id   int NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  firewall_id text,                      -- firewall entry in the web UI it was pulled from
  host        text,
  fw_version  text,
  fw_build    int,
  vdoms       text[] NOT NULL,
  errors      jsonb NOT NULL DEFAULT '[]', -- VDOM / IP version that could not be read
  taken_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS route_snapshots_device_idx ON route_snapshots (device_id, taken_at DESC);

CREATE TABLE IF NOT EXISTS routes (
  route_snapshot_id int NOT NULL REFERENCES route_snapshots(id) ON DELETE CASCADE,
  vdom          text NOT NULL,
  ip_version    smallint NOT NULL,
  type          text,                    -- connect, static, bgp, ospf, rip, isis, ...
  dst           inet NOT NULL,           -- destination prefix
  gateway       inet,                    -- NULL for directly connected routes
  interface     text,
  distance      int,
  metric        int,
  priority      int,
  vrf           int,
  tunnel        boolean NOT NULL DEFAULT false,
  tunnel_parent text,                    -- IPsec dial-up / tunnel parent interface
  installed_at  timestamptz,
  raw           jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS routes_snapshot_idx ON routes (route_snapshot_id, vdom);
CREATE INDEX IF NOT EXISTS routes_dst_gist ON routes USING gist (dst inet_ops);

-- Threat feed contents pulled live from the device (monitor API entry-list): one pull per
-- device and run, the status of every feed in it, and the entries of the newest pull only.
-- `vdom` is the feed's scope as in threat_feeds ('global', a VDOM, or 'root').
CREATE TABLE IF NOT EXISTS feed_pulls (
  id          serial PRIMARY KEY,
  device_id   int NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  firewall_id text,
  host        text,
  backup_file text,                      -- backup the list of feeds came from
  taken_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS feed_pulls_device_idx ON feed_pulls (device_id, taken_at DESC);

CREATE TABLE IF NOT EXISTS feed_status (
  pull_id      int NOT NULL REFERENCES feed_pulls(id) ON DELETE CASCADE,
  vdom         text NOT NULL,
  name         text NOT NULL,
  type         text,
  ok           boolean NOT NULL,         -- the last download worked
  error        text,                     -- FortiOS error (Timeout, DNS fail, ...) or why it could not be asked
  error_code   int,
  file_status  text,
  last_attempt timestamptz,
  last_update  timestamptz,
  entries      int,
  invalid      int,
  PRIMARY KEY (pull_id, vdom, name)
);
-- The list had more lines than the firewall accepts.
ALTER TABLE feed_status ADD COLUMN IF NOT EXISTS overflow boolean NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS feed_entries (
  pull_id  int NOT NULL REFERENCES feed_pulls(id) ON DELETE CASCADE,
  vdom     text NOT NULL,
  name     text NOT NULL,
  entry    text NOT NULL,
  valid    boolean NOT NULL,
  subnet   inet,                         -- address feeds: an IP or prefix ...
  start_ip inet,                         -- ... or a range
  end_ip   inet
);
CREATE INDEX IF NOT EXISTS feed_entries_feed_idx ON feed_entries (pull_id, vdom, name);
CREATE INDEX IF NOT EXISTS feed_entries_subnet_gist ON feed_entries USING gist (subnet inet_ops);
CREATE INDEX IF NOT EXISTS feed_entries_range_idx ON feed_entries (start_ip, end_ip) WHERE start_ip IS NOT NULL;

DROP VIEW IF EXISTS latest_feed_pulls;
CREATE VIEW latest_feed_pulls AS
SELECT DISTINCT ON (device_id) * FROM feed_pulls ORDER BY device_id, taken_at DESC;

DROP VIEW IF EXISTS latest_route_snapshots;
CREATE VIEW latest_route_snapshots AS
SELECT DISTINCT ON (device_id) * FROM route_snapshots ORDER BY device_id, taken_at DESC;

-- Latest snapshot per device, for "current state" queries. Dropped and recreated: s.*
-- changes when snapshots gains a column, which CREATE OR REPLACE VIEW cannot handle.
DROP VIEW IF EXISTS latest_snapshots;
CREATE VIEW latest_snapshots AS
SELECT DISTINCT ON (s.device_id) s.*, d.hostname, d.serial
FROM snapshots s JOIN devices d ON d.id = s.device_id
ORDER BY s.device_id, s.taken_at DESC;
