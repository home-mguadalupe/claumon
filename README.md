# FortiGate Backup

A small self-hosted web UI that backs up FortiGate configurations over the REST API,
searches inside the backup files, and (optionally) loads them into a PostgreSQL
inventory of interfaces, firewall policies, address and service objects and groups, IPsec
tunnels, VIPs, IP pools, SSL-VPN settings and policy routes, with a cross-reference
of which policies and groups use which objects.

No build step and no framework: plain Node.js, a single HTML page and one
dependency (`pg`, only used when the inventory database is enabled).

## Requirements

- Node.js 18 or newer
- Docker + Docker Compose (only for the optional inventory database)
- A FortiGate REST API admin with read access to the configuration and its API key

## Quick start

```bash
npm install
npm start
```

Open <http://127.0.0.1:3000>, add a firewall (host, HTTPS port, API key), click
**Test**, then **Backup**.

### With Docker

Runs the app and the inventory database together; only Docker is needed.

```bash
docker compose up -d --build
```

Open <http://127.0.0.1:3000>. The port is published on `127.0.0.1` only. Use
`PORT=8080 docker compose up -d` for another host port. Set `PGPASSWORD`,
`ENABLE_PUSH` or `FGT_MASTER_KEY` in the shell or in a `.env` file next to
`docker-compose.yml` (URL-safe characters only in `PGPASSWORD`).

`data/` (master key, push log) and `backups/` live in the `appdata` and `backups`
volumes, and the database in `pgdata`. `docker compose down` keeps them;
`docker compose down -v` **deletes them**, including the master key. Without
that key, the stored API keys can't be decrypted. To copy the key out:

```bash
docker compose cp app:/app/data/master.key ./master.key
```

To load existing backup files from inside the container:

```bash
docker compose exec app sh -c 'node scripts/ingest.js backups/*.conf'
```

### With the inventory database (without Docker for the app)

```bash
docker compose up -d postgres   # PostgreSQL 16; db/schema.sql is applied on first start
DATABASE_URL=postgres://fortiinv:fortiinv@127.0.0.1:5432/fortiinv npm start
```

With `DATABASE_URL` set, every new backup is loaded into the inventory automatically.
Existing backups can be loaded from the **Backups** tab (**Load to DB**) or from the
command line:

```bash
DATABASE_URL=postgres://fortiinv:fortiinv@127.0.0.1:5432/fortiinv \
  node scripts/ingest.js backups/*.conf
```

With `DATABASE_URL` set, saved firewalls (and their encrypted API keys) are stored in
the database too. Firewalls from an earlier `data/firewalls.json` are imported on
startup and the file is deleted. `db/schema.sql` is applied on every start, so
existing databases pick up new tables automatically.

## Configuration

| Variable       | Default     | Description                                                               |
|----------------|-------------|---------------------------------------------------------------------------|
| `PORT`         | `3000`      | HTTP port                                                                 |
| `BIND`         | `127.0.0.1` | Listen address. Use `0.0.0.0` to expose it on the network (see Security). |
| `DATABASE_URL` | *(unset)*   | PostgreSQL connection string; enables the inventory features              |
| `PGPASSWORD`   | `fortiinv`  | Password for the Postgres container in `docker-compose.yml`               |
| `FGT_MASTER_KEY` | *(unset)* | Master key that encrypts the stored API keys (32 bytes, base64)          |
| `FGT_MASTER_KEY_FILE` | `data/master.key` | Where the master key is read from / generated when `FGT_MASTER_KEY` is unset |
| `ENABLE_PUSH`  | *(unset)*   | `1` allows the **Push** tab to change firewall configuration (see Security) |

## Using the UI

### Firewalls
Add, test, back up and delete firewalls. You only enter the IP/hostname, HTTPS port
and API key: the firewall's name is taken from the device hostname when you save it.
If the device can't be reached at that moment, it is listed under its IP until the
next successful **Test** or **Backup**. **Test** shows hostname, model, firmware and
serial number.

### Backups
- **Search configs**: searches inside the backup files as you type.
  - Literal by default. Every character, including `" / * $ \ # [ ]` and spaces,
    matches exactly as typed. Enable **Regex** for regular expressions and
    **Match case** for case-sensitive search.
  - **Within config section** narrows matches to a config path, e.g. `firewall address`
    or `vpn ipsec phase1-interface`. Clicking a section in a result's path does the same.
  - **Backup** chooses what to search: **Latest per device** (default) searches only the
    newest backup of each firewall, **All backups** searches every file, or pick one file
    (or use **Search in file** on a backup row).
  - Each match shows its line number and full config path
    (`vdom › "root" › firewall address › "obj1"`). Secret values (passwords, PSKs,
    private keys, `ENC …` values) are redacted and cannot be searched for.
  - **Lines below** shows that many lines after each match (like `grep -A`), e.g. to see
    the rest of an `edit` block. Secrets stay redacted in these lines too.
  - Shows up to 500 matches; the total count is always shown.
- The backup list lets you download each file and load it into the inventory.

### Inventory
- **Firewalls** (top of the sidebar) is a one-line-per-device overview: model, FortiOS
  version and build, management IP (the address the backup was taken from), serial,
  VDOMs and last backup. Tick **All firewalls** to see the whole fleet; the VDOM filter
  shows the firewalls that have that VDOM. Click a row for the full VDOM list.
- Click a firewall in the list on the left (filterable) to show just that one. The
  newest snapshot is selected by default; older ones are in the **Snapshot** dropdown.
- Tick the checkboxes to view several firewalls at once, or **All firewalls**
  (which follows the list filter, e.g. filter "HQ" then tick All). Each firewall's
  latest snapshot is used, a **Firewall** column is added, and the VDOM filter
  lists the VDOMs of all selected firewalls.
- Filter by VDOM and search: matches are highlighted and counted.
- Click a column header to sort (ascending → descending → off). IPs sort numerically.
- Click a row to see all of its settings (secrets redacted). For policies, policy
  routes, addresses, services, their groups, VIPs and IP pools it also shows the correlation:
  - **contents**: a policy's source / destination / service / NAT pool, or a group's
    members, with nested groups expanded down to the actual subnets, ranges, FQDNs,
    VIPs and ports;
  - **where used**: every policy, policy route and group that references the object,
    directly or through (nested) groups (`via G1 › G2`).
  Names in there are links that jump to that object.
- The **Used by** column (addresses, services, groups, VIPs, IP pools) counts direct references; `unused` marks objects that no
  group, policy or policy route references.
- Policies are listed in evaluation order (config order), not by ID. Large tables show
  the first 1000 matching rows; search or pick a VDOM to narrow down.
- The view state lives in the URL (e.g. `#inventory?dev=1&sec=vips&q=172.30`), so
  you can bookmark or share a view and the browser back button works.

### Push
Creates or updates objects on one or more firewalls through the REST API:
**Address** (subnet, IP range or FQDN), **Address group**, **Service** (TCP/UDP/SCTP
ports, ICMP or IP protocol), **Service group** and **Policy**.

- Tick one or more firewalls, then tick one or more **VDOMs**. The VDOM list shows every
  VDOM of the ticked firewalls (with several ticked, `2/3` = on how many of them it
  exists); each ticked VDOM is pushed to every ticked firewall that has it.
  VDOMs come from each firewall's newest inventory snapshot, so they appear instantly;
  only firewalls without a snapshot are asked over the API. A VDOM created since the last
  backup appears after the next backup.
- Interface, address, service and schedule names are suggested live from the first
  ticked firewall and VDOM.
- Subnets can be typed as `10.1.0.0/24`, `10.1.0.0 255.255.255.0` or a single host IP.
  Port ranges as `443 8080-8090`, or `dst:src` (`1000:2000`).
- List fields (group members, policy interfaces / addresses / services): type a name and
  press Enter, or pick a suggestion.
- **Preview** only reads from the firewalls: it shows the exact API request and, per
  firewall, whether the object will be created, updated, or already exists.
  **Push** is enabled only after a preview of exactly the current form.
- Existing objects are left alone unless **Update … if it exists** is ticked. Policies
  are matched by name (a policy without a name is always created).
- New policies go to the bottom of the list, or above **Place before policy ID**.
- Every push (per firewall, with the payload and result) is appended to
  `data/push-log.jsonl` and shown under **Recent pushes**.
- Pushing needs `ENABLE_PUSH=1` and an API admin profile with read-write access to
  Firewall configuration. Changes reach the inventory with the next backup.

Keyboard: `/` focuses the search box, `Esc` clears it.

## Project layout

```
server.js            HTTP server and JSON API
public/index.html    the whole web UI
lib/fortigate.js     FortiGate REST API client (status, config backup)
lib/push.js          creating / updating objects and policies on firewalls
lib/fgtparse.js      FortiOS config parser
lib/extract.js       extracts inventory records from a parsed config
lib/inventory.js     PostgreSQL ingest + queries
lib/search.js        full-text search inside backup files
lib/firewalls.js     saved firewalls (database or JSON file)
lib/secrets.js       API key encryption (AES-256-GCM)
lib/db.js            shared PostgreSQL pool + schema setup
scripts/ingest.js    CLI: load backup files into the database
db/schema.sql        database schema
data/master.key      master key for API key encryption (generated at first start)
data/firewalls.json  saved firewalls when running without a database
data/push-log.jsonl  log of every config push
backups/             backup files (*.conf) + device metadata (*.meta.json)
```

## API

| Method | Path                                         | Description                          |
|--------|----------------------------------------------|--------------------------------------|
| GET    | `/api/firewalls`                             | List firewalls (without API keys)    |
| POST   | `/api/firewalls`                             | Add a firewall                       |
| DELETE | `/api/firewalls/:id`                         | Remove a firewall                    |
| POST   | `/api/firewalls/:id/test`                    | Test the connection                  |
| POST   | `/api/firewalls/:id/backup`                  | Take a backup                        |
| POST   | `/api/test`                                  | Test credentials before saving       |
| GET    | `/api/backups`                               | List backup files                    |
| GET    | `/api/backups/:file`                         | Download a backup                    |
| POST   | `/api/backups/:file/ingest`                  | Load a backup into the inventory     |
| GET    | `/api/search?q=&regex=1&case=1&in=&file=&after=&latest=1` | Search inside backups (`after` = lines below each match, `latest=1` = newest backup per device) |
| GET    | `/api/firewalls/:id/vdoms`                   | VDOM names on the device             |
| GET    | `/api/firewalls/:id/objects?vdom=`           | Object names on the device (for autocompletion) |
| GET    | `/api/push/status`                           | Whether pushing is enabled, object types |
| POST   | `/api/push`                                  | Create / update an object on firewalls. Body: `{ targets: [{ firewall: id, vdom }], type, data, update, dryRun }` (or `firewalls: [ids], vdom`); `type` = `address`, `addrgrp`, `service`, `servicegrp`, `policy`; `dryRun` only checks |
| GET    | `/api/push/history?limit=`                   | Recent pushes, newest first          |
| GET    | `/api/inventory/snapshots`                   | List inventory snapshots             |
| GET    | `/api/inventory/snapshots/:id/:section`      | Rows of one section of a snapshot    |
| GET    | `/api/inventory/snapshots/:id/xref/:section?vdom=&name=` | Settings, contents and where-used of one object (`name` = policy ID / route seq for policies) |

Sections: `interfaces`, `policies`, `addresses`, `addrgrps`, `services`, `servicegrps`, `routepolicies`, `phase1`, `phase2`,
`vips`, `ippools`, `sslvpn`. Correlation (`xref`) works for `policies`, `routepolicies`,
`addresses`, `addrgrps`, `services`, `servicegrps`, `vips` and `ippools`; references are stored in `object_refs`.

## Security

- The app has **no authentication**. Keep the default `BIND=127.0.0.1`, or put it
  behind a reverse proxy with authentication before exposing it.
- **API keys are encrypted at rest** with AES-256-GCM, in the `firewalls` table
  (database mode) or `data/firewalls.json` (file mode). The key is never sent to
  the browser, not even masked.
  Each encrypted key is bound to its firewall's id, so it cannot be copied onto
  another record.
- **The master key is never stored in the database.** It comes from `FGT_MASTER_KEY`
  or from `data/master.key`, which is generated (mode `0600`) on first start. A
  database dump alone does not reveal any API key.
  - **Back up the master key** separately from the database. Without it, the stored
    API keys cannot be decrypted and every firewall has to be re-added.
  - For production, set `FGT_MASTER_KEY` from a secret manager or systemd
    credential (`openssl rand -base64 32`) instead of keeping a key file next to the app.
  - Anyone who has both the master key and the database (or who controls the
    running server) can decrypt the keys. Give the FortiGate API user a
    **read-only** profile and restrict its **trusted hosts** to this server.
- **Pushing changes is off by default.** With `ENABLE_PUSH=1`, anyone who can reach the
  UI can change firewall policies, so keep `BIND=127.0.0.1` or put authentication in
  front of it. Pushing also needs a **read-write** API profile; limit it to Firewall
  configuration (and the VDOMs you manage), or keep read-only firewalls for backups only.
- Backups contain the full configuration. `data/` and `backups/` are set to mode
  `0700`, files to `0600`, and both are git-ignored. Treat them as secrets.
- Leave **Verify TLS cert** on wherever the firewall has a trusted certificate.
