// FortiGate backup web UI - zero dependencies, run with `node server.js`.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { testConnection } = require('./lib/fortigate');
const jobs = require('./lib/jobs');
const firewalls = require('./lib/firewalls');
const { search } = require('./lib/search');
const push = require('./lib/push');
const { audit, compare, CHECKS } = require('./lib/audit');
// Inventory DB is optional: only loaded when DATABASE_URL is set.
const inventory = process.env.DATABASE_URL ? require('./lib/inventory') : null;
const iplookup = process.env.DATABASE_URL ? require('./lib/iplookup') : null;
const routes = process.env.DATABASE_URL ? require('./lib/routes') : null;

const PORT = Number(process.env.PORT) || 3000;
const BIND = process.env.BIND || '127.0.0.1';
// Writing to firewalls is opt-in: the app has no authentication of its own.
const PUSH_ENABLED = process.env.ENABLE_PUSH === '1';
const DATA_DIR = path.join(__dirname, 'data');
const BACKUP_DIR = path.join(__dirname, 'backups');

// Both hold secrets (master key, device configs): owner-only access.
for (const dir of [DATA_DIR, BACKUP_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
  fs.chmodSync(dir, 0o700);
}

// API keys never leave the server, not even masked.
const publicView = ({ apiKey, apiKeyLast4, ...fw }) => fw;

function validateInput(b) {
  const host = String(b.host || '').trim();
  const apiKey = String(b.apiKey || '').trim();
  const port = Number(b.port) || 443;
  if (!/^[a-zA-Z0-9.\-:\[\]]+$/.test(host)) throw new Error('Invalid IP / hostname');
  if (!apiKey) throw new Error('API key is required');
  if (port < 1 || port > 65535) throw new Error('Invalid port');
  return { name: String(b.name || '').trim(), host, port, apiKey, verifyTls: !!b.verifyTls };
}

// Identifies the device a backup belongs to (hostname from its .meta.json sidecar, else the
// hostname prefix of the file name) and when it was taken.
function backupDevice(file) {
  const full = path.join(BACKUP_DIR, file);
  let meta = {};
  try {
    meta = JSON.parse(fs.readFileSync(full.replace(/\.conf$/, '.meta.json'), 'utf8'));
  } catch {}
  const taken = meta.takenAt ? new Date(meta.takenAt) : null;
  return {
    device: meta.hostname || file.split('_')[0],
    mtime: taken && !isNaN(taken) ? taken : fs.statSync(full).mtime,
  };
}

// Backup files never change once written, so each one is audited only once.
const auditCache = new Map();
function auditFile(full) {
  const st = fs.statSync(full);
  const key = `${full}|${st.mtimeMs}|${st.size}`;
  if (!auditCache.has(key)) {
    if (auditCache.size > 2000) auditCache.clear();
    auditCache.set(key, audit(fs.readFileSync(full, 'utf8')));
  }
  return auditCache.get(key);
}

// ---------- http helpers ----------
// Large inventory responses (tens of thousands of objects) are gzipped when `req` is given.
function send(res, status, data, req) {
  let body = JSON.stringify(data);
  const headers = { 'Content-Type': 'application/json' };
  if (req && body.length > 16384 && /\bgzip\b/.test(req.headers['accept-encoding'] || '')) {
    body = zlib.gzipSync(body);
    headers['Content-Encoding'] = 'gzip';
  }
  res.writeHead(status, headers);
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (c) => {
      raw += c;
      if (raw.length > 1e6) req.destroy();
    });
    req.on('end', () => {
      try {
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error('Invalid JSON body'));
      }
    });
  });
}

const safeName = (s) => s.replace(/[^a-zA-Z0-9._-]/g, '_');

// ---------- routes ----------
async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  const m = req.method;

  if (m === 'GET' && p === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return fs.createReadStream(path.join(__dirname, 'public', 'index.html')).pipe(res);
  }

  if (m === 'GET' && p === '/api/firewalls') {
    return send(res, 200, (await firewalls.list()).map(publicView));
  }

  if (m === 'POST' && p === '/api/firewalls') {
    const fw = { id: crypto.randomUUID(), ...validateInput(await readJson(req)) };
    if (!fw.name) {
      try {
        fw.name = (await testConnection(fw)).hostname;
      } catch {}
      if (!fw.name) Object.assign(fw, { name: fw.host, autoName: true });
    }
    return send(res, 201, publicView(await firewalls.add(fw)));
  }

  // Test credentials before saving them.
  if (m === 'POST' && p === '/api/test') {
    return send(res, 200, await testConnection(validateInput(await readJson(req))));
  }

  if (m === 'GET' && p === '/api/backups') {
    const files = fs
      .readdirSync(BACKUP_DIR)
      .filter((f) => f.endsWith('.conf'))
      .map((f) => {
        const st = fs.statSync(path.join(BACKUP_DIR, f));
        return { file: f, size: st.size, date: st.mtime };
      })
      .sort((a, b) => b.date - a.date);
    return send(res, 200, files);
  }

  // Search inside backup files: ?q=&regex=1&case=1&in=<config path>&file=<one file>&after=<lines below>
  // &latest=1 searches only the newest backup of each device.
  if (m === 'GET' && p === '/api/search') {
    const q = url.searchParams;
    const only = q.get('file') ? path.basename(q.get('file')) : null;
    let files = fs
      .readdirSync(BACKUP_DIR)
      .filter((f) => f.endsWith('.conf') && (!only || f === only))
      .map((f) => ({ name: f, path: path.join(BACKUP_DIR, f), ...backupDevice(f) }))
      .sort((a, b) => b.mtime - a.mtime);
    if (q.get('latest') === '1') {
      const seen = new Set();
      files = files.filter((f) => !seen.has(f.device) && seen.add(f.device));
    }
    return send(res, 200, search(files, q.get('q') || '', {
      regex: q.get('regex') === '1',
      caseSensitive: q.get('case') === '1',
      within: q.get('in') || '',
      after: Number(q.get('after')) || 0,
    }));
  }

  // Security audit of the newest backup of each device (or of one ?file=), plus the
  // security-relevant changes between its last ?history= (default 20) backups.
  if (m === 'GET' && p === '/api/audit') {
    const only = url.searchParams.get('file') ? path.basename(url.searchParams.get('file')) : null;
    const history = Math.min(100, Math.max(0, Number(url.searchParams.get('history') ?? 20) || 0));
    const byDevice = new Map();
    for (const f of fs.readdirSync(BACKUP_DIR).filter((f) => f.endsWith('.conf'))) {
      const b = { file: f, ...backupDevice(f) };
      if (!byDevice.has(b.device)) byDevice.set(b.device, []);
      byDevice.get(b.device).push(b);
    }
    const run = (f) => {
      try {
        return auditFile(path.join(BACKUP_DIR, f.file));
      } catch (err) {
        return { error: err.message };
      }
    };
    const devices = [];
    for (const [device, all] of byDevice) {
      all.sort((a, b) => b.mtime - a.mtime);
      const start = only ? all.findIndex((f) => f.file === only) : 0;
      if (start === -1) continue;
      const files = all.slice(start, start + history + 1);
      const audits = files.map(run);
      const { state, ...latest } = audits[0];
      const changes = [];
      for (let i = 0; i + 1 < files.length; i++) {
        if (audits[i].error || audits[i + 1].error) continue;
        const c = compare(audits[i + 1], audits[i]);
        if (c.items.length || c.newFindings.length || c.resolvedFindings.length) {
          changes.push({ from: files[i + 1].mtime, to: files[i].mtime, fromFile: files[i + 1].file, toFile: files[i].file, ...c });
        }
      }
      devices.push({ file: files[0].file, takenAt: files[0].mtime, device: { hostname: device }, ...latest, changes, compared: files.length - 1 });
    }
    if (only && !devices.length) return send(res, 404, { error: 'Not found' });
    devices.sort((a, b) => String(a.device.hostname).localeCompare(String(b.device.hostname)));
    return send(res, 200, { checks: CHECKS, devices }, req);
  }

  if (p.startsWith('/api/inventory/') && !inventory) {
    return send(res, 503, { error: 'Inventory database not configured (set DATABASE_URL)' });
  }

  // IP / network lookup: where it is configured and which policies use it.
  if (m === 'GET' && p === '/api/inventory/iplookup') {
    const q = url.searchParams;
    try {
      return send(res, 200, await iplookup.lookup(q.get('q'), { all: q.get('all') === '1', includeAny: q.get('any') === '1', broader: q.get('broader') === '1' }), req);
    } catch (err) {
      if (/^(Enter an IP|Invalid)/.test(err.message)) return send(res, 400, { error: err.message });
      throw err;
    }
  }

  if (m === 'GET' && p === '/api/inventory/snapshots') {
    return send(res, 200, await inventory.listSnapshots());
  }

  // Correlation for one object: ?vdom=&name= (policy id / route seq for policies).
  let match = p.match(/^\/api\/inventory\/snapshots\/(\d+)\/xref\/(\w+)$/);
  if (m === 'GET' && match) {
    const q = url.searchParams;
    return send(res, 200, await inventory.xref(Number(match[1]), match[2], q.get('vdom') || '', q.get('name') || ''), req);
  }

  match = p.match(/^\/api\/inventory\/snapshots\/(\d+)\/(\w+)$/);
  if (m === 'GET' && match) {
    return send(res, 200, await inventory.snapshotRows(Number(match[1]), match[2]), req);
  }

  // ---------- routing tables (stored in the inventory database) ----------
  if (p.startsWith('/api/routes') && !routes) {
    return send(res, 503, { error: 'Routing tables are stored in the inventory database: set DATABASE_URL' });
  }

  if (m === 'GET' && p === '/api/routes/snapshots') {
    return send(res, 200, await routes.listSnapshots(), req);
  }

  // Which route each firewall uses for an IP / network: ?q=&mode=best|covering|inside&all=1
  if (m === 'GET' && p === '/api/routes/lookup') {
    const q = url.searchParams;
    try {
      return send(res, 200, await routes.lookup(q.get('q'), { mode: q.get('mode') || 'best', all: q.get('all') === '1' }), req);
    } catch (err) {
      if (/^(Enter an IP|Invalid)/.test(err.message)) return send(res, 400, { error: err.message });
      throw err;
    }
  }

  // Routes of one pull: ?vdom=&type=&q=&limit=&format=csv
  match = p.match(/^\/api\/routes\/snapshots\/(\d+)$/);
  if (m === 'GET' && match) {
    const q = url.searchParams;
    const r = await routes.snapshotRoutes(Number(match[1]), {
      vdom: q.get('vdom'), type: q.get('type'), q: q.get('q'), limit: q.get('format') === 'csv' ? 50000 : q.get('limit'),
    });
    if (q.get('format') !== 'csv') return send(res, 200, r, req);
    const cols = ['vdom', 'ip_version', 'type', 'dst', 'gateway', 'interface', 'distance', 'metric', 'priority', 'vrf', 'tunnel', 'tunnel_parent', 'installed_at'];
    const cell = (v) => (v == null ? '' : v instanceof Date ? v.toISOString() : /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
    const stamp = new Date(r.snapshot.taken_at).toISOString().replace(/[:.]/g, '-').slice(0, 19);
    res.writeHead(200, {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="${safeName(r.snapshot.hostname)}_routes_${stamp}.csv"`,
    });
    return res.end([cols.join(','), ...r.routes.map((row) => cols.map((c) => cell(row[c])).join(','))].join('\n') + '\n');
  }
  if (m === 'DELETE' && match) {
    await routes.deleteSnapshot(Number(match[1]));
    return send(res, 200, { ok: true });
  }

  // Load an existing backup file into the inventory database.
  match = p.match(/^\/api\/backups\/([^/]+)\/ingest$/);
  if (m === 'POST' && match) {
    if (!inventory) return send(res, 503, { error: 'Inventory database not configured (set DATABASE_URL)' });
    const file = path.basename(decodeURIComponent(match[1]));
    const full = path.join(BACKUP_DIR, file);
    if (!file.endsWith('.conf') || !fs.existsSync(full)) return send(res, 404, { error: 'Not found' });
    return send(res, 200, await inventory.ingestFile(full));
  }

  match = p.match(/^\/api\/backups\/([^/]+)$/);
  if (m === 'GET' && match) {
    const file = path.basename(decodeURIComponent(match[1]));
    const full = path.join(BACKUP_DIR, file);
    if (!file.endsWith('.conf') || !fs.existsSync(full)) return send(res, 404, { error: 'Not found' });
    res.writeHead(200, {
      'Content-Type': 'text/plain',
      'Content-Disposition': `attachment; filename="${file}"`,
    });
    return fs.createReadStream(full).pipe(res);
  }

  // ---------- push configuration ----------
  // Automatic backups / routing-table refresh: intervals and last result per firewall.
  if (m === 'GET' && p === '/api/auto') {
    return send(res, 200, jobs.status());
  }

  if (m === 'GET' && p === '/api/push/status') {
    return send(res, 200, { enabled: PUSH_ENABLED, types: Object.fromEntries(Object.entries(push.TYPES).map(([k, t]) => [k, t.label])) });
  }

  if (m === 'GET' && p === '/api/push/history') {
    return send(res, 200, push.history(Number(url.searchParams.get('limit')) || 100));
  }

  // Body: { targets: [{ firewall: id, vdom }], type, data, update, dryRun }
  // (or { firewalls: [ids], vdom } for one VDOM on each). dryRun only reads from the devices.
  if (m === 'POST' && p === '/api/push') {
    const b = await readJson(req);
    if (!b.dryRun && !PUSH_ENABLED) return send(res, 403, { error: 'Pushing is disabled. Start the server with ENABLE_PUSH=1 to enable it.' });
    const raw = Array.isArray(b.targets) ? b.targets
      : (Array.isArray(b.firewalls) ? b.firewalls : []).map((firewall) => ({ firewall, vdom: b.vdom }));
    const seen = new Set();
    const wanted = raw.map((t) => ({ id: String(t?.firewall ?? ''), vdom: String(t?.vdom || 'root') }))
      .filter((t) => !seen.has(`${t.id}|${t.vdom}`) && seen.add(`${t.id}|${t.vdom}`));
    if (!wanted.length) throw new Error('Select at least one firewall and VDOM');
    const fwById = new Map();
    for (const id of new Set(wanted.map((t) => t.id))) {
      const fw = await firewalls.get(id);
      if (!fw) return send(res, 404, { error: 'Firewall not found' });
      fwById.set(id, fw);
    }
    const targets = wanted.map((t) => ({ fw: fwById.get(t.id), vdom: t.vdom }));
    return send(res, 200, await push.push(targets, { type: b.type, data: b.data, update: b.update, dryRun: !!b.dryRun }));
  }

  match = p.match(/^\/api\/firewalls\/([\w-]+)\/vdoms$/);
  if (m === 'GET' && match) {
    const fw = await firewalls.get(match[1]);
    if (!fw) return send(res, 404, { error: 'Firewall not found' });
    return send(res, 200, { vdoms: await push.vdoms(fw) });
  }

  // Object names on the device (interfaces, addresses, services, ...) for autocompletion.
  match = p.match(/^\/api\/firewalls\/([\w-]+)\/objects$/);
  if (m === 'GET' && match) {
    const fw = await firewalls.get(match[1]);
    if (!fw) return send(res, 404, { error: 'Firewall not found' });
    return send(res, 200, await push.suggestions(fw, url.searchParams.get('vdom')));
  }

  // Reads the live routing table of every VDOM and stores it in the database.
  match = p.match(/^\/api\/firewalls\/([\w-]+)\/routes$/);
  if (m === 'POST' && match) {
    if (!routes) return send(res, 503, { error: 'Routing tables are stored in the inventory database: set DATABASE_URL' });
    const fw = await firewalls.get(match[1]);
    if (!fw) return send(res, 404, { error: 'Firewall not found' });
    return send(res, 200, await jobs.pullRoutes(fw));
  }

  match = p.match(/^\/api\/firewalls\/([\w-]+)(?:\/(test|backup))?$/);
  if (match) {
    const [, id, action] = match;
    const fw = await firewalls.get(id);
    if (!fw) return send(res, 404, { error: 'Firewall not found' });

    if (m === 'DELETE' && !action) {
      await firewalls.remove(id);
      return send(res, 200, { ok: true });
    }

    if (m === 'POST' && action === 'test') {
      const status = await testConnection(fw);
      await jobs.syncName(fw, status.hostname);
      return send(res, 200, status);
    }

    if (m === 'POST' && action === 'backup') {
      return send(res, 200, await jobs.backup(fw));
    }
  }

  send(res, 404, { error: 'Not found' });
}

firewalls
  .init()
  .then(() =>
    http
      .createServer((req, res) =>
        handle(req, res).catch((err) => send(res, 400, { error: err.message }))
      )
      .listen(PORT, BIND, () => {
        console.log(`FortiGate backup UI on http://${BIND}:${PORT} (firewalls stored in ${firewalls.backend}, `
          + `config push ${PUSH_ENABLED ? 'ENABLED' : 'disabled - set ENABLE_PUSH=1 to enable'})`);
        jobs.start();
        const a = jobs.status();
        console.log(`Automatic backups: ${a.backupHours ? `every ${a.backupHours} h` : 'off'}, `
          + `routing tables: ${a.routesHours ? `every ${a.routesHours} h` : 'off (needs DATABASE_URL)'}`);
      })
  )
  .catch((err) => {
    console.error(`Startup failed: ${err.message}`);
    process.exit(1);
  });
