// FortiGate backup web UI - zero dependencies, run with `node server.js`.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { testConnection, backupConfig } = require('./lib/fortigate');
const firewalls = require('./lib/firewalls');
const { search } = require('./lib/search');
const push = require('./lib/push');
// Inventory DB is optional: only loaded when DATABASE_URL is set.
const inventory = process.env.DATABASE_URL ? require('./lib/inventory') : null;
const iplookup = process.env.DATABASE_URL ? require('./lib/iplookup') : null;

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

// Firewalls added without a name take the device hostname. If the device was not
// reachable when added, the name is filled in on the first successful test/backup.
async function syncName(fw, status) {
  if (!fw.autoName || !status.hostname) return;
  fw.name = status.hostname;
  fw.autoName = false;
  await firewalls.rename(fw.id, fw.name);
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
      await syncName(fw, status);
      return send(res, 200, status);
    }

    if (m === 'POST' && action === 'backup') {
      // Device status gives the serial, which the config file itself does not contain.
      const status = await testConnection(fw);
      await syncName(fw, status);
      const config = await backupConfig(fw);
      const takenAt = new Date();
      const stamp = takenAt.toISOString().replace(/[:.]/g, '-').slice(0, 19);
      const file = `${safeName(fw.name)}_${safeName(fw.host)}_${stamp}.conf`;
      const full = path.join(BACKUP_DIR, file);
      fs.writeFileSync(full, config, { mode: 0o600 });
      const meta = { ...status, host: fw.host, firewallName: fw.name, takenAt };
      fs.writeFileSync(full.replace(/\.conf$/, '.meta.json'), JSON.stringify(meta, null, 2), { mode: 0o600 });

      let ingest = null;
      if (inventory) {
        try {
          ingest = await inventory.ingestFile(full);
        } catch (err) {
          ingest = { error: `Backup saved, but inventory ingest failed: ${err.message}` };
        }
      }
      return send(res, 200, { file, size: config.length, ingest });
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
      .listen(PORT, BIND, () =>
        console.log(`FortiGate backup UI on http://${BIND}:${PORT} (firewalls stored in ${firewalls.backend}, `
          + `config push ${PUSH_ENABLED ? 'ENABLED' : 'disabled - set ENABLE_PUSH=1 to enable'})`))
  )
  .catch((err) => {
    console.error(`Startup failed: ${err.message}`);
    process.exit(1);
  });
