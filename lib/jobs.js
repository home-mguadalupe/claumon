// Backups and routing-table pulls, run from the UI and automatically on a schedule, so the
// inventory stays current without anyone clicking anything.
const fs = require('node:fs');
const path = require('node:path');
const { testConnection, backupConfig } = require('./fortigate');
const firewalls = require('./firewalls');

const BACKUP_DIR = path.join(__dirname, '..', 'backups');
const inventory = process.env.DATABASE_URL ? require('./inventory') : null;
const routes = process.env.DATABASE_URL ? require('./routes') : null;

// 0 turns a job off. Routes change far more often than config, so they refresh more often.
const hours = (v, def) => (v === undefined || v === '' ? def : Math.max(0, Number(v) || 0));
const BACKUP_HOURS = hours(process.env.AUTO_BACKUP_HOURS, 24);
const ROUTES_HOURS = routes ? hours(process.env.AUTO_ROUTES_HOURS, 1) : 0;
const TICK_MS = 5 * 60 * 1000;
const RETRY_MS = 30 * 60 * 1000;  // a firewall that failed is retried after this, not every tick
const PARALLEL = 4;

const safeName = (s) => s.replace(/[^a-zA-Z0-9._-]/g, '_');

// Firewalls added without a name take the device hostname once it is reachable.
async function syncName(fw, hostname) {
  if (!fw.autoName || !hostname) return;
  fw.name = hostname;
  fw.autoName = false;
  await firewalls.rename(fw.id, fw.name);
}

async function pullRoutes(fw, status) {
  const r = await routes.pull(fw, status);
  await syncName(fw, r.hostname);
  return r;
}

// Saves the config, loads it into the inventory and stores the routing table next to it.
// Inventory and route failures don't fail the backup; they are reported in the result.
async function backup(fw) {
  // Device status gives the serial, which the config file itself does not contain.
  const status = await testConnection(fw);
  await syncName(fw, status.hostname);
  const config = await backupConfig(fw);
  const takenAt = new Date();
  const stamp = takenAt.toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const file = `${safeName(fw.name)}_${safeName(fw.host)}_${stamp}.conf`;
  const full = path.join(BACKUP_DIR, file);
  fs.writeFileSync(full, config, { mode: 0o600 });
  const meta = { ...status, host: fw.host, firewallName: fw.name, takenAt };
  fs.writeFileSync(full.replace(/\.conf$/, '.meta.json'), JSON.stringify(meta, null, 2), { mode: 0o600 });

  let ingest = null;
  let routeResult = null;
  if (inventory) {
    try {
      ingest = await inventory.ingestFile(full);
    } catch (err) {
      ingest = { error: `Backup saved, but inventory ingest failed: ${err.message}` };
    }
    try {
      routeResult = await pullRoutes(fw, status);
    } catch (err) {
      routeResult = { error: `Routing table not saved: ${err.message}` };
    }
  }
  return { file, size: config.length, ingest, routes: routeResult };
}

// ---------- schedule ----------
const state = { running: false, lastTick: null, results: {} };  // results: firewall id -> last automatic run

// Newest backup file of a firewall (files are named "<name>_<host>_<time>.conf").
function lastBackup(fw) {
  let newest = 0;
  for (const f of fs.readdirSync(BACKUP_DIR)) {
    if (f.endsWith('.conf') && f.includes(`_${safeName(fw.host)}_`)) {
      newest = Math.max(newest, fs.statSync(path.join(BACKUP_DIR, f)).mtimeMs);
    }
  }
  return newest;
}

async function tick() {
  if (state.running) return;
  state.running = true;
  state.lastTick = new Date();
  try {
    const now = Date.now();
    const pulled = ROUTES_HOURS ? await routes.lastPulls() : new Map();
    const due = [];
    for (const fw of await firewalls.list()) {
      const prev = state.results[fw.id];
      if (prev?.error && now - new Date(prev.at) < RETRY_MS) continue;
      if (BACKUP_HOURS && now - lastBackup(fw) >= BACKUP_HOURS * 36e5) due.push([fw.id, 'backup']);
      else if (ROUTES_HOURS && now - (pulled.get(fw.id) || 0) >= ROUTES_HOURS * 36e5) due.push([fw.id, 'routes']);
    }
    await Promise.all(Array.from({ length: PARALLEL }, async () => {
      for (let job; (job = due.shift());) {
        const [id, kind] = job;
        const at = new Date();
        try {
          const fw = await firewalls.get(id);  // with the decrypted API key
          if (!fw) continue;
          const r = kind === 'backup' ? await backup(fw) : await pullRoutes(fw);
          const rt = kind === 'backup' ? r.routes : r;
          const warn = r.ingest?.error || rt?.error || (rt?.errors?.length
            ? 'routing table partly read: ' + rt.errors.map((e) => `${e.vdom} IPv${e.ipVersion}: ${e.error}`).join('; ') : null);
          state.results[id] = { kind, at, ok: true, warning: warn || undefined };
        } catch (err) {
          state.results[id] = { kind, at, ok: false, error: err.message };
          console.error(`Automatic ${kind} of firewall ${id} failed: ${err.message}`);
        }
      }
    }));
  } catch (err) {
    console.error(`Automatic run failed: ${err.message}`);
  } finally {
    state.running = false;
  }
}

function start() {
  if (!BACKUP_HOURS && !ROUTES_HOURS) return;
  setTimeout(tick, 30 * 1000).unref();  // shortly after start, then every few minutes
  setInterval(tick, TICK_MS).unref();
}

const status = () => ({
  backupHours: BACKUP_HOURS, routesHours: ROUTES_HOURS, running: state.running,
  lastTick: state.lastTick, results: state.results,
});

module.exports = { backup, pullRoutes, syncName, start, status, BACKUP_DIR };
