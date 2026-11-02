// Saved firewalls. Stored in PostgreSQL when DATABASE_URL is set, otherwise in
// data/firewalls.json. Either way the API key is only kept encrypted (see secrets.js).
//
// Records returned by list() carry `apiKeyLast4` only; get() adds the decrypted `apiKey`.
const fs = require('node:fs');
const path = require('node:path');
const { encrypt, decrypt, getMasterKey } = require('./secrets');

const JSON_FILE = path.join(__dirname, '..', 'data', 'firewalls.json');

const sealKey = (id, apiKey) => ({ apiKeyEnc: encrypt(apiKey, id), apiKeyLast4: apiKey.slice(-4) });
const withKey = ({ apiKeyEnc, ...fw }) => ({ ...fw, apiKey: decrypt(apiKeyEnc, fw.id) });
const withoutKey = ({ apiKeyEnc, ...fw }) => fw;

// Older versions stored the key in plain text; encrypt those entries.
function readJson() {
  let list;
  try {
    list = JSON.parse(fs.readFileSync(JSON_FILE, 'utf8'));
  } catch {
    return [];
  }
  return list.map(({ apiKey, ...fw }) => (apiKey ? { ...fw, ...sealKey(fw.id, apiKey) } : fw));
}

// ---------- JSON file ----------
const jsonStore = {
  async init() {
    const list = readJson();
    if (list.length) this.save(list); // rewrites any legacy plain-text keys
  },
  save(list) {
    fs.writeFileSync(JSON_FILE, JSON.stringify(list, null, 2), { mode: 0o600 });
    fs.chmodSync(JSON_FILE, 0o600); // `mode` only applies when the file is created
  },
  async list() {
    return readJson().map(withoutKey);
  },
  async get(id) {
    const fw = readJson().find((f) => f.id === id);
    return fw && withKey(fw);
  },
  async add({ apiKey, ...fw }) {
    const rec = { ...fw, ...sealKey(fw.id, apiKey) };
    this.save([...readJson(), rec]);
    return withoutKey(rec);
  },
  async remove(id) {
    this.save(readJson().filter((f) => f.id !== id));
  },
  async rename(id, name) {
    this.save(readJson().map((f) => (f.id === id ? { ...f, name, autoName: false } : f)));
  },
};

// ---------- PostgreSQL ----------
const COLS = `id, name, auto_name AS "autoName", host, port, verify_tls AS "verifyTls",
  api_key_last4 AS "apiKeyLast4"`;

const pgStore = {
  async init() {
    const { getPool, ensureSchema } = require('./db');
    this.pool = getPool();
    await ensureSchema();
    // Move firewalls from a previous JSON-file setup into the database, then
    // delete the file so no copy of the keys is left outside the database.
    const legacy = readJson();
    if (!legacy.length) return;
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      for (const fw of legacy) await this.insert(client, fw);
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
    fs.unlinkSync(JSON_FILE);
    console.log(`Imported ${legacy.length} firewall(s) from ${JSON_FILE} into the database and removed the file.`);
  },
  insert(db, fw) {
    return db.query(
      `INSERT INTO firewalls (id, name, auto_name, host, port, verify_tls, api_key_enc, api_key_last4)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (id) DO NOTHING`,
      [fw.id, fw.name, !!fw.autoName, fw.host, fw.port, !!fw.verifyTls, fw.apiKeyEnc, fw.apiKeyLast4]
    );
  },
  async list() {
    return (await this.pool.query(`SELECT ${COLS} FROM firewalls ORDER BY lower(name)`)).rows;
  },
  async get(id) {
    const { rows } = await this.pool.query(
      `SELECT ${COLS}, api_key_enc AS "apiKeyEnc" FROM firewalls WHERE id::text = $1`, [id]
    );
    return rows[0] && withKey(rows[0]);
  },
  async add({ apiKey, ...fw }) {
    const rec = { ...fw, ...sealKey(fw.id, apiKey) };
    await this.insert(this.pool, rec);
    return withoutKey({ ...rec, autoName: !!rec.autoName });
  },
  async remove(id) {
    await this.pool.query('DELETE FROM firewalls WHERE id::text = $1', [id]);
  },
  async rename(id, name) {
    await this.pool.query('UPDATE firewalls SET name = $2, auto_name = false WHERE id::text = $1', [id, name]);
  },
};

const store = process.env.DATABASE_URL ? pgStore : jsonStore;

// Fails at startup (not on first use) if the master key is missing or invalid.
async function init() {
  getMasterKey();
  await store.init();
}

module.exports = {
  init,
  list: () => store.list(),
  get: (id) => store.get(id),
  add: (fw) => store.add(fw),
  remove: (id) => store.remove(id),
  rename: (id, name) => store.rename(id, name),
  backend: process.env.DATABASE_URL ? 'database' : 'file',
};
