// Encryption of stored firewall API keys (AES-256-GCM).
//
// The master key never goes into the database: it comes from FGT_MASTER_KEY
// (base64, 32 bytes) or from a key file (FGT_MASTER_KEY_FILE, default
// data/master.key) that is generated on first use. A database dump alone is
// therefore not enough to recover any API key.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const DEFAULT_KEY_FILE = path.join(__dirname, '..', 'data', 'master.key');
const PREFIX = 'v1:';

let masterKey;

function parseKey(b64, source) {
  const key = Buffer.from(String(b64).trim(), 'base64');
  if (key.length !== 32) throw new Error(`${source} must be 32 bytes, base64-encoded (generate one with: openssl rand -base64 32)`);
  return key;
}

function getMasterKey() {
  if (masterKey) return masterKey;
  if (process.env.FGT_MASTER_KEY) return (masterKey = parseKey(process.env.FGT_MASTER_KEY, 'FGT_MASTER_KEY'));
  const file = process.env.FGT_MASTER_KEY_FILE || DEFAULT_KEY_FILE;
  try {
    // 'wx' only creates the file if it does not exist yet, so a key is never overwritten.
    fs.writeFileSync(file, crypto.randomBytes(32).toString('base64') + '\n', { mode: 0o600, flag: 'wx' });
    console.warn(`Generated a new master key in ${file} - back it up: without it the stored API keys cannot be decrypted.`);
  } catch (err) {
    if (err.code !== 'EEXIST') throw err;
  }
  return (masterKey = parseKey(fs.readFileSync(file, 'utf8'), file));
}

// `bind` (the firewall id) is authenticated along with the ciphertext, so an
// encrypted key copied onto another firewall's record fails to decrypt.
function encrypt(plain, bind) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', getMasterKey(), iv);
  c.setAAD(Buffer.from(bind));
  const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
  return PREFIX + Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
}

function decrypt(blob, bind) {
  if (!String(blob).startsWith(PREFIX)) throw new Error('Unknown API key encryption format');
  const raw = Buffer.from(blob.slice(PREFIX.length), 'base64');
  const d = crypto.createDecipheriv('aes-256-gcm', getMasterKey(), raw.subarray(0, 12));
  d.setAAD(Buffer.from(bind));
  d.setAuthTag(raw.subarray(12, 28));
  try {
    return Buffer.concat([d.update(raw.subarray(28)), d.final()]).toString('utf8');
  } catch {
    throw new Error('Cannot decrypt the stored API key - wrong master key?');
  }
}

module.exports = { encrypt, decrypt, getMasterKey };
