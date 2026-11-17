// Login for the web UI: one user and password, sessions in memory.
//
// The user is AUTH_USER (default "admin"). The password comes from AUTH_PASSWORD, or - when
// that is unset - a random one is generated on first start, printed once to the console and
// kept only as a scrypt hash in data/auth.json. Delete that file to get a new password.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const AUTH_FILE = path.join(__dirname, '..', 'data', 'auth.json');
const COOKIE = 'fgt_session';
const SESSION_IDLE_MS = 12 * 3600 * 1000; // a session ends after 12 h without requests
const MAX_FAILURES = 5; // failed logins per address ...
const FAILURE_WINDOW_MS = 15 * 60 * 1000; // ... within this window, then it is locked out

const hashPassword = (password, salt) => crypto.scryptSync(String(password), salt, 32);
// Compares digests, so neither length nor content leaks through timing.
const sameText = (a, b) => crypto.timingSafeEqual(
  crypto.createHash('sha256').update(String(a)).digest(),
  crypto.createHash('sha256').update(String(b)).digest(),
);

let cred; // { user, salt: Buffer, hash: Buffer }

function init() {
  const user = process.env.AUTH_USER || 'admin';
  if (process.env.AUTH_PASSWORD) {
    const salt = crypto.randomBytes(16);
    cred = { user, salt, hash: hashPassword(process.env.AUTH_PASSWORD, salt) };
    return;
  }
  let saved;
  try {
    saved = JSON.parse(fs.readFileSync(AUTH_FILE, 'utf8'));
  } catch (err) {
    if (err.code !== 'ENOENT') throw new Error(`Cannot read ${AUTH_FILE}: ${err.message}`);
  }
  if (!saved) {
    const password = crypto.randomBytes(18).toString('base64url');
    const salt = crypto.randomBytes(16);
    saved = { salt: salt.toString('base64'), hash: hashPassword(password, salt).toString('base64') };
    fs.writeFileSync(AUTH_FILE, JSON.stringify(saved, null, 2) + '\n', { mode: 0o600 });
    console.warn(`Login created - user: ${user}  password: ${password}\n`
      + `  This password is shown only once. Set AUTH_PASSWORD to choose your own, or delete ${AUTH_FILE} to generate a new one.`);
  }
  cred = { user, salt: Buffer.from(saved.salt, 'base64'), hash: Buffer.from(saved.hash, 'base64') };
  if (cred.salt.length < 16 || cred.hash.length !== 32) throw new Error(`${AUTH_FILE} is damaged: delete it to generate a new password`);
}

// ---------- failed-login throttle (per client address) ----------
const failures = new Map(); // address -> { count, since }

function lockedFor(addr) {
  const f = failures.get(addr);
  if (!f) return 0;
  const left = f.since + FAILURE_WINDOW_MS - Date.now();
  if (left <= 0) {
    failures.delete(addr);
    return 0;
  }
  return f.count >= MAX_FAILURES ? Math.ceil(left / 1000) : 0;
}

function recordFailure(addr) {
  if (failures.size > 10000) failures.clear();
  const f = failures.get(addr);
  if (f) f.count++;
  else failures.set(addr, { count: 1, since: Date.now() });
}

// ---------- sessions ----------
const sessions = new Map(); // id -> { user, expires }

function sessionId(req) {
  const m = /(?:^|;\s*)fgt_session=([A-Za-z0-9_-]+)/.exec(req.headers.cookie || '');
  return m && m[1];
}

// The logged-in user of a request, or null.
function user(req) {
  const id = sessionId(req);
  const s = id && sessions.get(id);
  if (!s) return null;
  if (s.expires < Date.now()) {
    sessions.delete(id);
    return null;
  }
  s.expires = Date.now() + SESSION_IDLE_MS;
  return s.user;
}

// Secure is added when the request arrived over HTTPS (directly or through a reverse proxy).
function cookie(req, value, extra = '') {
  const https = req.socket.encrypted || /^https\b/.test(req.headers['x-forwarded-proto'] || '');
  return `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Strict${https ? '; Secure' : ''}${extra}`;
}

// Returns { cookie } on success, or { status, error, retryAfter } on failure.
function login(req, username, password) {
  const addr = req.socket.remoteAddress || '';
  const wait = lockedFor(addr);
  if (wait) return { status: 429, error: `Too many failed logins. Try again in ${Math.ceil(wait / 60)} min.`, retryAfter: wait };
  // Both are always checked, so a wrong user takes as long as a wrong password.
  const okUser = sameText(username ?? '', cred.user);
  const okPass = crypto.timingSafeEqual(hashPassword(password ?? '', cred.salt), cred.hash);
  if (!okUser || !okPass) {
    recordFailure(addr);
    return { status: 401, error: 'Wrong user or password' };
  }
  failures.delete(addr);
  const now = Date.now();
  for (const [id, s] of sessions) if (s.expires < now) sessions.delete(id);
  const id = crypto.randomBytes(32).toString('base64url');
  sessions.set(id, { user: cred.user, expires: now + SESSION_IDLE_MS });
  return { cookie: cookie(req, id) };
}

// Ends the session; returns the cookie header that removes it from the browser.
function logout(req) {
  const id = sessionId(req);
  if (id) sessions.delete(id);
  return cookie(req, '', '; Max-Age=0');
}

// Browsers send Origin on every cross-site request that can change something. One that does
// not match the Host the request was sent to comes from another site: refuse it (CSRF).
function sameOrigin(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

module.exports = { init, user, login, logout, sameOrigin };
