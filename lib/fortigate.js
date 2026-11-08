// Minimal FortiGate REST API client (API key / Bearer token auth).
const https = require('node:https');

const TIMEOUT_MS = 20000;

function request(fw, method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = https.request(
      {
        host: fw.host,
        port: fw.port || 443,
        method,
        path,
        // FortiGates usually ship with a self-signed certificate.
        rejectUnauthorized: !!fw.verifyTls,
        timeout: TIMEOUT_MS,
        headers: {
          Authorization: `Bearer ${fw.apiKey}`,
          Accept: '*/*',
          ...(payload && {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
          }),
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) })
        );
      }
    );
    req.on('timeout', () => req.destroy(new Error(`Timeout after ${TIMEOUT_MS / 1000}s`)));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

function httpError(res) {
  const hints = {
    401: 'Unauthorized - check the API key and that this host is in the trusted hosts of the API admin',
    403: 'Forbidden - the API admin profile lacks permission (backup needs read access to System config)',
    404: 'Not found - endpoint not available on this FortiOS version',
    405: 'Method not allowed',
  };
  return new Error(`HTTP ${res.status}: ${hints[res.status] || res.body.toString('utf8').slice(0, 200)}`);
}

// Checks connectivity + credentials and returns basic device info.
async function testConnection(fw) {
  const res = await request(fw, 'GET', '/api/v2/monitor/system/status');
  if (res.status !== 200) throw httpError(res);
  let json;
  try {
    json = JSON.parse(res.body.toString('utf8'));
  } catch {
    throw new Error('Unexpected non-JSON response (is this a FortiGate?)');
  }
  const r = json.results || {};
  return {
    hostname: r.hostname,
    model: r.model_name ? `${r.model_name} ${r.model_number || ''}`.trim() : r.model,
    serial: json.serial,
    version: json.version,
    build: json.build,
  };
}

const isConfig = (buf) => buf.toString('utf8', 0, 64).startsWith('#config-version=');

// Downloads the full (global) configuration as text.
// FortiOS <= 7.4 uses GET with query params; 7.6+ expects POST with a JSON body.
async function backupConfig(fw) {
  let res = await request(fw, 'GET', '/api/v2/monitor/system/config/backup?scope=global');
  if (res.status === 200 && isConfig(res.body)) return res.body;

  if (res.status !== 401 && res.status !== 403) {
    res = await request(fw, 'POST', '/api/v2/monitor/system/config/backup', {
      destination: 'file',
      scope: 'global',
    });
    if (res.status === 200 && isConfig(res.body)) return res.body;
  }

  if (res.status !== 200) throw httpError(res);
  throw new Error(`Response is not a FortiGate config: ${res.body.toString('utf8').slice(0, 200)}`);
}

// Active routing table of one VDOM (what `get router info routing-table all` shows),
// IPv4 or IPv6. Needs read access to Router in the API admin profile.
async function getRoutes(fw, vdom, ipVersion = 4) {
  const res = await request(fw, 'GET', `/api/v2/monitor/router/ipv${ipVersion === 6 ? 6 : 4}?vdom=${encodeURIComponent(vdom)}`);
  if (res.status === 403) {
    throw new Error('HTTP 403: Forbidden - the API admin profile needs read access to Router (and to this VDOM)');
  }
  if (res.status !== 200) throw httpError(res);
  let json;
  try {
    json = JSON.parse(res.body.toString('utf8'));
  } catch {
    throw new Error('Unexpected non-JSON response from the routing table');
  }
  return Array.isArray(json.results) ? json.results : [];
}

module.exports = { request, testConnection, backupConfig, getRoutes };
