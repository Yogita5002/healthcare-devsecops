// Healthcare Patient Portal - secure demo API
// Security features: input validation, secrets from environment variables,
// masked PHI, security headers, request size limit, security metrics.
'use strict';
const http = require('http');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD; // injected from Kubernetes Secret
const API_KEY = process.env.API_KEY;               // injected from Kubernetes Secret

if (!ADMIN_PASSWORD || !API_KEY) {
  console.error('Required secrets are missing. Refusing to start.');
  process.exit(1);
}

// Sample patient records (PHI) - never returned unmasked
const patients = {
  1: { name: 'Ravi Kumar', dob: '1985-03-12', phone: '9876543210', condition: 'Hypertension' },
  2: { name: 'Anita Sharma', dob: '1992-07-25', phone: '9123456780', condition: 'Type 2 Diabetes' },
  3: { name: 'Arjun Mehta', dob: '1978-11-02', phone: '9988776655', condition: 'Asthma' },
};

const metrics = { requests: 0, failedLogins: 0, successfulLogins: 0, unauthorized: 0, badInput: 0 };

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; form-action 'none'",
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
  'Permissions-Policy': 'geolocation=(), camera=(), microphone=()',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
};

function send(res, status, body, type) {
  const isText = typeof body === 'string';
  const contentType = type || (isText ? 'text/plain' : 'application/json');
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': contentType + '; charset=utf-8' });
  res.end(isText ? body : JSON.stringify(body));
}

// Constant-time comparison prevents timing attacks on passwords/keys
function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

function maskPatient(id, p) {
  const [first, last] = p.name.split(' ');
  return {
    id: Number(id),
    name: `${first} ${last.charAt(0)}.`,
    dob: `****-**-${p.dob.slice(-2)}`,
    phone: `******${p.phone.slice(-4)}`,
    condition: p.condition,
  };
}

// Reads a JSON body with a 1 KB size limit
function readJson(req, res, callback) {
  let body = '';
  let tooLarge = false;
  req.on('data', (chunk) => {
    if (tooLarge) return;
    body += chunk;
    if (body.length > 1024) tooLarge = true;
  });
  req.on('end', () => {
    if (tooLarge) { metrics.badInput++; return send(res, 413, { error: 'Request too large' }); }
    let data;
    try { data = JSON.parse(body); } catch { metrics.badInput++; return send(res, 400, { error: 'Invalid JSON' }); }
    callback(data || {});
  });
}

function handleLogin(req, res) {
  readJson(req, res, (data) => {
    const { username, password } = data;
    // Input validation: strict allow-list for username, length limit for password
    if (typeof username !== 'string' || !/^[a-zA-Z0-9_]{3,20}$/.test(username) ||
        typeof password !== 'string' || password.length < 1 || password.length > 64) {
      metrics.badInput++;
      return send(res, 400, { error: 'Invalid input' });
    }
    if (username === 'admin' && safeEqual(password, ADMIN_PASSWORD)) {
      metrics.successfulLogins++;
      return send(res, 200, { message: 'Login successful' });
    }
    metrics.failedLogins++;
    console.warn(`SECURITY: failed login for user "${username}" from ${req.socket.remoteAddress}`);
    return send(res, 401, { error: 'Invalid credentials' });
  });
}

function handlePatient(req, res, id) {
  const key = req.headers['x-api-key'];
  if (!key || !safeEqual(key, API_KEY)) {
    metrics.unauthorized++;
    console.warn(`SECURITY: unauthorized access attempt to patient records from ${req.socket.remoteAddress}`);
    return send(res, 401, { error: 'Unauthorized' });
  }
  if (!/^\d{1,6}$/.test(id)) {
    metrics.badInput++;
    return send(res, 400, { error: 'Patient ID must be numeric' });
  }
  const p = patients[id];
  if (!p) return send(res, 404, { error: 'Patient not found' });
  return send(res, 200, maskPatient(id, p));
}

function metricsText() {
  return [
    '# HELP app_http_requests_total Total HTTP requests received',
    '# TYPE app_http_requests_total counter',
    `app_http_requests_total ${metrics.requests}`,
    '# HELP app_failed_logins_total Failed login attempts',
    '# TYPE app_failed_logins_total counter',
    `app_failed_logins_total ${metrics.failedLogins}`,
    '# HELP app_successful_logins_total Successful logins',
    '# TYPE app_successful_logins_total counter',
    `app_successful_logins_total ${metrics.successfulLogins}`,
    '# HELP app_unauthorized_requests_total Requests rejected for missing or invalid API key',
    '# TYPE app_unauthorized_requests_total counter',
    `app_unauthorized_requests_total ${metrics.unauthorized}`,
    '# HELP app_invalid_input_total Requests rejected by input validation',
    '# TYPE app_invalid_input_total counter',
    `app_invalid_input_total ${metrics.badInput}`,
  ].join('\n') + '\n';
}

const HOME = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Healthcare Patient Portal</title></head>
<body><h1>Healthcare Patient Portal</h1>
<p>Secure DevSecOps demo - Yogita Y V (RA2311026010096)</p>
<p>API: GET /health, POST /login, GET /patients/{id} (requires x-api-key header), GET /metrics</p>
</body></html>`;

const server = http.createServer((req, res) => {
  metrics.requests++;
  let path;
  try { path = new URL(req.url, 'http://localhost').pathname; } catch { return send(res, 400, { error: 'Bad request' }); }

  if (req.method === 'GET' && path === '/') return send(res, 200, HOME, 'text/html');
  if (req.method === 'GET' && path === '/health') return send(res, 200, { status: 'ok' });
  if (req.method === 'GET' && path === '/metrics') return send(res, 200, metricsText(), 'text/plain; version=0.0.4');
  if (req.method === 'POST' && path === '/login') return handleLogin(req, res);
  const match = path.match(/^\/patients\/([^/]+)$/);
  if (req.method === 'GET' && match) return handlePatient(req, res, match[1]);
  return send(res, 404, { error: 'Not found' });
});

server.headersTimeout = 10000;
server.requestTimeout = 15000;
server.listen(PORT, () => console.log(`Healthcare app listening on port ${PORT}`));
