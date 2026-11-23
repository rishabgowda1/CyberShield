'use strict';
// End-to-end API tests. ALLOW_PRIVATE_TARGETS lets the scanner reach a local test server (SSRF guard is unit-tested separately).
process.env.ALLOW_PRIVATE_TARGETS = '1';
const os = require('os'), fs = require('fs'), path = require('path'), https = require('https'), http = require('http');
const { execFileSync } = require('child_process');
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-test-'));

const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../server/server');
const phishing = require('../server/services/phishing');
const { request } = require('./helpers');

const CID = { 'x-client-id': 'test-client-0001' };
let api, httpsSrv, plainSrv, haveOpenssl = true;
let httpsPort, plainPort;

test.before(async () => {
  await phishing.load();
  api = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  try {
    const dir = process.env.DATA_DIR;
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${dir}/k.pem`, '-out', `${dir}/c.pem`, '-days', '30', '-subj', '/CN=localhost'], { stdio: 'ignore' });
    httpsSrv = https.createServer({ key: fs.readFileSync(`${dir}/k.pem`), cert: fs.readFileSync(`${dir}/c.pem`) }, (_q, res) => {
      res.writeHead(200, { 'x-powered-by': 'Express', server: 'nginx/1.18.0', 'set-cookie': ['sid=1; Path=/'], 'x-content-type-options': 'nosniff' }); res.end('hi');
    });
    await new Promise((r) => httpsSrv.listen(0, '127.0.0.1', r));
    httpsPort = httpsSrv.address().port;
  } catch { haveOpenssl = false; }
  plainSrv = http.createServer((_q, res) => { res.writeHead(200); res.end('plain'); });
  await new Promise((r) => plainSrv.listen(0, '127.0.0.1', r));
  plainPort = plainSrv.address().port;
});
test.after(() => { api.close(); httpsSrv && httpsSrv.close(); plainSrv.close(); });

test('GET /api/health', async () => {
  const r = await request(api.address().port, 'GET', '/api/health');
  assert.equal(r.status, 200);
  assert.equal(r.json.status, 'online');
  assert.equal(r.json.phishingDataset.loaded, true);
});

test('security headers + CSP are set and there is no X-Powered-By', async () => {
  const r = await request(api.address().port, 'GET', '/');
  assert.equal(r.status, 200);
  assert.match(r.headers['content-security-policy'], /script-src 'self'/);
  assert.doesNotMatch(r.headers['content-security-policy'], /upgrade-insecure-requests/);
  assert.equal(r.headers['x-powered-by'], undefined);
});

test('startup regression: unknown paths do not crash the router (old PathError bug)', async () => {
  assert.equal((await request(api.address().port, 'GET', '/some/unknown/path')).status, 404);
  const r = await request(api.address().port, 'GET', '/api/nope');
  assert.equal(r.status, 404);
  assert.equal(r.json.success, false);
});

test('scan input errors are JSON with clear messages', async () => {
  const p = api.address().port;
  for (const [body, code] of [[{}, 'BAD_INPUT'], [{ url: 'file:///etc/passwd' }, 'INVALID_URL'], [{ url: 'http://example.com:22' }, 'PORT_BLOCKED']]) {
    const r = await request(p, 'POST', '/api/scan', body, CID);
    assert.equal(r.status, 400); assert.equal(r.json.success, false); assert.equal(r.json.error.code, code);
  }
  const bad = await request(p, 'POST', '/api/scan', null, { ...CID });
  assert.equal(bad.status, 400);
});

test('non-whitelisted ports are refused even for local servers', async (t) => {
  if (!haveOpenssl) return t.skip('openssl not available');
  const r = await request(api.address().port, 'POST', '/api/scan', { url: `https://localhost:${httpsPort}` }, CID);
  // port is not in the allowed list -> must be refused even for local servers
  assert.equal(r.status, 400);
  assert.equal(r.json.error.code, 'PORT_BLOCKED');
});

test('scanner core handles self-signed HTTPS + plain HTTP targets (ports bypass via config)', async (t) => {
  if (!haveOpenssl) return t.skip('openssl not available');
  const config = require('../server/config');
  config.allowedPorts.push(httpsPort, plainPort);
  const { scanTarget } = require('../server/services/securityScanner');
  const r = await scanTarget(`https://localhost:${httpsPort}/`);
  assert.equal(r.success, true);
  for (const list of [r.findings, r.recommendations, r.domain.status, r.domain.nameServers, r.security.headers, r.security.urlIndicators, r.security.warnings, r.security.dns.a, r.security.dns.mx]) assert.ok(Array.isArray(list));
  assert.equal(r.security.tls.available, true);
  assert.equal(r.security.tls.authorized, false);                       // self-signed
  const ids = r.findings.map((f) => f.id);
  assert.ok(ids.includes('bad-cert')); assert.ok(ids.includes('x-powered-by')); assert.ok(ids.includes('server-version')); assert.ok(ids.includes('hdr-content-security-policy'));
  assert.equal(r.findings.find((f) => f.id === 'hdr-x-content-type-options').severity, 'pass');   // present -> pass, no deduction
  assert.ok(r.score <= 55 && r.status !== 'safe');
  assert.equal(r.security.headers.find((h) => h.key === 'x-content-type-options').present, true);

  const p = await scanTarget(`http://localhost:${plainPort}/`);
  assert.equal(p.security.tls.available, false);
  assert.ok(p.findings.some((f) => f.id === 'no-https'));
  assert.ok(p.score <= 45 && p.status === 'danger');
});

test('history round-trip and isolation between clients', async () => {
  const p = api.address().port;
  const a = await request(p, 'POST', '/api/phishing', { url: 'http://secure-login-examplebank.example/verify' }, CID);
  assert.equal(a.json.verdict, 'listed');
  const h1 = await request(p, 'GET', '/api/history', null, CID);
  assert.equal(h1.json.entries.length, 1);
  assert.equal((await request(p, 'GET', '/api/history', null, { 'x-client-id': 'someone-else-9999' })).json.entries.length, 0);
  assert.equal((await request(p, 'GET', '/api/history')).json.entries.length, 0);        // no id -> empty, no crash
  await request(p, 'DELETE', '/api/history', null, CID);
  assert.equal((await request(p, 'GET', '/api/history', null, CID)).json.entries.length, 0);
});

test('/api/network answers quickly and never hangs, with explicit fallbacks', async () => {
  const t0 = Date.now();
  const r = await request(api.address().port, 'GET', '/api/network');
  assert.ok(Date.now() - t0 < 8000, 'must respect the lookup timeout');
  assert.equal(r.json.success, true);
  for (const k of ['publicIp', 'clientIp', 'ipVersion', 'isp', 'org', 'asn', 'country', 'region', 'city', 'timezone']) assert.equal(typeof r.json[k], 'string', k);
  assert.match(r.json.clientIp, /127\.0\.0\.1/);                          // loopback is reported honestly
});
