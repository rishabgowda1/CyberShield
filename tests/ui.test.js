'use strict';
// Runs the REAL client (index.html + script.js) in jsdom against the REAL server and clicks every button.
process.env.ALLOW_PRIVATE_TARGETS = '1';
const os = require('os'), fs = require('fs'), path = require('path'), https = require('https');
const { execFileSync } = require('child_process');
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'cs-ui-'));

const test = require('node:test');
const assert = require('node:assert/strict');
const { JSDOM, VirtualConsole } = require('jsdom');
const app = require('../server/server');
const config = require('../server/config');
const phishing = require('../server/services/phishing');

const ROOT = path.join(__dirname, '..', 'client');
const HTML = fs.readFileSync(path.join(ROOT, 'index.html'), 'utf8');
const JS = fs.readFileSync(path.join(ROOT, 'script.js'), 'utf8');
const SECTIONS = ['dashboard', 'scanner', 'password', 'phishing', 'history', 'recommendations'];

/* ---------- static wiring checks: the "missing DOM id / dead button" class of bug ---------- */
test('every id used by script.js exists in index.html', () => {
  const ids = new Set([...HTML.matchAll(/\sid="([^"]+)"/g)].map((m) => m[1]));
  const used = new Set([...JS.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]));
  [...JS.matchAll(/(?:setText|busy|status)\('([a-z0-9-]+)'/g)].forEach((m) => used.add(m[1]));
  [...JS.matchAll(/'([a-z-]+-(?:btn|refresh|clear|toggle|copy))':/g)].forEach((m) => used.add(m[1]));
  const missing = [...used].filter((u) => !ids.has(u));
  assert.deepEqual(missing, []);
});

test('navigation: every nav/goto target maps to exactly one section', () => {
  const targets = [...HTML.matchAll(/data-(?:section|goto)="([^"]+)"/g)].map((m) => m[1]);
  targets.forEach((t) => assert.equal((HTML.match(new RegExp(`id="section-${t}"`, 'g')) || []).length, 1, t));
  SECTIONS.forEach((s) => assert.ok(targets.includes(s), `nav item for ${s}`));
  assert.ok(!/\sonclick=/.test(HTML), 'no inline handlers');
});

/* ---------- live UI test ---------- */
let server, dom, w, errors = [], httpsSrv, httpsPort;
const wait = async (fn, ms = 12000) => { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await fn()) return true; await new Promise((r) => setTimeout(r, 40)); } throw new Error(`timeout waiting for: ${fn}`); };
const $ = (id) => w.document.getElementById(id);
const click = (el) => el.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
const visible = () => SECTIONS.filter((s) => !$(`section-${s}`).hidden);

test.before(async () => {
  await phishing.load();
  server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const port = server.address().port;
  const dir = process.env.DATA_DIR;
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${dir}/k.pem`, '-out', `${dir}/c.pem`, '-days', '30', '-subj', '/CN=localhost'], { stdio: 'ignore' });
  httpsSrv = https.createServer({ key: fs.readFileSync(`${dir}/k.pem`), cert: fs.readFileSync(`${dir}/c.pem`) }, (_q, res) => { res.writeHead(200, { server: 'Apache/2.4.1' }); res.end('x'); });
  await new Promise((r) => httpsSrv.listen(0, '127.0.0.1', r));
  httpsPort = httpsSrv.address().port;
  config.allowedPorts.push(httpsPort);

  const vc = new VirtualConsole();
  vc.on('jsdomError', (e) => errors.push(e.message));
  vc.on('error', (e) => errors.push(String(e)));
  dom = new JSDOM(HTML, { url: `http://127.0.0.1:${port}/`, runScripts: 'outside-only', pretendToBeVisual: true, virtualConsole: vc });
  w = dom.window;
  w.confirm = () => true;
  w.fetch = (u, o) => fetch(new URL(u, `http://127.0.0.1:${port}`), o);
  w.eval(JS);                                              // DOM is already parsed -> init() runs immediately
});
test.after(() => { w.close(); server.close(); httpsSrv.close(); });

test('page boots: dashboard visible, backend pill turns green', async () => {
  assert.deepEqual(visible(), ['dashboard']);
  await wait(() => /online/.test($('backend-status').textContent));
  assert.ok($('backend-status').classList.contains('pill-ok'));
});

test('every navigation button shows exactly one section and updates the title', () => {
  for (const s of SECTIONS) {
    click(w.document.querySelector(`.nav-item[data-section="${s}"]`));
    assert.deepEqual(visible(), [s]);
    assert.equal($('page-title').textContent, { dashboard: 'Dashboard', scanner: 'Website Scanner', password: 'Password Security', phishing: 'Phishing Checker', history: 'Scan History', recommendations: 'Recommendations' }[s]);
    assert.ok(w.document.querySelector(`.nav-item[data-section="${s}"]`).classList.contains('active'));
  }
  click(w.document.querySelector('[data-goto="scanner"]'));   // quick-action buttons on the dashboard use the same path
  assert.deepEqual(visible(), ['scanner']);
});

test('network info is dashboard-only and never stuck on "Loading…"', async () => {
  assert.ok($('section-dashboard').contains($('network-card')));
  assert.equal(w.document.querySelectorAll('#net-public-ip').length, 1);
  click(w.document.querySelector('.nav-item[data-section="dashboard"]'));
  await wait(() => !$('net-refresh').disabled && $('net-sum-ip').textContent !== 'Loading…');
  for (const id of ['net-public-ip', 'net-client-ip', 'net-version', 'net-isp', 'net-asn', 'net-country', 'net-timezone']) assert.ok($(id).textContent.length > 0 && $(id).textContent !== '–', id);
  assert.match($('net-client-ip').textContent, /127\.0\.0\.1|::1/);
  click($('net-refresh'));                                     // refresh button works and re-enables itself
  await wait(() => !$('net-refresh').disabled);
});

test('password strength meter and generator', () => {
  click(w.document.querySelector('.nav-item[data-section="password"]'));
  const set = (v) => { $('pw-input').value = v; $('pw-input').dispatchEvent(new w.Event('input')); };
  set('password123');            assert.match($('pw-label').textContent, /Very weak|Weak/);
  set('abcdefgh');               assert.match($('pw-label').textContent, /Very weak|Weak/);
  set('t7#Qm!vR9$zLp2@xWc4Hn');  assert.match($('pw-label').textContent, /Strong|Very strong/);
  set('');                       assert.equal($('pw-label').textContent, 'Enter a password');
  click($('pw-toggle'));         assert.equal($('pw-input').type, 'text');
  $('gen-length').value = '32'; $('gen-length').dispatchEvent(new w.Event('input'));
  click($('gen-btn'));
  const pw = $('gen-output').value;
  assert.equal(pw.length, 32);
  assert.ok(/[a-z]/.test(pw) && /[A-Z]/.test(pw) && /\d/.test(pw) && /[^a-zA-Z0-9]/.test(pw), 'one of each selected type');
  assert.notEqual((click($('gen-btn')), $('gen-output').value), pw);
  ['gen-lower', 'gen-upper', 'gen-digits', 'gen-symbols'].forEach((id) => { $(id).checked = false; });
  click($('gen-btn'));
  assert.match($('gen-status').textContent, /at least one/);
  ['gen-lower', 'gen-upper', 'gen-digits', 'gen-symbols'].forEach((id) => { $(id).checked = true; });
});

test('phishing checker: listed, clean and invalid input', async () => {
  click(w.document.querySelector('.nav-item[data-section="phishing"]'));
  const run = async (v) => { $('phish-input').value = v; click($('phish-btn')); await wait(() => !$('phish-btn').disabled); };
  await run('secure-login-examplebank.example/verify');
  assert.equal($('phish-result').hidden, false);
  assert.match($('phish-result').textContent, /LISTED AS MALICIOUS/);
  await run('https://example.com');
  assert.match($('phish-result').textContent, /NO MATCH FOUND/);
  await run('http://[bad');
  assert.equal($('phish-result').hidden, true);
  assert.match($('phish-status').textContent, /valid URL/);
  assert.ok($('phish-status').classList.contains('toast-err'));
});

test('scanner: empty input, blocked target, then a real scan renders and updates history/dashboard/recommendations', async () => {
  click(w.document.querySelector('.nav-item[data-section="scanner"]'));
  click($('scan-btn'));
  assert.match($('scan-status').textContent, /Enter a website/);
  // (private-target blocking is covered in urlSafety.test.js; here an invalid port exercises the UI error path)
  $('scan-input').value = 'example.com:22'; click($('scan-btn'));
  await wait(() => !$('scan-btn').disabled && /Port 22/.test($('scan-status').textContent));
  assert.equal($('scan-result').hidden, true);

  $('scan-input').value = `https://localhost:${httpsPort}`;
  $('scan-input').dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));   // Enter key starts a scan too
  await wait(() => !$('scan-btn').disabled && !$('scan-result').hidden, 20000);
  const text = $('scan-result').textContent;
  for (const needle of ['Domain & registration', 'DNS', 'TLS / certificate', 'HTTP security headers', 'Findings', 'Certificate is not trusted']) assert.ok(text.includes(needle), needle);
  assert.ok(w.document.querySelector('#scan-result svg.ring'));
  assert.ok(!/undefined|\[object/.test(text), 'no undefined/[object] leaks');

  click(w.document.querySelector('.nav-item[data-section="history"]'));
  await wait(() => $('history-body').children.length >= 1);
  assert.equal($('history-empty').hidden, true);
  assert.match($('history-body').textContent, /localhost/);

  click(w.document.querySelector('.nav-item[data-section="recommendations"]'));
  await wait(() => /latest scan/.test($('reco-source').textContent));
  assert.ok($('reco-list').children.length > 0);
  assert.match($('reco-list').textContent, /certificate/i);

  click(w.document.querySelector('.nav-item[data-section="dashboard"]'));
  await wait(() => $('stat-total').textContent === '1');
  assert.notEqual($('stat-score').textContent, '–');
  assert.ok(w.document.querySelector('#score-chart svg circle'));

  click(w.document.querySelector('.nav-item[data-section="history"]'));
  click($('history-clear'));
  await wait(() => $('history-empty').hidden === false);
});

test('no JavaScript errors were thrown during the whole session', () => assert.deepEqual(errors, []));

test('leetspeak variants of common words are not rated strong', () => {
  click(w.document.querySelector('.nav-item[data-section="password"]'));
  $('pw-input').value = 'Tr0ub4dor&3xQ!'; $('pw-input').dispatchEvent(new w.Event('input'));
  assert.match($('pw-label').textContent, /Very weak|Weak/);
  assert.match($('pw-feedback').textContent, /common/);
});
