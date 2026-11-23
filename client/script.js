/* CyberShield client. One file, one init(), one navigation function, one API helper. */
(() => {
  'use strict';

  /* ------------------------------------------------------------ helpers */
  const $ = (id) => document.getElementById(id);
  const arr = (v) => (Array.isArray(v) ? v : []);          // every list is normalised before .map/.filter
  const NA = 'Not available';
  const show = (v) => (v === undefined || v === null || v === '' ? NA : String(v));
  const setText = (id, v) => { const el = $(id); if (el) el.textContent = v; };

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([k, v]) => { if (v === undefined || v === null || v === false) return; if (k === 'class') el.className = v; else el.setAttribute(k, v); });
    kids.flat(Infinity).forEach((k) => { if (k === null || k === undefined || k === false) return; el.append(k instanceof Node ? k : document.createTextNode(String(k))); });
    return el;                                              // textContent only – scanned data is untrusted and never parsed as HTML
  }
  const SVGNS = 'http://www.w3.org/2000/svg';
  function svg(tag, attrs, ...kids) {
    const el = document.createElementNS(SVGNS, tag);
    Object.entries(attrs || {}).forEach(([k, v]) => el.setAttribute(k, v));
    kids.forEach((k) => el.append(k instanceof Node ? k : document.createTextNode(String(k))));
    return el;
  }
  const fmtDate = (v) => { const t = Date.parse(v); return Number.isNaN(t) ? show(v) : new Date(t).toLocaleString(); };
  const badge = (label, kind) => h('span', { class: `badge b-${kind}` }, label);
  const kvList = (rows) => h('dl', { class: 'kv' }, rows.map(([k, v]) => h('div', {}, h('dt', {}, k), h('dd', {}, show(v)))));

  function clientId() {
    let id = '';
    try { id = localStorage.getItem('cybershield.clientId') || ''; } catch { /* storage blocked */ }
    if (!/^[a-zA-Z0-9-]{8,64}$/.test(id)) {
      id = (crypto.randomUUID && crypto.randomUUID()) || Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
      try { localStorage.setItem('cybershield.clientId', id); } catch { /* ignore */ }
    }
    return id;
  }
  const CLIENT_ID = clientId();

  /** The only place that talks to the backend: timeout, JSON parsing and useful error messages. */
  async function api(path, { method = 'GET', body, timeout = 15000 } = {}) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    try {
      const res = await fetch(path, {
        method, signal: ctrl.signal,
        headers: { 'content-type': 'application/json', 'x-client-id': CLIENT_ID },
        body: body ? JSON.stringify(body) : undefined,
      });
      let data = null;
      try { data = await res.json(); } catch { /* non-JSON response */ }
      if (!res.ok || !data || data.success === false) {
        throw new Error((data && data.error && data.error.message) || `The server returned an error (HTTP ${res.status}).`);
      }
      return data;
    } catch (e) {
      if (e.name === 'AbortError') throw new Error('The request timed out. Please try again.');
      if (e instanceof TypeError) throw new Error('Cannot reach the CyberShield server. Is it running?');
      throw e;
    } finally { clearTimeout(timer); }
  }

  /** Runs an async action while disabling its own button; always re-enables it. */
  async function busy(btnId, fn) {
    const btn = $(btnId);
    if (btn) btn.disabled = true;
    try { await fn(); } finally { if (btn) btn.disabled = false; }
  }
  const status = (id, msg, isErr) => { const el = $(id); if (!el) return; el.textContent = msg || ''; el.classList.toggle('toast-err', !!isErr); };

  /* ------------------------------------------------------------ state */
  const state = { history: [], networkLoaded: false };
  const SECTIONS = ['dashboard', 'scanner', 'password', 'phishing', 'history', 'recommendations'];
  const TITLES = { dashboard: 'Dashboard', scanner: 'Website Scanner', password: 'Password Security', phishing: 'Phishing Checker', history: 'Scan History', recommendations: 'Recommendations' };

  /* ------------------------------------------------------------ navigation */
  function showSection(name) {
    if (!SECTIONS.includes(name)) name = 'dashboard';
    SECTIONS.forEach((s) => { const el = $(`section-${s}`); if (el) el.hidden = s !== name; });
    document.querySelectorAll('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.section === name));
    setText('page-title', TITLES[name]);
    if (location.hash !== `#${name}`) history.replaceState(null, '', `#${name}`);
    const enter = { dashboard: enterDashboard, history: enterHistory, recommendations: enterRecommendations }[name];
    if (enter) enter();
  }

  /* ------------------------------------------------------------ backend status */
  async function checkHealth() {
    const pill = $('backend-status');
    try {
      const d = await api('/api/health', { timeout: 5000 });
      pill.textContent = `Backend ${d.status}`; pill.className = 'pill pill-ok';
    } catch { pill.textContent = 'Backend offline'; pill.className = 'pill pill-bad'; }
  }

  /* ------------------------------------------------------------ history + dashboard */
  async function loadHistory() {
    try { state.history = arr((await api('/api/history')).entries); } catch { /* keep previous list */ }
  }

  async function enterDashboard() {
    await loadHistory();
    renderDashboard();
    if (!state.networkLoaded) loadNetwork();            // network info is dashboard-only, loaded lazily once
  }

  function renderDashboard() {
    const scans = arr(state.history).filter((e) => e.type === 'scan');
    setText('stat-score', scans.length ? String(scans[0].score) : '–');
    setText('stat-total', String(scans.length));
    setText('stat-warnings', String(state.history.filter((e) => e.status === 'warning').length));
    setText('stat-danger', String(state.history.filter((e) => e.status === 'danger').length));
    drawChart(scans.slice(0, 10).reverse());
  }

  function drawChart(points) {
    const box = $('score-chart');
    if (!box) return;
    box.replaceChildren();
    if (!points.length) { box.append(h('p', { class: 'muted' }, 'Run a website scan to see your score history.')); return; }
    const W = 520, H = 200, L = 34, R = 12, T = 12, B = 26;
    const x = (i) => (points.length === 1 ? (L + W - R) / 2 : L + (i * (W - L - R)) / (points.length - 1));
    const y = (s) => T + ((100 - s) * (H - T - B)) / 100;
    const root = svg('svg', { viewBox: `0 0 ${W} ${H}`, role: 'presentation' });
    [0, 50, 100].forEach((g) => {
      root.append(svg('line', { x1: L, x2: W - R, y1: y(g), y2: y(g), stroke: '#22324f', 'stroke-width': 1 }), svg('text', { x: 4, y: y(g) + 4 }, g));
    });
    root.append(svg('polyline', { fill: 'none', stroke: '#3b82f6', 'stroke-width': 2.5, points: points.map((p, i) => `${x(i)},${y(p.score)}`).join(' ') }));
    points.forEach((p, i) => {
      const c = p.status === 'danger' ? '#ef4444' : p.status === 'warning' ? '#f59e0b' : '#22c55e';
      const dot = svg('circle', { cx: x(i), cy: y(p.score), r: 4.5, fill: c });
      dot.append(svg('title', {}, `${p.target}: ${p.score}`));
      root.append(dot, svg('text', { x: x(i) - 4, y: H - 8 }, i + 1));
    });
    box.append(root);
  }

  /* ------------------------------------------------------------ network (dashboard only) */
  function fillNetwork(d) {
    const map = { 'net-public-ip': d.publicIp, 'net-client-ip': d.clientIp, 'net-version': d.ipVersion, 'net-isp': d.isp, 'net-org': d.org,
      'net-asn': d.asn, 'net-country': d.country, 'net-region': d.region, 'net-city': d.city, 'net-timezone': d.timezone };
    Object.entries(map).forEach(([id, v]) => setText(id, show(v)));
    setText('net-sum-ip', show(d.publicIp));
    setText('net-sum-isp', [d.isp, d.asn].map(show).filter((v) => v !== NA).join(' / ') || NA);
    setText('net-sum-loc', [d.city, d.region, d.country].map(show).filter((v) => v !== NA).join(', ') || NA);
  }

  async function loadNetwork() {
    await busy('net-refresh', async () => {
      status('net-status', 'Looking up network information…');
      ['net-sum-ip', 'net-sum-isp', 'net-sum-loc'].forEach((id) => setText(id, 'Loading…'));
      try {
        const d = await api('/api/network', { timeout: 12000 });
        fillNetwork(d);
        state.networkLoaded = !d.partial;
        status('net-status', [d.error, d.clientIpNote, d.source && d.source !== NA ? `Source: ${d.source}` : ''].filter(Boolean).join(' '), d.partial);
      } catch (e) {
        fillNetwork({});
        status('net-status', e.message, true);
      }
    });
  }

  /* ------------------------------------------------------------ website scanner */
  async function runScan() {
    const input = $('scan-input').value.trim();
    if (!input) { status('scan-status', 'Enter a website URL or domain first.', true); return; }
    await busy('scan-btn', async () => {
      status('scan-status', 'Scanning… this can take up to 20 seconds.');
      $('scan-result').hidden = true;
      try {
        const r = await api('/api/scan', { method: 'POST', body: { url: input }, timeout: 30000 });
        renderScan(r);
        status('scan-status', `Scan finished in ${(r.durationMs / 1000).toFixed(1)} s.`);
        loadHistory();
      } catch (e) { status('scan-status', e.message, true); }
    });
  }

  function ring(score, st) {
    const C = 2 * Math.PI * 45;
    return svg('svg', { class: `ring ring-${st}`, viewBox: '0 0 110 110', role: 'img', 'aria-label': `Score ${score} out of 100` },
      svg('circle', { cx: 55, cy: 55, r: 45, fill: 'none', stroke: '#22324f', 'stroke-width': 10 }),
      svg('circle', { cx: 55, cy: 55, r: 45, fill: 'none', stroke: 'currentColor', 'stroke-width': 10, 'stroke-linecap': 'round', transform: 'rotate(-90 55 55)', 'stroke-dasharray': `${(C * score) / 100} ${C}` }),
      svg('text', { x: 55, y: 64, 'text-anchor': 'middle' }, score));
  }

  function renderScan(r) {
    const d = r.domain || {}, sec = r.security || {}, dnsI = sec.dns || {}, t = sec.tls || {};
    const out = $('scan-result');
    const card = (title, ...kids) => h('div', { class: 'card' }, h('h2', {}, title), ...kids);
    const parts = [];

    parts.push(h('div', { class: 'card result-head' }, ring(r.score, r.status),
      h('div', {}, h('h2', {}, d.hostname || r.url), badge(String(r.status).toUpperCase(), r.status), h('p', {}, r.assessment),
        h('p', { class: 'muted small' }, `Scanned ${fmtDate(r.scannedAt)} · ${show(r.url)}`))));

    parts.push(card('Domain & registration', kvList([
      ['Hostname', d.hostname], ['Protocol', d.protocol], ['Port', d.port], ['Resolved IP', d.ip], ['Registrar', d.registrar],
      ['Registration', d.registration === NA ? NA : fmtDate(d.registration)], ['Expiration', d.expiration === NA ? NA : fmtDate(d.expiration)],
      ['Last changed', d.lastChanged === NA ? NA : fmtDate(d.lastChanged)], ['Domain status', arr(d.status).join(', ')],
      ['Name servers', arr(d.nameServers).join(', ')], ['Data source', d.source]]),
      d.note ? h('p', { class: 'muted small' }, d.note) : null));

    parts.push(card('DNS', kvList([
      ['A (IPv4)', arr(dnsI.a).join(', ')], ['AAAA (IPv6)', arr(dnsI.aaaa).join(', ')], ['Name servers', arr(dnsI.ns).join(', ')],
      ['Mail (MX)', arr(dnsI.mx).join(', ')], ['SPF', dnsI.spf], ['DMARC', dnsI.dmarc]])));

    parts.push(card('TLS / certificate', t.available
      ? kvList([['Protocol', t.protocol], ['Cipher', t.cipher], ['Trusted', t.authorized ? 'Yes' : `No – ${t.authorizationError}`], ['Subject', t.subject], ['Issuer', t.issuer],
        ['Valid from', t.validFrom], ['Valid to', t.validTo], ['Days remaining', t.daysRemaining], ['Alt names', arr(t.altNames).join(', ')]])
      : h('p', {}, `HTTPS is not available${t.error ? ` (${t.error})` : ''}.`),
      sec.redirectsToHttps === true ? h('p', { class: 'muted small' }, 'HTTP requests are redirected to HTTPS.') : null,
      sec.redirectsToHttps === false ? h('p', { class: 'muted small' }, 'HTTP requests are NOT redirected to HTTPS.') : null));

    const hdr = arr(sec.headers);
    parts.push(card('HTTP security headers', hdr.length
      ? h('div', { class: 'table-wrap' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Header'), h('th', {}, 'Status'), h('th', {}, 'Value'))),
        h('tbody', {}, hdr.map((x) => h('tr', {}, h('td', {}, x.name), h('td', {}, !x.applicable ? badge('n/a', 'info') : x.present ? badge('present', 'pass') : badge('missing', 'warning')), h('td', { class: 'wrap' }, x.value || '–'))))))
      : h('p', { class: 'muted' }, 'No HTTP response was received, so headers could not be analysed.'),
      sec.httpStatus ? h('p', { class: 'muted small' }, `HTTP ${sec.httpStatus} from ${show(sec.finalUrl)}${arr(sec.redirects).length ? ` after ${sec.redirects.length} redirect(s)` : ''}`) : null));

    parts.push(card('Findings', arr(r.findings).length ? arr(r.findings).map((f) => h('div', { class: 'finding' },
      h('div', { class: 'ft' }, badge(f.severity, f.severity), h('strong', {}, f.title), f.deduction ? h('span', { class: 'muted small' }, `−${f.deduction} pts`) : null),
      f.detail ? h('p', { class: 'muted small' }, f.detail) : null, f.deduction && f.recommendation ? h('p', { class: 'small' }, `Fix: ${f.recommendation}`) : null))
      : h('p', { class: 'muted' }, 'No findings.')));

    if (arr(sec.warnings).length) parts.push(card('Scanner notes', h('ul', { class: 'bullets' }, arr(sec.warnings).map((w) => h('li', {}, w)))));

    out.replaceChildren(...parts);
    out.hidden = false;
  }

  /* ------------------------------------------------------------ phishing checker */
  async function runPhishing() {
    const input = $('phish-input').value.trim();
    if (!input) { status('phish-status', 'Enter a URL to check.', true); return; }
    await busy('phish-btn', async () => {
      status('phish-status', 'Checking…');
      $('phish-result').hidden = true;
      try {
        const r = await api('/api/phishing', { method: 'POST', body: { url: input } });
        const labels = { listed: 'LISTED AS MALICIOUS', suspicious: 'SUSPICIOUS', no_match: 'NO MATCH FOUND' };
        const ds = r.dataset ? `${r.dataset.type} (${r.dataset.matchKind} match)` : r.datasetLoaded ? 'No entry' : 'Dataset not loaded';
        $('phish-result').replaceChildren(h('div', { class: 'card' },
          h('h2', {}, badge(labels[r.verdict] || r.verdict, r.verdict), ` Safety score ${r.safetyScore}/100`),
          kvList([['Checked URL', r.url], ['Dataset result', ds], ['Dataset size', `${r.datasetEntries} entries`]]),
          r.note ? h('p', { class: 'muted small' }, r.note) : null,
          h('h3', {}, 'URL indicators'),
          arr(r.indicators).length ? arr(r.indicators).map((i) => h('div', { class: 'finding' }, h('div', { class: 'ft' }, badge(i.severity, i.severity), h('strong', {}, i.title)), i.detail ? h('p', { class: 'muted small' }, i.detail) : null))
            : h('p', { class: 'muted' }, 'No suspicious URL patterns detected.'),
          h('p', { class: 'muted small' }, r.disclaimer)));
        $('phish-result').hidden = false;
        status('phish-status', '');
        loadHistory();
      } catch (e) { status('phish-status', e.message, true); }
    });
  }

  /* ------------------------------------------------------------ password tools (browser only) */
  const COMMON = ['password', '123456', 'qwerty', 'abc123', 'letmein', 'welcome', 'admin', 'iloveyou', 'monkey', 'dragon', 'football', '111111', 'passw0rd', 'login', 'princess', 'sunshine', 'master', 'trustno1', 'troubador', 'troubadour', 'hello', 'secret', 'summer', 'winter', 'shadow', 'whatever', 'computer'];
  const LEVELS = [['Very weak', '#ef4444'], ['Weak', '#f97316'], ['Fair', '#f59e0b'], ['Strong', '#84cc16'], ['Very strong', '#22c55e']];

  function hasSequence(s) {
    for (let i = 0; i + 2 < s.length; i++) {
      const a = s.charCodeAt(i), b = s.charCodeAt(i + 1), c = s.charCodeAt(i + 2);
      if ((b - a === 1 && c - b === 1) || (a - b === 1 && b - c === 1)) return true;
    }
    return false;
  }

  function evaluatePassword(pw) {
    const fb = [];
    const pool = (/[a-z]/.test(pw) ? 26 : 0) + (/[A-Z]/.test(pw) ? 26 : 0) + (/\d/.test(pw) ? 10 : 0) + (/[^a-zA-Z0-9]/.test(pw) ? 33 : 0);
    let bits = pw.length * Math.log2(pool || 1);
    const low = pw.toLowerCase();
    if (pw.length < 8) fb.push('Use at least 12 characters.'); else if (pw.length < 12) fb.push('Longer is stronger – aim for 12 or more characters.');
    if (!/[a-z]/.test(pw) || !/[A-Z]/.test(pw)) fb.push('Mix upper- and lower-case letters.');
    if (!/\d/.test(pw)) fb.push('Add some digits.');
    if (!/[^a-zA-Z0-9]/.test(pw)) fb.push('Add a symbol such as ! or #.');
    if (/(.)\1{2,}/.test(pw)) { bits *= 0.8; fb.push('Avoid repeating the same character.'); }
    if (hasSequence(low)) { bits -= 10; fb.push('Avoid sequences like "abc" or "123".'); }
    if (/(19|20)\d\d/.test(pw)) { bits -= 5; fb.push('Avoid years and dates.'); }
    const unleet = low.replace(/[0@]/g, (m) => (m === '0' ? 'o' : 'a')).replace(/[1!]/g, 'i').replace(/3/g, 'e').replace(/4/g, 'a').replace(/[5$]/g, 's').replace(/7/g, 't');
    if (COMMON.some((c) => low.includes(c) || unleet.includes(c))) { bits = Math.min(bits, 18); fb.push('Contains a very common password or word.'); }
    bits = Math.max(0, Math.round(bits));
    const lvl = bits < 28 ? 0 : bits < 36 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
    return { bits, lvl, fb };
  }

  function updatePassword() {
    const pw = $('pw-input').value, bar = $('pw-meter-bar'), list = $('pw-feedback');
    list.replaceChildren();
    if (!pw) { bar.style.width = '0'; setText('pw-label', 'Enter a password'); setText('pw-entropy', ''); return; }
    const r = evaluatePassword(pw);
    bar.style.width = `${Math.max(6, Math.min(100, (r.bits / 100) * 100))}%`;
    bar.style.background = LEVELS[r.lvl][1];
    setText('pw-label', LEVELS[r.lvl][0]);
    setText('pw-entropy', `≈ ${r.bits} bits (estimate)`);
    (r.fb.length ? r.fb : ['No obvious weaknesses found.']).forEach((t) => list.append(h('li', {}, t)));
  }

  function randInt(max) {                                   // unbiased: rejection sampling, no modulo bias
    const limit = Math.floor(0x100000000 / max) * max, buf = new Uint32Array(1);
    do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
    return buf[0] % max;
  }

  function generatePassword() {
    const sets = [];
    if ($('gen-lower').checked) sets.push('abcdefghijklmnopqrstuvwxyz');
    if ($('gen-upper').checked) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if ($('gen-digits').checked) sets.push('0123456789');
    if ($('gen-symbols').checked) sets.push('!@#$%^&*()-_=+[]{};:,.?');
    if (!sets.length) { status('gen-status', 'Select at least one character type.', true); return; }
    const len = Math.max(8, Math.min(64, Number($('gen-length').value) || 16));
    const all = sets.join('');
    const chars = sets.map((s) => s[randInt(s.length)]);    // guarantee one of each selected type
    while (chars.length < len) chars.push(all[randInt(all.length)]);
    for (let i = chars.length - 1; i > 0; i--) { const j = randInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
    $('gen-output').value = chars.join('');
    status('gen-status', '');
  }

  async function copyPassword() {
    const out = $('gen-output');
    if (!out.value) { status('gen-status', 'Generate a password first.', true); return; }
    try { await navigator.clipboard.writeText(out.value); status('gen-status', 'Copied to clipboard.'); }
    catch { out.select(); status('gen-status', 'Select-all done – press Ctrl+C to copy.'); }
  }

  /* ------------------------------------------------------------ history + recommendations views */
  async function enterHistory() { await loadHistory(); renderHistory(); }

  function renderHistory() {
    const rows = arr(state.history);
    $('history-empty').hidden = rows.length > 0;
    $('history-table').hidden = rows.length === 0;
    $('history-body').replaceChildren(...rows.map((e) => h('tr', {}, h('td', {}, fmtDate(e.at)), h('td', {}, e.type === 'scan' ? 'Website scan' : 'Phishing check'),
      h('td', { class: 'wrap' }, e.target), h('td', {}, e.score), h('td', {}, badge(e.status, e.status)))));
  }

  const GENERIC_TIPS = ['Use a unique, long password for every account and store them in a password manager.', 'Turn on multi-factor authentication wherever it is offered.',
    'Keep operating systems, browsers and apps updated.', 'Check the address bar for HTTPS and the correct domain before signing in.', 'Be sceptical of urgent e-mails or messages asking you to click a link.'];

  async function enterRecommendations() {
    await loadHistory();
    const latest = arr(state.history).find((e) => e.type === 'scan' && arr(e.recommendations).length);
    setText('reco-source', latest ? `Based on your latest scan with findings: ${latest.target} (score ${latest.score}).` : 'Run a website scan to get recommendations specific to a site. General best practices:');
    $('reco-list').replaceChildren(...(latest ? arr(latest.recommendations) : GENERIC_TIPS).map((t) => h('li', {}, t)));
  }

  async function clearHistory() {
    if (!window.confirm('Delete all scan history for this browser?')) return;
    await busy('history-clear', async () => {
      try { await api('/api/history', { method: 'DELETE' }); state.history = []; renderHistory(); } catch (e) { window.alert(e.message); }
    });
  }

  /* ------------------------------------------------------------ profile */
  function initProfile() {
    const input = $('profile-name');
    let name = '';
    try { name = localStorage.getItem('cybershield.profile') || ''; } catch { /* ignore */ }
    input.value = name;
    const paint = () => setText('profile-avatar', (input.value.trim()[0] || '?').toUpperCase());
    paint();
    input.addEventListener('input', () => { paint(); try { localStorage.setItem('cybershield.profile', input.value.trim()); } catch { /* ignore */ } });
  }

  /* ------------------------------------------------------------ init: every listener is attached once, after the DOM exists */
  function init() {
    document.addEventListener('click', (e) => {
      const nav = e.target.closest('[data-section]');
      if (nav) return showSection(nav.dataset.section);
      const go = e.target.closest('[data-goto]');
      if (go) return showSection(go.dataset.goto);
      const id = e.target.closest('button') && e.target.closest('button').id;
      const actions = { 'scan-btn': runScan, 'phish-btn': runPhishing, 'net-refresh': loadNetwork, 'gen-btn': generatePassword, 'gen-copy': copyPassword, 'history-clear': clearHistory,
        'pw-toggle': () => { const i = $('pw-input'); const hide = i.type === 'password'; i.type = hide ? 'text' : 'password'; setText('pw-toggle', hide ? 'Hide' : 'Show'); } };
      if (id && actions[id]) actions[id]();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter') return;
      if (e.target.id === 'scan-input') runScan();
      if (e.target.id === 'phish-input') runPhishing();
    });
    $('pw-input').addEventListener('input', updatePassword);
    $('gen-length').addEventListener('input', () => setText('gen-length-val', $('gen-length').value));
    initProfile();
    generatePassword();
    checkHealth();
    setInterval(checkHealth, 30000);
    showSection(location.hash.slice(1));
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
