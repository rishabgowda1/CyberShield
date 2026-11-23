'use strict';
/**
 * Pure scoring logic: turns collected scan data into findings, a 0-100 score and recommendations.
 * Deductions are defined here in one place so the score is explainable and testable.
 */
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4, pass: 5 };

function statusFromScore(score) {
  if (score >= 80) return 'safe';
  if (score >= 50) return 'warning';
  return 'danger';
}

function assessmentFor(status, findings) {
  const n = findings.filter((f) => f.deduction > 0).length;
  if (status === 'safe') return n ? `Good overall security posture with ${n} minor improvement${n > 1 ? 's' : ''} available.` : 'No security issues detected by these checks.';
  if (status === 'warning') return `Several security weaknesses were detected (${n}). Review the findings below.`;
  return `Serious security problems were detected (${n}). Do not trust this site with sensitive data until they are resolved.`;
}

const SECURITY_HEADERS = [
  { key: 'strict-transport-security', name: 'Strict-Transport-Security', deduction: 8, severity: 'medium', httpsOnly: true,
    rec: 'Send a Strict-Transport-Security header (e.g. max-age=31536000; includeSubDomains) so browsers always use HTTPS.' },
  { key: 'content-security-policy', name: 'Content-Security-Policy', deduction: 8, severity: 'medium',
    rec: 'Add a Content-Security-Policy to limit where scripts and other resources can load from (mitigates XSS).' },
  { key: 'x-frame-options', name: 'X-Frame-Options', deduction: 4, severity: 'low',
    rec: 'Set X-Frame-Options: DENY (or CSP frame-ancestors) to prevent clickjacking.' },
  { key: 'x-content-type-options', name: 'X-Content-Type-Options', deduction: 3, severity: 'low',
    rec: 'Send X-Content-Type-Options: nosniff to stop MIME-type sniffing.' },
  { key: 'referrer-policy', name: 'Referrer-Policy', deduction: 2, severity: 'low',
    rec: 'Set a Referrer-Policy (e.g. strict-origin-when-cross-origin) to limit URL leakage.' },
  { key: 'permissions-policy', name: 'Permissions-Policy', deduction: 1, severity: 'low',
    rec: 'Add a Permissions-Policy header to disable browser features the site does not use.' },
];

/** Build the header table (always an array) from raw response headers. */
function headerReport(headers, isHttps) {
  const h = headers || {};
  const csp = String(h['content-security-policy'] || '');
  return SECURITY_HEADERS.map((spec) => {
    let present = h[spec.key] !== undefined;
    if (spec.key === 'x-frame-options' && !present && /frame-ancestors/i.test(csp)) present = true;
    const applicable = !(spec.httpsOnly && !isHttps);
    return { name: spec.name, key: spec.key, present, applicable, value: present ? String(h[spec.key] ?? 'via CSP frame-ancestors').slice(0, 200) : '' };
  });
}

/**
 * @param {object} ctx { isHttps, isIp, tls, http, redirectsToHttps, dns, domain, indicators, reputation }
 */
function evaluate(ctx) {
  const f = [];
  const add = (id, category, severity, title, detail, deduction, recommendation) =>
    f.push({ id, category, severity, title, detail: detail || '', deduction, recommendation: recommendation || '' });

  /* --- Transport security --- */
  const tls = ctx.tls || { available: false };
  if (!tls.available) {
    add('no-https', 'TLS', 'critical', 'HTTPS is not available', tls.error ? `TLS connection failed: ${tls.error}.` : '', 30,
      'Install a TLS certificate (free from Let\'s Encrypt) and serve the whole site over HTTPS.');
  } else {
    if (!tls.authorized) {
      add('bad-cert', 'TLS', 'high', 'Certificate is not trusted', `Reason: ${tls.authorizationError || 'unknown'}.`, 25,
        'Replace the certificate with one issued by a trusted CA that covers this hostname and is not expired.');
    } else add('cert-ok', 'TLS', 'pass', 'Certificate is valid and trusted', tls.issuer ? `Issued by ${tls.issuer}.` : '', 0);
    if (typeof tls.daysRemaining === 'number' && tls.authorized && tls.daysRemaining < 14) {
      add('cert-expiring', 'TLS', 'medium', 'Certificate expires soon', `${tls.daysRemaining} day(s) remaining.`, 10, 'Renew the certificate and automate renewal.');
    }
    if (['TLSv1', 'TLSv1.1', 'SSLv3'].includes(tls.protocol)) {
      add('old-tls', 'TLS', 'high', 'Outdated TLS protocol negotiated', tls.protocol, 15, 'Disable TLS 1.0/1.1; support TLS 1.2 and 1.3 only.');
    } else if (tls.protocol) add('tls-ok', 'TLS', 'pass', `Modern TLS protocol (${tls.protocol})`, '', 0);
  }
  if (ctx.redirectsToHttps === false) {
    add('no-https-redirect', 'TLS', 'medium', 'HTTP does not redirect to HTTPS', 'Plain-HTTP requests are served without upgrading.', 8,
      'Redirect all HTTP traffic to HTTPS with a 301 redirect.');
  } else if (ctx.redirectsToHttps === true) add('https-redirect', 'TLS', 'pass', 'HTTP redirects to HTTPS', '', 0);

  /* --- HTTP response --- */
  if (!ctx.http) {
    add('http-unreachable', 'HTTP', 'medium', 'Website did not return an HTTP response', ctx.httpError || '', 5,
      'Check that the web server is running and reachable.');
  } else {
    const rows = headerReport(ctx.http.headers, ctx.isHttps);
    rows.forEach((r) => {
      const spec = SECURITY_HEADERS.find((s) => s.key === r.key);
      if (!r.applicable) return;
      if (r.present) add(`hdr-${r.key}`, 'Headers', 'pass', `${r.name} present`, '', 0);
      else add(`hdr-${r.key}`, 'Headers', spec.severity, `${r.name} header missing`, '', spec.deduction, spec.rec);
    });
    const server = String(ctx.http.headers.server || '');
    if (/\d/.test(server)) add('server-version', 'Headers', 'low', 'Server header discloses version information', server.slice(0, 80), 2, 'Hide version details from the Server header.');
    if (ctx.http.headers['x-powered-by']) add('x-powered-by', 'Headers', 'low', 'X-Powered-By header discloses technology', String(ctx.http.headers['x-powered-by']).slice(0, 80), 2, 'Remove the X-Powered-By header.');
    const cookies = [].concat(ctx.http.headers['set-cookie'] || []);
    if (cookies.length) {
      if (ctx.isHttps && cookies.some((c) => !/;\s*secure/i.test(c))) add('cookie-secure', 'Cookies', 'low', 'Cookie set without the Secure flag', '', 3, 'Mark cookies Secure so they are never sent over plain HTTP.');
      if (cookies.some((c) => !/;\s*httponly/i.test(c))) add('cookie-httponly', 'Cookies', 'low', 'Cookie set without the HttpOnly flag', '', 2, 'Mark session cookies HttpOnly so scripts cannot read them.');
    }
  }

  /* --- DNS / e-mail authentication --- */
  const d = ctx.dns || {};
  if (!ctx.isIp && Array.isArray(d.mx) && d.mx.length) {
    if (!d.spf) add('no-spf', 'DNS', 'low', 'No SPF record found', 'The domain receives mail but has no SPF policy.', 2, 'Publish an SPF TXT record listing authorised mail senders.');
    if (!d.dmarc) add('no-dmarc', 'DNS', 'low', 'No DMARC record found', '', 3, 'Publish a DMARC record (_dmarc TXT) to protect against e-mail spoofing.');
  }

  /* --- Domain registration --- */
  const dom = ctx.domain || {};
  if (dom.available) {
    if (typeof dom.ageDays === 'number' && dom.ageDays < 30) add('young-domain', 'Domain', 'medium', 'Domain was registered very recently', `${dom.ageDays} day(s) old.`, 10, 'Treat newly registered domains with caution.');
    if (typeof dom.daysToExpiry === 'number' && dom.daysToExpiry >= 0 && dom.daysToExpiry < 30) add('domain-expiring', 'Domain', 'low', 'Domain registration expires soon', `${dom.daysToExpiry} day(s) remaining.`, 3, 'Renew the domain registration.');
  }

  /* --- URL indicators + reputation --- */
  (ctx.indicators || []).forEach((i) => add(`url-${i.id}`, 'URL', i.severity, i.title, i.detail, i.deduction, 'Verify this address independently before entering any personal information.'));
  const rep = ctx.reputation;
  if (rep && rep.verdict === 'listed') {
    add('reputation-listed', 'Reputation', 'critical', 'Listed in the malicious-URL dataset', `Dataset category: ${rep.dataset.type} (${rep.dataset.matchKind} match).`,
      rep.dataset.matchKind === 'exact' ? 60 : 40, 'Do not visit or enter data on this site.');
  } else if (rep && rep.datasetLoaded) add('reputation-clear', 'Reputation', 'pass', 'Not found in the malicious-URL dataset', 'A missing entry is not a guarantee of safety.', 0);

  f.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.deduction - a.deduction);
  const total = f.reduce((s, x) => s + x.deduction, 0);
  // Hard caps: some problems are serious enough that other good practices must not hide them.
  const caps = [];
  if (f.some((x) => x.id === 'no-https')) caps.push(['No working HTTPS', 45]);
  if (f.some((x) => x.id === 'bad-cert')) caps.push(['Untrusted certificate', 55]);
  if (f.some((x) => x.id === 'reputation-listed')) caps.push(['Listed in malicious-URL dataset', 10]);
  const cap = caps.reduce((m, c) => Math.min(m, c[1]), 100);
  const score = Math.max(0, Math.min(100 - total, cap));
  const status = statusFromScore(score);
  const recommendations = [...new Set(f.filter((x) => x.deduction > 0 && x.recommendation).map((x) => x.recommendation))];
  return { findings: f, score, status, assessment: assessmentFor(status, f), recommendations, cappedBy: caps.filter((c) => c[1] === cap && cap < 100 - total + 1).map((c) => c[0]) };
}

module.exports = { evaluate, statusFromScore, headerReport, SECURITY_HEADERS };
