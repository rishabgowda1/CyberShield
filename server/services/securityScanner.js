'use strict';
const net = require('net');
const tls = require('tls');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const { Resolver } = require('dns').promises;
const { getDomain } = require('tldts');

const config = require('../config');
const { AppError } = require('../errors');
const { parseTarget, resolveTarget, pinnedLookup, stripBrackets, withTimeout } = require('./urlSafety');
const { analyzeUrl } = require('./urlIndicators');
const { evaluate, headerReport } = require('./scoring');
const { lookupDomain, NA } = require('./whois');
const phishing = require('./phishing');

const arr = (v) => (Array.isArray(v) ? v : []);
const UA = 'CyberShield-Scanner/2.0 (+educational security scan)';

/* ------------------------------------------------------------------ DNS */
async function dnsRecords(hostname, isIp, addrs) {
  const out = { a: [], aaaa: [], ns: [], mx: [], spf: null, dmarc: null };
  addrs.forEach((x) => (x.family === 4 ? out.a : out.aaaa).push(x.address));
  const domain = getDomain(hostname);
  if (isIp || !domain) return out;
  const r = new Resolver({ timeout: 3000, tries: 1 });
  const safe = async (fn, fallback) => { try { return await fn(); } catch { return fallback; } };
  const [ns, mx, txt, dmarcTxt] = await Promise.all([
    safe(() => r.resolveNs(domain), []),
    safe(() => r.resolveMx(domain), []),
    safe(() => r.resolveTxt(domain), []),
    safe(() => r.resolveTxt(`_dmarc.${domain}`), []),
  ]);
  out.ns = arr(ns).map((n) => String(n).toLowerCase()).sort();
  out.mx = arr(mx).sort((a, b) => a.priority - b.priority).map((m) => `${m.priority} ${m.exchange}`);
  const flat = (rows) => arr(rows).map((chunks) => arr(chunks).join(''));
  out.spf = flat(txt).find((t) => /^v=spf1\b/i.test(t)) || null;
  out.dmarc = flat(dmarcTxt).find((t) => /^v=DMARC1\b/i.test(t)) || null;
  return out;
}

/* ------------------------------------------------------------------ TLS */
function tlsCheck(hostname, port, address, isIp) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    let socket;
    try {
      socket = tls.connect({
        host: hostname, port, servername: isIp ? undefined : hostname, lookup: pinnedLookup(address),
        rejectUnauthorized: false, timeout: config.timeouts.tls,
      });
    } catch (e) { return finish({ available: false, error: e.code || e.message }); }
    socket.on('secureConnect', () => {
      const cert = socket.getPeerCertificate() || {};
      const exp = cert.valid_to ? Date.parse(cert.valid_to) : NaN;
      const cipher = socket.getCipher() || {};
      const info = {
        available: true, authorized: !!socket.authorized,
        authorizationError: socket.authorized ? '' : String(socket.authorizationError || 'unknown'),
        protocol: socket.getProtocol() || '', cipher: cipher.name || '',
        subject: (cert.subject && (cert.subject.CN || cert.subject.O)) || '',
        issuer: (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || '',
        validFrom: cert.valid_from || '', validTo: cert.valid_to || '',
        daysRemaining: Number.isNaN(exp) ? null : Math.floor((exp - Date.now()) / 86400000),
        altNames: cert.subjectaltname ? String(cert.subjectaltname).split(/,\s*/).map((s) => s.replace(/^DNS:/, '')).slice(0, 20) : [],
      };
      socket.end();
      finish(info);
    });
    socket.on('timeout', () => { socket.destroy(); finish({ available: false, error: 'timeout' }); });
    socket.on('error', (e) => finish({ available: false, error: e.code || e.message }));
  });
}

/* ------------------------------------------------------------------ HTTP */
function requestOnce(u, address) {
  return new Promise((resolve, reject) => {
    const isHttps = u.protocol === 'https:';
    const req = (isHttps ? https : http).request({
      hostname: stripBrackets(u.hostname), port: u.port || (isHttps ? 443 : 80), path: `${u.pathname}${u.search}`,
      method: 'GET', headers: { 'user-agent': UA, accept: '*/*' }, lookup: pinnedLookup(address),
      rejectUnauthorized: false, timeout: config.timeouts.http, agent: false,
    }, (res) => {
      resolve({ statusCode: res.statusCode, headers: res.headers });
      res.destroy(); // headers are all we need; never download the body
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', (e) => reject(e));
    req.end();
  });
}

/** Follow up to 4 redirects; every hop is re-validated against the SSRF rules. */
async function fetchHeaders(startUrl, firstAddress) {
  let u = startUrl, address = firstAddress;
  const redirects = [];
  for (let hop = 0; hop < 5; hop++) {
    const res = await requestOnce(u, address);
    const loc = res.headers.location;
    if (res.statusCode >= 300 && res.statusCode < 400 && loc && hop < 4) {
      const next = new URL(loc, u);
      if (!['http:', 'https:'].includes(next.protocol)) break;
      if (next.port && !config.allowedPorts.includes(Number(next.port))) break;
      redirects.push({ from: u.href, to: next.href, status: res.statusCode });
      address = (await resolveTarget(stripBrackets(next.hostname)))[0];
      u = next;
      continue;
    }
    return { finalUrl: u.href, statusCode: res.statusCode, headers: res.headers, redirects };
  }
  throw new Error('too many redirects');
}

async function httpRedirectsToHttps(hostname, address) {
  try {
    const res = await requestOnce(new URL(`http://${net.isIP(hostname) === 6 ? `[${hostname}]` : hostname}/`), address);
    return res.statusCode >= 300 && res.statusCode < 400 && /^https:\/\//i.test(String(res.headers.location || ''));
  } catch { return null; } // port 80 closed/unreachable: not penalised
}

/* ------------------------------------------------------------------ result normalisation */
/** Guarantees the response contract: every list is an array, every optional object exists. */
function normalizeResult(r) {
  r.findings = arr(r.findings);
  r.recommendations = arr(r.recommendations);
  r.domain = r.domain || {};
  r.domain.status = arr(r.domain.status);
  r.domain.nameServers = arr(r.domain.nameServers);
  r.security = r.security || {};
  r.security.dns = r.security.dns || {};
  ['a', 'aaaa', 'ns', 'mx'].forEach((k) => { r.security.dns[k] = arr(r.security.dns[k]); });
  r.security.headers = arr(r.security.headers);
  r.security.urlIndicators = arr(r.security.urlIndicators);
  r.security.warnings = arr(r.security.warnings);
  r.security.redirects = arr(r.security.redirects);
  r.security.tls = r.security.tls || { available: false };
  return r;
}

/* ------------------------------------------------------------------ main */
async function runScan(rawInput) {
  const started = Date.now();
  const url = parseTarget(rawInput);
  const hostname = stripBrackets(url.hostname).toLowerCase();
  const isIp = net.isIP(hostname) !== 0;
  const isHttps = url.protocol === 'https:';
  const addrs = await resolveTarget(hostname);
  const address = addrs[0];
  const tlsPort = isHttps && url.port ? Number(url.port) : 443;
  const defaultPorts = !url.port || url.port === '80' || url.port === '443';
  const warnings = [];

  const [dnsR, tlsR, httpR, redirR, rdapR] = await Promise.allSettled([
    dnsRecords(hostname, isIp, addrs),
    tlsCheck(hostname, tlsPort, address, isIp),
    fetchHeaders(url, address),
    defaultPorts ? httpRedirectsToHttps(hostname, address) : Promise.resolve(null),
    isIp ? Promise.resolve(null) : lookupDomain(hostname),
  ]);

  const dnsInfo = dnsR.status === 'fulfilled' ? dnsR.value : (warnings.push('DNS record lookup failed.'), { a: [], aaaa: [], ns: [], mx: [], spf: null, dmarc: null });
  const tlsInfo = tlsR.status === 'fulfilled' ? tlsR.value : { available: false, error: 'lookup failed' };
  const httpInfo = httpR.status === 'fulfilled' ? httpR.value : null;
  const httpError = httpR.status === 'rejected' ? String(httpR.reason && (httpR.reason.code || httpR.reason.message) || 'request failed') : '';
  if (httpError) warnings.push(`HTTP request failed: ${httpError}.`);
  const redirectsToHttps = redirR.status === 'fulfilled' ? redirR.value : null;
  const domainInfo = rdapR.status === 'fulfilled' && rdapR.value ? rdapR.value : require('./whois').emptyDomain(hostname, { note: isIp ? 'IP address – no domain registration.' : '' });
  if (!domainInfo.available && domainInfo.note) warnings.push(domainInfo.note);

  const indicators = analyzeUrl(url);
  const reputation = phishing.reputation(url);
  const result = evaluate({
    isHttps: isHttps || tlsInfo.available, isIp, tls: tlsInfo, http: httpInfo, httpError, redirectsToHttps,
    dns: dnsInfo, domain: domainInfo, indicators, reputation,
  });

  return normalizeResult({
    success: true,
    scanId: crypto.randomUUID(),
    scannedAt: new Date().toISOString(),
    input: String(rawInput).trim().slice(0, 300),
    url: url.href,
    score: result.score,
    status: result.status,
    assessment: result.assessment,
    domain: {
      hostname, registrableDomain: getDomain(hostname) || '', protocol: url.protocol, port: Number(url.port) || (isHttps ? 443 : 80),
      ip: address.address, registrar: domainInfo.registrar, registration: domainInfo.registration, expiration: domainInfo.expiration,
      lastChanged: domainInfo.lastChanged, status: domainInfo.status, nameServers: domainInfo.nameServers.length ? domainInfo.nameServers : dnsInfo.ns,
      source: domainInfo.available ? 'RDAP' : 'DNS only', available: domainInfo.available, note: domainInfo.note || '',
    },
    security: {
      dns: dnsInfo,
      tls: tlsInfo,
      headers: httpInfo ? headerReport(httpInfo.headers, isHttps || tlsInfo.available) : [],
      httpStatus: httpInfo ? httpInfo.statusCode : null,
      finalUrl: httpInfo ? httpInfo.finalUrl : null,
      redirects: httpInfo ? httpInfo.redirects : [],
      redirectsToHttps,
      urlIndicators: indicators,
      reputation: { verdict: reputation.verdict, datasetLoaded: reputation.datasetLoaded, dataset: reputation.dataset },
      warnings,
    },
    findings: result.findings,
    recommendations: result.recommendations,
    durationMs: Date.now() - started,
  });
}

/** Public entry: whole scan is bounded by one hard timeout. */
function scanTarget(rawInput) {
  return withTimeout(runScan(rawInput), config.timeouts.scanTotal, 'The scan');
}

module.exports = { scanTarget, normalizeResult };
