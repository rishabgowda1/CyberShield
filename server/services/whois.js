'use strict';
/**
 * Domain registration data via RDAP (the JSON successor to WHOIS).
 * rdap.org redirects to the correct registry, so no manual WHOIS-server table or text parsing is needed.
 * Returns a fully-populated object even on failure ("Not available" strings + empty arrays).
 */
const { getDomain } = require('tldts');
const config = require('../config');

const NA = 'Not available';
const cache = new Map(); // domain -> {at, value}
const TTL = 60 * 60 * 1000;

function emptyDomain(hostname, extra = {}) {
  return { hostname, registrableDomain: getDomain(hostname) || '', registrar: NA, registration: NA, expiration: NA, lastChanged: NA,
    status: [], nameServers: [], source: 'RDAP', available: false, ageDays: null, daysToExpiry: null, note: '', ...extra };
}

function vcardName(entity) {
  const card = entity && entity.vcardArray && Array.isArray(entity.vcardArray[1]) ? entity.vcardArray[1] : [];
  const fn = card.find((r) => Array.isArray(r) && r[0] === 'fn');
  return fn && typeof fn[3] === 'string' ? fn[3] : '';
}

function parseRdap(json, hostname) {
  const events = Array.isArray(json.events) ? json.events : [];
  const ev = (a) => { const e = events.find((x) => x.eventAction === a); return e && e.eventDate ? e.eventDate : null; };
  const reg = ev('registration'), exp = ev('expiration'), chg = ev('last changed');
  const registrar = (Array.isArray(json.entities) ? json.entities : []).find((e) => Array.isArray(e.roles) && e.roles.includes('registrar'));
  const day = 86400000;
  const out = emptyDomain(hostname, {
    available: true,
    registrar: vcardName(registrar) || NA,
    registration: reg || NA, expiration: exp || NA, lastChanged: chg || NA,
    status: Array.isArray(json.status) ? json.status.map(String) : [],
    nameServers: (Array.isArray(json.nameservers) ? json.nameservers : []).map((n) => String(n.ldhName || '').toLowerCase()).filter(Boolean),
  });
  if (reg && !Number.isNaN(Date.parse(reg))) out.ageDays = Math.floor((Date.now() - Date.parse(reg)) / day);
  if (exp && !Number.isNaN(Date.parse(exp))) out.daysToExpiry = Math.floor((Date.parse(exp) - Date.now()) / day);
  return out;
}

async function lookupDomain(hostname) {
  const domain = getDomain(hostname);
  if (!domain) return emptyDomain(hostname, { note: 'No registrable domain (IP address or internal name).' });
  const hit = cache.get(domain);
  if (hit && Date.now() - hit.at < TTL) return { ...hit.value, hostname };
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { accept: 'application/rdap+json, application/json' },
      signal: AbortSignal.timeout(config.timeouts.rdap),
      redirect: 'follow',
    });
    if (!res.ok) {
      const note = res.status === 404 ? 'The registry for this TLD does not publish RDAP data, or the domain is unregistered.' : `RDAP service answered HTTP ${res.status}.`;
      return emptyDomain(hostname, { note });
    }
    const value = parseRdap(await res.json(), hostname);
    cache.set(domain, { at: Date.now(), value });
    return value;
  } catch (e) {
    return emptyDomain(hostname, { note: e.name === 'TimeoutError' ? 'Registration lookup timed out.' : 'Registration lookup service is unreachable.' });
  }
}

module.exports = { lookupDomain, parseRdap, emptyDomain, NA };
