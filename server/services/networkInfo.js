'use strict';
/**
 * Server-side network/IP lookup.
 * - The IP the server sees (req.ip) is reported as "Client IP seen by server" (::1 on localhost is expected).
 * - On loopback/private addresses the public IP is discovered by asking the geo-IP provider about the server's own
 *   egress address (on a developer machine this is the same internet connection as the browser).
 * - Two providers race in parallel with a hard timeout; the result is cached; missing fields become "Not available".
 */
const net = require('net');
const config = require('../config');
const { isPrivateAddress, unwrapMapped } = require('./urlSafety');

const NA = 'Not available';
const cache = new Map();
const OK_TTL = 10 * 60 * 1000, FAIL_TTL = 30 * 1000;

const str = (v) => (v === undefined || v === null || v === '' ? NA : String(v));

async function getJson(url) {
  const res = await fetch(url, { headers: { accept: 'application/json', 'user-agent': 'CyberShield/2.0' }, signal: AbortSignal.timeout(config.timeouts.network) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

const providers = [
  async (ip) => {
    const j = await getJson(`https://ipwho.is/${ip}`);
    if (j.success === false) throw new Error(j.message || 'lookup failed');
    return { publicIp: j.ip, ipVersion: j.type, isp: j.connection && j.connection.isp, org: j.connection && j.connection.org,
      asn: j.connection && j.connection.asn ? `AS${j.connection.asn}` : null, country: j.country, region: j.region, city: j.city,
      timezone: j.timezone && j.timezone.id, source: 'ipwho.is' };
  },
  async (ip) => {
    const j = await getJson(ip ? `https://ipapi.co/${ip}/json/` : 'https://ipapi.co/json/');
    if (j.error) throw new Error(j.reason || 'lookup failed');
    return { publicIp: j.ip, ipVersion: j.version, isp: j.org, org: j.org, asn: j.asn, country: j.country_name, region: j.region, city: j.city,
      timezone: j.timezone, source: 'ipapi.co' };
  },
];

function normalizeClientIp(raw) {
  const ip = unwrapMapped(String(raw || '').toLowerCase());
  return net.isIP(ip) ? ip : '';
}

async function getNetworkInfo(reqIp) {
  const clientIp = normalizeClientIp(reqIp);
  const local = !clientIp || isPrivateAddress(clientIp);
  const key = local ? 'self' : clientIp;
  const hit = cache.get(key);
  if (hit && hit.exp > Date.now()) return { ...hit.value, clientIp: clientIp || NA };

  const base = {
    clientIp: clientIp || NA,
    clientIpNote: local ? 'Loopback/private address: the server sees your local connection. The public IP below comes from an external lookup.' : '',
    publicIp: local ? NA : clientIp, ipVersion: clientIp ? (net.isIP(clientIp) === 6 ? 'IPv6' : 'IPv4') : NA,
    isp: NA, org: NA, asn: NA, country: NA, region: NA, city: NA, timezone: NA, source: NA, partial: true, error: '',
  };
  try {
    const r = await Promise.any(providers.map((p) => p(local ? '' : clientIp)));
    const value = { ...base, publicIp: str(r.publicIp), ipVersion: str(r.ipVersion && (/^IPv/.test(r.ipVersion) ? r.ipVersion : `IPv${r.ipVersion}`)),
      isp: str(r.isp), org: str(r.org), asn: str(r.asn), country: str(r.country), region: str(r.region), city: str(r.city), timezone: str(r.timezone),
      source: r.source, partial: false };
    cache.set(key, { exp: Date.now() + OK_TTL, value });
    return value;
  } catch (e) {
    const value = { ...base, error: 'External IP lookup is unavailable right now. Showing what the server can see locally.' };
    cache.set(key, { exp: Date.now() + FAIL_TTL, value });
    return value;
  }
}

module.exports = { getNetworkInfo, normalizeClientIp };
