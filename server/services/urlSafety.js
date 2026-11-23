'use strict';
const net = require('net');
const dns = require('dns').promises;
const config = require('../config');
const { AppError } = require('../errors');

const stripBrackets = (h) => String(h).replace(/^\[|\]$/g, '');

/* ---------- private / internal address detection (SSRF guard) ---------- */
const blocked = new net.BlockList();
[
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15],
  ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
].forEach(([a, p]) => blocked.addSubnet(a, p, 'ipv4'));
[
  ['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8], ['2001:db8::', 32],
  ['64:ff9b::', 96], ['2002::', 16],
].forEach(([a, p]) => blocked.addSubnet(a, p, 'ipv6'));

function unwrapMapped(ip) {
  const dotted = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (dotted) return dotted[1];
  const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(ip);
  if (hex) {
    const hi = parseInt(hex[1], 16), lo = parseInt(hex[2], 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return ip;
}

function isPrivateAddress(ip) {
  const clean = unwrapMapped(stripBrackets(ip).toLowerCase());
  const fam = net.isIP(clean);
  if (!fam) return true; // unparseable -> treat as unsafe
  return blocked.check(clean, fam === 4 ? 'ipv4' : 'ipv6');
}

/* ---------- parsing ---------- */
function isValidHostname(h) {
  if (h.length > 253) return false;
  const labels = h.split('.');
  if (labels.length < 2 && h !== 'localhost') return false;
  return labels.every((l) => /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i.test(l));
}

/** Strict parser used by the scanner (what we are allowed to connect to). */
function parseTarget(raw) {
  if (typeof raw !== 'string' || !raw.trim()) throw new AppError('Enter a website URL or domain.', 'BAD_INPUT');
  let s = raw.trim();
  if (s.length > 2048) throw new AppError('That URL is too long.', 'BAD_INPUT');
  if (/[\s<>"'`\\]/.test(s)) throw new AppError('The URL contains invalid characters.', 'INVALID_URL');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
  let u;
  try { u = new URL(s); } catch { throw new AppError('That does not look like a valid URL or domain (try example.com).', 'INVALID_URL'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new AppError('Only http and https URLs can be scanned.', 'INVALID_URL');
  if (u.username || u.password) throw new AppError('URLs containing credentials are not accepted.', 'INVALID_URL');
  const host = stripBrackets(u.hostname);
  if (!host || (net.isIP(host) === 0 && !isValidHostname(host))) {
    throw new AppError('Enter a full domain name such as example.com.', 'INVALID_URL');
  }
  if (u.port && !config.allowedPorts.includes(Number(u.port))) {
    throw new AppError(`Port ${u.port} is not allowed. Allowed ports: ${config.allowedPorts.join(', ')}.`, 'PORT_BLOCKED');
  }
  return u;
}

/** Lenient parser for the phishing checker (string analysis only, nothing is fetched). */
function parseLoose(raw) {
  if (typeof raw !== 'string' || !raw.trim()) throw new AppError('Enter a URL to check.', 'BAD_INPUT');
  let s = raw.trim();
  if (s.length > 4096) throw new AppError('That URL is too long.', 'BAD_INPUT');
  if (/\s/.test(s)) throw new AppError('The URL must not contain spaces.', 'INVALID_URL');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'http://' + s;
  let u;
  try { u = new URL(s); } catch { throw new AppError('That does not look like a valid URL.', 'INVALID_URL'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new AppError('Only http and https URLs can be checked.', 'INVALID_URL');
  return u;
}

/* ---------- DNS resolution + pinning (prevents DNS-rebinding between check and connect) ---------- */
async function withTimeout(promise, ms, label) {
  let t;
  const timer = new Promise((_, rej) => { t = setTimeout(() => rej(new AppError(`${label} timed out.`, 'TIMEOUT', 504)), ms); });
  try { return await Promise.race([promise, timer]); } finally { clearTimeout(t); }
}

async function resolveTarget(host) {
  const lit = net.isIP(host);
  let addrs;
  if (lit) {
    addrs = [{ address: host, family: lit }];
  } else {
    try {
      addrs = await withTimeout(dns.lookup(host, { all: true, verbatim: true }), config.timeouts.dns, 'DNS lookup');
    } catch (e) {
      if (e instanceof AppError) throw e;
      if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') {
        throw new AppError(`${host} does not resolve to any IP address. Check the spelling of the domain.`, 'DNS_NOT_FOUND', 422);
      }
      throw new AppError('The DNS lookup failed. Try again in a moment.', 'DNS_FAILED', 502);
    }
  }
  if (!config.allowPrivateTargets && addrs.some((a) => isPrivateAddress(a.address))) {
    throw new AppError('Scanning private, loopback or internal addresses is blocked.', 'TARGET_BLOCKED', 400);
  }
  addrs.sort((a, b) => a.family - b.family); // prefer IPv4 for reachability
  return addrs;
}

/** A `lookup` function that always returns the already-validated address. */
function pinnedLookup(address) {
  return (_host, opts, cb) => {
    if (typeof opts === 'function') { cb = opts; opts = {}; }
    if (opts && opts.all) return cb(null, [{ address: address.address, family: address.family }]);
    return cb(null, address.address, address.family);
  };
}

module.exports = { parseTarget, parseLoose, resolveTarget, pinnedLookup, isPrivateAddress, stripBrackets, withTimeout, unwrapMapped };
