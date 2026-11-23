'use strict';
const net = require('net');
const { stripBrackets } = require('./urlSafety');

const KEYWORDS = ['login', 'signin', 'secure', 'verify', 'account', 'update', 'banking', 'wallet', 'paypal', 'appleid', 'support', 'password'];
const RISKY_TLDS = ['zip', 'mov', 'xyz', 'top', 'tk', 'gq', 'ml', 'cf', 'ga', 'click', 'country', 'work', 'support'];

/**
 * Heuristic indicators computed from the URL string only (no network).
 * These are *indicators*, not proof of malicious intent.
 * @param {URL} u parsed URL
 * @param {{checkScheme?: boolean}} opts
 * @returns {{id:string,severity:string,title:string,detail:string,deduction:number}[]}
 */
function analyzeUrl(u, opts = {}) {
  const out = [];
  const host = stripBrackets(u.hostname).toLowerCase();
  const full = u.href;
  const add = (id, severity, title, detail, deduction) => out.push({ id, severity, title, detail, deduction });
  const labels = host.split('.');

  if (net.isIP(host)) add('ip-host', 'medium', 'Address uses a raw IP instead of a domain', 'Legitimate services rarely ask users to visit a bare IP address.', 10);
  if (u.username || u.password) add('credentials-in-url', 'high', 'URL contains a user@ section', 'Text before "@" is a common trick to disguise the real destination.', 12);
  if (labels.some((l) => l.startsWith('xn--'))) add('punycode', 'medium', 'Internationalised (punycode) domain', 'Look-alike characters can imitate well-known brands.', 5);
  if (!net.isIP(host) && labels.length >= 5) add('many-subdomains', 'low', 'Unusually deep subdomain nesting', `${labels.length} labels in the hostname.`, 4);
  const kw = KEYWORDS.filter((k) => host.includes(k));
  if (kw.length) add('sensitive-keyword', 'low', 'Hostname contains a sensitive keyword', `Found: ${kw.join(', ')}. Common in phishing hostnames, also used by legitimate sites.`, 4);
  if ((host.match(/-/g) || []).length >= 3) add('many-hyphens', 'low', 'Hostname contains many hyphens', 'Long hyphenated names are typical of throw-away phishing domains.', 3);
  if (full.length > 100) add('long-url', 'low', 'Very long URL', `${full.length} characters.`, 2);
  const tld = labels[labels.length - 1];
  if (!net.isIP(host) && RISKY_TLDS.includes(tld)) add('risky-tld', 'low', `Top-level domain ".${tld}" is frequently abused`, 'Not malicious by itself; check the rest of the evidence.', 3);
  if (u.port && !['80', '443'].includes(u.port)) add('odd-port', 'low', `Non-standard port ${u.port}`, '', 2);
  if (/[?&](url|redirect|redirect_uri|next|return|continue)=https?(%3a|:)/i.test(u.search)) add('embedded-url', 'low', 'Query string contains another URL', 'Open-redirect style links are used to hide the final destination.', 3);
  if (opts.checkScheme && u.protocol === 'http:') add('plain-http', 'low', 'Link does not use HTTPS', 'Traffic to this address is not encrypted.', 3);
  return out;
}

module.exports = { analyzeUrl };
