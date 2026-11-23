'use strict';
const fs = require('fs');
const readline = require('readline');
const config = require('../config');
const { parseLoose } = require('./urlSafety');
const { analyzeUrl } = require('./urlIndicators');

const MALICIOUS = new Set(['phishing', 'malware', 'defacement']);
const exact = new Map();  // normalized url -> type
const hosts = new Map();  // host -> count of malicious URLs
let state = { loaded: false, entries: 0, error: null };

/** lower-case, strip scheme / www. / fragment / trailing slash so dataset rows and user input compare equal */
function normalizeKey(raw) {
  return String(raw).trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^www\./, '').replace(/#.*$/, '').replace(/\/+$/, '');
}
const hostOf = (key) => key.split(/[/?]/)[0].split(':')[0];

async function load(file = config.phishingCsv) {
  exact.clear(); hosts.clear();
  state = { loaded: false, entries: 0, error: null };
  if (!fs.existsSync(file)) { state.error = 'Dataset file not found'; return state; }
  const rl = readline.createInterface({ input: fs.createReadStream(file, { encoding: 'utf8' }), crlfDelay: Infinity });
  let first = true;
  for await (const line of rl) {
    if (!line.trim()) continue;
    const cut = line.lastIndexOf(',');             // URL may contain commas; type is always the last column
    if (cut < 1) continue;
    const url = line.slice(0, cut).replace(/^"|"$/g, ''), type = line.slice(cut + 1).trim().toLowerCase();
    if (first) { first = false; if (type === 'type') continue; }
    const key = normalizeKey(url);
    if (!key) continue;
    exact.set(key, type);
    if (MALICIOUS.has(type)) hosts.set(hostOf(key), (hosts.get(hostOf(key)) || 0) + 1);
    state.entries++;
  }
  state.loaded = true;
  return state;
}

const status = () => ({ ...state });

/** Look up a parsed URL. Returns {verdict, dataset, datasetLoaded, note} */
function reputation(u) {
  if (!state.loaded) return { verdict: 'unknown', datasetLoaded: false, dataset: null, note: 'Dataset is not loaded.' };
  const key = normalizeKey(u.href);
  const host = hostOf(key);
  const t = exact.get(key);
  if (t && MALICIOUS.has(t)) return { verdict: 'listed', datasetLoaded: true, dataset: { type: t, matchKind: 'exact' }, note: '' };
  const hostType = exact.get(host);
  if (hostType && MALICIOUS.has(hostType)) return { verdict: 'listed', datasetLoaded: true, dataset: { type: hostType, matchKind: 'host' }, note: '' };
  const others = hosts.get(host) || 0;
  return { verdict: 'no_match', datasetLoaded: true, dataset: t ? { type: t, matchKind: 'exact' } : null,
    note: others ? `${others} other URL(s) on this host are listed as malicious.` : (t === 'benign' ? 'Listed as benign in the dataset.' : '') };
}

/** Full phishing check used by POST /api/phishing */
function check(raw) {
  const u = parseLoose(raw);
  const indicators = analyzeUrl(u, { checkScheme: true });
  const rep = reputation(u);
  let risk = indicators.reduce((s, i) => s + i.deduction, 0);
  if (rep.verdict === 'listed') risk = 100;
  else if (/other URL/.test(rep.note)) risk += 15;
  risk = Math.min(100, risk);
  const verdict = rep.verdict === 'listed' ? 'listed' : risk >= 8 ? 'suspicious' : 'no_match';
  return {
    url: u.href, normalized: normalizeKey(u.href), verdict, riskScore: risk, safetyScore: 100 - risk,
    dataset: rep.dataset, datasetLoaded: rep.datasetLoaded, datasetEntries: state.entries, note: rep.note, indicators,
    disclaimer: 'This is an educational check against a local dataset plus URL heuristics. "No match" does not prove a site is safe, and a match is not a legal verdict.',
  };
}

module.exports = { load, check, reputation, status, normalizeKey };
