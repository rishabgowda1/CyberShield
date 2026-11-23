'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { evaluate } = require('../server/services/scoring');

const goodTls = { available: true, authorized: true, protocol: 'TLSv1.3', issuer: 'Test CA', daysRemaining: 200 };
const allHeaders = { 'strict-transport-security': 'max-age=1', 'content-security-policy': "default-src 'self'", 'x-frame-options': 'DENY', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'permissions-policy': 'camera=()' };

test('a well configured site scores 100 / safe', () => {
  const r = evaluate({ isHttps: true, tls: goodTls, http: { headers: allHeaders }, redirectsToHttps: true, dns: { mx: [] }, domain: { available: true, ageDays: 900, daysToExpiry: 300 }, indicators: [], reputation: { verdict: 'no_match', datasetLoaded: true } });
  assert.equal(r.score, 100);
  assert.equal(r.status, 'safe');
  assert.deepEqual(r.recommendations, []);
});

test('no HTTPS and no headers is flagged as dangerous', () => {
  const r = evaluate({ isHttps: false, tls: { available: false, error: 'ECONNREFUSED' }, http: { headers: {} }, redirectsToHttps: null, dns: {}, domain: {}, indicators: [] });
  assert.ok(r.score < 50, `score ${r.score}`);
  assert.equal(r.status, 'danger');
  assert.ok(r.findings[0].severity === 'critical');
  assert.ok(r.recommendations.length > 0);
});

test('score is the explainable sum of deductions and never goes below 0', () => {
  const r = evaluate({ isHttps: true, tls: goodTls, http: { headers: { 'x-powered-by': 'Express' } }, redirectsToHttps: true, dns: {}, domain: {}, indicators: [] });
  const sum = r.findings.reduce((s, f) => s + f.deduction, 0);
  assert.equal(r.score, 100 - sum);
  const ind = [{ id: 'x', severity: 'high', title: 't', detail: '', deduction: 40 }];
  const worst = evaluate({ isHttps: false, tls: { available: false }, http: null, dns: {}, domain: {}, indicators: ind, reputation: { verdict: 'listed', datasetLoaded: true, dataset: { type: 'malware', matchKind: 'exact' } } });
  assert.equal(worst.score, 0);
});

test('hard caps stop good practices hiding a serious problem', () => {
  const noTls = evaluate({ isHttps: false, tls: { available: false }, http: { headers: allHeaders }, dns: {}, domain: {}, indicators: [] });
  assert.ok(noTls.score <= 45 && noTls.status === 'danger', `no HTTPS -> ${noTls.score}`);
  const badCert = evaluate({ isHttps: true, tls: { ...goodTls, authorized: false, authorizationError: 'CERT_HAS_EXPIRED' }, http: { headers: allHeaders }, redirectsToHttps: true, dns: {}, domain: {}, indicators: [] });
  assert.ok(badCert.score <= 55 && badCert.status === 'warning', `bad cert -> ${badCert.score}`);
  const listed = evaluate({ isHttps: true, tls: goodTls, http: { headers: allHeaders }, redirectsToHttps: true, dns: {}, domain: {}, indicators: [], reputation: { verdict: 'listed', datasetLoaded: true, dataset: { type: 'phishing', matchKind: 'host' } } });
  assert.ok(listed.score <= 10, `listed -> ${listed.score}`);
});

test('missing optional context never throws', () => {
  assert.doesNotThrow(() => evaluate({}));
});
