'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const phishing = require('../server/services/phishing');

test.before(async () => { await phishing.load(); });

test('dataset loads', () => { assert.equal(phishing.status().loaded, true); assert.ok(phishing.status().entries >= 5); });

test('exact match ignores scheme, www and trailing slash', () => {
  for (const u of ['http://secure-login-examplebank.example/verify', 'https://www.secure-login-examplebank.example/verify/', 'SECURE-LOGIN-EXAMPLEBANK.EXAMPLE/verify']) {
    const r = phishing.check(u);
    assert.equal(r.verdict, 'listed', u);
    assert.equal(r.dataset.matchKind, 'exact');
  }
});

test('benign entries and unknown URLs are not listed', () => {
  assert.equal(phishing.check('https://example.com').verdict, 'no_match');
  assert.equal(phishing.check('https://wikipedia.org/wiki/Computer_security').verdict, 'no_match');
});

test('heuristics flag suspicious URLs without a dataset hit', () => {
  const r = phishing.check('http://192.168.4.4/paypal-secure-login/verify-account?redirect=https://evil.test');
  assert.equal(r.verdict, 'suspicious');
  assert.ok(r.indicators.some((i) => i.id === 'ip-host'));
});

test('invalid input is rejected with a clear error', () => {
  assert.throws(() => phishing.check('http://[bad'), /valid URL/);
  assert.throws(() => phishing.check(''), /Enter a URL/);
});
