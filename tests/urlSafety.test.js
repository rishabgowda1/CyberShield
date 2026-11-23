'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseTarget, isPrivateAddress } = require('../server/services/urlSafety');

test('adds https:// when no protocol is given', () => {
  assert.equal(parseTarget('example.com').href, 'https://example.com/');
  assert.equal(parseTarget('  http://example.com/a?b=1 ').protocol, 'http:');
});

test('rejects dangerous or malformed input', () => {
  for (const bad of ['', '   ', 'file:///etc/passwd', 'ftp://example.com', 'javascript:alert(1)', 'http://user:pw@example.com', 'exa mple.com', 'localhost:99999', 'nodots', 'http://example.com:22', '<script>']) {
    assert.throws(() => parseTarget(bad), /./, `should reject: ${bad}`);
  }
  assert.throws(() => parseTarget(null));
});

test('private / loopback / metadata addresses are detected (SSRF guard)', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '::1', '::', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1', '::ffff:7f00:1', '::ffff:a9fe:a9fe', 'not-an-ip']) {
    assert.equal(isPrivateAddress(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111', '172.32.0.1']) assert.equal(isPrivateAddress(ip), false, ip);
});

test('decimal / hex IP tricks normalise to a blocked address', () => {
  assert.equal(isPrivateAddress(parseTarget('http://2130706433/').hostname), true);
  assert.equal(isPrivateAddress(parseTarget('http://0x7f.1/').hostname), true);
});
