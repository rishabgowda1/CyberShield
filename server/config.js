'use strict';
const path = require('path');

module.exports = {
  port: Number(process.env.PORT) || 3000,
  dataDir: process.env.DATA_DIR || path.join(__dirname, 'data'),
  phishingCsv: process.env.PHISH_CSV || path.join(__dirname, 'data', 'malicious_phish.csv'),
  trustProxy: process.env.TRUST_PROXY === '1',
  // SSRF protection: the scanner refuses loopback/private/link-local targets unless this is set (tests only).
  allowPrivateTargets: process.env.ALLOW_PRIVATE_TARGETS === '1',
  allowedPorts: [80, 443, 8080, 8443],
  historyLimit: 200,
  // Every network operation is bounded so no request can hang the UI.
  timeouts: { dns: 4000, tls: 5000, http: 6000, rdap: 6000, network: 4000, scanTotal: 22000 },
};
