'use strict';
const express = require('express');
const { AppError } = require('../errors');
const phishing = require('../services/phishing');
const store = require('../services/store');
const crypto = require('crypto');

const router = express.Router();

// POST /api/phishing   { "url": "http://example.test/login" }
router.post('/', async (req, res, next) => {
  try {
    const input = req.body && req.body.url;
    if (typeof input !== 'string') throw new AppError('A "url" string is required.', 'BAD_INPUT');
    const result = phishing.check(input);
    if (req.clientId) {
      const label = { listed: 'danger', suspicious: 'warning', no_match: 'safe' }[result.verdict];
      await store.add(req.clientId, {
        id: crypto.randomUUID(), type: 'phishing', target: result.normalized.slice(0, 120), score: result.safetyScore, status: label,
        at: new Date().toISOString(), summary: result.verdict === 'listed' ? 'Listed in malicious-URL dataset' : result.verdict === 'suspicious' ? 'Suspicious URL indicators' : 'No dataset match', recommendations: [],
      });
    }
    res.json({ success: true, ...result });
  } catch (e) { next(e); }
});

module.exports = router;
