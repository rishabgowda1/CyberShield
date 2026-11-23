'use strict';
const express = require('express');
const { AppError } = require('../errors');
const { scanTarget } = require('../services/securityScanner');
const store = require('../services/store');

const router = express.Router();

// POST /api/scan   { "url": "example.com" }
router.post('/', async (req, res, next) => {
  try {
    const input = req.body && req.body.url;
    if (typeof input !== 'string') throw new AppError('A "url" string is required.', 'BAD_INPUT');
    const result = await scanTarget(input);
    if (req.clientId) {
      await store.add(req.clientId, {
        id: result.scanId, type: 'scan', target: result.domain.hostname, score: result.score, status: result.status,
        at: result.scannedAt, summary: result.assessment, recommendations: result.recommendations.slice(0, 10),
      });
    }
    res.json(result);
  } catch (e) { next(e); }
});

module.exports = router;
