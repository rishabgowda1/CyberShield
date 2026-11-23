'use strict';
const express = require('express');
const { getNetworkInfo } = require('../services/networkInfo');

const router = express.Router();

// GET /api/network  – always answers within a few seconds, with partial data if the external lookup fails
router.get('/', async (req, res, next) => {
  try { res.json({ success: true, ...(await getNetworkInfo(req.ip)) }); } catch (e) { next(e); }
});

module.exports = router;
