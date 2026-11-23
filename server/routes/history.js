'use strict';
const express = require('express');
const store = require('../services/store');

const router = express.Router();

router.get('/', async (req, res, next) => {
  try { res.json({ success: true, entries: req.clientId ? await store.list(req.clientId) : [] }); } catch (e) { next(e); }
});

router.delete('/', async (req, res, next) => {
  try { if (req.clientId) await store.clear(req.clientId); res.json({ success: true, entries: [] }); } catch (e) { next(e); }
});

module.exports = router;
