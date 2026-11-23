'use strict';
/** Tiny JSON-file persistence layer (no native dependencies). Swap for SQLite/Mongo later without touching routes. */
const fs = require('fs');
const path = require('path');
const config = require('../config');

const MAX_CLIENTS = 2000;

class HistoryStore {
  constructor(file = path.join(config.dataDir, 'history.json')) {
    this.file = file;
    this.data = { clients: {} };
    this.ready = null;
    this.queue = Promise.resolve();
  }

  init() {
    if (!this.ready) this.ready = this._load();
    return this.ready;
  }

  async _load() {
    try {
      const txt = await fs.promises.readFile(this.file, 'utf8');
      const parsed = JSON.parse(txt);
      if (parsed && typeof parsed.clients === 'object') this.data = parsed;
    } catch (e) {
      if (e.code !== 'ENOENT') {
        try { await fs.promises.rename(this.file, this.file + '.corrupt'); } catch { /* ignore */ }
      }
    }
  }

  _persist() {
    this.queue = this.queue.then(async () => {
      try {
        await fs.promises.mkdir(path.dirname(this.file), { recursive: true });
        const tmp = this.file + '.tmp';
        await fs.promises.writeFile(tmp, JSON.stringify(this.data));
        await fs.promises.rename(tmp, this.file);
      } catch (e) { console.error('[store] could not write history:', e.message); }
    });
    return this.queue;
  }

  async list(clientId) {
    await this.init();
    const c = this.data.clients[clientId];
    return c ? c.entries : [];
  }

  async add(clientId, entry) {
    await this.init();
    let c = this.data.clients[clientId];
    if (!c) {
      const ids = Object.keys(this.data.clients);
      if (ids.length >= MAX_CLIENTS) {
        const oldest = ids.sort((a, b) => this.data.clients[a].updatedAt - this.data.clients[b].updatedAt)[0];
        delete this.data.clients[oldest];
      }
      c = this.data.clients[clientId] = { updatedAt: 0, entries: [] };
    }
    c.entries.unshift(entry);
    if (c.entries.length > config.historyLimit) c.entries.length = config.historyLimit;
    c.updatedAt = Date.now();
    await this._persist();
    return entry;
  }

  async clear(clientId) {
    await this.init();
    delete this.data.clients[clientId];
    await this._persist();
  }
}

module.exports = new HistoryStore();
module.exports.HistoryStore = HistoryStore;
