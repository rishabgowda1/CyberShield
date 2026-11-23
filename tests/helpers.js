'use strict';
const http = require('http');
/** Minimal JSON request helper for tests */
function request(port, method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = http.request({ host: '127.0.0.1', port, method, path, headers: { 'content-type': 'application/json', ...headers, ...(data ? { 'content-length': Buffer.byteLength(data) } : {}) } }, (res) => {
      let buf = '';
      res.on('data', (c) => (buf += c));
      res.on('end', () => { let json = null; try { json = JSON.parse(buf); } catch { /* not json */ } resolve({ status: res.statusCode, headers: res.headers, json, text: buf }); });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}
module.exports = { request };
