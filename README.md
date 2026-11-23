# CyberShield – Security Center (v2.0)

A full-stack student project: **vanilla HTML/CSS/JS client + Node.js/Express API**.
Website security scanner, security score, phishing-URL checker, password strength checker/generator,
network/IP information, server-persisted scan history and recommendations. No login required.

## Run it

```bash
npm install
npm start            # http://localhost:3000   (PORT=3001 npm start to change the port)
npm test             # 32 automated tests (unit + API + UI-in-jsdom)
```
Requires Node.js 18.17+ (tested on 22). Test suite needs `openssl` on the PATH for the self-signed-certificate scan test.

## Project layout

```
client/            index.html · style.css · script.js        (no build step, no CDN)
server/
  server.js        Express app, helmet CSP, rate limits, central JSON error handler
  config.js        ports, timeouts, SSRF switch
  routes/          scan.js · phishing.js · network.js · history.js
  services/        securityScanner.js  (DNS, TLS, headers, redirects)
                   urlSafety.js        (URL validation + SSRF guard + DNS pinning)
                   urlIndicators.js    (phishing/URL heuristics)
                   scoring.js          (findings -> score -> recommendations)
                   whois.js            (RDAP domain registration data)
                   networkInfo.js      (IP / ISP / ASN / geo, timeout + cache)
                   phishing.js         (CSV dataset loader + matcher)
                   store.js            (JSON-file persistence)
  data/malicious_phish.csv   <- SAMPLE ONLY, replace with the full dataset (columns: url,type)
tests/
```

## API (all responses are JSON with `success: true|false`)

| Method | Path | Body | Notes |
|---|---|---|---|
| GET | `/api/health` | – | server + dataset status |
| POST | `/api/scan` | `{ "url": "example.com" }` | 15 req/min/IP, 22 s hard limit |
| POST | `/api/phishing` | `{ "url": "..." }` | string analysis only, nothing is fetched |
| GET | `/api/network` | – | answers within ~4 s, partial data if lookup fails |
| GET / DELETE | `/api/history` | – | per-browser history via `X-Client-Id` header |

Errors: `{ "success": false, "error": { "code": "INVALID_URL", "message": "..." } }`

## Using the real phishing dataset
Download `malicious_phish.csv` (columns `url,type`; types `benign|phishing|malware|defacement`) and overwrite
`server/data/malicious_phish.csv`, or point `PHISH_CSV=/path/file.csv` at it. ~650k rows load in a few seconds and use roughly 100–150 MB RAM.

## Security notes
- The scanner refuses loopback/private/link-local/metadata addresses (SSRF), re-checks every redirect hop and pins the validated IP for the connection.
  `ALLOW_PRIVATE_TARGETS=1` disables this and exists **only for the test-suite**.
- Passwords are checked/generated in the browser only and never sent to the server.
- Scanned data is untrusted and rendered with `textContent` (no `innerHTML`); a strict CSP forbids inline scripts.
- The network lookup sends the visitor's IP to ipwho.is / ipapi.co. Mention this in any public deployment.
- Password strength is an entropy *estimate* plus a small common-word list – not a substitute for a breach database or zxcvbn.
- History is stored in `server/data/history.json` (anonymous, keyed by a random browser id). Use a real database if you add accounts or need multi-instance hosting.
