# Attack 08 — Response Header Disclosure

## Status: MEDIUM — partial fix available

## Description
Our server's HTTP responses expose information about the underlying infrastructure, which helps attackers fingerprint the platform and plan targeted attacks.

## Evidence
```
HTTP/1.1 200 OK
Server: Netlify                          ← platform disclosure
X-Nf-Request-Id: 01KKE249G40GFX2QJ28JZPAWQS  ← internal request ID
```

## What these reveal

### `Server: Netlify`
- Confirms the site runs on Netlify serverless
- Attacker knows:
  - Function execution limits (10s, 128MB free tier)
  - That functions are Node.js (CommonJS)
  - Known Netlify-specific attack vectors (function URL path traversal history, known CVEs)
  - That there's no WAF by default on free tier

### `X-Nf-Request-Id`
- Netlify's internal request tracing ID
- Format: timestamp + unique ID (e.g., `01KKE249G40GFX2QJ28JZPAWQS`)
- Could theoretically be used to correlate requests in support tickets / abuse reports
- Leaks approximate request timing information

## Severity: MEDIUM (informational leakage, not directly exploitable)

## Attack Flow
1. Attacker scans target site with our scanner
2. Notices `Server: Netlify` in our response headers
3. Searches NVD/GitHub for "Netlify functions CVE" or "Netlify bypass"
4. Targets known Netlify-specific issues (e.g. redirect bypass, function cold start race conditions)

## What to fix

### Option A — Netlify `_headers` file (recommended)
Create `public/_headers` or `netlify/_headers` to override headers:
```
/*
  Server:
  X-Nf-Request-Id:
```
**Note**: Netlify's CDN injects `Server: Netlify` — this header cannot be removed via `_headers` file. It's injected at the edge, not controllable by the site owner on free tier.

### Option B — Accept it (pragmatic)
`Server: Netlify` is widely known and expected. The real risk from this disclosure is low because:
- Netlify is a reputable, well-maintained platform
- The platform-level CVE risk is Netlify's responsibility to patch
- Focus efforts on fixing the HIGH severity issues (CORS, rate limiting, clickjacking) first

### What we CAN fix
The other missing security headers (CSP, X-Frame-Options, etc.) are controllable via `_headers` file. Fixing those is more impactful than suppressing `Server: Netlify`.

## Our own site scores
Our site's response is missing:
- `Content-Security-Policy` ← HIGH
- `X-Frame-Options` ← HIGH
- `X-Content-Type-Options` ← MEDIUM
- `Referrer-Policy` ← LOW
- `Permissions-Policy` ← LOW

See [13-own-headers.md](13-own-headers.md) for the complete fix.
