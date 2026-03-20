# SecureHeaders Scanner — Security Hardening Summary

**Site:** https://header-security-project.pages.dev
**Period:** 2026-03-19 to 2026-03-20
**Process:** 3 rounds of penetration testing with full remediation

---

## Journey at a Glance

```
Round 1 → Round 2 → Round 3 → Final
  10        14         4         0
findings  findings  findings  findings
```

**28 total vulnerabilities found and resolved.**

---

## All Findings — Complete Table

| ID | Severity | Finding | Round | Status |
|----|----------|---------|-------|--------|
| F-01 | Critical | SSRF — server used as proxy to internal IPs | R1 | ✅ Fixed |
| F-02 | High | No rate limiting on any endpoint | R1 | ✅ Fixed |
| F-03 | High | Wildcard CORS on all API endpoints | R1 | ✅ Fixed |
| F-04 | Medium | Missing HSTS header | R1 | ✅ Fixed |
| F-05 | Medium | URL scheme bypass (file://, ftp://) | R1 | ✅ Fixed |
| F-06 | Medium | No URL length validation | R1 | ✅ Fixed |
| F-07 | Low | Dev architecture (n8n URLs) in app.js | R1 | ✅ Fixed |
| F-08 | Low | CSP img-src allows any HTTPS origin | R1 | ✅ Fixed |
| F-09 | Info | Missing security.txt | R1 | ✅ Fixed |
| F-10 | Info | Server: cloudflare header | R1 | N/A (platform) |
| V-01 | Critical | Reflected XSS in monitor unsubscribe page | R2 | ✅ Fixed |
| V-02 | Critical | SSRF — 6 new bypass techniques | R2 | ✅ Fixed |
| V-03 | High | HTML injection in email templates | R2 | ✅ Fixed |
| V-04 | High | Rate limiting fail-open (multiple bugs) | R2 | ✅ Fixed |
| V-05 | High | Wildcard CORS still on scan.js/subscan.js | R2 | ✅ Fixed |
| V-06 | Medium | CSRF via text/plain simple request | R2 | ✅ Fixed |
| V-07 | Medium | Unauthenticated unsubscribe (IDOR) | R2 | ✅ Fixed |
| V-08 | Medium | env_global mutable global state in monitor.js | R2 | ✅ Fixed |
| V-09 | Low | n8n allowUnauthorizedCerts: true | R2 | ✅ Fixed |
| V-10 | Low | URL scheme bypass (persisted from R1) | R2 | ✅ Fixed |
| V-11 | Low | app.js unminified | R2 | ✅ Fixed |
| V-12 | Info | CORS trailing slash in SITE_URL | R2 | ✅ Fixed |
| F3-01 | High | SSRF in monitor.js quickScan() (missed in R2) | R3 | ✅ Fixed |
| F3-02 | High | Rate limiting non-functional (wrong token) | R3 | ✅ Fixed |
| F3-03 | Low | Unhandled crash leaks error code 1101 | R3 | ✅ Fixed |
| F3-04 | Low | API responses missing X-Content-Type-Options | R3 | ✅ Fixed |
| RL-1 | — | Rate limit catch block fail-open | Debug | ✅ Fixed |
| RL-2 | — | Rate limit count==null treated as allowed | Debug | ✅ Fixed |

---

## Key Changes Made

### SSRF Protection
- `isAllowedUrl()` blocks all bare IP hostnames — covers loopback, private ranges, IPv6, and all encoding variants (decimal, octal, hex) via `URL().hostname` normalisation
- `redirect: 'manual'` with per-hop validation blocks open-redirect chain bypass
- Applied to `scan.js`, `subscan.js`, and `monitor.js`

### Rate Limiting
- Upstash Redis pipeline API (POST, key in JSON body — no URL encoding issues)
- Fail-closed: missing env vars → 429, Redis error → 429, non-numeric count → 429
- Limits: scan 20/min, subscan 5/min, explain 5/min, monitor-subscribe 3/10min
- Root cause of months of non-function: wrong token type in Cloudflare (Redis password vs REST token)

### Input Validation
- `typeof url !== 'string'` guards on all inputs across all workers
- Content-Type enforcement: `application/json` required on all POST handlers
- URL max length: 2048 characters

### Authentication & Access Control
- HMAC-SHA-256 signed unsubscribe tokens (replaces guessable email+url parameters)
- CORS restricted to own domain on all 5 API workers

### Output Encoding
- `escHtml()` applied to all user-supplied values in HTML responses and email templates

### Infrastructure
- `env_global` mutable global removed — `env` passed explicitly through call chain
- `X-Content-Type-Options: nosniff` on all API responses
- app.js minified (27,913 bytes, was 38,016)
- security.txt created

---

## Before vs After

| Category | Before | After |
|----------|--------|-------|
| SSRF | Open to all IPs + all encoding bypasses | Blocked across 12 tested techniques |
| Rate Limiting | Unlimited (non-functional) | 20 req/min enforced, verified PASS |
| CORS | Wildcard * on all endpoints | Restricted to own domain |
| XSS | Confirmed exploitable in browser | Blocked |
| CSRF | Exploitable via text/plain | Blocked (415 for non-JSON) |
| IDOR | Unsubscribe by guessing email+url | HMAC token required |
| Input Types | Crashes on non-string (leaks 1101) | Type-guarded, 400 returned |
| app.js | Full source, architecture exposed | Minified |
| Email templates | HTML injectable | escHtml() applied |
| security.txt | Missing | Present |
| HSTS | Missing | max-age=31536000; preload |

---

## What Was NOT Vulnerable (Confirmed in Round 3)

27 additional attack vectors were tested and confirmed mitigated: HTTP smuggling, cache poisoning, CORS null/subdomain variants, HMAC timing attacks, prompt injection, open redirects, hidden endpoints, JSON parameter pollution, email header injection (CRLF), Unicode homograph domains, and more.

---

## Remaining Known Limitation

**DNS Rebinding:** Cannot be fully mitigated in Cloudflare Workers — there is no pre-fetch DNS resolution API to verify the resolved IP before the request is made. Mitigated in practice by Cloudflare's network-level protections and the bare-IP rejection in `isAllowedUrl()`.

---

*Full technical details: SECURITY_REMEDIATION_LOG.md*
*Pentest reports: pentest_report_v1/v2/v3_header-security-project.md*
