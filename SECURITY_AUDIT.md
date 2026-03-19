# Security Audit — SecureHeaders Scanner
## Site: https://secureheaders-scanner.netlify.app

Audit date: 2026-03-11
Auditor: Internal (self-audit)

---

## Progress Tracker

| # | Attack Vector | Status | Severity | Fixed |
|---|--------------|--------|----------|-------|
| 1 | SSRF via scan function | [x] | BLOCKED | N/A — platform blocks it |
| 2 | XSS via malicious URL in scan | [x] | MEDIUM | [x] URL validation added to scan.js |
| 3 | Oversized payload / DoS | [x] | LOW | N/A — Netlify platform limits |
| 4 | CORS wildcard on all API endpoints | [x] | HIGH | [x] Restricted to own domain in all 5 functions |
| 5 | Rate limiting absent | [x] | HIGH | [x] Redis rate limit: 5/min explain, 20/min scan, 5/min subscan |
| 6 | Monitor endpoint auth bypass | [x] | PROTECTED | N/A — MONITOR_SECRET protects it |
| 7 | XSS via shared report URL hash | [x] | LOW | [x] escHtml() chain + URL validation reduces injection surface |
| 8 | Response header disclosure | [x] | MEDIUM | [~] Server: Netlify cannot be removed (platform-injected) |
| 9 | Clickjacking | [x] | HIGH | [x] X-Frame-Options: DENY + frame-ancestors: none |
| 10 | Redirect chain abuse | [x] | LOW | N/A — Node fetch caps at 20 redirects |
| 11 | Function timeout abuse | [x] | LOW | N/A — 8s AbortSignal timeout in scan.js |
| 12 | Information disclosure in errors | [x] | LOW | [x] e.message replaced with generic messages in monitor.js |
| 13 | Site missing own security headers | [x] | HIGH | [x] All 6 headers via _headers — F → A+ (90/100) |

---

## Summary of Findings

### Critical / High
- **CORS Wildcard**: Every API endpoint returns `Access-Control-Allow-Origin: *`. Any website on the internet can silently call our scan/monitor/explain APIs from a visitor's browser using their IP and cookies.
- **No Rate Limiting**: 10 API calls completed in 2.7s without throttling. API key costs can be run up by any attacker. Claude API bill can be abused.
- **Clickjacking**: Site has no `X-Frame-Options` or CSP `frame-ancestors`. Can be embedded in an attacker's iframe to perform UI redress attacks.
- **Site scores F on its own scanner**: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy all missing from our own frontend.

### Medium
- **XSS via URL echo**: Scan API echoes back malicious URLs (e.g. `<script>` tags) in JSON response. Frontend must escape these — currently does via `escHtml()`, but any future rendering path that bypasses escaping is vulnerable.
- **Response header leakage**: `Server: Netlify` and `X-Nf-Request-Id` exposed in every response, confirming platform and exposing internal request IDs.

### Low / Informational
- **XSS via shared report**: `aiExplanation` from Claude is stored in base64 URL hash, then rendered via `renderMd()` → `mdInline()` → `escHtml()`. Chain looks safe but is complex.
- **Redirect chain**: Scanner follows unlimited redirects via `redirect: 'follow'` — attacker-controlled server could send 30+ redirects to waste function execution time.
- **Error messages**: Generic, no stack traces leaked. Good.
- **Monitor auth**: `/monitor` check endpoint properly returns 401 without valid secret. Good.
- **SSRF**: Blocked by Netlify's serverless runtime. Internal metadata endpoints (169.254.x.x) unreachable. Good.

---

## Detailed Files

Each attack has its own detailed file in `security-audit/`:

- [01-ssrf.md](security-audit/01-ssrf.md)
- [02-xss-url.md](security-audit/02-xss-url.md)
- [03-oversized-payload.md](security-audit/03-oversized-payload.md)
- [04-cors-wildcard.md](security-audit/04-cors-wildcard.md)
- [05-rate-limiting.md](security-audit/05-rate-limiting.md)
- [06-monitor-auth.md](security-audit/06-monitor-auth.md)
- [07-xss-shared-report.md](security-audit/07-xss-shared-report.md)
- [08-response-headers.md](security-audit/08-response-headers.md)
- [09-clickjacking.md](security-audit/09-clickjacking.md)
- [10-redirect-chain.md](security-audit/10-redirect-chain.md)
- [11-timeout-abuse.md](security-audit/11-timeout-abuse.md)
- [12-error-disclosure.md](security-audit/12-error-disclosure.md)
- [13-own-headers.md](security-audit/13-own-headers.md)

---

## Remediation Status — All Done

### Completed fixes (deployed 2026-03-11)

| Fix | Files changed | Result |
|-----|--------------|--------|
| Security headers on frontend | `public/_headers` (new) | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy added |
| CORS restricted | all 5 `netlify/functions/*.js` | `Access-Control-Allow-Origin: *` → own domain only |
| Rate limiting | `scan.js`, `explain.js`, `subscan.js`, `monitor.js` | IP-based Redis counter: 5/min (explain), 20/min (scan), 5/min (subscan), 3/10min (monitor-subscribe) |
| URL validation | `scan.js` | Rejects non-http/https URLs before fetching |
| Error disclosure | `monitor.js` | Replaced `e.message` with generic error messages |
| CSP `unsafe-inline` removed | `public/index.html`, `public/styles.css` (new), `public/app.js` (new) | Inline CSS/JS extracted to external files; CSP now has no unsafe directives |
| Email validation | `monitor.js` | Validates email format before subscribing |

### Final site score
- Before audit: **F (10/100)**
- After all fixes: **A+ (90/100)**
- Remaining -10: `Server: Netlify` header — injected by Netlify CDN, not removable on free plan

### Not fixable
- `Server: Netlify` header disclosure (#8) — Netlify edge injects this regardless of `_headers` file on free tier
