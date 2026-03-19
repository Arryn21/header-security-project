# Attack 13 — Our Site Missing Its Own Security Headers

## Status: VULNERABLE — fix required

## Description
Our security header scanner gives other sites an F grade for missing headers. Our own site has an F grade. This is both a security issue and a credibility problem — users scanning our own URL would see it fail.

## Current State
```
curl -sI https://secureheaders-scanner.netlify.app

HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload  ✓
Server: Netlify                                                           ✗ (leaks)
X-Nf-Request-Id: ...                                                      ✗ (leaks)
# Missing:
# Content-Security-Policy                                                 ✗
# X-Frame-Options                                                         ✗
# X-Content-Type-Options                                                  ✗
# Referrer-Policy                                                         ✗
# Permissions-Policy                                                      ✗
```

Scanning `https://secureheaders-scanner.netlify.app` with our own tool:
- Score: 10/100 (only HSTS passes — 20 pts)
- Penalty: -10 (Server: Netlify leaking)
- Final: 10/100, Grade: F

## Impact of missing headers

### No `X-Frame-Options`
Site can be embedded in iframes → clickjacking (Attack 09)

### No `Content-Security-Policy`
- No restriction on where scripts can load from
- If an attacker injects a script (via XSS), it can load from any domain
- No protection against data exfiltration via `connect-src`

### No `X-Content-Type-Options`
Browser may MIME-sniff responses. If an attacker finds a way to serve content on our domain (e.g. via a redirect to a data: URL), the browser might interpret it as a different content type.

### No `Referrer-Policy`
When users click links from our site, the full URL (including any sensitive query params) is sent to external sites as the `Referer` header.

### No `Permissions-Policy`
Browser features (camera, microphone, geolocation) not restricted. If XSS occurs, attacker code could request camera access.

## Fix — Create `netlify/_headers`

Create the file `netlify/_headers` (Netlify applies these automatically on all responses):

```
/*
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://secureheaders-scanner.netlify.app; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'

/.netlify/functions/*
  Access-Control-Allow-Origin: https://secureheaders-scanner.netlify.app
  Access-Control-Allow-Methods: POST, GET, OPTIONS
  Access-Control-Allow-Headers: Content-Type
  Vary: Origin
```

### CSP notes
- `'unsafe-inline'` for `script-src` and `style-src` — needed because `public/index.html` uses inline `<script>` and `<style>` blocks. This reduces CSP effectiveness but is necessary unless scripts are moved to external files.
- `connect-src 'self' https://secureheaders-scanner.netlify.app` — allows the frontend's fetch calls to our own functions.
- `img-src data: https:` — needed for any image URLs referenced in results (favicon URLs etc.)

### Ideal CSP (after refactoring)
After moving all JS to `public/app.js` and all CSS to `public/styles.css`:
```
Content-Security-Policy: default-src 'self'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'
```
This removes `unsafe-inline` and gets a CSP grade of A.

## Expected result after fix
Scanning our own URL:
- Before: 10/100, Grade F
- After: 90/100+, Grade A (all 6 headers present, leakage penalty reduced)

## Deploy
The `netlify/_headers` file is included in the deploy zip if added to the files manifest in `deploy_netlify.py`. Add it to the `FILES` dict in deploy_netlify.py:
```python
'_headers': 'netlify/_headers',
```
