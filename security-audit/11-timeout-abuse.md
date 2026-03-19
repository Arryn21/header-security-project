# Attack 11 — Function Timeout Abuse

## Status: HANDLED — platform limits apply

## Description
If a target URL intentionally responds slowly (or never responds), can the scan function hang indefinitely and waste resources?

## Evidence
```bash
POST /scan {"url":"https://httpbin.org/delay/15"}
→ {"error":true,"errorMessage":"Could not connect..."}
# Returned after ~10 seconds (Netlify function timeout enforced)
```

The scan function uses `AbortSignal.timeout(8000)` — an 8-second timeout on the fetch. If the fetch doesn't complete in 8 seconds, it's aborted and the function returns an error.

Netlify also enforces a 10-second hard function timeout on the free tier (26 seconds on paid).

## Attack Steps

### Step 1 — Slow-response server
```python
# Server that accepts connection but never sends headers
import socket, time
s = socket.socket()
s.bind(('0.0.0.0', 80))
s.listen(5)
while True:
    conn, _ = s.accept()
    time.sleep(300)  # hold connection open for 5 minutes
    conn.close()
```

### Step 2 — Submit the hanging URL
```bash
POST /scan {"url":"http://slow-server.evil.com"}
```

### Step 3 — What happens
- `fetch()` connects to `slow-server.evil.com`
- Server accepts TCP connection, never sends HTTP headers
- After 8 seconds, `AbortSignal.timeout(8000)` fires
- `fetch()` throws `AbortError`
- Error handler catches it, returns `{"error": true, ...}`
- Total function execution: ~8 seconds + overhead
- Netlify bills by execution time (free tier: 125k req + 100 hours/month)

At scale (combined with no rate limiting): 100 concurrent slow requests × 8 seconds each = consuming 800 function-execution-seconds at once. With free tier (100 hours/month = 360,000 seconds), this is manageable but wastes quota.

## Severity: LOW (8s timeout is reasonable, platform limits apply)

## What's in place
- `AbortSignal.timeout(8000)` in scan.js — 8 second fetch timeout
- Netlify 10-second hard function timeout
- Free tier quota limits natural abuse ceiling

## Recommended improvement
Reduce fetch timeout from 8s to 5s to cut wasted execution time per slow-URL request:
```js
// In scan.js:
signal: AbortSignal.timeout(5000)  // was 8000
```

This is a minor optimization. More impactful: fix rate limiting (Attack 05).
