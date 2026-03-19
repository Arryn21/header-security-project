# Attack 05 — No Rate Limiting

## Status: VULNERABLE — fix required

## Description
None of our Netlify functions implement any rate limiting. An attacker can send unlimited requests to:
- **scan.js**: Make our server fetch any URL thousands of times per second (our server used as a proxy/crawler)
- **explain.js**: Burn our Claude API credits at ~$0.0025 per call (Haiku pricing) — 1000 calls = $2.50, easy to automate
- **monitor.js subscribe**: Flood Upstash Redis with fake subscriptions, exhaust free tier storage
- **subscan.js**: Trigger 12 parallel outbound HTTP requests per call — amplification factor 12x

## Evidence
```
10 requests completed in 2.7 seconds — no 429, no slowdown
```

## Attack Steps

### Step 1 — Basic flood
```bash
# 50 parallel Claude API calls
for i in $(seq 1 50); do
  curl -s -X POST https://secureheaders-scanner.netlify.app/.netlify/functions/explain \
    -H "Content-Type: application/json" \
    -d '{"url":"https://example.com","score":50,"grade":"C","mode":"roadmap"}' &
done
wait
```

### Step 2 — Automated credit exhaustion script
```python
import concurrent.futures, requests
URL = 'https://secureheaders-scanner.netlify.app/.netlify/functions/explain'

def burn():
    requests.post(URL, json={'url':'https://example.com','score':0,'grade':'F','mode':'roadmap'})

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    ex.map(lambda _: burn(), range(500))
# ~500 Claude API calls in ~30 seconds
```

### Step 3 — Subscan amplification
```bash
# 1 call to subscan = 12 outbound requests from Netlify servers
# 100 calls = 1200 outbound requests
for i in $(seq 1 100); do
  curl -s -X POST .../subscan -d '{"domain":"target.com"}' &
done
```

## Severity: HIGH

## Financial Impact
- Claude Haiku: ~$0.0025/call for 700-token response
- 10,000 calls = ~$25 in API costs
- Upstash Redis free tier: 10,000 commands/day — 1000 fake subscriptions exhausts this

## What to fix

### Option A — Upstash Redis rate limiter (recommended, reuses existing infrastructure)

Add to `explain.js` (and optionally `scan.js`):
```js
async function checkRateLimit(ip) {
  const url   = process.env.UPSTASH_REDIS_URL;
  const token = process.env.UPSTASH_REDIS_TOKEN;
  if (!url || !token) return true; // fail open if not configured

  const key = `rl:${ip}`;
  const res = await fetch(`${url}/incr/${encodeURIComponent(key)}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await res.json();
  const count = data.result;

  if (count === 1) {
    // Set 60-second expiry on first request
    await fetch(`${url}/expire/${encodeURIComponent(key)}/60`, {
      headers: { Authorization: `Bearer ${token}` }
    });
  }

  return count <= 10; // allow 10 requests per IP per 60 seconds
}

// In handler, before processing:
const ip = event.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';
const allowed = await checkRateLimit(ip);
if (!allowed) {
  return { statusCode: 429, headers: { ...cors, 'Retry-After': '60' },
           body: JSON.stringify({ error: 'Rate limit exceeded. Try again in 60 seconds.' }) };
}
```

### Option B — Netlify Edge Functions (zero cost, no Redis)
Create `netlify/edge-functions/rate-limit.js` with Deno's built-in rate limiting.
More complex but doesn't consume Redis commands.

### Minimum viable fix
Apply rate limiting only to `explain.js` (Claude API cost vector) as highest priority.
Set limit: 10 requests/IP/minute for explain, 30 requests/IP/minute for scan.
