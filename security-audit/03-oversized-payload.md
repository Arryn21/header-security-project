# Attack 03 — Oversized Payload / Memory Exhaustion

## Status: HANDLED (Netlify limits apply)

## Description
Attacker sends an extremely large JSON body to exhaust function memory or cause a timeout, either for DoS or to trigger an error that leaks stack traces.

## Attack Steps

### Step 1 — Send large URL string
```bash
python -c "print('A'*100000)" | curl -X POST .../scan \
  -H "Content-Type: application/json" \
  -d "{\"url\":\"https://$(python -c 'print(\"a\"*100000)').com\"}"
```

### Step 2 — Send deeply nested JSON
```json
{"url": {"nested": {"deeply": {"very": "deep"}}}}
```

### Step 3 — Send array bomb
```json
{"url": ["a","b","c",...10000 items]}
```

## Test Results

All oversized/malformed payloads returned `error: true` with a clean error message. No stack traces, no memory errors exposed.

Netlify functions have a hard limit:
- Request body: 6 MB max
- Execution time: 10 seconds max
- Memory: 1024 MB max (free tier: 128 MB)

The function handles `JSON.parse` errors gracefully via try/catch at the handler level.

## Severity: LOW (Netlify platform limits handle this)

## What to fix
Nothing required for oversized payloads. However, consider adding explicit body size check:

```js
// Optional defensive check in handler
if (event.body && event.body.length > 50000) {
  return { statusCode: 413, headers: cors, body: JSON.stringify({ error: 'Request too large' }) };
}
```

## Notes
The real DoS risk is **rate limiting** (Attack 05), not payload size. An attacker sending thousands of small, valid scan requests is more dangerous than one large request.
