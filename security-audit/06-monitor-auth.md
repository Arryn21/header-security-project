# Attack 06 — Monitor Endpoint Auth Bypass

## Status: PROTECTED

## Description
The `/monitor` function has a `check` action that triggers security scans for all subscribers and sends alert emails. If unprotected, an attacker could trigger mass email sending, exhausting the Resend free tier or spamming all subscribers.

## Attack Steps

### Step 1 — Call check without secret
```bash
curl -X POST https://secureheaders-scanner.netlify.app/.netlify/functions/monitor \
  -H "Content-Type: application/json" \
  -d '{"action":"check"}'
```

### Step 2 — Try common secrets
```bash
for secret in "secret" "admin" "password" "monitor" "test" ""; do
  curl -X POST .../monitor -d "{\"action\":\"check\",\"secret\":\"$secret\"}"
done
```

### Step 3 — Try to enumerate via timing attack
Different response times for valid vs invalid secrets could leak partial secret.

## Test Results

```bash
curl -X POST .../monitor -d '{"action":"check"}'
# → {"error":"Unauthorized"}   HTTP 401
```

Authentication is working correctly. The `MONITOR_SECRET` environment variable is set and validated before any check logic runs.

No timing attack observed — comparison is straightforward string equality, executed before any DB calls.

## Severity: LOW (properly protected)

## What's in place
- `MONITOR_SECRET` env var in Netlify dashboard
- Same secret stored as GitHub Actions secret for the cron workflow
- Returns 401 immediately for wrong/missing secret
- No error detail leaked (just "Unauthorized")

## Recommended improvements (optional)
1. Use constant-time string comparison to prevent timing attacks (minor hardening):
   ```js
   const crypto = require('crypto');
   function safeEqual(a, b) {
     if (a.length !== b.length) return false;
     return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
   }
   // Replace: body.secret !== secret
   // With:    !safeEqual(body.secret || '', secret)
   ```

2. Log failed auth attempts (IP + timestamp) to Redis for monitoring brute-force attempts.
