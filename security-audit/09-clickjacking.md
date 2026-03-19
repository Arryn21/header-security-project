# Attack 09 — Clickjacking (UI Redress Attack)

## Status: VULNERABLE — fix required

## Description
Our site has no `X-Frame-Options` header and no CSP `frame-ancestors` directive. This means any website can embed our scanner in a hidden `<iframe>` and overlay it with a transparent attacker-controlled layer to trick users into performing actions they didn't intend.

## Evidence
```bash
curl -sI https://secureheaders-scanner.netlify.app | grep -i "x-frame\|frame-ancestors"
# → (no output — header absent)
```

## Attack Steps

### Attack Scenario 1 — Steal scanned URL (reconnaissance)
The attacker wants to know what URLs security teams are scanning. They create:

```html
<!-- evil.com/spy.html -->
<style>
  iframe { opacity: 0.01; position: absolute; top: 0; left: 0; width: 100%; height: 100%; z-index: 2; }
  .overlay { position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); z-index: 1; }
</style>
<div class="overlay">
  <h2>Free Security Check</h2>
  <p>Enter your company's website URL and click "Scan Now"</p>
</div>
<iframe src="https://secureheaders-scanner.netlify.app"></iframe>
```

User thinks they're clicking an innocent "scan" button — they're actually typing their company URL into our scanner and clicking "Scan Now". The attacker's page can't read the results directly, but this reveals that a specific company URL was scanned to network-layer observers.

### Attack Scenario 2 — Subscribe victim to monitoring
More targeted: overlay the email subscription form.

```html
<style>
  iframe {
    opacity: 0.01;
    position: fixed;
    top: -800px;   /* position iframe so email field aligns with attacker's "Subscribe" button */
    left: -200px;
    width: 1400px;
    height: 2000px;
    z-index: 999;
  }
</style>
<iframe src="https://secureheaders-scanner.netlify.app"></iframe>
<div style="position:fixed;top:300px;left:300px;z-index:1;">
  <input type="email" placeholder="Enter your email for free security tips">
  <button>Subscribe to Newsletter</button>
</div>
```

User enters their email in what appears to be attacker's newsletter form. Actually types into our monitor subscription box. Now receives weekly security alerts they didn't intend to sign up for, from our domain — looks like spam.

### Attack Scenario 3 — UI confusion on mobile
On mobile, clickjacking is particularly effective. Attacker serves a game or survey, positions our site's "Scan" button exactly where the game's play button appears.

## Severity: HIGH

**Why HIGH despite being "just" UI manipulation:**
- Our scan button triggers server-side HTTP requests to third-party URLs — an attacker can use this to make scans originate from Netlify's IPs (a form of indirect SSRF)
- Email subscription abuse (GDPR violation)
- Reputation damage if our domain sends unsolicited emails

## What to fix

### Fix 1 — Add `X-Frame-Options` header via `netlify/_headers`

Create or edit `netlify/_headers`:
```
/*
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=()
```

`DENY` prevents all framing. Use `SAMEORIGIN` if you ever need to frame the site from your own domain.

### Fix 2 — Add CSP `frame-ancestors` (modern equivalent)
CSP `frame-ancestors` supersedes `X-Frame-Options` in modern browsers. Both can coexist:

```
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; ...
```

### Which to apply where
- `netlify/_headers` → applies to frontend HTML
- API functions return their own headers — no framing protection needed there (APIs aren't framed)

## Test after fix
```bash
curl -sI https://secureheaders-scanner.netlify.app | grep -i "x-frame"
# Should show: x-frame-options: DENY
```

Also run our own scanner on our own URL — it should report X-Frame-Options as PRESENT.
