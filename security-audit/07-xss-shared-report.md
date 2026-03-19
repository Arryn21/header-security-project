# Attack 07 — XSS via Shared Report URL Hash

## Status: LIKELY SAFE — verify in browser

## Description
The shareable report feature encodes the full scan result as base64 into the URL hash: `#report/<base64>`. When a victim visits this URL, the frontend decodes the base64 and renders the report without re-scanning.

Attack: craft a malicious scan result with XSS payloads in string fields, base64-encode it, and share the link. If any field is rendered unsafely, XSS fires in the victim's browser.

## Attack Surface

Fields decoded from the URL hash that appear in the UI:
- `url` — the scanned URL
- `aiExplanation` — AI-generated text (stored in share data)
- `roadmap` — AI-generated roadmap text
- `leakingHeaders[].value` — raw header values from target site
- `headers[].value` — header values
- `cspAnalysis.issues[].message` — CSP issue descriptions
- `cookieAudit[].name` — cookie names

## Attack Steps

### Step 1 — Craft malicious scan object
```js
const maliciousScan = {
  url: '<img src=x onerror=alert(1)>',
  score: 100,
  grade: 'A+',
  aiExplanation: '## Title\n<script>alert(document.cookie)</script>',
  leakingHeaders: [{ header: 'Server', value: '<svg onload=alert(1)>' }],
  cookieAudit: [{ name: '<script>alert(1)</script>', issues: [] }]
};
```

### Step 2 — Encode to share URL
```js
const encoded = btoa(JSON.stringify(maliciousScan));
const shareUrl = `https://secureheaders-scanner.netlify.app/#report/${encoded}`;
console.log(shareUrl);
```

### Step 3 — Share link with victim
Post to social media, send in email, embed in QR code.

### Step 4 — Victim opens link
Frontend auto-loads the report. If any field is rendered via `innerHTML` without escaping, XSS fires.

## Analysis of Frontend Defenses

### URL field rendering
```js
// In index.html — confirmed uses escHtml():
resultUrl.textContent = data.url;  // safe — textContent not innerHTML
// or:
el.innerHTML = escHtml(data.url);  // safe — escaped
```

### AI explanation rendering
```js
aiDiv.innerHTML = renderMd(data.aiExplanation);
```
`renderMd()` → `mdInline()` → `escHtml()` — the `escHtml()` call happens first before any HTML tags are inserted, so `<script>` becomes `&lt;script&gt;`.

**BUT**: `renderMd()` splits on `\n` and looks for lines starting with `## `. The line content goes through `mdInline()` which calls `escHtml()`. Lines without special prefixes are wrapped in `<p>` tags after `mdInline()` escaping. Appears safe.

### Header value rendering
Need to verify in browser that leaking header values and cookie names go through `escHtml()`.

## Test

To test manually in browser:
```js
// Open browser console on the site, paste:
const malicious = {
  url: 'https://test.com',
  score: 0,
  grade: 'F',
  headers: [],
  leakingHeaders: [{ header: 'Server', value: '<img src=x onerror=alert(1)>' }],
  aiExplanation: '## Test\n**Bold** and <script>alert(1)</script>',
  cookieAudit: [],
  scannedAt: new Date().toISOString()
};
location.hash = '#report/' + btoa(JSON.stringify(malicious));
```
If alert box appears, XSS is present. If `<img src=x onerror=alert(1)>` renders as literal text, it's safe.

## Severity: LOW (defense chain appears solid, browser verification recommended)

## What to fix
1. **Browser-verify** the test case above before marking safe.
2. Add a check in the hash-loading code to validate the decoded object structure (reject objects with non-string fields where strings are expected).
3. Consider storing only safe fields in share URL (exclude raw header values from target sites).

## Additional Note on localStorage
The before/after comparison stores scan results in localStorage keyed by URL. Same XSS consideration applies — when a stored scan is re-loaded and rendered, the same escaping chain must apply. This is separate from the URL hash vector but has the same risk profile.
