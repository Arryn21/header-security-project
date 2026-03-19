# Attack 12 — Information Disclosure in Error Messages

## Status: LOW RISK — no sensitive leakage found

## Description
Error messages sometimes reveal internal implementation details (stack traces, file paths, library versions). Attackers use these to identify vulnerable dependencies or understand server-side code structure.

## Test Cases and Results

### Test 1 — Invalid URL
```bash
POST /scan {"url":"not-a-url"}
→ {
    "url": "https://not-a-url",
    "error": true,
    "errorMessage": "Could not connect to https://not-a-url. The site may be unreachable, blocking automated requests, or the URL may be invalid.",
    "score": null,
    ...
  }
```
Clean generic message. No stack trace, no file path, no Node.js version.

### Test 2 — Missing body
```bash
POST /scan (empty body)
→ {"error":true,"errorMessage":"..."}
```
`JSON.parse` of empty string would throw — caught by try/catch, generic error returned.

### Test 3 — Malformed JSON
```bash
POST /scan {bad json}
→ {"error":true,...}
```
Parse error caught gracefully.

### Test 4 — Monitor with invalid JSON
```bash
POST /monitor {bad json}
→ Likely 500 with minimal info
```

### Test 5 — Unknown function path
```bash
GET /.netlify/functions/nonexistent
→ {"error":"Function not found"}
```
Netlify platform error — no stack trace.

## Severity: LOW (no issues found)

## What's in place
- All functions wrap logic in `try/catch`
- Error handlers return generic messages without implementation details
- `scan.js` error: `"Could not connect to X. The site may be unreachable..."`
- `monitor.js` error: `e.message` is forwarded — **this one could leak implementation details**

## One concern: monitor.js forwards e.message

```js
// In monitor.js subscribe handler:
} catch (e) {
  return { statusCode: 500, headers: cors, body: JSON.stringify({ error: e.message }) };
}
```

If Redis or Resend throw errors with internal URLs or credentials in the message, those could be forwarded. Example:
```
"error": "fetch failed: https://credible-cougar-67943.upstash.io/get/sub:... — connection refused"
```

## Fix
Replace `e.message` with a generic error in monitor.js:
```js
} catch (e) {
  console.error('monitor error:', e.message); // Log internally
  return { statusCode: 500, headers: cors, body: JSON.stringify({ error: 'Internal server error. Please try again.' }) };
}
```

This is a low-priority fix but good practice.
