# SecureHeaders Scanner — Complete Project Documentation

---

## Table of Contents

1. [What This Project Does](#1-what-this-project-does)
2. [How It Works — Big Picture](#2-how-it-works--big-picture)
3. [Tech Stack](#3-tech-stack)
4. [File Structure](#4-file-structure)
5. [Frontend Deep Dive](#5-frontend-deep-dive)
6. [Backend Functions Deep Dive](#6-backend-functions-deep-dive)
7. [Security Headers Explained](#7-security-headers-explained)
8. [Scoring System](#8-scoring-system)
9. [Rate Limiting](#9-rate-limiting)
10. [AI Integration](#10-ai-integration)
11. [Email Monitoring](#11-email-monitoring)
12. [Environment Variables](#12-environment-variables)
13. [Deployment — Cloudflare Pages](#13-deployment--cloudflare-pages)
14. [How Cloudflare Pages Functions Work](#14-how-cloudflare-pages-functions-work)
15. [Common Issues & Fixes](#15-common-issues--fixes)
16. [Project History](#16-project-history)

---

## 1. What This Project Does

SecureHeaders Scanner is a free web tool that lets anyone scan any website's HTTP security headers. You enter a URL, it fetches that URL server-side, reads the response headers, and tells you:

- Which security headers are present or missing
- A security score out of 100
- A letter grade (A+ to F)
- What attacks are possible due to missing headers
- An AI-generated security analysis and remediation plan
- A copy-paste server config to fix everything immediately
- Subdomain scanning (checks 12 common subdomains)
- Cookie security audit
- CORS configuration analysis
- Weekly email alerts if your security grade drops

---

## 2. How It Works — Big Picture

```
User Browser
     |
     | visits https://header-security-project.pages.dev
     v
Cloudflare Pages (Static Site)
     | serves index.html, app.js, styles.css
     |
     | User enters URL, clicks Scan
     |
     | POST /api/scan  { url: "https://target.com" }
     v
Cloudflare Pages Function (functions/api/scan.js)
     |
     | 1. Check rate limit via Upstash Redis
     | 2. Fetch the target URL from Cloudflare's servers
     | 3. Read all response headers
     | 4. Score the headers
     | 5. Return JSON result
     v
app.js receives JSON, renders the UI

     | simultaneously POST /api/explain
     v
functions/api/explain.js
     |
     | Calls Claude AI API
     | Returns AI security analysis
     v
app.js renders the AI text
```

The key insight: the scanning happens **server-side** (in the Cloudflare function), not in your browser. This is important because:
- Some sites block browser requests (CORS) but allow server requests
- Your IP is not exposed to the target site
- You bypass browser security restrictions

---

## 3. Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| Frontend | Vanilla HTML/CSS/JS | No build step, fast, simple |
| Backend | Cloudflare Pages Functions | Serverless, free tier, global edge |
| Rate Limiting | Upstash Redis (REST API) | Serverless-compatible Redis, no npm needed |
| AI Analysis | Anthropic Claude API (Haiku) | Fast, cheap, good at security analysis |
| Email | Resend API | Simple REST API for transactional email |
| Hosting | Cloudflare Pages | Free, fast, deploys from GitHub |

---

## 4. File Structure

```
Header-Security-Project/
│
├── public/                         # Static files served to the browser
│   ├── index.html                  # The entire page structure (HTML only, no inline JS/CSS)
│   ├── app.js                      # All JavaScript for the frontend
│   ├── styles.css                  # All CSS styles
│   └── _headers                    # Security headers for the site itself
│
├── functions/                      # Cloudflare Pages Functions (serverless backend)
│   └── api/
│       ├── scan.js                 # Core: fetches target URL and scores headers
│       ├── config.js               # Generates copy-paste server configs
│       ├── explain.js              # AI analysis via Claude API
│       ├── subscan.js              # Scans 12 subdomains in parallel
│       └── monitor.js              # Email subscription and weekly checks
│
├── netlify/                        # Old Netlify functions (kept for reference)
│   └── functions/
│       ├── scan.js
│       ├── config.js
│       ├── explain.js
│       ├── subscan.js
│       └── monitor.js
│
├── security-audit/                 # Documentation of 13 attack vectors tested
│   ├── 01-ssrf.md
│   ├── 02-xss-url.md
│   └── ... (13 files total)
│
├── .github/
│   └── workflows/
│       └── weekly-monitor.yml      # GitHub Actions cron job for email monitoring
│
├── ROADMAP.md                      # All 15 features (all completed)
├── SECURITY_AUDIT.md               # Security audit results
├── DOCS.md                         # This file
└── netlify.toml                    # Old Netlify config (unused now)
```

---

## 5. Frontend Deep Dive

### index.html
The HTML file is intentionally minimal — it only defines structure. No inline JavaScript, no inline CSS. This was done for **Content Security Policy (CSP) compliance**: if you have JS or CSS inline in your HTML, you need `unsafe-inline` in your CSP, which weakens security.

Key elements:
- `<link rel="stylesheet" href="/styles.css">` — loads external CSS
- `<script src="/app.js">` at the bottom — loads JS after HTML is parsed
- Button `onclick="runScan()"` — calls a global function defined in app.js
- All sections start `style="display:none"` — shown programmatically after scan

### app.js
This file does everything in the browser. Key sections:

**URL Detection (lines 1-5)**
```js
const isLocal = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
const SCAN_URL = isLocal ? 'http://localhost:5678/webhook/scan-headers' : '/api/scan';
```
When running locally, it hits an n8n webhook. In production, it hits `/api/scan` which Cloudflare routes to `functions/api/scan.js`.

**runScan() — the main function**
1. Reads the URL input
2. Disables the scan button (prevents double-clicks)
3. Shows the loading spinner
4. POSTs to `/api/scan` with `{ url: "..." }`
5. Receives JSON with headers, score, grade, etc.
6. Calls `renderResults()` to update the UI
7. Simultaneously calls `/api/explain` for AI analysis
8. Simultaneously calls `/api/config` for the fix config
9. Re-enables the button in a `finally` block (always runs, even on error)

**Share Report feature**
When you click "Copy Link", the entire scan result is JSON-serialized, base64-encoded, and put in the URL hash (`#data=...`). When someone opens that link, the app decodes the hash and renders the result without re-scanning. No database needed.

**Before/After Comparison**
The app stores the last scan result in `localStorage`. If you scan the same URL twice, it shows a diff banner comparing the two scores.

### styles.css
All styling using CSS variables for the dark theme. Key variables:
```css
--bg: #0f1117;         /* Dark background */
--card: #1a1d27;       /* Card background */
--accent: #3b82f6;     /* Blue accent */
--green: #22c55e;      /* Pass indicators */
--red: #ef4444;        /* Fail indicators */
```

### public/_headers
This file tells Cloudflare Pages what HTTP headers to add to every response. It is the security config for the scanner site itself:

```
/*
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
  Content-Security-Policy: default-src 'self'; script-src 'self'; ...
```

- `/*` means: apply to all pages
- `X-Frame-Options: DENY` — nobody can embed this site in an iframe (prevents clickjacking)
- `X-Content-Type-Options: nosniff` — browser must respect declared content types
- `Content-Security-Policy` — only load scripts/styles from same origin (`'self'`)

---

## 6. Backend Functions Deep Dive

### How Cloudflare Pages Functions work
Files in the `functions/` directory automatically become API endpoints:
- `functions/api/scan.js` → `https://yoursite.pages.dev/api/scan`
- `functions/api/config.js` → `https://yoursite.pages.dev/api/config`

Every function exports an `onRequest` handler:
```js
export async function onRequest(context) {
  const { request, env } = context;
  // request = the incoming HTTP request (Web API standard)
  // env = environment variables you set in Cloudflare dashboard
  return new Response("hello", { status: 200 });
}
```

This is different from Netlify Functions which use Node.js-style handlers:
```js
// Netlify (old)
exports.handler = async function(event) {
  return { statusCode: 200, body: "hello" };
}

// Cloudflare Pages (new)
export async function onRequest(context) {
  return new Response("hello", { status: 200 });
}
```

---

### functions/api/scan.js — The Core Scanner

This is the most important file. Here's exactly what it does:

**Step 1: CORS Headers**
```js
const cors = {
  'Access-Control-Allow-Origin': corsOrigin,
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  ...
};
```
CORS headers tell browsers which origins can call this API. Since the frontend and backend are on the same domain (`pages.dev`), technically CORS isn't needed — but it's kept for safety.

**Step 2: Rate Limiting**
```js
const ip = request.headers.get('cf-connecting-ip') || ...;
if (!(await checkRateLimit(ip, 'scan', 20, env))) {
  return new Response(..., { status: 429 });
}
```
Limits each IP to 20 scans per minute. Uses Upstash Redis to store counters. The key is `rl:scan:{ip}:{minute}` — it changes every minute so counters auto-reset.

**Step 3: Fetch the Target**
```js
const response = await fetch(targetUrl, {
  method: 'GET',
  redirect: 'follow',
  signal: AbortSignal.timeout(10000),  // 10 second timeout
  headers: { 'User-Agent': 'Mozilla/5.0 ...' }
});
```
The function fetches the target URL from Cloudflare's servers. `redirect: 'follow'` means it follows redirects (http → https, www → non-www, etc). The 10-second timeout prevents hanging on slow sites.

**Step 4: Extract Headers**
```js
const headers = {};
response.headers.forEach((value, key) => {
  headers[key.toLowerCase()] = value;
});
```
Converts all headers to lowercase for case-insensitive checking.

**Step 5: Score Security Headers**
```js
for (const [key, config] of Object.entries(SECURITY_HEADERS)) {
  const value = headers[key] || null;
  const isPresent = value !== null;
  if (isPresent) { baseScore += config.weight; }
}
```
Each of 6 security headers has a weight (30, 20, 15, 15, 10, 10 = 100 total). If present, adds to score.

**Step 6: Penalties**
The base score can be reduced by:
- Information leakage headers (Server, X-Powered-By, etc.) — up to -10 each
- Weak CSP (present but misconfigured) — up to -15
- Insecure cookies — -5 per critical issue
- CORS misconfiguration — -10

**Step 7: CSP Deep Analysis**
If `Content-Security-Policy` is present, `analyzeCsp()` checks for dangerous directives:
- `'unsafe-inline'` in script-src → critical (XSS protection bypassed)
- `'unsafe-eval'` in script-src → critical (eval() attacks possible)
- Wildcard `*` in script-src → critical
- Missing `object-src 'none'` → warning (Flash/Java plugin attacks)
- Missing `base-uri` → warning (base tag injection)

**Step 8: Cookie Audit**
```js
const rawCookies = response.headers.getSetCookie();
```
For each cookie, checks:
- `Secure` flag — must be present (cookie only sent over HTTPS)
- `HttpOnly` flag — must be present (JS can't read it, XSS-safe)
- `SameSite` — must be Strict or Lax (prevents CSRF)

**Step 9: Progressive Score Simulation**
Calculates: "if you add header X, your score would go from 45 to 65". Shows the impact of each fix ranked by importance.

---

### functions/api/config.js — Config Generator

Takes the scan result and generates copy-paste configuration for 9 server types:
- Nginx
- Apache
- Vercel (vercel.json)
- Netlify (_headers)
- Cloudflare Worker
- Next.js (next.config.js)
- Express.js
- Django (settings.py)
- Laravel (middleware)

Only generates config for **missing** headers — doesn't touch headers that are already correct.

---

### functions/api/explain.js — AI Analysis

Calls the Claude API (claude-haiku model) with a detailed prompt containing the scan results. Supports two modes:

**mode: "analyze"** (default)
Generates:
- Risk Summary (2 sentences)
- Live Attack Scenarios (2 specific, realistic attacks possible right now)
- Quick Wins (top 3 fixes)
- What's Working (strongest existing protection)

**mode: "roadmap"**
Generates a 30-day remediation sprint plan:
- Week 1: Quick wins (< 1 hour)
- Week 2: Medium effort (2-4 hours)
- Week 3: Careful changes (4-8 hours)
- Week 4: Polish & monitor

The Claude model used is `claude-haiku-4-5-20251001` — the fastest, cheapest Claude model, good enough for structured security analysis.

---

### functions/api/subscan.js — Subdomain Scanner

Scans 12 common subdomains in **parallel** using `Promise.allSettled()`:
```js
const SUBDOMAINS = ['www', 'api', 'app', 'admin', 'blog', 'cdn',
                    'dev', 'staging', 'mail', 'shop', 'portal', 'dashboard'];
```

For each subdomain, does a quick scan (checks only the 6 security headers, no AI, no cookies). Uses a 6-second timeout per subdomain. `Promise.allSettled()` is used instead of `Promise.all()` — it waits for ALL promises to complete even if some fail, so unreachable subdomains don't crash the whole scan.

---

### functions/api/monitor.js — Email Monitoring

Handles 3 operations:

**POST subscribe**
1. Validates email format
2. Scans the target URL to get current grade
3. Saves subscription to Upstash Redis:
   ```
   key: sub:{email}:{base64(url)}
   value: { email, url, minGrade, lastGrade, lastScore, lastPresent, ... }
   ```
4. Sends confirmation email via Resend API

**GET ?action=unsubscribe&email=...&url=...**
Deletes the subscription from Redis. This URL is embedded in every alert email.

**POST check** (called by GitHub Actions weekly cron)
1. Gets all subscription keys from Redis (`SMEMBERS all_subs`)
2. For each subscription, scans the URL
3. If grade dropped below `minGrade`, sends an alert email
4. Updates the stored grade

The cron is protected by `MONITOR_SECRET` — the GitHub Action sends this secret in the request body, and the function rejects calls without it.

---

## 7. Security Headers Explained

| Header | Weight | What it does | Real attack it prevents |
|--------|--------|-------------|------------------------|
| Content-Security-Policy | 30 | Whitelist of allowed script/style/image sources | XSS — attacker injected scripts get blocked |
| Strict-Transport-Security | 20 | Forces HTTPS forever | MITM, SSL stripping, POODLE attack |
| X-Frame-Options | 15 | Blocks iframe embedding | Clickjacking — invisible iframe trick |
| X-Content-Type-Options | 15 | No MIME sniffing | MIME confusion — .jpg executed as JS |
| Referrer-Policy | 10 | Controls Referer header | Data leakage — URLs with tokens sent to analytics |
| Permissions-Policy | 10 | Disable camera/mic/GPS | Malicious ad scripts accessing microphone |

**Information Leaking Headers** (penalty, not score):
| Header | Penalty | What it reveals |
|--------|---------|----------------|
| Server | -10 | Web server + version (e.g. Apache/2.4.51) |
| X-Powered-By | -10 | Backend stack (e.g. PHP/8.1, Express) |
| X-AspNet-Version | -10 | Exact .NET version |
| X-AspNetMvc-Version | -5 | ASP.NET MVC version |
| X-Generator | -5 | CMS (WordPress, Drupal, etc.) |

---

## 8. Scoring System

```
baseScore = sum of weights for present security headers (max 100)

penalties:
  - leakage: -5 to -10 per leaking header found
  - cspQuality: -5 (C grade CSP), -10 (D), -15 (F)
  - cookies: -5 per critical cookie issue, -3 per high
  - cors: -10 if wildcard CORS with credentials

finalScore = max(0, baseScore - penalties)
```

**Grade thresholds:**
- A+ = 90-100
- A  = 80-89
- B  = 70-79
- C  = 55-69
- D  = 40-54
- F  = 0-39

---

## 9. Rate Limiting

Rate limiting uses **Upstash Redis** — a Redis database accessible via REST API (no npm, works in serverless).

How it works:
```js
const minute = Math.floor(Date.now() / 60000);  // changes every 60 seconds
const rlKey = `rl:scan:${ip}:${minute}`;

// INCR atomically increments the counter and returns new value
const count = await redis.incr(rlKey);

// On first request this minute, set 60-second expiry
if (count === 1) await redis.expire(rlKey, 60);

return count <= maxPerMinute;  // false = rate limited
```

Limits per function:
- `/api/scan` — 20 requests per minute per IP
- `/api/explain` — 5 AI requests per minute per IP
- `/api/subscan` — 5 subdomain scans per minute per IP
- `/api/monitor` subscribe — 3 subscriptions per 10 minutes per IP

**Known bug and fix:**
If Upstash returns an unexpected response, `count` becomes `undefined`. In JavaScript, `undefined <= 20` evaluates to `false`, which means the rate limiter treats every request as over-limit. The fix is:
```js
return count == null || count <= maxPerMinute;
// null/undefined → allow (fail open)
// number → enforce limit
```

---

## 10. AI Integration

The AI feature uses **Claude Haiku** via the Anthropic API.

How the API call works:
```js
const response = await fetch('https://api.anthropic.com/v1/messages', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'x-api-key': env.CLAUDE_API_KEY,       // your API key
    'anthropic-version': '2023-06-01'       // required header
  },
  body: JSON.stringify({
    model: 'claude-haiku-4-5-20251001',
    max_tokens: 700,
    messages: [{ role: 'user', content: prompt }]
  })
});
const data = await response.json();
const text = data.content[0].text;  // the AI response
```

The prompt is carefully structured to make Claude respond in a specific format (markdown with specific sections). This ensures the frontend can display it consistently.

---

## 11. Email Monitoring

Uses two external services:

**Upstash Redis** — stores subscriptions
- Each subscription is stored as a Redis hash
- All subscription keys are tracked in a Redis set (`all_subs`)
- This lets the monitor function list all subscriptions without a database

**Resend** — sends emails
- Simple REST API, no SMTP setup needed
- Free tier: 100 emails/day, 3,000/month
- Emails are HTML with inline styles (dark theme to match the site)

**GitHub Actions cron** (`.github/workflows/weekly-monitor.yml`)
- Runs every Monday at 9am UTC
- Calls `POST /api/monitor` with `{ action: "check", secret: "..." }`
- The function scans all subscribed URLs and sends alerts if needed

---

## 12. Environment Variables

Set these in Cloudflare Pages → Settings → Environment Variables:

| Variable | Where to get it | What it's for |
|----------|----------------|---------------|
| `CLAUDE_API_KEY` | console.anthropic.com → API Keys | Claude AI analysis |
| `UPSTASH_REDIS_URL` | upstash.com → your database → REST URL | Rate limiting + subscriptions |
| `UPSTASH_REDIS_TOKEN` | upstash.com → your database → REST Token | Authenticates Redis calls |
| `RESEND_API_KEY` | resend.com → API Keys | Sending monitoring emails |
| `MONITOR_SECRET` | any random string you choose | Protects the cron endpoint |
| `SITE_URL` | your Cloudflare Pages URL | Used in email links (unsubscribe, etc.) |
| `ALLOWED_ORIGIN` | your Cloudflare Pages URL (optional) | CORS restriction. If not set, defaults to `*` |

---

## 13. Deployment — Cloudflare Pages

### How Cloudflare Pages deployment works

1. You connect your GitHub repo to Cloudflare Pages
2. Every time you `git push` to `main`, Cloudflare automatically:
   - Clones your repo
   - Runs the build command (none in this case)
   - Takes the `public/` directory as the static site
   - Picks up `functions/` as serverless functions
   - Deploys everything globally to 300+ edge locations

### Build settings
- **Framework preset**: None
- **Build command**: (empty — no build step needed)
- **Build output directory**: `public`
- **Root directory**: (leave empty)

### Why "build output directory: public"?
The repo has files in multiple directories (`public/`, `functions/`, `netlify/`, etc.). Cloudflare needs to know which folder contains the files to serve as the website. Setting it to `public` means only `public/index.html`, `public/app.js`, and `public/styles.css` get served as the static site. The `functions/` directory is processed separately as serverless functions.

### Deployment URLs
- Every deployment gets a unique preview URL like `6e6e4388.header-security-project.pages.dev`
- The production URL is `header-security-project.pages.dev`
- You can add a custom domain in Pages settings

---

## 14. How Cloudflare Pages Functions Work

### Routing
File path in `functions/` maps directly to URL path:
```
functions/api/scan.js     →  /api/scan
functions/api/config.js   →  /api/config
functions/api/[id].js     →  /api/anything  (dynamic routes)
```

### The `context` object
Every function receives a `context` object:
```js
export async function onRequest(context) {
  const {
    request,  // The incoming Request (Web API standard)
    env,      // Your environment variables
    params,   // URL parameters (for dynamic routes)
    waitUntil // Run async tasks after response is sent
  } = context;
}
```

### Request vs Response (Web API standard)
Cloudflare uses the browser's Fetch API standard (same as `fetch()` in browsers):
```js
// Reading the request
const method = request.method;              // "GET", "POST", etc.
const url = new URL(request.url);           // parsed URL
const body = await request.json();          // parse JSON body
const header = request.headers.get('x-api-key');  // read header

// Creating the response
return new Response(
  JSON.stringify({ data: "hello" }),         // body (string)
  {
    status: 200,                             // HTTP status
    headers: {
      'Content-Type': 'application/json'    // response headers
    }
  }
);
```

### Key difference from Netlify Functions
```js
// Netlify (Node.js style)
exports.handler = async function(event) {
  const body = JSON.parse(event.body);
  const ip = event.headers['x-forwarded-for'];
  return { statusCode: 200, body: JSON.stringify(result) };
}

// Cloudflare Pages (Web API style)
export async function onRequest({ request, env }) {
  const body = await request.json();
  const ip = request.headers.get('cf-connecting-ip');
  return new Response(JSON.stringify(result), { status: 200 });
}
```

### `process.env` vs `env`
In Node.js (Netlify), you use `process.env.MY_VAR`.
In Cloudflare Workers/Pages, environment variables come through the `env` parameter, not `process.env`:
```js
// Netlify
const apiKey = process.env.CLAUDE_API_KEY;

// Cloudflare
export async function onRequest({ env }) {
  const apiKey = env.CLAUDE_API_KEY;
}
```

### `Buffer` is not available
Node.js has `Buffer.from(str).toString('base64')` for base64 encoding.
Cloudflare Workers don't have Node.js built-ins. Use the Web API instead:
```js
// Node.js (Netlify)
Buffer.from(url).toString('base64')

// Cloudflare (Web API)
btoa(url)   // encode
atob(str)   // decode
```

---

## 15. Common Issues & Fixes

### Issue: 429 on every request (rate limiter always fires)
**Cause**: Upstash Redis returns unexpected JSON, `count` becomes `undefined`. `undefined <= 20` is `false` in JavaScript, so every request is treated as over-limit.
**Fix**: `return count == null || count <= maxPerMinute` — if count is null/undefined, allow the request.

### Issue: Page not found after deployment
**Cause**: Build output directory not set to `public`. Cloudflare was trying to serve files from the repo root where there's no `index.html`.
**Fix**: In Cloudflare Pages settings → Builds & Deployments → set Build output directory to `public`.

### Issue: Scan button does nothing after a 429 error
**Cause**: The button gets disabled at the start of `runScan()`. If an error occurs, the `finally` block should re-enable it. If JS crashes before the `finally`, the button stays disabled.
**Fix**: Refresh the page. The `finally` block in the code handles this correctly now.

### Issue: CORS errors in browser
**Cause**: The CORS `Access-Control-Allow-Origin` header doesn't match the requesting origin.
**Fix**: Since the frontend and functions are on the same domain (both on `pages.dev`), same-origin requests don't need CORS at all. The CORS headers are kept as a safety measure with `*` fallback.

### Issue: `/.netlify/functions/scan` 404 after moving to Cloudflare
**Cause**: Old Netlify URLs hardcoded in `app.js`.
**Fix**: Updated all URLs from `/.netlify/functions/scan` to `/api/scan`.

### Issue: `Buffer is not defined`
**Cause**: `monitor.js` used `Buffer.from(url).toString('base64')` which is Node.js only.
**Fix**: Replaced with `btoa(url)` (Web API, available everywhere).

---

## 16. Project History

| Phase | Platform | What changed |
|-------|----------|-------------|
| v1 | n8n (local) | Prototype with n8n workflow automation |
| v2 | Vercel | Moved to serverless API routes |
| v3 | Netlify | Migrated to Netlify Functions, added all features |
| v4 | Cloudflare Pages | Migrated after hitting Netlify request limits |

### Why we left Netlify
Netlify's free tier has a limit on function invocations per month. Once we hit that limit, all serverless functions returned 429 errors.

### Why Cloudflare Pages
- More generous free tier (100,000 requests/day)
- Faster (runs on Cloudflare's global edge network, 300+ locations)
- Same pricing model and capability as Netlify for this use case
- Functions use Web API standard (same as browser's fetch API)

---

*Last updated: 2026-03-19*
