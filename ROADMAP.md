# SecureHeaders Scanner — Feature Roadmap & Progress

Live site: https://secureheaders-scanner.netlify.app
Site ID: 3450895d-3e35-4390-aa11-2e07fe213eba
Deploy script: `python deploy_netlify.py`

---

## Status Legend
- `[ ]` Not started
- `[~]` In progress
- `[x]` Done

---

## Phase 1 — High Impact, Low Effort (Do First)

- [x] **1. Information Leakage Detection**
  - Detects: `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, `X-Drupal-Cache`, `X-WordPress`
  - Deducts points from score (e.g., -10 per leaking header), shown as yellow "Danger" section in UI
  - Score shows base score, penalty, and final score separately

- [x] **2. Progressive Score Simulation**
  - Shows per-missing-header: current grade → new grade if fixed, with point gain
  - Sorted by highest impact first

- [x] **3. Real CVE / Attack Examples Per Header**
  - Each header has a `realWorldExample` field with named breach, year, and impact
  - Shown as collapsible "Real-world attack example" toggle in UI

- [x] **4. Compliance Mapping**
  - Each header maps to: OWASP A0x:2021, PCI DSS, GDPR Art., HIPAA §
  - Shown as color-coded compliance tags below each header row

---

## Phase 2 — Medium Effort, High Impact

- [x] **5. CSP Deep Analysis**
  - Parses CSP directives when present, grades quality A/C/D/F
  - Flags: `unsafe-inline`, `unsafe-eval`, wildcard sources, missing `object-src 'none'`, missing `base-uri`
  - Applies score penalty (5–15 pts) for weak CSP
  - Shown inline within CSP header row as expandable analysis block

- [x] **6. Cookie Security Audit**
  - Parses all `Set-Cookie` headers using `response.headers.getSetCookie()`
  - Checks each cookie: `Secure`, `HttpOnly`, `SameSite` flags
  - Applies score penalty per critical/high cookie issue
  - Shows per-cookie breakdown with color-coded flags

- [x] **7. CORS Misconfiguration Detection**
  - Detects `Access-Control-Allow-Origin: *` (warning)
  - Detects wildcard + credentials=true combo (critical)
  - Shown as dedicated CORS section with colored border

- [x] **8. Framework-Specific Fix Configs**
  - Added: Next.js (`next.config.js`), Express.js (Helmet.js), Django (`settings.py`), Laravel (middleware class)
  - Existing: Nginx, Apache, Vercel, Netlify, Cloudflare
  - 9 total framework tabs in UI

---

## Phase 3 — Bigger Features

- [x] **9. Shareable Report Cards**
  - Encodes full scan result as base64 into URL hash: `#report/<base64>`
  - "Copy Link" button appears after every scan — copies shareable URL to clipboard
  - Visiting a shared link auto-loads and renders the exact report (no re-scan)
  - Shows "Shared Report" banner with original scan date + "Scan Again" button
  - AI explanation stored in shared data so it's included in the link
  - Zero backend storage needed — report lives entirely in the URL

- [x] **10. CI/CD Integration Guide**
  - Shows after every scan with the scanned URL pre-filled
  - 3 tabs: GitHub Actions YAML, Node.js npm script, Shell script
  - Configurable minimum grade dropdown (A+ / A / B / C / D) — code updates live
  - All scripts call our scan API and exit 1 if grade drops below threshold
  - GitHub Actions includes scheduled weekly check (Monday 9am cron)

- [x] **11. Subdomain Scanner**
  - "Subdomains" button next to Scan Now — scans 12 common subdomains in parallel
  - Subdomains checked: www, api, app, admin, blog, cdn, dev, staging, mail, shop, portal, dashboard
  - Shows grade, score, passing headers, and leaking header badges per subdomain
  - Unreachable subdomains shown greyed out
  - Clicking any live card triggers a full scan of that subdomain
  - New `netlify/functions/subscan.js` with 6s per-subdomain timeout

- [x] **12. Before/After Comparison**
  - Saves every scan to localStorage keyed by URL
  - On re-scan: shows diff banner — old grade → new grade, score delta (+/- pts)
  - Pills show: headers fixed, headers regressed, leaks added, leaks removed
  - "No changes since last scan" shown if nothing changed
  - Shows time since last scan (e.g. "vs scan 2d ago")

- [x] **13. Email Monitoring / Alerts**
  - "Weekly Security Alerts" form appears after every scan
  - User enters email + minimum grade threshold (A+ / A / B / C / D)
  - Sends confirmation email on subscribe, alert email when grade drops
  - Storage: Upstash Redis (REST API, free tier)
  - Email: Resend (REST API, free tier)
  - Scheduling: GitHub Actions cron (`.github/workflows/weekly-monitor.yml`) — every Monday 9am
  - REQUIRES SETUP: See setup instructions below

  Setup steps (one-time, ~10 minutes):
  1. Sign up at resend.com → API Keys → create key → copy it
  2. Sign up at upstash.com → Create Redis DB → copy REST URL + token
  3. Go to Netlify dashboard → Site → Environment variables → add:
     - RESEND_API_KEY = your resend key
     - UPSTASH_REDIS_URL = your upstash REST URL
     - UPSTASH_REDIS_TOKEN = your upstash token
     - MONITOR_SECRET = any random string (e.g. openssl rand -hex 16)
  4. Redeploy: python deploy_netlify.py
  5. Add MONITOR_SECRET to GitHub repo secrets for the Actions workflow

---

## Phase 4 — AI Enhancements

- [x] **14. Attack Simulation in AI Explanation**
  - Upgraded prompt passes full scan data: missing headers, leaking headers, CSP issues, cookie issues
  - AI writes concrete named attacks with specific techniques and real attacker gains
  - Structure: Risk Summary → Live Attack Scenarios (2 attacks) → Quick Wins → What's Working
  - mode: 'analyze' sent with every scan

- [x] **15. AI-Generated Fix Priority Roadmap**
  - "Generate Roadmap" button appears after every scan
  - Calls explain.js with mode: 'roadmap'
  - Returns week-by-week sprint plan (Week 1: quick wins, Week 2: medium, Week 3: careful, Week 4: polish)
  - Includes expected score after each week and final grade projection
  - Roadmap stored in currentScan so it's included in shareable report links
  - Button becomes "Regenerate" after first use

---

## Already Done ✓

- [x] Core header scanner (6 headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- [x] Scoring system with grades A+ to F
- [x] Dark theme UI with score visualization
- [x] Server config generator (nginx, apache, vercel, netlify, cloudflare)
- [x] AI explanation via Claude API (claude-haiku-4-5)
- [x] Netlify deployment with serverless functions
- [x] Graceful error handling for unreachable sites
- [x] Environment-aware API URLs (local n8n vs production Netlify)

---

## Notes
- All features deploy via: `python deploy_netlify.py`
- Claude API key is hardcoded in `explain.js` (Netlify free plan blocks env var API)
- Frontend is a single file: `public/index.html`
- Functions are in: `netlify/functions/scan.js`, `config.js`, `explain.js`
- `netlify.toml` redirect rules exist but not applied in zip deploys — frontend calls `/.netlify/functions/*` directly
