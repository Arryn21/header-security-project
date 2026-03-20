const SECURITY_HEADERS = {
  'content-security-policy': {
    name: 'Content-Security-Policy', weight: 30,
    description: 'Prevents XSS and code injection attacks',
    fix: "Add: Content-Security-Policy: default-src 'self'",
    realWorldExample: "British Airways breach (2018): Attackers injected malicious JS that skimmed 500,000 credit cards for 2 weeks. BA was fined £20M. A strict CSP would have blocked the injected script entirely.",
    compliance: ['OWASP A03:2021', 'PCI DSS 6.4.3', 'GDPR Art.32'],
    refs: [
      { label: 'MDN Docs', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP' },
      { label: 'W3C CSP Level 3', url: 'https://www.w3.org/TR/CSP3/' },
      { label: 'OWASP CSP Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html' }
    ]
  },
  'strict-transport-security': {
    name: 'Strict-Transport-Security (HSTS)', weight: 20,
    description: 'Forces HTTPS connections, prevents downgrade attacks',
    fix: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
    realWorldExample: "POODLE attack (CVE-2014-3566): Attackers forced browsers to downgrade to SSL 3.0, then decrypted session cookies. HSTS tells browsers to never connect over HTTP, permanently closing this attack vector.",
    compliance: ['OWASP A02:2021', 'PCI DSS 4.2.1', 'HIPAA §164.312(e)'],
    refs: [
      { label: 'MDN Docs', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security' },
      { label: 'RFC 6797', url: 'https://datatracker.ietf.org/doc/html/rfc6797' },
      { label: 'OWASP HSTS Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html' }
    ]
  },
  'x-frame-options': {
    name: 'X-Frame-Options', weight: 15,
    description: 'Prevents clickjacking by blocking iframe embedding',
    fix: 'Add: X-Frame-Options: DENY',
    realWorldExample: "Twitter clickjacking (2009, CVE-2009-2238): Attackers embedded Twitter inside invisible iframes. Users clicked what they thought were normal buttons but were actually triggering Twitter actions. X-Frame-Options blocks all iframe embedding.",
    compliance: ['OWASP A05:2021', 'PCI DSS 6.4.1'],
    refs: [
      { label: 'MDN Docs', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options' },
      { label: 'RFC 7034', url: 'https://datatracker.ietf.org/doc/html/rfc7034' },
      { label: 'OWASP Clickjacking', url: 'https://owasp.org/www-community/attacks/Clickjacking' }
    ]
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options', weight: 15,
    description: 'Prevents MIME-type sniffing attacks',
    fix: 'Add: X-Content-Type-Options: nosniff',
    realWorldExample: "IE6/7 MIME confusion attacks (CVE-2008-5915): Browsers would execute .jpg files as JavaScript if they contained script content. Attackers uploaded 'images' to CDNs that ran as scripts on victim pages. nosniff forces browsers to respect declared content types.",
    compliance: ['OWASP A05:2021', 'PCI DSS 6.4.1'],
    refs: [
      { label: 'MDN Docs', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options' },
      { label: 'OWASP Secure Headers', url: 'https://owasp.org/www-project-secure-headers/#x-content-type-options' },
      { label: 'WHATWG MIME Sniffing', url: 'https://mimesniff.spec.whatwg.org/' }
    ]
  },
  'referrer-policy': {
    name: 'Referrer-Policy', weight: 10,
    description: 'Controls how much referrer info is shared',
    fix: 'Add: Referrer-Policy: strict-origin-when-cross-origin',
    realWorldExample: "Healthcare data leakage: Patient portal URLs containing session tokens and medical record IDs were sent in Referer headers to third-party analytics (Google Analytics, Facebook Pixel). Referrer-Policy stops this under HIPAA/GDPR.",
    compliance: ['GDPR Art.25', 'HIPAA §164.514', 'OWASP A01:2021'],
    refs: [
      { label: 'MDN Docs', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy' },
      { label: 'W3C Referrer Policy', url: 'https://www.w3.org/TR/referrer-policy/' },
      { label: 'OWASP Transport Layer', url: 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html' }
    ]
  },
  'permissions-policy': {
    name: 'Permissions-Policy', weight: 10,
    description: 'Controls access to browser APIs (camera, mic, GPS)',
    fix: 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()',
    realWorldExample: "Malicious ad scripts on major news sites were found silently accessing visitor microphones via the browser API. Permissions-Policy locks down all browser API access by default, requiring explicit opt-in per origin.",
    compliance: ['GDPR Art.25', 'OWASP A05:2021'],
    refs: [
      { label: 'MDN Docs', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy' },
      { label: 'W3C Permissions Policy', url: 'https://www.w3.org/TR/permissions-policy/' },
      { label: 'OWASP Secure Headers', url: 'https://owasp.org/www-project-secure-headers/#permissions-policy' }
    ]
  }
};

const LEAKING_HEADERS = {
  'server':              { name: 'Server',              penalty: 10, description: 'Reveals web server software and version (e.g. Apache/2.4.51)', fix: 'Remove or genericize — set: Server: webserver' },
  'x-powered-by':       { name: 'X-Powered-By',        penalty: 10, description: 'Exposes backend technology stack (e.g. PHP/8.1.2, Express)', fix: 'Remove entirely — in Express: app.disable("x-powered-by")' },
  'x-aspnet-version':   { name: 'X-AspNet-Version',    penalty: 10, description: 'Reveals exact .NET framework version, enabling targeted exploits', fix: 'Disable in web.config: <httpRuntime enableVersionHeader="false" />' },
  'x-aspnetmvc-version':{ name: 'X-AspNetMvc-Version', penalty:  5, description: 'Reveals ASP.NET MVC version', fix: 'In Global.asax Application_Start: MvcHandler.DisableMvcResponseHeader = true' },
  'x-generator':        { name: 'X-Generator',         penalty:  5, description: 'Reveals CMS or site generator (e.g. WordPress, Drupal, Joomla)', fix: 'Remove via plugin or server config' },
  'x-drupal-cache':     { name: 'X-Drupal-Cache',      penalty:  5, description: 'Confirms the site is running Drupal', fix: 'Disable via Drupal Performance settings or reverse proxy' },
  'x-wordpress-id':     { name: 'X-WordPress',         penalty:  5, description: 'Confirms the site is running WordPress', fix: 'Remove via security plugin (e.g. Wordfence, WP Headers & Footers)' },
};

function computeGrade(score) {
  return score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : 'F';
}

function analyzeCsp(cspValue) {
  const issues = [];
  const directives = {};

  cspValue.split(';').map(s => s.trim()).filter(Boolean).forEach(d => {
    const parts = d.split(/\s+/);
    directives[parts[0].toLowerCase()] = parts.slice(1);
  });

  const scriptSrc = directives['script-src'] || directives['default-src'] || [];
  const styleSrc  = directives['style-src']  || directives['default-src'] || [];
  const objectSrc = directives['object-src'] || directives['default-src'] || [];

  if (scriptSrc.includes("'unsafe-inline'"))
    issues.push({ severity: 'critical', message: "script-src allows 'unsafe-inline' — XSS protection is bypassed. Attackers can inject and execute arbitrary scripts." });
  if (scriptSrc.includes("'unsafe-eval'"))
    issues.push({ severity: 'critical', message: "script-src allows 'unsafe-eval' — eval() and similar functions can be used for code injection." });
  if (scriptSrc.some(s => s === '*' || s === 'http:' || s === 'https:'))
    issues.push({ severity: 'critical', message: "script-src uses a wildcard or broad scheme — scripts can load from any origin, defeating XSS protection." });
  if (styleSrc.includes("'unsafe-inline'"))
    issues.push({ severity: 'warning', message: "style-src allows 'unsafe-inline' — CSS injection can exfiltrate data via attribute selectors." });
  if (!objectSrc.includes("'none'"))
    issues.push({ severity: 'warning', message: "object-src is not set to 'none' — legacy plugin attacks (Flash, Java applets) may be possible." });
  if (!directives['base-uri'])
    issues.push({ severity: 'warning', message: "No base-uri directive — base tag injection can redirect relative URLs to attacker-controlled origins." });

  const criticals = issues.filter(i => i.severity === 'critical').length;
  let grade, label;
  if (issues.length === 0)    { grade = 'A'; label = 'Strong CSP'; }
  else if (criticals >= 2)    { grade = 'F'; label = 'Dangerously Weak CSP'; }
  else if (criticals === 1)   { grade = 'D'; label = 'Weak CSP — Critical Issues Found'; }
  else                        { grade = 'C'; label = 'Moderate CSP — Needs Hardening'; }

  return { grade, label, issues, directiveCount: Object.keys(directives).length };
}

function analyzeCookies(cookieHeaders) {
  return cookieHeaders.map(raw => {
    const parts = raw.split(';').map(s => s.trim());
    const name = (parts[0] || '').split('=')[0].trim() || 'cookie';
    const attrs = parts.slice(1).map(s => s.toLowerCase());

    const hasSecure   = attrs.some(a => a === 'secure');
    const hasHttpOnly = attrs.some(a => a === 'httponly');
    const sameSiteAttr = attrs.find(a => a.startsWith('samesite='));
    const sameSite = sameSiteAttr ? sameSiteAttr.split('=')[1] : null;

    const issues = [];
    if (!hasSecure)   issues.push({ flag: 'Secure',   severity: 'critical', message: 'Cookie sent over HTTP — interceptable by network attackers (MITM)' });
    if (!hasHttpOnly) issues.push({ flag: 'HttpOnly', severity: 'high',     message: 'Readable by JavaScript — can be stolen via XSS' });
    if (!sameSite)    issues.push({ flag: 'SameSite', severity: 'medium',   message: 'Missing SameSite attribute — vulnerable to CSRF attacks' });
    else if (sameSite === 'none' && !hasSecure)
                      issues.push({ flag: 'SameSite=None', severity: 'critical', message: 'SameSite=None without Secure is rejected by modern browsers and insecure' });

    return { name, hasSecure, hasHttpOnly, sameSite, issues };
  });
}

function analyzeCors(headers) {
  const origin = headers['access-control-allow-origin'];
  const credentials = headers['access-control-allow-credentials'];
  if (!origin) return null;

  const issues = [];
  if (origin === '*' && credentials === 'true')
    issues.push({ severity: 'critical', message: "Wildcard CORS (*) with credentials=true is a critical misconfiguration — any website can make authenticated requests on behalf of your users." });
  else if (origin === '*')
    issues.push({ severity: 'warning', message: "CORS allows any origin (*) — safe for public read-only APIs, dangerous if used on authenticated endpoints." });

  return { origin, credentials: credentials || 'false', issues };
}

async function checkRateLimit(ip, key, maxPerMinute, env) {
  const url   = (env.UPSTASH_REDIS_URL || '').replace(/\/$/, '');
  const token = env.UPSTASH_REDIS_TOKEN;
  if (!url || !token) return false;
  const minute = Math.floor(Date.now() / 60000);
  const rlKey  = `rl:${key}:${ip}:${minute}`;
  try {
    const res = await fetch(`${url}/pipeline`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify([['INCR', rlKey], ['EXPIRE', rlKey, 60]])
    });
    const data = await res.json();
    const count = data[0]?.result;
    return typeof count === 'number' && count <= maxPerMinute;
  } catch { return false; }
}

function isAllowedUrl(urlString) {
  let parsed;
  try { parsed = new URL(urlString); } catch { return false; }
  if (!['http:', 'https:'].includes(parsed.protocol)) return false;
  const h = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');

  // Block localhost and any bare IP address (dotted, decimal, hex, octal, IPv6)
  // Forcing domain names eliminates all encoding bypass techniques in one rule
  if (h === 'localhost') return false;
  if (/^[\d.]+$/.test(h)) return false;     // dotted IPv4 or decimal IP
  if (/^0x[0-9a-f]+$/i.test(h)) return false; // hex IP (0x7f000001)
  if (/^[0-9a-f:]+$/.test(h)) return false;   // IPv6 (bare or with colons)

  return true;
}

async function safeFetch(url, timeoutMs) {
  let currentUrl = url;
  for (let hops = 0; hops < 5; hops++) {
    const res = await fetch(currentUrl, {
      method: 'GET', redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecureHeaders-Scanner/1.0)' }
    });
    if (res.status < 300 || res.status >= 400) return res;
    const location = res.headers.get('location');
    if (!location) return res;
    const next = new URL(location, currentUrl).href;
    if (!isAllowedUrl(next)) throw new Error('SSRF_REDIRECT');
    currentUrl = next;
  }
  throw new Error('Too many redirects');
}

export async function onRequest(context) {
  const { request, env } = context;
  const allowedOrigin = env.SITE_URL || 'https://header-security-project.pages.dev';
  const origin = request.headers.get('origin') || '';
  const corsOrigin = origin === allowedOrigin ? origin : allowedOrigin;
  const cors = {
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff'
  };

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (request.method !== 'POST') return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers: cors });
  const ct = request.headers.get('content-type') || '';
  if (!ct.includes('application/json')) return new Response(JSON.stringify({ error: 'Unsupported Media Type' }), { status: 415, headers: cors });

  const ip = request.headers.get('cf-connecting-ip') || (request.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'unknown';
  if (!(await checkRateLimit(ip, 'scan', 20, env))) {
    return new Response(JSON.stringify({ error: 'Rate limit exceeded. Max 20 scan requests per minute per IP.' }), { status: 429, headers: { ...cors, 'Retry-After': '60' } });
  }

  const { url } = await request.json();
  if (!url || typeof url !== 'string') return new Response(JSON.stringify({ error: 'URL is required and must be a string' }), { status: 400, headers: cors });
  if (url.length > 2048) return new Response(JSON.stringify({ error: 'URL too long' }), { status: 400, headers: cors });

  const targetUrl = url.startsWith('http') ? url : 'https://' + url;
  try {
    const parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return new Response(JSON.stringify({ error: 'Only http:// and https:// URLs are allowed' }), { status: 400, headers: cors });
    }
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid URL format' }), { status: 400, headers: cors });
  }
  if (!isAllowedUrl(targetUrl)) {
    return new Response(JSON.stringify({ error: 'URL not allowed — private/internal addresses are blocked' }), { status: 400, headers: cors });
  }

  try {
    const response = await safeFetch(targetUrl, 10000);

    const headers = {};
    response.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });

    const rawCookies = typeof response.headers.getSetCookie === 'function'
      ? response.headers.getSetCookie()
      : [headers['set-cookie']].filter(Boolean);

    const results = [];
    let baseScore = 0, passing = 0;

    for (const [key, config] of Object.entries(SECURITY_HEADERS)) {
      const value = headers[key] || null;
      const isPresent = value !== null;
      if (isPresent) { baseScore += config.weight; passing++; }
      results.push({
        header: config.name, key, present: isPresent, value,
        weight: config.weight, description: config.description,
        fix: isPresent ? null : config.fix,
        realWorldExample: config.realWorldExample,
        compliance: config.compliance
      });
    }

    const cspValue = headers['content-security-policy'];
    const cspAnalysis = cspValue ? analyzeCsp(cspValue) : null;

    let cspPenalty = 0;
    if (cspAnalysis) {
      if (cspAnalysis.grade === 'F') cspPenalty = 15;
      else if (cspAnalysis.grade === 'D') cspPenalty = 10;
      else if (cspAnalysis.grade === 'C') cspPenalty = 5;
    }

    const leakingHeaders = [];
    let leakPenalty = 0;
    for (const [key, config] of Object.entries(LEAKING_HEADERS)) {
      const value = headers[key] || null;
      if (value !== null) {
        leakPenalty += config.penalty;
        leakingHeaders.push({ header: config.name, key, value, penalty: config.penalty, description: config.description, fix: config.fix });
      }
    }

    const cookieAudit = rawCookies.length ? analyzeCookies(rawCookies) : [];
    const cookiePenalty = cookieAudit.reduce((sum, c) => sum + c.issues.filter(i => i.severity === 'critical').length * 5 + c.issues.filter(i => i.severity === 'high').length * 3, 0);

    const corsAnalysis = analyzeCors(headers);
    const corsPenalty = corsAnalysis && corsAnalysis.issues.some(i => i.severity === 'critical') ? 10 : 0;

    const totalPenalty = leakPenalty + cspPenalty + cookiePenalty + corsPenalty;
    const totalScore = Math.max(0, baseScore - totalPenalty);
    const grade = computeGrade(totalScore);

    const missingHeaders = results.filter(h => !h.present).sort((a, b) => b.weight - a.weight);
    const progressiveScores = missingHeaders.map(h => {
      const newScore = Math.min(100, Math.max(0, totalScore + h.weight));
      return { header: h.header, key: h.key, weight: h.weight, newScore, newGrade: computeGrade(newScore) };
    });

    const result = {
      url: targetUrl, score: totalScore, baseScore, penalty: totalPenalty,
      penaltyBreakdown: { leakage: leakPenalty, cspQuality: cspPenalty, cookies: cookiePenalty, cors: corsPenalty },
      maxScore: 100, grade, scannedAt: new Date().toISOString(),
      summary: { total: results.length, passing, failing: results.length - passing, leaking: leakingHeaders.length },
      headers: results,
      leakingHeaders,
      progressiveScores,
      cspAnalysis,
      cookieAudit,
      corsAnalysis
    };

    return new Response(JSON.stringify(result), { status: 200, headers: { ...cors, 'Content-Type': 'application/json' } });

  } catch (err) {
    if (err.message === 'SSRF_REDIRECT') {
      return new Response(JSON.stringify({ error: 'URL not allowed — redirect to private/internal address blocked' }), { status: 400, headers: cors });
    }
    const result = {
      url: targetUrl, error: true,
      errorMessage: `Could not connect to ${targetUrl}. The site may be unreachable, blocking automated requests, or the URL may be invalid.`,
      score: null, maxScore: 100, grade: null, scannedAt: new Date().toISOString(),
      summary: { total: 0, passing: 0, failing: 0, leaking: 0 },
      headers: [], leakingHeaders: [], progressiveScores: [], cspAnalysis: null, cookieAudit: [], corsAnalysis: null
    };
    return new Response(JSON.stringify(result), { status: 200, headers: { ...cors, 'Content-Type': 'application/json' } });
  }
}
