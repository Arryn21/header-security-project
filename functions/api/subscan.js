const SUBDOMAINS = ['www', 'api', 'app', 'admin', 'blog', 'cdn', 'dev', 'staging', 'mail', 'shop', 'portal', 'dashboard'];

const WEIGHTS = {
  'content-security-policy':  30,
  'strict-transport-security': 20,
  'x-frame-options':          15,
  'x-content-type-options':   15,
  'referrer-policy':          10,
  'permissions-policy':       10
};

const LEAKING = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-drupal-cache'];

function computeGrade(score) {
  return score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : 'F';
}

async function quickScan(url) {
  try {
    let currentUrl = url;
    let response;
    for (let hops = 0; hops < 5; hops++) {
      response = await fetch(currentUrl, {
        method: 'GET', redirect: 'manual',
        signal: AbortSignal.timeout(6000),
        headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecureHeaders-Scanner/1.0)' }
      });
      if (response.status < 300 || response.status >= 400) break;
      const location = response.headers.get('location');
      if (!location) break;
      const next = new URL(location, currentUrl).href;
      if (!isAllowedUrl(next)) return { reachable: false };
      currentUrl = next;
    }

    const headers = {};
    response.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });

    let score = 0, passing = 0;
    const missing = [];
    for (const [key, weight] of Object.entries(WEIGHTS)) {
      if (headers[key]) { score += weight; passing++; }
      else missing.push(key);
    }

    const leaking = LEAKING.filter(h => headers[h]).map(h => ({ header: h, value: headers[h] }));
    const penalty = leaking.reduce((s, h) => s + (h.header === 'server' || h.header === 'x-powered-by' || h.header === 'x-aspnet-version' ? 10 : 5), 0);
    const finalScore = Math.max(0, score - penalty);
    const grade = computeGrade(finalScore);
    const finalUrl = response.url || url;

    return { reachable: true, score: finalScore, grade, passing, total: 6, missing, leaking, finalUrl };
  } catch {
    return { reachable: false };
  }
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

  if (h === 'localhost') return false;
  if (/^[\d.]+$/.test(h)) return false;
  if (/^0x[0-9a-f]+$/i.test(h)) return false;
  if (/^[0-9a-f:]+$/.test(h)) return false;

  return true;
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
  if (!(await checkRateLimit(ip, 'subscan', 5, env))) {
    return new Response(JSON.stringify({ error: 'Rate limit exceeded. Max 5 subdomain scans per minute per IP.' }), { status: 429, headers: { ...cors, 'Retry-After': '60' } });
  }

  const { domain } = await request.json();
  if (!domain || typeof domain !== 'string') return new Response(JSON.stringify({ error: 'domain is required and must be a string' }), { status: 400, headers: cors });

  const cleanDomain = domain
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0]
    .split('?')[0]
    .toLowerCase()
    .trim();

  if (!isAllowedUrl(`https://${cleanDomain}`)) {
    return new Response(JSON.stringify({ error: 'Domain not allowed — private/internal addresses are blocked' }), { status: 400, headers: cors });
  }

  const settled = await Promise.allSettled(
    SUBDOMAINS.map(async sub => {
      const url = `https://${sub}.${cleanDomain}`;
      const result = await quickScan(url);
      return { subdomain: sub, url, ...result };
    })
  );

  const scanned = settled.map((r, i) =>
    r.status === 'fulfilled'
      ? r.value
      : { subdomain: SUBDOMAINS[i], url: `https://${SUBDOMAINS[i]}.${cleanDomain}`, reachable: false }
  );

  const reachable = scanned.filter(s => s.reachable);

  return new Response(JSON.stringify({
    domain: cleanDomain,
    scanned,
    reachableCount: reachable.length,
    total: SUBDOMAINS.length,
    scannedAt: new Date().toISOString()
  }), { status: 200, headers: { ...cors, 'Content-Type': 'application/json' } });
}
