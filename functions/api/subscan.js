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
    const response = await fetch(url, {
      method: 'GET', redirect: 'follow',
      signal: AbortSignal.timeout(6000),
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecureHeaders-Scanner/1.0)' }
    });

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
  const url   = env.UPSTASH_REDIS_URL;
  const token = env.UPSTASH_REDIS_TOKEN;
  if (!url || !token) return true;
  const minute = Math.floor(Date.now() / 60000);
  const rlKey  = `rl:${key}:${ip}:${minute}`;
  try {
    const res = await fetch(`${url}/incr/${encodeURIComponent(rlKey)}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const { result: count } = await res.json();
    if (count === 1) {
      fetch(`${url}/expire/${encodeURIComponent(rlKey)}/60`, {
        headers: { Authorization: `Bearer ${token}` }
      });
    }
    return count <= maxPerMinute;
  } catch { return true; }
}

export async function onRequest(context) {
  const { request, env } = context;
  const allowedOrigin = env.ALLOWED_ORIGIN || '*';
  const origin = request.headers.get('origin') || '';
  const corsOrigin = allowedOrigin === '*' ? '*' : (origin === allowedOrigin ? origin : allowedOrigin);
  const cors = {
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin'
  };

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
  if (request.method !== 'POST') return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers: cors });

  const ip = request.headers.get('cf-connecting-ip') || (request.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'unknown';
  if (!(await checkRateLimit(ip, 'subscan', 5, env))) {
    return new Response(JSON.stringify({ error: 'Rate limit exceeded. Max 5 subdomain scans per minute per IP.' }), { status: 429, headers: { ...cors, 'Retry-After': '60' } });
  }

  const { domain } = await request.json();
  if (!domain) return new Response(JSON.stringify({ error: 'domain is required' }), { status: 400, headers: cors });

  const cleanDomain = domain
    .replace(/^https?:\/\//, '')
    .replace(/^www\./, '')
    .split('/')[0]
    .split('?')[0]
    .toLowerCase()
    .trim();

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
