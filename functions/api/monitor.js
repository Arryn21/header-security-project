// Email monitoring — subscribe/unsubscribe/check
// Requires env vars: RESEND_API_KEY, UPSTASH_REDIS_URL, UPSTASH_REDIS_TOKEN, MONITOR_SECRET, SITE_URL

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#x27;');
}

async function checkRateLimit(ip, key, max, windowSeconds, env) {
  const url   = env.UPSTASH_REDIS_URL;
  const token = env.UPSTASH_REDIS_TOKEN;
  if (!url || !token) return false;
  const window = Math.floor(Date.now() / (windowSeconds * 1000));
  const rlKey  = `rl:${key}:${ip}:${window}`;
  try {
    const res = await fetch(`${url}/incr/${encodeURIComponent(rlKey)}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    const { result: count } = await res.json();
    if (count === 1) {
      fetch(`${url}/expire/${encodeURIComponent(rlKey)}/${windowSeconds}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
    }
    return count == null || count <= max;
  } catch { return true; }
}

const GRADE_ORDER = ['A+', 'A', 'B', 'C', 'D', 'F'];
function gradeIndex(g) { return GRADE_ORDER.indexOf(g); }
function gradeWorse(a, b) { return gradeIndex(a) > gradeIndex(b); }

async function redis(cmd, ...args) {
  const url   = env_global.UPSTASH_REDIS_URL;
  const token = env_global.UPSTASH_REDIS_TOKEN;
  if (!url || !token) throw new Error('Upstash env vars not set');
  const res = await fetch(`${url}/${[cmd, ...args].map(encodeURIComponent).join('/')}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await res.json();
  return data.result;
}

// env_global is set per-request in the handler
let env_global = {};

async function getSubscription(email, url) {
  const key = `sub:${email}:${btoa(url)}`;
  const raw = await redis('GET', key);
  return raw ? JSON.parse(raw) : null;
}

async function saveSubscription(sub) {
  const key = `sub:${sub.email}:${btoa(sub.url)}`;
  await redis('SET', key, JSON.stringify(sub));
  await redis('SADD', 'all_subs', key);
}

async function deleteSubscription(email, url) {
  const key = `sub:${email}:${btoa(url)}`;
  await redis('DEL', key);
  await redis('SREM', 'all_subs', key);
}

async function getAllSubscriptions() {
  const keys = await redis('SMEMBERS', 'all_subs');
  if (!keys || !keys.length) return [];
  const subs = [];
  for (const key of keys) {
    const raw = await redis('GET', key);
    if (raw) subs.push(JSON.parse(raw));
  }
  return subs;
}

async function makeUnsubToken(email, url, secret) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${email}:${url}`));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function sendEmail(to, subject, html, env) {
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) throw new Error('RESEND_API_KEY not set');
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: 'SecureHeaders Scanner <onboarding@resend.dev>', to: [to], subject, html })
  });
  return res.json();
}

function confirmationEmail(sub, siteUrl) {
  const unsubLink = `${siteUrl}/api/monitor?action=unsubscribe&token=${encodeURIComponent(sub.unsubToken)}`;
  return `
    <div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0f1117;color:#e2e8f0;border-radius:12px;overflow:hidden;">
      <div style="background:#1a1d27;padding:24px 32px;border-bottom:1px solid #2a2d3e;">
        <h2 style="margin:0;color:#fff;">SecureHeaders <span style="color:#3b82f6;">Scanner</span></h2>
      </div>
      <div style="padding:32px;">
        <h3 style="color:#22c55e;margin-top:0;">Monitoring activated!</h3>
        <p style="color:#8892a4;">You're now subscribed to weekly security alerts for:</p>
        <div style="background:#0a0c14;border:1px solid #2a2d3e;border-radius:8px;padding:12px 16px;font-family:monospace;color:#3b82f6;margin:16px 0;">${escHtml(sub.url)}</div>
        <p style="color:#8892a4;">You'll get an email if the security grade drops below <strong style="color:#fff;">${sub.minGrade}</strong>.</p>
        <p style="color:#8892a4;">Current grade: <strong style="color:#fff;">${sub.lastGrade} (${sub.lastScore}/100)</strong></p>
        <hr style="border-color:#2a2d3e;margin:24px 0;">
        <p style="font-size:13px;color:#8892a4;">
          <a href="${unsubLink}" style="color:#ef4444;text-decoration:none;">Unsubscribe</a> ·
          <a href="${siteUrl}" style="color:#3b82f6;text-decoration:none;">Open Scanner</a>
        </p>
      </div>
    </div>`;
}

function alertEmail(sub, newGrade, newScore, changedHeaders, siteUrl) {
  const unsubLink = `${siteUrl}/api/monitor?action=unsubscribe&token=${encodeURIComponent(sub.unsubToken)}`;
  const changes = changedHeaders.length
    ? `<ul style="color:#8892a4;padding-left:20px;">${changedHeaders.map(h => `<li>${escHtml(h)}</li>`).join('')}</ul>`
    : '';
  return `
    <div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0f1117;color:#e2e8f0;border-radius:12px;overflow:hidden;">
      <div style="background:#450a0a;padding:24px 32px;border-bottom:1px solid #7f1d1d;">
        <h2 style="margin:0;color:#fff;">Security Grade Alert</h2>
      </div>
      <div style="padding:32px;">
        <p style="color:#8892a4;margin-top:0;">The security grade for <strong style="color:#fff;">${escHtml(sub.url)}</strong> has dropped:</p>
        <div style="display:flex;align-items:center;gap:16px;font-size:2.5rem;font-weight:800;margin:24px 0;">
          <span style="color:#22c55e;">${sub.lastGrade}</span>
          <span style="color:#8892a4;font-size:1.2rem;">→</span>
          <span style="color:#ef4444;">${newGrade}</span>
        </div>
        <p style="color:#8892a4;">Score: <strong style="color:#fff;">${sub.lastScore} → ${newScore} / 100</strong></p>
        ${changes ? `<p style="color:#8892a4;">Headers that changed:</p>${changes}` : ''}
        <a href="${siteUrl}" style="display:inline-block;margin-top:16px;padding:12px 24px;background:#3b82f6;color:#fff;border-radius:8px;text-decoration:none;font-weight:600;">View Full Report</a>
        <hr style="border-color:#2a2d3e;margin:24px 0;">
        <p style="font-size:13px;color:#8892a4;">
          <a href="${unsubLink}" style="color:#ef4444;text-decoration:none;">Unsubscribe</a> ·
          <a href="${siteUrl}" style="color:#3b82f6;text-decoration:none;">Open Scanner</a>
        </p>
      </div>
    </div>`;
}

const WEIGHTS = {
  'content-security-policy': 30, 'strict-transport-security': 20,
  'x-frame-options': 15, 'x-content-type-options': 15,
  'referrer-policy': 10, 'permissions-policy': 10
};

async function quickScan(url) {
  const response = await fetch(url, {
    method: 'GET', redirect: 'follow',
    signal: AbortSignal.timeout(10000),
    headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecureHeaders-Scanner/1.0)' }
  });
  const headers = {};
  response.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

  let score = 0;
  const present = {}, missing = [];
  for (const [key, weight] of Object.entries(WEIGHTS)) {
    if (headers[key]) { score += weight; present[key] = true; }
    else missing.push(key);
  }
  const grade = score >= 90 ? 'A+' : score >= 80 ? 'A' : score >= 70 ? 'B' : score >= 55 ? 'C' : score >= 40 ? 'D' : 'F';
  return { score, grade, present, missing };
}

export async function onRequest(context) {
  const { request, env } = context;
  env_global = env;

  const siteUrl = env.SITE_URL || 'https://secureheaders-scanner.pages.dev';
  const allowedOrigin = env.SITE_URL || 'https://header-security-project.pages.dev';
  const origin = request.headers.get('origin') || '';
  const corsOrigin = origin === allowedOrigin ? origin : allowedOrigin;
  const cors = {
    'Access-Control-Allow-Origin': corsOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin'
  };

  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });

  // GET: unsubscribe via link in email
  if (request.method === 'GET') {
    const params = new URL(request.url).searchParams;
    const action = params.get('action');
    const token  = params.get('token');
    if (action === 'unsubscribe' && token) {
      try {
        const subs = await getAllSubscriptions();
        const sub = subs.find(s => s.unsubToken === token);
        if (!sub) return new Response('Invalid or expired unsubscribe link.', { status: 400, headers: { 'Content-Type': 'text/plain' } });
        await deleteSubscription(sub.email, sub.url);
        return new Response(`<html><body style="font-family:system-ui;background:#0f1117;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
          <div style="text-align:center;padding:2rem;">
            <h2 style="color:#22c55e;">Unsubscribed</h2>
            <p style="color:#8892a4;">You'll no longer receive alerts for ${escHtml(sub.url)}</p>
            <a href="${escHtml(siteUrl)}" style="color:#3b82f6;">Back to Scanner</a>
          </div></body></html>`, { status: 200, headers: {
            'Content-Type': 'text/html',
            'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'",
            'X-Content-Type-Options': 'nosniff'
          }});
      } catch (e) {
        return new Response(JSON.stringify({ error: 'Unsubscribe failed. Please try again.' }), { status: 500, headers: cors });
      }
    }
    return new Response(JSON.stringify({ error: 'Invalid request' }), { status: 400, headers: cors });
  }

  if (request.method !== 'POST') return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers: cors });
  const ct = request.headers.get('content-type') || '';
  if (!ct.includes('application/json')) return new Response(JSON.stringify({ error: 'Unsupported Media Type' }), { status: 415, headers: cors });

  const body = await request.json();
  const { action } = body;

  // POST subscribe
  if (action === 'subscribe') {
    const { email, url, minGrade = 'B' } = body;
    if (!email || !url) return new Response(JSON.stringify({ error: 'email and url required' }), { status: 400, headers: cors });

    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email)) return new Response(JSON.stringify({ error: 'Invalid email address' }), { status: 400, headers: cors });

    const ip = request.headers.get('cf-connecting-ip') || (request.headers.get('x-forwarded-for') || '').split(',')[0].trim() || 'unknown';
    if (!(await checkRateLimit(ip, 'monitor-sub', 3, 600, env))) {
      return new Response(JSON.stringify({ error: 'Rate limit exceeded. Max 3 subscriptions per 10 minutes per IP.' }), { status: 429, headers: { ...cors, 'Retry-After': '600' } });
    }

    try {
      const scan = await quickScan(url.startsWith('http') ? url : 'https://' + url);
      const secret = env.MONITOR_SECRET || 'default-secret';
      const sub = {
        email, url, minGrade,
        lastGrade: scan.grade, lastScore: scan.score, lastPresent: scan.present,
        createdAt: new Date().toISOString(), lastCheck: new Date().toISOString(),
        unsubToken: await makeUnsubToken(email, url, secret)
      };
      await saveSubscription(sub);
      await sendEmail(email, `Monitoring activated for ${url}`, confirmationEmail(sub, siteUrl), env);
      return new Response(JSON.stringify({ ok: true, grade: scan.grade, score: scan.score }), { status: 200, headers: { ...cors, 'Content-Type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Subscription failed. Please try again.' }), { status: 500, headers: cors });
    }
  }

  // POST check (called by GitHub Actions cron, protected by secret)
  if (action === 'check') {
    const secret = env.MONITOR_SECRET;
    if (secret && body.secret !== secret)
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: cors });

    try {
      const subs = await getAllSubscriptions();
      const results = [];

      for (const sub of subs) {
        try {
          const scan = await quickScan(sub.url.startsWith('http') ? sub.url : 'https://' + sub.url);
          const degraded = gradeWorse(scan.grade, sub.minGrade) && !gradeWorse(sub.lastGrade, sub.minGrade);

          if (degraded) {
            const changedHeaders = Object.keys(WEIGHTS).filter(k => {
              const wasThere = sub.lastPresent && sub.lastPresent[k];
              const nowThere = scan.present[k];
              return wasThere && !nowThere;
            }).map(k => `${k} (was present, now missing)`);

            await sendEmail(sub.email,
              `Security alert: ${sub.url} dropped to grade ${scan.grade}`,
              alertEmail(sub, scan.grade, scan.score, changedHeaders, siteUrl), env
            );
            results.push({ url: sub.url, email: sub.email, status: 'alerted', prev: sub.lastGrade, curr: scan.grade });
          } else {
            results.push({ url: sub.url, email: sub.email, status: 'ok', grade: scan.grade });
          }

          sub.lastGrade = scan.grade;
          sub.lastScore = scan.score;
          sub.lastPresent = scan.present;
          sub.lastCheck = new Date().toISOString();
          await saveSubscription(sub);
        } catch (e) {
          results.push({ url: sub.url, status: 'error', error: e.message });
        }
      }

      return new Response(JSON.stringify({ checked: subs.length, results }), { status: 200, headers: { ...cors, 'Content-Type': 'application/json' } });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: cors });
    }
  }

  return new Response(JSON.stringify({ error: 'Unknown action' }), { status: 400, headers: cors });
}
