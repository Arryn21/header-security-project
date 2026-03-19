// Email monitoring — subscribe/unsubscribe/check
// Requires env vars: RESEND_API_KEY, UPSTASH_REDIS_URL, UPSTASH_REDIS_TOKEN, MONITOR_SECRET
// Storage: Upstash Redis (REST API — no npm needed)
// Email:   Resend       (REST API — no npm needed)

const SITE_URL = 'https://secureheaders-scanner.netlify.app';
const SCAN_URL = `${SITE_URL}/.netlify/functions/scan`;

async function checkRateLimit(ip, key, max, windowSeconds) {
  const url   = process.env.UPSTASH_REDIS_URL;
  const token = process.env.UPSTASH_REDIS_TOKEN;
  if (!url || !token) return true;
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
    return count <= max;
  } catch { return true; }
}

const GRADE_ORDER = ['A+', 'A', 'B', 'C', 'D', 'F'];

function gradeIndex(g) { return GRADE_ORDER.indexOf(g); }
function gradeWorse(a, b) { return gradeIndex(a) > gradeIndex(b); } // true if a is worse than b

// ── Upstash Redis helpers ──────────────────────────────────────────

async function redis(cmd, ...args) {
  const url   = process.env.UPSTASH_REDIS_URL;
  const token = process.env.UPSTASH_REDIS_TOKEN;
  if (!url || !token) throw new Error('Upstash env vars not set');

  const res = await fetch(`${url}/${[cmd, ...args].map(encodeURIComponent).join('/')}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  const data = await res.json();
  return data.result;
}

async function getSubscription(email, url) {
  const key = `sub:${email}:${Buffer.from(url).toString('base64')}`;
  const raw = await redis('GET', key);
  return raw ? JSON.parse(raw) : null;
}

async function saveSubscription(sub) {
  const key = `sub:${sub.email}:${Buffer.from(sub.url).toString('base64')}`;
  await redis('SET', key, JSON.stringify(sub));
  await redis('SADD', 'all_subs', key);
}

async function deleteSubscription(email, url) {
  const key = `sub:${email}:${Buffer.from(url).toString('base64')}`;
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

// ── Resend email helper ────────────────────────────────────────────

async function sendEmail(to, subject, html) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error('RESEND_API_KEY not set');

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: 'SecureHeaders Scanner <onboarding@resend.dev>',
      to: [to],
      subject,
      html
    })
  });
  return res.json();
}

function confirmationEmail(sub) {
  const unsubLink = `${SITE_URL}/.netlify/functions/monitor?action=unsubscribe&email=${encodeURIComponent(sub.email)}&url=${encodeURIComponent(sub.url)}`;
  return `
    <div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0f1117;color:#e2e8f0;border-radius:12px;overflow:hidden;">
      <div style="background:#1a1d27;padding:24px 32px;border-bottom:1px solid #2a2d3e;">
        <h2 style="margin:0;color:#fff;">SecureHeaders <span style="color:#3b82f6;">Scanner</span></h2>
      </div>
      <div style="padding:32px;">
        <h3 style="color:#22c55e;margin-top:0;">Monitoring activated!</h3>
        <p style="color:#8892a4;">You're now subscribed to weekly security alerts for:</p>
        <div style="background:#0a0c14;border:1px solid #2a2d3e;border-radius:8px;padding:12px 16px;font-family:monospace;color:#3b82f6;margin:16px 0;">${sub.url}</div>
        <p style="color:#8892a4;">You'll get an email if the security grade drops below <strong style="color:#fff;">${sub.minGrade}</strong>.</p>
        <p style="color:#8892a4;">Current grade: <strong style="color:#fff;">${sub.lastGrade} (${sub.lastScore}/100)</strong></p>
        <hr style="border-color:#2a2d3e;margin:24px 0;">
        <p style="font-size:13px;color:#8892a4;">
          <a href="${unsubLink}" style="color:#ef4444;text-decoration:none;">Unsubscribe</a> ·
          <a href="${SITE_URL}" style="color:#3b82f6;text-decoration:none;">Open Scanner</a>
        </p>
      </div>
    </div>`;
}

function alertEmail(sub, newGrade, newScore, changedHeaders) {
  const scanLink = `${SITE_URL}/#report`;
  const unsubLink = `${SITE_URL}/.netlify/functions/monitor?action=unsubscribe&email=${encodeURIComponent(sub.email)}&url=${encodeURIComponent(sub.url)}`;
  const changes = changedHeaders.length
    ? `<ul style="color:#8892a4;padding-left:20px;">${changedHeaders.map(h => `<li>${h}</li>`).join('')}</ul>`
    : '';
  return `
    <div style="font-family:system-ui,sans-serif;max-width:600px;margin:0 auto;background:#0f1117;color:#e2e8f0;border-radius:12px;overflow:hidden;">
      <div style="background:#450a0a;padding:24px 32px;border-bottom:1px solid #7f1d1d;">
        <h2 style="margin:0;color:#fff;">Security Grade Alert</h2>
      </div>
      <div style="padding:32px;">
        <p style="color:#8892a4;margin-top:0;">The security grade for <strong style="color:#fff;">${sub.url}</strong> has dropped:</p>
        <div style="display:flex;align-items:center;gap:16px;font-size:2.5rem;font-weight:800;margin:24px 0;">
          <span style="color:#22c55e;">${sub.lastGrade}</span>
          <span style="color:#8892a4;font-size:1.2rem;">→</span>
          <span style="color:#ef4444;">${newGrade}</span>
        </div>
        <p style="color:#8892a4;">Score: <strong style="color:#fff;">${sub.lastScore} → ${newScore} / 100</strong></p>
        ${changes ? `<p style="color:#8892a4;">Headers that changed:</p>${changes}` : ''}
        <a href="${SITE_URL}" style="display:inline-block;margin-top:16px;padding:12px 24px;background:#3b82f6;color:#fff;border-radius:8px;text-decoration:none;font-weight:600;">View Full Report</a>
        <hr style="border-color:#2a2d3e;margin:24px 0;">
        <p style="font-size:13px;color:#8892a4;">
          <a href="${unsubLink}" style="color:#ef4444;text-decoration:none;">Unsubscribe</a> ·
          <a href="${SITE_URL}" style="color:#3b82f6;text-decoration:none;">Open Scanner</a>
        </p>
      </div>
    </div>`;
}

// ── Quick scan (reused from scan.js logic) ─────────────────────────

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

// ── Handler ────────────────────────────────────────────────────────

const ALLOWED_ORIGIN = 'https://secureheaders-scanner.netlify.app';

exports.handler = async function(event) {
  const origin = event.headers?.origin || '';
  const cors = {
    'Access-Control-Allow-Origin': origin === ALLOWED_ORIGIN ? origin : ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Vary': 'Origin'
  };
  if (event.httpMethod === 'OPTIONS') return { statusCode: 204, headers: cors, body: '' };

  // ── GET: unsubscribe via link in email ──
  if (event.httpMethod === 'GET') {
    const { action, email, url } = event.queryStringParameters || {};
    if (action === 'unsubscribe' && email && url) {
      try {
        await deleteSubscription(email, url);
        return {
          statusCode: 200, headers: { 'Content-Type': 'text/html' },
          body: `<html><body style="font-family:system-ui;background:#0f1117;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;">
            <div style="text-align:center;padding:2rem;">
              <h2 style="color:#22c55e;">Unsubscribed</h2>
              <p style="color:#8892a4;">You'll no longer receive alerts for ${url}</p>
              <a href="${SITE_URL}" style="color:#3b82f6;">Back to Scanner</a>
            </div></body></html>`
        };
      } catch (e) {
        console.error('monitor unsubscribe error:', e.message);
        return { statusCode: 500, headers: cors, body: JSON.stringify({ error: 'Unsubscribe failed. Please try again.' }) };
      }
    }
    return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'Invalid request' }) };
  }

  if (event.httpMethod !== 'POST') return { statusCode: 405, headers: cors, body: JSON.stringify({ error: 'Method not allowed' }) };

  const body = JSON.parse(event.body || '{}');
  const { action } = body;

  // ── POST subscribe ──
  if (action === 'subscribe') {
    const { email, url, minGrade = 'B' } = body;
    if (!email || !url) return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'email and url required' }) };

    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email)) return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'Invalid email address' }) };

    const ip = (event.headers?.['x-forwarded-for'] || event.headers?.['client-ip'] || '').split(',')[0].trim() || 'unknown';
    if (!(await checkRateLimit(ip, 'monitor-sub', 3, 600))) {
      return { statusCode: 429, headers: { ...cors, 'Retry-After': '600' },
               body: JSON.stringify({ error: 'Rate limit exceeded. Max 3 subscriptions per 10 minutes per IP.' }) };
    }

    try {
      const scan = await quickScan(url.startsWith('http') ? url : 'https://' + url);
      const sub = {
        email, url, minGrade,
        lastGrade: scan.grade, lastScore: scan.score, lastPresent: scan.present,
        createdAt: new Date().toISOString(), lastCheck: new Date().toISOString()
      };
      await saveSubscription(sub);
      await sendEmail(email, `Monitoring activated for ${url}`, confirmationEmail(sub));
      return { statusCode: 200, headers: { ...cors, 'Content-Type': 'application/json' }, body: JSON.stringify({ ok: true, grade: scan.grade, score: scan.score }) };
    } catch (e) {
      console.error('monitor subscribe error:', e.message);
      return { statusCode: 500, headers: cors, body: JSON.stringify({ error: 'Subscription failed. Please try again.' }) };
    }
  }

  // ── POST check (called by GitHub Actions cron, protected by secret) ──
  if (action === 'check') {
    const secret = process.env.MONITOR_SECRET;
    if (secret && body.secret !== secret)
      return { statusCode: 401, headers: cors, body: JSON.stringify({ error: 'Unauthorized' }) };

    try {
      const subs = await getAllSubscriptions();
      const results = [];

      for (const sub of subs) {
        try {
          const scan = await quickScan(sub.url.startsWith('http') ? sub.url : 'https://' + sub.url);
          const degraded = gradeWorse(scan.grade, sub.minGrade) && !gradeWorse(sub.lastGrade, sub.minGrade);
          const anyChange = scan.grade !== sub.lastGrade;

          if (degraded) {
            // Find which headers changed
            const changedHeaders = Object.keys(WEIGHTS).filter(k => {
              const wasThere = sub.lastPresent && sub.lastPresent[k];
              const nowThere = scan.present[k];
              return wasThere && !nowThere;
            }).map(k => `${k} (was present, now missing)`);

            await sendEmail(sub.email,
              `Security alert: ${sub.url} dropped to grade ${scan.grade}`,
              alertEmail(sub, scan.grade, scan.score, changedHeaders)
            );
            results.push({ url: sub.url, email: sub.email, status: 'alerted', prev: sub.lastGrade, curr: scan.grade });
          } else {
            results.push({ url: sub.url, email: sub.email, status: 'ok', grade: scan.grade });
          }

          // Update stored grade
          sub.lastGrade = scan.grade;
          sub.lastScore = scan.score;
          sub.lastPresent = scan.present;
          sub.lastCheck = new Date().toISOString();
          await saveSubscription(sub);
        } catch (e) {
          results.push({ url: sub.url, status: 'error', error: e.message });
        }
      }

      return { statusCode: 200, headers: { ...cors, 'Content-Type': 'application/json' }, body: JSON.stringify({ checked: subs.length, results }) };
    } catch (e) {
      return { statusCode: 500, headers: cors, body: JSON.stringify({ error: e.message }) };
    }
  }

  return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'Unknown action' }) };
};
