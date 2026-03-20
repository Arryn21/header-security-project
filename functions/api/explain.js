async function checkRateLimit(ip, key, maxPerMinute, env) {
  const url   = env.UPSTASH_REDIS_URL;
  const token = env.UPSTASH_REDIS_TOKEN;
  if (!url || !token) return false;
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
    return count == null || count <= maxPerMinute;
  } catch { return true; }
}

async function callClaude(prompt, maxTokens, env) {
  const apiKey = env.CLAUDE_API_KEY;
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-haiku-4-5-20251001', max_tokens: maxTokens, messages: [{ role: 'user', content: prompt }] })
  });
  const data = await response.json();
  return data.content?.[0]?.text || null;
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
  if (!(await checkRateLimit(ip, 'explain', 5, env))) {
    return new Response(JSON.stringify({ error: 'Rate limit exceeded. Max 5 AI requests per minute per IP.' }), { status: 429, headers: { ...cors, 'Retry-After': '60' } });
  }

  const scan = await request.json();
  const { url = 'unknown', score = 0, grade = 'F', headers = [], mode = 'analyze', leakingHeaders = [], cspAnalysis = null, cookieAudit = [] } = scan;

  const missing = headers.filter(h => !h.present).map(h => `- ${h.header}: ${h.description}`).join('\n');
  const passing = headers.filter(h =>  h.present).map(h => `- ${h.header}`).join('\n');
  const leaking = leakingHeaders.map(h => `- ${h.header}: ${h.value}`).join('\n');
  const cspIssues = cspAnalysis?.issues?.map(i => `- [${i.severity.toUpperCase()}] ${i.message}`).join('\n') || '';
  const cookieIssues = cookieAudit.flatMap(c => c.issues.map(i => `- Cookie "${c.name}" missing ${i.flag}: ${i.message}`)).join('\n');

  try {
    if (mode === 'analyze') {
      const prompt = `You are a senior penetration tester reviewing a real website's HTTP security headers.

Website: ${url}
Score: ${score}/100 (Grade: ${grade})

MISSING security headers:
${missing || 'None — all headers present'}

PRESENT headers:
${passing || 'None'}

${leaking ? `INFORMATION LEAKAGE (server fingerprinting):\n${leaking}` : ''}
${cspIssues ? `CSP QUALITY ISSUES:\n${cspIssues}` : ''}
${cookieIssues ? `COOKIE SECURITY ISSUES:\n${cookieIssues}` : ''}

Write a security report in this exact structure:

## Risk Summary
2 sentences: overall risk level and what types of attacks are currently possible.

## Live Attack Scenarios
For the 2 most critical missing headers or issues, write a concrete attack scenario an attacker could run against ${url} RIGHT NOW. Be specific — name the attack technique, describe exactly what the attacker does and what they gain. Use realistic detail (e.g. actual XSS payload concept, actual MITM technique). Format each as:

**[Attack Name]** (exploits missing [Header])
What happens: [specific attack steps]
Attacker gains: [concrete impact — data stolen, session hijacked, etc.]

## Quick Wins
Top 3 fixes ranked by impact. One line each: what to add and why it immediately closes a real attack vector.

${passing ? '## What\'s Working\nOne sentence on the strongest protection already in place.' : ''}

Keep it under 280 words. Be direct, technical, and treat the reader as a developer who can act on this immediately.`;

      const explanation = await callClaude(prompt, 700, env) || 'Unable to generate analysis.';
      return new Response(JSON.stringify({ url, score, grade, explanation }), { status: 200, headers: { ...cors, 'Content-Type': 'application/json' } });
    }

    if (mode === 'roadmap') {
      const prompt = `You are a security engineer creating a practical remediation plan for a development team.

Website: ${url}
Current Score: ${score}/100 (Grade: ${grade})

MISSING headers (need to add):
${missing || 'None — skip header fixes'}

${leaking ? `LEAKING server info (need to remove):\n${leaking}` : ''}
${cspIssues ? `CSP problems (need to fix):\n${cspIssues}` : ''}
${cookieIssues ? `Cookie issues (need to fix):\n${cookieIssues}` : ''}

Create a realistic 30-day sprint-based remediation roadmap. Group fixes by effort and impact. Format exactly like this:

## Week 1 — Quick Wins (< 1 hour total)
List the changes that are one-liners or single config changes. Expected score after: X/100

## Week 2 — Medium Effort (2–4 hours)
List fixes that need some planning or testing. Expected score after: X/100

## Week 3 — Careful Changes (4–8 hours)
List changes that could break things if done wrong (e.g. strict CSP). Include what to test. Expected score after: X/100

## Week 4 — Polish & Monitor
Hardening steps, setting up monitoring, verifying with a rescan. Expected final score: X/100

## Expected Outcome
One sentence: grade improvement (e.g. "F → A in 30 days") and what attack vectors get closed.

Be specific about which headers go in which week and why. Keep it under 300 words.`;

      const roadmap = await callClaude(prompt, 800, env) || 'Unable to generate roadmap.';
      return new Response(JSON.stringify({ url, score, grade, roadmap }), { status: 200, headers: { ...cors, 'Content-Type': 'application/json' } });
    }

    return new Response(JSON.stringify({ error: 'Unknown mode' }), { status: 400, headers: cors });

  } catch (err) {
    return new Response(JSON.stringify({ explanation: 'AI analysis temporarily unavailable.', roadmap: 'AI roadmap temporarily unavailable.' }), { status: 200, headers: { ...cors, 'Content-Type': 'application/json' } });
  }
}
