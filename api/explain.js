module.exports = async function (req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const scan = req.body || {};
  const { url = 'unknown', score = 0, grade = 'F', headers = [] } = scan;

  const missing = headers.filter(h => !h.present).map(h => `- ${h.header}: ${h.description}`).join('\n');
  const passing = headers.filter(h => h.present).map(h => `- ${h.header}`).join('\n');

  const prompt = `You are a cybersecurity expert. Analyze this website's security header scan and give a concise, friendly report.

Website: ${url}
Security Score: ${score}/100 (Grade: ${grade})

MISSING headers (security risks):
${missing || 'None'}

PRESENT headers (good):
${passing || 'None'}

Provide:
1. A 2-sentence plain-English summary of the security risk level
2. Top 3 priority fixes (most critical first) with a one-line explanation of WHY each matters
3. One positive thing if any headers are present

Keep it under 200 words. Be direct and developer-friendly.`;

  const apiKey = process.env.CLAUDE_API_KEY;
  if (!apiKey) {
    return res.status(200).json({ explanation: 'AI analysis unavailable — CLAUDE_API_KEY not configured.' });
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 400,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    const data = await response.json();
    const explanation = data.content?.[0]?.text || 'Unable to generate explanation.';
    return res.status(200).json({ url, score, grade, explanation });

  } catch (err) {
    return res.status(200).json({ explanation: 'AI analysis temporarily unavailable.' });
  }
};
