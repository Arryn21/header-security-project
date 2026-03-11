const SECURITY_HEADERS = {
  'content-security-policy': {
    name: 'Content-Security-Policy',
    weight: 30,
    description: 'Prevents XSS and code injection attacks',
    fix: "Add: Content-Security-Policy: default-src 'self'"
  },
  'strict-transport-security': {
    name: 'Strict-Transport-Security (HSTS)',
    weight: 20,
    description: 'Forces HTTPS connections, prevents downgrade attacks',
    fix: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
  },
  'x-frame-options': {
    name: 'X-Frame-Options',
    weight: 15,
    description: 'Prevents clickjacking by blocking iframe embedding',
    fix: 'Add: X-Frame-Options: DENY'
  },
  'x-content-type-options': {
    name: 'X-Content-Type-Options',
    weight: 15,
    description: 'Prevents MIME-type sniffing attacks',
    fix: 'Add: X-Content-Type-Options: nosniff'
  },
  'referrer-policy': {
    name: 'Referrer-Policy',
    weight: 10,
    description: 'Controls how much referrer info is shared',
    fix: 'Add: Referrer-Policy: strict-origin-when-cross-origin'
  },
  'permissions-policy': {
    name: 'Permissions-Policy',
    weight: 10,
    description: 'Controls access to browser APIs (camera, mic, GPS)',
    fix: 'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()'
  }
};

module.exports = async function (req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'URL is required' });

  const targetUrl = url.startsWith('http') ? url : 'https://' + url;

  try {
    const response = await fetch(targetUrl, {
      method: 'GET',
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SecureHeaders-Scanner/1.0)' }
    });

    const headers = {};
    response.headers.forEach((value, key) => {
      headers[key.toLowerCase()] = value;
    });

    const results = [];
    let totalScore = 0;
    let passing = 0;

    for (const [key, config] of Object.entries(SECURITY_HEADERS)) {
      const value = headers[key] || null;
      const isPresent = value !== null;
      if (isPresent) { totalScore += config.weight; passing++; }
      results.push({
        header: config.name,
        key,
        present: isPresent,
        value,
        weight: config.weight,
        description: config.description,
        fix: isPresent ? null : config.fix
      });
    }

    const grade = totalScore >= 90 ? 'A+' : totalScore >= 80 ? 'A' : totalScore >= 70 ? 'B' : totalScore >= 55 ? 'C' : totalScore >= 40 ? 'D' : 'F';

    return res.status(200).json({
      url: targetUrl,
      score: totalScore,
      maxScore: 100,
      grade,
      scannedAt: new Date().toISOString(),
      summary: { total: results.length, passing, failing: results.length - passing },
      headers: results
    });

  } catch (err) {
    return res.status(200).json({
      url: targetUrl,
      error: true,
      errorMessage: `Could not connect to ${targetUrl}. The site may be unreachable, blocking automated requests, or the URL may be invalid.`,
      score: null,
      maxScore: 100,
      grade: null,
      scannedAt: new Date().toISOString(),
      summary: { total: 0, passing: 0, failing: 0 },
      headers: []
    });
  }
};
