const RECOMMENDED = {
  'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self';",
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
};

module.exports = async function (req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(204).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { server_type, scan_results } = req.body || {};
  const serverType = (server_type || 'nginx').toLowerCase();

  const fixes = {};
  if (scan_results && scan_results.headers) {
    for (const h of scan_results.headers) {
      if (!h.present) fixes[h.key] = RECOMMENDED[h.key];
    }
  } else {
    Object.assign(fixes, RECOMMENDED);
  }

  if (Object.keys(fixes).length === 0) {
    return res.status(200).json({ config: '# All security headers are already present! No changes needed.', server_type: serverType, headers_added: 0 });
  }

  let config = '';

  if (serverType === 'nginx') {
    config = '# Add inside your server {} block in nginx.conf\n\n';
    for (const [key, value] of Object.entries(fixes)) {
      config += `add_header ${key} "${value}" always;\n`;
    }
    config += '\n# Reload nginx:\n# sudo nginx -s reload';

  } else if (serverType === 'apache') {
    config = '# Add to .htaccess or VirtualHost config\n\n<IfModule mod_headers.c>\n';
    for (const [key, value] of Object.entries(fixes)) {
      config += `    Header always set ${key} "${value}"\n`;
    }
    config += '</IfModule>\n\n# Restart Apache:\n# sudo service apache2 restart';

  } else if (serverType === 'vercel') {
    const headers = Object.entries(fixes).map(([key, value]) => ({ key, value }));
    config = '// Add to vercel.json\n\n' + JSON.stringify({ headers: [{ source: '/(.*)', headers }] }, null, 2);

  } else if (serverType === 'netlify') {
    config = '# Add to netlify/_headers\n\n/*\n';
    for (const [key, value] of Object.entries(fixes)) {
      config += `  ${key}: ${value}\n`;
    }

  } else if (serverType === 'cloudflare') {
    config = '// Cloudflare Worker — add to your worker script\n\nexport default {\n  async fetch(request, env) {\n    const response = await fetch(request);\n    const newHeaders = new Headers(response.headers);\n';
    for (const [key, value] of Object.entries(fixes)) {
      config += `    newHeaders.set('${key}', '${value}');\n`;
    }
    config += '    return new Response(response.body, { status: response.status, headers: newHeaders });\n  }\n};';
  }

  return res.status(200).json({ server_type: serverType, config, headers_added: Object.keys(fixes).length });
};
