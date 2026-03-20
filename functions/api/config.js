const RECOMMENDED = {
  'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self';",
  'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
  'x-frame-options': 'DENY',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
};

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

  const { server_type, scan_results } = await request.json();
  const serverType = (server_type || 'nginx').toLowerCase();

  const fixes = {};
  if (scan_results && scan_results.headers) {
    for (const h of scan_results.headers) { if (!h.present) fixes[h.key] = RECOMMENDED[h.key]; }
  } else { Object.assign(fixes, RECOMMENDED); }

  if (Object.keys(fixes).length === 0) {
    return new Response(JSON.stringify({ config: '# All security headers already present!', server_type: serverType, headers_added: 0 }), { status: 200, headers: { ...cors, 'Content-Type': 'application/json' } });
  }

  let config = '';

  if (serverType === 'nginx') {
    config = '# Add inside your server {} block in nginx.conf\n\n';
    for (const [k, v] of Object.entries(fixes)) config += `add_header ${k} "${v}" always;\n`;
    config += '\n# Reload nginx:\n# sudo nginx -s reload';

  } else if (serverType === 'apache') {
    config = '# Add to .htaccess or your VirtualHost block\n\n<IfModule mod_headers.c>\n';
    for (const [k, v] of Object.entries(fixes)) config += `    Header always set ${k} "${v}"\n`;
    config += '</IfModule>\n\n# Restart Apache:\n# sudo service apache2 restart';

  } else if (serverType === 'vercel') {
    const headers = Object.entries(fixes).map(([key, value]) => ({ key, value }));
    config = '// Add to vercel.json\n\n' + JSON.stringify({ headers: [{ source: '/(.*)', headers }] }, null, 2);

  } else if (serverType === 'netlify') {
    config = '# Add to netlify/_headers\n\n/*\n';
    for (const [k, v] of Object.entries(fixes)) config += `  ${k}: ${v}\n`;

  } else if (serverType === 'cloudflare') {
    config = '// Cloudflare Worker — paste into Workers editor\n\nexport default {\n  async fetch(request, env) {\n    const response = await fetch(request);\n    const newHeaders = new Headers(response.headers);\n';
    for (const [k, v] of Object.entries(fixes)) config += `    newHeaders.set('${k}', '${v}');\n`;
    config += '    return new Response(response.body, { status: response.status, headers: newHeaders });\n  }\n};';

  } else if (serverType === 'nextjs') {
    config = '// Add to next.config.js\n\nconst securityHeaders = [\n';
    for (const [k, v] of Object.entries(fixes)) config += `  {\n    key: '${k}',\n    value: '${v.replace(/'/g, "\\'")}',\n  },\n`;
    config += '];\n\nmodule.exports = {\n  async headers() {\n    return [\n      {\n        source: "/(.*)",\n        headers: securityHeaders,\n      },\n    ];\n  },\n};';

  } else if (serverType === 'express') {
    config = '// Express.js — install Helmet for one-line security:\n// npm install helmet\n\nconst helmet = require("helmet");\napp.use(helmet());\n\n// ── Or set headers manually: ──\n';
    for (const [k, v] of Object.entries(fixes)) config += `app.use((req, res, next) => { res.setHeader('${k}', '${v.replace(/'/g, "\\'")}'); next(); });\n`;

  } else if (serverType === 'django') {
    const djangoMap = {
      'strict-transport-security': 'SECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True\nSECURE_HSTS_PRELOAD = True\nSECURE_SSL_REDIRECT = True',
      'x-content-type-options':    'SECURE_CONTENT_TYPE_NOSNIFF = True',
      'x-frame-options':           "X_FRAME_OPTIONS = 'DENY'",
      'referrer-policy':           "SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'",
      'content-security-policy':   "# pip install django-csp\n# Add 'csp.middleware.CSPMiddleware' to MIDDLEWARE\nCSP_DEFAULT_SRC = (\"'self'\",)\nCSP_SCRIPT_SRC  = (\"'self'\",)\nCSP_OBJECT_SRC  = (\"'none'\",)",
      'permissions-policy':        "# Add via custom middleware or use django-permissions-policy:\n# pip install django-permissions-policy",
    };
    config = '# Add to settings.py\n\n';
    for (const k of Object.keys(fixes)) config += (djangoMap[k] || `# ${k}: set via custom middleware`) + '\n\n';

  } else if (serverType === 'laravel') {
    config = '<?php\n// Create app/Http/Middleware/SecurityHeaders.php\n\nnamespace App\\Http\\Middleware;\nuse Closure;\n\nclass SecurityHeaders\n{\n    public function handle($request, Closure $next)\n    {\n        $response = $next($request);\n';
    for (const [k, v] of Object.entries(fixes)) config += `        $response->headers->set('${k}', '${v.replace(/'/g, "\\'")}');\n`;
    config += '        return $response;\n    }\n}\n\n// Then register in app/Http/Kernel.php:\n// protected $middleware = [ ... \\App\\Http\\Middleware\\SecurityHeaders::class ];';
  }

  return new Response(JSON.stringify({ server_type: serverType, config, headers_added: Object.keys(fixes).length }), { status: 200, headers: { ...cors, 'Content-Type': 'application/json' } });
}
