  const SCAN_URL = '/api/scan';
  const CONFIG_URL = '/api/config';
  const EXPLAIN_URL = '/api/explain';
  let currentScan = null;
  let currentServer = 'nginx';

  function setUrl(url) {
    document.getElementById('urlInput').value = url;
  }

  function show(id) { document.getElementById(id).style.display = 'block'; }
  function hide(id) { document.getElementById(id).style.display = 'none'; }

  async function runScan() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) {
      document.getElementById('urlInput').style.outline = '2px solid #ef4444';
      document.getElementById('urlInput').placeholder = 'Please enter a URL first';
      setTimeout(() => {
        document.getElementById('urlInput').style.outline = '';
        document.getElementById('urlInput').placeholder = 'https://yourwebsite.com';
      }, 2000);
      return;
    }

    // Normalize URL
    const targetUrl = url.startsWith('http') ? url : 'https://' + url;

    // Reset UI
    hide('results');
    hide('subscandResults');
    document.getElementById('sharedBanner').style.display = 'none';
    document.getElementById('errorBox').innerHTML = '';
    document.getElementById('diffBanner').style.display = 'none';
    if (location.hash) history.replaceState(null, '', location.pathname);
    show('loading');
    document.getElementById('scanBtn').disabled = true;
    document.getElementById('aiText').innerHTML = '<span class="ai-loading">Generating AI analysis...</span>';

    try {
      // 1. Scan headers
      const scanRes = await fetch(SCAN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl })
      });

      if (!scanRes.ok) throw new Error(`Scan failed: ${scanRes.status}`);
      const scan = await scanRes.json();
      currentScan = scan;

      // 2. Render results
      hide('loading');
      show('results');

      // Handle graceful error from backend (unreachable site, DNS failure, etc.)
      if (scan.error) {
        document.getElementById('errorBox').innerHTML =
          `<div class="error-box">${scan.errorMessage}</div>`;
        document.getElementById('scoreCard').style.display = 'none';
        document.getElementById('headersList').innerHTML = '';
        document.getElementById('configCode').textContent = '# No config to generate — site could not be reached.';
        document.getElementById('aiText').innerHTML = '<span class="ai-loading">AI analysis unavailable — site could not be reached.</span>';
        return;
      }

      document.getElementById('scoreCard').style.display = '';

      // Before/after comparison
      const prevSnapshot = loadFromHistory(scan.url);
      renderDiff(prevSnapshot, scan);
      saveToHistory(scan);

      renderScore(scan);
      renderHeaders(scan.headers, scan.cspAnalysis);
      renderLeakage(scan.leakingHeaders || []);
      renderProgressive(scan.progressiveScores || [], scan.score, scan.grade);
      renderCookieAudit(scan.cookieAudit || []);
      renderCors(scan.corsAnalysis);

      // 3. Load config (non-blocking)
      loadConfig(currentServer);

      // 4. Load AI explanation (non-blocking, also stores in currentScan for sharing)
      loadAIExplanation(scan);

      // 5. Show share bar, roadmap, monitor, CI/CD
      document.getElementById('shareBar').style.display = 'flex';
      document.getElementById('roadmapSection').style.display = 'block';
      document.getElementById('monitorSection').style.display = 'block';
      document.getElementById('cicdSection').style.display = 'block';
      renderCicd();

    } catch (err) {
      hide('loading');
      show('results');
      document.getElementById('errorBox').innerHTML =
        `<div class="error-box">Error: ${err.message}. Make sure the URL is accessible.</div>`;
    } finally {
      document.getElementById('scanBtn').disabled = false;
    }
  }

  function gradeColor(g) {
    return { 'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16', 'C': '#f59e0b', 'D': '#f97316', 'F': '#ef4444' }[g] || '#ef4444';
  }

  function gradeChipClass(g) {
    return { 'A+': 'chip-green', 'A': 'chip-green', 'B': 'chip-lime', 'C': 'chip-yellow', 'D': 'chip-orange', 'F': 'chip-red' }[g] || 'chip-red';
  }

  const COMPLIANCE_URLS = {
    'OWASP A01:2021': 'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
    'OWASP A02:2021': 'https://owasp.org/Top10/A02_2021-Cryptographic_Failures/',
    'OWASP A03:2021': 'https://owasp.org/Top10/A03_2021-Injection/',
    'OWASP A05:2021': 'https://owasp.org/Top10/A05_2021-Security_Misconfiguration/',
    'PCI DSS 4.2.1':  'https://www.pcisecuritystandards.org/document_library/',
    'PCI DSS 6.4.1':  'https://www.pcisecuritystandards.org/document_library/',
    'PCI DSS 6.4.3':  'https://www.pcisecuritystandards.org/document_library/',
    'GDPR Art.25':    'https://gdpr-info.eu/art-25-gdpr/',
    'GDPR Art.32':    'https://gdpr-info.eu/art-32-gdpr/',
    'HIPAA §164.312(e)': 'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
    'HIPAA §164.514':    'https://www.hhs.gov/hipaa/for-professionals/security/laws-regulations/index.html',
  };

  function complianceTag(tag) {
    const cls = tag.startsWith('OWASP') ? 'ctag-owasp' : tag.startsWith('PCI') ? 'ctag-pci' : tag.startsWith('GDPR') ? 'ctag-gdpr' : 'ctag-hipaa';
    const url = COMPLIANCE_URLS[tag];
    if (url) return `<a href="${url}" target="_blank" rel="noopener" class="ctag ${cls}">${tag}</a>`;
    return `<span class="ctag ${cls}">${tag}</span>`;
  }

  function renderScore(scan) {
    const circle = document.getElementById('scoreCircle');
    const color = gradeColor(scan.grade);
    circle.style.borderColor = color;
    circle.style.color = color;
    document.getElementById('gradeText').textContent = scan.grade;
    document.getElementById('scoreText').textContent = `${scan.score}/100`;

    const headlines = {
      'A+': 'Excellent security posture!', 'A': 'Strong security headers.',
      'B': 'Good, but room to improve.', 'C': 'Several issues found.',
      'D': 'Significant gaps in security.', 'F': 'Critical security headers missing.'
    };
    document.getElementById('scoreHeadline').textContent = headlines[scan.grade] || 'Scan complete.';

    let sub = `${scan.summary.passing} of ${scan.summary.total} headers passing`;
    if (scan.penalty > 0) sub += ` · <span style="color:var(--yellow)">-${scan.penalty} pts leakage penalty</span>`;
    sub += ` · scanned ${new Date(scan.scannedAt).toLocaleTimeString()}`;
    document.getElementById('scoreSubline').innerHTML = sub;
  }

  function renderHeaders(headers, cspAnalysis) {
    const list = document.getElementById('headersList');
    list.innerHTML = headers.map((h, i) => {
      const isCsp = h.key === 'content-security-policy';
      let cspBlock = '';
      if (isCsp && h.present && cspAnalysis) {
        const gradeColor = { A: 'chip-green', C: 'chip-yellow', D: 'chip-orange', F: 'chip-red' }[cspAnalysis.grade] || 'chip-yellow';
        const issueRows = cspAnalysis.issues.map(issue =>
          `<div class="csp-issue"><span class="${issue.severity === 'critical' ? 'sev-critical' : 'sev-warning'}">${issue.severity.toUpperCase()}</span><span>${escHtml(issue.message)}</span></div>`
        ).join('');
        cspBlock = `
          <div class="csp-analysis">
            <div class="csp-grade-row">
              <span class="grade-chip ${gradeColor}">${cspAnalysis.grade}</span>
              <span class="csp-grade-label">${escHtml(cspAnalysis.label)} · ${cspAnalysis.directiveCount} directives</span>
            </div>
            ${issueRows || '<div style="font-size:0.8rem;color:var(--green)">No issues found — CSP is well configured.</div>'}
          </div>`;
      }
      const refsHtml = (h.refs && h.refs.length) ? `
        <div class="refs-row">
          <span class="refs-label">Official docs:</span>
          ${h.refs.map(r => `<a href="${r.url}" target="_blank" rel="noopener" class="ref-link">${r.label}</a>`).join('')}
        </div>` : '';

      return `
        <div class="header-row ${h.present ? 'pass' : 'fail'}">
          <div class="header-info">
            <div class="header-name">${h.header}</div>
            <div class="header-desc">${h.present ? h.description : h.fix}</div>
            ${h.present && h.value ? `<div class="header-value">${escHtml(h.value)}</div>` : ''}
            ${h.compliance ? `<div class="compliance-row">${h.compliance.map(complianceTag).join('')}</div>` : ''}
            ${refsHtml}
            ${h.realWorldExample ? `
              <div class="cve-block">
                <button class="cve-toggle" data-cve-id="cve-${i}">Real-world attack example</button>
                <div class="cve-text" id="cve-${i}">${escHtml(h.realWorldExample)}</div>
              </div>` : ''}
            ${cspBlock}
          </div>
          <span class="badge ${h.present ? 'badge-pass' : 'badge-fail'}">${h.present ? 'PASS' : 'MISSING'}</span>
        </div>`;
    }).join('');

    // Event delegation for CVE toggles (avoids inline onclick blocked by CSP)
    list.addEventListener('click', e => {
      const btn = e.target.closest('.cve-toggle');
      if (!btn) return;
      const el = document.getElementById(btn.dataset.cveId);
      el.classList.toggle('open');
      btn.textContent = el.classList.contains('open') ? 'Hide example' : 'Real-world attack example';
    });
  }

  function renderLeakage(leaking) {
    const section = document.getElementById('leakageSection');
    const list = document.getElementById('leakageList');
    if (!leaking.length) { section.style.display = 'none'; return; }
    section.style.display = 'block';
    list.innerHTML = leaking.map(h => `
      <div class="header-row danger">
        <div class="header-info">
          <div class="header-name">${h.header}</div>
          <div class="header-desc">${h.description}</div>
          <div class="header-value">${escHtml(h.value)}</div>
          <div class="penalty-note">Fix: ${escHtml(h.fix)}</div>
        </div>
        <span class="badge badge-danger">-${h.penalty} pts</span>
      </div>
    `).join('');
  }

  function renderProgressive(scores, currentScore, currentGrade) {
    const section = document.getElementById('progressSection');
    const list = document.getElementById('progressList');
    if (!scores.length) { section.style.display = 'none'; return; }
    section.style.display = 'block';
    list.innerHTML = scores.map(s => `
      <div class="progress-row">
        <div class="progress-header-name">${s.header}</div>
        <div class="progress-arrow">
          <span class="grade-chip ${gradeChipClass(currentGrade)}">${currentGrade}</span>
          <span style="color:var(--muted)">→</span>
          <span class="grade-chip ${gradeChipClass(s.newGrade)}">${s.newGrade}</span>
          <span style="color:var(--green);font-size:0.82rem">${s.newScore}/100</span>
        </div>
        <span class="weight-pill">+${s.weight} pts</span>
      </div>
    `).join('');
  }

  function renderCookieAudit(cookies) {
    const section = document.getElementById('cookieSection');
    const list = document.getElementById('cookieList');
    if (!cookies.length) { section.style.display = 'none'; return; }
    section.style.display = 'block';
    list.innerHTML = cookies.map(c => {
      const hasIssues = c.issues.length > 0;
      const flagHtml = [
        `<span class="${c.hasSecure ? 'flag-ok' : 'flag-bad'}">Secure${c.hasSecure ? ' ✓' : ' ✗'}</span>`,
        `<span class="${c.hasHttpOnly ? 'flag-ok' : 'flag-bad'}">HttpOnly${c.hasHttpOnly ? ' ✓' : ' ✗'}</span>`,
        c.sameSite
          ? `<span class="${c.sameSite === 'strict' || c.sameSite === 'lax' ? 'flag-ok' : 'flag-warn'}">SameSite=${c.sameSite}</span>`
          : `<span class="flag-bad">SameSite ✗</span>`
      ].join('');
      const issueHtml = c.issues.map(i =>
        `<div class="cookie-issue" style="color:${i.severity === 'critical' ? 'var(--red)' : i.severity === 'high' ? '#f97316' : 'var(--yellow)'}">⚠ ${escHtml(i.message)}</div>`
      ).join('');
      return `
        <div class="cookie-card ${hasIssues ? 'has-issues' : 'clean'}">
          <div class="cookie-name">${escHtml(c.name)}</div>
          <div class="cookie-flags">${flagHtml}</div>
          ${issueHtml}
        </div>`;
    }).join('');
  }

  function renderCors(cors) {
    const section = document.getElementById('corsSection');
    const content = document.getElementById('corsContent');
    if (!cors || !cors.issues.length) { section.style.display = 'none'; return; }
    const isCritical = cors.issues.some(i => i.severity === 'critical');
    section.style.display = 'block';
    section.className = `cors-section ${isCritical ? 'cors-critical' : 'cors-warning'}`;
    content.innerHTML = `
      <div style="font-size:0.88rem;margin-bottom:0.5rem">
        <span style="color:var(--muted)">Access-Control-Allow-Origin:</span>
        <span style="color:var(--blue);font-family:monospace;margin-left:0.4rem">${escHtml(cors.origin)}</span>
        <span style="color:var(--muted);margin-left:1rem">credentials:</span>
        <span style="color:var(--blue);font-family:monospace;margin-left:0.4rem">${escHtml(cors.credentials)}</span>
      </div>
      ${cors.issues.map(i => `
        <div style="font-size:0.85rem;color:${i.severity === 'critical' ? 'var(--red)' : 'var(--yellow)'};padding:0.4rem 0;border-top:1px solid var(--border)">
          ${i.severity === 'critical' ? 'CRITICAL' : 'WARNING'}: ${escHtml(i.message)}
        </div>`).join('')}`;
  }

  async function loadConfig(serverType) {
    if (!currentScan) return;
    document.getElementById('configCode').textContent = 'Generating config...';
    try {
      const res = await fetch(CONFIG_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ server_type: serverType, scan_results: currentScan })
      });
      const data = await res.json();
      document.getElementById('configCode').textContent = data.config;
    } catch (e) {
      document.getElementById('configCode').textContent = '# Error generating config. Please try again.';
    }
  }

  function switchTab(server, el) {
    currentServer = server;
    document.querySelectorAll('#serverTabs .tab').forEach(t => t.classList.remove('active'));
    el.classList.add('active');
    loadConfig(server);
  }

  // ── CI/CD Integration ──────────────────────────────────────────────

  let currentCicdTab = 'gha';

  function switchCicdTab(tab, el) {
    currentCicdTab = tab;
    document.querySelectorAll('.cicd-tabs .tab').forEach(t => t.classList.remove('active'));
    el.classList.add('active');
    renderCicd();
  }

  function renderCicd() {
    if (!currentScan) return;
    const url = currentScan.url;
    const grade = document.getElementById('cicdGrade').value;
    const apiUrl = '/api/scan';
    const gradeOrder = ['A+', 'A', 'B', 'C', 'D', 'F'];

    let code = '';

    if (currentCicdTab === 'gha') {
      code = `# .github/workflows/security-headers.yml
# Fails if your site's security grade drops below ${grade}

name: Security Headers Check

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 9 * * 1'   # Every Monday at 9am

jobs:
  check-headers:
    runs-on: ubuntu-latest
    steps:
      - name: Scan security headers
        run: |
          RESULT=$(curl -s -X POST ${apiUrl} \\
            -H "Content-Type: application/json" \\
            -d '{"url":"${url}"}')

          GRADE=$(echo $RESULT | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('grade','F'))")
          SCORE=$(echo $RESULT | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('score',0))")

          echo "Security Grade: $GRADE (Score: $SCORE/100)"

          GRADES="A+ A B C D F"
          MIN_GRADE="${grade}"

          for g in $GRADES; do
            if [ "$g" = "$GRADE" ]; then break; fi
            if [ "$g" = "$MIN_GRADE" ]; then
              echo "FAIL: Grade $GRADE is below minimum $MIN_GRADE"
              exit 1
            fi
          done

          echo "PASS: Security headers meet minimum grade $MIN_GRADE"`;
    }

    else if (currentCicdTab === 'npm') {
      code = `// package.json — add to your "scripts" section:
{
  "scripts": {
    "check:headers": "node check-headers.js"
  }
}

// check-headers.js — save in your project root:
const MIN_GRADE = '${grade}';
const SITE_URL  = '${url}';
const GRADE_ORDER = ['A+', 'A', 'B', 'C', 'D', 'F'];

async function run() {
  const res = await fetch('${apiUrl}', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: SITE_URL })
  });
  const data = await res.json();
  const { grade, score } = data;

  console.log(\`Security Grade: \${grade} (Score: \${score}/100)\`);

  const gradeIdx = GRADE_ORDER.indexOf(grade);
  const minIdx   = GRADE_ORDER.indexOf(MIN_GRADE);

  if (gradeIdx === -1 || gradeIdx > minIdx) {
    console.error(\`FAIL: Grade \${grade} is below minimum \${MIN_GRADE}\`);
    process.exit(1);
  }
  console.log(\`PASS: Security headers meet minimum grade \${MIN_GRADE}\`);
}

run().catch(err => { console.error(err); process.exit(1); });

// Run with: npm run check:headers`;
    }

    else if (currentCicdTab === 'shell') {
      code = `#!/bin/bash
# check-headers.sh — run manually or add to any CI pipeline
# Usage: bash check-headers.sh
# Fails (exit 1) if grade is below ${grade}

SITE_URL="${url}"
MIN_GRADE="${grade}"
API_URL="${apiUrl}"

RESULT=$(curl -s -X POST "$API_URL" \\
  -H "Content-Type: application/json" \\
  -d "{\\"url\\":\\"$SITE_URL\\"}")

GRADE=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('grade','F'))")
SCORE=$(echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('score',0))")

echo "Site:   $SITE_URL"
echo "Grade:  $GRADE"
echo "Score:  $SCORE / 100"

GRADES="A+ A B C D F"
for g in $GRADES; do
  if [ "$g" = "$GRADE" ]; then
    echo "PASS: Meets minimum grade $MIN_GRADE"
    exit 0
  fi
  if [ "$g" = "$MIN_GRADE" ]; then
    echo "FAIL: Grade $GRADE is below minimum $MIN_GRADE"
    exit 1
  fi
done`;
    }

    document.getElementById('cicdCode').textContent = code;
  }

  function copyCicd() {
    const text = document.getElementById('cicdCode').textContent;
    const btn = document.getElementById('cicdCopyBtn');
    try {
      navigator.clipboard.writeText(text).then(() => {
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
      }).catch(() => {});
    } catch (_e) {}
  }

  function copyConfig() {
    const text = document.getElementById('configCode').textContent;
    const btn = document.getElementById('configCopyBtn');
    try {
      navigator.clipboard.writeText(text).then(() => {
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
      }).catch(() => {});
    } catch (_e) {}
  }

  function escHtml(str) {
    return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }


  // ── Markdown renderer ──────────────────────────────────────────────
  function renderMd(text) {
    if (!text) return '';
    const lines = text.split('\n');
    let html = '';
    let inList = false;

    for (const line of lines) {
      // Headings
      if (line.startsWith('## ')) {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<h2>${mdInline(line.slice(3))}</h2>`; continue;
      }
      if (line.match(/^#{3,4} /)) {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<h3>${mdInline(line.replace(/^#{3,4} /, ''))}</h3>`; continue;
      }
      if (line.startsWith('# ')) {
        if (inList) { html += '</ul>'; inList = false; }
        html += `<h2>${mdInline(line.slice(2))}</h2>`; continue;
      }
      // HR
      if (/^---+$/.test(line.trim())) {
        if (inList) { html += '</ul>'; inList = false; }
        html += '<hr>'; continue;
      }
      // Bullet
      if (/^[-*] /.test(line)) {
        if (!inList) { html += '<ul>'; inList = true; }
        html += `<li>${mdInline(line.slice(2))}</li>`; continue;
      }
      // Empty line
      if (line.trim() === '') {
        if (inList) { html += '</ul>'; inList = false; }
        continue;
      }
      // Paragraph
      if (inList) { html += '</ul>'; inList = false; }
      html += `<p>${mdInline(line)}</p>`;
    }
    if (inList) html += '</ul>';
    return html;
  }

  function mdInline(text) {
    return escHtml(text)
      .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*([^*]+?)\*/g,  '<em>$1</em>')
      .replace(/`([^`]+)`/g,     '<code>$1</code>');
  }

  // ── Email Monitoring ──────────────────────────────────────────────

  const MONITOR_URL = '/api/monitor';

  async function subscribeMonitor() {
    const email    = document.getElementById('monitorEmail').value.trim();
    const minGrade = document.getElementById('monitorMinGrade').value;
    const status   = document.getElementById('monitorStatus');

    if (!email || !currentScan) return;
    if (!email.includes('@')) {
      status.innerHTML = '<div class="monitor-error">Please enter a valid email address.</div>';
      return;
    }

    const btn = document.getElementById('monitorBtn');
    btn.disabled = true;
    btn.textContent = 'Subscribing...';
    status.innerHTML = '';

    try {
      const res = await fetch(MONITOR_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'subscribe', email, url: currentScan.url, minGrade })
      });
      const data = await res.json();

      if (data.ok) {
        status.innerHTML = `<div class="monitor-success">
          Subscribed! Current grade: <strong>${data.grade} (${data.score}/100)</strong>.
          You'll get an email at <strong>${email}</strong> if the grade drops below <strong>${minGrade}</strong>.
          Check your inbox for a confirmation.
        </div>`;
        btn.textContent = 'Subscribed';
      } else {
        throw new Error(data.error || 'Subscription failed');
      }
    } catch (e) {
      status.innerHTML = `<div class="monitor-error">Error: ${e.message}. The monitoring service may not be configured yet — see setup instructions.</div>`;
      btn.disabled = false;
      btn.textContent = 'Notify Me';
    }
  }

  // ── Before/After Comparison ───────────────────────────────────────

  const HISTORY_PREFIX = 'sh_scan_';

  function saveToHistory(scan) {
    const key = HISTORY_PREFIX + scan.url;
    const snapshot = {
      score: scan.score,
      grade: scan.grade,
      scannedAt: scan.scannedAt,
      headers: scan.headers.map(h => ({ key: h.key, present: h.present })),
      leakingCount: (scan.leakingHeaders || []).length,
      leakingKeys: (scan.leakingHeaders || []).map(l => l.key)
    };
    try { localStorage.setItem(key, JSON.stringify(snapshot)); } catch {}
  }

  function loadFromHistory(url) {
    try { return JSON.parse(localStorage.getItem(HISTORY_PREFIX + url) || 'null'); } catch { return null; }
  }

  function timeSince(isoString) {
    const secs = Math.floor((Date.now() - new Date(isoString)) / 1000);
    if (secs < 60)   return `${secs}s ago`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400)return `${Math.floor(secs / 3600)}h ago`;
    return `${Math.floor(secs / 86400)}d ago`;
  }

  function renderDiff(prev, curr) {
    const banner = document.getElementById('diffBanner');
    if (!prev) { banner.style.display = 'none'; return; }

    const scoreDelta = curr.score - prev.score;
    const deltaClass = scoreDelta > 0 ? 'delta-up' : scoreDelta < 0 ? 'delta-down' : 'delta-same';
    const deltaText  = scoreDelta > 0 ? `+${scoreDelta} pts` : scoreDelta < 0 ? `${scoreDelta} pts` : 'no change';

    // Header diffs
    const prevMap = Object.fromEntries(prev.headers.map(h => [h.key, h.present]));
    const currMap = Object.fromEntries(curr.headers.map(h => [h.key, h.present]));
    const fixed   = curr.headers.filter(h => !prevMap[h.key] && h.present).map(h => h.header || h.key);
    const broken  = curr.headers.filter(h =>  prevMap[h.key] && !h.present).map(h => h.header || h.key);

    // Leakage diffs
    const prevLeaks = new Set(prev.leakingKeys || []);
    const currLeaks = new Set((curr.leakingHeaders || []).map(l => l.key));
    const newLeaks  = [...currLeaks].filter(k => !prevLeaks.has(k));
    const fixedLeaks= [...prevLeaks].filter(k => !currLeaks.has(k));

    // Build pills
    const pills = [];
    if (fixed.length)      pills.push(`<span class="diff-pill pill-fixed">${fixed.length} header${fixed.length>1?'s':''} fixed</span>`);
    if (broken.length)     pills.push(`<span class="diff-pill pill-broken">${broken.length} header${broken.length>1?'s':''} regressed</span>`);
    if (fixedLeaks.length) pills.push(`<span class="diff-pill pill-leak-fix">${fixedLeaks.length} leak${fixedLeaks.length>1?'s':''} removed</span>`);
    if (newLeaks.length)   pills.push(`<span class="diff-pill pill-leak-new">${newLeaks.length} new leak${newLeaks.length>1?'s':''}</span>`);
    if (!pills.length)     pills.push(`<span class="diff-pill pill-nochange">No changes since last scan</span>`);

    const prevColor = gradeColor(prev.grade);
    const currColor = gradeColor(curr.grade);

    banner.style.display = 'block';
    banner.innerHTML = `
      <div class="diff-top">
        <div class="diff-grade-flow">
          <span style="color:${prevColor}">${prev.grade}</span>
          <span class="diff-arrow">→</span>
          <span style="color:${currColor}">${curr.grade}</span>
        </div>
        <span class="diff-score-delta ${deltaClass}">${deltaText}</span>
        <span class="diff-meta">vs scan ${timeSince(prev.scannedAt)}</span>
      </div>
      <div class="diff-changes">${pills.join('')}</div>`;
  }

  // ── Subdomain Scanner ─────────────────────────────────────────────

  const SUBSCAN_URL = '/api/subscan';

  async function runSubScan() {
    const raw = document.getElementById('urlInput').value.trim();
    if (!raw) {
      document.getElementById('urlInput').style.outline = '2px solid #ef4444';
      document.getElementById('urlInput').placeholder = 'Please enter a domain first';
      setTimeout(() => {
        document.getElementById('urlInput').style.outline = '';
        document.getElementById('urlInput').placeholder = 'https://yourwebsite.com';
      }, 2000);
      return;
    }

    const domain = raw.replace(/^https?:\/\//, '').split('/')[0];
    const body   = document.getElementById('subscanBody');
    const section = document.getElementById('subscandResults');

    section.style.display = 'block';
    document.getElementById('subScanBtn').disabled = true;
    document.getElementById('subscanSummary').textContent = `Scanning subdomains of ${domain}...`;
    body.innerHTML = `<div class="subscan-loading"><div class="subscan-spinner"></div>Checking 12 subdomains in parallel — takes ~8 seconds...</div>`;

    // Scroll to subdomain section
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });

    try {
      const res = await fetch(SUBSCAN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain })
      });
      const data = await res.json();
      renderSubScan(data);
    } catch (e) {
      body.innerHTML = `<div style="color:var(--red);font-size:0.9rem;padding:1rem 0">Error running subdomain scan: ${e.message}</div>`;
    } finally {
      document.getElementById('subScanBtn').disabled = false;
    }
  }

  function gradeColorHex(g) {
    return { 'A+': '#22c55e', 'A': '#22c55e', 'B': '#84cc16', 'C': '#f59e0b', 'D': '#f97316', 'F': '#ef4444' }[g] || '#ef4444';
  }

  function renderSubScan(data) {
    const body    = document.getElementById('subscanBody');
    const summary = document.getElementById('subscanSummary');
    const reachable = data.scanned.filter(s => s.reachable);

    summary.textContent = `${data.reachableCount} of ${data.total} subdomains reachable on ${data.domain}`;

    const cards = data.scanned.map(s => {
      if (!s.reachable) {
        return `<div class="sub-card unreachable">
          <div class="sub-name">${s.subdomain}.${data.domain}</div>
          <div class="sub-unreachable">Unreachable</div>
        </div>`;
      }
      const color = gradeColorHex(s.grade);
      const leakBadges = s.leaking && s.leaking.length
        ? s.leaking.map(l => `<span class="sub-flag sub-leak">${l.header}</span>`).join('')
        : '';
      return `<div class="sub-card" onclick="loadSubdomainScan('${escHtml(s.url)}')">
        <div class="sub-name">${s.subdomain}.${data.domain}</div>
        <div class="sub-grade" style="color:${color}">${s.grade}</div>
        <div class="sub-score">${s.score}/100 · ${s.passing}/${s.total} headers</div>
        ${leakBadges ? `<div class="sub-flags">${leakBadges}</div>` : ''}
        <div class="sub-click-hint">Click to full scan →</div>
      </div>`;
    });

    body.innerHTML = `<div class="subscan-grid">${cards.join('')}</div>`;
  }

  function loadSubdomainScan(url) {
    document.getElementById('urlInput').value = url;
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setTimeout(() => runScan(), 300);
  }

  // ── Shareable Reports ──────────────────────────────────────────────

  function encodeReport(scan) {
    const json = JSON.stringify(scan);
    // UTF-8 safe base64
    return btoa(unescape(encodeURIComponent(json)));
  }

  function decodeReport(encoded) {
    try {
      return JSON.parse(decodeURIComponent(escape(atob(encoded))));
    } catch { return null; }
  }

  function shareReport(btn) {

    if (!currentScan) {
      btn.textContent = 'Scan first!';
      setTimeout(() => { btn.textContent = 'Copy Link'; }, 2000);
      return;
    }

    // Immediate feedback — user knows the click registered
    btn.textContent = 'Copying...';

    const encoded = encodeReport(currentScan);
    const shareUrl = `${location.origin}${location.pathname}#report/${encoded}`;

    // Show the URL box
    const box = document.getElementById('shareUrlBox');
    box.textContent = shareUrl.length > 80 ? shareUrl.slice(0, 77) + '...' : shareUrl;
    box.style.display = 'block';

    const onSuccess = () => {
      btn.textContent = 'Copied!';
      btn.style.background = '#22c55e';
      setTimeout(() => { btn.textContent = 'Copy Link'; btn.style.background = ''; }, 2500);
    };
    const onFail = () => {
      btn.textContent = 'Copy manually';
      box.style.outline = '2px solid #3b82f6';
      setTimeout(() => { btn.textContent = 'Copy Link'; box.style.outline = ''; }, 3000);
    };

    try {
      navigator.clipboard.writeText(shareUrl).then(onSuccess).catch(onFail);
    } catch (_e) {
      onFail();
    }
  }

  function newScan() {
    // Clear hash and reset to fresh state
    history.replaceState(null, '', location.pathname);
    document.getElementById('sharedBanner').style.display = 'none';
    document.getElementById('shareBar').style.display = 'none';
    document.getElementById('results').style.display = 'none';
    document.getElementById('urlInput').value = '';
    document.getElementById('urlInput').focus();
  }

  function renderFromSharedData(scan) {
    currentScan = scan;
    document.getElementById('sharedBanner').style.display = 'flex';
    document.getElementById('sharedBannerMeta').textContent =
      `${scan.url} · scanned ${new Date(scan.scannedAt).toLocaleString()}`;

    hide('loading');
    show('results');
    document.getElementById('errorBox').innerHTML = '';
    document.getElementById('scoreCard').style.display = '';

    renderScore(scan);
    renderHeaders(scan.headers, scan.cspAnalysis);
    renderLeakage(scan.leakingHeaders || []);
    renderProgressive(scan.progressiveScores || [], scan.score, scan.grade);
    renderCookieAudit(scan.cookieAudit || []);
    renderCors(scan.corsAnalysis);

    // Config — generate fresh (free, no stored data needed)
    loadConfig(currentServer);

    // AI explanation stored in scan data
    if (scan.aiExplanation) {
      document.getElementById('aiText').innerHTML = renderMd(scan.aiExplanation);
    } else {
      document.getElementById('aiText').innerHTML = '<span class="ai-loading">AI analysis not included in this shared report.</span>';
    }

    // Roadmap stored in scan data
    if (scan.aiRoadmap) {
      document.getElementById('roadmapText').innerHTML = renderMd(scan.aiRoadmap);
      document.getElementById('roadmapBtn').textContent = 'Regenerate';
    }

    // Show share bar, roadmap, monitor, CI/CD
    document.getElementById('shareBar').style.display = 'flex';
    document.getElementById('roadmapSection').style.display = 'block';
    document.getElementById('monitorSection').style.display = 'block';
    document.getElementById('cicdSection').style.display = 'block';
    renderCicd();
  }

  // Check for shared report in URL hash on page load
  function loadFromHash() {
    const hash = location.hash;
    if (!hash.startsWith('#report/')) return;
    const encoded = hash.slice('#report/'.length);
    const scan = decodeReport(encoded);
    if (scan && scan.url) {
      document.getElementById('urlInput').value = scan.url;
      renderFromSharedData(scan);
    }
  }

  // Store AI explanation in currentScan so it's included in shared reports
  async function loadAIExplanation(scan) {
    try {
      const res = await fetch(EXPLAIN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...scan, mode: 'analyze' })
      });
      const data = await res.json();
      const explanation = data.explanation || 'No explanation available.';
      document.getElementById('aiText').innerHTML = renderMd(explanation);
      if (currentScan) currentScan.aiExplanation = explanation;
    } catch (e) {
      document.getElementById('aiText').innerHTML = '<span class="ai-loading">AI analysis unavailable. Your scan results are shown above.</span>';
    }
  }

  // ── AI Remediation Roadmap ─────────────────────────────────────────

  async function loadRoadmap() {
    if (!currentScan) return;
    const btn  = document.getElementById('roadmapBtn');
    const text = document.getElementById('roadmapText');

    btn.disabled = true;
    btn.textContent = 'Generating...';
    text.innerHTML = '<span class="roadmap-loading">Building your 30-day fix plan — usually takes 5–10 seconds...</span>';

    try {
      const res = await fetch(EXPLAIN_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...currentScan, mode: 'roadmap' })
      });
      const data = await res.json();
      const roadmap = data.roadmap || 'Unable to generate roadmap.';
      text.innerHTML = renderMd(roadmap);
      if (currentScan) currentScan.aiRoadmap = roadmap;
      btn.textContent = 'Regenerate';
    } catch (e) {
      text.innerHTML = '<span class="ai-loading">Roadmap generation failed. Please try again.</span>';
      btn.textContent = 'Generate Roadmap';
    } finally {
      btn.disabled = false;
    }
  }

  document.addEventListener('DOMContentLoaded', () => {
    hide('subscandResults');
    hide('results');
    document.getElementById('sharedBanner').style.display = 'none';
    loadFromHash();

    // Wire up all buttons (CSP blocks inline onclick, so we use addEventListener)
    document.getElementById('scanBtn').addEventListener('click', runScan);
    document.getElementById('subScanBtn').addEventListener('click', runSubScan);
    document.getElementById('dismissBtn').addEventListener('click', () => {
      document.getElementById('subscandResults').style.display = 'none';
    });
    document.getElementById('rescanBtn').addEventListener('click', newScan);
    document.getElementById('configCopyBtn').addEventListener('click', copyConfig);
    document.getElementById('roadmapBtn').addEventListener('click', loadRoadmap);
    document.getElementById('monitorBtn').addEventListener('click', subscribeMonitor);
    document.getElementById('cicdCopyBtn').addEventListener('click', copyCicd);
    document.getElementById('cicdGrade').addEventListener('change', renderCicd);
    document.getElementById('shareBtn').addEventListener('click', () => shareReport(document.getElementById('shareBtn')));

    document.querySelectorAll('.url-example').forEach(a => {
      a.addEventListener('click', e => { e.preventDefault(); setUrl(a.dataset.url); });
    });
    document.querySelectorAll('#serverTabs .tab').forEach(btn => {
      btn.addEventListener('click', () => switchTab(btn.dataset.server, btn));
    });
    document.querySelectorAll('.cicd-tabs .tab').forEach(btn => {
      btn.addEventListener('click', () => switchCicdTab(btn.dataset.tab, btn));
    });

    // Allow Enter key to trigger scan
    document.getElementById('urlInput').addEventListener('keydown', e => {
      if (e.key === 'Enter') runScan();
    });
  });
