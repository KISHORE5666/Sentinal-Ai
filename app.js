/* =============================================
   app.js – Router, SOC Dashboard & Auto-Response
   ============================================= */

let currentPage      = 'dashboard';
let currentPatchPage = 'dashboard';

/* ═══════════════════════════════════════════
   ROUTING
═══════════════════════════════════════════ */
function showPage(page) {
  currentPage = page;
  // Refresh auth session on activity
  if (typeof auth !== 'undefined' && auth.currentUser) auth._startSessionTimer();

  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const pageLabels = {
    dashboard:'SOC Dashboard', patch:'Patch Management',
    copilot:'AI Copilot', threat:'Threat Intelligence',
    mitre:'MITRE ATT&CK', reports:'Reports',
  };
  document.querySelectorAll('.nav-item').forEach(el => {
    if (el.textContent.trim().includes(pageLabels[page] || page))
      el.classList.add('active');
  });

  if (page === 'patch')     renderPatchModule('dashboard');
  else if (page === 'reports') renderPatchModule('reports');
  else if (page === 'copilot') _renderPage(renderCopilot());
  else if (page === 'threat')  { renderThreatModule(); }
  else if (page === 'mitre')   _renderPage(renderMitreAttack());
  else renderSOCDashboard();
}

function _renderPage(html) {
  document.getElementById('mainContent').innerHTML = html;
}

function showPatchPage(sub)       { currentPatchPage = sub; renderPatchModule(sub); }
function refreshPatchSubPage(sub) { renderPatchModule(sub || currentPatchPage); }

function renderPatchModule(subPage) {
  currentPatchPage = subPage;
  const main = document.getElementById('mainContent');
  const tabs = [
    {id:'dashboard', label:'📊 Dashboard'},
    {id:'repo',      label:'📦 Repository'},
    {id:'assign',    label:'📌 Assignment'},
    {id:'monitor',   label:'📡 Monitoring'},
    {id:'reports',   label:'📋 Reports'},
  ];
  const subNav = `<div style="background:var(--bg-card);border-bottom:1px solid var(--border);padding:0 32px;display:flex;gap:4px;">
    ${tabs.map(t=>`<button onclick="showPatchPage('${t.id}')"
      style="padding:10px 16px;background:none;border:none;border-bottom:2px solid ${subPage===t.id?'var(--accent)':'transparent'};
      color:${subPage===t.id?'var(--accent)':'var(--text-2)'};cursor:pointer;font-family:inherit;font-size:13px;
      font-weight:${subPage===t.id?600:400};transition:all .18s;">${t.label}</button>`).join('')}
  </div>`;
  let content = '';
  if      (subPage==='dashboard') content = renderPatchDashboard();
  else if (subPage==='repo')      content = renderPatchRepo();
  else if (subPage==='assign')    content = renderPatchAssignment();
  else if (subPage==='monitor')   content = renderMonitor();
  else if (subPage==='reports')   content = renderReports();
  main.innerHTML = subNav + content;
  if (subPage==='dashboard') requestAnimationFrame(()=>requestAnimationFrame(initDashboardCharts));
}

/* ═══════════════════════════════════════════
   SOC DASHBOARD — Overhauled
═══════════════════════════════════════════ */
function renderSOCDashboard() {
  const main    = document.getElementById('mainContent');
  const s       = db.stats();
  const as      = db.alertStats();
  const risk    = db.overallRisk();
  const alerts  = db.getAlerts().filter(a => a.status !== 'Resolved').slice(0, 8);
  const assets  = db.getAssets();
  const sevColor = { Critical:'var(--red)', High:'var(--orange)', Medium:'var(--yellow)', Low:'var(--green)' };
  const statIcon = { Open:'🔴', Investigating:'🟡', Resolved:'✅' };

  main.innerHTML = `
<div class="page-header fade-in">
  <div>
    <div class="page-title">🛡️ SOC Overview Dashboard</div>
    <div class="page-sub">Real-time security posture — Sentinel AI v2.0</div>
  </div>
  <div style="display:flex;align-items:center;gap:12px;">
    <div style="display:flex;align-items:center;gap:6px;font-size:12px;color:var(--green);">
      <span class="dot dot-green pulse"></span>All Systems Operational
    </div>
    <button class="btn btn-ghost btn-sm" onclick="renderSOCDashboard()">🔄 Refresh</button>
    ${auth.canDo('automated_response') ? `<button class="btn btn-primary btn-sm" onclick="showPage('copilot');generateNewAlert()">⚡ Inject Alert</button>` : ''}
  </div>
</div>

<div class="page-body fade-in">

  <!-- Top Stats Row -->
  <div class="stats-grid" style="grid-template-columns:repeat(6,1fr);">
    <div class="stat-card red">
      <div class="stat-label">Critical Alerts</div>
      <div class="stat-value red">${as.critical}</div>
      <div class="stat-sub">Open & unresolved</div>
    </div>
    <div class="stat-card orange">
      <div class="stat-label">High Alerts</div>
      <div class="stat-value" style="color:var(--orange);">${as.high}</div>
      <div class="stat-sub">Open & unresolved</div>
    </div>
    <div class="stat-card yellow">
      <div class="stat-label">Investigating</div>
      <div class="stat-value yellow">${as.invest}</div>
      <div class="stat-sub">In progress</div>
    </div>
    <div class="stat-card green">
      <div class="stat-label">Compliance Rate</div>
      <div class="stat-value green">${s.compliance}%</div>
      <div class="stat-sub">Patch compliance</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-label">Patches Pending</div>
      <div class="stat-value blue">${s.pending}</div>
      <div class="stat-sub">Awaiting deploy</div>
    </div>
    <div class="stat-card purple">
      <div class="stat-label">ML Confidence</div>
      <div class="stat-value" style="color:var(--accent2);">${as.avgConf}%</div>
      <div class="stat-sub">Avg detection conf.</div>
    </div>
  </div>

  <!-- Row 2: Risk Gauge + Alert Feed + Asset Health -->
  <div style="display:grid;grid-template-columns:200px 1fr 300px;gap:16px;margin-bottom:20px;">

    <!-- Risk Gauge -->
    <div class="panel">
      <div class="panel-header"><div class="panel-title">⚡ Risk Score</div></div>
      <div class="panel-body" style="text-align:center;padding:20px 16px;">
        <div style="position:relative;display:inline-flex;align-items:center;justify-content:center;margin-bottom:12px;">
          <canvas id="riskGaugeCanvas" width="140" height="140"></canvas>
          <div style="position:absolute;text-align:center;">
            <div style="font-size:26px;font-weight:800;color:${risk.color};">${risk.score}</div>
            <div style="font-size:9px;color:var(--text-3);text-transform:uppercase;letter-spacing:.06em;">/ 100</div>
          </div>
        </div>
        <div style="font-size:14px;font-weight:700;color:${risk.color};">● ${risk.level} Risk</div>
        <div style="font-size:10px;color:var(--text-3);margin-top:4px;">Organization-wide</div>
        <div style="margin-top:14px;display:flex;flex-direction:column;gap:6px;">
          ${assets.map(a => {
            const r = db.riskScore(a.id);
            return `<div style="display:flex;align-items:center;gap:6px;font-size:10px;">
              <span style="color:${r.color};">●</span>
              <span style="color:var(--text-2);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${a.name}</span>
              <span style="color:${r.color};font-weight:600;">${r.score}</span>
            </div>`;
          }).join('')}
        </div>
      </div>
    </div>

    <!-- Live Alert Feed -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🚨 Live Threat Feed</div>
        <div style="display:flex;gap:6px;align-items:center;">
          <span class="dot dot-red pulse"></span>
          <span style="font-size:11px;color:var(--text-3);" id="feedLastUpdate">Live</span>
          <button class="btn btn-ghost btn-sm" onclick="showPage('copilot')">View All →</button>
        </div>
      </div>
      <div style="max-height:320px;overflow-y:auto;" id="dashAlertFeed">
        ${alerts.map(al => `
        <div class="dash-alert-item" onclick="showPage('copilot');setTimeout(()=>selectCopilotAlert('${al.id}'),100)">
          <div style="display:flex;align-items:center;gap:8px;padding:10px 16px;border-bottom:1px solid rgba(99,120,220,.06);cursor:pointer;transition:background .15s;">
            <span style="font-size:16px;">${al.severity==='Critical'?'🔴':al.severity==='High'?'🟠':'🟡'}</span>
            <div style="flex:1;min-width:0;">
              <div style="font-size:12px;font-weight:600;color:var(--text-1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${al.title}</div>
              <div style="font-size:10px;color:var(--text-3);">${al.asset} · ${timeAgo(al.timestamp)} · ${al.technique}</div>
            </div>
            <div style="flex-shrink:0;text-align:right;">
              <span class="badge" style="background:${sevColor[al.severity]}22;color:${sevColor[al.severity]};font-size:9px;">${al.severity}</span>
              <div style="font-size:10px;color:var(--accent);font-weight:600;margin-top:2px;">${al.confidence}%</div>
            </div>
          </div>
        </div>`).join('') || '<div style="padding:40px;text-align:center;color:var(--text-3);">No open alerts 🎉</div>'}
      </div>
    </div>

    <!-- Asset Health Map -->
    <div class="panel">
      <div class="panel-header"><div class="panel-title">💻 Asset Health Map</div></div>
      <div class="panel-body" style="padding:14px;">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
          ${assets.map(a => {
            const r = db.riskScore(a.id);
            const openAlerts = db.getAlerts().filter(al => al.assetId === a.id && al.status !== 'Resolved').length;
            return `
            <div class="asset-health-card" style="border-color:${r.color}33;cursor:pointer;" onclick="showPage('patch');showPatchPage('monitor')" title="${a.name} — ${r.level} Risk">
              <div style="display:flex;align-items:center;gap:6px;margin-bottom:4px;">
                <span style="color:${r.color};font-size:16px;">${a.type==='Server'?'🖥️':a.type==='Workstation'?'💻':'🔌'}</span>
                <div>
                  <div style="font-size:10px;font-weight:700;color:var(--text-1);">${a.name}</div>
                  <div style="font-size:9px;color:var(--text-3);">${a.type}</div>
                </div>
              </div>
              <div style="display:flex;justify-content:space-between;align-items:center;">
                <div style="font-size:16px;font-weight:800;color:${r.color};">${r.score}</div>
                ${openAlerts > 0 ? `<span class="badge" style="background:${r.color}22;color:${r.color};font-size:9px;">${openAlerts} alerts</span>` : '<span style="font-size:9px;color:var(--green);">✅ Clean</span>'}
              </div>
              <div class="progress-bar" style="height:3px;margin-top:6px;">
                <div class="progress-fill" style="width:${r.score}%;background:${r.color};"></div>
              </div>
            </div>`;
          }).join('')}
        </div>
      </div>
    </div>
  </div>

  <!-- Row 3: Automated Response + MITRE Quick + Patch Summary -->
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;">

    <!-- Automated Response Playbooks -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🤖 Response Playbooks</div>
        <span class="tag">${db.getPlaybooks().filter(pb=>pb.enabled).length} active</span>
      </div>
      <div class="panel-body" style="padding:10px 14px;">
        ${db.getPlaybooks().map(pb => `
        <div style="display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:1px solid rgba(99,120,220,.06);">
          <div class="playbook-status-dot" style="background:${pb.enabled?'var(--green)':'var(--text-3)'};"></div>
          <div style="flex:1;min-width:0;">
            <div style="font-size:11px;font-weight:600;color:var(--text-1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${pb.name}</div>
            <div style="font-size:9px;color:var(--text-3);">${pb.actions.slice(0,2).join(', ')}${pb.actions.length>2?'…':''}</div>
          </div>
          ${auth.canDo('automated_response') ? `
          <label class="toggle-switch" title="${pb.enabled?'Disable':'Enable'} playbook">
            <input type="checkbox" ${pb.enabled?'checked':''} onchange="db.togglePlaybook('${pb.id}');renderSOCDashboard()"/>
            <span class="toggle-slider"></span>
          </label>` : `<span style="font-size:9px;color:${pb.enabled?'var(--green)':'var(--text-3)'};">${pb.enabled?'ON':'OFF'}</span>`}
        </div>`).join('')}
      </div>
    </div>

    <!-- MITRE ATT&CK Quick View -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🗡️ ATT&CK Coverage</div>
        <button class="btn btn-ghost btn-sm" onclick="showPage('mitre')">Full Matrix →</button>
      </div>
      <div class="panel-body" style="padding:10px 14px;">
        ${(() => {
          const topTactics = ATTACK_MATRIX.slice(0, 6);
          return topTactics.map(t => {
            const hits = t.techniques.reduce((s,tc)=>s+tc.hits,0);
            const cov  = Math.round((t.techniques.filter(tc=>tc.hits>0).length/t.techniques.length)*100);
            return `<div style="display:flex;align-items:center;gap:8px;padding:5px 0;">
              <div style="width:90px;font-size:9px;color:var(--text-2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${t.tactic}">${t.tactic}</div>
              <div class="progress-bar" style="flex:1;height:6px;">
                <div class="progress-fill" style="width:${cov}%;background:${t.color};"></div>
              </div>
              <div style="font-size:9px;color:${t.color};font-weight:600;width:28px;text-align:right;">${cov}%</div>
              <div style="font-size:9px;color:var(--text-3);width:28px;text-align:right;">${hits}h</div>
            </div>`;
          }).join('');
        })()}
        <div style="margin-top:10px;padding-top:8px;border-top:1px solid var(--border);display:flex;justify-content:space-between;font-size:10px;color:var(--text-3);">
          <span>Overall ATT&CK Coverage</span>
          <span style="color:var(--accent);font-weight:700;">${Math.round((ATTACK_MATRIX.reduce((s,t)=>s+t.techniques.filter(tc=>tc.hits>0).length,0)/ATTACK_MATRIX.reduce((s,t)=>s+t.techniques.length,0))*100)}%</span>
        </div>
      </div>
    </div>

    <!-- Patch Compliance Summary -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🔧 Patch Summary</div>
        <button class="btn btn-ghost btn-sm" onclick="showPage('patch')">Manage →</button>
      </div>
      <div class="panel-body" style="padding:10px 14px;">
        ${[['Successful','var(--green)','✅',s.success],['Failed','var(--red)','❌',s.failed],['Pending','var(--yellow)','⏳',s.pending],['Total Deployments','var(--blue)','📦',s.totalDep]].map(([l,c,icon,v])=>`
        <div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid rgba(99,120,220,.06);">
          <span style="font-size:14px;">${icon}</span>
          <div style="flex:1;font-size:11px;color:var(--text-2);">${l}</div>
          <div style="font-size:16px;font-weight:700;color:${c};">${v}</div>
        </div>`).join('')}
        <div style="margin-top:10px;">
          <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:5px;">
            <span style="color:var(--text-2);">Compliance Rate</span>
            <span style="color:var(--green);font-weight:700;">${s.compliance}%</span>
          </div>
          <div class="progress-bar" style="height:8px;">
            <div class="progress-fill" style="width:${s.compliance}%;background:var(--green);"></div>
          </div>
        </div>
      </div>
    </div>

  </div>
</div>`;

  // Draw risk gauge
  requestAnimationFrame(() => {
    const canvas = document.getElementById('riskGaugeCanvas');
    if (canvas) _drawRiskGauge(canvas, risk.score, risk.color);
  });

  // Live feed auto-refresh
  clearInterval(window._dashInterval);
  window._dashInterval = setInterval(() => {
    const feed = document.getElementById('dashAlertFeed');
    const upd  = document.getElementById('feedLastUpdate');
    if (!feed) { clearInterval(window._dashInterval); return; }
    const freshAlerts = db.getAlerts().filter(a => a.status !== 'Resolved').slice(0, 8);
    feed.innerHTML = freshAlerts.map(al => `
    <div style="display:flex;align-items:center;gap:8px;padding:10px 16px;border-bottom:1px solid rgba(99,120,220,.06);cursor:pointer;transition:background .15s;"
      onclick="showPage('copilot');setTimeout(()=>selectCopilotAlert('${al.id}'),100)">
      <span style="font-size:16px;">${al.severity==='Critical'?'🔴':al.severity==='High'?'🟠':'🟡'}</span>
      <div style="flex:1;min-width:0;">
        <div style="font-size:12px;font-weight:600;color:var(--text-1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${al.title}</div>
        <div style="font-size:10px;color:var(--text-3);">${al.asset} · ${timeAgo(al.timestamp)}</div>
      </div>
      <span class="badge" style="background:${{Critical:'var(--red)',High:'var(--orange)',Medium:'var(--yellow)',Low:'var(--green)'}[al.severity]}22;color:${{Critical:'var(--red)',High:'var(--orange)',Medium:'var(--yellow)',Low:'var(--green)'}[al.severity]};font-size:9px;">${al.severity}</span>
    </div>`).join('') || '<div style="padding:30px;text-align:center;color:var(--text-3);">No open alerts 🎉</div>';
    if (upd) upd.textContent = 'Updated ' + new Date().toLocaleTimeString();
  }, 15000);
}

function _drawRiskGauge(canvas, score, color) {
  const W = 140, H = 140;
  canvas.width = W; canvas.height = H;
  const ctx = canvas.getContext('2d');
  const cx = W/2, cy = H/2 + 10, r = 55, lw = 10;
  const start = -Math.PI * 1.1;
  const end   = start + (score / 100) * Math.PI * 2.2;
  ctx.clearRect(0, 0, W, H);
  // Track
  ctx.beginPath(); ctx.arc(cx, cy, r, start, start + Math.PI * 2.2);
  ctx.strokeStyle = 'rgba(99,120,220,.12)'; ctx.lineWidth = lw; ctx.lineCap = 'round';
  ctx.stroke();
  // Fill with gradient
  const grad = ctx.createLinearGradient(0, 0, W, 0);
  grad.addColorStop(0, '#22d3a0');
  grad.addColorStop(0.5, '#fbbf24');
  grad.addColorStop(1, color);
  ctx.beginPath(); ctx.arc(cx, cy, r, start, end);
  ctx.strokeStyle = grad; ctx.lineWidth = lw; ctx.lineCap = 'round';
  ctx.stroke();
}

/* ── Bootstrap ── */
window.addEventListener('DOMContentLoaded', () => {
  if (typeof auth !== 'undefined') {
    const isAuthed = auth.init();
    if (isAuthed) {
      _bootApp();
    } else {
      showLoginScreen();
    }
  } else {
    showPage('patch');
  }
});
