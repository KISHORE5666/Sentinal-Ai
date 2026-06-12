/* =============================================
   patch.js – Patch Management Module
   All render functions for:
     - Dashboard, Repository, Assignment,
       Monitoring, Reports
   ============================================= */

/* ── Utility ─────────────────────────────── */
function severityBadge(s) {
  const map = { Critical:'badge-critical', High:'badge-high', Medium:'badge-medium', Low:'badge-low' };
  return `<span class="badge ${map[s]||'badge-info'}">${s}</span>`;
}

function statusBadge(s) {
  const map = {
    'Pending':'badge-pending','Scheduled':'badge-scheduled',
    'In Progress':'badge-inprogress','Successful':'badge-success',
    'Failed':'badge-failed','Rolled Back':'badge-rolledback'
  };
  return `<span class="badge ${map[s]||'badge-info'}">${s}</span>`;
}

function fmtDate(d) {
  if (!d) return '—';
  const dt = new Date(d + 'T00:00:00');
  return dt.toLocaleDateString('en-GB',{day:'2-digit',month:'short',year:'numeric'});
}

function toast(msg, type='success') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span>${type==='success'?'✅':'❌'}</span><span>${msg}</span>`;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

/* ══════════════════════════════════════════
   1. PATCH DASHBOARD
══════════════════════════════════════════ */
function renderPatchDashboard() {
  const s = db.stats();
  const asgn = db.getAssignments();

  // Trend data: count by month
  const months = {};
  asgn.forEach(a => {
    if (!a.scheduled_date) return;
    const m = a.scheduled_date.slice(0,7);
    if (!months[m]) months[m] = {success:0,failed:0};
    if (a.status==='Successful') months[m].success++;
    if (a.status==='Failed') months[m].failed++;
  });
  const trendKeys = Object.keys(months).sort().slice(-6);

  // Severity breakdown
  const patches = db.getPatches();
  const sev = {Critical:0,High:0,Medium:0,Low:0};
  patches.forEach(p => { if(sev[p.severity]!==undefined) sev[p.severity]++; });

  return `
<div class="page-header fade-in">
  <div>
    <div class="page-title">🔧 Patch Management Dashboard</div>
    <div class="page-sub">Real-time overview of patch operations and compliance</div>
  </div>
  <div style="display:flex;gap:8px;">
    <button class="btn btn-ghost btn-sm" onclick="showPatchPage('repo')">📦 Repository</button>
    <button class="btn btn-primary btn-sm" onclick="openAddPatch()">＋ Add Patch</button>
  </div>
</div>
<div class="page-body fade-in">
  <!-- Stats -->
  <div class="stats-grid">
    <div class="stat-card blue">
      <div class="stat-label">Total Patches</div>
      <div class="stat-value blue">${s.total}</div>
      <div class="stat-sub">In repository</div>
    </div>
    <div class="stat-card yellow">
      <div class="stat-label">Pending / Scheduled</div>
      <div class="stat-value yellow">${s.pending}</div>
      <div class="stat-sub">Awaiting deployment</div>
    </div>
    <div class="stat-card red">
      <div class="stat-label">Failed Deployments</div>
      <div class="stat-value red">${s.failed}</div>
      <div class="stat-sub">Require attention</div>
    </div>
    <div class="stat-card green">
      <div class="stat-label">Compliance Rate</div>
      <div class="stat-value green">${s.compliance}%</div>
      <div class="stat-sub">${s.success} successful of ${s.totalDep} total</div>
    </div>
    <div class="stat-card purple">
      <div class="stat-label">Total Deployments</div>
      <div class="stat-value purple">${s.totalDep}</div>
      <div class="stat-sub">Across all assets</div>
    </div>
  </div>

  <!-- Row 2 -->
  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px;">
    <!-- Deployment Trend -->
    <div class="panel" style="grid-column:span 2;">
      <div class="panel-header">
        <div class="panel-title">📈 Deployment Trend</div>
        <span class="tag">Last 6 months</span>
      </div>
      <div class="panel-body">
        <div class="chart-container"><canvas id="trendChart"></canvas></div>
      </div>
    </div>
    <!-- Severity Breakdown -->
    <div class="panel">
      <div class="panel-header"><div class="panel-title">🎯 Severity Breakdown</div></div>
      <div class="panel-body">
        <div class="chart-container"><canvas id="sevChart"></canvas></div>
      </div>
    </div>
  </div>

  <!-- Row 3 -->
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;">
    <!-- Compliance Gauge -->
    <div class="panel">
      <div class="panel-header"><div class="panel-title">✅ Compliance Score</div></div>
      <div class="panel-body">
        <div class="compliance-ring-wrap">
          <canvas id="complianceChart" width="160" height="160"></canvas>
          <div class="ring-label" style="margin-top:-100px;position:relative;z-index:2;">${s.compliance}%</div>
          <div class="ring-sub" style="position:relative;z-index:2;">Patch Compliance</div>
        </div>
        <div style="margin-top:16px;">
          ${renderComplianceBar('Successful', s.success, s.totalDep, 'var(--green)')}
          ${renderComplianceBar('Failed', s.failed, s.totalDep, 'var(--red)')}
          ${renderComplianceBar('Pending/Scheduled', s.pending, s.totalDep, 'var(--yellow)')}
        </div>
      </div>
    </div>
    <!-- Recent Activity -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🕐 Recent Deployments</div>
        <button class="btn btn-ghost btn-sm" onclick="showPatchPage('monitor')">View All</button>
      </div>
      <div class="panel-body" style="padding:0;">
        <table><thead><tr>
          <th>Patch</th><th>Asset</th><th>Status</th>
        </tr></thead><tbody>
          ${asgn.slice(-6).reverse().map(a => {
            const p = db.getPatch(a.patch_id)||{patch_name:'—'};
            const as= db.getAsset(a.asset_id)||{name:'—'};
            return `<tr>
              <td style="max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${p.patch_name}</td>
              <td>${as.name}</td>
              <td>${statusBadge(a.status)}</td>
            </tr>`;
          }).join('')}
        </tbody></table>
      </div>
    </div>
  </div>
</div>`;
}

function renderComplianceBar(label, val, total, color) {
  const pct = total ? Math.round((val/total)*100) : 0;
  return `<div style="margin-bottom:10px;">
    <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--text-2);margin-bottom:4px;">
      <span>${label}</span><span style="color:${color}">${val} (${pct}%)</span>
    </div>
    <div class="progress-bar"><div class="progress-fill" style="width:${pct}%;background:${color};"></div></div>
  </div>`;
}

function initDashboardCharts() {
  const asgn = db.getAssignments();
  const months = {};
  asgn.forEach(a => {
    if (!a.scheduled_date) return;
    const m = a.scheduled_date.slice(0,7);
    if (!months[m]) months[m] = {success:0,failed:0};
    if (a.status==='Successful') months[m].success++;
    if (a.status==='Failed') months[m].failed++;
  });
  const trendKeys = Object.keys(months).sort().slice(-6);

  // Trend Chart
  const tc = document.getElementById('trendChart');
  if (tc) {
    const ctx = tc.getContext('2d');
    const labels = trendKeys.map(k => { const [y,m]=k.split('-'); return new Date(+y,+m-1).toLocaleString('default',{month:'short'})+' '+y; });
    const succData = trendKeys.map(k => months[k].success);
    const failData = trendKeys.map(k => months[k].failed);
    drawBarChart(ctx, tc, labels, [
      {label:'Successful', data: succData, color:'#22d3a0'},
      {label:'Failed',     data: failData, color:'#f87171'},
    ]);
  }

  // Severity pie
  const sc = document.getElementById('sevChart');
  if (sc) {
    const patches = db.getPatches();
    const sev = {Critical:0,High:0,Medium:0,Low:0};
    patches.forEach(p => { if(sev[p.severity]!==undefined) sev[p.severity]++; });
    const ctx = sc.getContext('2d');
    drawDoughnutChart(ctx, sc, Object.keys(sev), Object.values(sev),
      ['#f87171','#fb923c','#fbbf24','#22d3a0']);
  }

  // Compliance donut
  const cc = document.getElementById('complianceChart');
  if (cc) {
    const s = db.stats();
    const ctx = cc.getContext('2d');
    const pct = s.compliance;
    drawGaugeChart(ctx, cc, pct);
  }
}

/* ── Mini Canvas Charts (no library) ── */
function drawBarChart(ctx, canvas, labels, datasets) {
  const W = canvas.offsetWidth || 400, H = 160;
  canvas.width = W; canvas.height = H;
  const pad = {t:10,r:10,b:30,l:30};
  const cW = W-pad.l-pad.r, cH = H-pad.t-pad.b;
  const n = labels.length;
  const groupW = cW/n;
  const barW = (groupW - 8) / datasets.length;
  const maxVal = Math.max(1,...datasets.flatMap(d=>d.data));

  ctx.clearRect(0,0,W,H);
  ctx.font = '10px Inter, sans-serif';
  ctx.fillStyle = '#555e80';

  // Grid lines
  for (let i=0;i<=4;i++) {
    const y = pad.t + cH - (i/4)*cH;
    ctx.strokeStyle='rgba(99,120,220,.1)'; ctx.lineWidth=1;
    ctx.beginPath(); ctx.moveTo(pad.l,y); ctx.lineTo(pad.l+cW,y); ctx.stroke();
    ctx.fillText(Math.round(maxVal*(i/4)), 0, y+3);
  }

  // Bars
  datasets.forEach((ds,di) => {
    ds.data.forEach((val,i) => {
      const x = pad.l + i*groupW + di*barW + 4;
      const bH = (val/maxVal)*cH;
      const y = pad.t + cH - bH;
      ctx.fillStyle = ds.color;
      ctx.beginPath();
      ctx.roundRect ? ctx.roundRect(x,y,barW-2,bH,3) : ctx.rect(x,y,barW-2,bH);
      ctx.fill();
    });
  });

  // Labels
  labels.forEach((lbl,i) => {
    const x = pad.l + i*groupW + groupW/2;
    ctx.fillStyle='#555e80';
    ctx.textAlign='center';
    ctx.fillText(lbl, x, H-6);
  });
  ctx.textAlign='left';
}

function drawDoughnutChart(ctx, canvas, labels, data, colors) {
  const W = canvas.offsetWidth || 180, H = 160;
  canvas.width = W; canvas.height = H;
  const cx = W/2 - 30, cy = H/2, r = Math.min(cx,cy)*0.85, inner = r*0.55;
  const total = data.reduce((a,b)=>a+b,0)||1;
  let angle = -Math.PI/2;
  ctx.clearRect(0,0,W,H);

  data.forEach((val,i) => {
    const slice = (val/total)*Math.PI*2;
    ctx.beginPath();
    ctx.moveTo(cx,cy);
    ctx.arc(cx,cy,r,angle,angle+slice);
    ctx.fillStyle = colors[i];
    ctx.fill();
    angle += slice;
  });
  // Hole
  ctx.beginPath(); ctx.arc(cx,cy,inner,0,Math.PI*2);
  ctx.fillStyle = '#111521'; ctx.fill();

  // Legend
  ctx.font='11px Inter,sans-serif';
  labels.forEach((lbl,i) => {
    const ly = 24 + i*22;
    ctx.fillStyle = colors[i];
    ctx.fillRect(W-68, ly-10, 10, 10);
    ctx.fillStyle = '#8b95b8';
    ctx.fillText(`${lbl} (${data[i]})`, W-54, ly);
  });
}

function drawGaugeChart(ctx, canvas, pct) {
  const W=160, H=160;
  canvas.width=W; canvas.height=H;
  const cx=W/2, cy=H/2+10, r=62, lw=14;
  const start=-Math.PI*1.1, end=start + (pct/100)*Math.PI*2.2;
  ctx.clearRect(0,0,W,H);
  // Track
  ctx.beginPath(); ctx.arc(cx,cy,r,start,start+Math.PI*2.2);
  ctx.strokeStyle='rgba(99,120,220,.12)'; ctx.lineWidth=lw; ctx.lineCap='round';
  ctx.stroke();
  // Fill
  ctx.beginPath(); ctx.arc(cx,cy,r,start,end);
  ctx.strokeStyle='#22d3a0'; ctx.lineWidth=lw; ctx.lineCap='round';
  ctx.stroke();
}

/* ══════════════════════════════════════════
   2. PATCH REPOSITORY
══════════════════════════════════════════ */
let repoFilter = { search:'', severity:'' };

function renderPatchRepo() {
  const patches = db.getPatches().filter(p => {
    const q = repoFilter.search.toLowerCase();
    const match = !q || p.patch_name.toLowerCase().includes(q) ||
      p.vendor.toLowerCase().includes(q) || p.patch_version.toLowerCase().includes(q);
    const sev = !repoFilter.severity || p.severity === repoFilter.severity;
    return match && sev;
  });

  return `
<div class="page-header fade-in">
  <div>
    <div class="page-title">📦 Patch Repository</div>
    <div class="page-sub">Centralized catalog of all security patches</div>
  </div>
  <button class="btn btn-primary" onclick="openAddPatch()">＋ Add Patch</button>
</div>
<div class="page-body fade-in">
  <div class="panel">
    <div class="panel-header">
      <div class="toolbar">
        <div class="search-box">
          🔍
          <input type="text" id="repoSearch" placeholder="Search patches…" value="${repoFilter.search}"
            onInput="repoFilter.search=this.value;refreshPatchSubPage('repo')"/>
        </div>
        <select class="form-control" style="width:130px;" onchange="repoFilter.severity=this.value;refreshPatchSubPage('repo')">
          <option value="">All Severity</option>
          <option ${repoFilter.severity==='Critical'?'selected':''}>Critical</option>
          <option ${repoFilter.severity==='High'?'selected':''}>High</option>
          <option ${repoFilter.severity==='Medium'?'selected':''}>Medium</option>
          <option ${repoFilter.severity==='Low'?'selected':''}>Low</option>
        </select>
      </div>
      <span class="tag">${patches.length} patches</span>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead><tr>
          <th>ID</th><th>Patch Name</th><th>Version</th><th>Vendor</th>
          <th>Release Date</th><th>Severity</th><th>Actions</th>
        </tr></thead>
        <tbody>
          ${patches.length ? patches.map(p => `
          <tr>
            <td><span class="tag">${p.id}</span></td>
            <td style="max-width:240px;">
              <div style="font-weight:500;color:var(--text-1);">${p.patch_name}</div>
              <div style="font-size:11px;color:var(--text-3);margin-top:2px;">${p.description.slice(0,70)}…</div>
            </td>
            <td><code style="color:var(--accent);font-size:12px;">${p.patch_version}</code></td>
            <td>${p.vendor}</td>
            <td>${fmtDate(p.release_date)}</td>
            <td>${severityBadge(p.severity)}</td>
            <td>
              <div style="display:flex;gap:6px;">
                <button class="btn btn-ghost btn-sm" onclick="openAssign('${p.id}')">📌 Assign</button>
                <button class="btn btn-ghost btn-sm" onclick="openEditPatch('${p.id}')">✏️</button>
                <button class="btn btn-danger btn-sm" onclick="deletePatch('${p.id}')">🗑️</button>
              </div>
            </td>
          </tr>`).join('') : `<tr><td colspan="7"><div class="empty-state"><div class="es-icon">📭</div><p>No patches found</p></div></td></tr>`}
        </tbody>
      </table>
    </div>
  </div>
</div>`;
}

/* ══════════════════════════════════════════
   3. PATCH ASSIGNMENT
══════════════════════════════════════════ */
function renderPatchAssignment() {
  const assignments = db.getAssignments();
  const patches = db.getPatches();
  return `
<div class="page-header fade-in">
  <div>
    <div class="page-title">📌 Patch Assignment</div>
    <div class="page-sub">Assign patches to assets, schedule deployments</div>
  </div>
  <div style="display:flex;gap:8px;">
    <button class="btn btn-ghost" onclick="openBulkAssign()">📋 Bulk Assign</button>
    <button class="btn btn-primary" onclick="openAssign('')">＋ New Assignment</button>
  </div>
</div>
<div class="page-body fade-in">
  <div class="panel">
    <div class="panel-header">
      <div class="panel-title">📋 All Assignments</div>
      <span class="tag">${assignments.length} total</span>
    </div>
    <div class="tbl-wrap">
      <table>
        <thead><tr>
          <th>ID</th><th>Patch</th><th>Asset</th><th>Scheduled</th>
          <th>Assigned By</th><th>Status</th><th>Actions</th>
        </tr></thead>
        <tbody>
          ${assignments.length ? assignments.slice().reverse().map(a => {
            const p = db.getPatch(a.patch_id)||{patch_name:'Unknown',severity:'Low'};
            const asset = db.getAsset(a.asset_id)||{name:'Unknown'};
            return `<tr>
              <td><span class="tag">${a.id.split('_')[0]}</span></td>
              <td>
                <div style="font-weight:500;color:var(--text-1);">${p.patch_name.slice(0,30)}…</div>
                <div>${severityBadge(p.severity)}</div>
              </td>
              <td><span class="dot dot-green"></span>${asset.name}</td>
              <td>${fmtDate(a.scheduled_date)}</td>
              <td>${a.assigned_by}</td>
              <td>${statusBadge(a.status)}</td>
              <td>
                <div style="display:flex;gap:6px;">
                  <button class="btn btn-ghost btn-sm" onclick="openEditAssignment('${a.id}')">✏️ Edit</button>
                  <button class="btn btn-danger btn-sm" onclick="deleteAssignment('${a.id}')">🗑️</button>
                </div>
              </td>
            </tr>`;
          }).join('') : `<tr><td colspan="7"><div class="empty-state"><div class="es-icon">📭</div><p>No assignments yet</p></div></td></tr>`}
        </tbody>
      </table>
    </div>
  </div>
</div>`;
}

/* ══════════════════════════════════════════
   4. DEPLOYMENT MONITORING
══════════════════════════════════════════ */
function renderMonitor() {
  const statuses = ['Pending','Scheduled','In Progress','Successful','Failed','Rolled Back'];
  const asgn = db.getAssignments();
  const counts = {};
  statuses.forEach(s => counts[s] = asgn.filter(a=>a.status===s).length);

  return `
<div class="page-header fade-in">
  <div>
    <div class="page-title">📡 Deployment Monitoring</div>
    <div class="page-sub">Live tracking of patch deployment status across all assets</div>
  </div>
</div>
<div class="page-body fade-in">
  <!-- Status tiles -->
  <div style="display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:20px;">
    ${[
      ['Pending','⏳',counts['Pending'],'yellow'],
      ['Scheduled','📅',counts['Scheduled'],'blue'],
      ['In Progress','⚡',counts['In Progress'],'purple'],
      ['Successful','✅',counts['Successful'],'green'],
      ['Failed','❌',counts['Failed'],'red'],
      ['Rolled Back','↩️',counts['Rolled Back'],'orange'],
    ].map(([s,icon,c,col])=>`
      <div class="stat-card ${col}" style="text-align:center;padding:14px 10px;" onclick="filterMonitorStatus('${s}')" style="cursor:pointer;">
        <div style="font-size:22px;">${icon}</div>
        <div class="stat-value ${col}" style="font-size:22px;">${c}</div>
        <div class="stat-sub">${s}</div>
      </div>`).join('')}
  </div>

  <!-- Detail Table -->
  <div class="panel">
    <div class="panel-header">
      <div class="panel-title">🔍 Deployment Details</div>
      <select class="form-control" style="width:150px;" id="monitorFilter" onchange="filterMonitorStatus(this.value)">
        <option value="">All Statuses</option>
        ${statuses.map(s=>`<option>${s}</option>`).join('')}
      </select>
    </div>
    <div class="tbl-wrap" id="monitorTable">
      ${renderMonitorTable('')}
    </div>
  </div>
</div>`;
}

function renderMonitorTable(filterStatus) {
  const asgn = db.getAssignments().filter(a => !filterStatus || a.status===filterStatus);
  return `<table>
    <thead><tr>
      <th>Assignment</th><th>Patch</th><th>Asset</th><th>Severity</th>
      <th>Scheduled</th><th>Status</th><th>Notes</th><th>Action</th>
    </tr></thead>
    <tbody>
      ${asgn.length ? asgn.slice().reverse().map(a => {
        const p = db.getPatch(a.patch_id)||{patch_name:'—',severity:'Low'};
        const asset = db.getAsset(a.asset_id)||{name:'—'};
        return `<tr>
          <td><span class="tag">${a.id.split('_')[0]}</span></td>
          <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${p.patch_name}</td>
          <td>${asset.name}</td>
          <td>${severityBadge(p.severity)}</td>
          <td>${fmtDate(a.scheduled_date)}</td>
          <td>${statusBadge(a.status)}</td>
          <td style="font-size:11px;color:var(--text-3);">${a.notes||'—'}</td>
          <td>
            <select class="form-control" style="font-size:11px;padding:4px 8px;width:130px;"
              onchange="updateStatus('${a.id}',this.value)">
              ${['Pending','Scheduled','In Progress','Successful','Failed','Rolled Back']
                .map(s=>`<option ${a.status===s?'selected':''}>${s}</option>`).join('')}
            </select>
          </td>
        </tr>`;
      }).join('') : `<tr><td colspan="8"><div class="empty-state"><div class="es-icon">✅</div><p>No deployments match</p></div></td></tr>`}
    </tbody>
  </table>`;
}

function filterMonitorStatus(s) {
  const sel = document.getElementById('monitorFilter');
  if (sel) sel.value = s;
  const wrap = document.getElementById('monitorTable');
  if (wrap) wrap.innerHTML = renderMonitorTable(s);
}

function updateStatus(id, status) {
  db.updateAssignment(id, {status});
  toast(`Status updated to "${status}"`);
}

/* ══════════════════════════════════════════
   5. REPORTS
══════════════════════════════════════════ */
function renderReports() {
  const asgn = db.getAssignments();
  const patches = db.getPatches();

  // Missing patches: patches with no successful assignment on any asset
  const coveredAssets = {};
  asgn.filter(a=>a.status==='Successful').forEach(a=>{
    if(!coveredAssets[a.patch_id]) coveredAssets[a.patch_id]=new Set();
    coveredAssets[a.patch_id].add(a.asset_id);
  });
  const assets = db.getAssets();
  const missing = [];
  patches.forEach(p => {
    assets.forEach(as => {
      const covered = coveredAssets[p.id] && coveredAssets[p.id].has(as.id);
      const assigned = asgn.some(a=>a.patch_id===p.id && a.asset_id===as.id);
      if (!covered && !assigned) missing.push({patch:p, asset:as});
    });
  });

  const succDeployments = asgn.filter(a=>a.status==='Successful');
  const failDeployments = asgn.filter(a=>a.status==='Failed');
  const s = db.stats();

  return `
<div class="page-header fade-in">
  <div>
    <div class="page-title">📋 Patch Reports</div>
    <div class="page-sub">Compliance, deployment status and gap analysis</div>
  </div>
  <button class="btn btn-ghost" onclick="window.print()">🖨️ Export</button>
</div>
<div class="page-body fade-in">
  <!-- Report Tabs -->
  <div class="tabs">
    <button class="tab active" id="tab-missing"  onclick="switchReportTab('missing')">⚠️ Missing Patches (${missing.length})</button>
    <button class="tab" id="tab-success" onclick="switchReportTab('success')">✅ Successful (${succDeployments.length})</button>
    <button class="tab" id="tab-failed"  onclick="switchReportTab('failed')">❌ Failed (${failDeployments.length})</button>
    <button class="tab" id="tab-compliance" onclick="switchReportTab('compliance')">📊 Compliance</button>
  </div>

  <div id="reportContent">
    ${renderMissingReport(missing)}
  </div>
</div>`;
}

function renderMissingReport(missing) {
  return `<div class="panel">
    <div class="panel-header">
      <div class="panel-title">⚠️ Missing Patches — Unpatched Asset-Patch Combinations</div>
      <span class="tag">${missing.length} gaps identified</span>
    </div>
    <div class="tbl-wrap">
      <table><thead><tr>
        <th>Asset</th><th>Asset Type</th><th>Missing Patch</th><th>Severity</th><th>Released</th><th>Action</th>
      </tr></thead><tbody>
        ${missing.length ? missing.slice(0,30).map(({patch:p, asset:as})=>`
        <tr>
          <td><span class="dot dot-red"></span>${as.name}</td>
          <td>${as.type}</td>
          <td>${p.patch_name}</td>
          <td>${severityBadge(p.severity)}</td>
          <td>${fmtDate(p.release_date)}</td>
          <td><button class="btn btn-primary btn-sm" onclick="openAssignFor('${p.id}','${as.id}')">📌 Assign</button></td>
        </tr>`).join('') : `<tr><td colspan="6"><div class="empty-state"><div class="es-icon">🎉</div><p>No gaps found – all patches covered!</p></div></td></tr>`}
      </tbody></table>
    </div>
  </div>`;
}

function renderSuccessReport(items) {
  return `<div class="panel">
    <div class="panel-header"><div class="panel-title">✅ Successful Deployments</div></div>
    <div class="tbl-wrap"><table><thead><tr>
      <th>Patch</th><th>Asset</th><th>Severity</th><th>Date</th><th>By</th><th>Notes</th>
    </tr></thead><tbody>
      ${items.map(a=>{
        const p=db.getPatch(a.patch_id)||{patch_name:'—',severity:'Low'};
        const as=db.getAsset(a.asset_id)||{name:'—'};
        return `<tr>
          <td>${p.patch_name}</td><td>${as.name}</td>
          <td>${severityBadge(p.severity)}</td>
          <td>${fmtDate(a.scheduled_date)}</td>
          <td>${a.assigned_by}</td><td style="font-size:11px;color:var(--text-3);">${a.notes||'—'}</td>
        </tr>`;
      }).join('')}
    </tbody></table></div>
  </div>`;
}

function renderFailedReport(items) {
  return `<div class="panel">
    <div class="panel-header"><div class="panel-title">❌ Failed Deployments</div></div>
    <div class="tbl-wrap"><table><thead><tr>
      <th>Patch</th><th>Asset</th><th>Severity</th><th>Date</th><th>Notes</th><th>Action</th>
    </tr></thead><tbody>
      ${items.map(a=>{
        const p=db.getPatch(a.patch_id)||{patch_name:'—',severity:'Low'};
        const as=db.getAsset(a.asset_id)||{name:'—'};
        return `<tr>
          <td>${p.patch_name}</td><td>${as.name}</td>
          <td>${severityBadge(p.severity)}</td>
          <td>${fmtDate(a.scheduled_date)}</td>
          <td style="font-size:11px;color:var(--red);">${a.notes||'No details'}</td>
          <td><button class="btn btn-success btn-sm" onclick="updateStatus('${a.id}','Pending');showPatchPage('monitor')">♻️ Retry</button></td>
        </tr>`;
      }).join('')}
    </tbody></table></div>
  </div>`;
}

function renderComplianceReport() {
  const s = db.stats();
  const assets = db.getAssets();
  const asgn = db.getAssignments();

  const assetRows = assets.map(as => {
    const mine = asgn.filter(a=>a.asset_id===as.id);
    const succ = mine.filter(a=>a.status==='Successful').length;
    const total = mine.length;
    const pct = total ? Math.round((succ/total)*100) : 0;
    const color = pct>=80?'var(--green)':pct>=50?'var(--yellow)':'var(--red)';
    return {as, succ, total, pct, color};
  });

  return `<div class="panel">
    <div class="panel-header">
      <div class="panel-title">📊 Patch Compliance Report</div>
      <div style="display:flex;gap:12px;font-size:13px;">
        <span style="color:var(--green)">✅ Overall: ${s.compliance}%</span>
        <span style="color:var(--text-3)">${s.success}/${s.totalDep} deployments successful</span>
      </div>
    </div>
    <div class="panel-body">
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px;">
        ${assetRows.map(({as,succ,total,pct,color})=>`
        <div class="stat-card" style="padding:16px;">
          <div style="font-weight:600;color:var(--text-1);margin-bottom:4px;">${as.name}</div>
          <div style="font-size:11px;color:var(--text-3);margin-bottom:10px;">${as.type} · ${as.os}</div>
          <div style="font-size:22px;font-weight:700;color:${color};">${pct}%</div>
          <div class="progress-bar"><div class="progress-fill" style="width:${pct}%;background:${color};"></div></div>
          <div style="font-size:11px;color:var(--text-3);margin-top:6px;">${succ}/${total} patches applied</div>
        </div>`).join('')}
      </div>
    </div>
  </div>`;
}

let currentReportTab = 'missing';
function switchReportTab(tab) {
  currentReportTab = tab;
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  const el = document.getElementById('tab-'+tab);
  if (el) el.classList.add('active');
  const rc = document.getElementById('reportContent');
  if (!rc) return;
  const asgn = db.getAssignments();
  if (tab==='missing') {
    const patches=db.getPatches(), assets=db.getAssets();
    const coveredAssets={};
    asgn.filter(a=>a.status==='Successful').forEach(a=>{
      if(!coveredAssets[a.patch_id]) coveredAssets[a.patch_id]=new Set();
      coveredAssets[a.patch_id].add(a.asset_id);
    });
    const missing=[];
    patches.forEach(p=>assets.forEach(as=>{
      const covered=coveredAssets[p.id]&&coveredAssets[p.id].has(as.id);
      const assigned=asgn.some(a=>a.patch_id===p.id&&a.asset_id===as.id);
      if(!covered&&!assigned) missing.push({patch:p,asset:as});
    }));
    rc.innerHTML=renderMissingReport(missing);
  } else if (tab==='success') rc.innerHTML=renderSuccessReport(asgn.filter(a=>a.status==='Successful'));
  else if (tab==='failed')  rc.innerHTML=renderFailedReport(asgn.filter(a=>a.status==='Failed'));
  else rc.innerHTML=renderComplianceReport();
}

/* ══════════════════════════════════════════
   MODALS
══════════════════════════════════════════ */
function closeModal() {
  const m = document.getElementById('appModal');
  if (m) m.remove();
}

function showModal(title, bodyHTML, footerHTML) {
  closeModal();
  const div = document.createElement('div');
  div.className = 'modal-overlay';
  div.id = 'appModal';
  div.onclick = (e) => { if(e.target===div) closeModal(); };
  div.innerHTML = `
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">${title}</div>
        <button class="modal-close" onclick="closeModal()">×</button>
      </div>
      <div class="modal-body">${bodyHTML}</div>
      <div class="modal-footer">${footerHTML}</div>
    </div>`;
  document.body.appendChild(div);
}

// Add / Edit Patch
function openAddPatch(patch={}) {
  const edit = !!patch.id;
  const body = `
    <div class="form-row">
      <div class="form-group">
        <label class="form-label">Patch Name *</label>
        <input id="f_name" class="form-control" value="${patch.patch_name||''}" placeholder="e.g. Windows Kernel Update"/>
      </div>
      <div class="form-group">
        <label class="form-label">Version *</label>
        <input id="f_ver" class="form-control" value="${patch.patch_version||''}" placeholder="e.g. KB1234567"/>
      </div>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label class="form-label">Vendor *</label>
        <input id="f_vendor" class="form-control" value="${patch.vendor||''}" placeholder="Microsoft"/>
      </div>
      <div class="form-group">
        <label class="form-label">Release Date *</label>
        <input id="f_date" type="date" class="form-control" value="${patch.release_date||''}"/>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Severity *</label>
      <select id="f_sev" class="form-control">
        ${['Critical','High','Medium','Low'].map(s=>`<option ${patch.severity===s?'selected':''}>${s}</option>`).join('')}
      </select>
    </div>
    <div class="form-group">
      <label class="form-label">Description</label>
      <textarea id="f_desc" class="form-control">${patch.description||''}</textarea>
    </div>`;
  const footer = `
    <button class="btn btn-ghost" onclick="closeModal()">Cancel</button>
    <button class="btn btn-primary" onclick="savePatch('${patch.id||''}')">
      ${edit?'💾 Update':'➕ Add Patch'}
    </button>`;
  showModal(edit?'✏️ Edit Patch':'➕ Add New Patch', body, footer);
}

function openEditPatch(id) { openAddPatch(db.getPatch(id)||{}); }

function savePatch(existingId) {
  const name = document.getElementById('f_name').value.trim();
  const ver  = document.getElementById('f_ver').value.trim();
  const ven  = document.getElementById('f_vendor').value.trim();
  const date = document.getElementById('f_date').value;
  const sev  = document.getElementById('f_sev').value;
  const desc = document.getElementById('f_desc').value.trim();
  if (!name || !ver || !ven || !date) { toast('Please fill required fields','error'); return; }
  if (existingId) {
    db.updatePatch(existingId, {patch_name:name,patch_version:ver,vendor:ven,release_date:date,severity:sev,description:desc});
    toast('Patch updated');
  } else {
    db.addPatch({patch_name:name,patch_version:ver,vendor:ven,release_date:date,severity:sev,description:desc});
    toast('Patch added to repository');
  }
  closeModal();
  refreshPatchSubPage(currentPatchPage);
}

function deletePatch(id) {
  if (!confirm('Delete this patch and all its assignments?')) return;
  db.deletePatch(id);
  toast('Patch deleted');
  refreshPatchSubPage(currentPatchPage);
}

// Assign Patch Modal
function openAssign(patchId) {
  const patches = db.getPatches();
  const assets  = db.getAssets();
  const body = `
    <div class="form-group">
      <label class="form-label">Patch *</label>
      <select id="a_patch" class="form-control">
        ${patches.map(p=>`<option value="${p.id}" ${p.id===patchId?'selected':''}>${p.patch_name} (${p.severity})</option>`).join('')}
      </select>
    </div>
    <div class="form-group">
      <label class="form-label">Asset *</label>
      <select id="a_asset" class="form-control">
        ${assets.map(a=>`<option value="${a.id}">${a.name} – ${a.os}</option>`).join('')}
      </select>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label class="form-label">Scheduled Date *</label>
        <input id="a_date" type="date" class="form-control" value="${new Date().toISOString().slice(0,10)}"/>
      </div>
      <div class="form-group">
        <label class="form-label">Assigned By</label>
        <input id="a_by" class="form-control" value="Admin"/>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Notes</label>
      <textarea id="a_notes" class="form-control" placeholder="Optional notes…"></textarea>
    </div>`;
  const footer = `
    <button class="btn btn-ghost" onclick="closeModal()">Cancel</button>
    <button class="btn btn-primary" onclick="saveAssignment('')">📌 Assign</button>`;
  showModal('📌 Assign Patch to Asset', body, footer);
}

function openAssignFor(patchId, assetId) {
  openAssign(patchId);
  setTimeout(()=>{
    const sel = document.getElementById('a_asset');
    if (sel) sel.value = assetId;
  },100);
}

function openEditAssignment(id) {
  const a = db.getAssignment(id);
  if (!a) return;
  const patches = db.getPatches();
  const assets  = db.getAssets();
  const statuses = ['Pending','Scheduled','In Progress','Successful','Failed','Rolled Back'];
  const body = `
    <div class="form-group">
      <label class="form-label">Patch</label>
      <select id="a_patch" class="form-control">
        ${patches.map(p=>`<option value="${p.id}" ${p.id===a.patch_id?'selected':''}>${p.patch_name}</option>`).join('')}
      </select>
    </div>
    <div class="form-group">
      <label class="form-label">Asset</label>
      <select id="a_asset" class="form-control">
        ${assets.map(as=>`<option value="${as.id}" ${as.id===a.asset_id?'selected':''}>${as.name}</option>`).join('')}
      </select>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label class="form-label">Scheduled Date</label>
        <input id="a_date" type="date" class="form-control" value="${a.scheduled_date}"/>
      </div>
      <div class="form-group">
        <label class="form-label">Status</label>
        <select id="a_status" class="form-control">
          ${statuses.map(s=>`<option ${a.status===s?'selected':''}>${s}</option>`).join('')}
        </select>
      </div>
    </div>
    <div class="form-group">
      <label class="form-label">Assigned By</label>
      <input id="a_by" class="form-control" value="${a.assigned_by}"/>
    </div>
    <div class="form-group">
      <label class="form-label">Notes</label>
      <textarea id="a_notes" class="form-control">${a.notes||''}</textarea>
    </div>`;
  const footer = `
    <button class="btn btn-ghost" onclick="closeModal()">Cancel</button>
    <button class="btn btn-primary" onclick="saveAssignment('${id}')">💾 Save</button>`;
  showModal('✏️ Edit Assignment', body, footer);
}

function saveAssignment(existingId) {
  const patch_id  = document.getElementById('a_patch').value;
  const asset_id  = document.getElementById('a_asset').value;
  const scheduled_date = document.getElementById('a_date').value;
  const assigned_by = document.getElementById('a_by').value.trim() || 'Admin';
  const notes = document.getElementById('a_notes').value.trim();
  const status = document.getElementById('a_status') ? document.getElementById('a_status').value : 'Pending';
  if (!patch_id || !asset_id || !scheduled_date) { toast('Fill required fields','error'); return; }
  if (existingId) {
    db.updateAssignment(existingId, {patch_id,asset_id,scheduled_date,assigned_by,notes,status});
    toast('Assignment updated');
  } else {
    db.addAssignment({patch_id,asset_id,scheduled_date,assigned_by,notes,status:'Pending'});
    toast('Patch assigned successfully');
  }
  closeModal();
  refreshPatchSubPage(currentPatchPage);
}

function deleteAssignment(id) {
  if (!confirm('Remove this assignment?')) return;
  db.deleteAssignment(id);
  toast('Assignment removed');
  refreshPatchSubPage(currentPatchPage);
}

// Bulk Assignment Modal
function openBulkAssign() {
  const patches = db.getPatches();
  const assets  = db.getAssets();
  const body = `
    <div class="form-group">
      <label class="form-label">Patch *</label>
      <select id="b_patch" class="form-control">
        ${patches.map(p=>`<option value="${p.id}">${p.patch_name} (${p.severity})</option>`).join('')}
      </select>
    </div>
    <div class="form-group">
      <label class="form-label">Select Assets * <span style="font-size:10px;color:var(--text-3)">(Ctrl+click for multiple)</span></label>
      <select id="b_assets" class="form-control" multiple style="height:120px;">
        ${assets.map(a=>`<option value="${a.id}">${a.name} – ${a.type} – ${a.os}</option>`).join('')}
      </select>
    </div>
    <div class="form-row">
      <div class="form-group">
        <label class="form-label">Scheduled Date *</label>
        <input id="b_date" type="date" class="form-control" value="${new Date().toISOString().slice(0,10)}"/>
      </div>
      <div class="form-group">
        <label class="form-label">Assigned By</label>
        <input id="b_by" class="form-control" value="Admin"/>
      </div>
    </div>`;
  const footer = `
    <button class="btn btn-ghost" onclick="closeModal()">Cancel</button>
    <button class="btn btn-primary" onclick="saveBulkAssign()">📋 Bulk Assign</button>`;
  showModal('📋 Bulk Patch Assignment', body, footer);
}

function saveBulkAssign() {
  const patch_id = document.getElementById('b_patch').value;
  const sel = document.getElementById('b_assets');
  const asset_ids = Array.from(sel.selectedOptions).map(o=>o.value);
  const date = document.getElementById('b_date').value;
  const by   = document.getElementById('b_by').value || 'Admin';
  if (!asset_ids.length || !date) { toast('Select at least one asset and a date','error'); return; }
  db.addBulkAssignments(patch_id, asset_ids, date, by);
  toast(`Patch assigned to ${asset_ids.length} asset(s)`);
  closeModal();
  refreshPatchSubPage(currentPatchPage);
}
