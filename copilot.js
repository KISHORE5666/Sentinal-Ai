/* =============================================
   copilot.js – AI SOC Copilot Module
   Alert Analysis, Attack Explanation,
   Remediation & Investigation Workflow
   ============================================= */

/* ── Auto-Generated Alert Templates ── */
const ALERT_TEMPLATES = [
  { title:'Suspicious PowerShell Execution',         technique:'T1059.001', tactic:'Execution',            severity:'Critical', assetId:'A001', asset:'WEB-SVR-01' },
  { title:'LSASS Memory Access Detected',            technique:'T1003.001', tactic:'Credential Access',    severity:'Critical', assetId:'A003', asset:'DB-SVR-01'  },
  { title:'Unusual Outbound DNS Queries',            technique:'T1071.004', tactic:'Command and Control',  severity:'High',     assetId:'A006', asset:'PROXY-01'   },
  { title:'Registry Run Key Modification',           technique:'T1547.001', tactic:'Persistence',          severity:'High',     assetId:'A004', asset:'DEV-WS-01'  },
  { title:'Scheduled Task Created by Unknown Process',technique:'T1053.005',tactic:'Persistence',          severity:'Medium',   assetId:'A005', asset:'DEV-WS-02'  },
  { title:'SMB Lateral Movement Attempt',            technique:'T1021.002', tactic:'Lateral Movement',     severity:'Critical', assetId:'A002', asset:'WEB-SVR-02' },
  { title:'Volume Shadow Copy Deletion',             technique:'T1490',     tactic:'Impact',               severity:'Critical', assetId:'A007', asset:'STORAGE-01' },
  { title:'Anomalous Bytes Sent to External IP',     technique:'T1048',     tactic:'Exfiltration',         severity:'High',     assetId:'A006', asset:'PROXY-01'   },
  { title:'WMI Remote Execution',                    technique:'T1047',     tactic:'Execution',            severity:'High',     assetId:'A003', asset:'DB-SVR-01'  },
  { title:'Token Impersonation Privilege Escalation',technique:'T1134',     tactic:'Privilege Escalation', severity:'High',     assetId:'A001', asset:'WEB-SVR-01' },
  { title:'Known Tor Exit Node Communication',       technique:'T1090',     tactic:'Command and Control',  severity:'High',     assetId:'A007', asset:'STORAGE-01' },
  { title:'DLL Side-Loading Detected',               technique:'T1574.002', tactic:'Defense Evasion',      severity:'Medium',   assetId:'A004', asset:'DEV-WS-01'  },
];

const ATTACK_NARRATIVES = {
  'Execution':            { icon:'⚡', summary:'Adversary executed malicious code on the target system', detail:'The attacker has gained a foothold and is now running commands or scripts to further their objectives. This may include downloading additional payloads, establishing persistence, or performing reconnaissance.' },
  'Credential Access':    { icon:'🗝️', summary:'Attacker is attempting to steal account credentials',    detail:'Credential theft is a critical stage indicating the adversary is preparing for lateral movement or privilege escalation. Immediate credential rotation and session invalidation is essential.' },
  'Command and Control':  { icon:'📡', summary:'Malware is communicating with attacker infrastructure',  detail:'Active C2 communication indicates the attacker has persistent access and is receiving instructions. The affected asset must be isolated immediately to prevent data exfiltration.' },
  'Lateral Movement':     { icon:'↔️', summary:'Attacker is spreading across the network',              detail:'Lateral movement indicates the attacker is attempting to compromise additional assets. This exponentially increases blast radius and requires immediate network segmentation.' },
  'Impact':               { icon:'💥', summary:'Attacker is executing destructive or disruptive actions',detail:'Impact-stage activity such as ransomware or data destruction represents the final phase. All affected assets must be isolated and incident recovery procedures initiated immediately.' },
  'Persistence':          { icon:'🔗', summary:'Adversary is establishing long-term access mechanisms',  detail:'Persistence mechanisms ensure the attacker can maintain access even after reboots or password changes. All persistence artifacts must be identified and removed.' },
  'Privilege Escalation': { icon:'⬆️', summary:'Attacker is gaining elevated privileges',               detail:'Privilege escalation gives the attacker admin or SYSTEM-level access, dramatically expanding their capabilities. Immediate review of privileged account activity is required.' },
  'Defense Evasion':      { icon:'🎭', summary:'Attacker is hiding their activities from detection',     detail:'Defense evasion techniques are used to avoid detection by security tools. This suggests a sophisticated actor aware of the security environment.' },
  'Exfiltration':         { icon:'📤', summary:'Sensitive data is being transferred to attacker',        detail:'Data exfiltration is occurring. Immediate network blocking of the destination IP/domain and data loss assessment should be initiated.' },
  'Discovery':            { icon:'🔍', summary:'Attacker is mapping the network and systems',            detail:'Discovery activity indicates preparation for further attacks. The attacker is profiling the environment to identify targets for lateral movement or impact.' },
  'Initial Access':       { icon:'🚪', summary:'Attacker has gained initial entry to the environment',   detail:'Initial access is the first stage of compromise. Understanding the entry vector is critical to closing the gap and preventing reinfection.' },
  'Collection':           { icon:'📦', summary:'Adversary is gathering data of interest',                detail:'Data collection precedes exfiltration. Identifying what data has been accessed and staged is critical for breach notification and legal obligations.' },
};

const MITIGATIONS = {
  'T1059.001': ['Restrict PowerShell execution policy (AllSigned or RemoteSigned)','Enable Script Block Logging','Deploy AMSI (Antimalware Scan Interface)','Use AppLocker to whitelist allowed scripts'],
  'T1003.001': ['Enable Windows Credential Guard','Restrict LSASS access via Protected Process Light','Deploy EDR with credential-dumping detection','Audit LSASS access events (EID 4663)'],
  'T1110':     ['Implement account lockout policy (5 attempts)','Enable MFA on all privileged accounts','Monitor failed authentication events','Use CAPTCHA on externally exposed login pages'],
  'T1021.002': ['Disable SMBv1 across all assets','Restrict SMB access via host firewall','Require NTLMv2 only','Deploy SMB signing enforcement'],
  'T1486':     ['Maintain offline backups (3-2-1 rule)','Deploy VSS protection','Enable tamper protection on endpoint security','Conduct ransomware tabletop exercises'],
  'T1071.001': ['Implement TLS inspection at perimeter','Use DNS sinkholing for known C2 domains','Deploy network traffic analysis (NTA)','Block known C2 IPs at firewall'],
  'T1048':     ['Monitor outbound data volumes with DLP','Enforce egress filtering at perimeter','Implement protocol whitelisting','Alert on large outbound transfers'],
  'T1090':     ['Block Tor exit node IP ranges','Monitor for unusual encrypted traffic','Deploy UEBA for baseline deviation','Require VPN for remote access'],
  'default':   ['Review endpoint detection logs','Apply latest security patches','Audit privileged account activity','Enable enhanced logging on affected assets'],
};

/* ═══════════════════════════════════════════
   RENDER – AI SOC COPILOT PAGE
═══════════════════════════════════════════ */
function renderCopilot() {
  const alerts  = db.getAlerts();
  const as      = db.alertStats();
  const open    = alerts.filter(a => a.status !== 'Resolved');

  return `
<div class="page-header fade-in">
  <div>
    <div class="page-title">🤖 AI SOC Copilot</div>
    <div class="page-sub">Intelligent alert analysis, attack explanation & guided remediation</div>
  </div>
  <div style="display:flex;gap:8px;align-items:center;">
    <div class="ai-status-badge"><span class="dot dot-green pulse"></span>AI Engine Online</div>
    ${auth.canDo('automated_response') ? `<button class="btn btn-primary btn-sm" onclick="generateNewAlert()">⚡ Simulate Alert</button>` : ''}
  </div>
</div>

<div class="page-body fade-in">

  <!-- AI Stats Row -->
  <div class="stats-grid" style="grid-template-columns:repeat(5,1fr);">
    <div class="stat-card red">
      <div class="stat-label">Open Alerts</div>
      <div class="stat-value red">${as.open}</div>
      <div class="stat-sub">Require attention</div>
    </div>
    <div class="stat-card orange">
      <div class="stat-label">Investigating</div>
      <div class="stat-value" style="color:var(--orange)">${as.invest}</div>
      <div class="stat-sub">In progress</div>
    </div>
    <div class="stat-card green">
      <div class="stat-label">Resolved</div>
      <div class="stat-value green">${as.resolved}</div>
      <div class="stat-sub">Closed today</div>
    </div>
    <div class="stat-card blue">
      <div class="stat-label">Avg Confidence</div>
      <div class="stat-value blue">${as.avgConf}%</div>
      <div class="stat-sub">ML ensemble</div>
    </div>
    <div class="stat-card purple">
      <div class="stat-label">False Positives</div>
      <div class="stat-value" style="color:var(--accent2)">${as.fp}</div>
      <div class="stat-sub">Auto-filtered</div>
    </div>
  </div>

  <!-- ML Model Health -->
  <div class="panel" style="margin-bottom:20px;">
    <div class="panel-header">
      <div class="panel-title">🧠 ML Model Health & Accuracy</div>
      <span class="tag">Ensemble v2.0</span>
    </div>
    <div class="panel-body" style="padding:16px 20px;">
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;">
        ${mlEngine.modelStats().map(m => `
        <div class="model-card">
          <div class="model-header">
            <span style="font-size:20px;">${m.icon}</span>
            <div>
              <div class="model-name">${m.model}</div>
              <div style="font-size:10px;color:var(--accent);font-family:monospace;">v${m.version} · ${m.type}</div>
            </div>
            <span class="tag" style="margin-left:auto;">${m.algo}</span>
          </div>
          <div class="model-metrics">
            ${[['Accuracy',m.accuracy],['Precision',m.precision],['Recall',m.recall]].map(([k,v])=>`
            <div class="model-metric">
              <div style="display:flex;justify-content:space-between;font-size:11px;margin-bottom:3px;">
                <span style="color:var(--text-2)">${k}</span>
                <span style="color:var(--green);font-weight:600;">${v}%</span>
              </div>
              <div class="progress-bar" style="height:4px;">
                <div class="progress-fill" style="width:${v}%;background:var(--green);"></div>
              </div>
            </div>`).join('')}
          </div>
        </div>`).join('')}
      </div>
    </div>
  </div>

  <!-- Alert Feed + Detail -->
  <div style="display:grid;grid-template-columns:1fr 1.6fr;gap:16px;">
    <!-- Alert Feed -->
    <div class="panel" style="height:fit-content;">
      <div class="panel-header">
        <div class="panel-title">🚨 Active Alert Feed</div>
        <div style="display:flex;gap:6px;">
          <select class="form-control" style="width:110px;padding:4px 8px;font-size:11px;" id="alertFilter" onchange="filterCopilotAlerts(this.value)">
            <option value="">All</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Open">Open</option>
            <option value="Investigating">Investigating</option>
          </select>
        </div>
      </div>
      <div id="copilotAlertList" style="max-height:520px;overflow-y:auto;">
        ${renderAlertFeed(alerts, null)}
      </div>
    </div>

    <!-- AI Analysis Panel -->
    <div id="copilotDetail">
      <div class="panel" style="height:100%;min-height:400px;">
        <div class="panel-body" style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:60px 40px;text-align:center;">
          <div style="font-size:56px;margin-bottom:16px;opacity:.5;">🤖</div>
          <div style="font-size:16px;font-weight:700;margin-bottom:8px;color:var(--text-1);">Select an Alert to Analyze</div>
          <div style="color:var(--text-2);font-size:13px;max-width:280px;">Click any alert in the feed to see AI-powered analysis, attack explanation, and remediation recommendations.</div>
        </div>
      </div>
    </div>
  </div>

</div>`;
}

function renderAlertFeed(alerts, selectedId, filter) {
  let filtered = [...alerts];
  if (filter && ['Critical','High','Medium','Low'].includes(filter)) {
    filtered = alerts.filter(a => a.severity === filter);
  } else if (filter === 'Open' || filter === 'Investigating' || filter === 'Resolved') {
    filtered = alerts.filter(a => a.status === filter);
  }

  const sevColor = { Critical:'var(--red)', High:'var(--orange)', Medium:'var(--yellow)', Low:'var(--green)' };
  const statIcon = { Open:'🔴', Investigating:'🟡', Resolved:'✅' };

  return filtered.slice(0, 30).map(al => `
  <div class="alert-item ${selectedId === al.id ? 'alert-item-active' : ''}"
    onclick="selectCopilotAlert('${al.id}')" id="alertItem_${al.id}">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;">
      <div style="flex:1;min-width:0;">
        <div style="font-weight:600;font-size:12px;color:var(--text-1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"
          title="${al.title}">${statIcon[al.status]||'⚪'} ${al.title}</div>
        <div style="font-size:10px;color:var(--text-3);margin-top:2px;">${al.asset} · ${timeAgo(al.timestamp)}</div>
        <div style="font-size:10px;color:var(--text-3);margin-top:1px;font-family:monospace;">${al.technique} · ${al.tactic}</div>
      </div>
      <div style="display:flex;flex-direction:column;align-items:flex-end;gap:3px;flex-shrink:0;">
        <span class="badge" style="background:${sevColor[al.severity]}22;color:${sevColor[al.severity]};font-size:9px;">${al.severity}</span>
        <span style="font-size:10px;color:var(--accent);font-weight:700;">${al.confidence}%</span>
      </div>
    </div>
    <div class="alert-confidence-bar">
      <div style="width:${al.confidence}%;background:${sevColor[al.severity]};height:2px;border-radius:2px;margin-top:6px;transition:width .4s;"></div>
    </div>
  </div>`).join('') || `<div style="padding:40px;text-align:center;color:var(--text-3);">No alerts match filter</div>`;
}

function filterCopilotAlerts(val) {
  const alerts = db.getAlerts();
  const el = document.getElementById('copilotAlertList');
  if (el) el.innerHTML = renderAlertFeed(alerts, null, val);
}

let _selectedAlertId = null;
function selectCopilotAlert(id) {
  _selectedAlertId = id;
  // Highlight selected
  document.querySelectorAll('.alert-item').forEach(el => el.classList.remove('alert-item-active'));
  const itemEl = document.getElementById('alertItem_' + id);
  if (itemEl) itemEl.classList.add('alert-item-active');

  const alert  = db.getAlert(id);
  if (!alert) return;
  const result = mlEngine.analyze(alert);
  const narr   = ATTACK_NARRATIVES[alert.tactic] || { icon:'❓', summary:'Unknown attack pattern detected', detail:'Further analysis required.' };
  const mitig  = MITIGATIONS[alert.technique] || MITIGATIONS.default;
  const sevColor = { Critical:'var(--red)', High:'var(--orange)', Medium:'var(--yellow)', Low:'var(--green)' };

  const detail = document.getElementById('copilotDetail');
  if (!detail) return;

  detail.innerHTML = `
<div class="panel fade-in">
  <div class="panel-header" style="background:linear-gradient(90deg,rgba(91,120,245,.08),transparent);">
    <div>
      <div style="font-size:14px;font-weight:700;color:var(--text-1);">${narr.icon} ${alert.title}</div>
      <div style="font-size:11px;color:var(--text-3);margin-top:2px;">${alert.asset} · ${alert.technique} · ${timeAgo(alert.timestamp)}</div>
    </div>
    <div style="display:flex;gap:8px;align-items:center;">
      <span class="badge" style="background:${sevColor[alert.severity]}22;color:${sevColor[alert.severity]};">${alert.severity}</span>
      ${auth.canDo('update_status') ? `
      <select class="form-control" style="width:130px;padding:4px 8px;font-size:11px;" onchange="updateAlertStatus('${alert.id}',this.value)">
        ${['Open','Investigating','Resolved'].map(s=>`<option ${alert.status===s?'selected':''}>${s}</option>`).join('')}
      </select>` : `<span class="badge badge-info">${alert.status}</span>`}
    </div>
  </div>

  <div class="panel-body" style="padding:0;">

    <!-- Ensemble Score -->
    <div style="padding:16px 20px;border-bottom:1px solid var(--border);">
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:12px;">
        <div class="mini-score-card">
          <div class="mini-score-label">Composite Score</div>
          <div class="mini-score-val" style="color:${result.color};font-size:28px;">${result.composite}<span style="font-size:14px;">/100</span></div>
          <div class="mini-score-level" style="color:${result.color};">● ${result.level}</div>
        </div>
        <div class="mini-score-card">
          <div class="mini-score-label">Anomaly</div>
          <div class="mini-score-val" style="color:var(--blue);">${result.models.anomaly.score}<span style="font-size:12px;">/100</span></div>
          <div class="mini-score-level" style="color:var(--text-3);">Detection Model</div>
        </div>
        <div class="mini-score-card">
          <div class="mini-score-label">Signature</div>
          <div class="mini-score-val" style="color:var(--accent2);">${result.models.signature.score}<span style="font-size:12px;">/100</span></div>
          <div class="mini-score-level" style="color:var(--text-3);">${result.models.signature.matches.length} rule hits</div>
        </div>
        <div class="mini-score-card">
          <div class="mini-score-label">Behavior</div>
          <div class="mini-score-val" style="color:var(--green);">${result.models.behavior.score}<span style="font-size:12px;">/100</span></div>
          <div class="mini-score-level" style="color:var(--text-3);">${result.models.behavior.killChain?.icon} ${result.models.behavior.killChain?.name}</div>
        </div>
      </div>

      <!-- Kill Chain Progress -->
      <div style="margin-top:14px;">
        <div style="font-size:10px;color:var(--text-3);margin-bottom:6px;text-transform:uppercase;letter-spacing:.08em;">Kill Chain Stage</div>
        <div class="killchain-bar">
          ${['Recon','Initial Access','Execution','Priv Esc','Cred Access','Lateral Move','C2','Exfiltration','Impact'].map((s,i)=>{
            const stage = result.models.behavior.killChain?.stage || 0;
            const active = i < stage;
            const current = i === stage - 1;
            return `<div class="kc-step ${active?'kc-active':''} ${current?'kc-current':''}" title="${s}">${s.slice(0,4)}</div>`;
          }).join('')}
        </div>
      </div>
    </div>

    <!-- AI Explanation -->
    <div style="padding:16px 20px;border-bottom:1px solid var(--border);">
      <div class="ai-section-title">🤖 AI Explanation</div>
      <div class="ai-bubble">
        <div style="font-weight:600;color:var(--text-1);margin-bottom:6px;">${narr.summary}</div>
        <div style="color:var(--text-2);font-size:12px;line-height:1.7;">${narr.detail}</div>
        <div style="margin-top:10px;font-size:12px;color:var(--text-3);border-top:1px solid var(--border);padding-top:8px;">${result.explanation}</div>
      </div>
      <div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap;">
        <span class="tag">FP Risk: <span style="color:${result.fpRisk==='Very Low'?'var(--green)':result.fpRisk==='Low'?'var(--yellow)':'var(--red)'}">${result.fpRisk}</span></span>
        <span class="tag">Models Agree: ${result.highModels}/3</span>
        <span class="tag">Technique: ${alert.technique}</span>
        <span class="tag">Tactic: ${alert.tactic}</span>
      </div>
    </div>

    <!-- Signature Hits -->
    ${result.models.signature.matches.length > 0 ? `
    <div style="padding:14px 20px;border-bottom:1px solid var(--border);">
      <div class="ai-section-title">🔏 Signature Matches</div>
      <div style="display:flex;flex-direction:column;gap:6px;">
        ${result.models.signature.matches.map(m=>`
        <div style="display:flex;align-items:center;gap:8px;background:var(--bg-hover);border-radius:6px;padding:8px 12px;">
          <span class="badge badge-critical" style="font-size:9px;">${m.severity}</span>
          <span style="font-size:12px;color:var(--text-1);">${m.rule}</span>
          <span style="margin-left:auto;font-family:monospace;font-size:10px;color:var(--text-3);">${m.ruleId}</span>
        </div>`).join('')}
      </div>
    </div>` : ''}

    <!-- Remediation -->
    <div style="padding:14px 20px;border-bottom:1px solid var(--border);">
      <div class="ai-section-title">🛡️ AI Remediation Recommendations</div>
      <div style="display:flex;flex-direction:column;gap:6px;">
        ${result.recommendation.map((r,i)=>`
        <div class="remediation-item">
          <span class="remediation-num">${i+1}</span>
          <span style="font-size:12px;color:var(--text-1);">${r}</span>
        </div>`).join('')}
      </div>
    </div>

    <!-- MITRE Mitigations -->
    <div style="padding:14px 20px;border-bottom:1px solid var(--border);">
      <div class="ai-section-title">🗡️ MITRE Mitigations for ${alert.technique}</div>
      <div style="display:flex;flex-direction:column;gap:5px;">
        ${mitig.map(m=>`<div style="font-size:12px;color:var(--text-2);padding:5px 0;border-bottom:1px solid rgba(99,120,220,.05);">• ${m}</div>`).join('')}
      </div>
    </div>

    <!-- Actions -->
    ${auth.canDo('update_status') ? `
    <div style="padding:14px 20px;">
      <div class="ai-section-title">⚡ Quick Actions</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <button class="btn btn-primary btn-sm" onclick="updateAlertStatus('${alert.id}','Investigating')">🔍 Start Investigation</button>
        <button class="btn btn-success btn-sm" onclick="updateAlertStatus('${alert.id}','Resolved')">✅ Mark Resolved</button>
        ${auth.canDo('automated_response') ? `<button class="btn btn-ghost btn-sm" onclick="runPlaybook('${alert.id}')">🤖 Run Playbook</button>` : ''}
        <button class="btn btn-danger btn-sm" onclick="markFalsePositive('${alert.id}')">🚫 False Positive</button>
      </div>
      ${alert.notes ? `<div style="margin-top:10px;font-size:12px;color:var(--text-2);padding:8px 12px;background:var(--bg-hover);border-radius:6px;">📝 ${alert.notes}</div>` : ''}
    </div>` : ''}

  </div>
</div>`;
}

function updateAlertStatus(id, status) {
  db.updateAlert(id, { status, assignedTo: auth.getUser()?.username });
  toast(`Alert status updated to "${status}"`);
  selectCopilotAlert(id);
  // Refresh feed
  const feed = document.getElementById('copilotAlertList');
  if (feed) feed.innerHTML = renderAlertFeed(db.getAlerts(), id);
}

function markFalsePositive(id) {
  db.updateAlert(id, { falsePositive:true, status:'Resolved', notes:'Marked as false positive by ' + (auth.getUser()?.name || 'user') });
  toast('Alert marked as false positive and closed');
  selectCopilotAlert(id);
  const feed = document.getElementById('copilotAlertList');
  if (feed) feed.innerHTML = renderAlertFeed(db.getAlerts(), id);
}

function runPlaybook(alertId) {
  const alert = db.getAlert(alertId);
  if (!alert) return;
  const playbooks = db.getPlaybooks().filter(pb => pb.enabled);
  let matched = 0;
  playbooks.forEach(pb => {
    // Simple trigger evaluation
    if (pb.trigger.includes(`severity=${alert.severity}`) ||
        pb.trigger.includes(`technique=${alert.technique}`) ||
        pb.trigger.includes(`tactic=${alert.tactic}`)) {
      matched++;
      toast(`▶️ Playbook "${pb.name}" triggered — ${pb.actions.join(', ')}`);
    }
  });
  if (!matched) toast('No matching enabled playbooks for this alert', 'error');
}

function generateNewAlert() {
  const tpl = ALERT_TEMPLATES[Math.floor(Math.random() * ALERT_TEMPLATES.length)];
  const conf = Math.round(60 + Math.random() * 38);
  db.addAlert({
    ...tpl,
    status: 'Open',
    confidence: conf,
    falsePositive: false,
    assignedTo: null,
    notes: '',
    anomalyScore: Math.round(conf - 5 + Math.random()*10),
    sigScore:     Math.round(conf - 5 + Math.random()*10),
    behaviorScore:Math.round(conf - 8 + Math.random()*12),
  });
  toast('⚡ New alert injected into feed');
  const feed = document.getElementById('copilotAlertList');
  if (feed) feed.innerHTML = renderAlertFeed(db.getAlerts(), _selectedAlertId);
}

function timeAgo(ts) {
  const diff = Date.now() - ts;
  if (diff < 60000)   return `${Math.floor(diff/1000)}s ago`;
  if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
  if (diff < 86400000)return `${Math.floor(diff/3600000)}h ago`;
  return `${Math.floor(diff/86400000)}d ago`;
}
