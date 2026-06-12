/* =============================================
   threat.js – Threat Intelligence &
              MITRE ATT&CK Module
   ============================================= */

/* ═══════════════════════════════════════════
   MITRE ATT&CK MATRIX DATA
═══════════════════════════════════════════ */
const ATTACK_MATRIX = [
  {
    tactic:'Reconnaissance', id:'TA0043', color:'#6366f1',
    techniques:[
      { id:'T1595', name:'Active Scanning',         hits:3  },
      { id:'T1592', name:'Gather Victim Host Info', hits:2  },
      { id:'T1589', name:'Gather Victim Identity',  hits:1  },
      { id:'T1590', name:'Gather Victim Network',   hits:4  },
      { id:'T1598', name:'Phishing for Info',       hits:2  },
      { id:'T1597', name:'Search Closed Sources',   hits:0  },
    ]
  },
  {
    tactic:'Initial Access', id:'TA0001', color:'#8b5cf6',
    techniques:[
      { id:'T1566',     name:'Phishing',               hits:8  },
      { id:'T1566.001', name:'Spearphishing Attachment',hits:6  },
      { id:'T1190',     name:'Exploit Public App',      hits:11 },
      { id:'T1195',     name:'Supply Chain Compromise', hits:3  },
      { id:'T1133',     name:'External Remote Svcs',    hits:5  },
      { id:'T1078',     name:'Valid Accounts',          hits:9  },
      { id:'T1091',     name:'Removable Media',         hits:1  },
    ]
  },
  {
    tactic:'Execution', id:'TA0002', color:'#ec4899',
    techniques:[
      { id:'T1059',     name:'Command & Scripting',     hits:14 },
      { id:'T1059.001', name:'PowerShell',               hits:18 },
      { id:'T1059.003', name:'Windows Cmd Shell',        hits:7  },
      { id:'T1047',     name:'WMI',                      hits:5  },
      { id:'T1053',     name:'Scheduled Task/Job',       hits:6  },
      { id:'T1204',     name:'User Execution',           hits:4  },
      { id:'T1072',     name:'Software Deployment',      hits:2  },
    ]
  },
  {
    tactic:'Persistence', id:'TA0003', color:'#f97316',
    techniques:[
      { id:'T1547',     name:'Boot/Logon Autostart',    hits:7  },
      { id:'T1547.001', name:'Registry Run Keys',        hits:9  },
      { id:'T1053.005', name:'Scheduled Task',           hits:6  },
      { id:'T1505',     name:'Server Software Comp',     hits:3  },
      { id:'T1136',     name:'Create Account',           hits:4  },
      { id:'T1078',     name:'Valid Accounts',           hits:8  },
      { id:'T1197',     name:'BITS Jobs',                hits:2  },
    ]
  },
  {
    tactic:'Privilege Escalation', id:'TA0004', color:'#ef4444',
    techniques:[
      { id:'T1068',     name:'Exploitation for PE',     hits:9  },
      { id:'T1134',     name:'Access Token Manip.',     hits:6  },
      { id:'T1134.001', name:'Token Impersonation',     hits:4  },
      { id:'T1548',     name:'Abuse Elevation Control', hits:5  },
      { id:'T1055',     name:'Process Injection',       hits:7  },
      { id:'T1078.003', name:'Local Accounts',          hits:3  },
      { id:'T1611',     name:'Escape to Host',          hits:1  },
    ]
  },
  {
    tactic:'Defense Evasion', id:'TA0005', color:'#14b8a6',
    techniques:[
      { id:'T1055',     name:'Process Injection',       hits:7  },
      { id:'T1112',     name:'Modify Registry',         hits:6  },
      { id:'T1140',     name:'Deobfuscate/Decode',      hits:5  },
      { id:'T1218',     name:'Signed Binary Proxy',     hits:8  },
      { id:'T1562',     name:'Impair Defenses',         hits:10 },
      { id:'T1070',     name:'Indicator Removal',       hits:4  },
      { id:'T1574',     name:'Hijack Execution Flow',   hits:3  },
    ]
  },
  {
    tactic:'Credential Access', id:'TA0006', color:'#f59e0b',
    techniques:[
      { id:'T1110',     name:'Brute Force',             hits:12 },
      { id:'T1003',     name:'OS Credential Dumping',   hits:9  },
      { id:'T1003.001', name:'LSASS Memory',            hits:11 },
      { id:'T1555',     name:'Credentials from Store',  hits:5  },
      { id:'T1056',     name:'Input Capture',           hits:3  },
      { id:'T1539',     name:'Steal Web Session Cookie',hits:4  },
      { id:'T1558',     name:'Steal/Forge Kerberos',   hits:6  },
    ]
  },
  {
    tactic:'Discovery', id:'TA0007', color:'#3b82f6',
    techniques:[
      { id:'T1046',     name:'Network Service Scan',    hits:8  },
      { id:'T1083',     name:'File & Directory Disc.',  hits:5  },
      { id:'T1082',     name:'System Info Discovery',   hits:7  },
      { id:'T1033',     name:'System Owner/User Disc.', hits:4  },
      { id:'T1049',     name:'System Network Conn.',    hits:6  },
      { id:'T1057',     name:'Process Discovery',       hits:3  },
      { id:'T1018',     name:'Remote System Discovery', hits:9  },
    ]
  },
  {
    tactic:'Lateral Movement', id:'TA0008', color:'#0ea5e9',
    techniques:[
      { id:'T1021',     name:'Remote Services',         hits:7  },
      { id:'T1021.002', name:'SMB/Windows Admin',       hits:9  },
      { id:'T1021.001', name:'Remote Desktop Proto',    hits:6  },
      { id:'T1076',     name:'RDP Hijacking',           hits:3  },
      { id:'T1563',     name:'Remote Service Session',  hits:2  },
      { id:'T1534',     name:'Internal Spearphishing',  hits:4  },
      { id:'T1570',     name:'Lateral Tool Transfer',   hits:5  },
    ]
  },
  {
    tactic:'Collection', id:'TA0009', color:'#10b981',
    techniques:[
      { id:'T1560',     name:'Archive Collected Data',  hits:4  },
      { id:'T1074',     name:'Data Staged',             hits:6  },
      { id:'T1005',     name:'Data from Local System',  hits:5  },
      { id:'T1114',     name:'Email Collection',        hits:3  },
      { id:'T1056',     name:'Input Capture',           hits:4  },
      { id:'T1113',     name:'Screen Capture',          hits:2  },
      { id:'T1119',     name:'Automated Collection',    hits:3  },
    ]
  },
  {
    tactic:'Command & Control', id:'TA0011', color:'#8b5cf6',
    techniques:[
      { id:'T1071',     name:'App Layer Protocol',      hits:12 },
      { id:'T1071.001', name:'Web Protocols',           hits:10 },
      { id:'T1095',     name:'Non-App Layer Protocol',  hits:5  },
      { id:'T1090',     name:'Proxy',                   hits:7  },
      { id:'T1568',     name:'Dynamic Resolution',      hits:4  },
      { id:'T1573',     name:'Encrypted Channel',       hits:6  },
      { id:'T1105',     name:'Ingress Tool Transfer',   hits:8  },
    ]
  },
  {
    tactic:'Exfiltration', id:'TA0010', color:'#f97316',
    techniques:[
      { id:'T1048',     name:'Exfil Over Alt Protocol', hits:5  },
      { id:'T1041',     name:'Exfil Over C2 Channel',   hits:7  },
      { id:'T1567',     name:'Exfil to Cloud Service',  hits:4  },
      { id:'T1030',     name:'Data Transfer Size Limit',hits:2  },
      { id:'T1020',     name:'Automated Exfiltration',  hits:3  },
      { id:'T1052',     name:'Exfil Over Physical Med.', hits:1 },
      { id:'T1029',     name:'Scheduled Transfer',      hits:2  },
    ]
  },
  {
    tactic:'Impact', id:'TA0040', color:'#ef4444',
    techniques:[
      { id:'T1486',     name:'Data Encrypted (Ransom)', hits:8  },
      { id:'T1490',     name:'Inhibit System Recovery', hits:7  },
      { id:'T1499',     name:'Endpoint Denial of Svc',  hits:4  },
      { id:'T1485',     name:'Data Destruction',        hits:3  },
      { id:'T1491',     name:'Defacement',              hits:2  },
      { id:'T1561',     name:'Disk Wipe',               hits:2  },
      { id:'T1495',     name:'Firmware Corruption',     hits:1  },
    ]
  },
];

/* ═══════════════════════════════════════════
   THREAT INTELLIGENCE — SIMULATED FEEDS
═══════════════════════════════════════════ */
const TI_FEEDS = [
  { name:'VirusTotal',  icon:'🦠', status:'Online', lastSync:'2 min ago', indicators:1842, color:'var(--red)',    apiKey:'VT-****-****-DEMO' },
  { name:'AbuseIPDB',   icon:'🌐', status:'Online', lastSync:'5 min ago', indicators:3201, color:'var(--orange)', apiKey:'AB-****-****-DEMO' },
  { name:'AlienVault OTX',icon:'👽',status:'Online', lastSync:'8 min ago', indicators:2847, color:'var(--accent)', apiKey:'OTX-****-****-DEMO'},
  { name:'Shodan',      icon:'🔍', status:'Online', lastSync:'1 hr ago',  indicators:924,  color:'var(--blue)',   apiKey:'SH-****-****-DEMO'  },
];

/* ═══════════════════════════════════════════
   RENDER — THREAT INTELLIGENCE PAGE
═══════════════════════════════════════════ */
function renderThreatIntel() {
  const threats = db.getThreats();
  return `
<div class="page-header fade-in">
  <div>
    <div class="page-title">🌐 Threat Intelligence</div>
    <div class="page-sub">IOC enrichment, feed correlation and threat actor profiling</div>
  </div>
  <div style="display:flex;gap:8px;">
    <button class="btn btn-ghost btn-sm" onclick="showThreatPage('feeds')">📡 Feed Status</button>
    <button class="btn btn-primary btn-sm" onclick="openIOCLookup()">🔍 IOC Lookup</button>
  </div>
</div>

<div class="page-body fade-in">

  <!-- Feed Health Cards -->
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px;">
    ${TI_FEEDS.map(f=>`
    <div class="stat-card" style="padding:14px 16px;border-left:3px solid ${f.color};">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
        <span style="font-size:18px;">${f.icon}</span>
        <span class="badge badge-success" style="font-size:9px;">● ${f.status}</span>
      </div>
      <div style="font-weight:700;font-size:13px;color:var(--text-1);">${f.name}</div>
      <div style="font-size:10px;color:var(--text-3);margin-top:2px;">Synced ${f.lastSync}</div>
      <div style="font-size:20px;font-weight:700;color:${f.color};margin-top:6px;">${f.indicators.toLocaleString()}</div>
      <div style="font-size:10px;color:var(--text-3);">Active IOCs</div>
    </div>`).join('')}
  </div>

  <!-- IOC Lookup + Known Threats Table -->
  <div style="display:grid;grid-template-columns:1fr 1.5fr;gap:16px;">

    <!-- IOC Lookup Panel -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">🔍 IOC Enrichment Lookup</div>
      </div>
      <div class="panel-body">
        <div class="form-group">
          <label class="form-label">IOC Type</label>
          <select id="iocType" class="form-control" onchange="updateIOCPlaceholder()">
            <option value="ip">IP Address</option>
            <option value="domain">Domain</option>
            <option value="hash">File Hash (MD5/SHA256)</option>
            <option value="url">URL</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">IOC Value</label>
          <div style="display:flex;gap:8px;">
            <input id="iocValue" class="form-control" placeholder="e.g. 192.168.100.50"
              onkeydown="if(event.key==='Enter') lookupIOC()"/>
            <button class="btn btn-primary" onclick="lookupIOC()" style="white-space:nowrap;">🔍 Enrich</button>
          </div>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px;">
          <div style="font-size:11px;color:var(--text-3);width:100%;">Quick lookup:</div>
          ${db.getThreats().slice(0,4).map(t=>`
          <button class="btn btn-ghost btn-sm" style="font-size:10px;" onclick="quickLookup('${t.ioc}','${t.type.toLowerCase()}')">
            ${t.type==='IP'?'🌐':t.type==='Domain'?'🔗':'#️⃣'} ${t.ioc.slice(0,20)}${t.ioc.length>20?'…':''}
          </button>`).join('')}
        </div>
        <div id="iocResult" style="min-height:120px;">
          <div style="text-align:center;padding:30px;color:var(--text-3);">
            <div style="font-size:30px;margin-bottom:8px;">🔍</div>
            Enter an IOC above to enrich it across all threat feeds
          </div>
        </div>
      </div>
    </div>

    <!-- Known IOC Table -->
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">☠️ Known Malicious IOCs</div>
        <span class="tag">${db.getThreats().length} tracked</span>
      </div>
      <div class="tbl-wrap" style="max-height:460px;overflow-y:auto;">
        <table>
          <thead><tr>
            <th>IOC</th><th>Type</th><th>Source</th><th>Confidence</th><th>Tags</th><th>Action</th>
          </tr></thead>
          <tbody>
            ${db.getThreats().map(t=>`
            <tr>
              <td>
                <code style="font-size:11px;color:var(--accent);">${t.ioc}</code>
                <div style="font-size:10px;color:var(--text-3);">${t.label}</div>
              </td>
              <td><span class="badge badge-info" style="font-size:9px;">${t.type}</span></td>
              <td style="font-size:11px;">${t.source}</td>
              <td>
                <div style="display:flex;align-items:center;gap:6px;">
                  <div style="width:40px;height:4px;background:var(--bg-hover);border-radius:2px;">
                    <div style="width:${t.confidence}%;height:100%;background:${t.confidence>85?'var(--red)':t.confidence>70?'var(--orange)':'var(--yellow)'};border-radius:2px;"></div>
                  </div>
                  <span style="font-size:10px;color:var(--text-2);">${t.confidence}%</span>
                </div>
              </td>
              <td>${t.tags.map(tag=>`<span class="tag" style="font-size:9px;">${tag}</span>`).join('')}</td>
              <td>
                <button class="btn btn-ghost btn-sm" style="font-size:10px;" onclick="quickLookup('${t.ioc}','${t.type.toLowerCase()}')">🔍</button>
              </td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
    </div>
  </div>

</div>`;
}

function updateIOCPlaceholder() {
  const type = document.getElementById('iocType').value;
  const placeholders = { ip:'e.g. 185.220.101.5', domain:'e.g. evil.malware.xyz', hash:'e.g. a3f1c8b2d4e6...', url:'e.g. https://malware.xyz/payload' };
  document.getElementById('iocValue').placeholder = placeholders[type] || 'Enter IOC value';
}

function quickLookup(ioc, type) {
  document.getElementById('iocType').value = type === 'ip' ? 'ip' : type === 'domain' ? 'domain' : 'hash';
  document.getElementById('iocValue').value = ioc;
  lookupIOC();
}

function lookupIOC() {
  const ioc  = document.getElementById('iocValue').value.trim();
  const type = document.getElementById('iocType').value;
  const res  = document.getElementById('iocResult');
  if (!ioc) { toast('Enter an IOC value', 'error'); return; }

  res.innerHTML = `<div style="text-align:center;padding:20px;"><div class="login-spin" style="font-size:24px;color:var(--accent);">⟳</div><div style="color:var(--text-3);margin-top:8px;font-size:12px;">Querying ${TI_FEEDS.length} threat feeds…</div></div>`;

  setTimeout(() => {
    const known = db.getThreats().find(t => t.ioc === ioc || ioc.includes(t.ioc));
    const seed  = ioc.split('').reduce((h,c)=>Math.imul(31,h)+c.charCodeAt(0)|0,0);
    const rng   = Math.abs(seed) / 2147483647;
    const vtHits= known ? parseInt(known.vtScore) : Math.floor(rng * 15);
    const vtTotal = type === 'hash' ? 72 : 68;
    const abuseScore = known ? known.abuseScore : Math.floor(rng * 60);
    const confidence = known ? known.confidence : Math.floor(rng * 50 + 20);
    const country = known ? known.country : ['US','RU','CN','DE','BR','IN','FR'][Math.floor(rng*7)];
    const isMalicious = vtHits > 3 || abuseScore > 50 || (known && confidence > 70);
    const verdict = isMalicious ? { label:'MALICIOUS', color:'var(--red)', icon:'☠️' } :
                    vtHits > 0   ? { label:'SUSPICIOUS',color:'var(--orange)', icon:'⚠️' } :
                                   { label:'CLEAN',     color:'var(--green)', icon:'✅' };

    res.innerHTML = `
<div class="ioc-result fade-in">
  <div class="ioc-verdict" style="border-color:${verdict.color};">
    <span style="font-size:22px;">${verdict.icon}</span>
    <div>
      <div style="font-size:14px;font-weight:700;color:${verdict.color};">${verdict.label}</div>
      <code style="font-size:11px;color:var(--text-2);">${ioc}</code>
    </div>
    <div style="margin-left:auto;text-align:right;">
      <div style="font-size:11px;color:var(--text-3);">Threat Score</div>
      <div style="font-size:22px;font-weight:700;color:${verdict.color};">${confidence}%</div>
    </div>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px;">
    <div class="ti-feed-result" style="border-color:var(--red)22;">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:6px;">
        <span>🦠</span><span style="font-size:11px;font-weight:600;">VirusTotal</span>
        <span class="tag" style="margin-left:auto;font-size:9px;color:${vtHits>5?'var(--red)':'var(--green)'};">${vtHits>5?'DETECTED':'CLEAN'}</span>
      </div>
      <div style="font-size:20px;font-weight:700;color:${vtHits>5?'var(--red)':'var(--green)'};">${vtHits}<span style="font-size:11px;color:var(--text-3);">/${vtTotal}</span></div>
      <div style="font-size:10px;color:var(--text-3);">engines detected</div>
    </div>
    <div class="ti-feed-result" style="border-color:var(--orange)22;">
      <div style="display:flex;align-items:center;gap:6px;margin-bottom:6px;">
        <span>🌐</span><span style="font-size:11px;font-weight:600;">AbuseIPDB</span>
        <span class="tag" style="margin-left:auto;font-size:9px;color:${abuseScore>50?'var(--red)':'var(--green)'};">${abuseScore>50?'ABUSIVE':'SAFE'}</span>
      </div>
      <div style="font-size:20px;font-weight:700;color:${abuseScore>50?'var(--red)':'var(--green)'};">${abuseScore}<span style="font-size:11px;color:var(--text-3);">/100</span></div>
      <div style="font-size:10px;color:var(--text-3);">abuse confidence</div>
    </div>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:8px;margin-top:8px;font-size:11px;">
    <div style="background:var(--bg-hover);border-radius:6px;padding:8px;">
      <div style="color:var(--text-3);">Country</div>
      <div style="color:var(--text-1);font-weight:600;">${country}</div>
    </div>
    <div style="background:var(--bg-hover);border-radius:6px;padding:8px;">
      <div style="color:var(--text-3);">Type</div>
      <div style="color:var(--text-1);font-weight:600;">${type.toUpperCase()}</div>
    </div>
    <div style="background:var(--bg-hover);border-radius:6px;padding:8px;">
      <div style="color:var(--text-3);">Last Seen</div>
      <div style="color:var(--text-1);font-weight:600;">${known?.lastseen || 'Unknown'}</div>
    </div>
  </div>

  ${known?.techniques?.length ? `
  <div style="margin-top:8px;font-size:10px;color:var(--text-3);">ATT&CK Techniques:
    ${known.techniques.map(t=>`<span class="tag" style="font-size:9px;color:var(--accent);">${t}</span>`).join('')}
  </div>` : ''}
  ${known?.tags?.length ? `<div style="margin-top:6px;">${known.tags.map(t=>`<span class="tag" style="font-size:9px;">#${t}</span>`).join('')}</div>` : ''}
</div>`;
  }, 1200);
}

function openIOCLookup() {
  document.getElementById('iocValue').focus();
}

/* ═══════════════════════════════════════════
   RENDER — MITRE ATT&CK MATRIX
═══════════════════════════════════════════ */
function renderMitreAttack() {
  const totalTechniques = ATTACK_MATRIX.reduce((s,t)=>s+t.techniques.length, 0);
  const detectedTechs   = ATTACK_MATRIX.reduce((s,t)=>s+t.techniques.filter(tc=>tc.hits>0).length, 0);
  const totalHits       = ATTACK_MATRIX.reduce((s,t)=>s+t.techniques.reduce((ss,tc)=>ss+tc.hits,0), 0);
  const coverage        = Math.round((detectedTechs / totalTechniques) * 100);
  const maxHits         = Math.max(...ATTACK_MATRIX.flatMap(t=>t.techniques.map(tc=>tc.hits)));

  return `
<div class="page-header fade-in">
  <div>
    <div class="page-title">🗡️ MITRE ATT&CK Navigator</div>
    <div class="page-sub">Enterprise technique coverage heatmap across all 13 tactics</div>
  </div>
  <div style="display:flex;gap:8px;align-items:center;">
    <div style="display:flex;align-items:center;gap:6px;font-size:12px;">
      <div style="display:flex;gap:2px;align-items:center;">
        <div style="width:60px;height:8px;background:linear-gradient(to right,rgba(91,120,245,.1),rgba(91,120,245,1));border-radius:2px;"></div>
        <span style="color:var(--text-3);font-size:10px;">0 → ${maxHits} hits</span>
      </div>
    </div>
    <button class="btn btn-ghost btn-sm" onclick="showPage('threat')">← Back to TI</button>
  </div>
</div>

<div class="page-body fade-in">

  <!-- Coverage Stats -->
  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px;">
    <div class="stat-card blue">
      <div class="stat-label">Coverage Score</div>
      <div class="stat-value blue">${coverage}%</div>
      <div class="stat-sub">${detectedTechs}/${totalTechniques} techniques</div>
    </div>
    <div class="stat-card green">
      <div class="stat-label">Total Detections</div>
      <div class="stat-value green">${totalHits}</div>
      <div class="stat-sub">Across all tactics</div>
    </div>
    <div class="stat-card red">
      <div class="stat-label">Tactics Covered</div>
      <div class="stat-value red">${ATTACK_MATRIX.filter(t=>t.techniques.some(tc=>tc.hits>0)).length}</div>
      <div class="stat-sub">of ${ATTACK_MATRIX.length} total</div>
    </div>
    <div class="stat-card purple">
      <div class="stat-label">Highest Activity</div>
      <div class="stat-value" style="color:var(--accent2);">${maxHits}</div>
      <div class="stat-sub">Max hits on one technique</div>
    </div>
  </div>

  <!-- Tactic Coverage Bar Chart -->
  <div class="panel" style="margin-bottom:20px;">
    <div class="panel-header">
      <div class="panel-title">📊 Tactic Detection Coverage</div>
    </div>
    <div class="panel-body" style="padding:16px 20px;">
      <div style="display:grid;gap:8px;">
        ${ATTACK_MATRIX.map(t => {
          const tHits = t.techniques.reduce((s,tc)=>s+tc.hits,0);
          const tCov  = Math.round((t.techniques.filter(tc=>tc.hits>0).length / t.techniques.length)*100);
          return `
          <div style="display:grid;grid-template-columns:160px 1fr 60px 50px;align-items:center;gap:10px;">
            <div style="font-size:11px;font-weight:600;color:var(--text-1);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${t.tactic}">${t.tactic}</div>
            <div class="progress-bar" style="height:8px;">
              <div class="progress-fill" style="width:${tCov}%;background:${t.color};"></div>
            </div>
            <div style="font-size:11px;color:${t.color};font-weight:600;text-align:right;">${tCov}%</div>
            <div style="font-size:10px;color:var(--text-3);text-align:right;">${tHits} hits</div>
          </div>`;
        }).join('')}
      </div>
    </div>
  </div>

  <!-- ATT&CK Matrix Heatmap -->
  <div class="panel">
    <div class="panel-header">
      <div class="panel-title">🗺️ ATT&CK Matrix Heatmap</div>
      <div style="display:flex;gap:8px;align-items:center;font-size:11px;color:var(--text-3);">
        <span>Click any technique for details</span>
        <div class="heatmap-legend">
          <div style="width:12px;height:12px;background:rgba(91,120,245,.08);border-radius:2px;"></div><span>No hits</span>
          <div style="width:12px;height:12px;background:rgba(91,120,245,.4);border-radius:2px;"></div><span>Low</span>
          <div style="width:12px;height:12px;background:rgba(91,120,245,.7);border-radius:2px;"></div><span>Medium</span>
          <div style="width:12px;height:12px;background:rgba(91,120,245,1);border-radius:2px;"></div><span>High</span>
        </div>
      </div>
    </div>
    <div class="attack-matrix-wrap">
      <div class="attack-matrix">
        ${ATTACK_MATRIX.map(t => `
        <div class="attack-col">
          <div class="attack-tactic-header" style="border-top:3px solid ${t.color};">
            <div style="font-size:10px;font-weight:700;color:${t.color};white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="${t.tactic}">${t.tactic}</div>
            <div style="font-size:9px;color:var(--text-3);">${t.id}</div>
          </div>
          ${t.techniques.map(tc => {
            const intensity = maxHits > 0 ? tc.hits / maxHits : 0;
            const bg  = tc.hits > 0
              ? `rgba(${hexToRgb(t.color)},${Math.max(0.15, intensity)})`
              : 'rgba(99,120,220,.05)';
            const textColor = tc.hits > 0 ? '#fff' : 'var(--text-3)';
            return `
            <div class="attack-tech" style="background:${bg};color:${textColor};"
              onclick="showTechniqueDetail('${tc.id}','${tc.name.replace(/'/g,'\\'')}',${tc.hits},'${t.tactic}','${t.id}')"
              title="${tc.id}: ${tc.name} (${tc.hits} hits)">
              <div style="font-size:8.5px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${tc.name}</div>
              <div style="font-size:8px;opacity:.7;font-family:monospace;">${tc.id}</div>
              ${tc.hits > 0 ? `<div class="tech-hit-badge">${tc.hits}</div>` : ''}
            </div>`;
          }).join('')}
        </div>`).join('')}
      </div>
    </div>
  </div>

</div>

<div id="attackTechModal"></div>`;
}

function hexToRgb(cssVar) {
  // Map our CSS vars to RGB for the heatmap
  const map = {
    '#6366f1':'99,102,241','#8b5cf6':'139,92,246','#ec4899':'236,72,153',
    '#f97316':'249,115,22','#ef4444':'239,68,68','#14b8a6':'20,184,166',
    '#f59e0b':'245,158,11','#3b82f6':'59,130,246','#0ea5e9':'14,165,233',
    '#10b981':'16,185,129','#8b5cf6':'139,92,246',
  };
  return map[cssVar] || '91,120,245';
}

function showTechniqueDetail(id, name, hits, tactic, tacticId) {
  const el = document.getElementById('attackTechModal');
  if (!el) return;
  const alerts = db.getAlerts().filter(a => a.technique === id || a.technique.startsWith(id + '.'));
  const mitigation = (typeof MITIGATIONS !== 'undefined' && MITIGATIONS[id]) ? MITIGATIONS[id] : ['Review security controls for this technique','Apply least-privilege principle','Monitor event logs for related activity','Deploy specific detection rules'];

  el.innerHTML = `
<div class="modal-overlay" onclick="if(event.target===this)this.remove()">
  <div class="modal" style="width:560px;">
    <div class="modal-header">
      <div>
        <div class="modal-title">🗡️ ${name}</div>
        <div style="font-size:11px;color:var(--accent);font-family:monospace;">${id} · ${tactic} (${tacticId})</div>
      </div>
      <button class="modal-close" onclick="this.closest('.modal-overlay').remove()">×</button>
    </div>
    <div class="modal-body">
      <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:16px;">
        <div class="mini-score-card">
          <div class="mini-score-label">Detection Hits</div>
          <div class="mini-score-val" style="color:${hits>5?'var(--red)':hits>2?'var(--orange)':'var(--green)'};">${hits}</div>
        </div>
        <div class="mini-score-card">
          <div class="mini-score-label">Tactic Stage</div>
          <div style="font-size:12px;font-weight:600;color:var(--text-1);margin-top:4px;">${tactic}</div>
        </div>
        <div class="mini-score-card">
          <div class="mini-score-label">Related Alerts</div>
          <div class="mini-score-val" style="color:var(--accent);">${alerts.length}</div>
        </div>
      </div>

      <div style="margin-bottom:14px;">
        <div class="ai-section-title">🛡️ Mitigations</div>
        ${mitigation.map(m=>`<div style="font-size:12px;color:var(--text-2);padding:5px 0;border-bottom:1px solid rgba(99,120,220,.06);">• ${m}</div>`).join('')}
      </div>

      ${alerts.length > 0 ? `
      <div>
        <div class="ai-section-title">🚨 Related Active Alerts (${alerts.length})</div>
        ${alerts.slice(0,3).map(a=>`
        <div style="padding:8px 10px;background:var(--bg-hover);border-radius:6px;margin-bottom:6px;font-size:11px;">
          <div style="color:var(--text-1);font-weight:600;">${a.title}</div>
          <div style="color:var(--text-3);">${a.asset} · ${a.status} · ${a.confidence}% confidence</div>
        </div>`).join('')}
      </div>` : ''}
    </div>
    <div class="modal-footer">
      <button class="btn btn-ghost" onclick="this.closest('.modal-overlay').remove()">Close</button>
      ${typeof showPage === 'function' ? `<button class="btn btn-primary" onclick="this.closest('.modal-overlay').remove();showPage('copilot')">🤖 Go to AI Copilot</button>` : ''}
    </div>
  </div>
</div>`;
}

let _currentThreatPage = 'intel';
function showThreatPage(sub) {
  _currentThreatPage = sub;
  if (sub === 'attack') {
    document.getElementById('mainContent').innerHTML = renderMitreAttack();
  } else {
    renderThreatModule();
  }
}

function renderThreatModule() {
  const main = document.getElementById('mainContent');
  const subNav = `<div style="background:var(--bg-card);border-bottom:1px solid var(--border);padding:0 32px;display:flex;gap:4px;">
    ${[['intel','🌐 Threat Intelligence'],['attack','🗡️ MITRE ATT&CK']].map(([id,label])=>`
    <button onclick="showThreatPage('${id}')"
      style="padding:10px 16px;background:none;border:none;border-bottom:2px solid ${_currentThreatPage===id?'var(--accent)':'transparent'};
      color:${_currentThreatPage===id?'var(--accent)':'var(--text-2)'};cursor:pointer;font-family:inherit;font-size:13px;
      font-weight:${_currentThreatPage===id?600:400};transition:all .18s;">${label}</button>`).join('')}
  </div>`;
  let content = _currentThreatPage === 'attack' ? renderMitreAttack() : renderThreatIntel();
  main.innerHTML = subNav + content;
}
