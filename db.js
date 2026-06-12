/* =============================================
   db.js – In-Memory Database (localStorage)
   Extended with: Users, Threats, Alerts,
   Risk Scoring, Response Playbooks
   ============================================= */

const DB_KEY      = 'sentinel_pm';
const USERS_KEY   = 'sentinel_users';
const THREATS_KEY = 'sentinel_threats';
const ALERTS_KEY  = 'sentinel_alerts';

/* ─────────────────────────────────────────────
   SEED DATA
   ───────────────────────────────────────────── */
const SEED = {
  patches: [
    { id:'P001', patch_name:'Windows Kernel Elevation of Privilege', patch_version:'KB5034441', vendor:'Microsoft', release_date:'2024-01-09', severity:'Critical', description:'Patches a privilege escalation vulnerability in the Windows kernel affecting all modern versions.' },
    { id:'P002', patch_name:'OpenSSL Security Update',               patch_version:'3.2.1',      vendor:'OpenSSL',   release_date:'2024-01-16', severity:'High',     description:'Fixes a buffer overflow vulnerability in TLS handshake processing.' },
    { id:'P003', patch_name:'Apache HTTP Server Fix',                patch_version:'2.4.59',     vendor:'Apache',    release_date:'2024-02-01', severity:'High',     description:'Addresses a remote code execution flaw in mod_proxy module.' },
    { id:'P004', patch_name:'Chrome Browser Update',                 patch_version:'121.0.6167', vendor:'Google',    release_date:'2024-01-23', severity:'Medium',   description:'Patches multiple V8 engine memory corruption issues.' },
    { id:'P005', patch_name:'VMware ESXi Update',                    patch_version:'8.0U2a',     vendor:'VMware',    release_date:'2024-02-05', severity:'Critical', description:'Resolves a VMCI (VM Communication Interface) heap overflow flaw.' },
    { id:'P006', patch_name:'Linux Kernel NFTABLES Fix',             patch_version:'6.6.14',     vendor:'Kernel.org',release_date:'2024-02-10', severity:'High',     description:'Fixes a use-after-free vulnerability in the netfilter subsystem.' },
    { id:'P007', patch_name:'NGINX Security Patch',                  patch_version:'1.25.4',     vendor:'NGINX Inc', release_date:'2024-02-12', severity:'Medium',   description:'Corrects an HTTP/2 CONTINUATION frame resource exhaustion issue.' },
    { id:'P008', patch_name:'Oracle JDK Critical Patch',             patch_version:'21.0.2',     vendor:'Oracle',    release_date:'2024-01-16', severity:'Critical', description:'Multiple RCE and denial-of-service fixes across Java runtime.' },
    { id:'P009', patch_name:'FortiGate SSL-VPN Patch',               patch_version:'7.4.3',      vendor:'Fortinet',  release_date:'2024-02-20', severity:'Critical', description:'Addresses a heap overflow in SSL-VPN that enables unauthenticated RCE.' },
    { id:'P010', patch_name:'MySQL Connector Fix',                   patch_version:'8.3.0',      vendor:'Oracle',    release_date:'2024-02-22', severity:'Low',      description:'Minor patch for connector library auth bypass on specific configurations.' },
  ],
  assets: [
    { id:'A001', name:'WEB-SVR-01',  type:'Server',      os:'Windows Server 2022', ip:'10.0.1.10' },
    { id:'A002', name:'WEB-SVR-02',  type:'Server',      os:'Ubuntu 22.04',        ip:'10.0.1.11' },
    { id:'A003', name:'DB-SVR-01',   type:'Server',      os:'Windows Server 2019', ip:'10.0.2.10' },
    { id:'A004', name:'DEV-WS-01',   type:'Workstation', os:'Windows 11',          ip:'10.0.3.20' },
    { id:'A005', name:'DEV-WS-02',   type:'Workstation', os:'macOS 14',            ip:'10.0.3.21' },
    { id:'A006', name:'PROXY-01',    type:'Network',     os:'Ubuntu 20.04',        ip:'10.0.4.5'  },
    { id:'A007', name:'STORAGE-01',  type:'Server',      os:'Windows Server 2022', ip:'10.0.5.10' },
  ],
  assignments: [
    { id:'ASN001', patch_id:'P001', asset_id:'A001', scheduled_date:'2024-02-28', status:'Successful',  assigned_by:'Admin',  notes:'Deployed in maintenance window.' },
    { id:'ASN002', patch_id:'P001', asset_id:'A003', scheduled_date:'2024-02-28', status:'Successful',  assigned_by:'Admin',  notes:'' },
    { id:'ASN003', patch_id:'P002', asset_id:'A002', scheduled_date:'2024-03-01', status:'Failed',      assigned_by:'SecOps', notes:'Service dependency conflict.' },
    { id:'ASN004', patch_id:'P003', asset_id:'A006', scheduled_date:'2024-03-05', status:'In Progress', assigned_by:'SecOps', notes:'Rolling update in progress.' },
    { id:'ASN005', patch_id:'P005', asset_id:'A007', scheduled_date:'2024-03-10', status:'Scheduled',   assigned_by:'Admin',  notes:'Scheduled for weekend.' },
    { id:'ASN006', patch_id:'P009', asset_id:'A001', scheduled_date:'2024-03-12', status:'Pending',     assigned_by:'SecOps', notes:'Awaiting change approval.' },
    { id:'ASN007', patch_id:'P008', asset_id:'A004', scheduled_date:'2024-02-25', status:'Rolled Back', assigned_by:'Admin',  notes:'Compatibility issue with app.' },
    { id:'ASN008', patch_id:'P004', asset_id:'A004', scheduled_date:'2024-03-14', status:'Pending',     assigned_by:'SecOps', notes:'' },
    { id:'ASN009', patch_id:'P006', asset_id:'A002', scheduled_date:'2024-03-15', status:'Scheduled',   assigned_by:'Admin',  notes:'' },
    { id:'ASN010', patch_id:'P007', asset_id:'A006', scheduled_date:'2024-03-08', status:'Successful',  assigned_by:'SecOps', notes:'Auto-patched via pipeline.' },
  ]
};

const SEED_USERS = [
  { id:'U001', username:'admin',   password:'Admin@123',   role:'admin',   name:'Kishore S.', email:'admin@sentinel.ai',   avatar:'KS', lastLogin:null, failedAttempts:0, locked:false },
  { id:'U002', username:'analyst', password:'Analyst@123', role:'analyst', name:'Sarah M.',   email:'analyst@sentinel.ai', avatar:'SM', lastLogin:null, failedAttempts:0, locked:false },
  { id:'U003', username:'viewer',  password:'Viewer@123',  role:'viewer',  name:'James L.',   email:'viewer@sentinel.ai',  avatar:'JL', lastLogin:null, failedAttempts:0, locked:false },
];

const SEED_THREATS = [
  { id:'T001', ioc:'192.168.100.50', type:'IP',     label:'Malicious IP',       source:'AbuseIPDB', confidence:94, tags:['c2','botnet'],       vtScore:'48/72', abuseScore:100, country:'RU', lastseen:'2024-03-10', techniques:['T1071','T1095'] },
  { id:'T002', ioc:'evil.malware.xyz', type:'Domain', label:'C2 Domain',        source:'OTX',       confidence:88, tags:['c2','phishing'],     vtScore:'38/68', abuseScore:87,  country:'CN', lastseen:'2024-03-12', techniques:['T1071','T1568'] },
  { id:'T003', ioc:'a3f1c8b2d4e6f0a1b2c3d4e5f6a7b8c9', type:'Hash', label:'Ransomware Hash', source:'VirusTotal', confidence:99, tags:['ransomware','malware'], vtScore:'63/72', abuseScore:0, country:'—', lastseen:'2024-03-08', techniques:['T1486','T1490'] },
  { id:'T004', ioc:'10.0.4.99',  type:'IP',     label:'Lateral Movement',   source:'SIEM',      confidence:76, tags:['lateral','scan'],    vtScore:'0/72',  abuseScore:42,  country:'Internal', lastseen:'2024-03-14', techniques:['T1021','T1076'] },
  { id:'T005', ioc:'185.220.101.5', type:'IP',  label:'Tor Exit Node',      source:'AbuseIPDB', confidence:91, tags:['tor','proxy'],        vtScore:'12/72', abuseScore:100, country:'DE', lastseen:'2024-03-15', techniques:['T1090','T1188'] },
  { id:'T006', ioc:'malicious-update.com', type:'Domain', label:'Supply Chain Domain', source:'OTX', confidence:83, tags:['supply-chain'], vtScore:'22/68', abuseScore:75, country:'KP', lastseen:'2024-03-11', techniques:['T1195','T1071'] },
  { id:'T007', ioc:'b9e2f3a4c5d6e7f8a9b0c1d2e3f4a5b6', type:'Hash', label:'InfoStealer', source:'VirusTotal', confidence:96, tags:['infostealer','credential-theft'], vtScore:'58/72', abuseScore:0, country:'—', lastseen:'2024-03-13', techniques:['T1555','T1003'] },
  { id:'T008', ioc:'103.87.65.21', type:'IP',   label:'Brute Force Source',  source:'AbuseIPDB', confidence:79, tags:['bruteforce','auth'], vtScore:'5/72',  abuseScore:88,  country:'BR', lastseen:'2024-03-15', techniques:['T1110','T1078'] },
];

const now = Date.now();
const SEED_ALERTS = [
  { id:'AL001', title:'Suspicious PowerShell Execution',        asset:'WEB-SVR-01', assetId:'A001', severity:'Critical', status:'Open',         timestamp: now - 1800000,  technique:'T1059.001', tactic:'Execution',           confidence:94, falsePositive:false, assignedTo:null, notes:'', anomalyScore:91, sigScore:97, behaviorScore:88 },
  { id:'AL002', title:'Brute Force Attack Detected',            asset:'WEB-SVR-02', assetId:'A002', severity:'High',     status:'Investigating', timestamp: now - 3600000,  technique:'T1110',     tactic:'Credential Access',   confidence:87, falsePositive:false, assignedTo:'analyst', notes:'Checking source IPs', anomalyScore:82, sigScore:88, behaviorScore:91 },
  { id:'AL003', title:'Lateral Movement via SMB',               asset:'DB-SVR-01',  assetId:'A003', severity:'Critical', status:'Open',         timestamp: now - 900000,   technique:'T1021.002', tactic:'Lateral Movement',    confidence:91, falsePositive:false, assignedTo:null, notes:'', anomalyScore:89, sigScore:94, behaviorScore:90 },
  { id:'AL004', title:'Anomalous Data Exfiltration Volume',     asset:'PROXY-01',   assetId:'A006', severity:'High',     status:'Resolved',     timestamp: now - 86400000, technique:'T1048',     tactic:'Exfiltration',        confidence:78, falsePositive:false, assignedTo:'admin', notes:'Confirmed false positive - backup job', anomalyScore:76, sigScore:65, behaviorScore:93 },
  { id:'AL005', title:'Ransomware IOC Signature Match',         asset:'DEV-WS-01',  assetId:'A004', severity:'Critical', status:'Open',         timestamp: now - 600000,   technique:'T1486',     tactic:'Impact',              confidence:99, falsePositive:false, assignedTo:null, notes:'', anomalyScore:97, sigScore:99, behaviorScore:98 },
  { id:'AL006', title:'C2 Beaconing to Known Malicious Domain', asset:'WEB-SVR-01', assetId:'A001', severity:'High',     status:'Open',         timestamp: now - 2400000,  technique:'T1071.001', tactic:'Command and Control',  confidence:88, falsePositive:false, assignedTo:null, notes:'', anomalyScore:85, sigScore:91, behaviorScore:88 },
  { id:'AL007', title:'Privilege Escalation Attempt',           asset:'DB-SVR-01',  assetId:'A003', severity:'High',     status:'Investigating', timestamp: now - 5400000,  technique:'T1068',     tactic:'Privilege Escalation', confidence:82, falsePositive:false, assignedTo:'analyst', notes:'', anomalyScore:80, sigScore:84, behaviorScore:82 },
  { id:'AL008', title:'Unauthorized Registry Modification',     asset:'DEV-WS-01',  assetId:'A004', severity:'Medium',   status:'Open',         timestamp: now - 7200000,  technique:'T1112',     tactic:'Defense Evasion',     confidence:71, falsePositive:false, assignedTo:null, notes:'', anomalyScore:68, sigScore:74, behaviorScore:71 },
  { id:'AL009', title:'Credential Dumping via LSASS',           asset:'WEB-SVR-01', assetId:'A001', severity:'Critical', status:'Open',         timestamp: now - 300000,   technique:'T1003.001', tactic:'Credential Access',   confidence:96, falsePositive:false, assignedTo:null, notes:'', anomalyScore:94, sigScore:98, behaviorScore:96 },
  { id:'AL010', title:'Suspicious Network Scan Detected',       asset:'PROXY-01',   assetId:'A006', severity:'Medium',   status:'Open',         timestamp: now - 10800000, technique:'T1046',     tactic:'Discovery',           confidence:65, falsePositive:false, assignedTo:null, notes:'', anomalyScore:62, sigScore:68, behaviorScore:65 },
  { id:'AL011', title:'Phishing Email with Malicious Payload',  asset:'DEV-WS-02',  assetId:'A005', severity:'High',     status:'Resolved',     timestamp: now - 172800000,technique:'T1566.001', tactic:'Initial Access',      confidence:93, falsePositive:false, assignedTo:'admin', notes:'User reported, sandbox detonated', anomalyScore:90, sigScore:95, behaviorScore:94 },
  { id:'AL012', title:'Tor Exit Node Communication',            asset:'STORAGE-01', assetId:'A007', severity:'High',     status:'Open',         timestamp: now - 1200000,  technique:'T1090',     tactic:'Command and Control',  confidence:85, falsePositive:false, assignedTo:null, notes:'', anomalyScore:83, sigScore:87, behaviorScore:85 },
];

const SEED_PLAYBOOKS = [
  { id:'PB001', name:'Critical Alert Auto-Escalation',   trigger:'severity=Critical,status=Open,age>300000',  actions:['notify_admin','create_ticket','isolate_asset'],  enabled:true  },
  { id:'PB002', name:'Brute Force Auto-Block',           trigger:'technique=T1110,confidence>80',              actions:['block_ip','notify_analyst','log_event'],          enabled:true  },
  { id:'PB003', name:'Ransomware Containment',           trigger:'technique=T1486,confidence>85',              actions:['isolate_asset','snapshot_disk','notify_admin'],   enabled:true  },
  { id:'PB004', name:'False Positive Auto-Resolve',      trigger:'confidence<40,anomalyScore<35',              actions:['mark_fp','close_alert','log_event'],              enabled:false },
  { id:'PB005', name:'C2 Network Block',                 trigger:'tactic=Command and Control,confidence>75',  actions:['block_ip','block_domain','notify_analyst'],       enabled:true  },
];

/* ─────────────────────────────────────────────
   PATCH / ASSET / ASSIGNMENT STORE
   ───────────────────────────────────────────── */
function loadDB() {
  try {
    const raw = localStorage.getItem(DB_KEY);
    if (raw) return JSON.parse(raw);
  } catch(e) {}
  localStorage.setItem(DB_KEY, JSON.stringify(SEED));
  return JSON.parse(JSON.stringify(SEED));
}

function saveDB(data) { localStorage.setItem(DB_KEY, JSON.stringify(data)); }
function resetDB()    { localStorage.setItem(DB_KEY, JSON.stringify(SEED)); return JSON.parse(JSON.stringify(SEED)); }

let DB = loadDB();

/* ─────────────────────────────────────────────
   USERS STORE
   ───────────────────────────────────────────── */
function loadUsers() {
  try {
    const raw = localStorage.getItem(USERS_KEY);
    if (raw) return JSON.parse(raw);
  } catch(e) {}
  localStorage.setItem(USERS_KEY, JSON.stringify(SEED_USERS));
  return JSON.parse(JSON.stringify(SEED_USERS));
}
function saveUsers(u) { localStorage.setItem(USERS_KEY, JSON.stringify(u)); }

/* ─────────────────────────────────────────────
   THREATS STORE
   ───────────────────────────────────────────── */
function loadThreats() {
  try {
    const raw = localStorage.getItem(THREATS_KEY);
    if (raw) return JSON.parse(raw);
  } catch(e) {}
  localStorage.setItem(THREATS_KEY, JSON.stringify(SEED_THREATS));
  return JSON.parse(JSON.stringify(SEED_THREATS));
}
function saveThreats(t) { localStorage.setItem(THREATS_KEY, JSON.stringify(t)); }

/* ─────────────────────────────────────────────
   ALERTS STORE
   ───────────────────────────────────────────── */
function loadAlerts() {
  try {
    const raw = localStorage.getItem(ALERTS_KEY);
    if (raw) return JSON.parse(raw);
  } catch(e) {}
  localStorage.setItem(ALERTS_KEY, JSON.stringify(SEED_ALERTS));
  return JSON.parse(JSON.stringify(SEED_ALERTS));
}
function saveAlerts(a) { localStorage.setItem(ALERTS_KEY, JSON.stringify(a)); }

/* ─────────────────────────────────────────────
   GLOBAL DB FACADE
   ───────────────────────────────────────────── */
const db = {
  /* ── Patches ── */
  getPatches:  ()    => DB.patches,
  getPatch:    (id)  => DB.patches.find(p => p.id === id),
  addPatch(p) {
    p.id = 'P' + String(DB.patches.length + 1).padStart(3,'0') + '_' + Date.now().toString(36);
    DB.patches.push(p); saveDB(DB); return p;
  },
  updatePatch(id, data) {
    const i = DB.patches.findIndex(p => p.id === id);
    if (i > -1) { DB.patches[i] = {...DB.patches[i], ...data}; saveDB(DB); }
  },
  deletePatch(id) {
    DB.patches = DB.patches.filter(p => p.id !== id);
    DB.assignments = DB.assignments.filter(a => a.patch_id !== id);
    saveDB(DB);
  },

  /* ── Assets ── */
  getAssets: ()    => DB.assets,
  getAsset:  (id)  => DB.assets.find(a => a.id === id),

  /* ── Assignments ── */
  getAssignments: ()    => DB.assignments,
  getAssignment:  (id)  => DB.assignments.find(a => a.id === id),
  addAssignment(a) {
    a.id = 'ASN' + String(DB.assignments.length + 1).padStart(3,'0') + '_' + Date.now().toString(36);
    DB.assignments.push(a); saveDB(DB); return a;
  },
  addBulkAssignments(patch_id, asset_ids, scheduled_date, assigned_by) {
    const added = [];
    asset_ids.forEach(aid => {
      const a = { id:'ASN'+String(DB.assignments.length+added.length+1).padStart(3,'0')+'_'+Date.now().toString(36),
        patch_id, asset_id: aid, scheduled_date, status:'Pending', assigned_by, notes:'' };
      DB.assignments.push(a); added.push(a);
    });
    saveDB(DB); return added;
  },
  updateAssignment(id, data) {
    const i = DB.assignments.findIndex(a => a.id === id);
    if (i > -1) { DB.assignments[i] = {...DB.assignments[i], ...data}; saveDB(DB); }
  },
  deleteAssignment(id) {
    DB.assignments = DB.assignments.filter(a => a.id !== id); saveDB(DB);
  },

  /* ── Stats ── */
  stats() {
    const asgn  = DB.assignments;
    const total    = DB.patches.length;
    const pending  = asgn.filter(a => a.status === 'Pending' || a.status === 'Scheduled').length;
    const failed   = asgn.filter(a => a.status === 'Failed').length;
    const success  = asgn.filter(a => a.status === 'Successful').length;
    const totalDep = asgn.length;
    const compliance = totalDep ? Math.round((success / totalDep) * 100) : 0;
    return { total, pending, failed, success, totalDep, compliance };
  },

  /* ── Users ── */
  getUsers:  ()    => loadUsers(),
  getUser:   (id)  => loadUsers().find(u => u.id === id),
  getUserByName: (username) => loadUsers().find(u => u.username === username),
  updateUser(id, data) {
    const users = loadUsers();
    const i = users.findIndex(u => u.id === id);
    if (i > -1) { users[i] = {...users[i], ...data}; saveUsers(users); }
  },

  /* ── Threats ── */
  getThreats:  ()    => loadThreats(),
  getThreat:   (id)  => loadThreats().find(t => t.id === id),
  addThreat(t) {
    const threats = loadThreats();
    t.id = 'T' + String(threats.length + 1).padStart(3,'0') + '_' + Date.now().toString(36);
    threats.push(t); saveThreats(threats); return t;
  },

  /* ── Alerts ── */
  getAlerts:  ()    => loadAlerts(),
  getAlert:   (id)  => loadAlerts().find(a => a.id === id),
  addAlert(a) {
    const alerts = loadAlerts();
    a.id = 'AL' + String(alerts.length + 1).padStart(3,'0') + '_' + Date.now().toString(36);
    a.timestamp = Date.now();
    alerts.unshift(a); saveAlerts(alerts); return a;
  },
  updateAlert(id, data) {
    const alerts = loadAlerts();
    const i = alerts.findIndex(a => a.id === id);
    if (i > -1) { alerts[i] = {...alerts[i], ...data}; saveAlerts(alerts); }
  },
  deleteAlert(id) {
    const alerts = loadAlerts().filter(a => a.id !== id);
    saveAlerts(alerts);
  },
  alertStats() {
    const alerts = loadAlerts();
    const open     = alerts.filter(a => a.status === 'Open').length;
    const invest   = alerts.filter(a => a.status === 'Investigating').length;
    const resolved = alerts.filter(a => a.status === 'Resolved').length;
    const critical = alerts.filter(a => a.severity === 'Critical' && a.status !== 'Resolved').length;
    const high     = alerts.filter(a => a.severity === 'High'     && a.status !== 'Resolved').length;
    const fp       = alerts.filter(a => a.falsePositive).length;
    const avgConf  = alerts.length ? Math.round(alerts.reduce((s,a)=>s+a.confidence,0)/alerts.length) : 0;
    return { open, invest, resolved, critical, high, fp, total: alerts.length, avgConf };
  },

  /* ── Playbooks ── */
  getPlaybooks:    ()    => SEED_PLAYBOOKS,
  getPlaybook:     (id)  => SEED_PLAYBOOKS.find(p => p.id === id),
  togglePlaybook(id) {
    const pb = SEED_PLAYBOOKS.find(p => p.id === id);
    if (pb) pb.enabled = !pb.enabled;
  },

  /* ── Risk Scoring ── */
  riskScore(assetId) {
    const asgn   = DB.assignments.filter(a => a.asset_id === assetId);
    const alerts = loadAlerts().filter(a => a.assetId === assetId && a.status !== 'Resolved');
    const total  = asgn.length;
    const fail   = asgn.filter(a => a.status === 'Failed' || a.status === 'Rolled Back').length;
    const pend   = asgn.filter(a => a.status === 'Pending' || a.status === 'Scheduled').length;

    // Patch compliance score (0-40)
    const patchScore = total ? Math.round((1 - (fail + pend * 0.5) / total) * 40) : 40;

    // Alert threat score (0-60)
    let alertScore = 0;
    alerts.forEach(al => {
      if (al.severity === 'Critical') alertScore += 20;
      else if (al.severity === 'High') alertScore += 12;
      else if (al.severity === 'Medium') alertScore += 6;
      else alertScore += 2;
    });
    alertScore = Math.min(60, alertScore);

    const raw = Math.min(100, Math.max(0, (60 - patchScore) + alertScore));
    const level = raw >= 70 ? 'Critical' : raw >= 45 ? 'High' : raw >= 25 ? 'Medium' : 'Low';
    const color = raw >= 70 ? 'var(--red)' : raw >= 45 ? 'var(--orange)' : raw >= 25 ? 'var(--yellow)' : 'var(--green)';
    return { score: raw, level, color };
  },

  overallRisk() {
    const assets = DB.assets;
    const scores = assets.map(a => this.riskScore(a.id).score);
    const avg = scores.length ? Math.round(scores.reduce((s,x)=>s+x,0)/scores.length) : 0;
    return { score: avg, level: avg>=70?'Critical':avg>=45?'High':avg>=25?'Medium':'Low', color: avg>=70?'var(--red)':avg>=45?'var(--orange)':avg>=25?'var(--yellow)':'var(--green)' };
  }
};
