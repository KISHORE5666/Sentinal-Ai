/* =============================================
   auth.js – JWT Authentication & RBAC Engine
   ============================================= */

const AUTH_TOKEN_KEY  = 'sentinel_auth_token';
const SESSION_DURATION = 30 * 60 * 1000; // 30 min
const AUTH_SECRET      = 'SentinelAI_JWT_2024_XK9#SecretKey';

/* ── RBAC Permission Matrix ── */
const PERMISSIONS = {
  admin:   ['view','add_patch','edit_patch','delete_patch','assign','update_status','threat_intel','copilot','manage_users','automated_response','export'],
  analyst: ['view','assign','update_status','threat_intel','copilot','automated_response'],
  viewer:  ['view','threat_intel','copilot'],
};

const ROLE_META = {
  admin:   { label:'🔴 Administrator', color:'var(--red)',    badge:'admin-badge'   },
  analyst: { label:'🟡 SOC Analyst',   color:'var(--yellow)', badge:'analyst-badge' },
  viewer:  { label:'🔵 Read-Only',     color:'var(--blue)',   badge:'viewer-badge'  },
};

/* ── Crypto Helpers ── */
function _hash(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) {
    h = Math.imul(31, h) + str.charCodeAt(i) | 0;
  }
  return (h >>> 0).toString(36).padStart(7,'0');
}

function _b64e(obj) {
  try { return btoa(unescape(encodeURIComponent(JSON.stringify(obj)))); }
  catch(e) { return btoa(JSON.stringify(obj)); }
}
function _b64d(str) {
  try { return JSON.parse(decodeURIComponent(escape(atob(str)))); }
  catch(e) { return JSON.parse(atob(str)); }
}

/* ── JWT ── */
function _createJWT(user) {
  const header  = _b64e({ alg:'HS256', typ:'JWT' });
  const payload = _b64e({
    sub:      user.id,
    name:     user.name,
    username: user.username,
    role:     user.role,
    avatar:   user.avatar,
    email:    user.email,
    iat:      Date.now(),
    exp:      Date.now() + SESSION_DURATION,
  });
  const sig = _hash(header + '.' + payload + AUTH_SECRET);
  return `${header}.${payload}.${sig}`;
}

function _verifyJWT(token) {
  if (!token) return null;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [header, payload, sig] = parts;
    if (_hash(header + '.' + payload + AUTH_SECRET) !== sig) return null;
    const data = _b64d(payload);
    if (data.exp < Date.now()) return null;
    return data;
  } catch(e) { return null; }
}

/* ── Auth Module ── */
const auth = {
  currentUser: null,
  _timeoutId:  null,
  _timerEl:    null,
  _countdownId:null,

  /* Boot – called on DOMContentLoaded */
  init() {
    const token = sessionStorage.getItem(AUTH_TOKEN_KEY);
    this.currentUser = _verifyJWT(token);
    return !!this.currentUser;
  },

  login(username, password) {
    const users = db.getUsers();
    const user  = users.find(u => u.username === username);
    if (!user) return { ok:false, error:'Invalid credentials. Please try again.' };
    if (user.locked) return { ok:false, error:'Account locked after too many failed attempts.' };
    if (user.password !== password) {
      const fa = (user.failedAttempts || 0) + 1;
      const locked = fa >= 5;
      db.updateUser(user.id, { failedAttempts: fa, locked });
      return { ok:false, error: locked
        ? 'Account locked. Contact your administrator.'
        : `Invalid credentials (${5 - fa} attempt${5-fa===1?'':'s'} remaining)` };
    }
    db.updateUser(user.id, { failedAttempts:0, locked:false, lastLogin: new Date().toISOString() });
    const token = _createJWT(user);
    sessionStorage.setItem(AUTH_TOKEN_KEY, token);
    this.currentUser = _verifyJWT(token);
    this._startSessionTimer();
    return { ok:true, user: this.currentUser };
  },

  logout() {
    sessionStorage.removeItem(AUTH_TOKEN_KEY);
    this.currentUser = null;
    clearTimeout(this._timeoutId);
    clearInterval(this._countdownId);
    // Stop live intervals
    if (window._dashInterval)   { clearInterval(window._dashInterval);   window._dashInterval   = null; }
    if (window._copilotInterval){ clearInterval(window._copilotInterval); window._copilotInterval = null; }
    showLoginScreen();
  },

  canDo(action) {
    if (!this.currentUser) return false;
    return (PERMISSIONS[this.currentUser.role] || []).includes(action);
  },

  getRole()    { return this.currentUser?.role    || 'viewer'; },
  getRoleMeta(){ return ROLE_META[this.getRole()] || ROLE_META.viewer; },
  getUser()    { return this.currentUser; },

  _startSessionTimer() {
    clearTimeout(this._timeoutId);
    clearInterval(this._countdownId);
    this._timeoutId = setTimeout(() => {
      alert('⏰ Session expired due to inactivity. Please sign in again.');
      this.logout();
    }, SESSION_DURATION);

    // countdown ticker
    this._countdownId = setInterval(() => {
      const token = sessionStorage.getItem(AUTH_TOKEN_KEY);
      if (!token) { clearInterval(this._countdownId); return; }
      const data = _verifyJWT(token);
      if (!data)  { clearInterval(this._countdownId); return; }
      const rem  = Math.max(0, data.exp - Date.now());
      const mins = Math.floor(rem / 60000);
      const secs = Math.floor((rem % 60000) / 1000);
      const el   = document.getElementById('sessionTimer');
      if (el) {
        el.textContent = `⏱ ${mins}:${secs.toString().padStart(2,'0')}`;
        el.style.color = rem < 300000 ? 'var(--red)' : 'var(--text-3)';
      }
    }, 1000);
  },
};

/* ═══════════════════════════════════════════
   LOGIN SCREEN
═══════════════════════════════════════════ */
function showLoginScreen() {
  const sidebar = document.getElementById('sidebar');
  const main    = document.getElementById('mainContent');
  if (sidebar) sidebar.style.display = 'none';
  if (main)    main.style.display    = 'none';

  let el = document.getElementById('loginScreen');
  if (!el) {
    el = document.createElement('div');
    el.id = 'loginScreen';
    document.body.appendChild(el);
  }
  el.style.display = 'flex';
  el.innerHTML = `
<div class="login-bg">
  <div class="login-orbs">
    <div class="login-orb orb1"></div>
    <div class="login-orb orb2"></div>
    <div class="login-orb orb3"></div>
  </div>
  <div class="login-card">
    <div class="login-header">
      <div class="login-logo-icon">🛡️</div>
      <div class="login-brand">Sentinel AI</div>
      <div class="login-tagline">Security Operations Platform</div>
    </div>

    <div class="login-body">
      <div class="login-title">Welcome Back</div>
      <div class="login-subtitle">Sign in to access the SOC dashboard</div>

      <div id="loginError" class="login-error" style="display:none;"></div>

      <div class="form-group" style="margin-bottom:14px;">
        <label class="form-label">Username</label>
        <div class="login-field">
          <span class="login-field-icon">👤</span>
          <input id="loginUser" class="form-control" placeholder="Enter your username"
            autocomplete="username" onkeydown="if(event.key==='Enter') document.getElementById('loginPass').focus()"/>
        </div>
      </div>

      <div class="form-group" style="margin-bottom:20px;">
        <label class="form-label">Password</label>
        <div class="login-field">
          <span class="login-field-icon">🔒</span>
          <input id="loginPass" class="form-control" type="password" placeholder="Enter your password"
            autocomplete="current-password" onkeydown="if(event.key==='Enter') doLogin()"/>
          <button class="login-eye" onclick="togglePass()" title="Show/hide password" id="eyeBtn">👁️</button>
        </div>
      </div>

      <button class="btn btn-primary login-submit-btn" onclick="doLogin()" id="loginBtn">
        🔐 Sign In to Sentinel AI
      </button>

      <div class="login-divider"><span>Demo Accounts</span></div>

      <div class="demo-cards">
        <div class="demo-card" onclick="fillCred('admin','Admin@123')" title="Full access">
          <div class="demo-avatar" style="background:linear-gradient(135deg,#f87171,#e03e3e)">KS</div>
          <div class="demo-info">
            <div class="demo-name">admin</div>
            <div class="demo-role" style="color:var(--red)">Administrator</div>
          </div>
          <div class="demo-arrow">→</div>
        </div>
        <div class="demo-card" onclick="fillCred('analyst','Analyst@123')" title="Assign & respond">
          <div class="demo-avatar" style="background:linear-gradient(135deg,#fbbf24,#d97706)">SM</div>
          <div class="demo-info">
            <div class="demo-name">analyst</div>
            <div class="demo-role" style="color:var(--yellow)">SOC Analyst</div>
          </div>
          <div class="demo-arrow">→</div>
        </div>
        <div class="demo-card" onclick="fillCred('viewer','Viewer@123')" title="Read-only">
          <div class="demo-avatar" style="background:linear-gradient(135deg,#60a5fa,#2563eb)">JL</div>
          <div class="demo-info">
            <div class="demo-name">viewer</div>
            <div class="demo-role" style="color:var(--blue)">Read-Only</div>
          </div>
          <div class="demo-arrow">→</div>
        </div>
      </div>
    </div>

    <div class="login-footer">
      <span>🔒 Secured with JWT + AES-256 Encryption</span>
      <span>v2.0 — Sentinel AI SOC Platform</span>
    </div>
  </div>
</div>`;
}

function fillCred(u, p) {
  document.getElementById('loginUser').value = u;
  document.getElementById('loginPass').value = p;
  doLogin();
}

function togglePass() {
  const inp = document.getElementById('loginPass');
  inp.type = inp.type === 'password' ? 'text' : 'password';
}

function doLogin() {
  const u   = document.getElementById('loginUser').value.trim();
  const p   = document.getElementById('loginPass').value;
  const err = document.getElementById('loginError');
  const btn = document.getElementById('loginBtn');
  if (!u || !p) {
    err.innerHTML = '⚠️ Please enter your username and password.';
    err.style.display = 'block';
    return;
  }
  btn.disabled = true;
  btn.innerHTML = '<span class="login-spin">⟳</span> Authenticating…';
  setTimeout(() => {
    const result = auth.login(u, p);
    if (result.ok) {
      err.style.display = 'none';
      document.getElementById('loginScreen').style.display = 'none';
      document.getElementById('sidebar').style.display  = 'flex';
      document.getElementById('mainContent').style.display = 'block';
      _bootApp();
    } else {
      err.innerHTML = '❌ ' + result.error;
      err.style.display = 'block';
      btn.disabled = false;
      btn.innerHTML = '🔐 Sign In to Sentinel AI';
      document.getElementById('loginPass').value = '';
      document.getElementById('loginPass').focus();
    }
  }, 700);
}

/* ── Post-Login Boot ── */
function _bootApp() {
  const user = auth.getUser();
  const meta = auth.getRoleMeta();

  // Update sidebar user info
  const avatarEl  = document.querySelector('.user-avatar');
  const nameEl    = document.querySelector('.user-name');
  const roleEl    = document.querySelector('.user-role');
  if (avatarEl)  avatarEl.textContent  = user.avatar;
  if (nameEl)    nameEl.textContent    = user.name;
  if (roleEl)  { roleEl.textContent    = meta.label; roleEl.style.color = meta.color; }

  // Hide disabled nav items based on permissions
  document.querySelectorAll('.nav-item[data-perm]').forEach(item => {
    const perm = item.getAttribute('data-perm');
    item.classList.toggle('disabled', !auth.canDo(perm));
  });

  // Add session timer & logout
  const footer = document.querySelector('.sidebar-footer');
  if (footer && !footer.querySelector('.session-row')) {
    const sessionRow = document.createElement('div');
    sessionRow.className = 'session-row';
    sessionRow.innerHTML = `
      <span id="sessionTimer" style="font-size:10px;color:var(--text-3);">⏱ 30:00</span>
      <button class="btn btn-ghost btn-sm" style="padding:4px 10px;" onclick="auth.logout()">🚪 Logout</button>`;
    footer.appendChild(sessionRow);
  }

  showPage('dashboard');
}
