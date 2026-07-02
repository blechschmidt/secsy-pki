// Secsy PKI operator console — vanilla JS SPA, no build step, no external CDN.
//
// The console never holds privileges of its own: it stores the operator's
// credential (an HTTP Authorization header — basic-auth for the root user or an
// OIDC bearer token) and attaches it to every REST call. Authorization and
// auditing happen server-side, so the console reflects exactly the caller's
// RBAC permissions and every mutating action is recorded in the event log.
'use strict';

const AUTH_KEY = 'secsy_console_auth';
const store = {
  get auth() { return sessionStorage.getItem(AUTH_KEY); },
  set auth(v) { v ? sessionStorage.setItem(AUTH_KEY, v) : sessionStorage.removeItem(AUTH_KEY); },
};

let oidcConfig = null;      // { oidc_enabled, issuer_url, client_id }
let oidcDiscovery = null;   // fetched .well-known document
let currentUser = null;

// ---- REST helper ---------------------------------------------------------
async function api(method, path, body, raw) {
  const opts = { method, headers: {} };
  if (store.auth) opts.headers['Authorization'] = store.auth;
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 401) { logout(); throw new Error('authentication required'); }
  if (raw) {
    if (!res.ok) throw new Error(await res.text() || `HTTP ${res.status}`);
    return res.text();
  }
  const text = await res.text();
  const data = text ? JSON.parse(text) : {};
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}
const $ = (id) => document.getElementById(id);

function showError(el, msg) {
  el.textContent = msg;
  el.classList.remove('hidden');
}

// ---- Authentication ------------------------------------------------------
async function bootAuth() {
  try {
    oidcConfig = await (await fetch('/api/auth/config')).json();
  } catch (_) { oidcConfig = { oidc_enabled: false }; }

  // Complete an in-progress OIDC redirect, if any.
  const params = new URLSearchParams(location.search);
  if (params.get('code') && sessionStorage.getItem('pkce_verifier')) {
    try { await completeOIDC(params.get('code')); } catch (e) { showError($('loginError'), 'SSO failed: ' + e.message); }
    history.replaceState({}, '', location.pathname);
  }

  if (oidcConfig.oidc_enabled) {
    $('ssoBlock').classList.remove('hidden');
    $('ssoBtn').onclick = beginOIDC;
  }

  if (store.auth) {
    try { await afterLogin(); return; } catch (_) { store.auth = null; }
  }
  $('login').classList.remove('hidden');
}

$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('loginError').classList.add('hidden');
  const u = $('loginUser').value, p = $('loginPass').value;
  store.auth = 'Basic ' + btoa(u + ':' + p);
  try {
    await afterLogin();
  } catch (err) {
    store.auth = null;
    showError($('loginError'), err.message);
  }
});

async function afterLogin() {
  currentUser = await api('GET', '/api/me');
  $('login').classList.add('hidden');
  $('app').classList.remove('hidden');
  const roles = (currentUser.roles && currentUser.roles.length)
    ? ` <span class="roles">[${currentUser.roles.join(', ')}]</span>`
    : (currentUser.is_root ? ' <span class="roles">[root]</span>' : '');
  $('userBox').innerHTML = `Signed in as <b>${escapeHTML(currentUser.name || currentUser.sub || 'user')}</b>${roles}`;
  await loadCAs();
  await loadProfiles();
  await loadSecretInfo();
  switchView('certs');
}

function logout() {
  store.auth = null;
  currentUser = null;
  $('app').classList.add('hidden');
  $('login').classList.remove('hidden');
}
$('logoutBtn').onclick = logout;

// Minimal OIDC Authorization-Code + PKCE flow (public client).
async function beginOIDC() {
  oidcDiscovery = await (await fetch(oidcConfig.issuer_url.replace(/\/$/, '') + '/.well-known/openid-configuration')).json();
  const verifier = randStr(64);
  sessionStorage.setItem('pkce_verifier', verifier);
  const challenge = await s256(verifier);
  const p = new URLSearchParams({
    response_type: 'code',
    client_id: oidcConfig.client_id,
    redirect_uri: location.origin + location.pathname,
    scope: 'openid profile email',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: randStr(16),
  });
  location.href = oidcDiscovery.authorization_endpoint + '?' + p.toString();
}

async function completeOIDC(code) {
  if (!oidcDiscovery) {
    oidcDiscovery = await (await fetch(oidcConfig.issuer_url.replace(/\/$/, '') + '/.well-known/openid-configuration')).json();
  }
  const verifier = sessionStorage.getItem('pkce_verifier');
  sessionStorage.removeItem('pkce_verifier');
  const res = await fetch(oidcDiscovery.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      client_id: oidcConfig.client_id,
      redirect_uri: location.origin + location.pathname,
      code_verifier: verifier,
    }),
  });
  const tok = await res.json();
  if (!tok.id_token) throw new Error(tok.error_description || 'no id_token');
  store.auth = 'Bearer ' + tok.id_token;
  await afterLogin();
}

// ---- View routing --------------------------------------------------------
function switchView(name) {
  document.querySelectorAll('header nav button').forEach(b =>
    b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.view').forEach(v =>
    v.classList.toggle('active', v.id === 'view-' + name));
  if (name === 'monitor') loadMonitor();
}
document.querySelectorAll('header nav button').forEach(b =>
  b.onclick = () => switchView(b.dataset.view));

// ---- CAs & profiles ------------------------------------------------------
let cas = [];
async function loadCAs() {
  cas = await api('GET', '/api/keys');
  const opts = cas.map(c => `<option value="${c.id}">${escapeHTML(c.label)}</option>`).join('');
  const empty = '<option value="">— no CAs —</option>';
  $('certCA').innerHTML = opts || empty;
  $('issueCA').innerHTML = opts || empty;
  if (cas.length) { updateCRLLink(); loadCerts(); }
}
async function loadProfiles() {
  try {
    const profs = await api('GET', '/api/profiles');
    $('issueProfile').innerHTML = profs.map(p =>
      `<option value="${p.name}">${escapeHTML(p.name)} — ${escapeHTML(p.description || '')}</option>`).join('');
  } catch (_) { /* profiles are read-gated; ignore if forbidden */ }
}

// ---- Certificates view ---------------------------------------------------
$('certCA').onchange = () => { updateCRLLink(); loadCerts(); };
$('showRevoked').onchange = loadCerts;
$('refreshCerts').onclick = loadCerts;

function selectedCertCA() { return $('certCA').value; }
function updateCRLLink() {
  const id = selectedCertCA();
  const link = $('crlLink');
  if (id) { link.href = `/api/ca/${id}/crl?format=pem`; link.classList.remove('hidden'); }
  else link.classList.add('hidden');
}

async function loadCerts() {
  const id = selectedCertCA();
  const tbody = $('certRows');
  if (!id) { tbody.innerHTML = '<tr><td colspan="6" class="muted">Select a CA…</td></tr>'; return; }
  tbody.innerHTML = '<tr><td colspan="6" class="muted">Loading…</td></tr>';
  try {
    if ($('showRevoked').checked) {
      const revoked = await api('GET', `/api/ca/${id}/revoked`);
      tbody.innerHTML = revoked.length ? revoked.map(r => `
        <tr>
          <td class="mono">${escapeHTML(shortSerial(r.serial))}</td>
          <td colspan="2" class="muted">revoked</td>
          <td>${fmtTime(r.revoked_at)}</td>
          <td><span class="badge revoked">revoked</span></td>
          <td class="muted">reason ${r.reason ?? 0}</td>
        </tr>`).join('') : emptyRow('No revoked certificates.');
      return;
    }
    const certs = await api('GET', `/api/ca/${id}/certificates`);
    tbody.innerHTML = certs.length ? certs.map(c => `
      <tr>
        <td class="mono">${escapeHTML(shortSerial(c.serial))}</td>
        <td>${escapeHTML(c.common_name || '')}</td>
        <td>${escapeHTML(c.profile || '')}</td>
        <td>${fmtTime(c.not_after)}</td>
        <td><span class="badge ${c.status}">${c.status}</span></td>
        <td>${ctBadge(c)}</td>
        <td>${c.status === 'valid'
          ? `<button class="btn danger sm" onclick="revokeCert('${id}','${c.serial}')">Revoke</button>` : ''}</td>
      </tr>`).join('') : emptyRow('No certificates issued yet.');
  } catch (e) { tbody.innerHTML = emptyRow(e.message); }
}

// ctBadge renders the Certificate Transparency status of an issued certificate.
function ctBadge(c) {
  switch (c.ct_status) {
    case 'submitted': {
      const logs = (c.ct_logs && c.ct_logs.length) ? ' — ' + c.ct_logs.map(escapeHTML).join(', ') : '';
      return `<span class="badge valid" title="${c.sct_count || 0} SCT(s)${logs}">${c.sct_count || 0} SCT</span>`;
    }
    case 'failed_open':
      return `<span class="badge revoked" title="CT policy not met; issued fail-open">fail-open</span>`;
    default:
      return `<span class="muted">—</span>`;
  }
}

async function revokeCert(caID, serial) {
  const reason = prompt('Revocation reason (e.g. keyCompromise, superseded, cessationOfOperation):', 'unspecified');
  if (reason === null) return;
  try {
    await api('POST', `/api/ca/${caID}/revoke`, { serial, reason });
    loadCerts();
  } catch (e) { alert('Revoke failed: ' + e.message); }
}
window.revokeCert = revokeCert;

// ---- Monitor view --------------------------------------------------------
$('monRefresh').onclick = loadMonitor;
$('monSeverity').onchange = loadMonitor;
$('monScan').onclick = async () => {
  $('monScan').disabled = true;
  try {
    const rep = await api('POST', '/api/monitor/scan', { auto_renew: true });
    const r = rep.renewed || 0, f = rep.renew_failed || 0;
    alert(`Scan complete — ${r} renewed, ${f} failed.`);
    loadMonitor();
  } catch (e) { alert('Scan failed: ' + e.message); }
  finally { $('monScan').disabled = false; }
};

async function loadMonitor() {
  const tbody = $('monRows');
  tbody.innerHTML = '<tr><td colspan="6" class="muted">Loading…</td></tr>';
  try {
    const sev = $('monSeverity').value;
    const rep = await api('GET', '/api/monitor/expiring' + (sev ? `?severity=${sev}` : ''));
    const c = rep.counts || {};
    $('monCounts').textContent =
      `ok ${c.ok || 0} · warning ${c.warning || 0} · critical ${c.critical || 0} · expired ${c.expired || 0}`;
    const certs = rep.certificates || [];
    tbody.innerHTML = certs.length ? certs.map(it => `
      <tr>
        <td><span class="badge ${it.severity}">${it.severity}</span></td>
        <td>${escapeHTML(it.common_name || '')}</td>
        <td>${escapeHTML(it.ca_label || '')}</td>
        <td>${escapeHTML(it.profile || '')}</td>
        <td>${fmtDuration(it.expires_in_seconds)}</td>
        <td>${fmtTime(it.not_after)}</td>
      </tr>`).join('') : emptyRow('No certificates match.');
  } catch (e) { tbody.innerHTML = emptyRow(e.message); }
}

// ---- Issue view ----------------------------------------------------------
$('issueBtn').onclick = async () => {
  const id = $('issueCA').value;
  const msg = $('issueMsg');
  msg.className = 'notice hidden';
  if (!id) { showError(msg, 'Select a CA.'); msg.className = 'notice err'; return; }
  const csr = $('issueCSR').value.trim();
  if (!csr) { showError(msg, 'Paste a PEM CSR.'); msg.className = 'notice err'; return; }
  const body = { csr, profile: $('issueProfile').value };
  const days = parseInt($('issueDays').value, 10);
  if (days > 0) body.validity_days = days;
  $('issueBtn').disabled = true;
  try {
    const res = await api('POST', `/api/ca/${id}/issue`, body);
    let ctNote = '';
    if (res.ct && res.ct.enabled) {
      ctNote = res.ct.embedded
        ? ` CT: embedded ${res.ct.sct_count} SCT(s).`
        : ` CT: no SCTs embedded (issued fail-open).`;
    }
    msg.textContent = `Issued serial ${res.serial} (${res.profile}), valid until ${res.not_after}.${ctNote}`;
    msg.className = 'notice ok';
    $('issueResult').classList.remove('hidden');
    $('issuePEM').value = res.certificate + (res.chain ? '\n' + res.chain : '');
    if (selectedCertCA() === id) loadCerts();
  } catch (e) {
    showError(msg, e.message); msg.className = 'notice err';
  } finally { $('issueBtn').disabled = false; }
};

// ---- Secrets view --------------------------------------------------------
async function loadSecretInfo() {
  try {
    const info = await api('GET', '/api/secret/info');
    $('secretInfo').textContent =
      `KEK ${info.kek_label} · ${info.provider} · ${info.key_bits}-bit · wrap ${info.wrap_alg} · data ${info.data_alg}`;
    $('secretDisabled').classList.add('hidden');
  } catch (e) {
    // 404 when the feature is disabled (routes not registered).
    $('secretDisabled').classList.remove('hidden');
    $('secretInfo').textContent = '';
  }
}
$('encBtn').onclick = async () => {
  try {
    const pt = new TextEncoder().encode($('encPlain').value);
    const res = await api('POST', '/api/secret/encrypt', { plaintext: b64(pt) });
    $('encOut').value = JSON.stringify(res.envelope, null, 2);
  } catch (e) { alert('Encrypt failed: ' + e.message); }
};
$('decBtn').onclick = async () => {
  try {
    const env = JSON.parse($('decEnv').value);
    const res = await api('POST', '/api/secret/decrypt', { envelope: env });
    $('decOut').value = new TextDecoder().decode(unb64(res.plaintext));
  } catch (e) { alert('Decrypt failed: ' + e.message); }
};

// ---- Helpers -------------------------------------------------------------
function emptyRow(msg) { return `<tr><td colspan="6" class="muted">${escapeHTML(msg)}</td></tr>`; }
function escapeHTML(s) {
  return String(s ?? '').replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function shortSerial(s) {
  if (!s) return '';
  return s.length > 24 ? s.slice(0, 12) + '…' + s.slice(-8) : s;
}
function fmtTime(t) {
  if (!t) return '';
  const d = new Date(t);
  return isNaN(d) ? String(t) : d.toISOString().replace('T', ' ').slice(0, 16) + 'Z';
}
function fmtDuration(secs) {
  if (secs == null) return '';
  if (secs < 0) return 'expired';
  const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600);
  if (d > 0) return `${d}d ${h}h`;
  return `${h}h`;
}
function b64(bytes) { let s = ''; bytes.forEach(b => s += String.fromCharCode(b)); return btoa(s); }
function unb64(str) { const s = atob(str); return Uint8Array.from(s, c => c.charCodeAt(0)); }
function randStr(n) {
  const a = new Uint8Array(n); crypto.getRandomValues(a);
  return Array.from(a, b => ('0' + b.toString(16)).slice(-2)).join('').slice(0, n);
}
async function s256(v) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

bootAuth();
