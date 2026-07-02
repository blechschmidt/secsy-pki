// Secsy PKI operator console — vanilla JS SPA, no build step, no external CDN.
//
// The console never holds privileges of its own. It authenticates the operator
// one of two ways and lets the server decide everything else:
//
//   - a server-side session (established by interactive OIDC SSO or a password
//     login), carried in an HttpOnly cookie and protected by a CSRF token echoed
//     in the X-CSRF-Token header on every state-changing request; or
//   - a stateless Authorization header (basic-auth root, or a bearer token),
//     kept for backwards compatibility and API scripting.
//
// High-risk operations (revocation, CA ceremony, cross-signing) may demand a
// WebAuthn/passkey step-up; the console runs the assertion ceremony on demand
// and retries. Authorization and auditing always happen server-side, so the
// console reflects exactly the caller's RBAC permissions.
'use strict';

const AUTH_KEY = 'secsy_console_auth';
const store = {
  get auth() { return sessionStorage.getItem(AUTH_KEY); },
  set auth(v) { v ? sessionStorage.setItem(AUTH_KEY, v) : sessionStorage.removeItem(AUTH_KEY); },
};

let authConfig = null;      // { oidc_enabled, oidc_login_enabled, webauthn_enabled, ... }
let oidcConfig = null;      // alias kept for the legacy in-browser PKCE fallback
let oidcDiscovery = null;   // fetched .well-known document (legacy fallback)
let currentUser = null;
let csrfToken = null;       // set when authenticated by a server-side session

const UNSAFE = /^(POST|PUT|PATCH|DELETE)$/i;

// ---- REST helper ---------------------------------------------------------
async function api(method, path, body, raw, retried) {
  const opts = { method, headers: {}, credentials: 'same-origin' };
  if (store.auth) opts.headers['Authorization'] = store.auth;
  // Session (cookie) auth requires the CSRF synchronizer token on writes.
  if (csrfToken && UNSAFE.test(method)) opts.headers['X-CSRF-Token'] = csrfToken;
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 401) { logout(); throw new Error('authentication required'); }
  const text = await res.text();
  let data = {};
  if (text) { try { data = JSON.parse(text); } catch (_) { data = {}; } }
  // A high-risk operation may demand a WebAuthn step-up. Run it once, then retry.
  if (res.status === 403 && data.code === 'step_up_required' && !retried) {
    await webauthnStepUp(data.operation);
    return api(method, path, body, raw, true);
  }
  if (raw) {
    if (!res.ok) throw new Error(data.error || text || `HTTP ${res.status}`);
    return text;
  }
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
    authConfig = await (await fetch('/api/auth/config')).json();
  } catch (_) { authConfig = { oidc_enabled: false }; }
  oidcConfig = authConfig;

  // Legacy in-browser PKCE fallback: complete an in-progress redirect if the
  // server does not offer server-side login.
  const params = new URLSearchParams(location.search);
  if (params.get('code') && sessionStorage.getItem('pkce_verifier')) {
    try { await completeOIDC(params.get('code')); } catch (e) { showError($('loginError'), 'SSO failed: ' + e.message); }
    history.replaceState({}, '', location.pathname);
  }

  // Offer SSO: prefer the server-side flow (redirect to /auth/login), falling
  // back to the in-browser PKCE flow when only bearer verification is available.
  if (authConfig.oidc_login_enabled) {
    $('ssoBlock').classList.remove('hidden');
    $('ssoBtn').onclick = () => { location.href = '/auth/login'; };
  } else if (authConfig.oidc_enabled) {
    $('ssoBlock').classList.remove('hidden');
    $('ssoBtn').onclick = beginOIDC;
  }

  // A server-side session may already exist (e.g. after an SSO redirect).
  if (await resumeSession()) return;
  // Or a stateless credential kept from a prior visit.
  if (store.auth) {
    try { await afterLogin(); return; } catch (_) { store.auth = null; }
  }
  $('login').classList.remove('hidden');
}

// resumeSession restores state from an existing server-side session cookie.
async function resumeSession() {
  try {
    const res = await fetch('/auth/session', { credentials: 'same-origin' });
    if (!res.ok) return false;
    const info = await res.json();
    csrfToken = info.csrf_token || null;
    await afterLogin();
    return true;
  } catch (_) { return false; }
}

$('loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('loginError').classList.add('hidden');
  const u = $('loginUser').value, p = $('loginPass').value;
  try {
    if (authConfig && authConfig.password_login) {
      // Establish a real session (enables CSRF protection and WebAuthn step-up).
      const res = await fetch('/auth/login/password', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: u, password: p }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'login failed');
      csrfToken = data.csrf_token || null;
      store.auth = null;
    } else {
      // Fallback: stateless basic-auth.
      store.auth = 'Basic ' + btoa(u + ':' + p);
    }
    await afterLogin();
  } catch (err) {
    store.auth = null; csrfToken = null;
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
  // Offer passkey enrollment when the server has WebAuthn step-up enabled and the
  // caller holds a real session (not a stateless credential).
  const pk = $('passkeyBtn');
  if (pk) {
    if (authConfig && authConfig.webauthn_enabled && csrfToken) {
      pk.classList.remove('hidden');
      pk.onclick = registerPasskey;
    } else {
      pk.classList.add('hidden');
    }
  }
  await loadCAs();
  await loadProfiles();
  await loadSecretInfo();
  switchView('certs');
}

async function logout() {
  try { await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' }); } catch (_) {}
  store.auth = null;
  csrfToken = null;
  currentUser = null;
  $('app').classList.add('hidden');
  $('login').classList.remove('hidden');
}
$('logoutBtn').onclick = logout;

// ---- WebAuthn step-up ----------------------------------------------------
// b64uToBuf / bufToB64u convert between base64url (used on the wire) and the
// ArrayBuffers the WebAuthn API expects.
function b64uToBuf(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}
function bufToB64u(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function waHeaders() {
  const h = { 'Content-Type': 'application/json' };
  if (csrfToken) h['X-CSRF-Token'] = csrfToken;
  if (store.auth) h['Authorization'] = store.auth;
  return h;
}

// registerPasskey enrolls a new WebAuthn credential for the logged-in operator.
async function registerPasskey() {
  if (!window.PublicKeyCredential) { alert('This browser does not support WebAuthn.'); return; }
  const name = prompt('Name this passkey (e.g. "YubiKey", "Laptop"):', 'Passkey');
  if (name === null) return;
  const beginRes = await fetch('/auth/webauthn/register/begin', { method: 'POST', credentials: 'same-origin', headers: waHeaders(), body: '{}' });
  const opts = await beginRes.json();
  if (!beginRes.ok) { alert('Cannot start registration: ' + (opts.error || beginRes.status)); return; }
  const pub = {
    challenge: b64uToBuf(opts.challenge),
    rp: opts.rp,
    user: { id: b64uToBuf(opts.user.id), name: opts.user.name, displayName: opts.user.displayName },
    pubKeyCredParams: opts.pubKeyCredParams,
    authenticatorSelection: opts.authenticatorSelection,
    timeout: opts.timeout,
    attestation: opts.attestation,
    excludeCredentials: (opts.excludeCredentials || []).map(c => ({ type: c.type, id: b64uToBuf(c.id) })),
  };
  let cred;
  try { cred = await navigator.credentials.create({ publicKey: pub }); }
  catch (e) { alert('Passkey creation cancelled: ' + e.message); return; }
  const res = await fetch('/auth/webauthn/register/finish', {
    method: 'POST', credentials: 'same-origin', headers: waHeaders(),
    body: JSON.stringify({
      name,
      id: cred.id,
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      attestationObject: bufToB64u(cred.response.attestationObject),
    }),
  });
  const out = await res.json();
  if (!res.ok) { alert('Registration failed: ' + (out.error || res.status)); return; }
  alert('Passkey registered.');
}

// webauthnStepUp runs an assertion to satisfy a high-risk operation's step-up.
async function webauthnStepUp(operation) {
  if (!window.PublicKeyCredential) throw new Error('step-up required but this browser has no WebAuthn support');
  const beginRes = await fetch('/auth/webauthn/stepup/begin', { method: 'POST', credentials: 'same-origin', headers: waHeaders(), body: '{}' });
  const opts = await beginRes.json();
  if (beginRes.status === 428) throw new Error('a passkey is required for this operation — register one first');
  if (!beginRes.ok) throw new Error(opts.error || 'cannot start step-up');
  const pub = {
    challenge: b64uToBuf(opts.challenge),
    rpId: opts.rpId,
    userVerification: opts.userVerification,
    timeout: opts.timeout,
    allowCredentials: (opts.allowCredentials || []).map(c => ({ type: c.type, id: b64uToBuf(c.id) })),
  };
  const assertion = await navigator.credentials.get({ publicKey: pub });
  const res = await fetch('/auth/webauthn/stepup/finish', {
    method: 'POST', credentials: 'same-origin', headers: waHeaders(),
    body: JSON.stringify({
      id: assertion.id,
      clientDataJSON: bufToB64u(assertion.response.clientDataJSON),
      authenticatorData: bufToB64u(assertion.response.authenticatorData),
      signature: bufToB64u(assertion.response.signature),
    }),
  });
  if (!res.ok) { const e = await res.json().catch(() => ({})); throw new Error(e.error || 'step-up failed'); }
}

// Minimal OIDC Authorization-Code + PKCE flow (public client, legacy fallback).
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
  if (name === 'inventory') loadInventory();
  if (name === 'compliance') loadCompliance();
  if (name === 'bundle') loadBundle();
}
document.querySelectorAll('header nav button').forEach(b =>
  b.onclick = () => switchView(b.dataset.view));

// ---- CAs & profiles ------------------------------------------------------
let cas = [];
async function loadCAs() {
  cas = await api('GET', '/api/keys');
  const opts = cas.map(c => `<option value="${c.id}">${escapeHTML(c.label)}</option>`).join('');
  const empty = '<option value="">— no CAs —</option>';
  const allOpt = '<option value="">all CAs</option>';
  $('certCA').innerHTML = opts || empty;
  $('issueCA').innerHTML = opts || empty;
  $('invCA').innerHTML = allOpt + opts;
  $('compCA').innerHTML = allOpt + opts;
  $('bundleCA').innerHTML = opts || empty;
  if (cas.length) { updateCRLLink(); loadCerts(); }
}
// caLabel maps a CA id to its human label for tables that only carry the id.
function caLabel(id) { const c = cas.find(x => x.id === id); return c ? c.label : id; }
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
  const link = $('crlLink'), delta = $('crlDeltaLink');
  if (id) {
    link.href = `/api/ca/${id}/crl?format=pem`; link.classList.remove('hidden');
    delta.href = `/api/ca/${id}/crl/delta?format=pem`; delta.classList.remove('hidden');
  } else { link.classList.add('hidden'); delta.classList.add('hidden'); }
  loadCRLStatus(id);
}

// loadCRLStatus renders the base/delta CRL freshness and revocation counts.
async function loadCRLStatus(id) {
  const el = $('crlStatus');
  if (!id) { el.textContent = ''; return; }
  el.textContent = 'Loading CRL status…';
  try {
    const s = await api('GET', `/api/ca/${id}/crl/status`);
    const base = s.base || {};
    let html = `CRL #<b>${escapeHTML(base.number || '?')}</b> · `
      + `${base.revoked_count || 0} revoked · updated ${fmtTime(base.this_update)} · `
      + `next ${fmtTime(base.next_update)} ${expiryTag(base)}`;
    if (s.delta && s.delta.available) {
      const d = s.delta;
      html += ` &nbsp;|&nbsp; delta #<b>${escapeHTML(d.number || '?')}</b>`
        + (d.base_crl_number ? ` (base #${escapeHTML(d.base_crl_number)})` : '')
        + ` · ${d.revoked_count || 0} entries · next ${fmtTime(d.next_update)} ${expiryTag(d)}`;
    }
    if (s.sharded) html += ` &nbsp;|&nbsp; partitioned into ${s.shard_count} shards`;
    el.innerHTML = html;
  } catch (e) { el.textContent = 'CRL status unavailable: ' + e.message; }
}
function expiryTag(scope) {
  return scope && scope.expired ? '<span class="badge fail">stale</span>' : '';
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

// Revocation is driven by a modal with an RFC 5280 reason dropdown rather than a
// free-text prompt, so operators pick a valid reason code.
let revokeTarget = null; // { caID, serial }
function revokeCert(caID, serial) {
  revokeTarget = { caID, serial };
  $('revokeSubject').textContent = `Serial ${shortSerial(serial)} on CA ${caLabel(caID)}`;
  $('revokeError').classList.add('hidden');
  $('revokeReason').value = 'unspecified';
  $('revokeModal').classList.remove('hidden');
}
window.revokeCert = revokeCert;
$('revokeCancel').onclick = () => { $('revokeModal').classList.add('hidden'); revokeTarget = null; };
$('revokeConfirm').onclick = async () => {
  if (!revokeTarget) return;
  const { caID, serial } = revokeTarget;
  $('revokeConfirm').disabled = true;
  try {
    await api('POST', `/api/ca/${caID}/revoke`, { serial, reason: $('revokeReason').value });
    $('revokeModal').classList.add('hidden');
    revokeTarget = null;
    if (selectedCertCA() === caID) { loadCerts(); loadCRLStatus(caID); }
    if ($('view-inventory').classList.contains('active')) loadInventory();
  } catch (e) { showError($('revokeError'), e.message); }
  finally { $('revokeConfirm').disabled = false; }
};

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

// ---- Inventory view ------------------------------------------------------
let inventoryCache = []; // last-loaded records, filtered client-side for search

$('invRefresh').onclick = loadInventory;
$('invCA').onchange = loadInventory;
$('invProfile').onchange = loadInventory;
$('invSearch').oninput = renderInventory;
$('invStatus').onchange = renderInventory;
$('invCSV').onclick = exportInventoryCSV;

function inventoryQuery() {
  const p = new URLSearchParams();
  if ($('invCA').value) p.set('ca_id', $('invCA').value);
  if ($('invProfile').value.trim()) p.set('profile', $('invProfile').value.trim());
  const q = p.toString();
  return q ? '?' + q : '';
}

async function loadInventory() {
  const tbody = $('invRows');
  tbody.innerHTML = '<tr><td colspan="8" class="muted">Loading…</td></tr>';
  try {
    const inv = await api('GET', '/api/report/inventory' + inventoryQuery());
    inventoryCache = inv.certificates || [];
    renderInventory();
  } catch (e) {
    inventoryCache = [];
    tbody.innerHTML = `<tr><td colspan="8" class="muted">${escapeHTML(e.message)}</td></tr>`;
    $('invCounts').textContent = '';
  }
}

// renderInventory applies the client-side search + status filter over the loaded
// records (CA/profile filtering already happened server-side).
function renderInventory() {
  const tbody = $('invRows');
  const term = $('invSearch').value.trim().toLowerCase();
  const status = $('invStatus').value;
  const rows = inventoryCache.filter(c => {
    if (status && c.status !== status) return false;
    if (!term) return true;
    const hay = [c.serial, c.common_name, c.subject, (c.sans || []).join(' '), c.profile]
      .join(' ').toLowerCase();
    return hay.includes(term);
  });
  $('invCounts').textContent = `${rows.length} of ${inventoryCache.length} certificate(s)`;
  tbody.innerHTML = rows.length ? rows.map(c => `
    <tr>
      <td class="mono">${escapeHTML(shortSerial(c.serial))}</td>
      <td>${escapeHTML(c.common_name || '')}</td>
      <td>${escapeHTML(c.profile || '')}</td>
      <td>${escapeHTML(caLabel(c.ca_id))}</td>
      <td>${fmtTime(c.not_after)}</td>
      <td><span class="badge ${c.status}">${escapeHTML(c.status)}</span>${
        c.status === 'revoked' && c.revocation_reason_text ? ` <span class="muted">${escapeHTML(c.revocation_reason_text)}</span>` : ''}</td>
      <td>${c.sct_present ? `<span class="badge pass" title="${c.sct_count} SCT(s)">${c.sct_count} SCT</span>` : '<span class="muted">—</span>'}</td>
      <td><span class="badge ${c.lint_verdict || 'none'}" title="${escapeHTML((c.lint_findings || []).join(', '))}">${escapeHTML(c.lint_verdict || 'n/a')}</span></td>
    </tr>`).join('') : '<tr><td colspan="8" class="muted">No certificates match.</td></tr>';
}

// exportInventoryCSV downloads the server-rendered CSV. The endpoint is
// auth-gated, so it is fetched with the operator credential and saved as a Blob
// rather than a bare link.
async function exportInventoryCSV() {
  $('invCSV').disabled = true;
  try {
    const csv = await api('GET', '/api/report/inventory' + inventoryQuery() +
      (inventoryQuery() ? '&' : '?') + 'format=csv', undefined, true);
    downloadBlob(csv, 'certificate-inventory.csv', 'text/csv');
  } catch (e) { alert('CSV export failed: ' + e.message); }
  finally { $('invCSV').disabled = false; }
}

// ---- Compliance view -----------------------------------------------------
$('compRefresh').onclick = loadCompliance;
$('compCA').onchange = loadCompliance;

async function loadCompliance() {
  const roll = $('compRoll');
  roll.className = 'notice hidden';
  $('compStats').innerHTML = '';
  try {
    const q = $('compCA').value ? '?ca_id=' + encodeURIComponent($('compCA').value) : '';
    const rep = await api('GET', '/api/report/compliance' + q);
    const l = rep.lint || {};
    const chainOK = rep.audit_chain && rep.audit_chain.valid;
    roll.textContent = rep.conformant
      ? '✓ Conformant — audit chain verified and no non-conformant certificate was issued.'
      : '✗ Attention — the audit chain failed to verify or a non-conformant certificate was issued.';
    roll.className = 'notice ' + (rep.conformant ? 'ok' : 'err');
    $('compStats').innerHTML = [
      statCard(l.issued_total || 0, 'Issued', ''),
      statCard(l.pass || 0, 'Lint pass', 'ok'),
      statCard(l.warn || 0, 'Lint warn', l.warn ? 'warn' : ''),
      statCard(l.blocked || 0, 'Blocked (gate held)', l.blocked ? 'crit' : ''),
      statCard(chainOK ? 'OK' : 'FAIL', 'Audit chain', chainOK ? 'ok' : 'crit'),
    ].join('');

    $('compCARows').innerHTML = (rep.cas && rep.cas.length) ? rep.cas.map(c => `
      <tr>
        <td>${escapeHTML(c.label || '')}</td>
        <td>${escapeHTML(c.subject || '')}</td>
        <td>${escapeHTML(c.key_type || '')}</td>
        <td>${c.hsm_backed ? '<span class="badge pass">HSM</span>' : '<span class="badge none">soft</span>'}</td>
        <td>${c.issued_certificates || 0}</td>
      </tr>`).join('') : '<tr><td colspan="5" class="muted">No CAs.</td></tr>';

    const rules = [];
    (l.top_warning_rules || []).forEach(r => rules.push({ ...r, kind: 'warn' }));
    (l.top_blocked_rules || []).forEach(r => rules.push({ ...r, kind: 'blocked' }));
    $('compRuleRows').innerHTML = rules.length ? rules.map(r => `
      <tr>
        <td class="mono">${escapeHTML(r.code)}</td>
        <td><span class="badge ${r.kind === 'blocked' ? 'fail' : 'warn'}">${r.kind}</span></td>
        <td>${r.count}</td>
      </tr>`).join('') : '<tr><td colspan="3" class="muted">No lint findings recorded.</td></tr>';

    $('compProfileRows').innerHTML = (rep.profile_breakdown && rep.profile_breakdown.length)
      ? rep.profile_breakdown.map(p => `
        <tr><td>${escapeHTML(p.profile || '(none)')}</td><td>${p.count}</td></tr>`).join('')
      : '<tr><td colspan="2" class="muted">No certificates issued.</td></tr>';
  } catch (e) {
    roll.textContent = e.message; roll.className = 'notice err';
    $('compCARows').innerHTML = '<tr><td colspan="5" class="muted">—</td></tr>';
    $('compRuleRows').innerHTML = '<tr><td colspan="3" class="muted">—</td></tr>';
    $('compProfileRows').innerHTML = '<tr><td colspan="2" class="muted">—</td></tr>';
  }
}
function statCard(num, lbl, cls) {
  return `<div class="stat ${cls}"><div class="num">${escapeHTML(String(num))}</div><div class="lbl">${escapeHTML(lbl)}</div></div>`;
}

// ---- Trust bundle / chain view -------------------------------------------
$('bundleRefresh').onclick = loadBundle;
$('bundleCA').onchange = loadBundle;

async function loadBundle() {
  const id = $('bundleCA').value;
  const msg = $('bundleMsg');
  msg.className = 'notice hidden';
  $('svidPanel').classList.add('hidden');
  if (!id) { $('chainPEM').value = ''; return; }
  // The chain endpoint is public (relying parties fetch it unauthenticated), so
  // the download link points straight at it.
  $('chainDownload').href = `/api/ca/${id}/chain`;
  try {
    $('chainPEM').value = await api('GET', `/api/ca/${id}/chain`, undefined, true);
  } catch (e) {
    $('chainPEM').value = '';
    showError(msg, 'Chain unavailable: ' + e.message); msg.className = 'notice err';
  }
  // The SPIFFE trust bundle exists only when SPIFFE issuance is enabled; a 404
  // just hides the panel.
  try {
    const bundle = await api('GET', `/api/ca/${id}/svid/bundle`, undefined, true);
    $('svidBundle').value = bundle;
    $('svidPanel').classList.remove('hidden');
  } catch (_) { /* SPIFFE not enabled for this server */ }
}

// downloadBlob saves text content as a file via a transient object URL.
function downloadBlob(content, filename, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
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
