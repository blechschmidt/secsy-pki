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
    // Session-establishing endpoints (enable CSRF protection and WebAuthn
    // step-up), tried in order: directory (LDAP/AD) users first, then the
    // built-in root password. Both may be enabled, so a directory user and the
    // break-glass root account log in through the same form.
    const endpoints = [];
    if (authConfig && authConfig.ldap_login) endpoints.push('/auth/login/ldap');
    if (authConfig && authConfig.password_login) endpoints.push('/auth/login/password');
    if (endpoints.length) {
      let ok = false, lastErr = 'login failed';
      for (const ep of endpoints) {
        const res = await fetch(ep, {
          method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: u, password: p }),
        });
        const data = await res.json();
        if (res.ok) { csrfToken = data.csrf_token || null; store.auth = null; ok = true; break; }
        lastErr = data.error || 'login failed';
      }
      if (!ok) throw new Error(lastErr);
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
  // Tear down the live audit tail when navigating away so the SSE connection and
  // its server-side subscriber are released rather than leaking in the background.
  if (name !== 'audit' && typeof auditLiveController !== 'undefined' && auditLiveController) stopLiveTail();
  document.querySelectorAll('header nav button').forEach(b =>
    b.classList.toggle('active', b.dataset.view === name));
  document.querySelectorAll('.view').forEach(v =>
    v.classList.toggle('active', v.id === 'view-' + name));
  if (name === 'monitor') loadMonitor();
  if (name === 'inventory') loadInventory();
  if (name === 'discovery') loadDiscovery();
  if (name === 'ct') loadCT();
  if (name === 'cas') loadAuthorities();
  if (name === 'ssh') loadSSH();
  if (name === 'signing') loadSigning();
  if (name === 'secrets' && secretServiceEnabled) loadSigningKeys();
  if (name === 'acme') loadACME();
  if (name === 'audit') loadAudit();
  if (name === 'approvals') loadApprovals();
  if (name === 'compliance') loadCompliance();
  if (name === 'bundle') loadBundle();
  if (name === 'dns') loadDNS();
  if (name === 'tenants') loadTenants();
  if (name === 'tokens') loadTokens();
  if (name === 'webhooks') loadWebhooks();
}
document.querySelectorAll('header nav button').forEach(b =>
  b.onclick = () => switchView(b.dataset.view));

// ---- CAs & profiles ------------------------------------------------------
// cas holds every CA record; x509CAs only those with an X.509 certificate
// (SSH-only signing keys live in the same store but drive the SSH CA page).
let cas = [];
let x509CAs = [];
let profiles = [];
async function loadCAs() {
  cas = await api('GET', '/api/keys');
  x509CAs = cas.filter(c => c.certificate);
  const opt = (c) => `<option value="${c.id}">${escapeHTML(c.label)}</option>`;
  const opts = x509CAs.map(opt).join('');
  // Issuance targets only active keys; superseded/retired stay browsable.
  const activeOpts = x509CAs.filter(c => !c.status || c.status === 'active').map(opt).join('');
  const empty = '<option value="">— no CAs —</option>';
  const allOpt = '<option value="">all CAs</option>';
  $('certCA').innerHTML = opts || empty;
  $('issueCA').innerHTML = activeOpts || empty;
  $('p12CA').innerHTML = activeOpts || empty;
  $('invCA').innerHTML = allOpt + opts;
  $('compCA').innerHTML = allOpt + opts;
  $('bundleCA').innerHTML = opts || empty;
  $('validateCA').innerHTML = opts || empty;
  $('interParent').innerHTML = activeOpts || empty;
  $('csIssuer').innerHTML = activeOpts || empty;
  $('csSubject').innerHTML = '<option value="">— external (paste below) —</option>' + opts;
  $('csListCA').innerHTML = opts || empty;
  $('verifyCA').innerHTML = allOpt + opts;
  if (x509CAs.length) { updateCRLLink(); loadCerts(); }
}
// caLabel maps a CA id to its human label for tables that only carry the id.
function caLabel(id) { const c = cas.find(x => x.id === id); return c ? c.label : id; }
async function loadProfiles() {
  try {
    profiles = await api('GET', '/api/profiles');
    $('issueProfile').innerHTML = profiles.map(p =>
      `<option value="${p.name}">${escapeHTML(p.name)} — ${escapeHTML(p.description || '')}</option>`).join('');
    $('p12Profile').innerHTML = profiles.map(p =>
      `<option value="${p.name}">${escapeHTML(p.name)} — ${escapeHTML(p.description || '')}</option>`).join('');
    $('lintProfile').innerHTML = '<option value="">baseline rules</option>' + profiles.map(p =>
      `<option value="${p.name}">${escapeHTML(p.name)}</option>`).join('');
    renderIssueProfileInfo();
  } catch (_) { /* profiles are read-gated; ignore if forbidden */ }
}

// renderIssueProfileInfo shows the selected profile's validation rules under
// the issue form — what `secsy-ca profiles` prints on the CLI.
function renderIssueProfileInfo() {
  const p = profiles.find(x => x.name === $('issueProfile').value);
  if (!p) { $('issueProfileInfo').textContent = ''; return; }
  const bits = [];
  if (p.default_validity_days) bits.push(`default validity ${p.default_validity_days}d`);
  if (p.max_validity_days) bits.push(`max ${p.max_validity_days}d`);
  if (p.key_usages && p.key_usages.length) bits.push('key usage: ' + p.key_usages.join(', '));
  if (p.ext_key_usages && p.ext_key_usages.length) bits.push('EKU: ' + p.ext_key_usages.join(', '));
  if (p.algorithm) bits.push('algorithm: ' + p.algorithm);
  if (p.ct && p.ct.enabled) bits.push('CT submission');
  if (p.caa && p.caa.mode && p.caa.mode !== 'off') bits.push('CAA ' + p.caa.mode);
  if (p.must_staple) bits.push('OCSP Must-Staple' + (p.allow_must_staple_override ? ' (override allowed)' : ''));
  if (p.lint && p.lint.public) bits.push('CA/B public lint rules');
  if (p.upn) bits.push('UPN SAN' + (p.upn.require_upn ? ' (required)' : ''));
  // eIDAS / ETSI EN 319 412-5 qualified-certificate semantics (Task 128).
  if (p.qcstatements) {
    const qc = p.qcstatements;
    const t = { esign: 'e-signature', eseal: 'e-seal', web: 'website / QWAC' }[qc.type] || qc.type || 'qualified';
    let label = 'eIDAS qualified (' + t + (qc.sscd ? ', QSCD' : '') + ')';
    if (qc.allow_psd2_override) label += ' — PSD2 override allowed';
    bits.push(label);
  }
  // RFC 5280 id-ce-privateKeyUsagePeriod window (Task 132).
  if (p.private_key_usage_period) {
    const k = p.private_key_usage_period;
    const win = k.duration || (k.fraction ? Math.round(k.fraction * 100) + '% of validity'
      : (k.not_after ? 'fixed window' : 'per request'));
    bits.push('private-key usage period ' + win + (k.allow_override ? ' (override allowed)' : ''));
  }
  // RFC 9345 TLS delegated-credential eligibility (Task 133) — profile-only.
  if (p.delegation_usage) bits.push('RFC 9345 delegated-credential eligible');
  $('issueProfileInfo').textContent = bits.length ? 'Profile policy: ' + bits.join(' · ') : '';
  // Only relevant for UPN-enabled profiles; keep the input visible but hint it.
  const upnField = $('issueUPNField');
  if (upnField) upnField.style.display = p.upn ? '' : 'none';
  // The Must-Staple override (RFC 7633) is honored only where the profile sets
  // allow_must_staple_override; otherwise the profile default is fixed, so hide
  // the control and reset it to "profile default".
  const msField = $('issueMustStapleField');
  if (msField) {
    msField.style.display = p.allow_must_staple_override ? '' : 'none';
    if (!p.allow_must_staple_override) $('issueMustStaple').value = '';
  }
  // eIDAS PSD2 override fields (Task 128) — shown only where the qualified
  // profile permits a per-request PSD2 QcStatement (qcstatements.allow_psd2_override,
  // e.g. qualified-web); hidden and cleared otherwise so a stale value is never sent.
  const qcField = $('issueQCField');
  if (qcField) {
    const allowPSD2 = !!(p.qcstatements && p.qcstatements.allow_psd2_override);
    qcField.style.display = allowPSD2 ? '' : 'none';
    if (!allowPSD2) {
      document.querySelectorAll('.psd2Role').forEach(cb => { cb.checked = false; });
      $('issuePSD2NCAName').value = '';
      $('issuePSD2NCAID').value = '';
    }
  }
  // Private Key Usage Period override (Task 132) — shown only where the profile
  // sets private_key_usage_period.allow_override (e.g. qualified-esign/eseal);
  // otherwise the profile window (if any) is authoritative, so hide and clear it.
  const pkupField = $('issuePKUPField');
  if (pkupField) {
    const allowPKUP = !!(p.private_key_usage_period && p.private_key_usage_period.allow_override);
    pkupField.style.display = allowPKUP ? '' : 'none';
    if (!allowPKUP) $('issuePKUP').value = '';
  }
}
$('issueProfile').onchange = renderIssueProfileInfo;

// ---- Certificates view ---------------------------------------------------
$('certCA').onchange = () => { updateCRLLink(); loadCerts(); };
$('showRevoked').onchange = () => loadCerts();
$('refreshCerts').onclick = () => loadCerts();
$('certStatus').onchange = () => loadCerts();
$('certProfile').oninput = debounce(() => loadCerts(), 300);
$('certSearch').oninput = debounce(() => loadCerts(), 300);
$('certLoadMore').onclick = () => loadCerts(true);

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
    if (s.sharded) {
      const links = [];
      for (let i = 0; i < s.shard_count; i++) {
        links.push(`<a href="/api/ca/${id}/crl/partition/${i}?format=pem" target="_blank">${i}</a>`);
      }
      html += ` &nbsp;|&nbsp; partitioned into ${s.shard_count} shards: ${links.join(' ')}`;
    }
    el.innerHTML = html;
  } catch (e) { el.textContent = 'CRL status unavailable: ' + e.message; }
}
function expiryTag(scope) {
  return scope && scope.expired ? '<span class="badge fail">stale</span>' : '';
}

// certPageCursor carries the next-page cursor between "Load more" clicks; it is
// reset whenever the CA, filters, or view mode change.
let certPageCursor = '';

// certListQuery builds the ?limit=&cursor=&… query string for the paginated
// certificate/revoked endpoints (Task 83) from the toolbar filter controls.
function certListQuery(revoked) {
  const p = new URLSearchParams();
  p.set('limit', '50');
  if (certPageCursor) p.set('cursor', certPageCursor);
  const search = $('certSearch').value.trim();
  if (revoked) {
    // The revoked store records only (serial, revoked_at, reason); map the search
    // box to a serial prefix, the one filter it supports.
    if (search) p.set('serial_prefix', search);
  } else {
    if (search) p.set('q', search);
    if ($('certStatus').value) p.set('status', $('certStatus').value);
    if ($('certProfile').value.trim()) p.set('profile', $('certProfile').value.trim());
  }
  return '?' + p.toString();
}

// loadCerts renders one page of the selected CA's certificates. Called with
// append=false (default) it resets the table and paging cursor for a fresh
// filter; append=true fetches the next page and appends it ("Load more").
async function loadCerts(append) {
  const id = selectedCertCA();
  const tbody = $('certRows');
  const more = $('certLoadMore');
  const count = $('certCount');
  const revoked = $('showRevoked').checked;
  if (!id) {
    tbody.innerHTML = '<tr><td colspan="7" class="muted">Select a CA…</td></tr>';
    more.classList.add('hidden'); count.textContent = '';
    return;
  }
  if (!append) { certPageCursor = ''; tbody.innerHTML = '<tr><td colspan="7" class="muted">Loading…</td></tr>'; }
  try {
    const endpoint = revoked ? `/api/ca/${id}/revoked` : `/api/ca/${id}/certificates`;
    const res = await api('GET', endpoint + certListQuery(revoked));
    const items = res.items || [];
    const rowsHTML = revoked ? items.map(r => revokedRowHTML(id, r)).join('')
                             : items.map(c => certRowHTML(id, c)).join('');
    if (!append) {
      tbody.innerHTML = rowsHTML || emptyRow(revoked ? 'No revoked certificates.' : 'No certificates match.');
    } else if (rowsHTML) {
      tbody.insertAdjacentHTML('beforeend', rowsHTML);
    }
    certPageCursor = res.next_cursor || '';
    more.classList.toggle('hidden', !res.has_more);
    const shown = tbody.querySelectorAll('tr').length - (tbody.querySelector('.muted') ? 1 : 0);
    count.textContent = res.total ? `${Math.min(shown, res.total)} of ${res.total}` : '';
  } catch (e) {
    if (!append) tbody.innerHTML = emptyRow(e.message);
    else alert('Load more failed: ' + e.message);
  }
}

// revokedRowHTML renders one revocation row. reason 6 (certificateHold) is a
// reversible hold, badged distinctly with a Release action.
function revokedRowHTML(id, r) {
  const held = (r.reason === 6);
  return `
    <tr>
      <td class="mono">${escapeHTML(shortSerial(r.serial))}</td>
      <td colspan="2" class="muted">${held ? 'on hold' : 'revoked'}</td>
      <td>${fmtTime(r.revoked_at)}</td>
      <td><span class="badge ${held ? 'held' : 'revoked'}">${held ? 'held' : 'revoked'}</span></td>
      <td class="muted">reason ${r.reason ?? 0}${held
        ? ` · <button class="btn ghost sm" onclick="releaseCert('${id}','${r.serial}')" title="Remove the hold and return the certificate to service">Release</button>`
        : ''}</td>
    </tr>`;
}

// certRowHTML renders one issued-certificate row with its lifecycle actions.
function certRowHTML(id, c) {
  return `
    <tr>
      <td class="mono">${escapeHTML(shortSerial(c.serial))}</td>
      <td>${escapeHTML(c.common_name || '')}</td>
      <td>${escapeHTML(c.profile || '')}</td>
      <td>${fmtTime(c.not_after)}</td>
      <td><span class="badge ${c.status}">${c.status}</span></td>
      <td>${ctBadge(c)}</td>
      <td style="white-space:nowrap">${c.status === 'valid'
        ? `<button class="btn ghost sm" onclick="renewCert('${id}','${c.serial}')" title="Reissue with a fresh serial and validity window, reusing the certified key">Renew</button>
           <button class="btn ghost sm" onclick="suspendCert('${id}','${c.serial}')" title="Place on hold (RFC 5280 certificateHold) — a reversible revocation">Suspend</button>
           <button class="btn danger sm" onclick="revokeCert('${id}','${c.serial}')">Revoke</button>`
        : c.status === 'held'
        ? `<button class="btn ghost sm" onclick="releaseCert('${id}','${c.serial}')" title="Remove the hold and return the certificate to service">Release</button>
           <button class="btn danger sm" onclick="revokeCert('${id}','${c.serial}')" title="Convert the hold into a permanent revocation">Revoke</button>`
        : ''}</td>
    </tr>`;
}

// renewCert reissues a certificate under the same CA/profile with a fresh
// serial and validity window — the console counterpart of `secsy-ca renew`.
async function renewCert(caID, serial) {
  if (!confirm(`Renew certificate ${shortSerial(serial)}?\n\nA new certificate with a fresh serial and validity window is issued for the same key and profile; the old one stays valid until it expires or is revoked.`)) return;
  try {
    const res = await api('POST', `/api/ca/${caID}/renew`, { serial });
    alert(`Renewed: new serial ${res.serial}, valid until ${res.not_after}.`);
    if (selectedCertCA() === caID) loadCerts();
  } catch (e) { alert('Renew failed: ' + e.message); }
}
window.renewCert = renewCert;

// suspendCert places a certificate on hold (RFC 5280 certificateHold) — a
// reversible revocation. No reason picker: certificateHold is the only reason.
async function suspendCert(caID, serial) {
  if (!confirm(`Suspend certificate ${shortSerial(serial)}?\n\nThe certificate is placed on hold (certificateHold): OCSP reports it revoked and it appears on the CRL, but the hold can be released later to return it to service.`)) return;
  try {
    const res = await api('POST', `/api/ca/${caID}/certificates/${encodeURIComponent(serial)}:suspend`);
    alert(`Certificate ${shortSerial(serial)} is ${res.status}.`);
    if (selectedCertCA() === caID) { loadCerts(); loadCRLStatus(caID); }
    if ($('view-inventory').classList.contains('active')) loadInventory();
  } catch (e) { alert('Suspend failed: ' + e.message); }
}
window.suspendCert = suspendCert;

// releaseCert removes a certificate hold, returning it to service. It fails if
// the certificate was permanently revoked rather than suspended.
async function releaseCert(caID, serial) {
  if (!confirm(`Release the hold on certificate ${shortSerial(serial)}?\n\nOCSP will report it good again and the next base CRL omits it; the next delta CRL carries removeFromCRL for it. Only a suspended (on-hold) certificate can be released.`)) return;
  try {
    const res = await api('POST', `/api/ca/${caID}/certificates/${encodeURIComponent(serial)}:release`);
    alert(`Certificate ${shortSerial(serial)} is ${res.status}.`);
    if (selectedCertCA() === caID) { loadCerts(); loadCRLStatus(caID); }
    if ($('view-inventory').classList.contains('active')) loadInventory();
  } catch (e) { alert('Release failed: ' + e.message); }
}
window.releaseCert = releaseCert;

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

// ---- Bulk revocation (Task 70, incident response) -------------------------
// Two-phase flow with a mandatory confirmation of the dry-run count: Preview
// posts {dry_run:true} and renders the plan; Execute is armed only while the
// typed count equals the previewed total and echoes it as confirm_count, which
// the server re-checks against the live selection (409 on drift).
let bulkPlan = null; // last previewed plan for the currently selected CA

function bulkFilterBody() {
  const filter = {};
  if ($('bulkProfile').value.trim()) filter.profile = $('bulkProfile').value.trim();
  if ($('bulkPattern').value.trim()) filter.pattern = $('bulkPattern').value.trim();
  // datetime-local values carry no zone; incident timelines are kept in UTC.
  if ($('bulkIssuedAfter').value) filter.issued_after = $('bulkIssuedAfter').value + ':00Z';
  if ($('bulkIssuedBefore').value) filter.issued_before = $('bulkIssuedBefore').value + ':00Z';
  if ($('bulkIncludeExpired').checked) filter.include_expired = true;
  const serials = $('bulkSerials').value.split('\n')
    .map(l => l.replace(/#.*$/, '').trim()).filter(Boolean);
  if (serials.length) filter.serials = serials;
  return filter;
}

function resetBulkPlan() {
  bulkPlan = null;
  $('bulkPlanBox').classList.add('hidden');
  $('bulkResultBox').classList.add('hidden');
  $('bulkError').classList.add('hidden');
  $('bulkConfirmCount').value = '';
  $('bulkExecute').disabled = true;
  $('bulkProgress').textContent = '';
}
$('certCA').addEventListener('change', resetBulkPlan);

$('bulkPreview').onclick = async () => {
  const id = selectedCertCA();
  if (!id) { showError($('bulkError'), 'Select a CA first.'); return; }
  resetBulkPlan();
  $('bulkPreview').disabled = true;
  try {
    bulkPlan = await api('POST', `/api/ca/${id}/revocations:bulk`, {
      dry_run: true,
      reason: $('bulkReason').value,
      filter: bulkFilterBody(),
    });
    const p = bulkPlan;
    const bits = [`<b>${p.total}</b> certificate(s) will be revoked (reason <b>${escapeHTML(p.reason)}</b>, filter: ${escapeHTML(p.filter)})`];
    if (p.unknown) bits.push(`${p.unknown} serial(s) are not in the inventory and will be revoked as bare CRL entries`);
    if (p.already_revoked) bits.push(`${p.already_revoked} already revoked (skipped — resuming an earlier run?)`);
    if (p.filtered_out) bits.push(`${p.filtered_out} listed serial(s) excluded by the other filters`);
    if (p.expired_excluded) bits.push(`${p.expired_excluded} matching certificate(s) skipped as expired`);
    $('bulkPlanSummary').innerHTML = bits.join('<br>');
    $('bulkSampleRows').innerHTML = (p.sample || []).map(s => `
      <tr>
        <td class="mono">${escapeHTML(shortSerial(s.serial))}</td>
        <td>${s.known ? escapeHTML(s.common_name || '') : '<span class="muted">not in inventory</span>'}</td>
        <td>${escapeHTML(s.profile || '')}</td>
        <td>${s.known ? fmtTime(s.not_after) : ''}</td>
      </tr>`).join('') || emptyRow('Nothing matches this selection.');
    if (p.total > (p.sample || []).length) {
      $('bulkSampleRows').innerHTML += `<tr><td colspan="4" class="muted">… and ${p.total - p.sample.length} more</td></tr>`;
    }
    $('bulkExpectedCount').textContent = p.total;
    $('bulkPlanBox').classList.remove('hidden');
    if (p.total === 0) $('bulkConfirmCount').placeholder = 'nothing to revoke';
  } catch (e) { showError($('bulkError'), e.message); }
  finally { $('bulkPreview').disabled = false; }
};

// The execute button arms only while the typed count matches the previewed
// total — the operator must actively transcribe the number they reviewed.
$('bulkConfirmCount').addEventListener('input', () => {
  const armed = bulkPlan && bulkPlan.total > 0 &&
    $('bulkConfirmCount').value.trim() === String(bulkPlan.total);
  $('bulkExecute').disabled = !armed;
});

$('bulkExecute').onclick = async () => {
  const id = selectedCertCA();
  if (!id || !bulkPlan) return;
  const confirmed = parseInt($('bulkConfirmCount').value.trim(), 10);
  if (confirmed !== bulkPlan.total) return;
  $('bulkExecute').disabled = true;
  $('bulkProgress').textContent = `Revoking ${bulkPlan.total} certificate(s)…`;
  try {
    const result = await api('POST', `/api/ca/${id}/revocations:bulk`, {
      reason: $('bulkReason').value,
      filter: bulkFilterBody(),
      confirm_count: confirmed,
      operation_id: bulkPlan.operation_id,
    });
    $('bulkResultBox').innerHTML = `<div class="crl-status">Bulk revocation complete: <b>${result.revoked}</b> revoked`
      + ` in ${result.batches} batch(es), CRL scopes regenerated: ${escapeHTML((result.crl_scopes || []).join(', ') || 'none')}`
      + `, ${Number(result.duration_seconds || 0).toFixed(2)}s (operation <span class="mono">${escapeHTML(result.operation_id)}</span>)`
      + (result.presign_error ? ` — <span class="badge fail">presign refresh failed</span>` : '')
      + `</div>`;
    $('bulkResultBox').classList.remove('hidden');
    $('bulkPlanBox').classList.add('hidden');
    bulkPlan = null;
    loadCerts(); loadCRLStatus(id);
  } catch (e) {
    // The most common failure is 409 count drift (issuance raced the preview);
    // force a fresh preview so the operator confirms the new number.
    showError($('bulkError'), e.message + ' — run Preview again and confirm the fresh count.');
    $('bulkPlanBox').classList.add('hidden');
    bulkPlan = null;
  } finally {
    $('bulkProgress').textContent = '';
    $('bulkConfirmCount').value = '';
  }
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

// ---- External discovery view ---------------------------------------------
$('discRefresh').onclick = () => loadDiscovery();
$('discScan').onclick = runDiscoveryScan;
$('discSearch').oninput = debounce(() => loadDiscovery(), 300);
$('discLoadMore').onclick = () => loadDiscovery(true);

// discPageCursor carries the next-page cursor between "Load more" clicks over the
// stored discovered-certificate inventory; reset when the search filter changes.
let discPageCursor = '';

// loadDiscovery lists one page of the certificates already recorded by the
// discovery scanner (Task 83). append=true fetches the next page ("Load more");
// otherwise it resets for a fresh search. Unlike a scan (renderDiscovery), the
// stored inventory is paged server-side, so rows appear in the server's
// newest-first order rather than being re-sorted by severity across pages.
async function loadDiscovery(append) {
  const tbody = $('discRows');
  const more = $('discLoadMore');
  const count = $('discCount');
  if (!append) { discPageCursor = ''; tbody.innerHTML = '<tr><td colspan="7" class="muted">Loading…</td></tr>'; }
  try {
    const p = new URLSearchParams();
    p.set('limit', '50');
    if (discPageCursor) p.set('cursor', discPageCursor);
    const search = $('discSearch').value.trim();
    if (search) p.set('q', search);
    const rep = await api('GET', '/api/discovery?' + p.toString());
    const items = rep.items || rep.certificates || [];
    const rowsHTML = items.map(discoveredRowHTML).join('');
    if (!append) {
      tbody.innerHTML = rowsHTML || '<tr><td colspan="7" class="muted">No stored certificates match.</td></tr>';
    } else if (rowsHTML) {
      tbody.insertAdjacentHTML('beforeend', rowsHTML);
    }
    discPageCursor = rep.next_cursor || '';
    more.classList.toggle('hidden', !rep.has_more);
    const shown = tbody.querySelectorAll('tr').length - (tbody.querySelector('.muted') ? 1 : 0);
    count.textContent = rep.total ? `${Math.min(shown, rep.total)} of ${rep.total} stored` : '';
    $('discCounts').textContent = '';
  } catch (e) {
    if (!append) { tbody.innerHTML = `<tr><td colspan="7" class="muted">${escapeHTML(e.message)}</td></tr>`; $('discCounts').textContent = ''; }
    else alert('Load more failed: ' + e.message);
  }
}

// runDiscoveryScan probes the entered targets, then re-renders the results.
async function runDiscoveryScan() {
  const raw = $('discTargets').value.trim();
  const targets = raw.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);
  const btn = $('discScan');
  btn.disabled = true;
  const tbody = $('discRows');
  tbody.innerHTML = '<tr><td colspan="7" class="muted">Scanning…</td></tr>';
  try {
    const rep = await api('POST', '/api/discovery/scan', {
      targets,
      store: $('discStore').checked,
      notify: $('discNotify').checked,
    });
    // The scan returns findings (including unreachable endpoints); render them.
    renderDiscovery((rep.findings || []).filter(f => f.reachable), rep.counts, rep.findings || []);
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">${escapeHTML(e.message)}</td></tr>`;
  } finally { btn.disabled = false; }
}

// renderDiscovery paints a set of discovered certificates. It accepts either the
// persisted records (from GET) or scan findings (from POST); both share the leaf
// fields used here. Rogue (not-issued-by-this-PKI) certs are highlighted.
function renderDiscovery(certs, counts, allFindings) {
  const tbody = $('discRows');
  const rank = { critical: 0, warning: 1, ok: 2 };
  const rows = (certs || []).slice().sort((a, b) => (rank[a.severity] ?? 3) - (rank[b.severity] ?? 3));
  if (counts) {
    const unreachable = (allFindings || []).filter(f => !f.reachable).length;
    $('discCounts').textContent =
      `${counts.total} endpoint(s): ${counts.reachable} reachable, ${unreachable} unreachable · ` +
      `expiring ${counts.expiring_soon} · weak ${counts.weak_key} · sha1 ${counts.sha1_signature} · ` +
      `self-signed ${counts.self_signed} · mismatch ${counts.hostname_mismatch} · rogue ${counts.rogue}`;
  } else {
    $('discCounts').textContent = `${rows.length} discovered certificate(s)`;
  }
  // A scan renders its full result set, so hide the stored-inventory pager.
  $('discLoadMore').classList.add('hidden');
  $('discCount').textContent = '';
  tbody.innerHTML = rows.length ? rows.map(discoveredRowHTML).join('')
    : '<tr><td colspan="7" class="muted">No certificates found.</td></tr>';
}

// discoveredRowHTML renders one discovered-certificate row, shared by the paged
// stored-inventory listing and the scan-result view.
function discoveredRowHTML(c) {
  const key = c.key_algorithm ? (c.key_size ? `${c.key_algorithm}-${c.key_size}` : c.key_algorithm) : '—';
  const origin = c.issued_by_pki
    ? '<span class="badge pass" title="Chains to one of this PKI\'s CAs">this PKI</span>'
    : (c.self_signed
      ? '<span class="badge warning">self-signed</span>'
      : '<span class="badge fail" title="Not issued by this PKI">rogue</span>');
  const flags = (c.flags || []).length
    ? c.flags.map(f => `<span class="badge ${c.severity}">${escapeHTML(f)}</span>`).join(' ')
    : '<span class="muted">—</span>';
  return `<tr>
    <td class="mono">${escapeHTML(c.endpoint || '')}</td>
    <td>${escapeHTML(c.common_name || '')}</td>
    <td title="${escapeHTML(c.issuer || '')}">${escapeHTML(shortName(c.issuer))}</td>
    <td>${escapeHTML(key)}</td>
    <td>${fmtTime(c.not_after)}</td>
    <td>${origin}</td>
    <td>${flags}</td>
  </tr>`;
}

// shortName renders the CN portion of a distinguished name for compact display.
function shortName(dn) {
  if (!dn) return '—';
  const m = dn.match(/CN=([^,]+)/);
  return m ? m[1] : (dn.length > 40 ? dn.slice(0, 39) + '…' : dn);
}

// ---- Certificate chain validation view (Task 123) -------------------------
$('validateBtn').onclick = runValidation;

// runValidation posts the supplied leaf (+ optional intermediates) to
// /api/validate for path validation against the selected CA's trust anchors and
// renders the structured verdict. Nothing is signed server-side.
async function runValidation() {
  const ca = $('validateCA').value;
  const cert = $('validateCert').value.trim();
  const err = $('validateError');
  err.classList.add('hidden');
  if (!ca) { err.textContent = 'Select a trust-anchor CA.'; err.classList.remove('hidden'); return; }
  if (!cert) { err.textContent = 'Paste a certificate to validate.'; err.classList.remove('hidden'); return; }
  const inter = $('validateInter').value.trim();
  const btn = $('validateBtn');
  btn.disabled = true;
  $('validateResult').innerHTML = '<p class="muted">Validating…</p>';
  try {
    const body = { ca, certificate: cert, skip_revocation: $('validateSkipRev').checked };
    if (inter) body.intermediates = [inter];
    renderValidation(await api('POST', '/api/validate', body));
  } catch (e) {
    $('validateResult').innerHTML = '';
    err.textContent = e.message;
    err.classList.remove('hidden');
  } finally {
    btn.disabled = false;
  }
}

// renderValidation paints the verdict banner, the per-dimension checks, and the
// resolved chain returned by /api/validate.
function renderValidation(rep) {
  const badge = rep.valid ? '<span class="badge pass">VALID</span>' : '<span class="badge fail">INVALID</span>';
  const built = rep.chain_built ? 'chain built' : 'chain NOT built';
  let html = `<div class="panel"><h2 style="font-size:15px">${badge} — ${built} against ${escapeHTML(rep.trust_anchor || rep.ca_label || '')}</h2>`;
  if (rep.reasons && rep.reasons.length) {
    html += '<ul style="margin:6px 0">' + rep.reasons.map(r => `<li>${escapeHTML(r)}</li>`).join('') + '</ul>';
  }
  if (rep.warnings && rep.warnings.length) {
    html += '<ul class="muted" style="margin:6px 0">' + rep.warnings.map(r => `<li>⚠ ${escapeHTML(r)}</li>`).join('') + '</ul>';
  }
  html += '<table><thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead><tbody>';
  (rep.checks || []).forEach(c => {
    let detail = escapeHTML(c.detail);
    if (c.findings && c.findings.length) {
      detail += '<br>' + c.findings.map(f => `<span class="muted">• ${escapeHTML(f)}</span>`).join('<br>');
    }
    html += `<tr><td>${escapeHTML(c.name)}</td><td>${checkBadge(c.status)}</td><td>${detail}</td></tr>`;
  });
  html += '</tbody></table></div>';

  html += '<div class="panel"><h2 style="font-size:15px">Resolved chain</h2>' +
    '<table><thead><tr><th>#</th><th>Subject</th><th>Serial</th><th>Not after</th><th>Revocation</th><th>Flags</th></tr></thead><tbody>';
  (rep.chain || []).forEach(ci => {
    const flags = [];
    if (ci.is_trust_anchor) flags.push('<span class="badge pass">anchor</span>');
    else if (ci.is_ca) flags.push('<span class="badge">CA</span>');
    if (ci.expired) flags.push('<span class="badge fail">expired</span>');
    if (ci.not_yet_valid) flags.push('<span class="badge fail">not-yet-valid</span>');
    if (ci.weak_key) flags.push('<span class="badge fail">weak-key</span>');
    if (ci.weak_signature) flags.push('<span class="badge fail">weak-sig</span>');
    const rev = ci.revocation ? checkBadge(revStatusClass(ci.revocation.state), ci.revocation.state) : '<span class="muted">—</span>';
    html += `<tr><td>${ci.position}</td><td title="${escapeHTML(ci.subject)}">${escapeHTML(shortName(ci.subject))}</td>` +
      `<td class="mono">${escapeHTML(ci.serial_number || '')}</td><td>${fmtTime(ci.not_after)}</td>` +
      `<td>${rev}</td><td>${flags.join(' ') || '<span class="muted">—</span>'}</td></tr>`;
  });
  html += '</tbody></table></div>';
  $('validateResult').innerHTML = html;
}

// checkBadge renders a coloured badge for a pass/fail/warn/skipped status, or an
// explicit (class, label) pair for the revocation column.
function checkBadge(statusOrClass, label) {
  const map = { pass: 'pass', fail: 'fail', warn: 'warning', skipped: '' };
  const cls = label !== undefined ? statusOrClass : (map[statusOrClass] ?? '');
  return `<span class="badge ${cls}">${escapeHTML(label !== undefined ? label : statusOrClass)}</span>`;
}

// revStatusClass maps a revocation state to a badge colour class.
function revStatusClass(state) {
  if (state === 'good') return 'pass';
  if (state === 'unknown') return 'warning';
  return 'fail'; // revoked / held
}

// ---- CT SCT inclusion view (Task 93) -------------------------------------
$('ctRefresh').onclick = () => loadCT();
$('ctStatus').onchange = () => loadCT();

// loadCT lists the recorded SCT inclusion-proof state: whether the CT logs
// honored the SCTs embedded at issuance. "failed" rows are highlighted — they
// are the mis-issuance / log-misbehavior signal.
async function loadCT() {
  const tbody = $('ctRows');
  tbody.innerHTML = '<tr><td colspan="9" class="muted">Loading…</td></tr>';
  try {
    const p = new URLSearchParams();
    const status = $('ctStatus').value;
    if (status) p.set('status', status);
    p.set('limit', '500');
    const rep = await api('GET', '/api/ct/inclusion?' + p.toString());
    const c = rep.counts || {};
    $('ctCounts').innerHTML =
      `${rep.total || 0} SCT(s): ` +
      `<span class="badge ${(c.failed || 0) ? 'critical' : 'ok'}">failed ${c.failed || 0}</span> ` +
      `<span class="badge warning">pending ${c.pending || 0}</span> ` +
      `<span class="badge ok">included ${c.included || 0}</span> ` +
      `unknown-log ${c.unknown_log || 0}`;
    const items = rep.items || [];
    const rows = items.map(ctRowHTML).join('');
    tbody.innerHTML = rows || '<tr><td colspan="9" class="muted">No SCT inclusion state matches.</td></tr>';
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="9" class="muted">${escapeHTML(e.message)}</td></tr>`;
    $('ctCounts').textContent = '';
  }
}

// ctRowHTML renders one SCT inclusion row; failed rows carry a critical badge.
function ctRowHTML(r) {
  const sev = r.status === 'failed' ? 'critical'
    : r.status === 'included' ? 'ok'
    : r.status === 'pending' ? 'warning' : '';
  const logName = r.log_name || (r.log_id ? r.log_id.slice(0, 12) : '—');
  return `<tr>
    <td><span class="badge ${sev}">${escapeHTML(r.status || '')}</span></td>
    <td class="mono">${escapeHTML(r.ca_id || '')}</td>
    <td class="mono">${escapeHTML(r.serial || '')}</td>
    <td title="${escapeHTML(r.log_id || '')}">${escapeHTML(logName)}</td>
    <td>${fmtTime(r.sct_timestamp)}</td>
    <td>${r.tree_size || 0}</td>
    <td>${r.leaf_index || 0}</td>
    <td>${r.last_checked_at ? fmtTime(r.last_checked_at) : '—'}</td>
    <td class="muted">${escapeHTML(r.last_error || '')}</td>
  </tr>`;
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

// ---- Key-compromise search (Task 154) ------------------------------------
// Locate every certificate that certifies a leaked subject public key. The
// server matches on the SubjectPublicKeyInfo SHA-256 fingerprint; the console
// either passes a fingerprint straight through (the server normalizes hex /
// SHA256:base64) or derives it locally from a pasted public-key PEM. Because the
// list endpoint is per-CA and tenant-scoped, the search fans out over every CA
// the operator can read and aggregates the matches.
async function fingerprintPublicKeyPEM(pem) {
  const m = pem.match(/-----BEGIN PUBLIC KEY-----([\s\S]*?)-----END PUBLIC KEY-----/);
  if (!m) throw new Error('paste a PEM "PUBLIC KEY" block, or enter a fingerprint directly');
  // A "PUBLIC KEY" block's DER is exactly the SubjectPublicKeyInfo, so its
  // SHA-256 equals the server's keycheck.Fingerprint over the same bytes.
  const der = unb64(m[1].replace(/\s+/g, ''));
  const digest = await crypto.subtle.digest('SHA-256', der);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function runKeyCompromiseSearch() {
  const res = $('kcResult');
  res.style.color = '';
  let fp = $('kcFingerprint').value.trim();
  const pem = $('kcPubKey').value.trim();
  try {
    if (!fp && pem) { fp = await fingerprintPublicKeyPEM(pem); $('kcFingerprint').value = fp; }
    if (!fp) { res.textContent = 'Enter a fingerprint or paste a public key.'; res.style.color = 'var(--crit)'; return; }
    res.textContent = 'Searching…';
    $('kcTable').classList.add('hidden');
    const matches = [];
    for (const c of x509CAs) {
      let cursor = '';
      do {
        const q = `/api/ca/${c.id}/certificates?public_key_sha256=${encodeURIComponent(fp)}&limit=200` +
          (cursor ? '&cursor=' + encodeURIComponent(cursor) : '');
        const page = await api('GET', q);
        (page.items || []).forEach(it => matches.push({ ...it, _ca: c.label }));
        cursor = page.next_cursor || '';
      } while (cursor);
    }
    if (!matches.length) {
      res.textContent = `No certificates share this key (searched ${x509CAs.length} CA(s)).`;
      return;
    }
    const live = matches.filter(m => m.status === 'valid').length;
    res.innerHTML = `<b>${matches.length}</b> certificate(s) share this key across ${x509CAs.length} CA(s) — <b>${live}</b> still valid. ` +
      `Revoke every match with <code>secsy-ca revoke-bulk --by-public-key ${escapeHTML(fp)} -ca &lt;ref&gt;</code> (subject to four-eyes approval if configured).`;
    $('kcRows').innerHTML = matches.map(m => `<tr>
      <td class="mono">${escapeHTML(shortSerial(m.serial))}</td>
      <td>${escapeHTML(m.common_name || '')}</td>
      <td>${escapeHTML(m._ca)}</td>
      <td>${escapeHTML(m.profile || '')}</td>
      <td>${fmtTime(m.not_after)}</td>
      <td><span class="badge ${escapeHTML(m.status)}">${escapeHTML(m.status)}</span></td>
    </tr>`).join('');
    $('kcTable').classList.remove('hidden');
  } catch (e) { res.textContent = 'Search failed: ' + e.message; res.style.color = 'var(--crit)'; }
}
if ($('kcSearchBtn')) $('kcSearchBtn').onclick = runKeyCompromiseSearch;
if ($('kcPubKey')) $('kcPubKey').addEventListener('change', async () => {
  const v = $('kcPubKey').value.trim();
  if (!v) return;
  try { $('kcFingerprint').value = await fingerprintPublicKeyPEM(v); }
  catch (e) { $('kcResult').textContent = e.message; $('kcResult').style.color = 'var(--crit)'; }
});

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
  // just hides the panel (and the mint forms with it).
  $('svidMintPanel').classList.add('hidden');
  $('svidJWTPanel').classList.add('hidden');
  try {
    const bundle = await api('GET', `/api/ca/${id}/svid/bundle`, undefined, true);
    $('svidBundle').value = bundle;
    $('svidPanel').classList.remove('hidden');
    $('svidMintPanel').classList.remove('hidden');
    $('svidJWTPanel').classList.remove('hidden');
  } catch (_) { /* SPIFFE not enabled for this server */ }
}

// Mint an X.509-SVID under the selected CA (SPIFFE workload identity).
$('svidMintBtn').onclick = async () => {
  const id = $('bundleCA').value;
  const err = $('svidError');
  err.classList.add('hidden');
  $('svidOutBox').classList.add('hidden');
  const spiffeID = $('svidID').value.trim();
  const csr = $('svidCSR').value.trim();
  if (!spiffeID || !csr) { showError(err, 'A SPIFFE ID and a CSR are required.'); return; }
  const body = { spiffe_id: spiffeID, csr };
  const ttl = parseInt($('svidTTL').value, 10);
  if (ttl > 0) body.ttl_seconds = ttl;
  $('svidMintBtn').disabled = true;
  try {
    const res = await api('POST', `/api/ca/${id}/svid`, body);
    $('svidOut').value = res.certificate + (res.chain || '');
    $('svidOutBox').classList.remove('hidden');
  } catch (e) { showError(err, e.message); }
  finally { $('svidMintBtn').disabled = false; }
};

// Mint a JWT-SVID under the selected CA (SPIFFE workload identity as a signed JWS
// bearer token). The audience is required and no CSR is involved.
$('svidJWTMintBtn').onclick = async () => {
  const id = $('bundleCA').value;
  const err = $('svidJWTError');
  err.classList.add('hidden');
  $('svidJWTOutBox').classList.add('hidden');
  const spiffeID = $('svidJWTID').value.trim();
  const aud = $('svidJWTAud').value.split(',').map(s => s.trim()).filter(Boolean);
  if (!spiffeID) { showError(err, 'A SPIFFE ID is required.'); return; }
  if (!aud.length) { showError(err, 'At least one audience is required.'); return; }
  const body = { spiffe_id: spiffeID, audience: aud };
  const ttl = parseInt($('svidJWTTTL').value, 10);
  if (ttl > 0) body.ttl_seconds = ttl;
  $('svidJWTMintBtn').disabled = true;
  try {
    const res = await api('POST', `/api/ca/${id}/svid/jwt`, body);
    $('svidJWTOut').value = res.token;
    $('svidJWTOutBox').classList.remove('hidden');
  } catch (e) { showError(err, e.message); }
  finally { $('svidJWTMintBtn').disabled = false; }
};

// ---- DNS pinning records (DANE TLSA / SSHFP) -----------------------------
async function loadDNS() {
  // TLSA targets any X.509 CA (already loaded in x509CAs).
  const x = x509CAs.map(c => `<option value="${c.id}">${escapeHTML(c.label)}</option>`).join('');
  $('dnsTlsaCA').innerHTML = x || '<option value="">— no CAs —</option>';
  // SSHFP targets an SSH CA; reuse the SSH page's list, loading it on demand.
  try {
    if (!sshCAs.length) sshCAs = await api('GET', '/api/ssh/cas');
  } catch (_) { /* read-gated or none configured */ }
  $('dnsSshfpCA').innerHTML = sshCAs.length
    ? sshCAs.map(c => `<option value="${c.id}">${escapeHTML(c.label)}</option>`).join('')
    : '<option value="">— no SSH CAs —</option>';
}

function dnsShowOut(boxId, outId, zone) {
  $(outId).value = zone;
  $(boxId).classList.remove('hidden');
}

$('dnsTlsaBtn').onclick = async () => {
  const msg = $('dnsMsg'); msg.className = 'notice hidden';
  const id = $('dnsTlsaCA').value, host = $('dnsTlsaHost').value.trim();
  if (!id || !host) { notice(msg, 'err', 'Select a CA and enter a host.'); return; }
  const port = $('dnsTlsaPort').value || '443';
  const serial = $('dnsTlsaSerial').value.trim();
  let q = `?host=${encodeURIComponent(host)}&port=${encodeURIComponent(port)}`;
  if (serial) q += `&serial=${encodeURIComponent(serial)}`;
  try {
    const b = await api('GET', `/api/ca/${id}/dns-records/tlsa${q}`);
    dnsShowOut('dnsTlsaOutBox', 'dnsTlsaOut', b.zone || '');
    notice(msg, 'ok', `${(b.tlsa || []).length} TLSA record(s) generated.`);
  } catch (e) { notice(msg, 'err', 'TLSA generation failed: ' + e.message); }
};

$('dnsSshfpBtn').onclick = async () => {
  const msg = $('dnsMsg'); msg.className = 'notice hidden';
  const id = $('dnsSshfpCA').value;
  if (!id) { notice(msg, 'err', 'Select an SSH CA.'); return; }
  const host = $('dnsSshfpHost').value.trim();
  const serial = $('dnsSshfpSerial').value.trim();
  const key = $('dnsSshfpKey').value.trim();
  if ((serial === '') === (key === '')) {
    notice(msg, 'err', 'Provide either a host cert serial or a public key, not both.');
    return;
  }
  const body = {};
  if (host) body.host = host;
  if (serial) body.serial = serial; else body.public_key = key;
  try {
    const b = await api('POST', `/api/ssh/cas/${id}/dns-records/sshfp`, body);
    dnsShowOut('dnsSshfpOutBox', 'dnsSshfpOut', b.zone || '');
    notice(msg, 'ok', `${(b.sshfp || []).length} SSHFP record(s) generated.`);
  } catch (e) { notice(msg, 'err', 'SSHFP generation failed: ' + e.message); }
};

function dnsCopy(outId, btnId) {
  const v = $(outId); v.select();
  navigator.clipboard.writeText(v.value).catch(() => document.execCommand('copy'));
  $(btnId).textContent = 'Copied';
  setTimeout(() => { $(btnId).textContent = 'Copy'; }, 1500);
}
$('dnsTlsaCopy').onclick = () => dnsCopy('dnsTlsaOut', 'dnsTlsaCopy');
$('dnsSshfpCopy').onclick = () => dnsCopy('dnsSshfpOut', 'dnsSshfpCopy');

// downloadBlob saves text content as a file via a transient object URL.
function downloadBlob(content, filename, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

// ---- Issue view ----------------------------------------------------------

// issueFormBody collects the request body shared by the Issue and Preview
// actions: the CSR, profile, optional validity, UPN otherName SANs (smartcard-
// logon / PKINIT), and the RFC 7633 OCSP Must-Staple override. Must-Staple is a
// tri-state — "" leaves the profile default, "true"/"false" force the extension
// on/off — and is honored by the server only under a profile that sets
// allow_must_staple_override (the control is hidden otherwise).
function issueFormBody(csr) {
  const body = { csr, profile: $('issueProfile').value };
  const days = parseInt($('issueDays').value, 10);
  if (days > 0) body.validity_days = days;
  const upns = $('issueUPN').value.split(',').map(s => s.trim()).filter(Boolean);
  if (upns.length) body.upns = upns;
  const ms = $('issueMustStaple').value;
  if (ms === 'true') body.must_staple = true;
  else if (ms === 'false') body.must_staple = false;
  // eIDAS PSD2 authorization (Task 128): honored only under a qualified profile
  // that sets allow_psd2_override — the field is hidden and reset otherwise, so
  // gate on its visibility to never submit a PSD2 block the server would reject.
  if ($('issueQCField').style.display !== 'none') {
    const roles = Array.from(document.querySelectorAll('.psd2Role:checked')).map(cb => cb.value);
    const ncaName = $('issuePSD2NCAName').value.trim();
    const ncaID = $('issuePSD2NCAID').value.trim();
    if (roles.length || ncaName || ncaID) {
      body.psd2 = {};
      if (roles.length) body.psd2.roles = roles;
      if (ncaName) body.psd2.nca_name = ncaName;
      if (ncaID) body.psd2.nca_id = ncaID;
    }
  }
  // RFC 5280 private-key usage period override (Task 132): a duration from the
  // certificate notBefore, honored only where the profile permits overrides.
  if ($('issuePKUPField').style.display !== 'none') {
    const pkup = $('issuePKUP').value.trim();
    if (pkup) body.private_key_usage_period = { duration: pkup };
  }
  return body;
}

$('issueBtn').onclick = async () => {
  const id = $('issueCA').value;
  const msg = $('issueMsg');
  msg.className = 'notice hidden';
  $('issuePreviewResult').classList.add('hidden');
  if (!id) { showError(msg, 'Select a CA.'); msg.className = 'notice err'; return; }
  const csr = $('issueCSR').value.trim();
  if (!csr) { showError(msg, 'Paste a PEM CSR.'); msg.className = 'notice err'; return; }
  const body = issueFormBody(csr);
  $('issueBtn').disabled = true;
  try {
    const res = await api('POST', `/api/ca/${id}/issue`, body);
    // A require_approval profile (Task 84) holds issuance for four-eyes approval:
    // no certificate is returned yet — point the operator at the Approvals queue.
    if (res.status === 'pending_approval') {
      msg.textContent = `Issuance held for approval: request ${res.approval_id} needs ` +
        `${res.required_approvals} distinct approver(s). Approve it under Approvals, then fetch the certificate there.`;
      msg.className = 'notice warn';
      $('issueResult').classList.add('hidden');
      loadApprovals();
      return;
    }
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

// Preview (dry run): run the request through the full fail-closed pre-issuance
// gate stack (POST …/certificates:preview) and render the verdict WITHOUT
// signing — no serial, no audit, no HSM. Reuses issueFormBody() so the preview
// reflects exactly what "Issue certificate" would submit.
$('issuePreviewBtn').onclick = async () => {
  const id = $('issueCA').value;
  const msg = $('issueMsg');
  msg.className = 'notice hidden';
  const box = $('issuePreviewResult');
  if (!id) { showError(msg, 'Select a CA.'); msg.className = 'notice err'; return; }
  const csr = $('issueCSR').value.trim();
  if (!csr) { showError(msg, 'Paste a PEM CSR.'); msg.className = 'notice err'; return; }
  $('issueResult').classList.add('hidden');
  box.classList.remove('hidden');
  box.innerHTML = '<p class="muted">Previewing…</p>';
  $('issuePreviewBtn').disabled = true;
  try {
    const res = await api('POST', `/api/ca/${id}/certificates:preview`, issueFormBody(csr));
    renderIssuePreview(res);
  } catch (e) {
    box.innerHTML = '';
    showError(msg, e.message); msg.className = 'notice err';
  } finally { $('issuePreviewBtn').disabled = false; }
};

// renderIssuePreview paints the preview verdict: a decision banner, the resolved
// leaf summary, and the per-gate table (reusing the validation checkBadge).
function renderIssuePreview(r) {
  const decision = (r.decision || '').toLowerCase();
  const cls = decision === 'accept' ? 'ok' : decision === 'park' ? 'warn' : 'err';
  const label = decision === 'accept' ? 'WOULD ISSUE'
    : decision === 'park' ? 'WOULD BE HELD FOR APPROVAL' : 'WOULD BE REJECTED';
  let html = `<div class="notice ${cls}" style="margin-bottom:12px"><strong>${label}</strong>` +
    ` — ${escapeHTML(r.profile || '')} under ${escapeHTML(r.ca_label || r.ca_id || '')}. ` +
    `Dry run only: nothing signed, no serial, no audit.</div>`;

  const rows = [];
  if (r.subject) rows.push(['Subject', escapeHTML(r.subject)]);
  if (r.sans && r.sans.length) rows.push(['SANs', escapeHTML(r.sans.join(', '))]);
  if (r.key_usages && r.key_usages.length) rows.push(['Key usage', escapeHTML(r.key_usages.join(', '))]);
  if (r.ext_key_usages && r.ext_key_usages.length) rows.push(['EKU', escapeHTML(r.ext_key_usages.join(', '))]);
  const validity = r.validity_days + 'd' +
    (r.requested_validity_days && r.requested_validity_days !== r.validity_days
      ? ` (requested ${r.requested_validity_days}d, max ${r.max_validity_days}d)` : '');
  rows.push(['Validity', escapeHTML(validity)]);
  rows.push(['OCSP Must-Staple', r.must_staple ? 'yes' : 'no']);
  if (r.subject_key_provided === false) {
    rows.push(['Subject key', '<span class="muted">synthesized (no CSR key) — identifiers indicative</span>']);
  }
  html += '<table><tbody>' + rows.map(([k, v]) =>
    `<tr><th style="text-align:left;width:160px">${k}</th><td>${v}</td></tr>`).join('') + '</tbody></table>';

  html += '<h2 style="font-size:15px;margin-top:14px">Pre-issuance gates</h2>';
  html += '<table><thead><tr><th>Gate</th><th>Status</th><th>Detail</th></tr></thead><tbody>';
  (r.gates || []).forEach(g => {
    let detail = escapeHTML(g.reason || '');
    if (g.findings && g.findings.length) {
      detail += '<br>' + g.findings.map(f => `<span class="muted">• ${escapeHTML(f)}</span>`).join('<br>');
    }
    html += `<tr><td>${escapeHTML(g.name)}</td><td>${checkBadge(g.status)}</td><td>${detail}</td></tr>`;
  });
  html += '</tbody></table>';
  $('issuePreviewResult').innerHTML = html;
}

// ---- Bulk / batch issuance (Task 101, fleet provisioning) -----------------
// Same two-phase confirm-the-count contract as bulk revocation: Preview posts
// {dry_run:true} and renders the per-item plan; Execute is armed only while the
// typed count equals the previewed item count and echoes it as confirm_count.
// Each item is issued independently — the result carries a per-item status
// (issued / pending-for-approval / failed) so a partial failure is visible.
let bulkIssuePlan = null;

function parseBulkIssueItems() {
  const raw = $('bulkIssueItems').value.trim();
  if (!raw) throw new Error('Paste a JSON array of items first.');
  let items;
  try { items = JSON.parse(raw); }
  catch (e) { throw new Error('Items is not valid JSON: ' + e.message); }
  if (!Array.isArray(items) || items.length === 0) throw new Error('Items must be a non-empty JSON array.');
  return items;
}

function resetBulkIssuePlan() {
  bulkIssuePlan = null;
  $('bulkIssuePlanBox').classList.add('hidden');
  $('bulkIssueResultBox').classList.add('hidden');
  $('bulkIssueError').classList.add('hidden');
  $('bulkIssueConfirmCount').value = '';
  $('bulkIssueExecute').disabled = true;
  $('bulkIssueProgress').textContent = '';
}
$('issueCA').addEventListener('change', resetBulkIssuePlan);

$('bulkIssuePreview').onclick = async () => {
  const id = $('issueCA').value;
  if (!id) { showError($('bulkIssueError'), 'Select a CA first.'); return; }
  resetBulkIssuePlan();
  $('bulkIssuePreview').disabled = true;
  try {
    const items = parseBulkIssueItems();
    bulkIssuePlan = await api('POST', `/api/ca/${id}/certificates:bulk`, { dry_run: true, items });
    const p = bulkIssuePlan;
    const bits = [`<b>${p.valid}</b> of ${p.requested} item(s) will be issued`];
    if (p.need_approval) bits.push(`${p.need_approval} require manual approval and will be parked (fetch from Approvals once signed off)`);
    if (p.invalid) bits.push(`<span class="badge fail">${p.invalid} invalid</span> and will not be issued`);
    $('bulkIssuePlanSummary').innerHTML = bits.join('<br>');
    $('bulkIssuePlanRows').innerHTML = (p.items || []).map(it => `
      <tr>
        <td>${escapeHTML(it.ref)}</td>
        <td>${it.valid ? escapeHTML(it.subject || (it.sans || []).join(', ')) : '<span class="muted">' + escapeHTML(it.error || '') + '</span>'}</td>
        <td>${escapeHTML(it.profile || '')}</td>
        <td>${it.valid ? (it.requires_approval ? '<span class="badge warn">needs approval</span>' : '<span class="badge ok">ready</span>') : '<span class="badge fail">invalid</span>'}</td>
      </tr>`).join('') || emptyRow('No items.');
    $('bulkIssueExpectedCount').textContent = p.requested;
    $('bulkIssuePlanBox').classList.remove('hidden');
  } catch (e) { showError($('bulkIssueError'), e.message); }
  finally { $('bulkIssuePreview').disabled = false; }
};

// Arm only while the typed count equals the previewed item count.
$('bulkIssueConfirmCount').addEventListener('input', () => {
  const armed = bulkIssuePlan && bulkIssuePlan.requested > 0 &&
    $('bulkIssueConfirmCount').value.trim() === String(bulkIssuePlan.requested);
  $('bulkIssueExecute').disabled = !armed;
});

$('bulkIssueExecute').onclick = async () => {
  const id = $('issueCA').value;
  if (!id || !bulkIssuePlan) return;
  const confirmed = parseInt($('bulkIssueConfirmCount').value.trim(), 10);
  if (confirmed !== bulkIssuePlan.requested) return;
  $('bulkIssueExecute').disabled = true;
  $('bulkIssueProgress').textContent = `Issuing ${bulkIssuePlan.requested} certificate(s)…`;
  try {
    const items = parseBulkIssueItems();
    const result = await api('POST', `/api/ca/${id}/certificates:bulk`, {
      items, confirm_count: confirmed, operation_id: bulkIssuePlan.operation_id,
    });
    $('bulkIssueResultSummary').innerHTML =
      `Batch complete: <b>${result.issued}</b> issued, ${result.pending} pending approval, `
      + `${result.failed} failed of ${result.requested} `
      + `(${Number(result.duration_seconds || 0).toFixed(2)}s, operation <span class="mono">${escapeHTML(result.operation_id)}</span>)`;
    $('bulkIssueResultRows').innerHTML = (result.items || []).map(it => {
      let detail = '', badge = 'ok';
      if (it.status === 'issued') { detail = shortSerial(it.serial); }
      else if (it.status === 'pending') { detail = `approval ${escapeHTML(it.approval_id)} (needs ${it.required_approvals})`; badge = 'warn'; }
      else { detail = `[${escapeHTML(it.error_code || '')}] ${escapeHTML(it.error || '')}`; badge = 'fail'; }
      return `<tr><td>${escapeHTML(it.ref)}</td><td><span class="badge ${badge}">${escapeHTML(it.status)}</span></td><td class="mono">${detail}</td></tr>`;
    }).join('') || emptyRow('No items.');
    $('bulkIssueResultBox').classList.remove('hidden');
    $('bulkIssuePlanBox').classList.add('hidden');
    bulkIssuePlan = null;
    if (result.pending > 0) loadApprovals();
    if (selectedCertCA() === id) loadCerts();
  } catch (e) {
    showError($('bulkIssueError'), e.message);
    $('bulkIssuePlanBox').classList.add('hidden');
    bulkIssuePlan = null;
  } finally {
    $('bulkIssueProgress').textContent = '';
    $('bulkIssueConfirmCount').value = '';
  }
};

// ---- PKCS#12 export view -------------------------------------------------
// Split a comma-separated input into trimmed, non-empty values.
function csvList(v) {
  return (v || '').split(',').map(s => s.trim()).filter(Boolean);
}
$('p12Btn').onclick = async () => {
  const id = $('p12CA').value;
  const msg = $('p12Msg');
  msg.className = 'notice hidden';
  if (!id) { showError(msg, 'Select a CA.'); msg.className = 'notice err'; return; }
  const cn = $('p12CN').value.trim();
  const emails = csvList($('p12Emails').value);
  const dns = csvList($('p12DNS').value);
  if (!cn && !emails.length && !dns.length) {
    showError(msg, 'Provide a common name or at least one SAN.'); msg.className = 'notice err'; return;
  }
  const password = $('p12Password').value;
  if (password.length < 6) { showError(msg, 'Password must be at least 6 characters.'); msg.className = 'notice err'; return; }

  const body = {
    profile: $('p12Profile').value,
    common_name: cn,
    key_type: $('p12KeyType').value,
    encoder: $('p12Encoder').value,
    password,
    escrow: $('p12Escrow').checked,
  };
  const org = $('p12O').value.trim(); if (org) body.organization = org;
  if (emails.length) body.emails = emails;
  if (dns.length) body.dns_names = dns;
  const bits = parseInt($('p12KeyBits').value, 10); if (bits > 0) body.key_bits = bits;
  const days = parseInt($('p12Days').value, 10); if (days > 0) body.validity_days = days;

  $('p12Btn').disabled = true;
  try {
    const res = await api('POST', `/api/ca/${id}/pkcs12`, body);
    // Download the binary bundle (base64 DER -> bytes).
    const fname = (cn || res.serial || 'certificate').replace(/[^A-Za-z0-9._-]+/g, '_') + '.p12';
    downloadBlob(unb64(res.pkcs12), fname, 'application/x-pkcs12');

    let note = `Exported serial ${res.serial} (${res.profile}, ${res.key_type}, ${res.encoder}), valid until ${res.not_after}. Bundle downloaded as ${fname}.`;
    if (res.escrow) note += ` Subject key escrowed (${res.escrow.threshold}-of-${res.escrow.agents}).`;
    msg.textContent = note;
    msg.className = 'notice ok';

    $('p12Result').classList.remove('hidden');
    $('p12Chain').value = res.chain || '';
    if (res.escrow) {
      $('p12EscrowWrap').classList.remove('hidden');
      const env = JSON.stringify(res.escrow.envelope, null, 2);
      $('p12EscrowEnvelope').value = env;
      $('p12EscrowNote').textContent = `Recover with: secsy-secret recover -context "${res.escrow.context}" (quorum: ${res.escrow.threshold}-of-${res.escrow.agents}).`;
      $('p12EscrowDownload').onclick = (e) => {
        e.preventDefault();
        downloadBlob(env, `${res.serial}.escrow.json`, 'application/json');
      };
    } else {
      $('p12EscrowWrap').classList.add('hidden');
    }
    if (selectedCertCA() === id) loadCerts();
  } catch (e) {
    showError(msg, e.message); msg.className = 'notice err';
  } finally { $('p12Btn').disabled = false; }
};

// ---- Secrets view --------------------------------------------------------
// secretServiceEnabled tracks whether the secret layer (KEK) is configured, so
// the signing-keys panel (which shares the /api/secret/* gate) is shown and
// loaded only when the routes exist.
let secretServiceEnabled = false;
async function loadSecretInfo() {
  try {
    const info = await api('GET', '/api/secret/info');
    let text = `KEK ${info.kek_label} · ${info.provider} · ${info.key_bits}-bit · wrap ${info.wrap_alg} · data ${info.data_alg}`;
    if (info.escrow_available) {
      text += ` · escrow ${info.escrow_threshold}-of-${info.escrow_agents} recovery agents (recovery via secsy-secret recover, dual control)`;
      $('encEscrowLabel').classList.remove('hidden');
    } else {
      $('encEscrowLabel').classList.add('hidden');
    }
    $('secretInfo').textContent = text;
    $('secretDisabled').classList.add('hidden');
    secretServiceEnabled = true;
    if ($('sigKeysSection')) $('sigKeysSection').classList.remove('hidden');
    loadSigningKeys();
  } catch (e) {
    // 404 when the feature is disabled (routes not registered).
    $('secretDisabled').classList.remove('hidden');
    $('secretInfo').textContent = '';
    secretServiceEnabled = false;
    if ($('sigKeysSection')) $('sigKeysSection').classList.add('hidden');
  }
}

// ---- Secret-layer signing keys (Task 155) --------------------------------
// Named HSM-backed asymmetric keys on the secret layer: create a key, export
// its public half, and sign/verify arbitrary data. Every call is authorized,
// audited, and (for sign) metered server-side; the console only drives it.
async function loadSigningKeys() {
  const tbody = $('sigKeyRows');
  if (!tbody) return;
  try {
    const res = await api('GET', '/api/secret/signing-keys');
    const keys = res.signing_keys || [];
    if (!keys.length) { tbody.innerHTML = '<tr><td colspan="5" class="muted">No signing keys yet.</td></tr>'; return; }
    tbody.innerHTML = keys.map(k => `<tr>
      <td class="mono">${escapeHTML(k.name)}</td>
      <td>${escapeHTML(k.algorithm)}</td>
      <td>${escapeHTML(k.provider || '')}</td>
      <td>${fmtTime(k.created_at)}</td>
      <td><button class="btn ghost sm" data-sigkey="${escapeHTML(k.name)}" title="Use this key in Sign / verify">Use ▸</button>
          <button class="btn ghost sm" data-sigpub="${escapeHTML(k.name)}" title="Show / download the public key">Public key</button></td>
    </tr>`).join('');
    tbody.querySelectorAll('[data-sigkey]').forEach(b => b.onclick = () => { $('sigKeyName').value = b.dataset.sigkey; });
    tbody.querySelectorAll('[data-sigpub]').forEach(b => b.onclick = () => showSigningPublicKey(b.dataset.sigpub));
  } catch (e) {
    // Listing needs secret:signing-key; a plain signer (secret:sign) can still
    // sign/verify by typing a key name, so this is informational, not fatal.
    tbody.innerHTML = '<tr><td colspan="5" class="muted">Key listing needs the secret:signing-key capability. You can still sign/verify by entering a key name.</td></tr>';
  }
}

async function showSigningPublicKey(name) {
  try {
    const k = await api('GET', '/api/secret/signing-keys/' + encodeURIComponent(name));
    $('sigKeyPub').value = k.public_key_pem || '';
    $('sigKeyPubBox').classList.remove('hidden');
    const a = $('sigKeyPubDownload');
    a.onclick = (e) => { e.preventDefault(); downloadBlob(k.public_key_pem || '', name + '.pub.pem', 'application/x-pem-file'); };
  } catch (e) { alert('Public key export failed: ' + e.message); }
}

$('sigKeyCreateBtn').onclick = async () => {
  const err = $('sigKeysError');
  err.classList.add('hidden');
  const name = $('sigKeyNewName').value.trim();
  if (!name) { showError(err, 'A key name is required.'); return; }
  try {
    const k = await api('POST', '/api/secret/signing-keys', { name, algorithm: $('sigKeyNewAlg').value });
    $('sigKeyNewName').value = '';
    $('sigKeyPub').value = k.public_key_pem || '';
    $('sigKeyPubBox').classList.remove('hidden');
    $('sigKeyPubDownload').onclick = (e) => { e.preventDefault(); downloadBlob(k.public_key_pem || '', name + '.pub.pem', 'application/x-pem-file'); };
    $('sigKeyName').value = name;
    await loadSigningKeys();
  } catch (e) { showError(err, 'Create failed: ' + e.message); }
};

$('sigSignBtn').onclick = async () => {
  const err = $('sigError'); err.classList.add('hidden');
  const name = $('sigKeyName').value.trim();
  if (!name) { showError(err, 'A key name is required.'); return; }
  try {
    const body = { message: b64(new TextEncoder().encode($('sigMessage').value)) };
    if ($('sigHash').value) body.hash = $('sigHash').value;
    const res = await api('POST', `/api/secret/signing-keys/${encodeURIComponent(name)}/sign`, body);
    $('sigOut').value = res.signature;
    const el = $('sigVerifyResult');
    el.style.color = '';
    el.textContent = `signed · ${res.algorithm}${res.hash ? ' · ' + res.hash : ''}`;
  } catch (e) { showError(err, 'Sign failed: ' + e.message); }
};

$('sigVerifyBtn').onclick = async () => {
  const err = $('sigError'); err.classList.add('hidden');
  const name = $('sigKeyName').value.trim();
  if (!name) { showError(err, 'A key name is required.'); return; }
  const sig = $('sigOut').value.trim();
  if (!sig) { showError(err, 'A base64 signature is required — sign first, or paste one.'); return; }
  try {
    const body = { message: b64(new TextEncoder().encode($('sigMessage').value)), signature: sig };
    if ($('sigHash').value) body.hash = $('sigHash').value;
    const res = await api('POST', `/api/secret/signing-keys/${encodeURIComponent(name)}/verify`, body);
    const el = $('sigVerifyResult');
    el.style.color = res.valid ? 'var(--ok)' : 'var(--crit)';
    el.textContent = res.valid ? `✓ valid signature (${res.algorithm})` : '✗ INVALID — signature does not match';
  } catch (e) { showError(err, 'Verify failed: ' + e.message); }
};
$('encBtn').onclick = async () => {
  try {
    const pt = new TextEncoder().encode($('encPlain').value);
    const body = { plaintext: b64(pt) };
    if ($('encEscrow').checked) body.escrow = true;
    const ectx = $('encContext').value;
    if (ectx) body.context = b64(new TextEncoder().encode(ectx));
    const res = await api('POST', '/api/secret/encrypt', body);
    $('encOut').value = JSON.stringify(res.envelope, null, 2);
  } catch (e) { alert('Encrypt failed: ' + e.message); }
};
$('decBtn').onclick = async () => {
  try {
    const env = JSON.parse($('decEnv').value);
    const body = { envelope: env };
    const dctx = $('decContext').value;
    if (dctx) body.context = b64(new TextEncoder().encode(dctx));
    const res = await api('POST', '/api/secret/decrypt', body);
    $('decOut').value = new TextDecoder().decode(unb64(res.plaintext));
  } catch (e) { alert('Decrypt failed: ' + e.message); }
};

// ---- Stateless crypto service (Task 138) ---------------------------------
$('dkBtn').onclick = async () => {
  try {
    const body = { bits: parseInt($('dkBits').value, 10) };
    if ($('dkWrappedOnly').checked) body.wrapped_only = true;
    const dkctx = $('dkContext').value;
    if (dkctx) body.context = b64(new TextEncoder().encode(dkctx));
    const res = await api('POST', '/api/secret/datakey', body);
    let out = '';
    if (res.plaintext) out += 'data key (base64):\n' + res.plaintext + '\n\n';
    out += `wrapped under KEK ${res.kek_label} v${res.kek_version} — decrypt to recover:\n` +
           JSON.stringify(res.wrapped, null, 2);
    $('dkOut').value = out;
  } catch (e) { alert('Data key failed: ' + e.message); }
};
$('hmacGenBtn').onclick = async () => {
  try {
    const data = b64(new TextEncoder().encode($('hmacData').value));
    const res = await api('POST', '/api/secret/hmac', { data });
    $('hmacTag').value = res.hmac;
    $('hmacVer').value = res.version;
    const el = $('hmacResult');
    el.style.color = '';
    el.textContent = `${res.algorithm} · MAC key version ${res.version}`;
  } catch (e) { alert('HMAC generate failed: ' + e.message); }
};
$('hmacVerBtn').onclick = async () => {
  try {
    const body = { data: b64(new TextEncoder().encode($('hmacData').value)), hmac: $('hmacTag').value.trim() };
    const v = parseInt($('hmacVer').value, 10);
    if (!isNaN(v) && v > 0) body.version = v;
    const res = await api('POST', '/api/secret/hmac/verify', body);
    const el = $('hmacResult');
    el.style.color = res.valid ? 'var(--ok)' : 'var(--crit)';
    el.textContent = res.valid ? `✓ valid (MAC key version ${res.version})` : '✗ INVALID — tag does not match';
  } catch (e) { alert('HMAC verify failed: ' + e.message); }
};
$('rndBtn').onclick = async () => {
  try {
    const res = await api('POST', '/api/secret/random',
      { bytes: parseInt($('rndBytes').value, 10), format: $('rndFormat').value });
    $('rndOut').value = res.random;
    $('rndSource').textContent = `source: ${res.source}`;
  } catch (e) { alert('Random failed: ' + e.message); }
};

// ---- Tenant administration (Task 61) --------------------------------------
// Lifecycle (suspend/reactivate), per-tenant quotas, and the usage report.
// Everything is enforced server-side; this page is platform-admin territory
// (the list endpoint answers 403 for everyone else).
let tenants = [];
let quotaTarget = null;

// limitCell renders a quota value, where 0 means unlimited.
function limitCell(v) { return v > 0 ? String(v) : '∞'; }

async function loadTenants() {
  const rows = $('tenantRows');
  try {
    tenants = await api('GET', '/api/tenants');
    $('tenantsDenied').classList.add('hidden');
  } catch (e) {
    tenants = [];
    rows.innerHTML = '';
    showError($('tenantsDenied'), 'Listing tenants failed: ' + e.message);
    return;
  }
  if (!tenants.length) { rows.innerHTML = emptyRow('No tenants.'); return; }
  rows.innerHTML = tenants.map(t => {
    const q = t.quotas || {};
    const suspended = t.status === 'suspended';
    const rate = q.rate_limit_per_second > 0 ? `${q.rate_limit_per_second}/s ×${q.rate_limit_burst}` : 'default';
    const toggle = t.id === 'default' ? '' :
      `<button class="btn ${suspended ? '' : 'danger'} sm" data-act="${suspended ? 'activate' : 'suspend'}" data-id="${t.id}">${suspended ? 'Reactivate' : 'Suspend'}</button>`;
    return `<tr${suspended ? ' style="opacity:.6"' : ''}>
      <td>${escapeHTML(t.slug)}</td>
      <td>${escapeHTML(t.name)}</td>
      <td>${suspended ? '<span class="badge revoked">suspended</span>' : '<span class="badge ok">active</span>'}</td>
      <td>${limitCell(q.max_certs_per_day)}</td>
      <td>${limitCell(q.max_active_certs)}</td>
      <td>${limitCell(q.max_secret_ops_per_day)}</td>
      <td>${escapeHTML(rate)}</td>
      <td style="white-space:nowrap">
        <button class="btn ghost sm" data-act="usage" data-id="${t.id}">usage</button>
        <button class="btn ghost sm" data-act="quotas" data-id="${t.id}">quotas</button>
        ${toggle}
      </td>
    </tr>`;
  }).join('');
  rows.querySelectorAll('button[data-act]').forEach(b => {
    const t = tenants.find(x => x.id === b.dataset.id);
    if (!t) return;
    if (b.dataset.act === 'usage') b.onclick = () => loadTenantUsage(t);
    if (b.dataset.act === 'quotas') b.onclick = () => openQuotaModal(t);
    if (b.dataset.act === 'suspend' || b.dataset.act === 'activate') {
      b.onclick = () => setTenantStatus(t, b.dataset.act === 'suspend' ? 'suspended' : 'active');
    }
  });
}
$('refreshTenants').onclick = loadTenants;

async function setTenantStatus(t, status) {
  if (status === 'suspended' &&
      !confirm(`Suspend tenant "${t.slug}"?\n\nAll enrollment (ACME/SCEP/EST/CMP/gRPC/REST/SSH) and secret operations will be refused. OCSP/CRL for its existing certificates keep working, and revocation stays possible.`)) {
    return;
  }
  try {
    await api('PUT', `/api/tenants/${encodeURIComponent(t.id)}/status`, { status });
    await loadTenants();
  } catch (e) {
    showError($('globalError'), `Updating tenant ${t.slug}: ${e.message}`);
  }
}

$('tenantCreateBtn').onclick = async () => {
  const err = $('tenantCreateError');
  err.classList.add('hidden');
  const body = {
    slug: $('tenantSlug').value.trim(),
    name: $('tenantName').value.trim(),
    kek_label: $('tenantKEK').value.trim(),
  };
  if (!body.slug) { showError(err, 'A slug is required.'); return; }
  try {
    await api('POST', '/api/tenants', body);
    $('tenantSlug').value = $('tenantName').value = $('tenantKEK').value = '';
    await loadTenants();
  } catch (e) { showError(err, e.message); }
};

function openQuotaModal(t) {
  quotaTarget = t;
  const q = t.quotas || {};
  $('quotaTenantLabel').textContent = t.slug;
  $('quotaCertsDay').value = q.max_certs_per_day || 0;
  $('quotaActive').value = q.max_active_certs || 0;
  $('quotaSecretOps').value = q.max_secret_ops_per_day || 0;
  $('quotaRate').value = q.rate_limit_per_second || 0;
  $('quotaBurst').value = q.rate_limit_burst || 0;
  $('quotaError').classList.add('hidden');
  $('quotaModal').classList.remove('hidden');
}
$('quotaCancel').onclick = () => { $('quotaModal').classList.add('hidden'); quotaTarget = null; };
$('quotaSave').onclick = async () => {
  if (!quotaTarget) return;
  const num = (id) => { const v = Number($(id).value); return isFinite(v) && v >= 0 ? v : 0; };
  const quotas = {
    max_certs_per_day: Math.floor(num('quotaCertsDay')),
    max_active_certs: Math.floor(num('quotaActive')),
    max_secret_ops_per_day: Math.floor(num('quotaSecretOps')),
    rate_limit_per_second: num('quotaRate'),
    rate_limit_burst: num('quotaBurst'),
  };
  try {
    await api('PUT', `/api/tenants/${encodeURIComponent(quotaTarget.id)}`, { quotas });
    $('quotaModal').classList.add('hidden');
    quotaTarget = null;
    await loadTenants();
  } catch (e) { showError($('quotaError'), e.message); }
};

async function loadTenantUsage(t) {
  $('usageTenantLabel').textContent = '— ' + t.slug;
  try {
    const u = await api('GET', `/api/tenants/${encodeURIComponent(t.id)}/usage?days=14`);
    $('tenantUsageEmpty').classList.add('hidden');
    $('tenantUsageBox').classList.remove('hidden');
    const q = u.quotas || {};
    const cap = (v, max) => max > 0 ? `${v} / ${max}` : String(v);
    $('tenantUsageSummary').innerHTML =
      `CAs: <b>${u.cas}</b> &nbsp; active certs: <b>${escapeHTML(cap(u.active_certs, q.max_active_certs))}</b> ` +
      `&nbsp; issued (lifetime): <b>${u.total_issued}</b> &nbsp; revoked: <b>${u.total_revoked}</b> ` +
      `&nbsp; <span class="muted">as of ${escapeHTML(fmtTime(u.generated_at))}</span>`;
    $('tenantUsageRows').innerHTML = (u.days || []).map(d => `<tr>
      <td>${escapeHTML(d.day)}</td>
      <td>${escapeHTML(cap(d.certs_issued, q.max_certs_per_day))}</td>
      <td>${d.certs_revoked}</td>
      <td>${escapeHTML(cap(d.secret_ops, q.max_secret_ops_per_day))}</td>
    </tr>`).join('') || emptyRow('No usage recorded.');
  } catch (e) {
    $('tenantUsageEmpty').classList.remove('hidden');
    $('tenantUsageBox').classList.add('hidden');
    $('tenantUsageEmpty').textContent = 'Usage unavailable: ' + e.message;
  }
}

// ---- API tokens / service accounts (Task 86) -------------------------------
async function loadTokens() {
  const rows = $('tokenRows');
  let tokens;
  try {
    tokens = await api('GET', '/api/tokens');
    $('tokensDenied').classList.add('hidden');
  } catch (e) {
    rows.innerHTML = '';
    showError($('tokensDenied'), 'Listing tokens failed: ' + e.message);
    return;
  }
  if (!tokens.length) { rows.innerHTML = '<tr><td colspan="9" class="muted">No API tokens.</td></tr>'; return; }
  const badge = (s) => s === 'active' ? '<span class="badge ok">active</span>'
    : `<span class="badge revoked">${escapeHTML(s)}</span>`;
  rows.innerHTML = tokens.map(t => {
    const active = (t.status || tokenStatus(t)) === 'active';
    return `<tr${active ? '' : ' style="opacity:.6"'}>
      <td>${escapeHTML(t.name)}</td>
      <td>${escapeHTML(t.scope)}</td>
      <td>${escapeHTML(t.tenant_id)}</td>
      <td>${escapeHTML((t.roles || []).join(', '))}</td>
      <td>${badge(t.status || tokenStatus(t))}</td>
      <td>${t.expires_at ? escapeHTML(fmtTime(t.expires_at)) : 'never'}</td>
      <td>${t.last_used_at ? escapeHTML(fmtTime(t.last_used_at)) : '—'}</td>
      <td><code>${escapeHTML(t.prefix || '')}</code></td>
      <td style="white-space:nowrap">${active ? `<button class="btn danger sm" data-id="${t.id}">Revoke</button>` : ''}</td>
    </tr>`;
  }).join('');
  rows.querySelectorAll('button[data-id]').forEach(b => {
    const t = tokens.find(x => x.id === b.dataset.id);
    b.onclick = () => revokeToken(t);
  });
}
$('refreshTokens').onclick = loadTokens;

// tokenStatus derives a lifecycle label if the server did not send one.
function tokenStatus(t) {
  if (t.revoked_at) return 'revoked';
  if (t.expires_at && new Date(t.expires_at) <= new Date()) return 'expired';
  return 'active';
}

async function revokeToken(t) {
  if (!confirm(`Revoke API token "${t.name}"?\n\nAny caller using it will immediately fail authentication.`)) return;
  try {
    await api('DELETE', `/api/tokens/${encodeURIComponent(t.id)}`);
    await loadTokens();
  } catch (e) { showError($('globalError'), `Revoking token ${t.name}: ${e.message}`); }
}

$('tokenCreateBtn').onclick = async () => {
  const err = $('tokenCreateError');
  err.classList.add('hidden');
  const roles = Array.from($('tokenRoles').querySelectorAll('input:checked')).map(c => c.value);
  if (!$('tokenName').value.trim()) { showError(err, 'A name is required.'); return; }
  if (!roles.length) { showError(err, 'Select at least one role.'); return; }
  const body = {
    name: $('tokenName').value.trim(),
    roles,
    scope: $('tokenScope').value,
    description: $('tokenDesc').value.trim(),
  };
  const tenant = $('tokenTenant').value.trim();
  if (body.scope === 'tenant' && tenant) body.tenant_id = tenant;
  const days = parseInt($('tokenExpires').value, 10);
  if (!isNaN(days) && days > 0) body.expires_in_days = days;
  try {
    const res = await api('POST', '/api/tokens', body, true); // raw: create may 202 (approval) or 201
    let created;
    try { created = JSON.parse(res); } catch (_) { created = {}; }
    if (!created.secret) {
      // A 202 (four-eyes) has no body/secret; surface the pending-approval note.
      showError(err, 'Held for four-eyes approval — an approver must sign off, then re-submit. See the Approvals page.');
      await loadTokens();
      return;
    }
    revealTokenSecret(created);
    // Reset the form.
    $('tokenName').value = $('tokenTenant').value = $('tokenDesc').value = $('tokenExpires').value = '';
    $('tokenRoles').querySelectorAll('input:checked').forEach(c => { c.checked = false; });
    await loadTokens();
  } catch (e) { showError(err, e.message); }
};

function revealTokenSecret(tok) {
  $('tokenSecretEmpty').classList.add('hidden');
  $('tokenSecretBox').classList.remove('hidden');
  $('tokenSecretMeta').textContent = `${tok.name} — ${tok.scope} scope, roles: ${(tok.roles || []).join(', ')}`;
  $('tokenSecretValue').value = tok.secret;
}
$('tokenSecretCopy').onclick = async () => {
  const v = $('tokenSecretValue');
  v.select();
  try { await navigator.clipboard.writeText(v.value); } catch (_) { document.execCommand('copy'); }
  $('tokenSecretCopy').textContent = 'Copied';
  setTimeout(() => { $('tokenSecretCopy').textContent = 'Copy'; }, 1500);
};

// ---- Outbound Webhooks view (Task 116) -------------------------------------
// Durable subscriptions delivering signed certificate lifecycle events.
async function loadWebhooks() {
  const rows = $('webhookRows');
  let webhooks;
  try {
    webhooks = await api('GET', '/api/webhooks');
    $('webhooksDenied').classList.add('hidden');
  } catch (e) {
    rows.innerHTML = '';
    showError($('webhooksDenied'), 'Listing webhooks failed: ' + e.message);
    return;
  }
  if (!webhooks.length) { rows.innerHTML = '<tr><td colspan="6" class="muted">No webhook subscriptions.</td></tr>'; return; }
  rows.innerHTML = webhooks.map(w => {
    const events = (w.event_types && w.event_types.length) ? w.event_types.join(', ') : 'all';
    const badge = w.enabled ? '<span class="badge ok">enabled</span>' : '<span class="badge revoked">disabled</span>';
    const toggle = w.enabled
      ? `<button class="btn ghost sm" data-act="disable" data-id="${w.id}">Disable</button>`
      : `<button class="btn ghost sm" data-act="enable" data-id="${w.id}">Enable</button>`;
    return `<tr${w.enabled ? '' : ' style="opacity:.6"'}>
      <td><code>${escapeHTML(w.url)}</code></td>
      <td>${escapeHTML(w.scope)}</td>
      <td>${escapeHTML(w.tenant_id)}</td>
      <td>${escapeHTML(events)}</td>
      <td>${badge}</td>
      <td style="white-space:nowrap">
        <button class="btn ghost sm" data-act="test" data-id="${w.id}">Test</button>
        <button class="btn ghost sm" data-act="deliveries" data-id="${w.id}">Deliveries</button>
        ${toggle}
        <button class="btn danger sm" data-act="delete" data-id="${w.id}">Delete</button>
      </td>
    </tr>`;
  }).join('');
  rows.querySelectorAll('button[data-id]').forEach(b => {
    const w = webhooks.find(x => x.id === b.dataset.id);
    b.onclick = () => webhookAction(b.dataset.act, w);
  });
}
$('refreshWebhooks').onclick = loadWebhooks;

async function webhookAction(act, w) {
  try {
    if (act === 'delete') {
      if (!confirm(`Delete webhook ${w.url}?\n\nIts delivery history is removed too.`)) return;
      await api('DELETE', `/api/webhooks/${encodeURIComponent(w.id)}`);
      await loadWebhooks();
    } else if (act === 'enable' || act === 'disable') {
      await api('POST', `/api/webhooks/${encodeURIComponent(w.id)}/${act}`);
      await loadWebhooks();
    } else if (act === 'test') {
      const res = await api('POST', `/api/webhooks/${encodeURIComponent(w.id)}/test`, {});
      const note = res && res.worker_enabled === false
        ? ' (queued, but the delivery worker is disabled — enable webhook.enabled to send)'
        : ' — check Deliveries for the outcome';
      alert(`Test delivery queued for ${w.url}${note}.`);
      await showWebhookDeliveries(w);
    } else if (act === 'deliveries') {
      await showWebhookDeliveries(w);
    }
  } catch (e) {
    showError($('globalError'), `Webhook ${act}: ${e.message}`);
  }
}

async function showWebhookDeliveries(w) {
  const box = $('webhookDeliveries');
  box.innerHTML = '<div class="muted">Loading deliveries…</div>';
  let deliveries;
  try {
    deliveries = await api('GET', `/api/webhooks/${encodeURIComponent(w.id)}/deliveries?limit=50`);
  } catch (e) {
    box.innerHTML = `<div class="notice err">Loading deliveries failed: ${escapeHTML(e.message)}</div>`;
    return;
  }
  if (!deliveries.length) {
    box.innerHTML = `<h2 style="font-size:14px">Deliveries — ${escapeHTML(w.url)}</h2><div class="muted">No deliveries yet.</div>`;
    return;
  }
  const badge = (s) => s === 'delivered' ? '<span class="badge ok">delivered</span>'
    : s === 'dead' ? '<span class="badge revoked">dead</span>'
    : `<span class="badge">${escapeHTML(s)}</span>`;
  box.innerHTML = `<h2 style="font-size:14px">Deliveries — ${escapeHTML(w.url)}</h2>
    <table><thead><tr><th>Event</th><th>Status</th><th>Attempts</th><th>Code</th><th>Last error</th></tr></thead>
    <tbody>${deliveries.map(d => `<tr>
      <td>${escapeHTML(d.event_type)}</td>
      <td>${badge(d.status)}</td>
      <td>${d.attempts}/${d.max_attempts}</td>
      <td>${d.last_status_code || '—'}</td>
      <td>${escapeHTML(d.last_error || '')}</td>
    </tr>`).join('')}</tbody></table>`;
}

$('webhookCreateBtn').onclick = async () => {
  const err = $('webhookCreateError');
  err.classList.add('hidden');
  const url = $('webhookURL').value.trim();
  if (!url) { showError(err, 'An endpoint URL is required.'); return; }
  const events = Array.from($('webhookEvents').querySelectorAll('input:checked')).map(c => c.value);
  const body = {
    url,
    event_types: events,
    scope: $('webhookScope').value,
    description: $('webhookDesc').value.trim(),
  };
  const tenant = $('webhookTenant').value.trim();
  if (body.scope === 'tenant' && tenant) body.tenant_id = tenant;
  const secret = $('webhookSecret').value.trim();
  if (secret) body.secret = secret;
  try {
    const created = await api('POST', '/api/webhooks', body);
    revealWebhookSecret(created);
    $('webhookURL').value = $('webhookTenant').value = $('webhookDesc').value = $('webhookSecret').value = '';
    $('webhookEvents').querySelectorAll('input:checked').forEach(c => { c.checked = false; });
    await loadWebhooks();
  } catch (e) { showError(err, e.message); }
};

function revealWebhookSecret(w) {
  $('webhookSecretEmpty').classList.add('hidden');
  $('webhookSecretBox').classList.remove('hidden');
  const events = (w.event_types && w.event_types.length) ? w.event_types.join(', ') : 'all events';
  $('webhookSecretMeta').textContent = `${w.url} — ${w.scope} scope, ${events}`;
  $('webhookSecretValue').value = w.secret || '';
}
$('webhookSecretCopy').onclick = async () => {
  const v = $('webhookSecretValue');
  v.select();
  try { await navigator.clipboard.writeText(v.value); } catch (_) { document.execCommand('copy'); }
  $('webhookSecretCopy').textContent = 'Copied';
  setTimeout(() => { $('webhookSecretCopy').textContent = 'Copy'; }, 1500);
};

// ---- Authorities view (Task 62: CLI parity) --------------------------------
// CA lifecycle: create roots/intermediates, rotate/retire intermediate signing
// keys, cross-sign, and the HSM key inventory. Everything is RBAC-gated
// server-side (ca:manage / hsm:manage); high-risk calls may demand step-up.
let rotationByCA = {}; // ca id -> RotationStatus (only CAs in a lineage)

$('casRefresh').onclick = loadAuthorities;

async function loadAuthorities() {
  const tbody = $('casRows');
  tbody.innerHTML = '<tr><td colspan="7" class="muted">Loading…</td></tr>';
  try { await loadCAs(); } catch (e) { tbody.innerHTML = emptyRow(e.message); return; }
  rotationByCA = {};
  try {
    const rep = await api('GET', '/api/rotations');
    (rep.rotations || []).forEach(r => { if (r.ca) rotationByCA[r.ca.id] = r; });
  } catch (_) { /* rotation list is read-gated; table still renders */ }

  // The table shows every X.509 authority plus pending externally-signed CAs
  // (key + CSR emitted, certificate not imported yet).
  const authorities = cas.filter(c => c.certificate || c.status === 'pending');
  if (!authorities.length) { tbody.innerHTML = emptyRow('No CAs yet — create a root below.'); }
  else {
    tbody.innerHTML = authorities.map(c => {
      const external = !c.parent_id && !!c.csr;
      const kind = c.parent_id ? 'intermediate' : (external ? 'external sub' : 'root');
      const status = c.status || 'active';
      const rot = rotationByCA[c.id];
      let statusCell = `<span class="badge ${status === 'active' ? 'valid' : (status === 'retired' ? 'revoked' : 'warning')}">${status}</span>`;
      if (rot && status === 'superseded') {
        statusCell += rot.safe_to_retire
          ? ' <span class="muted">drained</span>'
          : ` <span class="muted">${rot.outstanding_leaves} leaves outstanding</span>`;
      }
      if (status === 'pending') {
        statusCell += ' <span class="muted">awaiting external signature</span>';
      }
      const actions = [];
      if (kind === 'intermediate' && status === 'active') {
        actions.push(`<button class="btn ghost sm" data-act="rotate" data-id="${c.id}">Rotate key</button>`);
      }
      if (status === 'superseded') {
        actions.push(`<button class="btn danger sm" data-act="retire" data-id="${c.id}">Retire</button>`);
      }
      if (external) {
        actions.push(`<button class="btn ghost sm" data-act="csr" data-id="${c.id}">CSR</button>`);
        actions.push(`<button class="btn ghost sm" data-act="import" data-id="${c.id}">${status === 'pending' ? 'Import cert' : 'Re-import'}</button>`);
      }
      if (c.certificate) {
        actions.push(`<a class="btn ghost sm" href="/api/ca/${c.id}/chain" target="_blank">Chain</a>`);
      }
      return `<tr${status !== 'active' ? ' style="opacity:.65"' : ''}>
        <td>${escapeHTML(c.label)}</td>
        <td title="${escapeHTML(c.subject || '')}">${escapeHTML(shortName(c.subject))}</td>
        <td>${escapeHTML(c.key_type || '')}</td>
        <td>${kind}</td>
        <td>${statusCell}</td>
        <td>${fmtTime(c.not_after)}</td>
        <td style="white-space:nowrap">${actions.join(' ')}</td>
      </tr>`;
    }).join('');
    tbody.querySelectorAll('button[data-act]').forEach(b => {
      if (b.dataset.act === 'rotate') b.onclick = () => openRotateModal(b.dataset.id);
      if (b.dataset.act === 'retire') b.onclick = () => openRetireModal(b.dataset.id);
      if (b.dataset.act === 'csr') b.onclick = () => downloadExternalCSR(b.dataset.id);
      if (b.dataset.act === 'import') b.onclick = () => openImportCertModal(b.dataset.id);
    });
  }
  loadKeyInventory();
}

// -- create root / intermediate --
$('rootCreateBtn').onclick = async () => {
  const err = $('rootCreateError');
  err.classList.add('hidden');
  const body = {
    label: $('rootLabel').value.trim(),
    key_type: $('rootKeyType').value,
    subject: { cn: $('rootCN').value.trim(), o: $('rootO').value.trim() },
    validity_days: parseInt($('rootDays').value, 10) || 0,
  };
  if ($('rootPathLen').value !== '') body.max_path_len = parseInt($('rootPathLen').value, 10);
  if (!body.label || !body.subject.cn) { showError(err, 'A label and a common name are required.'); return; }
  $('rootCreateBtn').disabled = true;
  try {
    const ca = await api('POST', '/api/ca/init-root', body);
    notice($('casMsg'), 'ok', `Root CA "${ca.label}" created — key generated inside the HSM.`);
    $('rootLabel').value = $('rootCN').value = $('rootO').value = '';
    await loadAuthorities();
  } catch (e) { showError(err, e.message); }
  finally { $('rootCreateBtn').disabled = false; }
};

$('interCreateBtn').onclick = async () => {
  const err = $('interCreateError');
  err.classList.add('hidden');
  const parent = $('interParent').value;
  const body = {
    label: $('interLabel').value.trim(),
    key_type: $('interKeyType').value,
    subject: { cn: $('interCN').value.trim(), o: $('interO').value.trim() },
    validity_days: parseInt($('interDays').value, 10) || 0,
  };
  if ($('interPathLen').value !== '') body.max_path_len = parseInt($('interPathLen').value, 10);
  if (!parent) { showError(err, 'Select a parent CA.'); return; }
  if (!body.label || !body.subject.cn) { showError(err, 'A label and a common name are required.'); return; }
  $('interCreateBtn').disabled = true;
  try {
    const ca = await api('POST', `/api/ca/${parent}/issue-intermediate`, body);
    notice($('casMsg'), 'ok', `Intermediate CA "${ca.label}" issued under ${caLabel(parent)}.`);
    $('interLabel').value = $('interCN').value = $('interO').value = '';
    await loadAuthorities();
  } catch (e) { showError(err, e.message); }
  finally { $('interCreateBtn').disabled = false; }
};

// -- externally-signed subordinate CA (offline/third-party root) --
$('extCsrBtn').onclick = async () => {
  const err = $('extCsrError');
  err.classList.add('hidden');
  const body = {
    label: $('extLabel').value.trim(),
    key_type: $('extKeyType').value,
    subject: { cn: $('extCN').value.trim(), o: $('extO').value.trim() },
  };
  if ($('extPathLen').value !== '') body.max_path_len = parseInt($('extPathLen').value, 10);
  if (!body.label || !body.subject.cn) { showError(err, 'A label and a common name are required.'); return; }
  $('extCsrBtn').disabled = true;
  try {
    const res = await api('POST', '/api/ca/csr', body);
    notice($('casMsg'), 'ok',
      `Key for "${res.ca.label}" generated inside the HSM; the CA is pending until the signed certificate is imported. `
      + `Submit the downloaded CSR to the external parent for signing.`);
    downloadBlob(res.csr_pem, `${res.ca.label}.csr.pem`, 'application/x-pem-file');
    $('extLabel').value = $('extCN').value = $('extO').value = '';
    await loadAuthorities();
  } catch (e) { showError(err, e.message); }
  finally { $('extCsrBtn').disabled = false; }
};

async function downloadExternalCSR(caID) {
  try {
    const pem = await api('GET', `/api/ca/${caID}/csr`, undefined, true);
    downloadBlob(pem, `${caLabel(caID)}.csr.pem`, 'application/x-pem-file');
  } catch (e) { notice($('casMsg'), 'err', e.message); }
}

let importTarget = null;
function openImportCertModal(caID) {
  importTarget = caID;
  const ca = cas.find(c => c.id === caID);
  $('importCALabel').textContent = caLabel(caID);
  $('importError').classList.add('hidden');
  $('importCertPEM').value = '';
  $('importChainPEM').value = '';
  $('importReplace').checked = false;
  // Replace only applies once a certificate is installed (external renewal).
  $('importReplaceRow').classList.toggle('hidden', !ca || ca.status === 'pending');
  $('importCertModal').classList.remove('hidden');
}
$('importCancel').onclick = () => { $('importCertModal').classList.add('hidden'); importTarget = null; };
$('importConfirm').onclick = async () => {
  if (!importTarget) return;
  const body = { certificate_pem: $('importCertPEM').value.trim() };
  if (!body.certificate_pem) { showError($('importError'), 'Paste the signed CA certificate (PEM).'); return; }
  if ($('importChainPEM').value.trim()) body.chain_pem = $('importChainPEM').value.trim();
  if ($('importReplace').checked) body.replace = true;
  $('importConfirm').disabled = true;
  try {
    const res = await api('POST', `/api/ca/${importTarget}/import-cert`, body);
    $('importCertModal').classList.add('hidden');
    importTarget = null;
    const warn = (res.warnings || []).length ? ` Warnings: ${res.warnings.join(' • ')}` : '';
    notice($('casMsg'), (res.warnings || []).length ? 'warn' : 'ok',
      `Imported certificate for "${res.ca.label}" — the CA is now active and its served chain includes the external parent(s).${warn}`);
    downloadBlob(res.chain_pem, `${res.ca.label}-chain.pem`, 'application/x-pem-file');
    await loadAuthorities();
  } catch (e) { showError($('importError'), e.message); }
  finally { $('importConfirm').disabled = false; }
};

// -- rotate / retire modals --
let rotateTarget = null;
function openRotateModal(caID) {
  rotateTarget = caID;
  $('rotateCALabel').textContent = caLabel(caID);
  $('rotateError').classList.add('hidden');
  $('rotateNewLabel').value = '';
  $('rotateKeyType').value = '';
  $('rotateDays').value = '';
  $('rotateModal').classList.remove('hidden');
}
$('rotateCancel').onclick = () => { $('rotateModal').classList.add('hidden'); rotateTarget = null; };
$('rotateConfirm').onclick = async () => {
  if (!rotateTarget) return;
  const body = {};
  if ($('rotateNewLabel').value.trim()) body.new_label = $('rotateNewLabel').value.trim();
  if ($('rotateKeyType').value) body.key_type = $('rotateKeyType').value;
  const days = parseInt($('rotateDays').value, 10);
  if (days > 0) body.validity_days = days;
  $('rotateConfirm').disabled = true;
  try {
    const res = await api('POST', `/api/ca/${rotateTarget}/rotate`, body);
    $('rotateModal').classList.add('hidden');
    rotateTarget = null;
    const until = res.retire_after ? ` The old key can be retired after ${fmtTime(res.retire_after)} (once its leaves drain).` : '';
    notice($('casMsg'), 'ok',
      `Rotated: new key "${res.new_ca.label}" is now the active issuer; "${res.old_ca.label}" is superseded and keeps validating its leaves.${until} `
      + `Publish the combined overlap chain to relying parties.`);
    downloadBlob(res.combined_chain_pem, 'combined-chain.pem', 'application/x-pem-file');
    await loadAuthorities();
  } catch (e) { showError($('rotateError'), e.message); }
  finally { $('rotateConfirm').disabled = false; }
};

let retireTarget = null;
async function openRetireModal(caID) {
  retireTarget = caID;
  $('retireCALabel').textContent = caLabel(caID);
  $('retireError').classList.add('hidden');
  $('retireForce').checked = false;
  $('retireReason').value = 'cessationOfOperation';
  const rot = rotationByCA[caID];
  $('retireInfo').textContent = rot && !rot.safe_to_retire
    ? `${rot.outstanding_leaves} leaves signed by this key are still valid — retiring now requires force and will break their chains.`
    : 'No outstanding leaves remain: the key can be retired safely. Its certificate is revoked under the parent and the parent CRL refreshed.';
  $('retireModal').classList.remove('hidden');
}
$('retireCancel').onclick = () => { $('retireModal').classList.add('hidden'); retireTarget = null; };
$('retireConfirm').onclick = async () => {
  if (!retireTarget) return;
  $('retireConfirm').disabled = true;
  try {
    const res = await api('POST', `/api/ca/${retireTarget}/retire`, {
      reason: $('retireReason').value,
      force: $('retireForce').checked,
    });
    $('retireModal').classList.add('hidden');
    retireTarget = null;
    notice($('casMsg'), 'ok',
      `Retired "${res.retired_ca.label}": its certificate (serial ${shortSerial(res.revoked_serial)}) is revoked under the parent and the parent CRL was refreshed.`);
    await loadAuthorities();
  } catch (e) { showError($('retireError'), e.message); }
  finally { $('retireConfirm').disabled = false; }
};

// -- cross-signing --
$('crossSignBtn').onclick = async () => {
  const err = $('crossSignError');
  err.classList.add('hidden');
  $('csResultBox').classList.add('hidden');
  const issuer = $('csIssuer').value;
  if (!issuer) { showError(err, 'Select an issuer CA.'); return; }
  const body = {};
  const subjectCA = $('csSubject').value;
  const pemText = $('csPEM').value.trim();
  if (subjectCA) {
    body.subject_ca_id = subjectCA;
  } else if (/BEGIN CERTIFICATE REQUEST/.test(pemText)) {
    body.csr_pem = pemText;
  } else if (/BEGIN CERTIFICATE/.test(pemText)) {
    body.certificate_pem = pemText;
  } else {
    showError(err, 'Select a subject CA or paste an external certificate/CSR (PEM).');
    return;
  }
  const days = parseInt($('csDays').value, 10);
  if (days > 0) body.validity_days = days;
  $('crossSignBtn').disabled = true;
  try {
    const res = await api('POST', `/api/ca/${issuer}/cross-signs`, body);
    $('csResult').value = (res.chain_pem || res.certificate_pem || '');
    $('csResultBox').classList.remove('hidden');
    notice($('casMsg'), 'ok', `Cross-signed ${res.cross_sign.subject} under ${caLabel(issuer)} — alternate chain ready.`);
    if ($('csListCA').value === issuer || $('csListCA').value === subjectCA) loadCrossSigns();
  } catch (e) { showError(err, e.message); }
  finally { $('crossSignBtn').disabled = false; }
};

$('csListRefresh').onclick = loadCrossSigns;
async function loadCrossSigns() {
  const id = $('csListCA').value;
  const tbody = $('csRows');
  if (!id) { tbody.innerHTML = emptyRow('Select a CA and load.'); return; }
  tbody.innerHTML = '<tr><td colspan="6" class="muted">Loading…</td></tr>';
  try {
    const rep = await api('GET', `/api/ca/${id}/cross-signs`);
    const list = rep.cross_signs || [];
    tbody.innerHTML = list.length ? list.map(cs => `
      <tr>
        <td title="${escapeHTML(cs.subject || '')}">${escapeHTML(shortName(cs.subject))}</td>
        <td>${escapeHTML(caLabel(cs.issuer_ca_id))}</td>
        <td>${escapeHTML(cs.source || '')}</td>
        <td>${fmtTime(cs.not_after)}</td>
        <td><span class="badge ${cs.status === 'active' ? 'valid' : 'revoked'}">${escapeHTML(cs.status || '')}</span></td>
        <td><a class="btn ghost sm" href="/api/ca/${id}/cross-signs/${cs.id}/chain" target="_blank">Chain</a></td>
      </tr>`).join('') : emptyRow('No cross-signs for this CA.');
  } catch (e) { tbody.innerHTML = emptyRow(e.message); }
}

// -- HSM key inventory --
async function loadKeyInventory() {
  const tbody = $('keyInvRows');
  const note = $('keyInvNote');
  try {
    const inv = await api('GET', '/api/inventory/keys');
    note.textContent = `Provider ${inv.provider} · ${inv.keys.length} key(s) · `
      + (inv.extractable_count ? `⚠ ${inv.extractable_count} extractable` : 'none extractable')
      + (inv.unbound_count ? ` · ${inv.unbound_count} not bound to a CA (KEK/TSA/signing keys)` : '');
    tbody.innerHTML = inv.keys.length ? inv.keys.map(k => `
      <tr>
        <td class="mono">${escapeHTML(k.label)}</td>
        <td>${escapeHTML(k.key_type || '')}</td>
        <td>${k.extractable ? '<span class="badge fail">YES</span>' : '<span class="badge pass">no</span>'}</td>
        <td>${k.sensitive ? 'yes' : 'no'}</td>
        <td>${escapeHTML(k.ca_label || '—')}</td>
      </tr>`).join('') : emptyRow('No keys on the provider.');
  } catch (e) {
    // 403 for non-admins, 501 when the provider cannot enumerate keys.
    note.textContent = '';
    tbody.innerHTML = emptyRow('Key inventory unavailable: ' + e.message);
  }
}

// notice paints a dismissible status banner.
function notice(el, cls, msg) {
  el.textContent = msg;
  el.className = 'notice ' + cls;
}

// ---- SSH CA view (Task 62: CLI parity) --------------------------------------
let sshCAs = [];
let sshProfiles = [];

$('sshRefresh').onclick = loadSSH;
$('sshCA').onchange = () => { updateSSHLinks(); loadSSHCerts(); };
$('sshCertType').onchange = renderSSHProfileOptions;

async function loadSSH() {
  try {
    sshCAs = await api('GET', '/api/ssh/cas');
  } catch (e) {
    notice($('sshMsg'), 'err', 'Listing SSH CAs failed: ' + e.message);
    return;
  }
  $('sshCA').innerHTML = sshCAs.length
    ? sshCAs.map(c => `<option value="${c.id}">${escapeHTML(c.label)}</option>`).join('')
    : '<option value="">— no SSH CAs —</option>';
  try {
    sshProfiles = await api('GET', '/api/ssh/profiles');
    renderSSHProfileOptions();
  } catch (_) { /* read-gated */ }
  updateSSHLinks();
  loadSSHCerts();
}

function renderSSHProfileOptions() {
  const type = $('sshCertType').value;
  const list = sshProfiles.filter(p => !p.cert_type || p.cert_type === type);
  $('sshProfile').innerHTML = '<option value="">default for type</option>' + list.map(p =>
    `<option value="${p.name}">${escapeHTML(p.name)}${p.max_validity_secs ? ` (max ${fmtDuration(p.max_validity_secs)})` : ''}</option>`).join('');
}

function updateSSHLinks() {
  const id = $('sshCA').value;
  const pub = $('sshPubLink'), krl = $('sshKRLLink');
  if (id) {
    pub.href = `/api/ssh/cas/${id}/public`; pub.classList.remove('hidden');
    krl.href = `/api/ssh/cas/${id}/krl`; krl.classList.remove('hidden');
  } else { pub.classList.add('hidden'); krl.classList.add('hidden'); }
}

$('sshCreateBtn').onclick = async () => {
  const err = $('sshCreateError');
  err.classList.add('hidden');
  const label = $('sshCALabel').value.trim();
  if (!label) { showError(err, 'A label is required.'); return; }
  $('sshCreateBtn').disabled = true;
  try {
    const ca = await api('POST', '/api/ssh/cas', { label, key_type: $('sshCAKeyType').value });
    notice($('sshMsg'), 'ok', `SSH CA "${ca.label}" created. Install its public key as the trust anchor (TrustedUserCAKeys / @cert-authority).`);
    $('sshCALabel').value = '';
    await loadSSH();
    $('sshCA').value = ca.id;
    updateSSHLinks();
    loadSSHCerts();
  } catch (e) { showError(err, e.message); }
  finally { $('sshCreateBtn').disabled = false; }
};

$('sshSignBtn').onclick = async () => {
  const err = $('sshSignError');
  err.classList.add('hidden');
  $('sshCertBox').classList.add('hidden');
  const id = $('sshCA').value;
  if (!id) { showError(err, 'Select (or create) an SSH CA first.'); return; }
  const pub = $('sshPubKey').value.trim();
  if (!pub) { showError(err, 'Paste the public key to certify (authorized_keys line).'); return; }
  const body = {
    public_key: pub,
    cert_type: $('sshCertType').value,
    key_id: $('sshKeyID').value.trim(),
    principals: $('sshPrincipals').value.split(',').map(s => s.trim()).filter(Boolean),
  };
  if ($('sshProfile').value) body.profile = $('sshProfile').value;
  const secs = parseInt($('sshValidity').value, 10);
  if (secs > 0) body.validity_seconds = secs;
  $('sshSignBtn').disabled = true;
  try {
    const res = await api('POST', `/api/ssh/cas/${id}/sign`, body);
    $('sshCertOut').value = res.certificate;
    $('sshCertBox').classList.remove('hidden');
    notice($('sshMsg'), 'ok', `Signed ${res.cert_type} certificate serial ${res.serial} (key ID ${res.key_id}), valid until ${fmtTime(res.valid_before)}.`);
    loadSSHCerts();
  } catch (e) { showError(err, e.message); }
  finally { $('sshSignBtn').disabled = false; }
};

async function loadSSHCerts() {
  const id = $('sshCA').value;
  const certs = $('sshCertRows'), revs = $('sshRevRows');
  if (!id) {
    certs.innerHTML = emptyRow('Select an SSH CA…');
    revs.innerHTML = '<tr><td colspan="3" class="muted">—</td></tr>';
    return;
  }
  try {
    const list = await api('GET', `/api/ssh/cas/${id}/certificates`);
    certs.innerHTML = list.length ? list.map(c => `
      <tr>
        <td class="mono">${escapeHTML(c.serial)}</td>
        <td>${escapeHTML(c.cert_type)}</td>
        <td>${escapeHTML(c.key_id || '')}</td>
        <td>${escapeHTML((c.principals || []).join(', '))}</td>
        <td>${escapeHTML(c.profile || '')}</td>
        <td><span class="badge ${c.status === 'valid' ? 'valid' : 'revoked'}">${escapeHTML(c.status)}</span></td>
        <td>${fmtTime(c.valid_before)}</td>
        <td>${c.status === 'valid'
          ? `<button class="btn danger sm" onclick="revokeSSHCert('${id}','${c.serial}')">Revoke</button>` : ''}</td>
      </tr>`).join('') : emptyRow('No certificates signed yet.');
  } catch (e) { certs.innerHTML = emptyRow(e.message); }
  try {
    const list = await api('GET', `/api/ssh/cas/${id}/revocations`);
    revs.innerHTML = list.length ? list.map(rv => `
      <tr>
        <td class="mono">${escapeHTML(rv.serial || rv.key_id || '')}</td>
        <td>${escapeHTML(rv.reason || '')}</td>
        <td>${fmtTime(rv.revoked_at)}</td>
      </tr>`).join('') : '<tr><td colspan="3" class="muted">No revocations.</td></tr>';
  } catch (e) { revs.innerHTML = `<tr><td colspan="3" class="muted">${escapeHTML(e.message)}</td></tr>`; }
}

async function revokeSSHCert(caID, serial) {
  if (!confirm(`Revoke SSH certificate serial ${serial}?\n\nThe revocation is published to relying hosts through the CA's KRL.`)) return;
  try {
    await api('POST', `/api/ssh/cas/${caID}/revoke`, { serial });
    notice($('sshMsg'), 'ok', `Revoked serial ${serial}. Re-distribute the KRL to relying hosts.`);
    loadSSHCerts();
  } catch (e) { alert('Revoke failed: ' + e.message); }
}
window.revokeSSHCert = revokeSSHCert;

// ---- Artifact signing view (Task 62: CLI parity) ----------------------------
let signers = [];

async function loadSigning() {
  const tbody = $('signerRows');
  tbody.innerHTML = '<tr><td colspan="5" class="muted">Loading…</td></tr>';
  try {
    signers = await api('GET', '/api/sign/signers');
  } catch (e) {
    signers = [];
    tbody.innerHTML = emptyRow(e.message);
    return;
  }
  $('signingDisabled').classList.toggle('hidden', signers.length > 0);
  $('signSigner').innerHTML = signers.map(s =>
    `<option value="${escapeHTML(s.name)}">${escapeHTML(s.name)} — ${escapeHTML(shortName(s.subject))}</option>`).join('')
    || '<option value="">— no signers —</option>';
  tbody.innerHTML = signers.length ? signers.map(s => `
    <tr>
      <td>${escapeHTML(s.name)}</td>
      <td title="${escapeHTML(s.subject)}">${escapeHTML(shortName(s.subject))}</td>
      <td>${escapeHTML(s.digest_algorithm)}</td>
      <td>${s.timestamp_default ? 'yes' : 'no'}</td>
      <td>${s.level_default ? escapeHTML(s.level_default.toUpperCase()) : '—'}</td>
      <td>${fmtTime(s.not_after)}</td>
    </tr>`).join('') : emptyRow('No signing identities configured (secsy-ca signing-key provisions one; signing.enabled activates the service).');
}

// readFileB64 reads a selected file as base64, refusing oversized uploads —
// the digest path exists for anything bigger.
const MAX_SIGN_UPLOAD = 8 * 1024 * 1024;
function readFileB64(input) {
  const f = input.files && input.files[0];
  if (!f) return Promise.resolve(null);
  if (f.size > MAX_SIGN_UPLOAD) return Promise.reject(new Error('file exceeds 8 MiB — sign by digest instead'));
  return new Promise((resolve, reject) => {
    const rd = new FileReader();
    rd.onerror = () => reject(new Error('reading file failed'));
    rd.onload = () => {
      const bytes = new Uint8Array(rd.result);
      let bin = '';
      for (let i = 0; i < bytes.length; i += 0x8000) {
        bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
      }
      resolve(btoa(bin));
    };
    rd.readAsArrayBuffer(f);
  });
}

$('signBtn').onclick = async () => {
  const err = $('signError');
  err.classList.add('hidden');
  $('signOutBox').classList.add('hidden');
  if (!$('signSigner').value) { showError(err, 'No signer available.'); return; }
  const body = { signer: $('signSigner').value };
  const level = $('signLevel').value;
  if (level) body.level = level;
  $('signBtn').disabled = true;
  try {
    const artifact = await readFileB64($('signFile'));
    const digest = $('signDigest').value.trim();
    if (artifact && digest) throw new Error('provide a file or a digest, not both');
    if (artifact) body.artifact = artifact;
    else if (digest) body.digest = digest;
    else throw new Error('choose an artifact file or paste its digest');
    const res = await api('POST', '/api/sign', body);
    $('signOut').value = res.signature_pem;
    $('signOutBox').classList.remove('hidden');
    $('signDownload').onclick = (ev) => {
      ev.preventDefault();
      downloadBlob(res.signature_pem, 'artifact.p7s', 'application/x-pem-file');
    };
    const tsNote = res.timestamped ? ` · RFC 3161 countersigned at ${fmtTime(res.timestamp_time)}` : '';
    const ltvNote = (res.embedded_crls || res.embedded_ocsps)
      ? ` · LTV ${res.embedded_crls || 0} CRL(s) / ${res.embedded_ocsps || 0} OCSP` : '';
    const lvl = res.level ? `CAdES-${res.level.toUpperCase()} · ` : '';
    notice(err, 'ok', `Signed with ${res.signer} (${lvl}${res.digest_algorithm}:${shortSerial(res.digest)})${tsNote}${ltvNote}.`);
  } catch (e) { showError(err, e.message); err.className = 'notice err'; }
  finally { $('signBtn').disabled = false; }
};

$('verifyBtn').onclick = async () => {
  const out = $('verifyResult');
  out.className = 'notice hidden';
  const sig = $('verifySig').value.trim();
  if (!sig) { notice(out, 'err', 'Paste the detached signature.'); return; }
  const body = { signature: sig, require_timestamp: $('verifyRequireTS').checked };
  if ($('verifyCA').value) body.ca_id = $('verifyCA').value;
  $('verifyBtn').disabled = true;
  try {
    const artifact = await readFileB64($('verifyFile'));
    const digest = $('verifyDigest').value.trim();
    if (artifact && digest) throw new Error('provide a file or a digest, not both');
    if (artifact) body.artifact = artifact;
    else if (digest) body.digest = digest;
    else throw new Error('choose the artifact file or paste its digest');
    if ($('verifyRequireLevel') && $('verifyRequireLevel').value) body.require_level = $('verifyRequireLevel').value;
    const res = await api('POST', '/api/sign/verify', body);
    if (res.valid) {
      const ts = res.timestamped ? ` · timestamped ${fmtTime(res.timestamp_time)}` : '';
      const lvl = res.level ? `CAdES-${res.level.toUpperCase()} · ` : '';
      const ltv = (res.revocation_crls || res.revocation_ocsps)
        ? ` · LTV ${res.revocation_crls || 0} CRL(s) / ${res.revocation_ocsps || 0} OCSP` : '';
      notice(out, 'ok', `✓ Valid — ${lvl}signed by ${res.signer_subject} (serial ${shortSerial(res.signer_serial)}), ${res.digest_algorithm}:${shortSerial(res.digest)}${ts}${ltv}, verified at ${fmtTime(res.verified_at)}.`);
    } else {
      notice(out, 'err', `✗ Invalid — ${res.reason}${res.signer_subject ? ` (claimed signer: ${res.signer_subject})` : ''}`);
    }
  } catch (e) { notice(out, 'err', 'Verification failed: ' + e.message); }
  finally { $('verifyBtn').disabled = false; }
};

// ---- ACME service view (challenge capabilities + accounts/orders) -----------
$('acmeRefresh').onclick = loadACME;

async function loadACME() {
  const accts = $('acmeAccountRows');
  const orders = $('acmeOrderRows');
  const msg = $('acmeMsg');
  msg.className = 'notice hidden';
  accts.innerHTML = '<tr><td colspan="6" class="muted">Loading…</td></tr>';
  orders.innerHTML = '<tr><td colspan="6" class="muted">Loading…</td></tr>';

  // The read-only account/order listings double as a liveness signal: an empty
  // list is normal, but an outright error usually means ACME is not enabled.
  let anyOK = false;
  try {
    const rows = await api('GET', '/api/acme/accounts?limit=100');
    anyOK = true;
    accts.innerHTML = (rows && rows.length) ? rows.map(a => `<tr>
      <td class="mono">${escapeHTML(a.id)}</td>
      <td><span class="badge ${a.status === 'valid' ? 'valid' : 'warning'}">${escapeHTML(a.status || '')}</span></td>
      <td>${escapeHTML((a.contacts || []).join(', '))}</td>
      <td style="white-space:nowrap">${fmtTime(a.created_at)}</td>
    </tr>`).join('') : emptyRow('No ACME accounts registered.');
  } catch (e) {
    accts.innerHTML = emptyRow(e.message);
  }

  try {
    const rows = await api('GET', '/api/acme/orders?limit=100');
    anyOK = true;
    orders.innerHTML = (rows && rows.length) ? rows.map(o => {
      const ids = (o.identifiers || []).map(i => i.value).join(', ');
      const badge = o.status === 'valid' ? 'valid'
        : (o.status === 'invalid' ? 'revoked' : 'warning');
      return `<tr>
        <td class="mono">${escapeHTML(o.id)}</td>
        <td><span class="badge ${badge}">${escapeHTML(o.status || '')}</span></td>
        <td title="${escapeHTML(ids)}">${escapeHTML(ids)}</td>
        <td style="white-space:nowrap">${fmtTime(o.expires)}</td>
        <td style="white-space:nowrap">${fmtTime(o.created_at)}</td>
      </tr>`;
    }).join('') : emptyRow('No ACME orders yet.');
  } catch (e) {
    orders.innerHTML = emptyRow(e.message);
  }

  $('acmeDisabled').classList.toggle('hidden', anyOK);
}

// ---- Audit view (Task 62: CLI parity) ---------------------------------------
let auditOffset = 0;

$('auditRefresh').onclick = () => { auditOffset = 0; loadAudit(); };
$('auditAction').onchange = () => { auditOffset = 0; loadAudit(); };
$('auditActor').onchange = () => { auditOffset = 0; loadAudit(); };
$('auditLimit').onchange = () => { auditOffset = 0; loadAudit(); };
$('auditPrev').onclick = () => {
  auditOffset = Math.max(0, auditOffset - parseInt($('auditLimit').value, 10));
  loadAudit();
};
$('auditNext').onclick = () => {
  auditOffset += parseInt($('auditLimit').value, 10);
  loadAudit();
};

async function loadAudit() {
  const tbody = $('auditRows');
  tbody.innerHTML = '<tr><td colspan="7" class="muted">Loading…</td></tr>';
  const p = new URLSearchParams();
  if ($('auditAction').value.trim()) p.set('action', $('auditAction').value.trim());
  if ($('auditActor').value.trim()) p.set('actor', $('auditActor').value.trim());
  p.set('limit', $('auditLimit').value);
  p.set('offset', String(auditOffset));
  try {
    const rep = await api('GET', '/api/events?' + p.toString());
    const entries = rep.entries || [];
    $('auditCounts').textContent = `${rep.total} event(s) · showing ${auditOffset + 1}–${auditOffset + entries.length}`;
    $('auditPage').textContent = `offset ${auditOffset}`;
    tbody.innerHTML = entries.length ? entries.map(e => `
      <tr>
        <td style="white-space:nowrap">${fmtTime(e.timestamp)}</td>
        <td class="mono">${escapeHTML(e.action)}</td>
        <td title="${escapeHTML(e.actor_roles || '')}">${escapeHTML(e.actor_name || e.actor || '')}</td>
        <td>${escapeHTML(e.tenant || '')}</td>
        <td class="mono" title="${escapeHTML(e.target || '')}">${escapeHTML(e.target_name || shortSerial(e.target))}</td>
        <td><span class="badge ${e.result === 'success' ? 'valid' : (e.result === 'denied' ? 'revoked' : 'warning')}">${escapeHTML(e.result)}</span></td>
        <td class="muted" title="${escapeHTML(e.detail || '')}">${escapeHTML((e.detail || '').slice(0, 80))}</td>
      </tr>`).join('') : emptyRow('No events match.');
  } catch (e) {
    tbody.innerHTML = emptyRow(e.message);
    $('auditCounts').textContent = '';
  }
}

$('auditVerifyBtn').onclick = async () => {
  const out = $('auditVerify');
  out.className = 'notice';
  out.textContent = 'Recomputing the hash chain…';
  try {
    const res = await api('GET', '/api/events/verify');
    if (res.valid) notice(out, 'ok', `✓ Chain intact — ${res.count} event(s) verified against the genesis hash.`);
    else notice(out, 'err', `✗ Chain BROKEN at seq ${res.broken_at_seq}: ${res.reason}`);
  } catch (e) {
    // 409 carries the verification result too; api() throws on it.
    notice(out, 'err', '✗ ' + e.message);
  }
};

async function exportAudit(format, filename) {
  try {
    const data = await api('GET', '/api/events/export?format=' + format, undefined, true);
    downloadBlob(data, filename, 'text/plain');
  } catch (e) { alert('Export failed: ' + e.message); }
}
$('auditExportJSON').onclick = () => exportAudit('json', 'audit-export.ndjson');
$('auditExportCEF').onclick = () => exportAudit('cef', 'audit-export.cef.log');
$('auditExportSyslog').onclick = () => exportAudit('rfc5424', 'audit-export.syslog.log');

// ---- Live audit-event tail (Server-Sent Events) -----------------------------
// The live feed streams every hash-chained audit event as it is sealed,
// tenant/RBAC-scoped on the server identically to the paged log. It consumes the
// stream with fetch() + a ReadableStream reader rather than the native
// EventSource so the operator's Authorization header (basic root / bearer token)
// rides along — EventSource can only carry cookies. The ?action= filter is shared
// with the paged view; tenant scoping is enforced server-side.
let auditLiveController = null;   // AbortController for the in-flight stream, or null
const AUDIT_LIVE_MAX = 300;       // cap the live table so a long session can't grow unbounded

function auditLiveActive() { return auditLiveController !== null; }

$('auditLiveToggle').onclick = () => auditLiveActive() ? stopLiveTail() : startLiveTail();
$('auditLiveClear').onclick = () => { $('auditLiveRows').innerHTML = ''; };

function auditLiveRow(e) {
  const badge = e.result === 'success' ? 'valid' : (e.result === 'denied' ? 'revoked' : 'warning');
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td style="white-space:nowrap">${fmtTime(e.timestamp)}</td>
    <td class="mono">${escapeHTML(e.action || '')}</td>
    <td title="${escapeHTML(e.actor_roles || '')}">${escapeHTML(e.actor_name || e.actor || '')}</td>
    <td>${escapeHTML(e.tenant || '')}</td>
    <td class="mono" title="${escapeHTML(e.target || '')}">${escapeHTML(e.target_name || shortSerial(e.target))}</td>
    <td><span class="badge ${badge}">${escapeHTML(e.result || '')}</span></td>
    <td class="muted" title="${escapeHTML(e.detail || '')}">${escapeHTML((e.detail || '').slice(0, 80))}</td>`;
  return tr;
}

function auditLiveNoticeRow(text) {
  const tr = document.createElement('tr');
  tr.innerHTML = `<td colspan="7" class="muted" style="text-align:center">${escapeHTML(text)}</td>`;
  return tr;
}

function auditLiveStatus(html) { $('auditLiveStatus').innerHTML = html; }

async function startLiveTail() {
  if (auditLiveActive()) return;
  const p = new URLSearchParams();
  if ($('auditAction').value.trim()) p.set('action', $('auditAction').value.trim());
  const url = '/api/events/stream' + (p.toString() ? '?' + p.toString() : '');
  const controller = new AbortController();
  auditLiveController = controller;
  $('auditLiveToggle').textContent = '■ Stop';
  $('auditLiveClear').classList.remove('hidden');
  $('auditLivePanel').classList.remove('hidden');
  auditLiveStatus('<span style="color:var(--warn)">●</span> connecting…');
  const headers = { 'Accept': 'text/event-stream' };
  if (store.auth) headers['Authorization'] = store.auth;
  try {
    const res = await fetch(url, { headers, credentials: 'same-origin', signal: controller.signal });
    if (res.status === 401) { logout(); throw new Error('authentication required'); }
    if (!res.ok) {
      let msg = `HTTP ${res.status}`;
      try { const j = JSON.parse(await res.text()); if (j.error) msg = j.error; } catch (_) { /* keep msg */ }
      throw new Error(msg);
    }
    auditLiveStatus('<span style="color:var(--ok)">●</span> streaming — new events appear at the top');
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      // SSE frames are separated by a blank line.
      let sep;
      while ((sep = buf.indexOf('\n\n')) >= 0) {
        handleAuditSSEFrame(buf.slice(0, sep));
        buf = buf.slice(sep + 2);
      }
    }
    if (auditLiveActive()) auditLiveStatus('<span class="muted">○</span> stream closed by server');
  } catch (e) {
    if (e.name === 'AbortError') return;   // operator stopped it; finally resets the UI
    auditLiveStatus(`<span style="color:var(--crit)">●</span> ${escapeHTML(e.message)}`);
  } finally {
    if (auditLiveController === controller) {
      auditLiveController = null;
      $('auditLiveToggle').textContent = '▶ Live tail';
    }
  }
}

function handleAuditSSEFrame(frame) {
  let event = 'message', data = '';
  for (const line of frame.split('\n')) {
    if (line === '' || line.startsWith(':')) continue;   // blank or comment (heartbeat)
    if (line.startsWith('event:')) event = line.slice(6).trim();
    else if (line.startsWith('data:')) data += line.slice(5).trim();
  }
  if (!data) return;
  let payload;
  try { payload = JSON.parse(data); } catch (_) { return; }
  const tbody = $('auditLiveRows');
  if (event === 'audit') {
    tbody.insertBefore(auditLiveRow(payload), tbody.firstChild);
    while (tbody.children.length > AUDIT_LIVE_MAX) tbody.removeChild(tbody.lastChild);
  } else if (event === 'lag') {
    tbody.insertBefore(auditLiveNoticeRow('⚠ ' + (payload.message || `dropped ${payload.dropped} event(s)`)), tbody.firstChild);
  }
}

function stopLiveTail() {
  if (auditLiveController) { auditLiveController.abort(); auditLiveController = null; }
  $('auditLiveToggle').textContent = '▶ Live tail';
  auditLiveStatus('<span class="muted">○</span> stopped');
}

// ---- Four-eyes / maker-checker approvals ------------------------------------
async function loadApprovals() {
  const tbody = $('approvalsRows');
  tbody.innerHTML = '<tr><td colspan="8" class="muted">Loading…</td></tr>';
  const p = new URLSearchParams();
  if ($('approvalsStatus').value) p.set('status', $('approvalsStatus').value);
  if ($('approvalsClass').value.trim()) p.set('class', $('approvalsClass').value.trim());
  try {
    const rep = await api('GET', '/api/approvals?' + p.toString());
    $('approvalsDisabled').classList.toggle('hidden', rep.enabled !== false);
    const rows = rep.requests || [];
    tbody.innerHTML = rows.length ? rows.map(r => {
      const badge = (r.status === 'approved' || r.status === 'executed') ? 'valid'
        : ((r.status === 'rejected' || r.status === 'expired') ? 'revoked' : 'warning');
      let actions = r.status === 'pending'
        ? `<button class="btn ghost sm" onclick="doApprove('${escapeHTML(r.id)}')">Approve</button>
           <button class="btn ghost sm" onclick="doReject('${escapeHTML(r.id)}')">Reject</button>`
        : '';
      // Per-profile issuance approvals (Task 84) deliver the certificate once
      // approved: offer a fetch button for cert.issue requests past the gate.
      if (r.operation_class === 'cert.issue' && (r.status === 'approved' || r.status === 'executed')) {
        actions += ` <button class="btn ghost sm" onclick="fetchApprovalCert('${escapeHTML(r.id)}')">Certificate</button>`;
      }
      return `<tr>
        <td class="mono" title="${escapeHTML(r.summary || '')}">${escapeHTML(r.id)}</td>
        <td class="mono">${escapeHTML(r.operation_class)}</td>
        <td class="mono">${escapeHTML(r.resource_name || r.resource_key)}</td>
        <td>${escapeHTML(r.requested_by_name || r.requested_by)}</td>
        <td>${r.approvals_count}/${r.required_approvals}</td>
        <td><span class="badge ${badge}">${escapeHTML(r.status)}</span></td>
        <td style="white-space:nowrap">${fmtTime(r.created_at)}</td>
        <td>${actions}</td>
      </tr>`;
    }).join('') : emptyRow('No approval requests.');
  } catch (e) {
    tbody.innerHTML = emptyRow(e.message);
  }
}

// doApprove / doReject are global so the per-row buttons (inline onclick) can
// reach them. A distinct approver is required; the server refuses self-approval.
async function doApprove(id) {
  const comment = prompt('Approve request ' + id + '?\nA DIFFERENT approver than the requester is required.\nOptional comment:');
  if (comment === null) return; // cancelled
  try { await api('POST', '/api/approvals/' + id + '/approve', { comment }); loadApprovals(); }
  catch (e) { alert('Approve failed: ' + e.message); }
}
async function doReject(id) {
  const comment = prompt('Reject request ' + id + '? Optional reason:');
  if (comment === null) return;
  try { await api('POST', '/api/approvals/' + id + '/reject', { comment }); loadApprovals(); }
  catch (e) { alert('Reject failed: ' + e.message); }
}
// fetchApprovalCert completes and retrieves the certificate for an approved
// per-profile issuance request (Task 84). On the first call for an approved
// request the server issues it on the HSM; subsequent calls redeliver the same
// certificate. It is global so the per-row button can reach it.
async function fetchApprovalCert(id) {
  try {
    const res = await api('GET', '/api/approvals/' + id + '/certificate');
    if (res.certificate) {
      const pem = res.certificate + (res.chain ? '\n' + res.chain : '');
      downloadBlob(pem, `cert-${res.serial || id}.pem`, 'application/x-pem-file');
      alert(`Certificate for request ${id} issued (serial ${res.serial}); the PEM has been downloaded.`);
    } else {
      alert(res.message || 'The certificate is not ready yet.');
    }
    loadApprovals();
  } catch (e) {
    alert('Fetch certificate failed: ' + e.message);
  }
}

$('approvalsRefresh').onclick = () => loadApprovals();
$('approvalsStatus').onchange = () => loadApprovals();
$('approvalsClass').addEventListener('keydown', e => { if (e.key === 'Enter') loadApprovals(); });

// ---- Certificate lint (Compliance view) -------------------------------------
$('lintBtn').onclick = async () => {
  const out = $('lintResult');
  out.className = 'notice hidden';
  $('lintTable').classList.add('hidden');
  const pem = $('lintPEM').value.trim();
  if (!pem) { notice(out, 'err', 'Paste a PEM certificate.'); return; }
  const body = { certificate: pem };
  if ($('lintProfile').value) body.profile = $('lintProfile').value;
  if ($('lintPublic').checked) body.public = true;
  if ($('lintMode').value) body.mode = $('lintMode').value;
  if ($('lintZlint').checked) body.zlint = true;
  $('lintBtn').disabled = true;
  try {
    const res = await api('POST', '/api/lint', body);
    if (body.zlint && !res.zlint_available) {
      notice(out, 'warn', 'zlint requested but this server was not built with -tags zlint; showing hand-rolled checks only.');
    } else if (res.pass) {
      notice(out, 'ok', `✓ PASS — ${shortName(res.subject)} (serial ${shortSerial(res.serial)}) raised no findings under ${res.profile || 'the'} ${res.mode} policy${res.public ? ' with CA/B public rules' : ''}${res.zlint ? ' + zlint' : ''}.`);
    } else {
      notice(out, res.errors ? 'err' : 'warn',
        `${res.errors ? '✗' : '⚠'} ${res.errors} error(s), ${res.warnings} warning(s) for ${shortName(res.subject)} — ${res.summary}`);
      $('lintRows').innerHTML = (res.findings || []).map(f => `
        <tr>
          <td class="mono">${escapeHTML(f.code)}</td>
          <td><span class="badge ${f.mode === 'enforce' ? 'fail' : 'warn'}">${escapeHTML(f.mode)}</span></td>
          <td>${escapeHTML(f.description)}</td>
        </tr>`).join('');
      $('lintTable').classList.remove('hidden');
    }
  } catch (e) { notice(out, 'err', e.message); }
  finally { $('lintBtn').disabled = false; }
};

// ---- Helpers -------------------------------------------------------------
// debounce coalesces rapid calls (e.g. keystrokes in a filter box) into a single
// invocation after the input settles, so typing does not fire a request per key.
function debounce(fn, ms) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
}
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
