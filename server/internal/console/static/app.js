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

// postVerdict posts to an endpoint whose NEGATIVE answer is a verdict rather than
// a fault: POST /api/ers/verify and POST /api/ca/{id}/svid/jwt/verify both answer
// 409 with the very body they would have sent on 200 ({valid:false, reason:…}).
// api() throws on every non-2xx, but in raw mode the thrown message is the
// response text — so the verdict is recovered from it and rendered as the answer,
// instead of reaching the operator as a bare "HTTP 409".
async function postVerdict(path, body) {
  try {
    return JSON.parse(await api('POST', path, body, true));
  } catch (e) {
    let data = null;
    try { data = JSON.parse(e.message); } catch (_) { /* a real transport/auth error */ }
    if (data && typeof data.valid === 'boolean') return data;
    throw e;
  }
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
  if (name === 'hsm') loadHSM();
  if (name === 'ssh') loadSSH();
  if (name === 'signing') loadSigning();
  if (name === 'secrets' && secretServiceEnabled) loadSecretsPage();
  if (name === 'acme') loadACME();
  if (name === 'audit') loadAudit();
  if (name === 'approvals') loadApprovals();
  if (name === 'compliance') loadCompliance();
  if (name === 'bundle') loadBundle();
  if (name === 'dns') loadDNS();
  if (name === 'ops') loadOps();
  if (name === 'tenants') loadTenants();
  if (name === 'tokens') loadTokens();
  if (name === 'access') loadAccess();
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
  // An adopted CA's parent is optional (blank lets the server discover it, and an
  // externally-signed subordinate has no parent here at all), so this select keeps
  // its own empty choice rather than borrowing the "— no CAs —" placeholder.
  $('caImpParent').innerHTML = '<option value="">— discover / external parent —</option>' + activeOpts;
  // The two provisioning forms issue a credential, so they offer the same active
  // issuers the ordinary issuance forms do.
  $('signProvCA').innerHTML = activeOpts || empty;
  $('tsaProvCA').innerHTML = activeOpts || empty;
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
    // The four-eyes gate answers 202 and revokes nothing. The approval pins this
    // exact selection (filter + reason + confirmed count), so the operator must
    // re-run the same preview and execute once it is signed off.
    const held = heldForApproval(result);
    if (held) {
      $('bulkResultBox').innerHTML = `<div class="notice warn">${escapeHTML(held)} Preview and execute the same selection again to consume the approval.</div>`;
      $('bulkResultBox').classList.remove('hidden');
      $('bulkPlanBox').classList.add('hidden');
      bulkPlan = null;
      loadApprovals();
      return;
    }
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

// ---- TLS delegated credentials (RFC 9345, Task 198) ------------------------
// Mirrors `secsy-ca delegated-credential mint`, with the difference that decides
// the form: the CLI is handed the leaf's private key as a file, while the server
// can only obtain it by recovering the M-of-N escrow envelope taken at PKCS#12
// export — so the envelope and a quorum of recovery-agent ids are what this panel
// asks for. There is no REST counterpart of `delegated-credential verify` (it is
// pure offline crypto over a wire credential and a certificate), so verification
// is not offered here.

// dcSPKIBase64 accepts what an operator actually holds — a PUBLIC KEY PEM — and
// yields the base64 DER SubjectPublicKeyInfo the endpoint wants. A PEM body is
// already that base64, so the armour and the line breaks are all that must go;
// bare base64 passes through unchanged.
function dcSPKIBase64(text) {
  return text.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
}

$('dcBtn').onclick = async () => {
  const out = $('dcResult'), msg = $('dcMsg');
  msg.className = 'notice hidden';
  out.classList.add('hidden');
  const id = selectedCertCA();
  if (!id) { notice(msg, 'err', 'Select a certificate authority above.'); return; }
  const serial = $('dcSerial').value.trim();
  if (!serial) { notice(msg, 'err', 'Give the decimal serial of the leaf to delegate for.'); return; }
  const agents = csvList($('dcAgents').value);
  if (!agents.length) { notice(msg, 'err', 'List the recovery agents that unseal the escrow envelope.'); return; }
  const env = $('dcEscrowEnvelope').value.trim();
  if (!env) { notice(msg, 'err', 'Paste the escrow envelope stored when the leaf was exported as a PKCS#12.'); return; }
  // The envelope travels as JSON, not as a string, so it is parsed here — a typo
  // in a pasted envelope deserves its own message rather than a decoder error.
  let envelope;
  try { envelope = JSON.parse(env); }
  catch (_) { notice(msg, 'err', 'The escrow envelope is not valid JSON — paste the whole envelope object.'); return; }
  const body = {
    serial, recovery_agents: agents, escrow_envelope: envelope,
    dc_key_type: $('dcKeyType').value,
  };
  const hours = parseInt($('dcValidHours').value, 10);
  if (hours > 0) body.valid_for_seconds = hours * 3600;
  if ($('dcEndpoint').value === 'client') body.client = true;
  const signAlg = $('dcSignAlg').value.trim(); if (signAlg) body.signature_scheme = signAlg;
  const expectAlg = $('dcExpectAlg').value.trim(); if (expectAlg) body.expected_cert_verify_algorithm = expectAlg;
  const pub = dcSPKIBase64($('dcPubKey').value.trim()); if (pub) body.dc_public_key = pub;
  $('dcBtn').disabled = true;
  try {
    const res = await api('POST', `/api/ca/${id}/delegated-credential`, body);
    renderDelegatedCredential(res);
  } catch (e) { notice(msg, 'err', e.message); }
  finally { $('dcBtn').disabled = false; }
};

// renderDelegatedCredential shows the credential's terms and offers the bytes.
// The wire credential and the delegated public key are public material and are
// shown; the delegated PRIVATE key (present only when the server generated the
// keypair) is offered as a download and never written into the page.
function renderDelegatedCredential(res) {
  const out = $('dcResult');
  out.className = 'notice ok';
  out.innerHTML =
    `<div style="font-size:15px"><b>✓ ${escapeHTML(res.endpoint || '')} delegated credential</b> for serial ` +
    `<span class="mono">${escapeHTML(shortSerial(res.serial || ''))}</span></div>` +
    `<div class="muted" style="margin-top:6px">` +
      `valid ${escapeHTML(fmtDuration(res.valid_time_seconds))} from the certificate notBefore, until ` +
      `${escapeHTML(fmtTime(res.not_after))}<br>` +
      `signed with ${escapeHTML(res.algorithm || '')} · handshake scheme ` +
      `${escapeHTML(res.expected_cert_verify_algorithm || '')}` +
      (res.dc_private_key_pem
        ? '<br>the delegated keypair was generated here — download the private key now, it is not stored'
        : '<br>the delegated public key was supplied, so its private half stayed with you') +
    '</div>' +
    `<div class="mono" style="margin-top:8px;word-break:break-all">${escapeHTML(res.delegated_credential || '')}</div>`;
  out.classList.remove('hidden');
  const add = (text, content, filename, type) => {
    const b = document.createElement('button');
    b.className = 'btn ghost sm';
    b.style.margin = '8px 8px 0 0';
    b.textContent = text;
    b.onclick = () => downloadBlob(content, filename, type);
    out.appendChild(b);
  };
  const stem = res.serial || 'credential';
  // The wire credential is what a TLS terminator loads, so it is offered as the
  // raw bytes the base64 encodes rather than as the encoding.
  if (res.delegated_credential) {
    add('Download wire credential', unb64(res.delegated_credential), `${stem}.dc.bin`, 'application/octet-stream');
  }
  if (res.dc_public_key_pem) {
    add('Download delegated public key', res.dc_public_key_pem, `${stem}.dc-pub.pem`, 'application/x-pem-file');
  }
  if (res.dc_private_key_pem) {
    add('Download delegated private key', res.dc_private_key_pem, `${stem}.dc-key.pem`, 'application/x-pem-file');
  }
}

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

// Mirrors `secsy-ca ct verify-inclusion`: run the inclusion check now instead of
// waiting for the leader-elected background monitor's next tick. It drives the
// same monitor over the same configured logs, so the console can never report a
// different posture than the CLI. "failed" and "new_misbehavior" are the
// mis-issuance / log-misbehavior signal — a log that did not merge a certificate
// it signed an SCT for — so a non-zero count is an error verdict however cleanly
// the run itself completed.
$('ctVerifyBtn').onclick = async () => {
  const out = $('ctVerifyResult'), btn = $('ctVerifyBtn');
  const body = {};
  const max = parseInt($('ctVerifyMax').value, 10);
  if (max > 0) body.max = max;
  btn.disabled = true;
  notice(out, '', 'Fetching signed tree heads and verifying Merkle audit paths…');
  try {
    const res = await api('POST', '/api/ct/verify-inclusion', body);
    const bits = [`${res.certs || 0} certificate(s) examined, ${res.checked || 0} SCT(s) checked: ` +
      `${res.included || 0} included, ${res.pending || 0} pending, ${res.failed || 0} failed, ` +
      `${res.unknown_log || 0} from an unknown log, ${res.errors || 0} fetch error(s).`];
    if (res.new_misbehavior) {
      bits.push(`${res.new_misbehavior} SCT(s) newly transitioned to FAILED: a log did not include a certificate it promised to log. Investigate before the next issuance.`);
    } else if (res.failed) {
      bits.push('Failed SCTs remain from an earlier scan — filter the table by "failed" to see them.');
    }
    if (res.error) bits.push('Scan error: ' + res.error);
    notice(out, (res.failed || res.new_misbehavior) ? 'err' : 'ok', bits.join(' '));
    loadCT(); // the standing table and counts have moved
  } catch (e) {
    // 503 = no CT logs are configured (or the configured ones are unusable); the
    // server's message names which, so it is surfaced verbatim.
    notice(out, 'err', 'Inclusion verification failed: ' + e.message);
  } finally { btn.disabled = false; }
};

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
  // The retention posture explains why the listing above is (or is not)
  // shrinking, so it is refreshed alongside it and fails independently.
  loadRetentionStatus();
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
  // The blocklist and the evidence records are deployment-global rather than
  // per-CA, so they reload with the view but ignore the CA filter above.
  loadBlockedKeys();
  loadEvidenceRecords();
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

// ---- Compromised-key blocklist (Task 120, Compliance view) -----------------
// Mirrors `secsy-ca blocked-keys list|add|remove`. The store is deployment-global
// — a compromised key is compromised for every tenant — and holds no key
// material, only the SubjectPublicKeyInfo SHA-256 fingerprint the pre-issuance
// gate compares against.
async function loadBlockedKeys() {
  const tbody = $('bkRows');
  tbody.innerHTML = '<tr><td colspan="6" class="muted">Loading…</td></tr>';
  let keys = [];
  try {
    const rep = await api('GET', '/api/blocked-keys');
    keys = rep.blocked_keys || [];
    $('bkCount').textContent = `${rep.total || 0} key(s) blocked deployment-wide`;
  } catch (e) {
    $('bkCount').textContent = '';
    tbody.innerHTML = `<tr><td colspan="6" class="muted">${escapeHTML(e.message)}</td></tr>`;
    return;
  }
  tbody.innerHTML = keys.length ? keys.map((k, i) => `
    <tr>
      <td class="mono">${escapeHTML(k.fingerprint || '')}</td>
      <td>${escapeHTML(k.reason || '')}</td>
      <td>${escapeHTML(k.source || '')}</td>
      <td>${escapeHTML(k.added_by || '')}</td>
      <td style="white-space:nowrap">${fmtTime(k.added_at)}</td>
      <td style="white-space:nowrap"><button class="btn danger sm" data-bk="${i}">Unblock</button></td>
    </tr>`).join('')
    : '<tr><td colspan="6" class="muted">No keys are blocked.</td></tr>';
  tbody.querySelectorAll('button[data-bk]').forEach(b => {
    b.onclick = () => unblockKey(keys[Number(b.dataset.bk)]);
  });
}

// Mirrors `secsy-ca blocked-keys add`. Exactly one input names the key: pasted
// material (certificate / CSR / public key, PEM or bare base64 DER) or a
// pre-computed fingerprint. 201 created the entry, 200 means it was already
// blocked — which is reported plainly rather than as a success.
$('bkAddBtn').onclick = async () => {
  const msg = $('bkMsg'), btn = $('bkAddBtn');
  msg.className = 'notice hidden';
  const fp = $('bkFingerprint').value.trim();
  const material = $('bkMaterial').value.trim();
  if (fp && material) {
    notice(msg, 'err', 'Give the material or a fingerprint, not both — naming the key two ways hides which one you meant to block.');
    return;
  }
  if (!fp && !material) {
    notice(msg, 'err', 'Paste the certificate, CSR or public key to block, or enter a pre-computed fingerprint.');
    return;
  }
  const body = {};
  if (fp) body.fingerprint = fp;
  else body[$('bkKind').value] = material;
  const reason = $('bkReason').value.trim(); if (reason) body.reason = reason;
  const source = $('bkSource').value.trim(); if (source) body.source = source;
  btn.disabled = true;
  try {
    const res = await api('POST', '/api/blocked-keys', body);
    notice(msg, res.newly_added ? 'ok' : 'warn', res.newly_added
      ? `Blocked ${res.fingerprint} — every issuance surface now refuses this key, for every tenant.`
      : `Already blocked since ${fmtTime(res.added_at)} by ${res.added_by || 'unknown'} ` +
        `(source ${res.source || '—'}${res.reason ? ', reason: ' + res.reason : ''}). ` +
        'Nothing changed: the original entry and its justification stand.');
    $('bkMaterial').value = $('bkFingerprint').value = $('bkReason').value = '';
    loadBlockedKeys();
  } catch (e) {
    // 403 = ca:configure is required; 400 names the input that could not be read.
    notice(msg, 'err', 'Blocking failed: ' + e.message);
  } finally { btn.disabled = false; }
};

// Mirrors `secsy-ca blocked-keys remove`. Un-blocking re-admits a key the CA was
// refusing to certify, which is the security-relevant half of the pair — hence
// the confirmation and the recorded justification. The canonical fingerprint is
// standard-alphabet base64 and may contain '/', so it is percent-encoded.
async function unblockKey(k) {
  const msg = $('bkMsg');
  if (!confirm(`Un-block this key?\n\n${k.fingerprint}\n\nThe CA will certify it again on every issuance surface and for every tenant. Do this only if the key was never compromised.`)) return;
  const reason = prompt('Why is this key being un-blocked? (recorded in the audit log)');
  if (reason === null) return; // cancelled
  try {
    const q = reason.trim() ? '?reason=' + encodeURIComponent(reason.trim()) : '';
    const res = await api('DELETE', '/api/blocked-keys/' + encodeURIComponent(k.fingerprint) + q);
    notice(msg, res.removed ? 'ok' : 'warn', res.removed
      ? `Un-blocked ${res.fingerprint}.`
      : `${res.fingerprint} was not on the blocklist (${res.status}); nothing changed.`);
    loadBlockedKeys();
  } catch (e) { notice(msg, 'err', 'Un-blocking failed: ' + e.message); }
}
$('bkRefresh').onclick = loadBlockedKeys;

// ---- RFC 4998 Evidence Records (Task 161, Compliance view) ----------------
// An evidence record keeps a proof verifiable after the algorithms under it
// weaken, by nesting RFC 3161 archive-timestamp chains. Mirrors
// `secsy-ca ers list|generate|renew|export`; verification lives below.
let ersOffset = 0;

async function loadEvidenceRecords() {
  const tbody = $('ersRows');
  tbody.innerHTML = '<tr><td colspan="8" class="muted">Loading…</td></tr>';
  const limit = parseInt($('ersLimit').value, 10) || 200;
  let items = [];
  try {
    const rep = await api('GET', `/api/ers?limit=${limit}&offset=${ersOffset}`);
    items = rep.items || [];
    $('ersCount').textContent = rep.total
      ? `${rep.total} record(s) · showing ${ersOffset + 1}–${ersOffset + items.length}`
      : 'no records';
    $('ersPage').textContent = `offset ${ersOffset}`;
  } catch (e) {
    $('ersCount').textContent = '';
    tbody.innerHTML = `<tr><td colspan="8" class="muted">${escapeHTML(e.message)}</td></tr>`;
    return;
  }
  tbody.innerHTML = items.length ? items.map(ersRowHTML).join('')
    : '<tr><td colspan="8" class="muted">No evidence records. Generate one to start preserving a range of the audit chain.</td></tr>';
  tbody.querySelectorAll('button[data-ers]').forEach(b => {
    const rec = items[Number(b.dataset.i)];
    if (b.dataset.ers === 'export') b.onclick = () => exportEvidenceRecord(rec.id);
    if (b.dataset.ers === 'renew') b.onclick = () => renewEvidenceRecord(rec);
    if (b.dataset.ers === 'verify') b.onclick = () => {
      $('ersID').value = rec.id;
      $('ersRecord').value = '';
      runERSVerify();
    };
  });
}

// ersRowHTML renders one stored record. The TSA expiry is badged rather than
// merely printed: an expired embedded TSA certificate is precisely what a
// time-stamp renewal exists to stay ahead of, so a lapsed record is worthless
// and must not read like a healthy one.
function ersRowHTML(r, i) {
  const covers = r.scope === 'audit'
    ? `seq ${r.first_seq}–${r.last_seq}`
    : `${(r.object_ids || []).length} object(s)`;
  let tsa = '<span class="muted">—</span>';
  if (r.tsa_not_after) {
    const left = (new Date(r.tsa_not_after) - Date.now()) / 86400000;
    const cls = left <= 0 ? 'fail' : left < 30 ? 'warn' : 'pass';
    tsa = `<span class="badge ${cls}">${escapeHTML(fmtTime(r.tsa_not_after))}</span>`;
  }
  return `<tr>
    <td class="mono" title="${escapeHTML(r.description || '')}">${escapeHTML(r.id || '')}</td>
    <td>${escapeHTML(r.scope || '')}</td>
    <td class="mono">${escapeHTML(covers)}</td>
    <td>${escapeHTML(r.digest_alg || '')}</td>
    <td>${r.chains || 0}</td>
    <td style="white-space:nowrap">${fmtTime(r.last_gen_time)}</td>
    <td style="white-space:nowrap">${tsa}</td>
    <td style="white-space:nowrap">
      <button class="btn ghost sm" data-ers="export" data-i="${i}">Export</button>
      <button class="btn ghost sm" data-ers="renew" data-i="${i}">Renew</button>
      <button class="btn ghost sm" data-ers="verify" data-i="${i}">Verify</button>
    </td>
  </tr>`;
}

// ersSummary describes a record the way `ers generate|renew -json` reports it.
function ersSummary(r, lead) {
  return `${lead}: ${r.scope} scope, ${r.digest_alg}, ${r.chains} chain(s), newest stamp ${fmtTime(r.last_gen_time)}` +
    (r.tsa_not_after ? `, TSA certificate valid until ${fmtTime(r.tsa_not_after)}` : '') + '.';
}

// Mirrors `secsy-ca ers generate -audit-from N -audit-to M`. Only the audit-range
// scope is offered: an artifact-scope record's protected bytes are never stored,
// so every later renewal and verification would need them re-supplied — a promise
// a browser session cannot keep, and the CLI takes files directly.
$('ersGenBtn').onclick = async () => {
  const err = $('ersGenError'), msg = $('ersAdminMsg');
  err.classList.add('hidden');
  msg.className = 'notice hidden';
  const from = parseInt($('ersGenFrom').value, 10), to = parseInt($('ersGenTo').value, 10);
  if (!(from > 0) || !(to > 0)) { showError(err, 'An inclusive audit-sequence range is required — both bounds, 1 or greater.'); return; }
  if (to < from) { showError(err, 'The range ends before it starts.'); return; }
  const body = { audit_from: from, audit_to: to };
  if ($('ersGenHash').value) body.hash = $('ersGenHash').value;
  const desc = $('ersGenDesc').value.trim(); if (desc) body.description = desc;
  $('ersGenBtn').disabled = true;
  try {
    const res = await api('POST', '/api/ers/generate', body);
    notice(msg, 'ok', ersSummary(res, `Generated ${res.id}`));
    ersOffset = 0;
    loadEvidenceRecords();
  } catch (e) {
    // 400 = the range is past the event-log head; 503 = no archive-timestamp
    // source is configured (neither ers.tsa_url nor a TSA-role key).
    showError(err, e.message);
  } finally { $('ersGenBtn').disabled = false; }
};

// Mirrors `secsy-ca ers renew` and `ers renew -hashtree`. The panel's two renewal
// controls decide the kind and the target digest, so a per-row button needs no
// modal of its own — only the confirmation that says which renewal is about to
// happen.
async function renewEvidenceRecord(rec) {
  const msg = $('ersAdminMsg');
  const hashTree = $('ersRenewHashTree').checked;
  const target = $('ersRenewHash').value;
  const ask = hashTree
    ? `Add a hash-tree chain to ${rec.id}${target ? ' under ' + target : ''}?\n\nEvery protected object is re-hashed under a stronger digest — the renewal for algorithm deprecation.`
    : `Add a fresh archive time-stamp to ${rec.id}?\n\nThis is the renewal that must happen before the embedded TSA certificate expires.`;
  if (!confirm(ask)) return;
  const body = { id: rec.id };
  if (hashTree) {
    body.hashtree = true;
    if (target) body.hash = target;
  }
  try {
    const res = await api('POST', '/api/ers/renew', body);
    notice(msg, 'ok', ersSummary(res, `Renewed ${res.id} (${res.kind})`));
    loadEvidenceRecords();
  } catch (e) {
    // A hash-tree renewal of an artifact-scope record needs the original object
    // bytes re-supplied, which only the CLI can do; the server says exactly that.
    notice(msg, 'err', `Renewing ${rec.id} failed: ${e.message}`);
  }
}

// Mirrors `secsy-ca ers export`: the decoded structure plus the record itself.
// The DER is taken from the JSON body's base64 "record" — the same bytes
// ?format=der streams — because api()'s raw mode decodes a response as text,
// which would corrupt binary, and base64 is how every other binary download in
// this console is carried.
async function exportEvidenceRecord(id) {
  const out = $('ersExportOut');
  out.innerHTML = '<p class="muted">Exporting…</p>';
  let res;
  try {
    res = await api('GET', '/api/ers/export?id=' + encodeURIComponent(id));
  } catch (e) {
    out.innerHTML = `<div class="notice err">Export failed: ${escapeHTML(e.message)}</div>`;
    return;
  }
  const info = res.info || {};
  const stamps = (info.timestamps || []).map(t => `<tr>
      <td>${t.chain}</td>
      <td>${t.index}</td>
      <td>${escapeHTML(t.hash || '')}</td>
      <td style="white-space:nowrap">${fmtTime(t.gen_time)}</td>
      <td>${escapeHTML(t.tsa_subject || '—')}</td>
      <td style="white-space:nowrap">${t.tsa_not_after ? fmtTime(t.tsa_not_after) : '—'}</td>
    </tr>`).join('');
  out.innerHTML =
    `<div class="notice ok"><b>${escapeHTML(res.id || '')}</b> — ${escapeHTML(res.scope || '')} scope, ` +
    `ERS version ${info.version || 0}, ${info.chains || 0} chain(s), ` +
    `digests ${escapeHTML((info.digest_algorithms || []).join(', '))} (current ${escapeHTML(info.current_hash || '')}), ` +
    `first stamped ${fmtTime(info.first_gen_time)}, latest ${fmtTime(info.latest_gen_time)}, ` +
    `${res.size || 0} bytes of DER.</div>` +
    (stamps
      ? `<table style="margin-top:8px"><thead><tr><th>Chain</th><th>Index</th><th>Algorithm</th><th>Stamped</th><th>TSA</th><th>TSA expires</th></tr></thead><tbody>${stamps}</tbody></table>`
      : '<p class="muted">This record carries no archive time-stamp.</p>');
  if (res.record) {
    const dl = document.createElement('button');
    dl.className = 'btn ghost sm';
    dl.style.marginTop = '8px';
    dl.textContent = 'Download evidence record (DER)';
    dl.onclick = () => downloadBlob(unb64(res.record), `evidence-record-${res.id}.der`, 'application/octet-stream');
    out.appendChild(dl);
  }
}

$('ersRefresh').onclick = () => { ersOffset = 0; loadEvidenceRecords(); };
$('ersLimit').onchange = () => { ersOffset = 0; loadEvidenceRecords(); };
$('ersPrev').onclick = () => {
  ersOffset = Math.max(0, ersOffset - (parseInt($('ersLimit').value, 10) || 200));
  loadEvidenceRecords();
};
$('ersNext').onclick = () => {
  ersOffset += parseInt($('ersLimit').value, 10) || 200;
  loadEvidenceRecords();
};

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
  $('svidJWTVerifyPanel').classList.add('hidden');
  // A verdict belongs to the CA it was reached under, so it does not survive a
  // change of issuer.
  $('svidVerifyResult').classList.add('hidden');
  $('svidVerifyError').classList.add('hidden');
  try {
    const bundle = await api('GET', `/api/ca/${id}/svid/bundle`, undefined, true);
    $('svidBundle').value = bundle;
    $('svidPanel').classList.remove('hidden');
    $('svidMintPanel').classList.remove('hidden');
    $('svidJWTPanel').classList.remove('hidden');
    $('svidJWTVerifyPanel').classList.remove('hidden');
  } catch (_) { /* SPIFFE not enabled for this server */ }
  loadAlternateChains(id);
}

// loadAlternateChains lists every path to a trust anchor for this CA: the native
// chain plus one per cross-signature. A client that trusts only an older root
// validates the same leaf through the alternate, which is the whole point of
// cross-signing — so each is offered as a downloadable bundle.
async function loadAlternateChains(id) {
  const tbody = $('altChainRows');
  if (!tbody) return;
  try {
    const res = await api('GET', `/api/ca/${id}/chains`);
    const chains = res.chains || [];
    if (!chains.length) { tbody.innerHTML = '<tr><td colspan="4" class="muted">No chains published for this CA.</td></tr>'; return; }
    tbody.innerHTML = chains.map((c, i) => `<tr>
      <td>${c.native ? 'native <span class="muted">(primary)</span>' : 'cross-sign'}</td>
      <td>${escapeHTML(c.issuer_label || c.issuer_ca_id || '')}</td>
      <td>${(c.pem.match(/BEGIN CERTIFICATE/g) || []).length} certs</td>
      <td><button class="btn ghost sm" data-altchain="${i}">Download PEM</button></td>
    </tr>`).join('');
    tbody.querySelectorAll('[data-altchain]').forEach(b => b.onclick = () => {
      const c = chains[parseInt(b.dataset.altchain, 10)];
      downloadBlob(c.pem, `chain-${c.native ? 'native' : 'crosssign'}-${b.dataset.altchain}.pem`, 'application/x-pem-file');
    });
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="4" class="muted">Unavailable (${escapeHTML(e.message)}).</td></tr>`;
  }
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

// Validate a JWT-SVID against this CA's trust bundle — mirrors
// `secsy-ca svid jwt-verify`. A rejected token is a verdict, not a fault: the
// server answers 409 with the same body shape, so postVerdict recovers it and the
// rejection is rendered as a clear failure with the server's reason.
$('svidVerifyBtn').onclick = async () => {
  const id = $('bundleCA').value;
  const err = $('svidVerifyError'), out = $('svidVerifyResult'), btn = $('svidVerifyBtn');
  err.classList.add('hidden');
  out.classList.add('hidden');
  const token = $('svidVerifyToken').value.trim();
  const aud = $('svidVerifyAud').value.trim();
  if (!token) { showError(err, 'Paste the JWT-SVID to validate.'); return; }
  // The audience is mandatory by the SPIFFE spec: a validator must reject a token
  // not addressed to it, and defaulting this would quietly turn that rule off.
  if (!aud) { showError(err, 'An audience is required — a JWT-SVID must be addressed to its validator.'); return; }
  const body = { token, audience: aud };
  const domains = csvList($('svidVerifyDomains').value);
  if (domains.length) body.trust_domains = domains;
  btn.disabled = true;
  try {
    const res = await postVerdict(`/api/ca/${id}/svid/jwt/verify`, body);
    renderJWTSVIDVerdict(out, res);
  } catch (e) { showError(err, e.message); }
  finally { btn.disabled = false; }
};

// renderJWTSVIDVerdict paints the verdict. On a negative one only valid/reason are
// set, so the reason is the whole answer and nothing else is invented around it.
function renderJWTSVIDVerdict(el, res) {
  el.className = 'notice ' + (res.valid ? 'ok' : 'err');
  if (!res.valid) {
    el.innerHTML = '<div style="font-size:15px"><b>✗ rejected</b></div>' +
      `<div style="margin-top:6px">${escapeHTML(res.reason || 'the token did not validate')}</div>`;
    el.classList.remove('hidden');
    return;
  }
  const rows = [
    ['SPIFFE ID', escapeHTML(res.spiffe_id || '')],
    ['Trust domain', escapeHTML(res.trust_domain || '')],
    ['Path', escapeHTML(res.path || '')],
    ['Audience', (res.audience || []).map(a => `<code>${escapeHTML(a)}</code>`).join(' ')],
    ['Signed by', `<span class="mono">${escapeHTML(res.key_id || '')}</span> (${escapeHTML(res.algorithm || '')})`],
    ['Issued', res.issued_at ? escapeHTML(fmtTime(res.issued_at)) : '<span class="muted">no iat claim</span>'],
    ['Expires', res.expires_at ? escapeHTML(fmtTime(res.expires_at)) : '<span class="muted">—</span>'],
  ];
  el.innerHTML = '<div style="font-size:15px"><b>✓ valid</b></div>' +
    '<table style="margin-top:8px"><tbody>' + rows.map(([k, v]) =>
      `<tr><th style="text-align:left;width:150px">${k}</th><td>${v}</td></tr>`).join('') + '</tbody></table>';
  el.classList.remove('hidden');
}

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
    let text = `KEK ${info.kek_label} (family ${info.kek_family} v${info.kek_version}) · ${info.provider} · ` +
      `${info.key_bits}-bit · wrap ${info.wrap_alg} · data ${info.data_alg}`;
    // Post-quantum hybrid state (Task 137): "available" means the ML-KEM material
    // is provisioned, "enabled" that new envelopes actually carry an
    // encapsulation. Both are reported because a deployment that provisioned the
    // material and forgot to enable it has harvest-now-decrypt-later exposure it
    // believes it does not have.
    if (info.pqc_hybrid_available) {
      text += ` · PQC hybrid ${info.pqc_kem || 'ml-kem'} ${info.pqc_hybrid_enabled ? 'enabled' : 'provisioned but OFF'}`;
    }
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
    // Escrow-on-write is offered for stored secrets on the same condition as
    // ad-hoc encryption: only when the deployment actually has recovery agents.
    $('storeEscrowLabel').classList.toggle('hidden', !info.escrow_available);
    loadSigningKeys();
  } catch (e) {
    // 404 when the feature is disabled (routes not registered).
    $('secretDisabled').classList.remove('hidden');
    $('secretInfo').textContent = '';
    secretServiceEnabled = false;
    if ($('sigKeysSection')) $('sigKeysSection').classList.add('hidden');
  }
}

// loadSecretsPage refreshes every panel on the Secrets view. Each loader is
// independently fault-tolerant: the secret layer's capabilities are split
// (decrypt / encrypt / rotate / signing-key), so an operator holding only some
// of them still gets a working page with the rest reporting why.
function loadSecretsPage() {
  loadSigningKeys();
  loadStoredSecrets();
  loadSecretLifecycle();
  loadKEKStatus();
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

// Adoption of an existing key (Task 198): the console half of `secsy-secret
// signing-key import`, and the one control on this page whose request body
// carries a private key. The material is read from the field, sent once, and the
// field is cleared the moment the server confirms — nothing keeps key material in
// the DOM, and the response (which never contains any) is rendered as metadata.
$('sigKeyImportBtn').onclick = async () => {
  const err = $('sigKeyImportError');
  err.classList.add('hidden');
  const out = $('sigKeyImportResult');
  out.textContent = '';
  out.style.color = '';
  const name = $('sigKeyImportName').value.trim();
  const material = $('sigKeyImportPem').value.trim();
  if (!name) { showError(err, 'A key name is required.'); return; }
  if (!material) { showError(err, 'Paste the existing private key.'); return; }
  const body = { name };
  // PEM travels as text; anything else is treated as base64 of a raw container
  // (bare DER, PKCS#12) — the same discrimination the CLI's file loader makes on
  // the bytes it read.
  if (material.includes('-----BEGIN')) body.key_pem = material;
  else body.key_base64 = material;
  if ($('sigKeyImportAlg').value) body.algorithm = $('sigKeyImportAlg').value;
  if ($('sigKeyImportPass').value) body.passphrase = $('sigKeyImportPass').value;
  const btn = $('sigKeyImportBtn');
  btn.disabled = true;
  try {
    const k = await api('POST', '/api/secret/signing-keys/import', body);
    $('sigKeyImportPem').value = '';
    $('sigKeyImportPass').value = '';
    $('sigKeyImportName').value = '';
    out.style.color = 'var(--ok)';
    out.textContent = `✓ imported ${k.name} · ${k.algorithm} · ${k.key_type} · held by ${k.provider}`
      + ' — attestation will report this key as imported rather than generated. Destroy the remaining copies of it.';
    // The public half is the useful output, and it goes to the same box the
    // create form fills, so verifiers are handed it the same way.
    $('sigKeyPub').value = k.public_key_pem || '';
    $('sigKeyPubBox').classList.remove('hidden');
    $('sigKeyPubDownload').onclick = (e) => { e.preventDefault(); downloadBlob(k.public_key_pem || '', k.name + '.pub.pem', 'application/x-pem-file'); };
    $('sigKeyName').value = k.name;
    await loadSigningKeys();
  } catch (e) { showError(err, 'Import failed: ' + e.message); }
  finally { btn.disabled = false; }
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

// Verification takes two forms and the console picks by what was filled in: a
// pasted public key verifies without any stored key at all, which is what a
// relying party outside this PKI actually has. Otherwise the named key's public
// half is used server-side.
$('sigVerifyBtn').onclick = async () => {
  const err = $('sigError'); err.classList.add('hidden');
  const sig = $('sigOut').value.trim();
  if (!sig) { showError(err, 'A base64 signature is required — sign first, or paste one.'); return; }
  const pub = $('sigVerifyPub').value.trim();
  const name = $('sigKeyName').value.trim();
  if (!pub && !name) { showError(err, 'A key name or a supplied public key is required.'); return; }
  const body = { message: b64(new TextEncoder().encode($('sigMessage').value)), signature: sig };
  if ($('sigHash').value) body.hash = $('sigHash').value;
  try {
    let res;
    if (pub) {
      const alg = $('sigVerifyAlg').value;
      if (!alg) { showError(err, 'Verifying against a supplied public key needs its algorithm.'); return; }
      res = await api('POST', '/api/secret/verify', { ...body, public_key_pem: pub, algorithm: alg });
    } else {
      res = await api('POST', `/api/secret/signing-keys/${encodeURIComponent(name)}/verify`, body);
    }
    const el = $('sigVerifyResult');
    el.style.color = res.valid ? 'var(--ok)' : 'var(--crit)';
    el.textContent = res.valid
      ? `✓ valid signature (${res.algorithm}${pub ? ', supplied key' : ''})`
      : '✗ INVALID — signature does not match';
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

// ---- Hardware security module (Tasks 167/168/189) ------------------------
// Three claims, kept visually separate because they establish different things:
// the device is genuine hardware (device attestation), a key on it was born
// there and cannot leave (key attestation), and every signature it produced is
// accounted for (audit log). None implies the others.

// checkList renders the itemized verdict both attestation kinds carry.
function checkList(checks) {
  if (!checks || !checks.length) return '';
  return `<table style="margin-top:8px"><thead><tr><th></th><th>Check</th><th>Detail</th></tr></thead><tbody>` +
    checks.map(c => `<tr>
      <td style="color:${c.passed ? 'var(--ok)' : 'var(--crit)'}">${c.passed ? '✓' : '✗'}</td>
      <td class="mono">${escapeHTML(c.name)}</td>
      <td class="muted">${escapeHTML(c.detail || '')}</td>
    </tr>`).join('') + '</tbody></table>';
}

// findingList renders problems and warnings, in that order of urgency.
function findingList(res) {
  let out = '';
  (res.problems || []).forEach(p => { out += `<div style="color:var(--crit)">✗ ${escapeHTML(p)}</div>`; });
  (res.warnings || []).forEach(w => { out += `<div class="muted">⚠ ${escapeHTML(w)}</div>`; });
  return out;
}

// renderDeviceVerdict leads with the serial: it is the answer the operation
// exists to produce, and burying it under a checklist would miss the point.
function renderDeviceVerdict(el, res) {
  el.className = 'notice ' + (res.verified ? 'ok' : 'err');
  el.innerHTML =
    `<div style="font-size:15px"><b>${res.verified ? '✓ genuine YubiHSM' : '✗ NOT ESTABLISHED'}</b>` +
    (res.serial ? ` — serial <b class="mono">${escapeHTML(res.serial)}</b>` : '') + '</div>' +
    `<div class="muted">${escapeHTML(res.summary || '')}</div>` +
    `<div class="muted" style="margin-top:6px">` +
      `chain anchored: ${res.chain_anchored ? 'yes' : 'no'}` +
      (res.trust_anchor ? ` (${escapeHTML(res.trust_anchor)})` : '') +
      ` · proof of possession: ${res.proof_of_possession ? 'yes' : 'no'}` +
      (res.firmware_version ? ` · firmware ${escapeHTML(res.firmware_version)}` : '') +
    '</div>' +
    findingList(res) + checkList(res.checks);
  el.classList.remove('hidden');
}

// renderKeyVerdict leads with the two properties that decide whether a CA key
// is really confined to hardware.
function renderKeyVerdict(el, res) {
  el.className = 'notice ' + (res.verified ? 'ok' : 'err');
  el.innerHTML =
    `<div style="font-size:15px"><b>${res.verified ? '✓ attested' : '✗ NOT ESTABLISHED'}</b>` +
    (res.key_label ? ` — <span class="mono">${escapeHTML(res.key_label)}</span>` : '') + '</div>' +
    `<div class="muted">${escapeHTML(res.summary || '')}</div>` +
    `<div class="muted" style="margin-top:6px">` +
      `non-exportable: ${res.non_exportable ? 'yes' : '<b>NO</b>'}` +
      ` · generated on device: ${res.generated_on_device ? 'yes' : '<b>NO</b>'}` +
      ` · device-bound: ${res.device_bound ? 'yes' : 'no'}` +
      ` · chain anchored: ${res.chain_anchored ? 'yes' : 'no'}` +
      (res.device_serial ? ` · device ${escapeHTML(res.device_serial)}` : '') +
      (res.spki_fingerprint ? `<br>SPKI ${escapeHTML(res.spki_fingerprint)}` : '') +
    '</div>' +
    findingList(res) + checkList(res.checks);
  el.classList.remove('hidden');
}

// lastAttestation keeps the most recent bundle so it can be downloaded and
// handed to an auditor — the evidence, not just this server's conclusion.
let lastAttestation = null;

async function loadHSM() {
  const msg = $('hsmMsg');
  msg.className = 'notice hidden';
  // The CA dropdown mirrors the other pages: only X.509 CAs have a key label to
  // resolve, and the key-attestation endpoint says so plainly if one does not.
  $('hsmAttestCA').innerHTML = x509CAs.map(c => `<option value="${c.id}">${escapeHTML(c.label)}</option>`).join('');
  try {
    const info = await api('GET', '/api/hsm/info');
    $('hsmDisabled').classList.add('hidden');
    $('hsmBody').classList.remove('hidden');
    if (!info.available) {
      $('hsmInfo').innerHTML = `<span style="color:var(--crit)">device unreachable</span>` +
        (info.error ? `<div class="muted">${escapeHTML(info.error)}</div>` : '');
    } else {
      $('hsmInfo').innerHTML =
        `serial <b class="mono">${escapeHTML(info.serial || '?')}</b><br>` +
        `firmware ${escapeHTML(info.version || '?')}${info.part_number ? ' · ' + escapeHTML(info.part_number) : ''}<br>` +
        `log ${escapeHTML(info.log_used || '?')} · forced audit ${info.force_audit ? 'on' : 'off'} · ` +
        `audit subsystem ${info.audit_provisioned ? 'provisioned' : 'not provisioned'}` +
        `<div class="muted" style="margin-top:6px">This serial is the device's own claim over the session. ` +
        `Attest it below to have Yubico's attestation CA certify it instead.</div>`;
    }
  } catch (e) {
    // The /api/hsm/* routes exist only when a YubiHSM is configured.
    $('hsmDisabled').classList.remove('hidden');
    $('hsmBody').classList.add('hidden');
    return;
  }
  loadHSMAuditStatus();
  loadHSMKeyLabels();
}

// loadHSMKeyLabels fills the datalist behind the free-text label field, so
// attesting an arbitrary key (`secsy-ca hsm-attest key`) is a pick rather than a
// recollection. It stays a convenience only: the field remains free text, because
// an object the inventory cannot enumerate is exactly the one worth attesting.
async function loadHSMKeyLabels() {
  try {
    const inv = await api('GET', '/api/inventory/keys');
    $('hsmAttestLabels').innerHTML = (inv.keys || []).map(k => {
      const hint = [k.key_type, k.ca_label].filter(Boolean).join(' · ');
      return `<option value="${escapeHTML(k.label)}">${escapeHTML(hint)}</option>`;
    }).join('');
  } catch (_) { /* 403 for non-admins, 501 when the provider cannot enumerate keys */ }
}

async function loadHSMAuditStatus() {
  const el = $('hsmAuditStatus');
  try {
    const st = await api('GET', '/api/hsm/audit-status');
    if (!st.provisioned) {
      el.innerHTML = '<span class="muted">Not provisioned. Until the device is commissioned for forced audit logging, ' +
        'nothing proves the log is complete — provisioning is irreversible and needs a factory-reset device.</span>';
      return;
    }
    const gap = (st.signatures || 0) - (st.ledger_entries || 0);
    el.innerHTML =
      `anchor <span class="mono">${escapeHTML((st.anchor || '').slice(0, 24))}…</span><br>` +
      `${st.stored_entries} entries collected · ${st.signatures} signature(s) on the device · ` +
      `${st.ledger_entries} recorded by the CA ` +
      (gap === 0
        ? '<span style="color:var(--ok)">✓ reconciled</span>'
        : `<span style="color:var(--crit)"><b>✗ ${Math.abs(gap)} unaccounted</b></span>`) + '<br>' +
      `<span class="muted">${st.freshness_proofs || 0} timestamp(s)` +
      (st.last_attested_at ? `, newest ${fmtTime(st.last_attested_at)}` : '') +
      ` · ${st.commitments || 0} serial binding(s)` +
      (st.last_committed_at ? `, newest ${fmtTime(st.last_committed_at)}` : '') + '</span>' +
      (st.options_error ? `<div style="color:var(--crit)">✗ ${escapeHTML(st.options_error)}</div>` : '');
  } catch (e) {
    el.innerHTML = `<span class="muted">Unavailable (${escapeHTML(e.message)}).</span>`;
  }
}
$('hsmRefresh').onclick = loadHSM;

// downloadAPI streams an authenticated download through the API helper, since a
// bare <a href> would carry no Authorization header or session CSRF token.
async function downloadAPI(path, filename, type) {
  const msg = $('hsmMsg');
  msg.className = 'notice hidden';
  try {
    const text = await api('GET', path, undefined, true);
    downloadBlob(text, filename, type || 'application/json');
  } catch (e) {
    showError(msg, `${filename}: ${e.message}`); msg.className = 'notice err';
  }
}
$('hsmDevCertBtn').onclick = () => downloadAPI('/api/hsm/attestation', 'device-attestation.pem', 'application/x-pem-file');
$('hsmBundleBtn').onclick = () => downloadAPI('/api/hsm/audit-bundle', 'hsm-audit-bundle.json');
$('hsmSignedLogBtn').onclick = () => downloadAPI('/api/hsm/signed-audit-log', 'signed-audit-log.json');
$('hsmCombinedLogBtn').onclick = () => downloadAPI('/api/hsm/combined-audit-log', 'combined-audit-log.json');

$('hsmProvisionBtn').onclick = async () => {
  if (!confirm('Provision this device for forced audit logging?\n\nThis is IRREVERSIBLE: the device will refuse to sign once its log fills, and the setting cannot be turned off without a factory reset that destroys every key on it.')) return;
  const msg = $('hsmMsg');
  msg.className = 'notice hidden';
  try {
    const res = await api('POST', '/api/hsm/provision-audit', {});
    msg.textContent = `Provisioned. ${res.output || ''}`;
    msg.className = 'notice ok';
    loadHSM();
  } catch (e) { showError(msg, 'Provisioning failed: ' + e.message); msg.className = 'notice err'; }
};

// Device authenticity: the challenge is what separates "this certificate is
// genuine" from "this device is genuine", so it happens unless explicitly opted
// out of, and the verdict says which of the two was established.
$('hsmAttestDeviceBtn').onclick = async () => {
  const err = $('hsmDeviceError'); err.classList.add('hidden');
  const btn = $('hsmAttestDeviceBtn');
  const body = {};
  const ch = $('hsmChallenge').value.trim();
  if ($('hsmNoChallenge').checked) body.no_challenge = true;
  else if (ch) body.challenge = ch;
  const exp = $('hsmExpectSerial').value.trim();
  if (exp) body.expected_serial = exp;
  btn.disabled = true;
  try {
    const res = await api('POST', '/api/hsm/attest-device', body);
    lastAttestation = res.attestation;
    renderDeviceVerdict($('hsmDeviceResult'), res.verification || {});
    // Offer the evidence, not only the conclusion.
    const el = $('hsmDeviceResult');
    const dl = document.createElement('button');
    dl.className = 'btn ghost sm';
    dl.style.marginTop = '8px';
    dl.textContent = 'Download bundle';
    dl.onclick = () => downloadBlob(JSON.stringify(res.attestation, null, 2), 'device-attestation.json', 'application/json');
    el.appendChild(dl);
  } catch (e) { showError(err, 'Attestation failed: ' + e.message); }
  finally { btn.disabled = false; }
};

async function attestKey(path, btn) {
  const err = $('hsmKeyError'); err.classList.add('hidden');
  btn.disabled = true;
  try {
    const res = await api('GET', path);
    lastAttestation = res.attestation;
    renderKeyVerdict($('hsmKeyResult'), res.verification || {});
    const el = $('hsmKeyResult');
    const dl = document.createElement('button');
    dl.className = 'btn ghost sm';
    dl.style.marginTop = '8px';
    dl.textContent = 'Download attestation';
    dl.onclick = () => downloadBlob(JSON.stringify(res.attestation, null, 2), 'key-attestation.json', 'application/json');
    el.appendChild(dl);
  } catch (e) { showError(err, 'Attestation failed: ' + e.message); }
  finally { btn.disabled = false; }
}
$('hsmAttestCABtn').onclick = () => {
  const id = $('hsmAttestCA').value;
  if (!id) { showError($('hsmKeyError'), 'Select a CA.'); return; }
  attestKey(`/api/ca/${encodeURIComponent(id)}/key-attestation`, $('hsmAttestCABtn'));
};
$('hsmAttestLabelBtn').onclick = () => {
  const label = $('hsmAttestLabel').value.trim();
  if (!label) { showError($('hsmKeyError'), 'A key label is required.'); return; }
  attestKey(`/api/hsm/keys/${encodeURIComponent(label)}/attestation`, $('hsmAttestLabelBtn'));
};

// Device-wide attestation audit (Task 198): the console half of `secsy-ca
// hsm-attest audit`. One key that could not be attested is a row carrying its
// error, not a failed request, so the operator still sees the verdict on every
// other key — which is the whole point of an inventory pass.
$('hsmAuditAttestBtn').onclick = async () => {
  const err = $('hsmAuditAttestError');
  err.classList.add('hidden');
  const btn = $('hsmAuditAttestBtn');
  const sum = $('hsmAuditAttestSummary');
  btn.disabled = true;
  sum.textContent = 'Attesting every key on the device…';
  try {
    renderAttestationAudit(await api('GET', '/api/hsm/attestation-audit'));
  } catch (e) {
    sum.textContent = 'Not run.';
    showError(err, 'Attestation audit failed: ' + e.message);
  } finally { btn.disabled = false; }
};

// renderAttestationAudit draws the rollup and the per-key verdict table, with the
// same columns the CLI's audit table prints.
function renderAttestationAudit(res) {
  const keys = res.keys || [];
  const bad = (res.failed || 0) + (res.errors || 0);
  $('hsmAuditAttestSummary').innerHTML =
    `<span style="color:var(--${bad ? 'crit' : 'ok'})">${bad ? '✗' : '✓'} ${escapeHTML(res.summary || '')}</span>` +
    ` <span class="muted">· ${res.verified || 0} verified · ${res.exportable || 0} exportable · ` +
    `${res.imported || 0} imported · provider ${escapeHTML(res.provider || '')}</span>`;
  const tbody = $('hsmAuditAttestRows');
  if (!keys.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted">No keys on the device.</td></tr>';
  } else {
    tbody.innerHTML = keys.map(k => {
      const v = k.verification || {};
      let verdict;
      if (k.error) verdict = `<span style="color:var(--crit)">ERROR: ${escapeHTML(k.error)}</span>`;
      else if (v.verified) verdict = '<span style="color:var(--ok)">ok</span>';
      else verdict = `<span style="color:var(--crit)">FAIL: ${escapeHTML((v.problems || [])[0] || 'did not satisfy policy')}</span>`;
      return `<tr>
        <td class="mono">${escapeHTML(k.label || '')}${k.key_type ? `<br><span class="muted">${escapeHTML(k.key_type)}</span>` : ''}</td>
        <td>${escapeHTML(k.ca_label || '')}</td>
        <td>${k.error ? '<span class="muted">?</span>'
                      : (v.non_exportable ? 'no' : '<b style="color:var(--crit)">yes</b>')}</td>
        <td>${escapeHTML(v.origin || '')}</td>
        <td class="muted">${escapeHTML((v.capabilities || []).join(', '))}</td>
        <td>${verdict}</td>
      </tr>`;
    }).join('');
  }
  $('hsmAuditAttestResult').classList.remove('hidden');
}

// Verification routes on the bundle's own "kind" marker rather than on which
// fields happen to be populated — the same discrimination the CLI verifier
// makes, and for the same reason: reading a device bundle as a key attestation
// would report a pile of missing fields instead of a serial number.
$('hsmVerifyBtn').onclick = async () => {
  const err = $('hsmVerifyError'); err.classList.add('hidden');
  $('hsmVerifyResult').classList.add('hidden');
  const raw = $('hsmVerifyInput').value.trim();
  if (!raw) { showError(err, 'Paste an attestation bundle.'); return; }
  let parsed;
  try { parsed = JSON.parse(raw); }
  catch (_) { showError(err, 'That is not a JSON attestation bundle. Export one from this page, or use "secsy-ca hsm-attest verify" for a bare PEM.'); return; }
  // An exported response wraps the bundle; a bare bundle is also accepted.
  const att = parsed.attestation || parsed;
  try {
    let res;
    if (att.kind === 'yubihsm-device-attestation' || att.challenge_certificate_pem) {
      const body = { attestation: att };
      if ($('hsmVerifyChallenge').value.trim()) body.expected_challenge = $('hsmVerifyChallenge').value.trim();
      if ($('hsmVerifySerial').value.trim()) body.expected_serial = $('hsmVerifySerial').value.trim();
      if ($('hsmVerifyAllowNoChallenge').checked) body.allow_no_challenge = true;
      res = await api('POST', '/api/hsm/device-attestation:verify', body);
      renderDeviceVerdict($('hsmVerifyResult'), res.verification || {});
    } else {
      const body = {
        certificate_pem: att.certificate_pem,
        device_certificate_pem: att.device_certificate_pem,
      };
      if ($('hsmVerifySerial').value.trim()) body.expected_serial = $('hsmVerifySerial').value.trim();
      if ($('hsmVerifyKey').value.trim()) body.expected_public_key_pem = $('hsmVerifyKey').value.trim();
      res = await api('POST', '/api/hsm/attestation:verify', body);
      renderKeyVerdict($('hsmVerifyResult'), res.verification || {});
    }
  } catch (e) { showError(err, 'Verification failed: ' + e.message); }
};

// hsmCommandName maps the YubiHSM command byte onto its name. Only the commands
// a CA deployment actually produces are named; anything else shows as its byte,
// which is still enough to look up in the device reference.
const HSM_COMMANDS = {
  0x03: 'session-open', 0x04: 'session-auth', 0x05: 'session-cmd', 0x06: 'device-info',
  0x08: 'reset', 0x40: 'close-session', 0x41: 'get-storage-info', 0x43: 'put-opaque',
  0x44: 'get-opaque', 0x45: 'put-authkey', 0x46: 'put-asymmetric-key', 0x47: 'generate-asymmetric-key',
  0x48: 'sign-pkcs1', 0x49: 'list-objects', 0x4a: 'decrypt-pkcs1', 0x4b: 'export-wrapped',
  0x4c: 'import-wrapped', 0x4d: 'put-wrap-key', 0x4e: 'get-log-entries', 0x4f: 'get-object-info',
  0x50: 'set-option', 0x51: 'get-option', 0x52: 'get-pseudo-random', 0x53: 'put-hmac-key',
  0x54: 'sign-hmac', 0x55: 'get-public-key', 0x56: 'sign-pss', 0x57: 'sign-ecdsa',
  0x58: 'derive-ecdh', 0x59: 'delete-object', 0x5a: 'decrypt-oaep', 0x5b: 'generate-hmac-key',
  0x5c: 'generate-wrap-key', 0x5d: 'verify-hmac', 0x5e: 'sign-ssh-certificate', 0x5f: 'put-template',
  0x60: 'get-template', 0x61: 'decrypt-otp', 0x64: 'attest-asymmetric-key', 0x65: 'put-otp-aead-key',
  0x67: 'set-log-index', 0x6a: 'sign-eddsa', 0x6b: 'blink-device', 0x6c: 'change-authkey',
};
function hsmCommandName(c) {
  return HSM_COMMANDS[c] || '0x' + Number(c).toString(16).padStart(2, '0');
}

$('hsmLogRefresh').onclick = async () => {
  const tbody = $('hsmLogRows');
  tbody.innerHTML = '<tr><td colspan="7" class="muted">Loading…</td></tr>';
  try {
    const res = await api('GET', '/api/hsm/audit-log');
    const entries = res.entries || [];
    if (!entries.length) { tbody.innerHTML = '<tr><td colspan="7" class="muted">The device log is empty.</td></tr>'; return; }
    tbody.innerHTML = entries.map(e => `<tr>
      <td>${e.number}</td>
      <td class="mono">${escapeHTML(hsmCommandName(e.command))}</td>
      <td class="mono">0x${Number(e.session_key || 0).toString(16).padStart(4, '0')}</td>
      <td class="mono">0x${Number(e.target_key || 0).toString(16).padStart(4, '0')}</td>
      <td>${e.result === 0x83 ? '<span style="color:var(--ok)">ok</span>' : '0x' + Number(e.result).toString(16)}</td>
      <td>${e.tick}</td>
      <td class="mono">${escapeHTML((e.hash || '').slice(0, 16))}…${e.hash_valid === false ? ' <span style="color:var(--crit)">✗ chain broken</span>' : ''}</td>
    </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">Unavailable (${escapeHTML(e.message)}).</td></tr>`;
  }
};

// ---- Format-preserving encryption / tokenization (Task 144) ---------------
// encode/decode a value through a named FF1 template. Success and failure both
// land in the same result box; the deterministic flag matters because it is what
// decides whether tokens can be searched on.
async function runTransform(direction) {
  const err = $('fpeError'); err.classList.add('hidden');
  $('fpeOut').value = ''; $('fpeMeta').textContent = '';
  const template = $('fpeTemplate').value.trim();
  const value = $('fpeValue').value;
  if (!template || !value) { showError(err, 'A template and a value are required.'); return; }
  const body = { template, value };
  const tweak = $('fpeTweak').value;
  if (tweak) body.tweak = b64(new TextEncoder().encode(tweak));
  try {
    const res = await api('POST', `/api/secret/transform/${direction}`, body);
    $('fpeOut').value = res.result;
    $('fpeMeta').textContent = `${direction}d through “${res.template}”` +
      (res.deterministic ? ' · deterministic (tokens are searchable)' : ' · randomized');
  } catch (e) { showError(err, `${direction} failed: ${e.message}`); }
}
$('fpeEncodeBtn').onclick = () => runTransform('encode');
$('fpeDecodeBtn').onclick = () => runTransform('decode');

// ---- Stored-secret registry (Tasks 72/73) --------------------------------
// The registry holds named envelopes server-side. Reading a value is two calls
// by design — fetch the envelope, then decrypt it — because the decrypt gate is
// where the secret layer authorizes and audits plaintext access; the console
// must not be able to shortcut it.
let storedSecrets = [];

async function loadStoredSecrets() {
  const tbody = $('storeRows');
  if (!tbody) return;
  try {
    const res = await api('GET', '/api/secret/store');
    storedSecrets = res.secrets || [];
    if (!storedSecrets.length) { tbody.innerHTML = '<tr><td colspan="8" class="muted">No stored secrets yet.</td></tr>'; return; }
    tbody.innerHTML = storedSecrets.map(s => `<tr>
      <td class="mono">${escapeHTML(s.name)}</td>
      <td>v${s.current_version}</td>
      <td>${escapeHTML(s.kek_label || '')} v${s.kek_version}</td>
      <td>${s.escrowed ? 'yes' : '—'}</td>
      <td>${s.expires_at ? fmtTime(s.expires_at) : '—'}</td>
      <td>${s.rotate_every_days > 0 ? s.rotate_every_days + 'd' : '—'}</td>
      <td>${s.value_changed_at ? fmtTime(s.value_changed_at) : fmtTime(s.created_at)}</td>
      <td>
        <button class="btn ghost sm" data-secret-reveal="${escapeHTML(s.id)}" title="Fetch the envelope and decrypt it">Reveal</button>
        <button class="btn ghost sm" data-secret-versions="${escapeHTML(s.id)}">Versions</button>
        <button class="btn ghost sm" data-secret-edit="${escapeHTML(s.id)}" title="Load this secret's name into the form">Update</button>
        <button class="btn ghost sm" data-secret-del="${escapeHTML(s.id)}">Delete</button>
      </td>
    </tr>`).join('');
    tbody.querySelectorAll('[data-secret-reveal]').forEach(b => b.onclick = () => revealStoredSecret(b.dataset.secretReveal));
    tbody.querySelectorAll('[data-secret-versions]').forEach(b => b.onclick = () => loadSecretVersions(b.dataset.secretVersions));
    tbody.querySelectorAll('[data-secret-edit]').forEach(b => b.onclick = () => {
      const s = storedSecrets.find(x => x.id === b.dataset.secretEdit);
      if (s) { $('storeName').value = s.name; $('storeValue').focus(); }
    });
    tbody.querySelectorAll('[data-secret-del]').forEach(b => b.onclick = () => deleteStoredSecret(b.dataset.secretDel));
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="8" class="muted">The stored-secret registry needs the secret:decrypt capability (${escapeHTML(e.message)}).</td></tr>`;
  }
}

// secretByID resolves a row for the labels below without a second round-trip.
function secretByID(id) { return storedSecrets.find(s => s.id === id) || { id, name: id }; }

// revealStoredSecret fetches the envelope and runs it back through the decrypt
// endpoint. A context-bound secret cannot be revealed here without its AAD, so
// the shared Context field is offered as the source.
async function revealStoredSecret(id, version) {
  const err = $('storeError'); err.classList.add('hidden');
  const s = secretByID(id);
  try {
    const path = version
      ? `/api/secret/store/${encodeURIComponent(id)}/versions/${version}`
      : `/api/secret/store/${encodeURIComponent(id)}`;
    const rec = await api('GET', path);
    const body = { envelope: rec.envelope };
    const ctx = $('storeContext').value;
    if (ctx) body.context = b64(new TextEncoder().encode(ctx));
    const out = await api('POST', '/api/secret/decrypt', body);
    $('storeRevealLabel').textContent = `Plaintext — ${s.name} v${version || rec.current_version || rec.version}`;
    $('storeReveal').value = new TextDecoder().decode(unb64(out.plaintext));
    $('storeRevealBox').classList.remove('hidden');
  } catch (e) {
    showError(err, `Reveal failed: ${e.message}` +
      (s.context_bound ? ' — this secret is context-bound; enter its context above first.' : ''));
  }
}

async function loadSecretVersions(id) {
  const err = $('storeError'); err.classList.add('hidden');
  try {
    const res = await api('GET', `/api/secret/store/${encodeURIComponent(id)}/versions`);
    $('storeHistName').textContent = `— ${res.name}`;
    const rows = (res.versions || []).map(v => `<tr>
      <td>v${v.version}${v.current ? ' <span class="muted">(current)</span>' : ''}</td>
      <td>${escapeHTML(v.kek_label || '')} v${v.kek_version}</td>
      <td>${escapeHTML(v.created_by || '')}</td>
      <td>${escapeHTML(v.comment || '')}</td>
      <td>${fmtTime(v.created_at)}</td>
      <td>
        <button class="btn ghost sm" data-ver-reveal="${v.version}">Reveal</button>
        ${v.current ? '' : `<button class="btn ghost sm" data-ver-roll="${v.version}" title="Append a copy of this version as the new current value">Roll back</button>`}
      </td>
    </tr>`).join('');
    $('storeHistRows').innerHTML = rows || '<tr><td colspan="6" class="muted">No versions.</td></tr>';
    $('storeHistTable').classList.remove('hidden');
    $('storeHistEmpty').classList.add('hidden');
    $('storeHistRows').querySelectorAll('[data-ver-reveal]').forEach(b =>
      b.onclick = () => revealStoredSecret(id, parseInt(b.dataset.verReveal, 10)));
    $('storeHistRows').querySelectorAll('[data-ver-roll]').forEach(b =>
      b.onclick = () => rollbackStoredSecret(id, parseInt(b.dataset.verRoll, 10)));
  } catch (e) { showError(err, 'Version history failed: ' + e.message); }
}

// rollbackStoredSecret makes an older value current again. History is never
// rewritten — the old value is appended as a new version — so the audit trail
// still shows that a rollback happened and when.
async function rollbackStoredSecret(id, version) {
  const s = secretByID(id);
  if (!confirm(`Make version ${version} of "${s.name}" current again?\n\nThe old value is appended as a new version; nothing in the history is rewritten.`)) return;
  const err = $('storeError'); err.classList.add('hidden');
  try {
    await api('POST', `/api/secret/store/${encodeURIComponent(id)}/rollback`,
      { version, comment: `rolled back to v${version} from the console` });
    await loadStoredSecrets();
    await loadSecretVersions(id);
  } catch (e) { showError(err, 'Rollback failed: ' + e.message); }
}

async function deleteStoredSecret(id) {
  const s = secretByID(id);
  if (!confirm(`Delete stored secret "${s.name}" and its entire version history?\n\nThis cannot be undone.`)) return;
  const err = $('storeError'); err.classList.add('hidden');
  try {
    await api('DELETE', `/api/secret/store/${encodeURIComponent(id)}`);
    $('storeHistTable').classList.add('hidden');
    $('storeHistEmpty').classList.remove('hidden');
    await loadStoredSecrets();
  } catch (e) { showError(err, 'Delete failed: ' + e.message); }
}

// storePutBtn creates a secret or appends a version to an existing one. Which
// of the two it is depends on whether the name is already taken, so the console
// resolves the name first rather than making the operator pick an endpoint.
$('storePutBtn').onclick = async () => {
  const err = $('storeError'); err.classList.add('hidden');
  const name = $('storeName').value.trim();
  if (!name) { showError(err, 'A name is required.'); return; }
  const ttl = parseInt($('storeTTL').value, 10);
  const rot = parseInt($('storeRotate').value, 10);
  const body = { plaintext: b64(new TextEncoder().encode($('storeValue').value)) };
  const ctx = $('storeContext').value;
  if (ctx) body.context = b64(new TextEncoder().encode(ctx));
  if ($('storeEscrow').checked) body.escrow = true;
  if (!isNaN(ttl)) body.ttl_days = ttl;
  if (!isNaN(rot)) body.rotate_every_days = rot;
  const comment = $('storeComment').value.trim();
  if (comment) body.comment = comment;
  $('storePutBtn').disabled = true;
  try {
    const existing = storedSecrets.find(s => s.name === name);
    if (existing) {
      await api('PUT', `/api/secret/store/${encodeURIComponent(existing.id)}`, body);
    } else {
      await api('POST', '/api/secret/store', { name, ...body });
    }
    $('storeValue').value = ''; $('storeComment').value = '';
    await loadStoredSecrets();
    await loadSecretLifecycle();
  } catch (e) { showError(err, 'Save failed: ' + e.message); }
  finally { $('storePutBtn').disabled = false; }
};
$('storeRefresh').onclick = loadStoredSecrets;

// severityClass maps a lifecycle severity onto the shared notice palette.
function severityClass(sev) {
  return sev === 'expired' || sev === 'critical' ? 'crit' : 'warn';
}

async function loadSecretLifecycle() {
  const tbody = $('lifecycleRows');
  if (!tbody) return;
  try {
    const res = await api('GET', '/api/secret/lifecycle');
    const items = res.items || [];
    if (!items.length) { tbody.innerHTML = '<tr><td colspan="7" class="muted">Nothing needs attention.</td></tr>'; return; }
    tbody.innerHTML = items.map(i => `<tr>
      <td class="mono">${escapeHTML(i.name)}</td>
      <td>${escapeHTML(i.state)}</td>
      <td><span class="badge ${severityClass(i.severity)}">${escapeHTML(i.severity)}</span></td>
      <td>v${i.current_version}</td>
      <td>${i.expires_at ? fmtTime(i.expires_at) : '—'}</td>
      <td>${i.rotation_due_at ? fmtTime(i.rotation_due_at) : '—'}</td>
      <td class="muted">${escapeHTML(i.detail || '')}</td>
    </tr>`).join('');
  } catch (e) {
    tbody.innerHTML = `<tr><td colspan="7" class="muted">Unavailable (${escapeHTML(e.message)}).</td></tr>`;
  }
}
$('lifecycleRefresh').onclick = loadSecretLifecycle;

// ---- KEK rotation lifecycle (Task 63) ------------------------------------
// Rotation is deliberately three steps — rotate, re-wrap, retire — because a
// version may only be withdrawn once nothing still depends on it. The console
// mirrors that: retire is offered per row, and the server refuses while secrets
// remain, which is the safety property worth surfacing rather than hiding.
async function loadKEKStatus() {
  const tbody = $('kekRows');
  if (!tbody) return;
  try {
    const st = await api('GET', '/api/secret/kek/status');
    $('kekSummary').textContent =
      `family ${st.family} · active v${st.active_version} (${st.active_label}) · ` +
      `${st.stored_secrets} stored secret(s), ${st.secrets_on_old_kek} not yet on the active version` +
      (st.never_rotated ? ' · never rotated' : '');
    const versions = st.versions || [];
    tbody.innerHTML = versions.map(v => `<tr>
      <td>v${v.version}</td>
      <td class="mono">${escapeHTML(v.label)}</td>
      <td>${escapeHTML(v.status)}</td>
      <td>${v.secrets}</td>
      <td>${v.status === 'retiring' ? `<button class="btn ghost sm" data-kek-retire="${v.version}">Retire</button>` : ''}</td>
    </tr>`).join('') || '<tr><td colspan="5" class="muted">No versions recorded.</td></tr>';
    tbody.querySelectorAll('[data-kek-retire]').forEach(b =>
      b.onclick = () => retireKEK(parseInt(b.dataset.kekRetire, 10)));
    $('kekError').classList.add('hidden');
  } catch (e) {
    $('kekSummary').textContent = '';
    tbody.innerHTML = `<tr><td colspan="5" class="muted">KEK rotation needs the secret:rotate capability (${escapeHTML(e.message)}).</td></tr>`;
  }
}
$('kekRefresh').onclick = loadKEKStatus;

function showKEKResult(text, cls) {
  const el = $('kekResult');
  el.textContent = text;
  el.className = 'notice ' + (cls || '');
}

$('kekRotateBtn').onclick = async () => {
  if (!confirm('Generate a new KEK version in the HSM and make it active?\n\nExisting envelopes keep decrypting under the retiring version; re-wrap moves them onto the new one.')) return;
  $('kekError').classList.add('hidden');
  $('kekRotateBtn').disabled = true;
  try {
    const res = await api('POST', '/api/secret/kek/rotate', { key_type: $('kekKeyType').value });
    showKEKResult(`Rotated ${res.family}: v${res.old_version} (${res.old_label}) → v${res.new_version} (${res.new_label}). Re-wrap next, then retire the old version.`, 'ok');
    await loadKEKStatus();
  } catch (e) { showError($('kekError'), 'Rotate failed: ' + e.message); }
  finally { $('kekRotateBtn').disabled = false; }
};

$('kekRewrapBtn').onclick = async () => {
  $('kekError').classList.add('hidden');
  $('kekRewrapBtn').disabled = true;
  try {
    const r = await api('POST', '/api/secret/rewrap', { all: true });
    showKEKResult(`Re-wrapped ${r.rewrapped}/${r.total} onto v${r.active_version} (${r.active_label}) · ` +
      `${r.skipped} already current, ${r.conflicts} conflict(s), ${r.failed} failed.` +
      ((r.errors && r.errors.length) ? '\n' + r.errors.join('\n') : ''),
      r.failed > 0 ? 'err' : 'ok');
    await loadKEKStatus();
  } catch (e) { showError($('kekError'), 'Re-wrap failed: ' + e.message); }
  finally { $('kekRewrapBtn').disabled = false; }
};

async function retireKEK(version) {
  if (!confirm(`Retire KEK version ${version}?\n\nIt is withdrawn from service; the server refuses while any secret still depends on it.`)) return;
  $('kekError').classList.add('hidden');
  try {
    const v = await api('POST', '/api/secret/kek/retire', { version });
    showKEKResult(`Retired v${v.version} (${v.label}) — status ${v.status}.`, 'ok');
    await loadKEKStatus();
  } catch (e) { showError($('kekError'), 'Retire failed: ' + e.message); }
}

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

// ---- Access: per-CA / per-key grants (Task 191) --------------------------
// The console's view of the resource-scoped permission model: who has been
// delegated authority over one individual CA or signing key, and what that
// actually lets them do. Config-declared grants appear alongside stored ones and
// are shown read-only, because removing them means editing rbac.grants.

// accessResourceSpec resolves the selected resource: the free-text field wins so
// a signing key (which has no entry in the CA list) can be addressed by name.
function accessResourceSpec() {
  const custom = $('accessResourceCustom').value.trim();
  return custom || $('accessResource').value || '';
}

async function loadAccess() {
  // Populate the CA picker from the authorities the caller can already see —
  // which, for a delegated operator, is exactly the CAs it was granted.
  const sel = $('accessResource');
  const prev = sel.value;
  sel.innerHTML = cas.map(c => `<option value="ca/${c.id}">${escapeHTML(c.label)} — ca/${escapeHTML(c.id)}</option>`).join('');
  if (prev) sel.value = prev;
  loadResourceRoles();
  loadGroups();
  await loadAccessGrants();
}

// loadResourceRoles renders the grantable-role catalog and drives the grant
// form's Role picker from it — the console counterpart of `secsy-ca grant roles`.
// The catalog is generated from the evaluator's own bundle table, so a role or
// capability added there appears here without a console change; the markup's
// hard-coded <optgroup> list is left in place only as the fallback for a server
// that does not answer (an older build, or a read the caller is denied).
async function loadResourceRoles() {
  const roleRows = $('accessRoleRows'), scopeRows = $('accessScopeRows');
  let cat;
  try {
    cat = await api('GET', '/api/grants/roles');
  } catch (e) {
    roleRows.innerHTML = `<tr><td colspan="3" class="muted">Catalog unavailable (${escapeHTML(e.message)}); the Role picker keeps its built-in list.</td></tr>`;
    scopeRows.innerHTML = '<tr><td colspan="2" class="muted">—</td></tr>';
    return;
  }
  const roles = cat.roles || [];
  roleRows.innerHTML = roles.length ? roles.map(r => `
    <tr>
      <td><code>${escapeHTML(r.role)}</code></td>
      <td>${(r.applies_to || []).map(t => `<code>${escapeHTML(t)}</code>`).join(' ')}</td>
      <td>${(r.actions || []).map(a => `<code>${escapeHTML(a)}</code>`).join(' ')}</td>
    </tr>`).join('') : '<tr><td colspan="3" class="muted">No grantable roles.</td></tr>';
  scopeRows.innerHTML = (cat.scopes || []).map(s =>
    `<tr><td><code>${escapeHTML(s.scope)}</code></td><td>${escapeHTML(s.description || '')}</td></tr>`).join('')
    || '<tr><td colspan="2" class="muted">—</td></tr>';
  $('accessRoleNote').textContent = cat.note || '';

  // Rebuild the picker, grouped by the resource types each role applies to, so an
  // operator cannot pick a role the grant endpoints would refuse on the selected
  // resource. The current selection survives a refresh.
  if (!roles.length) return;
  const sel = $('accessRole');
  const prev = sel.value;
  const byType = new Map();
  roles.forEach(r => {
    const key = (r.applies_to || []).join(', ') || 'any resource';
    if (!byType.has(key)) byType.set(key, []);
    byType.get(key).push(r);
  });
  sel.innerHTML = Array.from(byType.entries()).map(([type, rs]) =>
    `<optgroup label="${escapeHTML(type)}">` + rs.map(r =>
      `<option value="${escapeHTML(r.role)}">${escapeHTML(r.role)} — ${escapeHTML((r.actions || []).join(' '))}</option>`
    ).join('') + '</optgroup>').join('');
  if (prev && roles.some(r => r.role === prev)) sel.value = prev;
}

// ---- Internal user groups (Access view) -----------------------------------
// The grant form can target a group, but nothing in the console could create one
// or say who is in it. A grant matches an internal group by its ID (that is what
// the membership lookup feeding the evaluator returns), while an
// identity-provider group matches by the claim value — so the id is what the
// "Use in grant" shortcut fills in.
let accessGroups = [];
let selectedGroupID = null;

async function loadGroups() {
  const tbody = $('groupRows');
  tbody.innerHTML = '<tr><td colspan="4" class="muted">Loading…</td></tr>';
  try {
    accessGroups = await api('GET', '/api/groups');
  } catch (e) {
    accessGroups = [];
    tbody.innerHTML = `<tr><td colspan="4" class="muted">${escapeHTML(e.message)}</td></tr>`;
    return;
  }
  if (!accessGroups.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="muted">No internal groups. Grants can still target an identity-provider group by its claim value.</td></tr>';
    $('groupMembersBox').classList.add('hidden');
    selectedGroupID = null;
    return;
  }
  tbody.innerHTML = accessGroups.map((g, i) => `
    <tr>
      <td>${escapeHTML(g.name || '')}</td>
      <td class="mono">${escapeHTML(g.id || '')}</td>
      <td>${escapeHTML(g.tenant_id || '')}</td>
      <td style="white-space:nowrap">
        <button class="btn ghost sm" data-grp="members" data-i="${i}">Members</button>
        <button class="btn ghost sm" data-grp="use" data-i="${i}">Use in grant</button>
        <button class="btn danger sm" data-grp="delete" data-i="${i}">Delete</button>
      </td>
    </tr>`).join('');
  tbody.querySelectorAll('button[data-grp]').forEach(b => {
    const g = accessGroups[Number(b.dataset.i)];
    if (b.dataset.grp === 'members') b.onclick = () => showGroupMembers(g);
    if (b.dataset.grp === 'use') b.onclick = () => useGroupInGrant(g);
    if (b.dataset.grp === 'delete') b.onclick = () => deleteGroup(g);
  });
  // Keep an expanded membership list in step with a reload.
  if (selectedGroupID) {
    const still = accessGroups.find(g => g.id === selectedGroupID);
    if (still) showGroupMembers(still); else $('groupMembersBox').classList.add('hidden');
  }
}

async function showGroupMembers(g) {
  selectedGroupID = g.id;
  const box = $('groupMembersBox'), rows = $('groupMemberRows');
  $('groupMembersTitle').textContent = `Members of ${g.name || g.id}`;
  box.classList.remove('hidden');
  rows.innerHTML = '<tr><td colspan="2" class="muted">Loading…</td></tr>';
  let members;
  try {
    members = await api('GET', `/api/groups/${encodeURIComponent(g.id)}/members`);
  } catch (e) {
    rows.innerHTML = `<tr><td colspan="2" class="muted">${escapeHTML(e.message)}</td></tr>`;
    return;
  }
  rows.innerHTML = members.length ? members.map((sub, i) => `
    <tr>
      <td class="mono">${escapeHTML(sub)}</td>
      <td style="white-space:nowrap"><button class="btn ghost sm" data-mem="${i}">Remove</button></td>
    </tr>`).join('') : '<tr><td colspan="2" class="muted">No members: this group confers nothing yet.</td></tr>';
  rows.querySelectorAll('button[data-mem]').forEach(b => {
    b.onclick = () => removeGroupMember(g, members[Number(b.dataset.mem)]);
  });
}

$('groupCreateBtn').onclick = async () => {
  const msg = $('groupMsg'), name = $('groupNewName').value.trim();
  msg.className = 'notice hidden';
  if (!name) { notice(msg, 'err', 'A group name is required.'); return; }
  try {
    const g = await api('POST', '/api/groups', { name });
    notice(msg, 'ok', `Created group "${g.name}" — grant to it with entity id ${g.id}.`);
    $('groupNewName').value = '';
    await loadGroups();
  } catch (e) { notice(msg, 'err', 'Creating the group failed: ' + e.message); }
};

// Deleting a group silently strips every grant made to it from everyone in it, so
// it is confirmed.
async function deleteGroup(g) {
  const msg = $('groupMsg');
  if (!confirm(`Delete group "${g.name || g.id}"?\n\nEvery grant made to this group stops applying to its members.`)) return;
  try {
    await api('DELETE', '/api/groups/' + encodeURIComponent(g.id));
    if (selectedGroupID === g.id) { selectedGroupID = null; $('groupMembersBox').classList.add('hidden'); }
    notice(msg, 'ok', `Deleted group "${g.name || g.id}".`);
    await loadGroups();
  } catch (e) { notice(msg, 'err', 'Deleting the group failed: ' + e.message); }
}

$('groupMemberAddBtn').onclick = async () => {
  const msg = $('groupMsg'), sub = $('groupMemberSub').value.trim();
  msg.className = 'notice hidden';
  if (!selectedGroupID) { notice(msg, 'err', 'Open a group\'s members first.'); return; }
  if (!sub) { notice(msg, 'err', 'A subject is required.'); return; }
  const g = accessGroups.find(x => x.id === selectedGroupID) || { id: selectedGroupID };
  try {
    await api('POST', `/api/groups/${encodeURIComponent(g.id)}/members`, { user_sub: sub });
    notice(msg, 'ok', `Added ${sub} to "${g.name || g.id}" — it now holds every grant made to this group.`);
    $('groupMemberSub').value = '';
    await showGroupMembers(g);
  } catch (e) { notice(msg, 'err', 'Adding the member failed: ' + e.message); }
};

async function removeGroupMember(g, sub) {
  const msg = $('groupMsg');
  if (!confirm(`Remove ${sub} from "${g.name || g.id}"?\n\nIt loses every grant this group carries.`)) return;
  try {
    await api('DELETE', `/api/groups/${encodeURIComponent(g.id)}/members/${encodeURIComponent(sub)}`);
    notice(msg, 'ok', `Removed ${sub} from "${g.name || g.id}".`);
    await showGroupMembers(g);
  } catch (e) { notice(msg, 'err', 'Removing the member failed: ' + e.message); }
}

// useGroupInGrant points the grant form at this group. The id, not the name, is
// what the evaluator matches an internal group's membership against.
function useGroupInGrant(g) {
  $('accessEntityType').value = 'group';
  $('accessEntityID').value = g.id;
  notice($('groupMsg'), 'ok', `Grant form set to group "${g.name || g.id}" (${g.id}) — pick a role and resource above, then Grant.`);
}

$('groupRefresh').onclick = loadGroups;

async function loadAccessGrants() {
  const rows = $('accessRows');
  const resource = accessResourceSpec();
  if (!resource) {
    rows.innerHTML = '<tr><td colspan="6" class="muted">Select a resource.</td></tr>';
    return;
  }
  let grants;
  try {
    grants = await api('GET', '/api/grants?resource=' + encodeURIComponent(resource));
    $('accessDenied').classList.add('hidden');
  } catch (e) {
    rows.innerHTML = '';
    showError($('accessDenied'), 'Listing grants failed: ' + e.message);
    return;
  }
  if (!grants.length) {
    rows.innerHTML = `<tr><td colspan="6" class="muted">No grants on ${escapeHTML(resource)}. Access here comes from platform or tenant roles only.</td></tr>`;
    return;
  }
  rows.innerHTML = grants.map((g, i) => {
    const fromConfig = g.source === 'config';
    const revoke = fromConfig
      ? '<span class="muted" title="Declared in rbac.grants; remove it from the configuration file">config-managed</span>'
      : `<button class="btn danger sm" data-i="${i}">Revoke</button>`;
    return `<tr>
      <td><code>${escapeHTML(g.role)}</code></td>
      <td>${escapeHTML(g.entity_type)}:${escapeHTML(g.entity_id)}</td>
      <td>${escapeHTML(g.scope || 'self')}</td>
      <td>${fromConfig ? '<span class="badge">config</span>' : '<span class="badge ok">database</span>'}</td>
      <td>${g.created_at ? escapeHTML(fmtTime(g.created_at)) : '—'}</td>
      <td style="white-space:nowrap">${revoke}</td>
    </tr>`;
  }).join('');
  rows.querySelectorAll('button[data-i]').forEach(b => {
    b.onclick = () => revokeAccessGrant(resource, grants[Number(b.dataset.i)]);
  });
}

async function revokeAccessGrant(resource, g) {
  if (!confirm(`Revoke ${g.role} on ${resource} from ${g.entity_type}:${g.entity_id}?`)) return;
  try {
    await api('DELETE', '/api/grants', {
      resource, entity_type: g.entity_type, entity_id: g.entity_id, role: g.role,
    });
  } catch (e) {
    showError($('accessDenied'), 'Revoking the grant failed: ' + e.message);
    return;
  }
  await loadAccessGrants();
}

$('accessGrantBtn').onclick = async () => {
  const resource = accessResourceSpec();
  const entityID = $('accessEntityID').value.trim();
  if (!resource || !entityID) {
    showError($('accessGrantError'), 'A resource and a group/user identifier are required.');
    return;
  }
  try {
    await api('POST', '/api/grants', {
      resource,
      entity_type: $('accessEntityType').value,
      entity_id: entityID,
      role: $('accessRole').value,
      scope: $('accessScope').value,
    });
    $('accessGrantError').classList.add('hidden');
    $('accessEntityID').value = '';
  } catch (e) {
    showError($('accessGrantError'), 'Granting failed: ' + e.message);
    return;
  }
  await loadAccessGrants();
};

$('accessEffectiveBtn').onclick = async () => {
  const resource = accessResourceSpec();
  const out = $('accessEffectiveOut');
  if (!resource) {
    showError($('accessEffectiveError'), 'Select a resource first.');
    return;
  }
  let q = '/api/grants/effective?resource=' + encodeURIComponent(resource);
  const subject = $('accessSubject').value.trim();
  if (subject) q += '&subject=' + encodeURIComponent(subject);
  let eff;
  try {
    eff = await api('GET', q);
    $('accessEffectiveError').classList.add('hidden');
  } catch (e) {
    out.innerHTML = '';
    showError($('accessEffectiveError'), 'Effective-access lookup failed: ' + e.message);
    return;
  }
  const chips = (label, vals) => vals && vals.length
    ? `<div class="field"><label>${label}</label><div>${vals.map(v => `<code>${escapeHTML(String(v))}</code>`).join(' ')}</div></div>`
    : '';
  const grantRows = (eff.grants || []).map(g =>
    `<tr><td><code>${escapeHTML(g.resource_type)}/${escapeHTML(g.resource_id)}</code></td>
         <td><code>${escapeHTML(g.role)}</code></td>
         <td>${escapeHTML(g.entity_type)}:${escapeHTML(g.entity_id)}</td>
         <td>${escapeHTML(g.scope || 'self')}</td></tr>`).join('');
  out.innerHTML = `
    <div class="field"><label>Subject</label><div>${escapeHTML(eff.subject || '(me)')}${eff.is_root ? ' <span class="badge">root</span>' : ''}</div></div>
    ${eff.tenant_id ? `<div class="field"><label>Tenant</label><div>${escapeHTML(eff.tenant_id)}</div></div>` : ''}
    ${chips('Platform roles', eff.platform_roles)}
    ${chips('Tenant roles', eff.tenant_roles)}
    ${chips('Resource roles (from grants)', eff.resource_roles)}
    ${chips('Effective capabilities here', eff.actions)}
    ${grantRows ? `<div class="field"><label>Matching grants</label><table><thead><tr><th>Resource</th><th>Role</th><th>Entity</th><th>Scope</th></tr></thead><tbody>${grantRows}</tbody></table></div>` : ''}
    ${(eff.actions || []).length ? '' : '<div class="muted">No capabilities at this resource.</div>'}`;
};

$('refreshAccess').onclick = loadAccess;
$('accessResource').onchange = loadAccessGrants;
$('accessResourceCustom').onchange = loadAccessGrants;

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
    // The four-eyes gate answers 202 without creating anything, so the hold must
    // be reported before any field of the (absent) CA is read.
    const held = heldForApproval(ca);
    if (held) { notice($('casMsg'), 'warn', held); loadApprovals(); return; }
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
    const held = heldForApproval(ca);
    if (held) { notice($('casMsg'), 'warn', held); loadApprovals(); return; }
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
    const held = heldForApproval(res);
    if (held) { notice($('casMsg'), 'warn', held); loadApprovals(); return; }
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
    const held = heldForApproval(res);
    if (held) { notice($('casMsg'), 'warn', held); loadApprovals(); return; }
    const warn = (res.warnings || []).length ? ` Warnings: ${res.warnings.join(' • ')}` : '';
    notice($('casMsg'), (res.warnings || []).length ? 'warn' : 'ok',
      `Imported certificate for "${res.ca.label}" — the CA is now active and its served chain includes the external parent(s).${warn}`);
    downloadBlob(res.chain_pem, `${res.ca.label}-chain.pem`, 'application/x-pem-file');
    await loadAuthorities();
  } catch (e) { showError($('importError'), e.message); }
  finally { $('importConfirm').disabled = false; }
};

// -- adopt existing key material (Task 198) --
// Both forms below carry a private key. They are the only console forms that do,
// so they follow one rule: the material goes into the request body and nowhere
// else — never into a result box, never back into an input — and every field that
// held it is cleared once the server has it.

// MAX_KEY_IMPORT_BYTES keeps a mis-chosen file from being base64-expanded into a
// request the server would reject anyway: it caps the whole body at 1 MiB, and a
// key container is a few tens of kilobytes.
const MAX_KEY_IMPORT_BYTES = 512 * 1024;

// keyImportMaterial collects the private-key half of an import request: the PEM
// textarea, or a container file (PKCS#12/DER) read to base64 — the two encodings
// the endpoints accept, of which exactly one may be supplied. The file is read
// straight into the body, so a container never appears on the page.
async function keyImportMaterial(pemID, fileID, passID) {
  const pem = $(pemID).value.trim();
  const input = $(fileID);
  const file = input.files && input.files[0];
  if (pem && file) throw new Error('supply the key as PEM or as a container file, not both');
  if (!pem && !file) throw new Error('paste the private key (PEM) or choose a container file');
  if (file && file.size > MAX_KEY_IMPORT_BYTES) throw new Error('that file is larger than 512 KiB — it is not a key container');
  const body = pem ? { key_pem: pem } : { key_base64: await readFileB64(input) };
  const pass = $(passID).value;
  if (pass) body.passphrase = pass;
  return body;
}

// heldForApproval reports the four-eyes message when a guarded operation answered
// 202 instead of performing the work. api() returns the body for any 2xx, so the
// hold arrives as data rather than as an error — the same discrimination the
// issuance form makes on res.status, over the shape writeApprovalPending sends
// ({status, message, approval}) with the flatter issuance shape as a fallback.
function heldForApproval(res) {
  if (!res || res.status !== 'pending_approval') return null;
  const pa = res.approval || res;
  const id = pa.id || pa.approval_id || '(unknown)';
  const need = pa.required_approvals || 0;
  const have = pa.approvals_count || 0;
  return `Held for four-eyes approval: request ${id} needs ${need} distinct approver(s) ` +
    `(${have} recorded so far). Approve it under Approvals, then submit this form again.`;
}

// Mirrors `secsy-ca ca import`: adopt an existing authority, its key and its
// certificate. Guarded by the same maker-checker class as creating a root.
$('caImpKeySource').onchange = () => {
  const existing = $('caImpKeySource').value === 'existing';
  $('caImpExistingRow').classList.toggle('hidden', !existing);
  $('caImpMaterialRow').classList.toggle('hidden', existing);
  // Whichever half was abandoned is emptied rather than merely hidden: a private
  // key left sitting in a hidden field is a private key still on the page.
  if (existing) { $('caImpKeyPEM').value = $('caImpPass').value = ''; $('caImpKeyFile').value = ''; }
  else { $('caImpExistingLabel').value = ''; }
};
$('caImpBtn').onclick = async () => {
  const err = $('caImpError'), out = $('caImpResult');
  err.classList.add('hidden');
  out.classList.add('hidden');
  const body = { label: $('caImpLabel').value.trim() };
  if (!body.label) { showError(err, 'A label is required.'); return; }
  const tenant = $('caImpTenant').value.trim(); if (tenant) body.tenant = tenant;
  const parent = $('caImpParent').value; if (parent) body.parent = parent;
  const cert = $('caImpCert').value.trim(); if (cert) body.certificate = cert;
  const chain = $('caImpChain').value.trim(); if (chain) body.chain = chain;
  $('caImpBtn').disabled = true;
  try {
    if ($('caImpKeySource').value === 'existing') {
      const label = $('caImpExistingLabel').value.trim();
      if (!label) throw new Error('give the label the key is already stored under');
      body.existing_key_label = label;
      if (!cert) throw new Error('a certificate is required when adopting a key by label');
    } else {
      Object.assign(body, await keyImportMaterial('caImpKeyPEM', 'caImpKeyFile', 'caImpPass'));
    }
    const res = await api('POST', '/api/ca/import', body);
    const held = heldForApproval(res);
    if (held) {
      notice(out, 'warn', held);
      out.classList.remove('hidden');
      loadApprovals();
      return;
    }
    renderCAImportResult(res);
    // Clear the whole form: the key material and its passphrase must not survive
    // the request, and a successful adoption is not resubmittable anyway.
    $('caImpLabel').value = $('caImpTenant').value = $('caImpExistingLabel').value = '';
    $('caImpKeyPEM').value = $('caImpPass').value = $('caImpCert').value = $('caImpChain').value = '';
    $('caImpKeyFile').value = '';
    await loadAuthorities();
  } catch (e) { showError(err, e.message); }
  finally { $('caImpBtn').disabled = false; }
};

// renderCAImportResult paints what the adoption established. The warnings lead,
// because they are the part an operator must act on — a CA adopted with a weak
// key or an unverifiable chain is still adopted.
function renderCAImportResult(res) {
  const out = $('caImpResult');
  const ca = res.ca || {};
  const warnings = res.warnings || [];
  out.className = 'notice ' + (warnings.length ? 'warn' : 'ok');
  out.innerHTML =
    `<div style="font-size:15px"><b>${warnings.length ? '⚠' : '✓'} adopted ${escapeHTML(ca.label || '')}</b>` +
    (res.self_signed ? ' <span class="badge ok">self-signed root</span>' : ' <span class="badge warning">subordinate</span>') +
    '</div>' +
    `<div class="muted" style="margin-top:6px">` +
      escapeHTML(ca.subject || '') +
      `<br>${escapeHTML(ca.key_type || '')} · serial ${escapeHTML(shortSerial(ca.serial || ''))} · ` +
      `expires ${escapeHTML(fmtTime(ca.not_after))} · status ${escapeHTML(ca.status || 'active')}` +
      `<br>key ${res.key_imported ? 'imported into the provider' : 'adopted in place (already on the provider)'}` +
      (res.source_format ? ` from ${escapeHTML(res.source_format)}` : '') +
      (res.key_fingerprint ? `<br>key fingerprint <span class="mono">${escapeHTML(res.key_fingerprint)}</span>` : '') +
    '</div>' +
    (warnings.length
      ? '<div style="margin-top:8px"><b>Warnings</b><ul style="margin:4px 0 0">' +
        warnings.map(w => `<li>${escapeHTML(w)}</li>`).join('') + '</ul></div>'
      : '') +
    (res.notice ? `<div class="muted" style="margin-top:8px">${escapeHTML(res.notice)}</div>` : '');
  out.classList.remove('hidden');
  if (res.chain_pem) {
    const dl = document.createElement('button');
    dl.className = 'btn ghost sm';
    dl.style.marginTop = '8px';
    dl.textContent = 'Download served chain (PEM)';
    dl.onclick = () => downloadBlob(res.chain_pem, `${ca.label || 'ca'}-chain.pem`, 'application/x-pem-file');
    out.appendChild(dl);
  }
}

// Mirrors `secsy-ca import-key`: put an existing key on a role's backend under a
// label, with no CA record attached.
$('keyImpBtn').onclick = async () => {
  const err = $('keyImpError'), out = $('keyImpResult');
  err.classList.add('hidden');
  out.classList.add('hidden');
  const body = {
    label: $('keyImpLabel').value.trim(),
    role: $('keyImpRole').value,
    usage: $('keyImpUsage').value,
  };
  if (!body.label) { showError(err, 'A label is required.'); return; }
  const id = $('keyImpID').value.trim(); if (id) body.id = id;
  $('keyImpBtn').disabled = true;
  try {
    Object.assign(body, await keyImportMaterial('keyImpKeyPEM', 'keyImpKeyFile', 'keyImpPass'));
    const res = await api('POST', '/api/keys/import', body);
    out.className = 'notice ok';
    out.innerHTML =
      `<div style="font-size:15px"><b>✓ imported ${escapeHTML(res.label || '')}</b> — ` +
      `${escapeHTML(res.key_type || '')}` +
      (res.verified
        ? ' <span class="badge pass">signature verified</span>'
        : ' <span class="badge none">no signature check (decrypt-only)</span>') + '</div>' +
      `<div class="muted" style="margin-top:6px">` +
        `provider ${escapeHTML(res.provider || '')} · role ${escapeHTML(res.role || '')} · ` +
        `usage ${escapeHTML(res.usage || '')} · read as ${escapeHTML(res.source_format || '')}` +
        (res.id ? ` · CKA_ID <span class="mono">${escapeHTML(res.id)}</span>` : '') +
        (res.uri ? `<br><span class="mono">${escapeHTML(res.uri)}</span>` : '') +
        (res.ssh_public_key ? `<br><span class="mono">${escapeHTML(res.ssh_public_key)}</span>` : '') +
      '</div>' +
      (res.notice ? `<div style="margin-top:8px">${escapeHTML(res.notice)}</div>` : '');
    out.classList.remove('hidden');
    $('keyImpLabel').value = $('keyImpID').value = '';
    $('keyImpKeyPEM').value = $('keyImpPass').value = '';
    $('keyImpKeyFile').value = '';
    loadKeyInventory();
  } catch (e) { showError(err, e.message); }
  finally { $('keyImpBtn').disabled = false; }
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
    const held = heldForApproval(res);
    if (held) { notice($('casMsg'), 'warn', held); loadApprovals(); return; }
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
    const held = heldForApproval(res);
    if (held) { notice($('casMsg'), 'warn', held); loadApprovals(); return; }
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
    const held = heldForApproval(res);
    if (held) { notice($('casMsg'), 'warn', held); loadApprovals(); return; }
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

// -- provisioning the two signing credentials (Task 198) --
// Both endpoints answer with the same shape — the key that is now on the backend,
// the certificate it was issued, and the configuration stanza that ties the two
// together — so one renderer serves both. The config hint is the point of the
// call: until it is applied, the credential exists but nothing uses it.
function renderProvisioned(out, res, filename) {
  const key = res.key || {}, cert = res.certificate || {};
  out.className = 'notice ok';
  out.innerHTML =
    `<div style="font-size:15px"><b>✓ ${escapeHTML(key.label || '')}</b> — ${escapeHTML(key.key_type || '')}` +
    (key.reused
      ? ' <span class="badge warning">existing key reused</span>'
      : ' <span class="badge ok">key generated</span>') + '</div>' +
    `<div class="muted" style="margin-top:6px">` +
      `provider ${escapeHTML(key.provider || '')} · role ${escapeHTML(key.role || '')}` +
      (res.profile ? ` · profile ${escapeHTML(res.profile)}` : '') +
      (key.uri ? `<br><span class="mono">${escapeHTML(key.uri)}</span>` : '') +
      `<br>${escapeHTML(cert.subject || '')}` +
      `<br>serial ${escapeHTML(shortSerial(cert.serial || ''))} · issued by ` +
      `${escapeHTML(cert.ca_label || cert.ca_id || '')} · valid ${escapeHTML(fmtTime(cert.not_before))} → ` +
      `${escapeHTML(fmtTime(cert.not_after))}` +
    '</div>' +
    `<pre class="mono" style="white-space:pre-wrap;margin:10px 0 0">${escapeHTML(res.config_hint || '')}</pre>`;
  out.classList.remove('hidden');
  const dl = document.createElement('button');
  dl.className = 'btn ghost sm';
  dl.style.marginTop = '8px';
  dl.textContent = 'Download certificate (PEM)';
  dl.onclick = () => downloadBlob(cert.certificate_pem || '', filename, 'application/x-pem-file');
  out.appendChild(dl);
}

// Mirrors `secsy-ca signing-key`: an artifact code-signing key plus its
// certificate, issued through the ordinary lint-gated path.
$('signProvBtn').onclick = async () => {
  const err = $('signProvError'), out = $('signProvResult');
  err.classList.add('hidden');
  out.classList.add('hidden');
  const ca = $('signProvCA').value;
  if (!ca) { showError(err, 'Select an issuing CA.'); return; }
  const body = { ca, key_type: $('signProvKeyType').value, chain: $('signProvChain').checked };
  const label = $('signProvLabel').value.trim(); if (label) body.label = label;
  const profile = $('signProvProfile').value.trim(); if (profile) body.profile = profile;
  const cn = $('signProvCN').value.trim(); if (cn) body.common_name = cn;
  const org = $('signProvO').value.trim(); if (org) body.organization = org;
  const days = parseInt($('signProvDays').value, 10); if (days > 0) body.validity_days = days;
  $('signProvBtn').disabled = true;
  try {
    const res = await api('POST', '/api/sign/signers', body);
    renderProvisioned(out, res, `${(res.key && res.key.label) || 'codesign'}.pem`);
  } catch (e) { showError(err, e.message); }
  finally { $('signProvBtn').disabled = false; }
};

// Mirrors `secsy-ca tsa-key`: the RFC 3161 timestamp authority's credential.
$('tsaProvBtn').onclick = async () => {
  const err = $('tsaProvError'), out = $('tsaProvResult');
  err.classList.add('hidden');
  out.classList.add('hidden');
  const ca = $('tsaProvCA').value;
  if (!ca) { showError(err, 'Select an issuing CA.'); return; }
  const body = { ca, key_type: $('tsaProvKeyType').value, chain: $('tsaProvChain').checked };
  const label = $('tsaProvLabel').value.trim(); if (label) body.label = label;
  const cn = $('tsaProvCN').value.trim(); if (cn) body.common_name = cn;
  const org = $('tsaProvO').value.trim(); if (org) body.organization = org;
  const days = parseInt($('tsaProvDays').value, 10); if (days > 0) body.validity_days = days;
  $('tsaProvBtn').disabled = true;
  try {
    const res = await api('POST', '/api/tsa/key', body);
    renderProvisioned(out, res, `${(res.key && res.key.label) || 'tsa'}.pem`);
  } catch (e) { showError(err, e.message); }
  finally { $('tsaProvBtn').disabled = false; }
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

// ---- RFC 4998 Evidence Record verification (Task 161) --------------------
// Verification re-derives every digest, so the response reports per-chain and
// per-object results rather than a bare boolean — a record can be internally
// sound while covering an object the caller did not supply. Mirrors
// `secsy-ca ers verify`; the listing, generation, renewal and export of records
// live with the rest of the ERS panel in the Compliance view.
$('ersVerifyBtn').onclick = () => runERSVerify();

async function runERSVerify() {
  const err = $('ersError'); err.classList.add('hidden');
  const out = $('ersResult'); out.classList.add('hidden');
  const id = $('ersID').value.trim();
  const record = $('ersRecord').value.trim();
  if (!id && !record) { showError(err, 'A stored record id or a base64 DER record is required.'); return; }
  if (id && record) { showError(err, 'Supply an id or a record, not both.'); return; }
  try {
    // A record that does not verify answers 409 with the same body shape: that is
    // a verdict, and postVerdict renders it as one rather than as an error.
    renderERSResult(out, await postVerdict('/api/ers/verify', id ? { id } : { record }));
  } catch (e) {
    showError(err, 'Verification failed: ' + e.message);
  }
}

function renderERSResult(el, res) {
  el.className = 'notice ' + (res.valid ? 'ok' : 'err');
  const chains = (res.chains || []).map(c =>
    `<tr><td class="mono">${escapeHTML(c.algorithm || '')}</td><td>${fmtTime(c.timestamp)}</td>` +
    `<td>${(c.tokens || []).length} token(s)</td>` +
    `<td class="muted">${escapeHTML(((c.tokens || [])[0] || {}).issuer || '')}</td></tr>`).join('');
  const objects = (res.objects || []).map(o =>
    `<tr><td class="mono">${escapeHTML(o.id || '')}</td><td>${escapeHTML(o.digest_algorithm || '')}</td>` +
    `<td class="mono">${escapeHTML((o.digest || '').slice(0, 24))}…</td>` +
    `<td style="color:${o.verified ? 'var(--ok)' : 'var(--crit)'}">${o.verified ? '✓' : '✗'}</td></tr>`).join('');
  el.innerHTML =
    `<div style="font-size:15px"><b>${res.valid ? '✓ record verifies' : '✗ record does NOT verify'}</b></div>` +
    (chains ? `<table style="margin-top:8px"><thead><tr><th>Hash algorithm</th><th>Timestamped</th><th>Tokens</th><th>TSA</th></tr></thead><tbody>${chains}</tbody></table>` : '') +
    (objects ? `<table style="margin-top:8px"><thead><tr><th>Object</th><th>Digest algorithm</th><th>Digest</th><th></th></tr></thead><tbody>${objects}</tbody></table>` : '');
  el.classList.remove('hidden');
}

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

// Mirrors `secsy-ca approvals expire`: retire every request whose approval window
// has elapsed. The gate already treats such a request as expired the moment it is
// next touched, but until something sweeps them the queue keeps listing requests
// that can never execute.
$('approvalsExpireBtn').onclick = async () => {
  const out = $('approvalsExpireResult'), btn = $('approvalsExpireBtn');
  btn.disabled = true;
  try {
    const res = await api('POST', '/api/approvals/expire');
    const gate = res.enabled ? ''
      : ' The approval gate is currently disabled, so anything swept was left over from when it was on.';
    notice(out, res.expired ? 'warn' : 'ok', res.expired
      ? `${res.expired} stale request(s) expired.${gate}`
      : `Nothing to sweep: no request's approval window has elapsed.${gate}`);
    loadApprovals();
  } catch (e) {
    // 503 = the approval workflow was never installed on this server.
    notice(out, 'err', 'Expiry sweep failed: ' + e.message);
  } finally { btn.disabled = false; }
};

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

// ---- Operations view (Task 198) -------------------------------------------
// The run-book operations that previously needed a shell on the CA host:
// preflight diagnostics, the DR manifest, its restore drill, and the static
// artifact snapshot. Every endpoint here answers 503 with an explanatory message
// on a server started without the operations dependencies, and several report a
// failed verdict with a non-2xx status that api() turns into a thrown error — so
// each panel renders the server's own message rather than going blank.
$('opsDoctorRun').onclick = runDoctor;
$('opsBackupDownload').onclick = downloadDRManifest;
$('opsRestoreRun').onclick = runRestoreDrill;
$('opsPublishRun').onclick = publishSnapshot;
$('opsPublishVerify').onclick = verifyPublishedSnapshot;

// doctorStatusClass maps a diagnostic status onto the shared badge palette.
const doctorStatusClass = { pass: 'pass', warn: 'warn', fail: 'fail', skip: 'none' };

// opsDoctorRan keeps a first visit from being blank without re-running the suite
// on every later navigation — the button is how it is refreshed after that.
let opsDoctorRan = false;

// loadOps hosts the four operator panels. Only the read-only diagnostics suite
// (`secsy-ca doctor`) runs by itself, and only on the first visit; the DR
// manifest (`secsy-ca backup`), the restore drill (`secsy-ca backup
// verify-restore`) and publishing (`secsy-ca publish`, `secsy-ca publish
// -verify`) are deliberate, operator-triggered actions.
function loadOps() {
  if (!opsDoctorRan) runDoctor();
}

// runDoctor mirrors `secsy-ca doctor`: the read-only preflight suite. The report
// is the answer, so every verdict arrives as HTTP 200 and is rendered as a
// banner; only a transport/authorization failure lands in the catch.
async function runDoctor() {
  const banner = $('opsDoctorBanner'), meta = $('opsDoctorMeta'), tbody = $('opsDoctorRows');
  const btn = $('opsDoctorRun');
  opsDoctorRan = true;
  btn.disabled = true;
  notice(banner, '', 'Running the diagnostic suite…');
  banner.classList.remove('hidden');
  meta.textContent = '';
  tbody.innerHTML = '<tr><td colspan="4" class="muted">Running…</td></tr>';
  try {
    const rep = await api('GET', '/api/doctor' + ($('opsDoctorDeep').checked ? '?deep=true' : ''));
    const s = rep.summary || {};
    const cls = rep.verdict === 'ok' ? 'ok' : (rep.verdict === 'warn' ? 'warn' : 'err');
    const mark = rep.verdict === 'ok' ? '✓' : (rep.verdict === 'warn' ? '⚠' : '✗');
    notice(banner, cls, `${mark} Verdict ${rep.verdict} (exit code ${rep.exit_code}) — ` +
      `${s.pass || 0} pass · ${s.warn || 0} warn · ${s.fail || 0} fail · ${s.skip || 0} skip`);
    meta.textContent = `config ${rep.config_path || '(none)'} · checked ${fmtTime(rep.checked_at)} · ` +
      `${rep.deep ? 'deep' : 'shallow'} probes · timeout ${rep.timeout_seconds}s`;
    tbody.innerHTML = (rep.checks || []).length ? (rep.checks || []).map(c => {
      let html = `<tr>
        <td>${checkBadge(doctorStatusClass[c.status] || 'none', c.status)}</td>
        <td class="mono">${escapeHTML(c.name)}</td>
        <td>${escapeHTML(c.message)}</td>
        <td class="muted">${escapeHTML(c.elapsed_ms)} ms</td>
      </tr>`;
      // The hint is the fix, so it rides directly beneath the row that needs it.
      if (c.hint && (c.status === 'warn' || c.status === 'fail')) {
        html += `<tr><td></td><td colspan="3" class="muted">hint: ${escapeHTML(c.hint)}</td></tr>`;
      }
      return html;
    }).join('') : '<tr><td colspan="4" class="muted">The suite reported no checks.</td></tr>';
  } catch (e) {
    notice(banner, 'err', 'Diagnostics unavailable: ' + e.message);
    meta.textContent = '';
    tbody.innerHTML = '<tr><td colspan="4" class="muted">—</td></tr>';
  } finally { btn.disabled = false; }
}

// downloadDRManifest mirrors `secsy-ca backup`: the disaster-recovery metadata
// bundle (public material only — never a private key), offered as a file and
// summarized inline. It is fetched raw so the file the operator archives is the
// server's exact bytes, then parsed for the summary.
async function downloadDRManifest() {
  const msg = $('opsBackupMsg'), sum = $('opsBackupSummary'), notes = $('opsBackupNotes');
  const btn = $('opsBackupDownload');
  btn.disabled = true;
  msg.className = 'notice hidden';
  sum.textContent = 'Exporting…';
  notes.innerHTML = '';
  try {
    const text = await api('GET', '/api/backup', undefined, true);
    const res = JSON.parse(text);
    const m = res.manifest || {};
    downloadBlob(text, 'dr-manifest.json', 'application/json');
    notice(msg, m.audit_chain_valid ? 'ok' : 'warn', m.audit_chain_valid
      ? '✓ Exported — the audit chain verified at export time.'
      : '⚠ Exported, but the audit chain did NOT verify at export time; investigate before relying on this anchor.');
    sum.textContent =
      `${(m.cas || []).length} CA(s) · audit head seq ${m.audit_head_seq} · ` +
      `chain ${m.audit_chain_valid ? 'valid' : 'INVALID'} · ${m.audit_event_count} event(s) · ` +
      `key provider ${m.key_provider || '—'} · driver ${m.db_driver || '—'} · ` +
      `scheduled backups ${res.scheduled_backup_enabled ? 'enabled' : 'disabled'}` +
      (res.scheduled_destination ? ` → ${res.scheduled_destination}` : '') +
      (res.config_path ? ` · config ${res.config_path}` : '');
    // The notes say what the bundle deliberately does NOT carry, and where that
    // material actually lives — the most load-bearing part of a DR runbook.
    notes.innerHTML = (m.notes || []).length
      ? '<div class="muted" style="margin-bottom:4px">Not in this bundle:</div>' +
        '<ul class="muted" style="margin:0">' + m.notes.map(n => `<li>${escapeHTML(n)}</li>`).join('') + '</ul>'
      : '';
  } catch (e) {
    notice(msg, 'err', 'DR manifest export failed: ' + e.message);
    sum.textContent = '';
  } finally { btn.disabled = false; }
}

// runRestoreDrill mirrors `secsy-ca backup verify-restore`. A failed drill
// answers HTTP 500 and a deployment that has never published a scheduled backup
// answers 404, both carrying the result body — api() throws on either, so the
// thrown message is rendered as the verdict instead of being swallowed.
async function runRestoreDrill() {
  const out = $('opsRestoreResult'), btn = $('opsRestoreRun');
  btn.disabled = true;
  notice(out, '', 'Fetching, decrypting and restoring the newest scheduled backup — this can take minutes…');
  out.classList.remove('hidden');
  try {
    const res = await api('POST', '/api/backup/verify-restore', {});
    out.className = 'notice ' + (res.ok ? 'ok' : 'err');
    out.innerHTML =
      `<div style="font-size:15px"><b>${res.ok ? '✓ backup restores' : '✗ RESTORE NOT PROVEN'}</b>` +
      (res.backend ? ` — backend ${escapeHTML(res.backend)}` : '') + '</div>' +
      `<div class="muted" style="margin-top:6px">` +
        `started ${escapeHTML(fmtTime(res.started_at))}` +
        (res.driver ? ` · driver ${escapeHTML(res.driver)}` : '') +
        (res.artifact_file ? ` · artifact ${escapeHTML(res.artifact_file)}` : '') +
        (res.artifact_size ? ` (${escapeHTML(res.artifact_size)} bytes)` : '') +
        (res.backup_created_at ? ` · taken ${escapeHTML(fmtTime(res.backup_created_at))}` : '') +
        `<br>integrity ${res.integrity_ok ? 'ok' : 'FAILED'} · fingerprint ${res.fingerprint_match ? 'matches' : 'MISMATCH'}` +
        (res.manifest_head ? `<br>manifest head ${escapeHTML(res.manifest_head)}` : '') +
        (res.restored_head ? `<br>restored head ${escapeHTML(res.restored_head)}` : '') +
        (res.artifact_sha256 ? `<br>artifact sha256 ${escapeHTML(res.artifact_sha256)}` : '') +
        (res.stage ? `<br>stage ${escapeHTML(res.stage)}` : '') +
        (res.error ? `<br>${escapeHTML(res.error)}` : '') +
      '</div>' + checkList((res.checks || []).map(c => ({ name: c.name, passed: c.ok, detail: c.detail })));
  } catch (e) {
    notice(out, 'err', '✗ Restore drill did not prove a restore: ' + e.message);
  } finally { btn.disabled = false; }
}

// publishSnapshot mirrors `secsy-ca publish`: replace the static CRL / pre-signed
// OCSP / chain snapshot relying parties fetch. HTTP 409 means another publish is
// already in flight (the destination is single-writer), which is a retry rather
// than a failure — so it is called out as such.
async function publishSnapshot() {
  const out = $('opsPublishResult'), btn = $('opsPublishRun');
  btn.disabled = true;
  notice(out, '', 'Building and writing the snapshot…');
  out.classList.remove('hidden');
  renderPublishArtifacts(null);
  try {
    const body = {};
    const cas = csvList($('opsPublishCAs').value);
    if (cas.length) body.cas = cas;
    if ($('opsPublishSkipOCSP').checked) body.skip_ocsp = true;
    const res = await api('POST', '/api/publish', body);
    const skipped = (res.skipped || []).map(s =>
      `${escapeHTML(s.label || s.id)} (${escapeHTML(s.reason)})`).join(', ');
    out.className = 'notice ok';
    out.innerHTML =
      `<div style="font-size:15px"><b>✓ snapshot v${escapeHTML(res.version)} published</b> — ` +
      `${escapeHTML(res.artifact_count)} artifact(s) for ${escapeHTML(res.ca_count)} CA(s)</div>` +
      `<div class="muted" style="margin-top:6px">` +
        `${escapeHTML(res.backend)} → ${escapeHTML(res.destination)} · generated ${escapeHTML(fmtTime(res.generated_at))} · ` +
        `${escapeHTML(res.duration_ms)} ms<br>` +
        `OCSP ${res.include_ocsp ? (res.ocsp_fresh ? 'included (freshly signed)' : 'included (reused presign batch)') : 'skipped'}` +
        (res.earliest_expiry ? ` · earliest artifact expiry ${escapeHTML(fmtTime(res.earliest_expiry))}` : '') +
        (skipped ? `<br>skipped: ${skipped}` : '') +
      '</div>' +
      publishCATable(res.cas);
    renderPublishArtifacts(res.artifacts);
  } catch (e) {
    notice(out, 'err', 'Publish failed: ' + e.message);
  } finally { btn.disabled = false; }
}

// verifyPublishedSnapshot mirrors `secsy-ca publish -verify`: re-read the
// published snapshot and check every object against its own manifest. A failed
// integrity audit is a HTTP 200 carrying ok:false — a verdict, not a transport
// error — so the banner is driven by ok, never by the status code.
async function verifyPublishedSnapshot() {
  const out = $('opsPublishResult'), btn = $('opsPublishVerify');
  btn.disabled = true;
  notice(out, '', 'Re-reading and digesting every published artifact…');
  out.classList.remove('hidden');
  renderPublishArtifacts(null);
  try {
    const res = await api('POST', '/api/publish/verify', {});
    out.className = 'notice ' + (res.ok ? 'ok' : 'err');
    out.innerHTML =
      `<div style="font-size:15px"><b>${res.ok ? '✓ published snapshot intact' : '✗ INTEGRITY AUDIT FAILED'}</b>` +
      (res.version ? ` — v${escapeHTML(res.version)}` : '') + '</div>' +
      `<div class="muted" style="margin-top:6px">` +
        `${escapeHTML(res.backend)} → ${escapeHTML(res.destination)} · ` +
        `${escapeHTML(res.verified_artifacts)} artifact(s) re-read for ${escapeHTML(res.ca_count)} CA(s) · ` +
        `${escapeHTML(res.duration_ms)} ms` +
        (res.generated_at ? `<br>generated ${escapeHTML(fmtTime(res.generated_at))}` : '') +
        (res.earliest_expiry ? ` · earliest artifact expiry ${escapeHTML(fmtTime(res.earliest_expiry))}` : '') +
        (res.error ? `<br>${escapeHTML(res.error)}` : '') +
      '</div>' +
      publishCATable(res.cas);
    renderPublishArtifacts(res.artifacts);
  } catch (e) {
    notice(out, 'err', 'Verification failed: ' + e.message);
  } finally { btn.disabled = false; }
}

// publishCATable renders the per-CA summary both publish operations return.
function publishCATable(cas) {
  if (!cas || !cas.length) return '';
  return '<table style="margin-top:8px"><thead><tr><th>CA</th><th>Pre-signed OCSP</th><th>CRL shards</th></tr></thead><tbody>' +
    cas.map(c => `<tr><td>${escapeHTML(c.label || c.id)}</td>` +
      `<td>${escapeHTML(c.ocsp_responses)}</td><td>${escapeHTML(c.crl_shards)}</td></tr>`).join('') +
    '</tbody></table>';
}

// renderPublishArtifacts lists the integrity record of every published object.
function renderPublishArtifacts(artifacts) {
  const table = $('opsPublishArtifacts'), tbody = $('opsPublishArtifactRows');
  if (!artifacts || !artifacts.length) {
    tbody.innerHTML = '';
    table.classList.add('hidden');
    return;
  }
  tbody.innerHTML = artifacts.map(a => `<tr>
    <td class="mono">${escapeHTML(a.path)}</td>
    <td>${escapeHTML(a.kind)}</td>
    <td>${escapeHTML(a.size)}</td>
    <td class="mono" title="${escapeHTML(a.sha256)}">${escapeHTML((a.sha256 || '').slice(0, 16))}…</td>
  </tr>`).join('');
  table.classList.remove('hidden');
}

// ---- Certificate-inventory retention (Task 198) ---------------------------
$('invRetPreview').onclick = () => runRetention(true);
$('invRetRun').onclick = () => runRetention(false);

// loadRetentionStatus mirrors `secsy-ca inventory retention status`: the resolved
// policy, how much is eligible right now, and the newest recorded pass. The
// endpoints work whether or not the background loop is enabled, so whether it
// runs at all is stated explicitly.
async function loadRetentionStatus() {
  const el = $('invRetStatus');
  el.textContent = 'Loading…';
  try {
    const st = await api('GET', '/api/inventory/retention');
    el.textContent =
      (st.enabled
        ? `Background loop enabled, every ${st.interval || '—'}`
        : 'Background loop DISABLED — retention runs only when triggered here or from the CLI') +
      ` · mode ${st.mode || '—'} · window ${st.window || '—'} · cutoff ${fmtTime(st.cutoff)}` +
      (st.prune_cutoff ? ` · prune cutoff ${fmtTime(st.prune_cutoff)}` : '') +
      ` · ${st.eligible} eligible · ${st.prunable} prunable · ${st.archive_size} archived` +
      (st.last_run ? ` · last run ${fmtTime(st.last_run.timestamp)} (${st.last_run.result})` : ' · never run');
  } catch (e) {
    el.textContent = 'Retention status unavailable: ' + e.message;
  }
}

// runRetention mirrors `secsy-ca inventory retention dry-run` (preview) and
// `secsy-ca inventory retention run`. A real pass permanently removes rows from
// the hot inventory, so it is confirmed first.
async function runRetention(dryRun) {
  if (!dryRun && !confirm('Run a retention pass now?\n\nEligible certificate-inventory rows are archived and, in prune mode, permanently deleted from the hot inventory. This cannot be undone. The authoritative revocation records (OCSP/CRL) are not affected.')) return;
  const out = $('invRetResult');
  const btns = [$('invRetPreview'), $('invRetRun')];
  btns.forEach(b => { b.disabled = true; });
  notice(out, '', dryRun ? 'Planning a pass…' : 'Running the retention pass…');
  out.classList.remove('hidden');
  try {
    const res = await api('POST', '/api/inventory/retention/run', { dry_run: dryRun });
    out.className = 'notice ' + (res.error ? 'err' : 'ok');
    out.innerHTML =
      `<div style="font-size:15px"><b>${res.dry_run ? 'Preview' : 'Retention pass'} — mode ${escapeHTML(res.mode)}</b></div>` +
      `<div class="muted" style="margin-top:6px">` +
        `${escapeHTML(res.eligible)} eligible · ${escapeHTML(res.archived)} archived · ` +
        `${escapeHTML(res.pruned)} pruned · ${escapeHTML(res.backlog)} still backlogged · ` +
        `archive holds ${escapeHTML(res.archive_size)} · ${escapeHTML(res.protected_by_approvals)} pinned by approvals<br>` +
        `window ${escapeHTML(res.window)} · cutoff ${escapeHTML(fmtTime(res.cutoff))}` +
        (res.prune_cutoff ? ` · prune cutoff ${escapeHTML(fmtTime(res.prune_cutoff))}` : '') +
        ` · started ${escapeHTML(fmtTime(res.started))} · ${escapeHTML(res.duration_ms)} ms<br>` +
        `manifest digest <span class="mono">${escapeHTML(res.digest)}</span>` +
        (res.error ? `<br>${escapeHTML(res.error)}` : '') +
      '</div>';
  } catch (e) {
    // A pass that failed part-way answers 500 with the committed counts in the
    // body; api() surfaces only its error string, so say that the counts are in
    // the status line the refresh below repaints.
    notice(out, 'err', (dryRun ? 'Preview' : 'Retention pass') + ' failed: ' + e.message);
  } finally {
    btns.forEach(b => { b.disabled = false; });
    loadRetentionStatus();
  }
}

// ---- Audit-chain anchoring (Task 198) -------------------------------------
// anchorAuditChain mirrors `secsy-ca audit anchor`: timestamp the current chain
// head with the deployment's TSA so the tip stays provable offline, long after
// the process that sealed it is gone. An unchanged head is reported as skipped —
// informational, not a failure, and deliberately mints no redundant token.
$('auditAnchorBtn').onclick = async () => {
  const out = $('auditAnchorResult'), btn = $('auditAnchorBtn');
  btn.disabled = true;
  notice(out, '', 'Timestamping the chain head…');
  out.classList.remove('hidden');
  try {
    const res = await api('POST', '/api/events/anchor', { force: $('auditAnchorForce').checked });
    const source = res.tsa_source || (res.anchor && res.anchor.tsa_source) || 'internal';
    if (res.skipped) {
      notice(out, '', `No anchor created — ${res.reason || 'the head has not moved since the last anchor'} ` +
        `(TSA ${source}). Tick "force" to anchor anyway.`);
      return;
    }
    const a = res.anchor || {};
    out.className = 'notice ok';
    out.innerHTML =
      `<div style="font-size:15px"><b>✓ chain head anchored at seq ${escapeHTML(a.seq)}</b></div>` +
      `<div class="muted" style="margin-top:6px">` +
        `head hash <span class="mono">${escapeHTML(a.head_hash)}</span><br>` +
        `TSA ${escapeHTML(source)} · genTime ${escapeHTML(fmtTime(a.gen_time))}` +
        (a.created_at ? ` · recorded ${escapeHTML(fmtTime(a.created_at))}` : '') +
      '</div>';
    // Offer the evidence itself: the DER TimeStampToken an auditor can re-verify
    // offline (openssl ts -verify) against the TSA certificate.
    if (a.token) {
      const dl = document.createElement('button');
      dl.className = 'btn ghost sm';
      dl.style.marginTop = '8px';
      dl.textContent = 'Download token (.tst)';
      dl.onclick = () => downloadBlob(unb64(a.token), `audit-anchor-${a.seq}.tst`, 'application/timestamp-reply');
      out.appendChild(dl);
    }
  } catch (e) {
    notice(out, 'err', 'Anchoring failed: ' + e.message);
  } finally { btn.disabled = false; }
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
