const API = {
    base: '',

    get authHeader() {
        return sessionStorage.getItem('auth_header');
    },
    set authHeader(v) {
        if (v) sessionStorage.setItem('auth_header', v);
        else sessionStorage.removeItem('auth_header');
    },

    get refreshToken() {
        return sessionStorage.getItem('refresh_token');
    },
    set refreshToken(v) {
        if (v) sessionStorage.setItem('refresh_token', v);
        else sessionStorage.removeItem('refresh_token');
    },

    async request(method, path, body) {
        await tokenManager.refreshIfNeeded();
        const opts = { method, headers: {} };
        if (this.authHeader) {
            opts.headers['Authorization'] = this.authHeader;
        }
        if (body) {
            opts.headers['Content-Type'] = 'application/json';
            opts.body = JSON.stringify(body);
        }
        const res = await fetch(this.base + path, opts);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
        return data;
    },

    get(path) { return this.request('GET', path); },
    post(path, body) { return this.request('POST', path, body); },
    del(path, body) { return this.request('DELETE', path, body); },
};

// Token lifecycle manager
const tokenManager = {
    _refreshTimer: null,

    getExpiry() {
        const auth = sessionStorage.getItem('auth_header');
        if (!auth || !auth.startsWith('Bearer ')) return null;
        try {
            const payload = JSON.parse(atob(auth.substring(7).split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));
            return payload.exp ? payload.exp * 1000 : null;
        } catch (e) { return null; }
    },

    async refreshIfNeeded() {},

    async doRefresh() {
        if (!API.refreshToken || !oidcDiscovery || !oidcConfig) return false;
        try {
            const res = await fetch(oidcDiscovery.token_endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    grant_type: 'refresh_token',
                    client_id: oidcConfig.client_id,
                    refresh_token: API.refreshToken,
                }),
            });
            const tokens = await res.json();
            if (tokens.id_token) {
                API.authHeader = 'Bearer ' + tokens.id_token;
                if (tokens.refresh_token) API.refreshToken = tokens.refresh_token;
                this.scheduleRefresh();
                return true;
            }
        } catch (e) { /* refresh failed */ }
        logout();
        return false;
    },

    scheduleRefresh() {
        this.cancelRefresh();
        const exp = this.getExpiry();
        if (!exp || !API.refreshToken) return;
        const delay = Math.max(0, exp - Date.now() - 30000);
        this._refreshTimer = setTimeout(() => this.doRefresh(), delay);
    },

    cancelRefresh() {
        if (this._refreshTimer) {
            clearTimeout(this._refreshTimer);
            this._refreshTimer = null;
        }
    },
};

let currentUser = null;

// Toast
function showToast(title, message, isError) {
    const el = document.getElementById('toast');
    document.getElementById('toastTitle').textContent = title;
    document.getElementById('toastBody').textContent = message;
    el.classList.toggle('text-bg-danger', !!isError);
    el.classList.toggle('text-bg-success', !isError);
    bootstrap.Toast.getOrCreateInstance(el).show();
}

// Navigation
document.querySelectorAll('[data-page]').forEach(link => {
    link.addEventListener('click', e => {
        e.preventDefault();
        showPage(link.dataset.page);
    });
});

function showPage(name) {
    document.querySelectorAll('.page').forEach(p => p.classList.add('d-none'));
    document.getElementById(name + 'Page').classList.remove('d-none');
    document.querySelectorAll('[data-page]').forEach(l => {
        l.classList.toggle('active', l.dataset.page === name);
    });
    if (name === 'cas') loadCAs();
    if (name === 'sign') { loadCASelect('signCA'); loadCASelect('signx509CA'); }
    if (name === 'groups') loadGroups();
    if (name === 'permissions') { loadCASelect('permCA').then(loadPermissions); }
    if (name === 'restrictions') { loadRestrictionsMatrix(); }
    if (name === 'audit') { loadCASelect('auditCA').then(loadAuditLog); }
    if (name === 'hsm') { loadHSMPage(); }
}

// OIDC with PKCE (public client, no client_secret)
let oidcConfig = null;
let oidcDiscovery = null;

async function sha256(plain) {
    const data = new TextEncoder().encode(plain);
    return crypto.subtle.digest('SHA-256', data);
}

function base64url(buf) {
    return btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function generateCodeVerifier() {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    return base64url(arr);
}

async function generateCodeChallenge(verifier) {
    const hash = await sha256(verifier);
    return base64url(hash);
}

(async function init() {
    // Fetch server's OIDC config
    try {
        const res = await fetch('/api/auth/config');
        oidcConfig = await res.json();
        if (oidcConfig.oidc_enabled) {
            // Discover endpoints from the issuer
            const discoRes = await fetch(oidcConfig.issuer_url + '/.well-known/openid-configuration');
            oidcDiscovery = await discoRes.json();
            document.getElementById('oidcDiscoveryLogin').classList.remove('d-none');
        }
    } catch (e) { /* OIDC not available */ }

    // Check if we're returning from an OIDC redirect with an auth code
    const params = new URLSearchParams(window.location.search);
    if (params.has('code') && params.has('state')) {
        const code = params.get('code');
        const savedState = sessionStorage.getItem('oidc_state');
        const codeVerifier = sessionStorage.getItem('oidc_code_verifier');
        sessionStorage.removeItem('oidc_state');
        sessionStorage.removeItem('oidc_code_verifier');
        window.history.replaceState({}, '', window.location.pathname);

        if (savedState && params.get('state') === savedState && codeVerifier && oidcDiscovery) {
            try {
                const tokenRes = await fetch(oidcDiscovery.token_endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({
                        grant_type: 'authorization_code',
                        client_id: oidcConfig.client_id,
                        code: code,
                        redirect_uri: window.location.origin + '/',
                        code_verifier: codeVerifier,
                    }),
                });
                const tokens = await tokenRes.json();
                if (tokens.id_token) {
                    API.authHeader = 'Bearer ' + tokens.id_token;
                    if (tokens.refresh_token) API.refreshToken = tokens.refresh_token;
                    currentUser = await API.get('/api/me');
                    onLogin();
                    return;
                } else {
                    showLoginError(tokens.error_description || tokens.error || 'Token exchange failed');
                }
            } catch (err) {
                showLoginError('OIDC token exchange failed: ' + err.message);
            }
        } else {
            showLoginError('Invalid OIDC state — possible CSRF. Please try again.');
        }
    }

    // Restore session
    if (API.authHeader) {
        try {
            currentUser = await API.get('/api/me');
            onLogin();
        } catch (e) {
            API.authHeader = null;
        }
    }
})();

document.getElementById('oidcDiscoveryBtn').addEventListener('click', async () => {
    if (!oidcConfig || !oidcDiscovery) return;

    const state = crypto.randomUUID();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    sessionStorage.setItem('oidc_state', state);
    sessionStorage.setItem('oidc_code_verifier', codeVerifier);

    const params = new URLSearchParams({
        response_type: 'code',
        client_id: oidcConfig.client_id,
        redirect_uri: window.location.origin + '/',
        scope: 'openid profile email',
        state: state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
    });
    window.location.href = oidcDiscovery.authorization_endpoint + '?' + params.toString();
});

// Login
function showLoginError(msg) {
    API.authHeader = null;
    document.getElementById('loginError').textContent = msg;
    document.getElementById('loginError').classList.remove('d-none');
}

document.getElementById('basicLoginForm').addEventListener('submit', async e => {
    e.preventDefault();
    const user = document.getElementById('loginUser').value;
    const pass = document.getElementById('loginPass').value;
    API.authHeader = 'Basic ' + btoa(user + ':' + pass);
    try {
        currentUser = await API.get('/api/me');
        onLogin();
    } catch (err) {
        showLoginError(err.message);
    }
});

document.getElementById('oidcLoginBtn').addEventListener('click', async () => {
    const token = document.getElementById('oidcToken').value.trim();
    API.authHeader = 'Bearer ' + token;
    try {
        currentUser = await API.get('/api/me');
        onLogin();
    } catch (err) {
        showLoginError(err.message);
    }
});

function onLogin() {
    document.getElementById('loginError').classList.add('d-none');
    document.getElementById('loginPage').classList.add('d-none');
    document.getElementById('mainContent').classList.remove('d-none');
    document.getElementById('logoutItem').classList.remove('d-none');
    document.getElementById('userInfo').innerHTML =
        `<a class="nav-link text-info" href="#" id="userInfoLink" role="button"><i class="bi bi-person-circle"></i> ${esc(currentUser.name || currentUser.sub)}${currentUser.is_root ? ' (root)' : ''}</a>`;
    document.getElementById('userInfoLink').addEventListener('click', e => {
        e.preventDefault();
        showUserInfoModal();
    });
    tokenManager.scheduleRefresh();
    checkHSMAuditStatus();
    showPage('cas');
}

async function checkHSMAuditStatus() {
    const hsmNav = document.querySelector('[data-page="hsm"]');
    try {
        const info = await API.get('/api/hsm/info');
        if (hsmNav) hsmNav.closest('.nav-item').classList.remove('d-none');
        const banner = document.getElementById('hsmAuditWarning');
        if (info.suppress_audit_warning) {
            banner.classList.add('d-none');
        } else if (!info.available || !info.audit_provisioned || !info.force_audit) {
            banner.classList.remove('d-none');
        } else {
            banner.classList.add('d-none');
        }
    } catch (e) {
        // HSM not configured — hide HSM tab and warning
        if (hsmNav) hsmNav.closest('.nav-item').classList.add('d-none');
        document.getElementById('hsmAuditWarning').classList.add('d-none');
    }
}

function showUserInfoModal() {
    const body = document.getElementById('userInfoModalBody');
    let html = '<table class="table table-sm mb-0">';

    // Server-side user info
    const fields = [
        ['Subject', currentUser.sub],
        ['Name', currentUser.name],
        ['Email', currentUser.email],
        ['Root', currentUser.is_root ? 'Yes' : 'No'],
    ];
    for (const [label, value] of fields) {
        if (value) html += `<tr><th class="text-nowrap">${esc(label)}</th><td><code>${esc(String(value))}</code></td></tr>`;
    }

    // Decode JWT claims if Bearer token
    const authHeader = API.authHeader;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7);
        const parts = token.split('.');
        if (parts.length === 3) {
            try {
                const header = JSON.parse(atob(parts[0].replace(/-/g,'+').replace(/_/g,'/')));
                const payload = JSON.parse(atob(parts[1].replace(/-/g,'+').replace(/_/g,'/')));

                html += '<tr><td colspan="2"><hr class="my-2"></td></tr>';
                html += '<tr><th colspan="2">JWT Header</th></tr>';
                for (const [k, v] of Object.entries(header)) {
                    html += `<tr><th class="text-nowrap ps-3">${esc(k)}</th><td><code>${esc(String(v))}</code></td></tr>`;
                }

                html += '<tr><th colspan="2">JWT Claims</th></tr>';
                for (const [k, v] of Object.entries(payload)) {
                    let display = v;
                    if ((k === 'exp' || k === 'iat' || k === 'auth_time' || k === 'nbf') && typeof v === 'number') {
                        display = new Date(v * 1000).toLocaleString() + ` (${v})`;
                    } else if (typeof v === 'object') {
                        display = JSON.stringify(v);
                    }
                    html += `<tr><th class="text-nowrap ps-3">${esc(k)}</th><td style="word-break:break-all"><code>${esc(String(display))}</code></td></tr>`;
                }
            } catch (e) { /* not a valid JWT */ }
        }
    }

    html += '</table>';
    body.innerHTML = html;
    new bootstrap.Modal(document.getElementById('userInfoModal')).show();
}

function logout() {
    tokenManager.cancelRefresh();
    API.authHeader = null;
    API.refreshToken = null;
    currentUser = null;
    document.getElementById('mainContent').classList.add('d-none');
    document.getElementById('logoutItem').classList.add('d-none');
    document.getElementById('userInfo').innerHTML = '';
    document.getElementById('loginPage').classList.remove('d-none');
    document.getElementById('loginError').classList.add('d-none');
    document.getElementById('loginPass').value = '';
    document.getElementById('oidcToken').value = '';
    document.getElementById('hsmAuditWarning').classList.add('d-none');
}

document.getElementById('logoutBtn').addEventListener('click', e => {
    e.preventDefault();
    logout();
});

// CAs
async function loadCAs() {
    try {
        const cas = await API.get('/api/keys');
        const tbody = document.getElementById('casTableBody');
        tbody.innerHTML = cas.map(ca => `
            <tr>
                <td><strong>${esc(ca.label)}</strong></td>
                <td>${truncated(ca.id, 8)}</td>
                <td>${ca.parent_id ? truncated(ca.parent_id, 8) : '<span class="badge bg-primary">root</span>'}</td>
                <td><span class="badge bg-secondary">${esc(ca.key_type)}</span></td>
                <td>${truncated(ca.pkcs11_uri, 40)}</td>
                <td class="text-nowrap">
                    ${ca.public_key ? `<div class="btn-group me-1"><button class="btn btn-sm btn-outline-info dropdown-toggle" data-bs-toggle="dropdown" data-bs-display="static" title="Copy public key"><i class="bi bi-clipboard"></i></button><ul class="dropdown-menu dropdown-menu-end"><li><a class="dropdown-item" href="#" onclick="copyPubKey('${ca.id}','pem');return false"><i class="bi bi-file-earmark-lock me-1"></i>PEM format</a></li><li><a class="dropdown-item" href="#" onclick="copyPubKey('${ca.id}','ssh');return false"><i class="bi bi-terminal me-1"></i>OpenSSH format</a></li></ul></div>` : ''}
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteCA('${ca.id}')"><i class="bi bi-trash"></i></button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

document.getElementById('addCABtn').addEventListener('click', async () => {
    await loadCASelect('caParent');
    new bootstrap.Modal(document.getElementById('addCAModal')).show();
});

document.getElementById('saveCABtn').addEventListener('click', async () => {
    try {
        const parentVal = document.getElementById('caParent').value;
        await API.post('/api/keys', {
            label: document.getElementById('caLabel').value,
            parent_id: parentVal || undefined,
            pkcs11_uri: document.getElementById('caPKCS11URI').value,
            key_type: document.getElementById('caKeyType').value,
            public_key: document.getElementById('caPublicKey').value,
        });
        bootstrap.Modal.getInstance(document.getElementById('addCAModal')).hide();
        showToast('Success', 'CA created');
        loadCAs();
    } catch (err) {
        showToast('Error', err.message, true);
    }
});

async function deleteCA(id) {
    if (!await modalConfirm('Delete CA', 'Delete this CA? All associated permissions will be removed.')) return;
    try {
        await API.del(`/api/keys/${id}`);
        showToast('Success', 'CA deleted');
        loadCAs();
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

async function copyPubKey(id, format) {
    try {
        await tokenManager.refreshIfNeeded();
        const headers = {};
        if (API.authHeader) headers['Authorization'] = API.authHeader;
        const resp = await fetch(`/api/keys/${id}/public-key?format=${format}`, { headers });
        if (!resp.ok) throw new Error('Failed to fetch public key');
        const text = await resp.text();
        copyToClipboard(text.trim(), `Public key copied (${format === 'pem' ? 'PEM' : 'OpenSSH'})`);
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

async function loadCASelect(selectId) {
    try {
        const cas = await API.get('/api/keys');
        const sel = document.getElementById(selectId);
        const firstOpt = sel.querySelector('option');
        sel.innerHTML = '';
        if (firstOpt && firstOpt.value === '') sel.appendChild(firstOpt);
        cas.forEach(ca => {
            const opt = document.createElement('option');
            opt.value = ca.id;
            opt.textContent = ca.label;
            sel.appendChild(opt);
        });
    } catch (err) { /* ignore */ }
}

// Sign Certificate — restriction-aware UI
let activeRestrictions = null;

document.getElementById('signCA').addEventListener('change', async () => {
    const caId = document.getElementById('signCA').value;
    activeRestrictions = null;
    applySignRestrictions(null);
    if (!caId) return;
    try {
        activeRestrictions = await API.get(`/api/keys/${caId}/my-restrictions`);
        applySignRestrictions(activeRestrictions);
    } catch (e) { /* ignore */ }
});

function applySignRestrictions(rs) {
    const keyIdField = document.getElementById('signKeyID');
    const reasonField = document.getElementById('signReason');
    const reasonGroup = reasonField.closest('.mb-3');
    const extField = document.getElementById('signExtensions');
    const extGroup = extField.closest('.mb-3');
    const critField = document.getElementById('signCriticalOpts');
    const critGroup = critField.closest('.mb-3');
    const certTypeField = document.getElementById('signCertType');
    const principalsField = document.getElementById('signPrincipals');
    const validBeforeField = document.getElementById('signValidBefore');

    // Reset all fields to unrestricted
    keyIdField.disabled = false;
    keyIdField.placeholder = 'auto (user subject)';
    reasonGroup.style.display = '';
    reasonField.required = false;
    extGroup.style.display = '';
    extField.disabled = false;
    critGroup.style.display = '';
    critField.disabled = false;
    certTypeField.disabled = false;
    for (const opt of certTypeField.options) opt.disabled = false;
    principalsField.placeholder = 'user1,user2';
    principalsField.title = '';
    validBeforeField.placeholder = '+52w, +1d, RFC3339...';
    validBeforeField.title = '';

    if (!rs) return;

    // Force email key ID
    if (rs.force_key_id_email) {
        keyIdField.disabled = true;
        keyIdField.placeholder = 'auto: user email';
        keyIdField.value = '';
    }

    // Require reason
    if (rs.require_reason) {
        reasonGroup.style.display = '';
        reasonField.required = true;
    } else {
        reasonGroup.style.display = 'none';
        reasonField.value = '';
    }

    // Deny extensions
    if (rs.deny_extensions) {
        extGroup.style.display = 'none';
        extField.value = '';
    } else if (rs.allowed_extensions && rs.allowed_extensions.length) {
        extField.placeholder = 'Allowed: ' + rs.allowed_extensions.join(', ');
    }

    // Deny critical options
    if (rs.deny_critical_options) {
        critGroup.style.display = 'none';
        critField.value = '';
    }

    // Restrict cert types
    if (rs.allowed_cert_types && rs.allowed_cert_types.length) {
        for (const opt of certTypeField.options) {
            opt.disabled = !rs.allowed_cert_types.includes(opt.value);
        }
        if (!rs.allowed_cert_types.includes(certTypeField.value)) {
            certTypeField.value = rs.allowed_cert_types[0];
        }
    }

    // Show allowed principals hint
    if (rs.allowed_principals && rs.allowed_principals.length) {
        principalsField.placeholder = 'Allowed: ' + rs.allowed_principals.join(', ');
        principalsField.title = 'Restricted to: ' + rs.allowed_principals.join(', ');
    }

    // Show max validity hint
    if (rs.max_validity_secs) {
        validBeforeField.placeholder = 'max: ' + formatDuration(rs.max_validity_secs);
        validBeforeField.title = 'Maximum validity: ' + formatDuration(rs.max_validity_secs);
    }
}

document.getElementById('signForm').addEventListener('submit', async e => {
    e.preventDefault();
    try {
        const principals = document.getElementById('signPrincipals').value;
        let extensions = null;
        const extStr = document.getElementById('signExtensions').value.trim();
        if (extStr) extensions = JSON.parse(extStr);
        let critOpts = null;
        const critStr = document.getElementById('signCriticalOpts').value.trim();
        if (critStr) critOpts = JSON.parse(critStr);

        const result = await API.post(`/api/keys/${document.getElementById('signCA').value}/sign`, {
            public_key: document.getElementById('signPubKey').value,
            cert_type: document.getElementById('signCertType').value,
            key_id: document.getElementById('signKeyID').value || undefined,
            reason: document.getElementById('signReason').value || undefined,
            principals: principals ? principals.split(',').map(s => s.trim()) : [],
            valid_after: document.getElementById('signValidAfter').value || undefined,
            valid_before: document.getElementById('signValidBefore').value || undefined,
            extensions: extensions,
            critical_options: critOpts,
        });
        document.getElementById('resultKeyID').value = result.key_id;
        document.getElementById('resultCert').value = result.certificate;
        document.getElementById('signResult').classList.remove('d-none');
        showToast('Success', 'Certificate signed');
    } catch (err) {
        showToast('Error', err.message, true);
    }
});

// X.509 Certificate Signing — parse CSR on input
let csrParseTimer = null;
document.getElementById('signx509CSR').addEventListener('input', () => {
    clearTimeout(csrParseTimer);
    csrParseTimer = setTimeout(parseAndDisplayCSR, 400);
});

async function parseAndDisplayCSR() {
    const csrText = document.getElementById('signx509CSR').value.trim();
    const infoDiv = document.getElementById('csrInfo');
    const tbody = document.getElementById('csrInfoBody');
    if (!csrText || !csrText.includes('BEGIN CERTIFICATE REQUEST')) {
        infoDiv.classList.add('d-none');
        return;
    }
    try {
        const info = await API.post('/api/parse-csr', { csr: csrText });
        tbody.innerHTML = '';
        const addRow = (label, value) => {
            if (!value) return;
            tbody.innerHTML += `<tr><td class="fw-bold text-nowrap" style="width:1%">${esc(label)}</td><td class="font-monospace">${esc(value)}</td></tr>`;
        };
        addRow('Algorithm', info.public_key_algorithm);
        const subj = info.subject || {};
        if (subj.CN) addRow('Common Name', subj.CN);
        if (subj.O) addRow('Organization', subj.O);
        if (subj.OU) addRow('Org Unit', subj.OU);
        if (subj.C) addRow('Country', subj.C);
        if (subj.ST) addRow('State', subj.ST);
        if (subj.L) addRow('Locality', subj.L);
        const sans = info.sans || {};
        if (sans.dns) addRow('DNS SANs', sans.dns.join(', '));
        if (sans.ip) addRow('IP SANs', sans.ip.join(', '));
        if (sans.email) addRow('Email SANs', sans.email.join(', '));
        infoDiv.classList.remove('d-none');
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="2" class="text-danger">${esc(err.message)}</td></tr>`;
        infoDiv.classList.remove('d-none');
    }
}

document.getElementById('signx509Form').addEventListener('submit', async e => {
    e.preventDefault();
    try {
        const result = await API.post(`/api/keys/${document.getElementById('signx509CA').value}/sign-x509`, {
            csr: document.getElementById('signx509CSR').value,
            valid_before: document.getElementById('signx509ValidBefore').value || '+365d',
        });
        document.getElementById('x509ResultSerial').value = result.serial;
        document.getElementById('x509ResultCert').value = result.certificate;
        document.getElementById('signx509Result').classList.remove('d-none');
        showToast('Success', 'X.509 certificate signed');
    } catch (err) {
        showToast('Error', err.message, true);
    }
});


// Groups
let selectedGroupId = null;

async function loadGroups() {
    try {
        const groups = await API.get('/api/groups');
        const tbody = document.getElementById('groupsTableBody');
        tbody.innerHTML = groups.map(g => `
            <tr>
                <td>${esc(g.name)}</td>
                <td>${truncated(g.id, 8)}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary me-1" onclick="showMembers('${g.id}', '${esc(g.name)}')"><i class="bi bi-people"></i></button>
                    <button class="btn btn-sm btn-outline-danger" onclick="deleteGroup('${g.id}')"><i class="bi bi-trash"></i></button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

document.getElementById('addGroupBtn').addEventListener('click', async () => {
    const name = await modalInput('Create Group', 'Group name', 'e.g. developers');
    if (!name) return;
    try {
        await API.post('/api/groups', { name });
        showToast('Success', 'Group created');
        loadGroups();
    } catch (err) {
        showToast('Error', err.message, true);
    }
});

async function deleteGroup(id) {
    if (!await modalConfirm('Delete Group', 'Delete this group? Members will be removed.')) return;
    try {
        await API.del(`/api/groups/${id}`);
        showToast('Success', 'Group deleted');
        loadGroups();
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

async function showMembers(groupId, groupName) {
    selectedGroupId = groupId;
    document.getElementById('groupMembersTitle').textContent = groupName;
    document.getElementById('groupMembersPanel').style.display = 'block';
    try {
        const members = await API.get(`/api/groups/${groupId}/members`);
        const list = document.getElementById('groupMembersList');
        list.innerHTML = members.map(sub => `
            <li class="list-group-item d-flex justify-content-between align-items-center">
                <code>${esc(sub)}</code>
                <button class="btn btn-sm btn-outline-danger" onclick="removeMember('${groupId}', '${esc(sub)}')"><i class="bi bi-x-lg"></i></button>
            </li>
        `).join('');
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

document.getElementById('addMemberBtn').addEventListener('click', async () => {
    if (!selectedGroupId) return;
    const sub = await modalInput('Add Member', 'User subject (sub)', 'e.g. user-id or email');
    if (!sub) return;
    try {
        await API.post(`/api/groups/${selectedGroupId}/members`, { user_sub: sub });
        showToast('Success', 'Member added');
        showMembers(selectedGroupId, document.getElementById('groupMembersTitle').textContent);
    } catch (err) {
        showToast('Error', err.message, true);
    }
});

async function removeMember(groupId, sub) {
    try {
        await API.del(`/api/groups/${groupId}/members/${sub}`);
        showToast('Success', 'Member removed');
        showMembers(groupId, document.getElementById('groupMembersTitle').textContent);
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

// Permissions
document.getElementById('permCA').addEventListener('change', loadPermissions);

async function loadPermissions() {
    const caId = document.getElementById('permCA').value;
    if (!caId) return;
    try {
        const [perms, rsList] = await Promise.all([
            API.get(`/api/keys/${caId}/permissions`),
            API.get(`/api/keys/${caId}/restriction-sets`),
        ]);
        const rsMap = {};
        rsList.forEach(rs => rsMap[rs.id] = rs.name);

        const tbody = document.getElementById('permTableBody');
        tbody.innerHTML = perms.map(p => `
            <tr>
                <td><span class="badge ${p.entity_type === 'user' ? 'bg-info' : 'bg-warning'}">${esc(p.entity_type)}</span></td>
                <td>${truncated(p.entity_id, 20)}</td>
                <td><span class="badge bg-primary">${esc(p.permission)}</span></td>
                <td>${p.ssh_restriction_set_id ? `<span class="badge bg-secondary">${esc(rsMap[p.ssh_restriction_set_id] || p.ssh_restriction_set_id)}</span>` : '<span class="text-muted">default</span>'}</td>
                <td>${p.x509_restriction_set_id ? `<span class="badge bg-secondary">${esc(rsMap[p.x509_restriction_set_id] || p.x509_restriction_set_id)}</span>` : '<span class="text-muted">default</span>'}</td>
                <td>
                    <button class="btn btn-sm btn-outline-danger" onclick="revokePermission('${caId}', '${p.entity_type}', '${p.entity_id}', '${p.permission}')"><i class="bi bi-x-lg"></i></button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

document.getElementById('grantPermBtn').addEventListener('click', async () => {
    const caId = document.getElementById('permCA').value;
    if (!caId) { showToast('Error', 'Select a CA first', true); return; }
    try {
        const rsList = await API.get(`/api/keys/${caId}/restriction-sets`);
        const sshSel = document.getElementById('permSSHRestrictionSet');
        const x509Sel = document.getElementById('permX509RestrictionSet');
        sshSel.innerHTML = '<option value="">None (use key default)</option>';
        x509Sel.innerHTML = '<option value="">None (use key default)</option>';
        rsList.forEach(rs => {
            const opt = document.createElement('option');
            opt.value = rs.id;
            opt.textContent = rs.name + (rs.ca_id ? '' : ' (global)');
            if (rs.type === 'x509') {
                x509Sel.appendChild(opt);
            } else {
                sshSel.appendChild(opt);
            }
        });
    } catch (e) {}
    new bootstrap.Modal(document.getElementById('grantPermModal')).show();
});

document.getElementById('savePermBtn').addEventListener('click', async () => {
    const caId = document.getElementById('permCA').value;
    if (!caId) { showToast('Error', 'Select a CA first', true); return; }
    try {
        const sshRS = document.getElementById('permSSHRestrictionSet').value;
        const x509RS = document.getElementById('permX509RestrictionSet').value;
        await API.post(`/api/keys/${caId}/permissions`, {
            entity_type: document.getElementById('permEntityType').value,
            entity_id: document.getElementById('permEntityID').value,
            permission: document.getElementById('permPermission').value,
            ssh_restriction_set_id: sshRS || undefined,
            x509_restriction_set_id: x509RS || undefined,
        });
        bootstrap.Modal.getInstance(document.getElementById('grantPermModal')).hide();
        showToast('Success', 'Permission granted');
        loadPermissions();
    } catch (err) {
        showToast('Error', err.message, true);
    }
});

async function revokePermission(caId, entityType, entityId, permission) {
    if (!await modalConfirm('Revoke Permission', 'Revoke this permission?')) return;
    try {
        await API.del(`/api/keys/${caId}/permissions`, {
            entity_type: entityType,
            entity_id: entityId,
            permission: permission,
        });
        showToast('Success', 'Permission revoked');
        loadPermissions();
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

// Audit Log
var auditOffset = 0;
var auditLimit = 25;

document.getElementById('auditCA').addEventListener('change', () => { auditOffset = 0; loadAuditLog(); });

async function loadAuditLog() {
    try {
        const caId = document.getElementById('auditCA').value;
        let url = `/api/audit-log?limit=${auditLimit}&offset=${auditOffset}`;
        if (caId) url += `&ca_id=${encodeURIComponent(caId)}`;
        const data = await API.get(url);
        const tbody = document.getElementById('auditTableBody');
        if (data.entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="8" class="text-muted text-center">No audit log entries</td></tr>';
        } else {
            tbody.innerHTML = data.entries.map(e => `
                <tr>
                    <td class="text-nowrap small">${new Date(e.timestamp).toLocaleString()}</td>
                    <td>${truncated(e.user_email || e.user_sub, 20)}</td>
                    <td><strong>${esc(e.ca_label)}</strong></td>
                    <td>${truncated(e.key_id, 25)}</td>
                    <td><span class="badge bg-secondary">${esc(e.cert_type || 'user')}</span></td>
                    <td>${(e.principals || []).map(p => `<code>${esc(p)}</code>`).join(', ')}</td>
                    <td class="small">${new Date(e.valid_before).toLocaleString()}</td>
                    <td><button class="btn btn-sm btn-outline-info" onclick="showAuditDetail('${e.id}')"><i class="bi bi-info-circle"></i></button></td>
                </tr>
            `).join('');
        }

        // Pagination
        const totalPages = Math.ceil(data.total / auditLimit);
        const currentPage = Math.floor(auditOffset / auditLimit);
        const pag = document.getElementById('auditPagination');
        if (totalPages <= 1) { pag.innerHTML = ''; return; }
        let pagHtml = '';
        pagHtml += `<li class="page-item ${currentPage === 0 ? 'disabled' : ''}"><a class="page-link" href="#" onclick="auditGoPage(${currentPage - 1}); return false;">Prev</a></li>`;
        for (let i = 0; i < totalPages && i < 10; i++) {
            pagHtml += `<li class="page-item ${i === currentPage ? 'active' : ''}"><a class="page-link" href="#" onclick="auditGoPage(${i}); return false;">${i + 1}</a></li>`;
        }
        pagHtml += `<li class="page-item ${currentPage >= totalPages - 1 ? 'disabled' : ''}"><a class="page-link" href="#" onclick="auditGoPage(${currentPage + 1}); return false;">Next</a></li>`;
        pag.innerHTML = pagHtml;
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

function auditGoPage(page) {
    auditOffset = page * auditLimit;
    loadAuditLog();
}

// Store entries for detail view
let auditEntries = {};
const origLoadAuditLog = loadAuditLog;

async function showAuditDetail(id) {
    // Fetch all entries from current view to find the one we need
    const caId = document.getElementById('auditCA').value;
    let url = `/api/audit-log?limit=500&offset=0`;
    if (caId) url += `&ca_id=${encodeURIComponent(caId)}`;
    try {
        const data = await API.get(url);
        const entry = data.entries.find(e => e.id === id);
        if (!entry) { showToast('Error', 'Entry not found', true); return; }

        const body = document.getElementById('userInfoModalBody');
        const fields = [
            ['Timestamp', new Date(entry.timestamp).toLocaleString()],
            ['User', entry.user_email || entry.user_sub],
            ['User Name', entry.user_name],
            ['User Subject', entry.user_sub],
            ['CA', entry.ca_label],
            ['CA ID', entry.ca_id],
            ['Key ID', entry.key_id],
            ['Serial', entry.serial],
            ['Cert Type', entry.cert_type || 'user'],
            ['Principals', (entry.principals || []).join(', ')],
            ['Valid After', new Date(entry.valid_after).toLocaleString()],
            ['Valid Before', new Date(entry.valid_before).toLocaleString()],
            ['Extensions', entry.extensions ? JSON.stringify(entry.extensions, null, 2) : 'default'],
            ['Critical Options', entry.critical_options ? JSON.stringify(entry.critical_options, null, 2) : 'none'],
            ['Public Key', entry.public_key],
            ['Restriction Set ID', entry.restriction_set_id || 'none'],
        ];
        let html = '<table class="table table-sm mb-0">';
        for (const [label, value] of fields) {
            if (value) html += `<tr><th class="text-nowrap">${esc(label)}</th><td style="word-break:break-all"><code>${esc(String(value))}</code></td></tr>`;
        }
        html += '</table>';
        body.innerHTML = html;
        document.querySelector('#userInfoModal .modal-title').innerHTML = '<i class="bi bi-journal-text"></i> Audit Log Entry';
        new bootstrap.Modal(document.getElementById('userInfoModal')).show();
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

function switchAuditTab(tab) {
    document.getElementById('auditSignTab').classList.toggle('active', tab === 'sign');
    document.getElementById('auditAccessTab').classList.toggle('active', tab === 'access');
    document.getElementById('auditSignPane').style.display = tab === 'sign' ? '' : 'none';
    document.getElementById('auditAccessPane').style.display = tab === 'access' ? '' : 'none';
    if (tab === 'access') loadAccessLog();
}

// Access Log
var accessOffset = 0;
var accessLimit = 50;

async function loadAccessLog() {
    try {
        const data = await API.get(`/api/access-log?limit=${accessLimit}&offset=${accessOffset}`);
        const tbody = document.getElementById('accessTableBody');
        if (data.entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="text-muted text-center">No access log entries</td></tr>';
        } else {
            tbody.innerHTML = data.entries.map(e => {
                const statusCls = e.status >= 400 ? 'text-danger' : (e.status >= 300 ? 'text-warning' : '');
                return `<tr>
                    <td class="text-nowrap small">${new Date(e.timestamp).toLocaleString()}</td>
                    <td><code>${esc(e.user_sub)}</code></td>
                    <td><span class="badge bg-secondary">${esc(e.method)}</span></td>
                    <td><code>${esc(e.path)}</code></td>
                    <td class="${statusCls}">${e.status}</td>
                    <td class="small">${esc(e.ip)}</td>
                </tr>`;
            }).join('');
        }

        const totalPages = Math.ceil(data.total / accessLimit);
        const currentPage = Math.floor(accessOffset / accessLimit);
        const pag = document.getElementById('accessPagination');
        if (totalPages <= 1) { pag.innerHTML = ''; return; }
        let html = `<li class="page-item ${currentPage === 0 ? 'disabled' : ''}"><a class="page-link" href="#" onclick="accessGoPage(${currentPage - 1}); return false;">Prev</a></li>`;
        for (let i = Math.max(0, currentPage - 4); i < Math.min(totalPages, currentPage + 5); i++) {
            html += `<li class="page-item ${i === currentPage ? 'active' : ''}"><a class="page-link" href="#" onclick="accessGoPage(${i}); return false;">${i + 1}</a></li>`;
        }
        html += `<li class="page-item ${currentPage >= totalPages - 1 ? 'disabled' : ''}"><a class="page-link" href="#" onclick="accessGoPage(${currentPage + 1}); return false;">Next</a></li>`;
        pag.innerHTML = html;
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

function accessGoPage(page) {
    accessOffset = page * accessLimit;
    loadAccessLog();
}

document.getElementById('accessExportBtn').addEventListener('click', async () => {
    try {
        const res = await fetch('/api/access-log?export=json', { headers: { 'Authorization': API.authHeader } });
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'access-log.json';
        a.click();
        URL.revokeObjectURL(a.href);
    } catch (err) {
        showToast('Error', err.message, true);
    }
});

document.getElementById('auditExportBtn').addEventListener('click', async () => {
    const caId = document.getElementById('auditCA').value;
    let url = `/api/audit-log?export=json`;
    if (caId) url += `&ca_id=${encodeURIComponent(caId)}`;
    try {
        const res = await fetch(url, { headers: { 'Authorization': API.authHeader } });
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'audit-log.json';
        a.click();
        URL.revokeObjectURL(a.href);
    } catch (err) {
        showToast('Error', err.message, true);
    }
});

// HSM Page
let hsmAttestPEM = null;
let hsmAuditData = null;

async function loadHSMPage() {
    // Load HSM info
    try {
        const info = await API.get('/api/hsm/info');
        const el = document.getElementById('hsmInfoContent');
        if (!info.available) {
            el.innerHTML = `<div class="col"><span class="text-danger"><i class="bi bi-exclamation-circle"></i> HSM not available: ${esc(info.error || 'unknown error')}</span></div>`;
        } else {
            const auditBadge = info.audit_provisioned && info.force_audit
                ? '<span class="badge bg-success">Provisioned</span>'
                : '<span class="badge bg-warning text-dark">Not provisioned</span>';
            el.innerHTML = `
                <div class="col-auto"><strong>Serial:</strong> ${esc(info.serial)}</div>
                <div class="col-auto"><strong>Firmware:</strong> ${esc(info.version)}</div>
                <div class="col-auto"><strong>Part:</strong> ${esc(info.part_number)}</div>
                <div class="col-auto"><strong>Log:</strong> ${esc(info.log_used)}</div>
                <div class="col-auto"><strong>Audit:</strong> ${auditBadge}</div>
            `;
        }
    } catch (e) {
        document.getElementById('hsmInfoContent').innerHTML = `<div class="col text-danger">${esc(e.message)}</div>`;
    }

    // Load attestation
    try {
        const res = await fetch('/api/hsm/attestation', { headers: { 'Authorization': API.authHeader } });
        if (res.ok) {
            hsmAttestPEM = await res.text();
            document.getElementById('hsmAttestCert').textContent = hsmAttestPEM;
        } else {
            const err = await res.json();
            document.getElementById('hsmAttestCert').textContent = 'Error: ' + (err.error || res.statusText);
        }
    } catch (e) {
        document.getElementById('hsmAttestCert').textContent = 'Error: ' + e.message;
    }

    // Load HSM audit log
    try {
        hsmAuditData = await API.get('/api/hsm/audit-log');
        document.getElementById('hsmAuditInfo').innerHTML =
            `Device: <strong>${esc(hsmAuditData.device_serial || 'unknown')}</strong> | Entries: <strong>${hsmAuditData.entries ? hsmAuditData.entries.length : 0}</strong>`;

        const tbody = document.getElementById('hsmAuditBody');
        if (!hsmAuditData.entries || hsmAuditData.entries.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="text-muted">No entries</td></tr>';
        } else {
            tbody.innerHTML = hsmAuditData.entries.map(e => {
                const hashCls = e.hash_valid ? '' : 'text-danger fw-bold';
                return `<tr>
                    <td>${e.number}</td>
                    <td><code>0x${e.command.toString(16).padStart(2,'0')}</code></td>
                    <td><code>0x${e.target_key.toString(16).padStart(4,'0')}</code></td>
                    <td>${e.tick}</td>
                    <td class="${hashCls}">${truncated(e.hash, 12)}</td>
                </tr>`;
            }).join('');
        }
    } catch (e) {
        document.getElementById('hsmAuditInfo').textContent = 'Error: ' + e.message;
    }
}

document.getElementById('downloadAttestBtn').addEventListener('click', () => {
    if (!hsmAttestPEM) return;
    const blob = new Blob([hsmAttestPEM], { type: 'application/x-pem-file' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'device-attestation.pem';
    a.click();
    URL.revokeObjectURL(a.href);
});

document.getElementById('exportSignedBtn').addEventListener('click', async () => {
    try {
        showToast('Info', 'Signing audit log with HSM attestation key...');
        const res = await fetch('/api/hsm/signed-audit-log', { headers: { 'Authorization': API.authHeader } });
        if (!res.ok) { const e = await res.json(); throw new Error(e.error); }
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'signed-audit-log.json';
        a.click();
        URL.revokeObjectURL(a.href);
        showToast('Success', 'Signed audit log exported');
    } catch (err) {
        showToast('Error', err.message, true);
    }
});

document.getElementById('exportCombinedBtn').addEventListener('click', async () => {
    try {
        const res = await fetch('/api/hsm/combined-audit-log', { headers: { 'Authorization': API.authHeader } });
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'combined-audit-log.json';
        a.click();
        URL.revokeObjectURL(a.href);
    } catch (err) {
        showToast('Error', err.message, true);
    }
});

document.getElementById('provisionAuditBtn').addEventListener('click', async () => {
    if (!await modalConfirm('Provision HSM Audit Logging',
        'This will IRREVERSIBLY enable forced audit logging for all cryptographic operations on the YubiHSM. ' +
        'The HSM will refuse operations when the audit log is full until logs are consumed. ' +
        'This cannot be undone without a factory reset. Continue?')) return;
    try {
        const result = await API.post('/api/hsm/provision-audit');
        showToast('Success', 'HSM audit logging provisioned');
        loadHSMPage();
    } catch (err) {
        if (err.message && err.message.includes('boot sentinel')) {
            if (await modalConfirm('Factory Reset Required',
                'The HSM was not factory reset before provisioning. ' +
                'A factory reset will ERASE ALL KEYS AND DATA on the device. ' +
                'After reset, you can re-provision audit logging.\n\n' +
                'Factory reset the YubiHSM now?')) {
                try {
                    await API.post('/api/hsm/factory-reset');
                    showToast('Success', 'HSM factory reset complete. You can now provision audit logging.');
                    loadHSMPage();
                } catch (resetErr) {
                    showToast('Error', 'Factory reset failed: ' + resetErr.message, true);
                }
            }
        } else {
            showToast('Error', err.message, true);
        }
    }
});

document.getElementById('downloadHSMAuditBtn').addEventListener('click', () => {
    if (!hsmAuditData) return;
    const blob = new Blob([JSON.stringify(hsmAuditData, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'hsm-audit-log.json';
    a.click();
    URL.revokeObjectURL(a.href);
});

// Restriction Sets — matrix view

var rsAllSets = {}; // caId -> sets array, cached for edit lookups

async function loadRestrictionsMatrix() {
    const container = document.getElementById('rsMatrixContainer');
    try {
        const [cas, allSets] = await Promise.all([
            API.get('/api/keys'),
            API.get('/api/restriction-sets'),
        ]);

        // Build CA label map and cache sets
        const caMap = {};
        for (const ca of cas) caMap[ca.id] = ca;
        for (const rs of allSets) {
            rs._caLabel = rs.ca_id && caMap[rs.ca_id] ? caMap[rs.ca_id].label : '';
        }

        const allSSH = allSets.filter(rs => rs.type !== 'x509');
        const allX509 = allSets.filter(rs => rs.type === 'x509');

        // --- Section 1: Defaults per CA ---
        let defaultsHTML = '';
        if (cas.length) {
            const sshOpts = allSSH.map(rs =>
                `<option value="${rs.id}">\${sel_${rs.id}} ${esc(rs.name)}${rs._caLabel ? ' (' + esc(rs._caLabel) + ')' : ''}</option>`
            ).join('');
            const x509Opts = allX509.map(rs =>
                `<option value="${rs.id}">\${sel_${rs.id}} ${esc(rs.name)}${rs._caLabel ? ' (' + esc(rs._caLabel) + ')' : ''}</option>`
            ).join('');

            defaultsHTML = `
            <h5 class="mb-3">Defaults per Key</h5>
            <div class="table-responsive mb-4">
                <table class="table table-striped table-bordered align-middle mb-0">
                    <thead><tr><th>Key</th><th>Default SSH Restriction Set</th><th>Default X.509 Restriction Set</th></tr></thead>
                    <tbody>`;
            for (const ca of cas) {
                const sshOptsFinal = allSSH.map(rs =>
                    `<option value="${rs.id}" ${ca.default_ssh_restriction_set_id === rs.id ? 'selected' : ''}>${esc(rs.name)}${rs._caLabel ? ' (' + esc(rs._caLabel) + ')' : ''}</option>`
                ).join('');
                const x509OptsFinal = allX509.map(rs =>
                    `<option value="${rs.id}" ${ca.default_x509_restriction_set_id === rs.id ? 'selected' : ''}>${esc(rs.name)}${rs._caLabel ? ' (' + esc(rs._caLabel) + ')' : ''}</option>`
                ).join('');
                defaultsHTML += `<tr>
                    <td><strong>${esc(ca.label)}</strong></td>
                    <td><select class="form-select form-select-sm" onchange="setDefaultRS('${ca.id}','ssh',this.value)">${sshOptsFinal}</select></td>
                    <td><select class="form-select form-select-sm" onchange="setDefaultRS('${ca.id}','x509',this.value)">${x509OptsFinal}</select></td>
                </tr>`;
            }
            defaultsHTML += '</tbody></table></div>';
        }

        // --- Section 2: Restriction Sets with SSH/X.509 tabs ---
        let setsHTML = `
        <h5 class="mb-3">Restriction Sets</h5>
        <ul class="nav nav-tabs mb-3" role="tablist">
            <li class="nav-item" role="presentation">
                <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#rsGlobalSSH" type="button" role="tab">SSH</button>
            </li>
            <li class="nav-item" role="presentation">
                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#rsGlobalX509" type="button" role="tab">X.509</button>
            </li>
        </ul>
        <div class="tab-content">
            <div class="tab-pane fade show active" id="rsGlobalSSH" role="tabpanel">
                <div class="mb-3"><button class="btn btn-sm btn-success" onclick="addRestrictionSet('','ssh')"><i class="bi bi-plus-lg"></i> New SSH Restriction Set</button></div>
                ${allSSH.length ? allSSH.map(renderRSCard).join('') : '<p class="text-muted">No SSH restriction sets.</p>'}
            </div>
            <div class="tab-pane fade" id="rsGlobalX509" role="tabpanel">
                <div class="mb-3"><button class="btn btn-sm btn-success" onclick="addRestrictionSet('','x509')"><i class="bi bi-plus-lg"></i> New X.509 Restriction Set</button></div>
                ${allX509.length ? allX509.map(renderRSCard).join('') : '<p class="text-muted">No X.509 restriction sets.</p>'}
            </div>
        </div>`;

        container.innerHTML = defaultsHTML + setsHTML;
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

function renderRSCard(rs) {
    const any = '<span class="text-muted">any</span>';
    const unlimited = '<span class="text-muted">unlimited</span>';
    const listOrAny = (arr) => arr && arr.length ? arr.map(v => `<code>${esc(v)}</code>`).join(', ') : any;
    let rows = `<tr><th>Max Validity</th><td>${rs.max_validity_secs ? formatDuration(rs.max_validity_secs) : unlimited}</td></tr>`;
    if (rs.type === 'x509') {
        rows += `<tr><th>Allowed Key Usages</th><td>${listOrAny(rs.allowed_key_usages)}</td></tr>`;
        rows += `<tr><th>Allowed Ext Key Usages</th><td>${listOrAny(rs.allowed_ext_key_usages)}</td></tr>`;
        rows += `<tr><th>Allowed SAN Types</th><td>${listOrAny(rs.allowed_san_types)}</td></tr>`;
        rows += `<tr><th>Allowed SAN Patterns</th><td>${listOrAny(rs.allowed_san_patterns)}</td></tr>`;
        rows += `<tr><th>Allowed Subject Fields</th><td>${listOrAny(rs.allowed_subject_fields)}</td></tr>`;
        rows += `<tr><th>Max Path Length</th><td>${rs.max_path_length != null ? rs.max_path_length : unlimited}</td></tr>`;
        rows += `<tr><th>Deny CA</th><td>${rs.deny_ca ? '<span class="badge bg-danger">Yes</span>' : 'No'}</td></tr>`;
    } else {
        rows += `<tr><th>Allowed Principals</th><td>${listOrAny(rs.allowed_principals)}</td></tr>`;
        rows += `<tr><th>Allowed Cert Types</th><td>${listOrAny(rs.allowed_cert_types)}</td></tr>`;
        rows += `<tr><th>Force Key ID (email)</th><td>${rs.force_key_id_email ? '<span class="badge bg-success">Yes</span>' : 'No'}</td></tr>`;
        rows += `<tr><th>Require Reason</th><td>${rs.require_reason ? '<span class="badge bg-success">Yes</span>' : 'No'}</td></tr>`;
        rows += `<tr><th>Deny Extensions</th><td>${rs.deny_extensions ? '<span class="badge bg-danger">Denied</span>' : 'No'}</td></tr>`;
        rows += `<tr><th>Allowed Extensions</th><td>${rs.deny_extensions ? '<span class="text-muted">n/a</span>' : listOrAny(rs.allowed_extensions)}</td></tr>`;
        rows += `<tr><th>Deny Critical Options</th><td>${rs.deny_critical_options ? '<span class="badge bg-danger">Denied</span>' : 'No'}</td></tr>`;
        rows += `<tr><th>Max Valid-After Offset</th><td>${rs.max_valid_after_offset ? formatDuration(rs.max_valid_after_offset) : unlimited}</td></tr>`;
    }
    const caLabel = rs._caLabel ? `<span class="badge bg-secondary ms-2">${esc(rs._caLabel)}</span>` : '';
    return `
    <div class="card mb-2">
        <div class="card-header py-2 d-flex justify-content-between align-items-center">
            <span><strong class="small">${esc(rs.name)}</strong>${caLabel}</span>
            <div>
                <button class="btn btn-sm btn-outline-primary me-1" onclick="editRestrictionSet('${rs.ca_id}','${rs.id}')"><i class="bi bi-pencil"></i></button>
                <button class="btn btn-sm btn-outline-danger" onclick="deleteRestrictionSet('${rs.id}')"><i class="bi bi-trash"></i></button>
            </div>
        </div>
        <div class="card-body py-2">
            <table class="table table-sm mb-0">${rows}</table>
        </div>
    </div>`;
}

function formatDuration(secs) {
    if (secs >= 86400 && secs % 86400 === 0) return (secs / 86400) + 'd';
    if (secs >= 3600 && secs % 3600 === 0) return (secs / 3600) + 'h';
    if (secs >= 60 && secs % 60 === 0) return (secs / 60) + 'm';
    return secs + 's';
}

async function setDefaultRS(caId, rsType, rsId) {
    try {
        await API.request('PUT', `/api/keys/${caId}/default-restriction-set`, {
            restriction_set_id: rsId || null,
            type: rsType,
        });
        showToast('Success', 'Default restriction set updated');
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

function addRestrictionSet(caId, type) {
    showRSEditor(null, type, caId);
}

async function editRestrictionSet(caId, id) {
    try {
        const sets = rsAllSets[caId] || await API.get(`/api/keys/${caId}/restriction-sets`);
        const rs = sets.find(s => s.id === id);
        if (rs) showRSEditor(rs, null, caId);
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

async function deleteRestrictionSet(id) {
    if (!await modalConfirm('Delete Restriction Set', 'Delete this restriction set? Permissions referencing it will fall back to the CA default.')) return;
    try {
        await API.del(`/api/restriction-sets/${id}`);
        showToast('Success', 'Restriction set deleted');
        loadRestrictionsMatrix();
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

function showRSEditor(existing, defaultType, caId) {
    const isEdit = !!existing;
    const rsType = existing?.type || defaultType || 'ssh';
    const html = `
        <input type="hidden" id="rsEdType" value="${rsType}">
        <div class="mb-3"><label class="form-label">Name</label><input type="text" class="form-control" id="rsEdName" value="${esc(existing?.name || '')}"></div>
        <div class="mb-3"><label class="form-label">Max Validity (seconds, e.g. 86400 for 1 day)</label><input type="number" class="form-control" id="rsEdMaxValidity" value="${existing?.max_validity_secs || ''}"></div>
        <div id="rsEdSSHFields" style="display:${rsType === 'ssh' ? '' : 'none'}">
            <div class="mb-3"><label class="form-label">Allowed Principals (comma-separated, * for any)</label><input type="text" class="form-control" id="rsEdPrincipals" value="${(existing?.allowed_principals || []).join(', ')}"></div>
            <div class="mb-3"><label class="form-label">Allowed Cert Types (comma-separated: user, host)</label><input type="text" class="form-control" id="rsEdCertTypes" value="${(existing?.allowed_cert_types || []).join(', ')}"></div>
            <div class="mb-3 form-check"><input type="checkbox" class="form-check-input" id="rsEdForceEmail" ${existing?.force_key_id_email ? 'checked' : ''}><label class="form-check-label" for="rsEdForceEmail">Force Key ID to user email</label></div>
            <div class="mb-3 form-check"><input type="checkbox" class="form-check-input" id="rsEdRequireReason" ${existing?.require_reason ? 'checked' : ''}><label class="form-check-label" for="rsEdRequireReason">Require reason (appended to key ID)</label></div>
            <div class="mb-3 form-check"><input type="checkbox" class="form-check-input" id="rsEdDenyExt" ${existing?.deny_extensions ? 'checked' : ''}><label class="form-check-label" for="rsEdDenyExt">Deny custom extensions</label></div>
            <div class="mb-3"><label class="form-label">Allowed Extensions (comma-separated, leave empty for any)</label><input type="text" class="form-control" id="rsEdExtensions" value="${(existing?.allowed_extensions || []).join(', ')}"></div>
            <div class="mb-3 form-check"><input type="checkbox" class="form-check-input" id="rsEdDenyCrit" ${existing?.deny_critical_options ? 'checked' : ''}><label class="form-check-label" for="rsEdDenyCrit">Deny critical options</label></div>
            <div class="mb-3"><label class="form-label">Max Valid-After Offset (seconds into the future)</label><input type="number" class="form-control" id="rsEdMaxOffset" value="${existing?.max_valid_after_offset || ''}"></div>
        </div>
        <div id="rsEdX509Fields" style="display:${rsType === 'x509' ? '' : 'none'}">
            <div class="mb-3"><label class="form-label">Allowed Key Usages (comma-separated, e.g. digitalSignature, keyEncipherment)</label><input type="text" class="form-control" id="rsEdKeyUsages" value="${(existing?.allowed_key_usages || []).join(', ')}"></div>
            <div class="mb-3"><label class="form-label">Allowed Ext Key Usages (comma-separated, e.g. serverAuth, clientAuth)</label><input type="text" class="form-control" id="rsEdExtKeyUsages" value="${(existing?.allowed_ext_key_usages || []).join(', ')}"></div>
            <div class="mb-3"><label class="form-label">Allowed SAN Types (comma-separated: dns, ip, email)</label><input type="text" class="form-control" id="rsEdSANTypes" value="${(existing?.allowed_san_types || []).join(', ')}"></div>
            <div class="mb-3"><label class="form-label">Allowed SAN Patterns (comma-separated, e.g. *.example.com, 10.0.0.0/8)</label><input type="text" class="form-control" id="rsEdSANPatterns" value="${(existing?.allowed_san_patterns || []).join(', ')}"></div>
            <div class="mb-3"><label class="form-label">Allowed Subject Fields (comma-separated: CN, O, OU, C, ST, L)</label><input type="text" class="form-control" id="rsEdSubjectFields" value="${(existing?.allowed_subject_fields || []).join(', ')}"></div>
            <div class="mb-3"><label class="form-label">Max Path Length (-1 = no CA certs)</label><input type="number" class="form-control" id="rsEdMaxPathLen" value="${existing?.max_path_length != null ? existing.max_path_length : ''}"></div>
            <div class="mb-3 form-check"><input type="checkbox" class="form-check-input" id="rsEdDenyCA" ${existing?.deny_ca ? 'checked' : ''}><label class="form-check-label" for="rsEdDenyCA">Deny CA certificates</label></div>
        </div>
    `;

    document.getElementById('inputModalTitle').textContent = (isEdit ? 'Edit ' : 'New ') + (rsType === 'x509' ? 'X.509' : 'SSH') + ' Restriction Set';
    document.getElementById('inputModalLabel').textContent = '';
    document.getElementById('inputModalValue').style.display = 'none';
    const body = document.getElementById('inputModal').querySelector('.modal-body');
    body.innerHTML = html;

    const modal = new bootstrap.Modal(document.getElementById('inputModal'));

    const okBtn = document.getElementById('inputModalOk');
    const handler = async () => {
        okBtn.removeEventListener('click', handler);
        const edCaId = '';
        const selectedType = document.getElementById('rsEdType').value;
        const data = {
            name: document.getElementById('rsEdName').value,
            type: selectedType,
            max_validity_secs: parseInt(document.getElementById('rsEdMaxValidity').value) || null,
        };
        if (selectedType === 'ssh') {
            data.allowed_principals = splitTrim(document.getElementById('rsEdPrincipals').value);
            data.allowed_cert_types = splitTrim(document.getElementById('rsEdCertTypes').value);
            data.force_key_id_email = document.getElementById('rsEdForceEmail').checked;
            data.require_reason = document.getElementById('rsEdRequireReason').checked;
            data.deny_extensions = document.getElementById('rsEdDenyExt').checked;
            data.allowed_extensions = splitTrim(document.getElementById('rsEdExtensions').value);
            data.deny_critical_options = document.getElementById('rsEdDenyCrit').checked;
            data.max_valid_after_offset = parseInt(document.getElementById('rsEdMaxOffset').value) || null;
        } else {
            data.allowed_key_usages = splitTrim(document.getElementById('rsEdKeyUsages').value);
            data.allowed_ext_key_usages = splitTrim(document.getElementById('rsEdExtKeyUsages').value);
            data.allowed_san_types = splitTrim(document.getElementById('rsEdSANTypes').value);
            data.allowed_san_patterns = splitTrim(document.getElementById('rsEdSANPatterns').value);
            data.allowed_subject_fields = splitTrim(document.getElementById('rsEdSubjectFields').value);
            const mpl = document.getElementById('rsEdMaxPathLen').value;
            data.max_path_length = mpl !== '' ? parseInt(mpl) : null;
            data.deny_ca = document.getElementById('rsEdDenyCA').checked;
        }
        try {
            if (isEdit) {
                await API.request('PUT', `/api/restriction-sets/${existing.id}`, data);
            } else if (edCaId) {
                await API.post(`/api/keys/${edCaId}/restriction-sets`, data);
            } else {
                await API.post('/api/restriction-sets', data);
            }
            modal.hide();
            showToast('Success', isEdit ? 'Restriction set updated' : 'Restriction set created');
            loadRestrictionsMatrix();
        } catch (err) {
            showToast('Error', err.message, true);
        }
        restoreInputModal();
    };
    okBtn.addEventListener('click', handler);
    document.getElementById('inputModal').addEventListener('hidden.bs.modal', () => {
        okBtn.removeEventListener('click', handler);
        restoreInputModal();
    }, { once: true });
    modal.show();
}

function restoreInputModal() {
    const body = document.getElementById('inputModal').querySelector('.modal-body');
    body.innerHTML = `
        <label class="form-label" id="inputModalLabel"></label>
        <input type="text" class="form-control" id="inputModalValue">
    `;
    document.getElementById('inputModalValue').style.display = '';
}

function splitTrim(s) {
    if (!s || !s.trim()) return [];
    return s.split(',').map(x => x.trim()).filter(x => x);
}

// Utility
function esc(s) {
    if (!s) return '';
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
}

document.addEventListener('click', e => {
    const btn = e.target.closest('[data-copy]');
    if (btn) copyToClipboard(btn.dataset.copy, btn.dataset.copyMsg);

    const trunc = e.target.closest('[data-full]');
    if (trunc) {
        const full = trunc.dataset.full;
        const short = trunc.dataset.short;
        if (trunc.textContent === full) {
            trunc.textContent = short;
        } else {
            trunc.textContent = full;
        }
    }
});

function truncated(value, len) {
    if (!value) return '';
    if (value.length <= len) return `<code class="small">${esc(value)}</code>`;
    return `<code class="small text-truncate-toggle" role="button" data-full="${esc(value)}" data-short="${esc(value.substring(0, len))}...">${esc(value.substring(0, len))}...</code>`;
}

function copyToClipboard(text, message) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied', message || 'Copied to clipboard');
    }).catch(() => {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
        showToast('Copied', message || 'Copied to clipboard');
    });
}

function modalInput(title, label, placeholder) {
    return new Promise(resolve => {
        document.getElementById('inputModalTitle').textContent = title;
        document.getElementById('inputModalLabel').textContent = label;
        const input = document.getElementById('inputModalValue');
        input.value = '';
        input.placeholder = placeholder || '';
        const modal = new bootstrap.Modal(document.getElementById('inputModal'));
        const okBtn = document.getElementById('inputModalOk');
        const onOk = () => { cleanup(); modal.hide(); resolve(input.value.trim()); };
        const onHidden = () => { cleanup(); resolve(null); };
        const onKey = e => { if (e.key === 'Enter') onOk(); };
        function cleanup() {
            okBtn.removeEventListener('click', onOk);
            input.removeEventListener('keydown', onKey);
            document.getElementById('inputModal').removeEventListener('hidden.bs.modal', onHidden);
        }
        okBtn.addEventListener('click', onOk);
        input.addEventListener('keydown', onKey);
        document.getElementById('inputModal').addEventListener('hidden.bs.modal', onHidden, { once: true });
        modal.show();
        setTimeout(() => input.focus(), 200);
    });
}

function modalConfirm(title, message) {
    return new Promise(resolve => {
        document.getElementById('confirmModalTitle').textContent = title;
        document.getElementById('confirmModalMessage').textContent = message;
        const modal = new bootstrap.Modal(document.getElementById('confirmModal'));
        const okBtn = document.getElementById('confirmModalOk');
        const onOk = () => { cleanup(); modal.hide(); resolve(true); };
        const onHidden = () => { cleanup(); resolve(false); };
        function cleanup() {
            okBtn.removeEventListener('click', onOk);
            document.getElementById('confirmModal').removeEventListener('hidden.bs.modal', onHidden);
        }
        okBtn.addEventListener('click', onOk);
        document.getElementById('confirmModal').addEventListener('hidden.bs.modal', onHidden, { once: true });
        modal.show();
    });
}
