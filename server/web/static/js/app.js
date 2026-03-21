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
    if (name === 'sign') loadCASelect('signCA');
    if (name === 'groups') loadGroups();
    if (name === 'permissions') { loadCASelect('permCA'); loadPermissions(); }
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
    showPage('cas');
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
}

document.getElementById('logoutBtn').addEventListener('click', e => {
    e.preventDefault();
    logout();
});

// CAs
async function loadCAs() {
    try {
        const cas = await API.get('/api/cas');
        const tbody = document.getElementById('casTableBody');
        tbody.innerHTML = cas.map(ca => `
            <tr>
                <td><strong>${esc(ca.label)}</strong></td>
                <td>${truncated(ca.id, 8)}</td>
                <td>${ca.parent_id ? truncated(ca.parent_id, 8) : '<span class="badge bg-primary">root</span>'}</td>
                <td><span class="badge bg-secondary">${esc(ca.key_type)}</span></td>
                <td>${truncated(ca.pkcs11_uri, 40)}</td>
                <td class="text-nowrap">
                    ${ca.public_key ? `<button class="btn btn-sm btn-outline-info me-1" title="Copy public key" data-copy="${esc(ca.public_key)}" data-copy-msg="Public key copied"><i class="bi bi-clipboard"></i></button>` : ''}
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
        await API.post('/api/cas', {
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
        await API.del(`/api/cas/${id}`);
        showToast('Success', 'CA deleted');
        loadCAs();
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

async function loadCASelect(selectId) {
    try {
        const cas = await API.get('/api/cas');
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

// Sign Certificate
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

        const result = await API.post(`/api/cas/${document.getElementById('signCA').value}/sign`, {
            public_key: document.getElementById('signPubKey').value,
            cert_type: document.getElementById('signCertType').value,
            key_id: document.getElementById('signKeyID').value || undefined,
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

// Key Generation
document.getElementById('keygenType').addEventListener('change', function () {
    const bitsGroup = document.getElementById('keygenBitsGroup');
    bitsGroup.style.display = this.value === 'ed25519' ? 'none' : 'block';
});
document.getElementById('keygenType').dispatchEvent(new Event('change'));

document.getElementById('keygenForm').addEventListener('submit', async e => {
    e.preventDefault();
    try {
        const keyType = document.getElementById('keygenType').value;
        const result = await API.post('/api/keys/generate', {
            key_type: keyType,
            bits: keyType !== 'ed25519' ? parseInt(document.getElementById('keygenBits').value) : 0,
            comment: document.getElementById('keygenComment').value,
        });
        document.getElementById('keygenPub').value = result.public_key;
        document.getElementById('keygenPriv').value = result.private_key;
        document.getElementById('keygenResult').classList.remove('d-none');
        showToast('Success', 'Key pair generated');
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
        const perms = await API.get(`/api/cas/${caId}/permissions`);
        const tbody = document.getElementById('permTableBody');
        tbody.innerHTML = perms.map(p => `
            <tr>
                <td><span class="badge ${p.entity_type === 'user' ? 'bg-info' : 'bg-warning'}">${esc(p.entity_type)}</span></td>
                <td>${truncated(p.entity_id, 20)}</td>
                <td><span class="badge bg-primary">${esc(p.permission)}</span></td>
                <td>
                    <button class="btn btn-sm btn-outline-danger" onclick="revokePermission('${caId}', '${p.entity_type}', '${p.entity_id}', '${p.permission}')"><i class="bi bi-x-lg"></i></button>
                </td>
            </tr>
        `).join('');
    } catch (err) {
        showToast('Error', err.message, true);
    }
}

document.getElementById('grantPermBtn').addEventListener('click', () => {
    new bootstrap.Modal(document.getElementById('grantPermModal')).show();
});

document.getElementById('savePermBtn').addEventListener('click', async () => {
    const caId = document.getElementById('permCA').value;
    if (!caId) { showToast('Error', 'Select a CA first', true); return; }
    try {
        await API.post(`/api/cas/${caId}/permissions`, {
            entity_type: document.getElementById('permEntityType').value,
            entity_id: document.getElementById('permEntityID').value,
            permission: document.getElementById('permPermission').value,
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
        await API.del(`/api/cas/${caId}/permissions`, {
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
