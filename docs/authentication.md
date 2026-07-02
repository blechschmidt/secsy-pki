# Operator authentication — OIDC SSO, mutual-TLS, and WebAuthn step-up

The [RBAC layer](rbac-and-audit.md) decides **what** a principal may do. This
document covers **who** a caller is: how the console and API authenticate
operators and machine clients, and how a first-class authentication event is
tied to an RBAC principal (a `UserInfo` carrying platform and per-tenant roles).

Three complementary mechanisms are provided, each configured under a top-level
`auth:` block and each inert until enabled. The pre-existing stateless paths —
HTTP basic-auth for the built-in `root` user and OIDC **Bearer** tokens for API
callers — keep working unchanged, so nothing here is a breaking change.

| Mechanism | For | Credential | Config |
|-----------|-----|-----------|--------|
| **OIDC/OAuth2 login** | Console operators | Interactive SSO → server-side session cookie | `auth.oidc` |
| **Mutual-TLS** | Machine / API callers | Client certificate bound to a principal | `auth.mtls` |
| **WebAuthn step-up** | Console operators, high-risk ops | Passkey assertion | `auth.webauthn` |
| Basic-auth (root) | Break-glass / bootstrap | `root_user` password | `policy.allow_root_basic_auth` |
| Bearer token | API scripting | OIDC access/id token | `oidc` |

The middleware tries credentials in order: **basic-auth → Bearer → session
cookie → mutual-TLS**, then rejects with `401`.

---

## 1. Interactive OIDC/OAuth2 login (console SSO)

Rather than have the browser hold and refresh an IdP token, the server drives
the full **Authorization-Code + PKCE** handshake and establishes a server-side
session:

```
GET /auth/login        → 302 to the IdP (state + nonce + PKCE in a signed,
                         short-lived transaction cookie)
GET /auth/callback     → verifies state, exchanges the code, verifies the id
                         token + nonce, maps claims → RBAC roles, sets the
                         session cookie, redirects to /console/
POST /auth/logout      → terminates the session, clears cookies
GET  /auth/session     → returns the current principal + CSRF token
```

### Claim / group → RBAC role mapping

An operator's roles are the **union** of:

- the top-level `rbac:` subject / verified-email / group assignments, and
- the `auth.oidc.role_mappings` — IdP **claim values** (typically groups) mapped
  to roles, optionally scoped to a tenant.

```yaml
auth:
  oidc:
    enabled: true
    # issuer_url / client_id inherit the top-level oidc block when omitted
    client_secret: "…"                      # omit for a public (PKCE) client
    redirect_url: "https://pki.example.com/auth/callback"
    scopes: ["openid", "profile", "email", "groups"]
    groups_claim: "groups"
    role_mappings:
      - { value: "pki-admins",   roles: ["admin"] }              # platform-wide
      - { value: "pki-issuers",  roles: ["issuer"] }
      - { value: "acme-issuers", tenant: "acme-corp", roles: ["issuer"] }
      - { claim: "roles", value: "auditor", roles: ["auditor"] }  # any claim
    allow_zero_role: false     # deny login to an operator with no resolved role
```

A mapping matches when the named claim (a string or a list of strings) contains
`value`. Unknown role names are dropped at load, and an `enabled` login block
with a mapping referencing an unknown role fails validation at startup.

## 2. Mutual-TLS client-certificate authentication

Machine and API callers can authenticate with a **client certificate** instead
of a token. When `auth.mtls.enabled` is set, the TLS listener requests a client
certificate and verifies it against `ca_file` (`tls.VerifyClientCertIfGiven`, so
the console and public endpoints stay reachable without one). A *verified*
certificate is then bound to a principal by the first matching binding:

```yaml
auth:
  mtls:
    enabled: true
    ca_file: "certs/client-ca.pem"
    bindings:
      # every non-empty selector must match; the principal gets the listed roles
      - { subject_cn: "build-robot", subject: "svc:build-robot", roles: ["issuer"] }
      - { san_uri: "spiffe://example.org/ns/ops/sa/deployer", roles: ["admin"],
          tenant_roles: { acme-corp: ["issuer"] } }
      - { san_dns: "scanner.example.com", roles: ["auditor"] }
```

Selectors: `subject_cn`, `subject_dn`, `san_dns`, `san_uri`, `san_email`. A
binding with **no** selector matches nothing (fail-closed) and is dropped. The
chain itself is verified by the TLS stack, not the binder.

## 3. WebAuthn / passkey step-up

High-risk operations can require a fresh **WebAuthn assertion** in addition to a
valid session. This defends against a hijacked session or an unattended console:
revoking a certificate, running a CA key ceremony, cross-signing, deleting a CA,
or factory-resetting the HSM all demand a passkey tap.

```yaml
auth:
  webauthn:
    enabled: true
    rp_id: "pki.example.com"           # the console's registrable domain
    origins: ["https://pki.example.com"]
    step_up_ttl_minutes: 5             # how long one step-up stays valid
    step_up_operations:                # defaults to the set below when omitted
      - cert.revoke
      - ca.init_root
      - ca.issue_intermediate
      - ca.cross_sign
      - ca.manage
      - hsm.factory_reset
```

Endpoints (all require a live session + CSRF token):

```
POST /auth/webauthn/register/begin   /register/finish   — enroll a passkey
POST /auth/webauthn/stepup/begin     /stepup/finish      — assert for step-up
GET  /auth/webauthn/credentials                          — list enrolled passkeys
```

Only the credential id, its public key (SPKI DER), and the authenticator's
signature counter are stored (`webauthn_credentials` table) — the private key
never leaves the authenticator. A non-advancing counter is rejected as a cloned
authenticator. When a gated request lacks a valid step-up, the API returns
`403` with `{"code":"step_up_required","operation":"…"}`; the console runs the
assertion ceremony and retries automatically.

Step-up gates **session** (console) callers. A caller authenticated by a strong
non-interactive credential — root basic-auth, a bearer token, or a bound mutual-
TLS certificate — already presented a strong credential and is not gated.

## Sessions & CSRF

Interactive logins (OIDC and password) create a server-side session referenced
by an opaque, random id in an **HttpOnly** cookie. A companion **CSRF** token is
issued per session; every state-changing request authenticated by the cookie
must echo it in the `X-CSRF-Token` header (the console reads it from a
JS-readable cookie / `/auth/session`). Token/basic/mTLS callers are exempt —
they do not rely on ambient browser credentials and so are not forgeable
cross-site. Sessions are process-local (no shared state); a restart simply
re-prompts for SSO.

`POST /auth/login/password` establishes a session from the `root_user`
credentials, so even password logins get CSRF protection and can use step-up.

## Audit & metrics

Every login, logout, and step-up is written to the tamper-evident
[event log](rbac-and-audit.md):

`auth.login`, `auth.login_failed`, `auth.logout`, `auth.step_up`,
`auth.step_up_denied`, `webauthn.register`, `webauthn.remove`.

Prometheus metrics: `secsy_auth_logins_total{method,result}`,
`secsy_auth_logouts_total`, `secsy_auth_step_ups_total{result}`, and
`secsy_auth_sessions_active`.

## Security notes

- The server refuses cleartext HTTP by default; cookies are `Secure` unless
  `auth.session.insecure` is set (local testing only).
- The OIDC login binds **state** (CSRF on the callback), **nonce** (token
  replay), and **PKCE** (code interception); the transaction is carried in an
  HMAC-signed, 10-minute cookie.
- mTLS bindings never widen access on their own — the bound roles are still
  subject to the same RBAC checks and, for tenant resources, tenant membership.
