# Operator authentication — OIDC SSO, LDAP/AD, mutual-TLS, WebAuthn step-up, and API tokens

The [RBAC layer](rbac-and-audit.md) decides **what** a principal may do. This
document covers **who** a caller is: how the console and API authenticate
operators and machine clients, and how a first-class authentication event is
tied to an RBAC principal (a `UserInfo` carrying platform and per-tenant roles).

Several complementary mechanisms are provided, each configured under a top-level
`auth:` block and each inert until enabled. Both OIDC paths accept
[multiple identity providers](#multiple-oidc-providers) — the issuer that
authenticates a CI pipeline is usually not the one your operators log in through. The pre-existing stateless paths —
HTTP basic-auth for the built-in `root` user and OIDC **Bearer** tokens for API
callers — keep working unchanged, so nothing here is a breaking change.

| Mechanism | For | Credential | Config |
|-----------|-----|-----------|--------|
| **OIDC/OAuth2 login** | Console operators | Interactive SSO → server-side session cookie | `auth.oidc`, `auth.oidc.providers` |
| **LDAP / Active Directory** | Console + machine callers | Directory username + password (bind) | `auth.ldap` |
| **Mutual-TLS** | Machine / API callers | Client certificate bound to a principal | `auth.mtls` |
| **WebAuthn step-up** | Console operators, high-risk ops | Passkey assertion | `auth.webauthn` |
| **API token** | Machine / service accounts | Native, revocable, role/tenant-scoped secret | always on; `auth.api_tokens` tunes lifetime |
| Basic-auth (root) | Break-glass / bootstrap | `root_user` password | `policy.allow_root_basic_auth` |
| Bearer token | API scripting, CI pipelines | OIDC access/id token | `oidc`, `oidc.providers` |

The middleware tries credentials in order: **basic-auth (root → LDAP) → API token
→ Bearer (OIDC) → session cookie → mutual-TLS**, then rejects with `401`. A basic
credential that is not the built-in `root` user is bound against the directory
when `auth.ldap` is enabled, so CLI/API callers can present AD credentials over
HTTP Basic (always over TLS — the server refuses cleartext HTTP by default).

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

<a id="multiple-oidc-providers"></a>

## 1a. Multiple OIDC providers

A deployment rarely has one identity provider. The pipeline that asks for an
artifact signature authenticates through its forge's workload-identity issuer
(GitHub Actions, GitLab, a Kubernetes projected service-account token); the
humans who administer the PKI sign in through the corporate IdP; a partner's
automation may arrive through a third. Each mints its own JWTs, under its own
issuer, with its own audience and its own idea of what a subject string means.

secsy-pki keeps these **separate on two axes**:

| Axis | Config | Credential | Typical IdP |
|------|--------|-----------|-------------|
| **Machine** — `Authorization: Bearer <jwt>` | `oidc` / `oidc.providers[]` | a token the caller already holds | GitHub Actions OIDC, GitLab, a cloud IdP |
| **Console** — interactive browser login | `auth.oidc` / `auth.oidc.providers[]` | the Authorization-Code + PKCE handshake | Entra ID, Okta, Keycloak |

Both axes accept **several providers at once**, and the two are independent: the
issuer that signs your CI tokens need not be, and usually is not, the one your
operators log in through.

### Machine callers: `oidc.providers`

```yaml
oidc:
  providers:
    # Automated signing from a CI pipeline. The workflow's OIDC token is
    # verified here and maps to exactly the signer role.
    - name: github
      issuer_url: "https://token.actions.githubusercontent.com"
      client_id: "secsy-pki-signing"       # the audience the workflow requests
      role_mappings:
        - { claim: "sub", value: "repo:example-org/app:environment:release", roles: ["signer"] }

    # API scripting by staff service principals, through the corporate IdP.
    - name: entra
      issuer_url: "https://login.microsoftonline.com/<tenant-id>/v2.0"
      client_id: "api://secsy-pki"
      # audiences: ["api://secsy-pki-legacy"]   # additional accepted audiences
      groups_claim: "roles"                     # Entra app roles
      role_mappings:
        - { value: "PKI.Issue", roles: ["issuer"] }
```

A presented token is routed to **exactly one** provider by its `iss` claim, then
verified there (signature, issuer, expiry, audience). Three properties make
federating issuers safe rather than additive risk:

- **Routing cannot pick a lenient verifier.** The `iss` used for routing is read
  from the *unverified* payload, which is sound because the selected provider
  re-checks the issuer cryptographically. A forged `iss` only lands the token at
  a provider whose JWKS will not verify it. An issuer no provider serves is
  rejected outright, never offered to the others in turn.
- **Every provider is audience-bound.** `client_id` (plus any `audiences`) is the
  accepted `aud` set. A provider with neither is a **load error**: it would
  otherwise honor any token the same IdP minted for an unrelated relying party.
- **Authorization is per provider.** A provider's `role_mappings` are evaluated
  *only* for tokens it verified. So a mapping granting `signer` to
  `repo:example-org/app:environment:release` grants nothing to a token from a
  different issuer asserting that identical subject — which is the failure mode
  a shared, provider-agnostic subject list would have.

> The top-level `rbac.subjects` / `rbac.groups` assignments remain
> provider-agnostic and are unioned in for every provider. Use them for
> identities you trust regardless of issuer; use a provider's `role_mappings`
> when the grant is specific to one IdP.

Two providers may not share an issuer URL (routing would become
order-dependent), and provider names must be unique. Both are refused at load.

### Console operators: `auth.oidc.providers`

```yaml
auth:
  oidc:
    enabled: true
    # Shared defaults — a provider omitting a field inherits it from here.
    redirect_url: "https://pki.example.com/auth/callback"
    scopes: ["openid", "profile", "email", "groups"]
    groups_claim: "groups"
    allow_zero_role: false
    providers:
      - name: entra                           # /auth/login?provider=entra
        display_name: "Microsoft Entra ID"    # the console's button label
        issuer_url: "https://login.microsoftonline.com/<tenant-id>/v2.0"
        client_id: "console-entra"
        client_secret_file: "/etc/secsy/entra-client-secret"
        default: true                         # a bare /auth/login uses this one
        role_mappings:
          - { value: "PKI-Admins", roles: ["admin"] }
      - name: partner
        display_name: "Partner IdP"
        issuer_url: "https://idp.partner.example.net"
        client_id: "console-partner"
        redirect_url: "https://pki.example.com/auth/callback/partner"
        allow_zero_role: true                 # overrides the shared policy
        role_mappings:
          - { value: "pki-readers", tenant: "partner", roles: ["auditor"] }
```

The console reads `/api/auth/config` and renders **one sign-in button per
provider**, so an operator chooses their IdP instead of being sent to whichever
one is the default.

```
GET /auth/login                     → the default provider (first, or `default: true`)
GET /auth/login?provider=<name>     → that provider
GET /auth/login/oidc/<name>         → the same, as a path
GET /auth/callback                  → dispatched by the provider recorded in the
                                      signed login transaction cookie
GET /auth/callback/<name>           → a per-provider callback path, for an IdP
                                      whose registration demands a distinct URI
```

**Providers may share one registered `redirect_url`.** The name of the provider
that began the flow is sealed inside the HMAC-signed, 10-minute transaction
cookie alongside the state, nonce, and PKCE verifier, so the callback knows which
verifier, client credentials, and claim mapping to complete with. A transaction
arriving at a *different* provider's callback is refused
(`code: provider_mismatch`) rather than completed — otherwise a code issued by
one IdP would be exchanged with another's client credentials and its claims
mapped through the wrong role mapping.

### Role mapping across providers

Mappings under `auth.oidc.role_mappings` (the shared block) are evaluated for
**every** console provider; a provider's own `role_mappings` are unioned on top.
That is what keeps the single-provider form working — but it also means a group
name asserted by *any* federated IdP matches a shared mapping. **When providers
differ in how much you trust them, declare the mapping on the provider**, not in
the shared block.

`allow_zero_role` is per provider (falling back to the shared setting), so one
IdP can admit role-less viewers while another denies them at login.

### Audit, diagnosis, and discovery

- Login audit detail carries `provider=<name>`: `auth.login method=oidc
  provider=entra`, and `auth.login_failed … reason=provider_mismatch`.
- The resolved principal carries `auth_provider` (`/api/me`, `/auth/session`,
  and the console's "signed in as" line) — diagnostic only; the roles already
  reflect that provider's mapping.
- `/api/auth/config` publishes `oidc_providers` (name, label, login URL) and
  `bearer_providers` (name, issuer, accepted audiences), so a workload can
  discover which issuer and audience to request a token for rather than having
  that pairing passed around out of band. No client secret ever appears there.
- An IdP that cannot be discovered at startup is logged as a `WARNING` and
  skipped; the other providers still come up. For machine issuers that leaves
  Bearer verification working for the rest; for console login, if **no** provider
  comes up the server refuses to start, since SSO was configured and is wholly
  unavailable.

### Backward compatibility

The single-provider form is unchanged and remains a provider in its own right,
named `default`:

- `oidc.issuer_url` + `oidc.client_id` → one machine provider named `default`.
  Adding `oidc.providers` **does not** drop it; the two are unioned (declaring
  the same issuer twice is a load error).
- `auth.oidc.issuer_url` / `client_id` still inherit the top-level `oidc` block
  when omitted, so one IdP can serve both axes.

See [`examples/multi-oidc/`](../../examples/multi-oidc/README.md) for a complete
GitHub-Actions-plus-Entra-ID configuration.

## 1b. LDAP / Active Directory authentication

Deployments that centralize identity in **LDAP or Active Directory** can
authenticate operators with their directory username + password, mapping the
caller's **directory groups → RBAC roles** through the same `role_mappings`
mechanism as OIDC. It serves both the console (an interactive login that
establishes a session) and machine/CLI callers (HTTP/RPC Basic).

```
POST /auth/login/ldap   → binds the directory credentials, maps groups → roles,
                          sets the session cookie, returns the CSRF token
Authorization: Basic …  → a non-root basic credential is bound against the
                          directory per request (machine/CLI callers)
```

Two bind flows are supported (RFC 4511):

- **search-then-bind** (default; set `bind_dn`): the server binds as a
  low-privilege **service account**, searches the user subtree for the entry
  matching the login name, then re-binds as that entry's DN with the supplied
  password to verify it. This is the standard AD pattern and the only way to
  accept a friendly login name (`sAMAccountName`) rather than a full DN.
- **simple-bind** (leave `bind_dn` empty; set `user_dn_template`): the login name
  is templated straight into a bind DN or `userPrincipalName` and bound. No
  service account is required.

```yaml
auth:
  ldap:
    enabled: true
    url: "ldaps://ad.example.com:636"          # ldaps:// (implicit TLS) or ldap:// + start_tls
    # start_tls: true                          # required for an ldap:// URL
    bind_dn: "CN=svc-pki,OU=Service,DC=example,DC=com"
    bind_password: "…"                         # or bind_password_source (below)
    user_base_dn: "OU=Users,DC=example,DC=com"
    user_filter: "(&(objectClass=user)(sAMAccountName=%s))"   # %s = escaped login name
    group_attribute: "memberOf"                # read groups from the user entry…
    # group_base_dn / group_filter:            # …or search a group subtree instead
    #   group_base_dn: "OU=Groups,DC=example,DC=com"
    #   group_filter: "(&(objectClass=group)(member=%s))"     # %s = user DN, %u = username
    email_attribute: "mail"
    name_attribute: "displayName"
    groups_claim: "groups"
    role_mappings:
      - { value: "CN=PKI-Admins,OU=Groups,DC=example,DC=com",  roles: ["admin"] }
      - { value: "CN=PKI-Issuers,OU=Groups,DC=example,DC=com", tenant: "acme", roles: ["issuer"] }
    allow_zero_role: false     # deny login to a directory user matching no mapping
    tls:
      ca_file: "/etc/secsy/ad-ca.pem"          # trust anchors (empty = system store)
      server_name: "ad.example.com"            # cert-name / SNI override (for IP dials)
      min_version: "1.2"
    timeout_seconds: 10
```

The resolved directory groups are presented to the shared `ClaimMapper` under
`groups_claim`, so `role_mappings` behaves identically to OIDC's — a group's DN
(or, with `group_attribute` naming an attribute such as `cn`, its name) is
matched against `value`, granting platform-wide or tenant-scoped roles. The
result is unioned with the top-level `rbac:` subject/email/group assignments.

**Sourcing the bind password.** `bind_password` may be given inline, or sourced
from a credential store with `bind_password_source` — the same machinery as the
[HSM PIN](../hsm/configuration.md) (`env`, `file`, `vault`, `aws`, `azure`),
resolved lazily and never written back into a redacted config:

```yaml
    bind_password_source:
      type: file
      file: { path: /etc/secsy/ldap-bind.pass }   # 0600
```

**TLS is mandatory.** A bind (which carries the password) is never sent over an
unencrypted connection: `ldaps://` uses implicit TLS, `ldap://` must be upgraded
with `start_tls: true`, and a **StartTLS failure fails the login closed** rather
than continuing in the clear. Server-certificate verification is on by default
(`tls.insecure_skip_verify` exists only for tests). An `ldap://` URL without
`start_tls` is rejected at startup unless `insecure_allow_cleartext` is explicitly
set.

**Other hardening.** Empty passwords are rejected before any bind (defeating the
LDAP *unauthenticated-bind* pitfall, where a DN + empty password can be silently
promoted to a successful anonymous bind); login names are escaped
(`ldap.EscapeFilter` / `ldap.EscapeDN`) before interpolation, so a username can
never inject into the search filter or bind DN; and an unknown user fails with
the same generic error as a wrong password (no user enumeration).

`secsy-ca doctor` gains an **`auth.ldap`** check that connects, negotiates TLS,
and performs the service-account bind (no end-user login), so a directory
misconfiguration is caught before operators are locked out.

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

## 4. Native scoped API tokens (service accounts)

Machine callers no longer have to share the single `root` basic credential or
depend on an external OIDC IdP. A **native API token** is a first-class,
revocable, long-lived credential bound to a set of RBAC roles and a tenant
scope, with an optional expiry.

A token is an opaque, high-entropy secret of the form `secsy_pat_<random>`
(256 bits of CSPRNG entropy). It is presented under a **distinct Authorization
scheme** so it never conflates with OIDC Bearer verification:

```
Authorization: Token secsy_pat_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

Clients that can only emit `Bearer` may use `Authorization: Bearer secsy_pat_…`
— the `secsy_pat_` prefix unambiguously routes it to token verification (an
OIDC JWT never carries that prefix). Verification is **fail-closed**: an
unknown, malformed, expired, or revoked token is rejected with no
distinguishing detail.

### At-rest storage — a deliberate security decision

The plaintext secret is returned **exactly once** at creation and is **never
persisted**. Only a one-way hash — `hex(SHA-256(secret))` — is stored
(`api_tokens.token_hash`, UNIQUE-indexed). A fast hash, not argon2/bcrypt, is
the correct choice here:

- the secret carries 256 bits of entropy and cannot be brute-forced offline, so
  the password-hardening KDFs that exist to slow guessing of *low*-entropy
  passwords add nothing; and
- a deterministic, unsalted hash is what makes the O(1) indexed lookup on the
  hot verification path possible.

This matches how GitHub/GitLab personal access tokens are stored. A database
disclosure therefore cannot yield a usable credential.

### Scope, roles, and privilege

- A **tenant-scoped** token (`scope: tenant`, the default) exercises its roles
  only within its owning tenant — the same cross-tenant isolation that confines
  a tenant OIDC operator applies.
- A **platform-scoped** token (`scope: platform`) holds its roles across all
  tenants and may only be minted by a platform administrator.

Managing tokens is an administrative capability (`token:manage`, admin-only): a
token can carry any role, so allowing a lesser role to mint tokens would let it
escalate its own privilege. Tenant admins may mint tenant-scoped tokens within
their tenant; platform tokens require a platform admin.

When the [four-eyes gate](approvals.md) is enabled, minting a token
with a **sensitive grant** — any privileged role (anything beyond read-only
`auditor`) or platform scope — is held for approval (`token.create` class,
`202` response) and minted only after the approver threshold is met. Revocation
is deliberately **not** gated: it removes access and must stay fast for incident
response.

### Lifecycle surfaces

REST (`token:manage`; create returns the secret once):

```
GET    /api/tokens                 — list tokens the caller may manage (?tenant=)
POST   /api/tokens                 — mint a token (201 with secret, or 202 pending approval)
DELETE /api/tokens/{id}            — revoke a token
```

CLI (platform-operator level; direct store access):

```
secsy-ca token create -name ci-issuer -roles issuer -tenant acme -expires-days 90
secsy-ca token create -name platform-bot -roles admin -scope platform
secsy-ca token list [-tenant acme]
secsy-ca token revoke <id>
```

Console: an **API Tokens** page lists tokens, mints them (revealing the secret
once with a copy button), and revokes them.

Optional lifetime policy — cap how long a token may live (0/omitted = no cap,
non-expiring tokens allowed):

```yaml
auth:
  api_tokens:
    max_lifetime_days: 365   # a create request must expire within a year
```

Each successful verification updates a throttled **last-used** timestamp and
client IP, so a stale or leaked token is easy to spot and revoke.

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
`auth.step_up_denied`, `webauthn.register`, `webauthn.remove`, `token.create`,
`token.revoke` (the token id is the event target; the secret is never logged).

LDAP logins record `auth.login` / `auth.login_failed` with `method=ldap` (the
failed-login detail carries a non-sensitive reason: `invalid_credentials`,
`directory_unavailable`, or `no_access`).

With [several OIDC providers](#multiple-oidc-providers) configured, the OIDC
login events carry `provider=<name>` so each IdP's logins are separable in the
log.

Prometheus metrics: `secsy_auth_logins_total{method,result}` (method ∈
oidc|password|ldap|mtls), `secsy_auth_logouts_total`,
`secsy_auth_step_ups_total{result}`,
`secsy_auth_sessions_active`, `secsy_auth_token_operations_total{operation,result}`,
`secsy_auth_token_verifications_total{result}` (result ∈
success|expired|revoked|unknown|error), and `secsy_auth_tokens_active`.

## Security notes

- The server refuses cleartext HTTP by default; cookies are `Secure` unless
  `auth.session.insecure` is set (local testing only).
- The OIDC login binds **state** (CSRF on the callback), **nonce** (token
  replay), and **PKCE** (code interception); the transaction is carried in an
  HMAC-signed, 10-minute cookie that also names the provider that began the flow,
  so one IdP's authorization code cannot be completed at another's callback.
- With several machine issuers federated, a token is verified by exactly one
  provider and authorized by **that** provider's claim mapping. A provider with
  no accepted audience is refused at load rather than trusting every token the
  issuer mints.
- mTLS bindings never widen access on their own — the bound roles are still
  subject to the same RBAC checks and, for tenant resources, tenant membership.
- LDAP binds occur only over TLS (LDAPS or StartTLS, fail-closed); empty
  passwords are rejected before binding; and login names are escaped before use
  in filters/DNs. HTTP Basic against the directory re-binds per request — keep it
  behind TLS (the default) and prefer sessions or API tokens for high-volume
  machine callers.
