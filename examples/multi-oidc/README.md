# Two identity providers: GitHub Actions for signing, Entra ID for the console

One deployment, two populations, two identity providers — plus a third for a
partner's auditors. The pipeline that signs releases proves its identity through
GitHub's workload-identity issuer; the operators who administer the PKI sign in
through Microsoft Entra ID; partner auditors arrive through their own IdP and see
only their tenant.

These are deliberately **not** the same provider, and `secsy-pki` keeps them from
becoming interchangeable.

| File | Purpose |
|------|---------|
| [`config.yaml`](config.yaml) | Three providers across both axes, each with its own audience and claim → role mapping |

Reference: [`docs/security/authentication.md#multiple-oidc-providers`](../../docs/security/authentication.md#multiple-oidc-providers),
[`docs/security/rbac-and-audit.md`](../../docs/security/rbac-and-audit.md).

---

## The two axes

There are two independent OIDC paths, and the common mistake is to assume one
block serves both:

| Axis | Config block | Credential | Who |
|------|--------------|-----------|-----|
| **Machine** | `oidc.providers[]` | `Authorization: Bearer <jwt>` the caller already holds | CI pipelines, service principals, workloads |
| **Console** | `auth.oidc.providers[]` | the browser Authorization-Code + PKCE handshake | humans |

A GitHub Actions token must not be able to log in to the console, and an
operator's Entra session must not be able to impersonate the signing workflow.
Separating the axes is what makes that structural rather than a matter of
careful group naming.

```
GitHub Actions job ──Bearer──▶ oidc.providers[github]  ──▶ role: signer  (artifact:sign only)
Entra service principal ─Bearer─▶ oidc.providers[entra] ──▶ role: issuer / auditor
Operator's browser ──PKCE──▶ auth.oidc.providers[entra] ──▶ role: admin / issuer / auditor
Partner auditor ─────PKCE──▶ auth.oidc.providers[partner] ─▶ auditor, in tenant "partner" only
```

## Why a token from one issuer cannot borrow another's roles

Every provider carries its own `role_mappings`, and **a mapping is evaluated only
for tokens the provider that declared it verified**. That matters because a
subject string says nothing about who vouched for it: GitHub asserts
`sub: repo:example-org/example-repo:environment:release`, and any other issuer
can assert that exact string. With the mapping attached to the `github` provider,
an identical subject arriving from `entra` resolves to **zero roles**.

Three further rules hold the boundary:

1. **Routing is by `iss`, and cannot pick a lenient verifier.** The issuer used
   to select a provider is read from the unverified payload — sound, because the
   selected provider then checks the issuer cryptographically. A forged `iss`
   only lands the token at a provider whose JWKS will not verify it. An issuer no
   provider serves is rejected outright.
2. **Every provider is audience-bound.** `client_id` (plus any `audiences`) is
   the accepted `aud` set, and a provider with neither is a **startup error** —
   it would otherwise honor any token the IdP minted for an unrelated relying
   party of the same tenant.
3. **One issuer, one provider.** Two providers may not share an issuer URL
   (routing would become order-dependent); names must be unique. Both are refused
   at load.

### The trap: shared `role_mappings`

Mappings written directly under `auth.oidc.role_mappings` apply to **every**
console provider. That is what keeps the single-provider form working, but with
providers of differing trust it means a group name asserted by the *partner* IdP
would match a mapping meant for Entra. The example therefore declares no shared
mappings and puts every mapping on its provider. Do the same whenever the
providers are not equally trusted.

## 1. Register the clients

**GitHub** needs nothing registered — the audience is whatever your workflow
asks for:

```yaml
# .github/workflows/sign-release.yml
permissions:
  id-token: write
environment: release          # makes `sub` stable across tags — see below
```

Then `core.getIDToken('secsy-pki-signing')`, matching `oidc.providers[github].client_id`.

> **Use a GitHub Environment.** Without one, `sub` embeds the git ref
> (`repo:OWNER/REPO:ref:refs/tags/v1.2.3`) and changes every release, so it
> cannot be pinned in config. Inside an environment it becomes
> `repo:OWNER/REPO:environment:release` — stable, and gated by that
> environment's protection rules. See
> [`examples/github-oidc-signing/`](../github-oidc-signing/README.md) for the
> full signing walkthrough.

**Entra ID** needs two app registrations, because the two axes are two clients:

| Registration | Type | Used for | Config |
|---|---|---|---|
| `api://secsy-pki` | Exposed API (app roles `PKI.Issue`, `PKI.Audit`) | service principals calling the API with a Bearer token | `oidc.providers[entra].client_id` |
| `console-entra` | Web app, redirect `https://pki.example.com/auth/callback` | the browser login | `auth.oidc.providers[entra].client_id` |

Add the `groups` claim to the console app's token configuration (or use app
roles and set `groups_claim: roles`, as the machine provider does here).

**Partner IdP**: one web-app registration with redirect
`https://pki.example.com/auth/callback/partner`.

## 2. Callback URLs — share one, or don't

Both console providers in this example could share
`https://pki.example.com/auth/callback`; `partner` is given its own path only to
show that it works. The name of the provider that began the flow is sealed inside
the HMAC-signed, 10-minute login transaction cookie alongside the state, nonce
and PKCE verifier, so the callback always knows which verifier and client
credentials to complete with.

```
GET /auth/login                   → the default provider (`default: true`, else the first)
GET /auth/login?provider=partner  → that provider
GET /auth/login/oidc/partner      → the same, as a path
GET /auth/callback                → dispatched by the provider in the transaction cookie
GET /auth/callback/partner        → a per-provider path, when an IdP demands a distinct URI
```

A transaction that arrives at a *different* provider's callback is refused with
`{"code":"provider_mismatch"}` rather than completed — otherwise a code issued by
one IdP would be exchanged with another's client credentials.

## 3. Run it

```console
$ secsy-pki-server -config config.yaml
```

Startup names every provider it brought up:

```
OIDC Bearer verification enabled: provider="github" issuer=https://token.actions.githubusercontent.com audiences=[secsy-pki-signing]
OIDC Bearer verification enabled: provider="entra" issuer=https://login.microsoftonline.com/.../v2.0 audiences=[api://secsy-pki]
Interactive OIDC login provider "entra" enabled (issuer=https://login.microsoftonline.com/.../v2.0 redirect_url=https://pki.example.com/auth/callback)
Interactive OIDC login provider "partner" enabled (issuer=https://idp.partner.example.net redirect_url=https://pki.example.com/auth/callback/partner)
```

An IdP that cannot be discovered is logged as a `WARNING` and skipped, so one
provider's outage is not the server's. If **no** console provider comes up the
server refuses to start — SSO was configured and is wholly unavailable.

## 4. Check what a client should request

`/api/auth/config` is public (a browser must read it before it can log in) and
publishes both axes, so a pipeline discovers the issuer/audience pairing rather
than having it passed around out of band:

```console
$ curl -s https://pki.example.com/api/auth/config | jq
{
  "oidc_enabled": true,
  "oidc_login_enabled": true,
  "webauthn_enabled": true,
  "oidc_providers": [
    { "name": "entra",   "display_name": "Microsoft Entra ID", "login_url": "/auth/login?provider=entra", "default": true },
    { "name": "partner", "display_name": "Partner IdP",        "login_url": "/auth/login?provider=partner" }
  ],
  "bearer_providers": [
    { "name": "github", "issuer_url": "https://token.actions.githubusercontent.com", "audiences": ["secsy-pki-signing"] },
    { "name": "entra",  "issuer_url": "https://login.microsoftonline.com/.../v2.0",  "audiences": ["api://secsy-pki"] }
  ]
}
```

No client secret ever appears there. The console reads this document and renders
**one sign-in button per provider**, so an operator picks their IdP instead of
being sent to the default.

## 5. Confirm the isolation holds

The two checks worth running after the first successful login of each kind:

```console
# The console session reports which IdP authenticated it.
$ curl -s --cookie "secsy_session=…" https://pki.example.com/api/me | jq '{sub, roles, auth_provider}'
{ "sub": "…", "roles": ["admin"], "auth_provider": "entra" }

# The tamper-evident event log separates logins per provider (console Audit
# page, or the API's server-side action filter).
$ curl -s --cookie "secsy_session=…" \
    "https://pki.example.com/api/events?action=auth.login&limit=20" \
    | jq -r '.entries[] | "\(.actor)\t\(.detail)"'
op@example.com                  method=oidc provider=entra
auditor@partner.example.net     method=oidc provider=partner
```

And the negative case: an Entra service-principal token that asserts the GitHub
workflow's `sub` authenticates (it is a valid Entra token) but resolves to no
roles, so `POST /api/sign` answers `403`. That is the whole point of the
per-provider mapping.

## Security properties

- **No stored secret for CI.** The pipeline's credential is a per-run,
  minutes-long OIDC token.
- **Least privilege per population.** `signer` grants exactly `artifact:sign`;
  it can never mint certificates. Partner auditors hold `auditor` *within one
  tenant* and nothing platform-wide.
- **Provider-scoped authorization.** A grant to one issuer's identity is
  unclaimable by another issuer asserting the same subject.
- **Audience-bound verification.** A token minted for a different relying party
  of the same IdP does not authenticate here.
- **Break-glass closed last.** `policy.allow_root_basic_auth: true` is left on
  while you verify SSO; turn it off once both IdPs work, since a shared static
  password is then the weakest credential in the deployment.
