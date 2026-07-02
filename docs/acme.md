# ACME (RFC 8555): automated certificate issuance

secsy-pki includes an **ACME server** so standard ACME clients — [certbot](https://certbot.eff.org/),
[lego](https://go-acme.github.io/lego/), [acme.sh](https://acme.sh),
Caddy, Traefik, cert-manager, and the Go `golang.org/x/crypto/acme` client —
can obtain certificates automatically. Every certificate the ACME server issues
is signed by an **HSM-backed CA** through the same [`ca.Manager`](certificate-authority.md)
used by the REST API and CLI, and every order is written to the
[tamper-evident audit log](rbac-and-audit.md).

The ACME endpoints authenticate clients with their own **account key pairs**
(JWS-signed requests, per RFC 8555 §6.2) rather than OIDC or the root user, so
they are mounted **outside** the OIDC auth middleware. Access is governed
instead by three deployment controls, described below: a single fixed
issuing-CA + profile, optional External Account Binding, and per-order auditing.

- [1. Enabling the ACME server](#1-enabling-the-acme-server)
- [2. Configuring the ACME-enabled profile](#2-configuring-the-acme-enabled-profile)
- [3. Challenge types (http-01, dns-01)](#3-challenge-types-http-01-dns-01)
- [4. Access control: External Account Binding](#4-access-control-external-account-binding)
- [5. Client examples](#5-client-examples)
- [6. Auditing and operator visibility](#6-auditing-and-operator-visibility)
- [7. Endpoint reference](#7-endpoint-reference)
- [8. Operational notes](#8-operational-notes)

## 1. Enabling the ACME server

ACME is **off by default**. Enable it in `config.yaml` and point it at an
existing X.509 issuing CA (create one first — see the
[CA guide](certificate-authority.md)):

```yaml
acme:
  enabled: true
  # Externally reachable origin. Leave empty to derive it per request from the
  # Host header + scheme (honoring X-Forwarded-Proto / X-Forwarded-Host behind a
  # TLS-terminating proxy). Set it explicitly in production.
  base_url: "https://pki.example.com"
  # The CA that signs ACME certificates. Use ca_label OR ca_id (id wins).
  ca_label: "Secsy Issuing CA"
  # Certificate profile applied to every ACME-issued certificate.
  profile: "server"
  # Advertised in the directory; when set, clients must agree on registration.
  terms_of_service: "https://pki.example.com/tos"
  # Challenge types offered per authorization (default: both).
  challenge_types: ["http-01", "dns-01"]
```

The server fails to start if `acme.enabled` is true but the referenced CA does
not exist or is not an X.509 issuer, so misconfiguration surfaces immediately.

Once running, the directory is served at `<base_url>/acme/directory`:

```console
$ curl -s https://pki.example.com/acme/directory | jq
{
  "newNonce":   "https://pki.example.com/acme/new-nonce",
  "newAccount": "https://pki.example.com/acme/new-account",
  "newOrder":   "https://pki.example.com/acme/new-order",
  "revokeCert": "https://pki.example.com/acme/revoke-cert",
  "keyChange":  "https://pki.example.com/acme/key-change",
  "meta": { "termsOfService": "https://pki.example.com/tos" }
}
```

## 2. Configuring the ACME-enabled profile

An "ACME-enabled profile" is simply the certificate [profile](certificate-authority.md#3-certificate-profiles)
named in `acme.profile`. The profile fixes the key usages, extended key usages,
and validity of every ACME-issued certificate; ACME clients cannot influence
these (they only supply identifiers and a CSR public key). This is deliberate:
it keeps automated issuance inside a shape the operator has vetted.

Use a **built-in** profile (`server` is the default and correct choice for TLS)
or define a **custom** one and reference it. Custom profiles are declared in the
same `profiles:` block used elsewhere:

```yaml
profiles:
  - name: "acme-tls"
    description: "Short-lived TLS server certs for ACME automation"
    key_usages:     ["digitalSignature", "keyEncipherment"]
    ext_key_usages: ["serverAuth"]
    default_validity_days: 90     # short-lived; renew often via ACME
    max_validity_days:     90

acme:
  enabled: true
  ca_label: "Secsy Issuing CA"
  profile: "acme-tls"            # <- the ACME-enabled profile
```

Notes:

- The `default_validity_days` of the profile determines ACME cert lifetime; ACME
  clients renew automatically well before expiry, so short-lived certs (30–90
  days) are the norm.
- Validity is still clamped to the profile maximum **and** the issuing CA's own
  `notAfter`, exactly as for API/CLI issuance.
- The global `policy.max_cert_validity_days` does **not** apply to ACME (that cap
  governs the interactive `/issue` and `/sign` endpoints); bound ACME lifetime
  through the profile instead.

## 3. Challenge types (http-01, dns-01)

For each identifier in an order the server creates an authorization offering the
configured challenge types. The server performs the validation itself
(outbound), so it must be able to reach the client's challenge responder.

**http-01** (RFC 8555 §8.3) — the client serves the key authorization at
`http://<domain>/.well-known/acme-challenge/<token>` on **port 80**. The server
fetches it and compares. For local testing where port 80 is unavailable, set
`acme.http01_port` to a high port (integration tests use this).

**dns-01** (RFC 8555 §8.4) — the client publishes a TXT record at
`_acme-challenge.<domain>` whose value is `base64url(SHA-256(keyAuthorization))`.
The server resolves it via DNS. dns-01 is the **only** challenge type offered for
**wildcard** (`*.example.com`) identifiers, per the RFC.

Restrict the offered set with `acme.challenge_types` (e.g. `["dns-01"]` to force
DNS validation only). IP-address identifiers (RFC 8738) are disabled unless
`acme.allow_ip_identifiers: true`.

## 4. Access control: External Account Binding

Because ACME clients self-register with any key pair, an open ACME server will
issue to anyone who can satisfy a challenge for a name. To restrict *who* may
register — the ACME analogue of an RBAC grant — enable **External Account
Binding** (EAB, RFC 8555 §7.3.4). Each operator-provisioned key id (`kid`) maps
to a shared HMAC secret; a client must present a valid EAB (signed with that
secret) on account creation.

```yaml
acme:
  enabled: true
  ca_label: "Secsy Issuing CA"
  require_eab: true
  eab_hmac_keys:
    # kid: HMAC key, base64url or standard base64 (generate: openssl rand -base64 32)
    "team-web":     "R29vZCBsdWNrIGRlY29kaW5nIHRoaXMga2V5IQ"
    "team-payments": "c2Vjc3ktcGtpLWVhYi1obWFjLWtleS1zYW1wbGU"
```

Provide the `kid` and HMAC key to the client (e.g. `certbot --eab-kid team-web
--eab-hmac-key <key>`). Startup fails if `require_eab` is set with no keys.

When EAB is required the directory advertises `"externalAccountRequired": true`
and the bound `kid` is recorded on the account and in the audit log.

## 5. Client examples

The examples below assume ACME is enabled at `https://pki.example.com`.

### certbot (http-01)

```console
certbot certonly \
  --server https://pki.example.com/acme/directory \
  --standalone \
  -d app.example.com \
  --agree-tos -m ops@example.com
```

### lego (dns-01, e.g. via a DNS provider plugin)

```console
lego --server https://pki.example.com/acme/directory \
     --email ops@example.com \
     --dns <provider> \
     --domains "*.example.com" \
     run
```

### With External Account Binding

```console
certbot register \
  --server https://pki.example.com/acme/directory \
  --eab-kid team-web \
  --eab-hmac-key R29vZCBsdWNrIGRlY29kaW5nIHRoaXMga2V5IQ \
  --agree-tos -m ops@example.com
```

### Go client (`golang.org/x/crypto/acme`)

This is the client used by the integration test
(`server/internal/e2e/acme_test.go`), which drives a full order end-to-end
against a SoftHSM-backed CA. See that file for a complete worked example of
`Register → AuthorizeOrder → Accept → WaitOrder → CreateOrderCert`.

## 6. Auditing and operator visibility

Every ACME operation appends an entry to the [hash-chained event log](rbac-and-audit.md):

| Action | When |
|--------|------|
| `acme.account.new` | An account is registered (records the EAB `kid`, if any) |
| `acme.order.new` | An order is placed (records the identifiers) |
| `acme.challenge` | A challenge is validated or fails |
| `acme.order.finalize` | A certificate is issued (records the serial and profile) |
| `acme.cert.revoke` | A certificate is revoked via ACME |

The actor is `acme:<account-id>`. These events are covered by the same
tamper-evidence and `GET /api/events/verify` integrity check as the rest of the
log, and ACME-issued certificates appear in the CA's `issued_certificates`
inventory and its CRL/OCSP responses just like any other certificate.

Operators can inspect ACME state through RBAC-gated (read: admin/issuer/auditor)
inventory endpoints:

```console
GET /api/acme/accounts    # registered ACME accounts
GET /api/acme/orders      # ACME orders and their status/serials
```

## 7. Endpoint reference

All paths are relative to `acme.directory_path` (default `/acme`). Except the
directory and new-nonce, every endpoint is a JWS-signed POST (POST-as-GET for
reads), per RFC 8555.

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/acme/directory` | Service directory |
| HEAD/GET | `/acme/new-nonce` | Fetch an anti-replay nonce |
| POST | `/acme/new-account` | Register / look up an account |
| POST | `/acme/new-order` | Create an order |
| POST | `/acme/order/{id}` | Fetch an order (POST-as-GET) |
| POST | `/acme/order/{id}/finalize` | Submit a CSR to issue |
| POST | `/acme/authz/{id}` | Fetch an authorization |
| POST | `/acme/chall/{id}` | Respond to / fetch a challenge |
| POST | `/acme/cert/{id}` | Download the issued chain (PEM) |
| POST | `/acme/acct/{id}` | Fetch / update / deactivate an account |
| POST | `/acme/acct/{id}/orders` | List an account's orders |
| POST | `/acme/revoke-cert` | Revoke a certificate |
| POST | `/acme/key-change` | Rotate the account key |

## 8. Operational notes

- **TLS.** Real ACME clients require the directory to be served over HTTPS.
  Configure `server.tls_cert`/`tls_key`, or terminate TLS at a trusted proxy and
  set `base_url`/forwarded headers accordingly. (The server itself already
  [fails closed without TLS](security-review.md) unless explicitly overridden.)
- **Reachability.** For http-01 the server must reach the client on port 80; for
  dns-01 it must resolve public DNS. In split-horizon networks, prefer dns-01.
- **Nonces** are held in memory and are single-use; a restart simply forces
  clients to fetch a fresh one (`badNonce` → automatic retry). No configuration
  needed.
- **Revocation** is authorized either by the account that placed the order or by
  the certificate's own key pair, and flows through the standard revocation store
  → it appears in the CA's CRL and OCSP responses.
- **Testing.** `server/internal/e2e/acme_test.go` (build tag `sqlite`, gated on
  the `SECSY_*` SoftHSM env) runs the full http-01 and dns-01 flows plus
  revocation against a real token; `server/internal/acme/server_test.go` runs the
  same flows against the software provider (no HSM needed).

## See also

- [Certificate authority](certificate-authority.md) — creating the issuing CA and profiles
- [RBAC, audit logging & config](rbac-and-audit.md) — the event log and roles
- [HSM / PKCS#11 configuration](hsm-configuration.md) — the key provider
