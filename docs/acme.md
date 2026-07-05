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
instead by three deployment controls, described below: a fixed issuing-CA with
one or more operator-vetted profiles, optional External Account Binding, and
per-order auditing.

- [1. Enabling the ACME server](#1-enabling-the-acme-server)
- [2. Configuring the ACME-enabled profile](#2-configuring-the-acme-enabled-profile)
- [3. Challenge types (http-01, dns-01, tls-alpn-01)](#3-challenge-types-http-01-dns-01-tls-alpn-01)
  - [Multi-perspective corroboration (MPIC / SC-067)](#multi-perspective-corroboration-mpic--sc-067)
- [4. Access control: External Account Binding](#4-access-control-external-account-binding)
- [5. Client examples](#5-client-examples)
- [6. Auditing and operator visibility](#6-auditing-and-operator-visibility)
- [7. Endpoint reference](#7-endpoint-reference)
- [8. Renewal Information (ARI)](#8-renewal-information-ari)
- [9. STAR: short-term auto-renewed certificates (RFC 8739)](#9-star-short-term-auto-renewed-certificates-rfc-8739)
- [10. Operational notes](#10-operational-notes)

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
  # Challenge types offered per authorization (default: all three).
  challenge_types: ["http-01", "dns-01", "tls-alpn-01"]
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
  "renewalInfo": "https://pki.example.com/acme/renewal-info",
  "meta": { "termsOfService": "https://pki.example.com/tos" }
}
```

(When the [ACME Profiles extension](#client-selectable-profiles-rfc-9773) is
configured, `meta` additionally carries a `profiles` map of the selectable
issuance profiles.)

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

### Client-selectable profiles (RFC 9773)

The single `acme.profile` above fixes the shape of every ACME certificate. To
offer **several** profiles from one ACME endpoint — for example a short-lived
TLS-server profile and an mTLS-client profile — enable the **ACME Profiles
extension** ([RFC 9773](https://www.rfc-editor.org/rfc/rfc9773.html)) by mapping
each ACME-visible profile name to an internal issuance profile:

```yaml
acme:
  enabled: true
  ca_label: "Secsy Issuing CA"
  profile: "server"            # default when a client selects nothing (backward compatible)
  profiles:
    short-lived:
      description: "90-day TLS server certificates"
      profile: "acme-tls"      # internal (built-in or custom) profile id
    mtls-client:
      description: "Client-authentication certificates"
      profile: "client"
```

Each mapped internal profile is validated at startup (a typo fails fast, exactly
like a bad CA reference), and the set is advertised in the directory's
`meta.profiles`:

```console
$ curl -s https://pki.example.com/acme/directory | jq '.meta.profiles'
{
  "short-lived": "90-day TLS server certificates",
  "mtls-client": "Client-authentication certificates"
}
```

A client picks one by naming it in the `profile` field of its **newOrder**
request. The selection is recorded on the order and governs the **whole**
issuance path at finalize — the pre-issuance lint, CAA, name-constraints,
certificate-policy, and CT gates all run against the chosen profile. Omitting the
field uses `acme.profile`, so clients that predate the extension keep working
unchanged.

Naming a profile the server does not advertise is rejected with the
`urn:ietf:params:acme:error:invalidProfile` problem (HTTP 400), whose `detail`
lists the available names.

- **Client support.** Profile selection is a recent ACME extension; use a client
  that implements RFC 9773 (recent certbot exposes `--preferred-profile` /
  `--required-profile`). Any client that does not send a `profile` field
  transparently receives the default profile, so enabling the extension never
  breaks existing automation.
- **Selected profile is visible** on the operator inventory endpoint
  `GET /api/acme/orders` (the `profile` field) and in the `acme.order.new` audit
  event, and issuance is metered per profile — see
  [§6 Auditing and operator visibility](#6-auditing-and-operator-visibility).

## 3. Challenge types (http-01, dns-01, tls-alpn-01)

For each identifier in an order the server creates an authorization offering the
configured challenge types. The server performs the validation itself
(outbound), so it must be able to reach the client's challenge responder. The
challenge path performs **no HSM operation** — only the finalize step signs, on
the HSM, through the shared CA manager.

**http-01** (RFC 8555 §8.3) — the client serves the key authorization at
`http://<domain>/.well-known/acme-challenge/<token>` on **port 80**. The server
fetches it and compares. For local testing where port 80 is unavailable, set
`acme.http01_port` to a high port (integration tests use this).

**dns-01** (RFC 8555 §8.4) — the client publishes a TXT record at
`_acme-challenge.<domain>` whose value is `base64url(SHA-256(keyAuthorization))`.
The server resolves it via DNS. dns-01 is the **only** challenge type offered for
**wildcard** (`*.example.com`) identifiers, per the RFC.

**tls-alpn-01** (RFC 8737) — the client answers on **port 443** by presenting a
special validation certificate over a TLS handshake that negotiates the
`acme-tls/1` ALPN protocol. The server dials the identifier, offering only
`acme-tls/1`, and requires the peer to present a **self-signed** certificate
whose single `subjectAltName` is the identifier and that carries the **critical**
`id-pe-acmeIdentifier` extension (OID `1.3.6.1.5.5.7.1.31`) whose OCTET-STRING
value equals `SHA-256(keyAuthorization)`. This validates over the same port a web
service already listens on (no port 80 responder needed), and — like http-01 —
it works for IP-address identifiers (RFC 8738) but **not** for wildcards. For
local testing where port 443 is unavailable, set `acme.tls_alpn01_port` to a high
port.

Restrict the offered set with `acme.challenge_types` (e.g. `["dns-01"]` to force
DNS validation only, or `["tls-alpn-01"]` for a port-443-only responder). The
default offers all three. IP-address identifiers (RFC 8738) are disabled unless
`acme.allow_ip_identifiers: true`; when enabled they may be validated with
http-01 or tls-alpn-01.

**`email-reply-00` (RFC 8823)** validates `email`-type identifiers for **S/MIME**
issuance: the server mails a signed challenge to the mailbox and validates the
reply. It is offered only when an inbound-mail (IMAP) poller is configured; see
[enrollment.md §7](enrollment.md#7-acme-smime-certificates-rfc-8823-email-reply-00)
for the `acme.email` block and full flow.

### Multi-perspective corroboration (MPIC / SC-067)

By default the three domain-control challenges are validated from a **single**
network vantage point, which a localized BGP/DNS hijack can fool. Enable
**Multi-Perspective Issuance Corroboration** (CA/Browser Forum ballot SC-067)
under `acme.mpic` to re-check each http-01 / dns-01 / tls-alpn-01 validation from
several independent remote perspectives (each with its own resolver and/or
outbound SOCKS5 proxy) and issue only when a **quorum** agrees. It is off by
default and fails **closed** when too few perspectives corroborate. See
**[ACME MPIC (SC-067)](acme-mpic.md)** for the quorum rule, configuration, and
observability.

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
| `acme.order.new` | An order is placed (records the identifiers and the selected issuance profile) |
| `acme.challenge` | A challenge is validated or fails (the detail records the challenge type — `http-01`, `dns-01`, or `tls-alpn-01` — and identifier) |
| `acme.order.finalize` | A certificate is issued (records the serial and profile) |
| `acme.cert.revoke` | A certificate is revoked via ACME |
| `acme.renewal_info` | A renewal-info (ARI) window is served (records whether the window is normal/revoked/rotating) |
| `acme.order.replaces` | A new order links to the certificate it renews via `replaces` |

The actor is `acme:<account-id>`. These events are covered by the same
tamper-evidence and `GET /api/events/verify` integrity check as the rest of the
log, and ACME-issued certificates appear in the CA's `issued_certificates`
inventory and its CRL/OCSP responses just like any other certificate.

Challenge validation is also metered: `secsy_acme_challenge_validations_total`
counts attempts by challenge `type` (`http-01`|`dns-01`|`tls-alpn-01`) and
`result` (`valid`|`invalid`), giving each challenge type observable parity on the
[metrics endpoint](observability.md). Issuance is metered per profile:
`secsy_acme_certificates_issued_total{profile}` counts certificates issued
through finalize by the internal issuance profile they were signed under, so with
the [ACME Profiles extension](#client-selectable-profiles-rfc-9773) an operator
can see volume broken down by selectable profile.

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
| POST | `/acme/order/{id}` | Fetch an order (POST-as-GET), or cancel a STAR recurrence (`status="canceled"`) |
| POST | `/acme/order/{id}/finalize` | Submit a CSR to issue |
| POST/GET | `/acme/star-cert/{id}` | Download the current STAR certificate (GET is unauthenticated when the order set `allow-certificate-get`) |
| POST | `/acme/authz/{id}` | Fetch an authorization |
| POST | `/acme/chall/{id}` | Respond to / fetch a challenge |
| POST | `/acme/cert/{id}` | Download the issued chain (PEM) |
| POST | `/acme/acct/{id}` | Fetch / update / deactivate an account |
| POST | `/acme/acct/{id}/orders` | List an account's orders |
| POST | `/acme/revoke-cert` | Revoke a certificate |
| POST | `/acme/key-change` | Rotate the account key |
| GET | `/acme/renewal-info/{certID}` | Renewal Information (ARI) — suggested renewal window |

## 8. Renewal Information (ARI)

The server implements [ACME Renewal Information](https://datatracker.ietf.org/doc/draft-ietf-acme-ari/)
(`draft-ietf-acme-ari`) so clients schedule renewals against the server's advice
instead of a fixed timer, and react promptly when a certificate must be replaced.

**Advertisement.** The directory carries a `renewalInfo` field (the base URL of
the resource). ARI-aware clients (recent certbot, lego, Caddy, …) pick it up
automatically.

**Looking up a window.** A client requests
`GET /acme/renewal-info/<certID>`, where `certID` is
`base64url(AuthorityKeyIdentifier) || "." || base64url(SerialNumber)` (ARI §4.1).
The response is an unauthenticated JSON body plus a `Retry-After` header:

```console
$ curl -s https://pki.example.com/acme/renewal-info/aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE
{
  "suggestedWindow": {
    "start": "2026-09-01T00:00:00Z",
    "end":   "2026-09-16T00:00:00Z"
  },
  "explanationURL": "https://pki.example.com/notices/mass-renewal"
}
```

The client picks a uniformly random time within `[start, end)` and renews then,
which spreads renewal load across the fleet.

**Window policy.**

- *Normal:* the window begins `acme.renewal_window_days` before expiry (falling
  back to the [expiry monitor's](expiry-monitoring.md) `renew_before_days`, then
  to the final third of the certificate's lifetime) and spans
  `acme.renewal_window_width_hours` (default: half the renew-before span).
- *Forced (immediate):* when the certificate has been **revoked**, or its issuing
  CA key is being **rotated** (the key is `superseded` mid-[rollover](ca-rotation.md)),
  the window ends at *now* so the client renews right away and migrates onto the
  new key.

**Renewal linkage (`replaces`).** A `newOrder` request may carry a `replaces`
field naming the CertID of the certificate it renews. The server verifies the
predecessor was issued to the same account and has not already been replaced
(returning `urn:ietf:params:acme:error:alreadyReplaced` otherwise), records the
linkage on the order, and audits it (`acme.order.replaces`).

**Configuration.**

```yaml
acme:
  renewal_window_days: 30          # when the suggested window opens (0 = derive)
  renewal_window_width_hours: 360  # window width (0 = half the renew-before span)
  renewal_poll_hours: 6            # advertised Retry-After cadence
  renewal_explanation_url: "https://pki.example.com/notices/mass-renewal"
```

To compute a CertID from a certificate you hold, use `acme.CertID(*x509.Certificate)`.

## 9. STAR: short-term auto-renewed certificates (RFC 8739)

[STAR](https://www.rfc-editor.org/rfc/rfc8739) turns an order into a
**subscription**: the server issues a short-lived certificate and *automatically
re-issues* it ahead of expiry, and the subscriber always fetches the current one
from a single stable URL. It suits deployments that prefer very short lifetimes
(so revocation is rarely needed) with no per-renewal client work — and it lets a
relying party fetch the certificate over an unauthenticated GET, e.g. for CDN
push. Off by default.

**Enabling.**

```yaml
acme:
  star:
    enabled: true
    min_lifetime_hours: 1     # floor on each certificate's lifetime (advertised as min-lifetime)
    max_lifetime_hours: 168   # ceiling on each certificate's lifetime (7 days)
    max_duration_days: 365    # longest total recurrence (advertised as max-duration)
```

When enabled the directory advertises the bounds under `meta.auto-renewal`:

```console
$ curl -s https://pki.example.com/acme/directory | jq '.meta."auto-renewal"'
{ "min-lifetime": 3600, "max-duration": 31536000, "allow-certificate-get": true }
```

**Ordering.** A client adds an `auto-renewal` object to its **newOrder** (only
`dns`/`ip` identifiers — not S/MIME email):

```json
{
  "identifiers": [{ "type": "dns", "value": "app.example.com" }],
  "auto-renewal": {
    "start-date": "2026-07-05T00:00:00Z",   // optional; defaults to now
    "end-date":   "2026-10-05T00:00:00Z",   // required — recurrence horizon
    "lifetime":   86400,                      // required — per-certificate seconds
    "allow-certificate-get": true             // optional — permit unauthenticated GET
  }
}
```

The recurrence is validated against the configured bounds (`lifetime` within
min/max, duration within max, `end-date` in the future); a violation is rejected
with `urn:ietf:params:acme:error:malformed`. The order is then validated and
finalized exactly like a normal order — you still solve a challenge per identifier
and submit a CSR — after which it reports `status: valid` and carries a
**`star-certificate`** URL instead of `certificate`, plus the resolved
`auto-renewal` object. `expires` reflects the recurrence's `end-date`.

**Fetching.** `star-certificate` always returns the *current* certificate:

```console
# Authenticated POST-as-GET (always available):
# ... signed JWS POST to the star-certificate URL ...
# Unauthenticated GET (only when the order set allow-certificate-get):
$ curl -s https://pki.example.com/acme/star-cert/<order-id>
-----BEGIN CERTIFICATE----- ...
```

**Renewal.** A leader-elected background job re-issues each STAR certificate
before it expires (from the CSR captured at finalize — same key and identifiers),
up to `end-date`, then stops. Because the certificates are deliberately
short-lived and self-renewing, they are excluded from the
[expiry monitor](expiry-monitoring.md). Renewal never involves the client.

**Cancellation.** POST `status: "canceled"` to the order URL (RFC 8739 §3.5) to
end the subscription: renewal stops immediately and `star-certificate` then
answers `403` with `urn:ietf:params:acme:error:autoRenewalCanceled`.

**Observability.** `secsy_acme_star_orders_total{event}` counts
`created|renewed|renew_failed|canceled|ended`, and each event is audited under the
`cert.acme` action.

> **Client support.** STAR is a niche extension; certbot/lego do not implement it.
> Drive it with a STAR-aware client or a direct JWS integration. The server's
> behavior is exercised by the raw-JWS test in
> `server/internal/acme/star_test.go`.

## 10. Operational notes

- **TLS.** Real ACME clients require the directory to be served over HTTPS.
  Configure `server.tls_cert`/`tls_key`, or terminate TLS at a trusted proxy and
  set `base_url`/forwarded headers accordingly. (The server itself already
  [fails closed without TLS](security-review.md) unless explicitly overridden.)
- **Reachability.** For http-01 the server must reach the client on port 80, for
  tls-alpn-01 on port 443 (negotiating `acme-tls/1`), and for dns-01 it must
  resolve public DNS. In split-horizon networks, prefer dns-01.
- **Nonces** are single-use anti-replay tokens (RFC 8555 §6.5) and are correct
  across replicas. Each is *self-authenticating* — an HMAC over a timestamp and
  random bytes, keyed by a server-wide secret shared through the store — so a
  nonce minted by one replica is accepted by any other behind a load balancer
  (no more spurious `badNonce` on a round-robin request). Single use is enforced
  by a shared consumed-set in the store, so a replay is rejected everywhere.
  Expiry (30 min TTL) and forged/malformed nonces are rejected in-process before
  the store is touched, keeping the fast path cheap; a leader-elected sweep prunes
  the consumed-set. **No configuration is needed** — the shared secret is
  generated once and persisted automatically. Operators who prefer to pin or
  rotate the key may set `acme.nonce_hmac_key` (base64, ≥16 bytes) identically on
  every replica. The `secsy_acme_nonces_total{result}` metric breaks nonce
  outcomes down by `issued|valid|replayed|expired|invalid|error`.
  > **Known follow-up:** rate-limit token buckets remain **per-replica** (each
  > replica meters independently), so effective public-endpoint limits scale with
  > the replica count. Only the anti-replay nonce store is shared today; see
  > [Rate limiting](rate-limiting.md) and [High availability](high-availability.md).
- **Revocation** is authorized either by the account that placed the order or by
  the certificate's own key pair, and flows through the standard revocation store
  → it appears in the CA's CRL and OCSP responses.
- **Testing.** `server/internal/e2e/acme_test.go` (build tag `sqlite`, gated on
  the `SECSY_*` SoftHSM env) runs the full http-01 and dns-01 flows, revocation,
  and the ARI renewal-hint flow against a real token; `server/internal/acme/server_test.go`
  runs the http-01, dns-01, and tls-alpn-01 flows against the software provider
  (no HSM needed), and `server/internal/acme/tlsalpn_test.go` covers the RFC 8737
  validation logic hermetically with an in-process TLS responder presenting
  correctly and incorrectly crafted validation certificates.

## See also

- [ACME MPIC (SC-067)](acme-mpic.md) — multi-perspective domain-control corroboration
- [Certificate authority](certificate-authority.md) — creating the issuing CA and profiles
- [RBAC, audit logging & config](rbac-and-audit.md) — the event log and roles
- [HSM / PKCS#11 configuration](hsm-configuration.md) — the key provider
