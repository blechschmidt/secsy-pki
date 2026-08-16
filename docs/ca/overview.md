# Certificate authority: setup, issuance, revocation, CRL & OCSP

This guide covers the full X.509 lifecycle on the HSM-backed CA: standing up
root and intermediate CAs, issuing end-entity certificates from CSRs, renewing
and revoking them, and serving revocation status via CRL and OCSP.

Every signing operation — root/intermediate certs, leaf certs, CRLs, and OCSP
responses — is performed **on the key provider** (the HSM). CA private keys are
generated on the device and never leave it. Configure the provider first:
[HSM / PKCS#11 configuration](../hsm/configuration.md).

Two interfaces drive the CA:

- **`secsy-ca`** — an operator CLI that shares the server's config, database, and
  key provider. Best for bootstrapping and back-office tasks.
- **HTTP API** — for programmatic issuance by authenticated users, subject to
  [RBAC and per-CA permissions](../security/rbac-and-audit.md).

Build the CLI (SQLite build needs the `sqlite` tag):

```bash
cd server
go build -tags sqlite -o secsy-ca ./cmd/secsy-ca
```

## 1. Initialize a root CA

Generates a CA key on the provider and a self-signed root certificate signed on
the device.

```bash
secsy-ca -config config.yaml init-root \
  -label "Root CA" \
  -cn "Example Root CA" -o "Example Inc" -c "US" \
  -key-type ecdsa-p384 \
  -validity-days 3650 \
  -path-len -1
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-label` | *(required)* | Key label / CA name — the stable handle used everywhere (must be unique on the token) |
| `-cn` | *(required)* | Subject common name |
| `-o -ou -c -st -l` | — | Subject organization / OU / country / state / locality |
| `-key-type` | `ecdsa-p384` | `ed25519`, `ecdsa-p256/p384/p521`, `rsa-2048`, `rsa-4096` |
| `-validity-days` | `3650` | Certificate lifetime |
| `-path-len` | `-1` | Max path length. `-1` = unconstrained; `0` = may only sign leaf certs |

> **Key labels are permanent and must be unique.** See
> [HSM configuration](../hsm/configuration.md#key-labels-must-be-unique).

## 2. Issue an intermediate CA

Recommended topology: keep the root offline-ish (rarely used, long path budget)
and issue day-to-day certificates from an intermediate.

```bash
secsy-ca -config config.yaml issue-intermediate \
  -parent "Root CA" \
  -label "Issuing CA" \
  -cn "Example Issuing CA" -o "Example Inc" \
  -key-type ecdsa-p256 \
  -validity-days 1825 \
  -path-len 0
```

`-parent` accepts a CA label or ID (`secsy-ca list` shows both). The
intermediate's key is generated on the HSM and its certificate is signed by the
parent CA on the HSM.

List configured CAs at any time:

```bash
secsy-ca -config config.yaml list
```

The equivalent API calls (admin / `ca:manage`) are
`POST /api/ca/init-root` and `POST /api/ca/{id}/issue-intermediate`, taking a
[`CASubject`](../../server/internal/models/models.go) JSON body.

## 3. Certificate profiles

A **profile** fixes the key usages, extended key usages, and validity bounds of
an issued leaf, so callers don't hand-craft them. Requested validity is clamped
to the profile maximum *and* to the issuer's `notAfter`.

| Profile | Key usages | Ext key usages | Default / max validity |
|---------|-----------|----------------|------------------------|
| `server` | digitalSignature, keyEncipherment | serverAuth | 397 d / 397 d |
| `server-muststaple` | digitalSignature, keyEncipherment | serverAuth | 397 d / 397 d |
| `client` | digitalSignature | clientAuth | 365 d / 730 d |
| `server-client` | digitalSignature, keyEncipherment | serverAuth, clientAuth | 397 d / 397 d |
| `code-signing` | digitalSignature | codeSigning | 3 y / 3 y |
| `email` | digitalSignature, keyEncipherment | emailProtection | 365 d / 730 d |

```bash
secsy-ca profiles            # or: GET /api/profiles
```

Operators can add custom profiles or override a built-in (by reusing its name)
via the `profiles:` config block — see
[RBAC & config](../security/rbac-and-audit.md#3-centralized-configuration).

### OCSP Must-Staple (RFC 7633)

Setting `must_staple: true` on a profile stamps the RFC 7633 **TLS Feature**
extension (`id-pe-tlsfeature`, OID `1.3.6.1.5.5.7.1.24`) on every leaf: a
non-critical `SEQUENCE OF INTEGER` carrying `status_request(5)`. A relying party
that honors it aborts a TLS handshake in which the server does not staple a valid
OCSP response, so the certificate cannot be used soft-fail. The built-in
`server-muststaple` profile enables it out of the box; `openssl x509 -text`
renders it as `TLS Feature: status_request`.

- **Per-request override.** With `allow_must_staple_override: true` on the
  profile, a REST/gRPC issue request may set `must_staple` per certificate (turn
  it on or off); without it the profile default is authoritative and any
  per-request value is ignored.
- **Preserved on renewal and rotation.** A renewal keeps a Must-Staple
  commitment the original certificate carried (including one applied via a
  per-request override), and issuance after a CA key rotation keeps stamping it.
- **Lint safety net.** `lint.require_must_staple: true` flags (warn by default) a
  serverAuth leaf that ends up *without* Must-Staple — useful to catch a profile
  that forgot to set the knob. `secsy-ca lint -require-must-staple <cert>` runs
  the same check ad hoc.
- **Mutually exclusive with delegated credentials.** RFC 9345 §4.2 forbids
  combining Must-Staple with the `DelegationUsage` marker, so a profile cannot set
  both `must_staple`/`allow_must_staple_override` and `delegation_usage` — the
  combination is rejected fail-closed at profile install and again at issuance.
  See [TLS Delegated Credentials](../certificates/delegated-credentials.md).

### Private-key usage period (RFC 5280)

A `private_key_usage_period` block on a profile stamps the non-critical
`id-ce-privateKeyUsagePeriod` extension (OID `2.5.29.16`): the window during which
the certified private key may *produce* signatures, which can be narrower than the
certificate's own validity (the classic case is a signing key that must retire
before the certificate expires while signatures it already made stay verifiable).
The window is expressed as a `duration` from `notBefore` (e.g. `365d`, `52w`,
`8760h`), a `fraction` of the certificate validity, or explicit `not_before` /
`not_after` instants, and is always clamped inside the certificate validity.

- **Per-request override.** With `allow_override: true`, a REST/gRPC issue request
  may supply a `private_key_usage_period` (a `duration` or explicit instants) per
  certificate; without it the profile window (if any) is authoritative. The
  built-in `qualified-esign` / `qualified-eseal` profiles set `allow_override`
  with no default, so the deployment supplies a window per request where its policy
  requires one.
- **Preserved on renewal** and re-applied against the fresh validity window.
- **Console / CLI.** The [Issue page](../operations/web-console.md) shows a *private-key usage
  period* field where the profile permits an override; `secsy-ca issue -pkup 365d`
  (or `-pkup-not-before`/`-pkup-not-after`) is the CLI equivalent, and `-dry-run`
  previews the resolved window through the `private_key_usage_period` gate.

### Delegated-credential eligibility (RFC 9345)

Setting `delegation_usage: true` on a profile stamps the RFC 9345
`id-ce-delegationUsage` extension (OID `1.3.6.1.4.1.44363.44`), marking every leaf
issued under it *eligible* to authorize short-lived TLS Delegated Credentials. It
is profile-only (there is no per-request override) and pairs with a `serverAuth`
profile that has `digitalSignature` key usage; the built-in `server-delegation`
profile is the reference. The [Issue page](../operations/web-console.md) policy summary flags a
delegation-eligible profile so an operator knows the resulting leaf can mint
delegated credentials. It is mutually exclusive with OCSP Must-Staple (above). See
[TLS Delegated Credentials](../certificates/delegated-credentials.md) for minting and verification.

## 4. Issue an end-entity certificate

The subject, SANs, and public key all come from the caller's PKCS#10 CSR; the
profile supplies usages and validity. secsy-pki never sees the subscriber's
private key.

Create a CSR (subscriber side):

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout tls.key -out tls.csr \
  -subj "/CN=app.example.com" \
  -addext "subjectAltName=DNS:app.example.com,DNS:www.example.com"
```

Issue it:

```bash
secsy-ca -config config.yaml issue \
  -ca "Issuing CA" \
  -csr tls.csr \
  -profile server \
  -validity-days 90 \
  -chain \
  -out tls.crt
```

- `-validity-days 0` (default) uses the profile default.
- `-chain` appends the issuing CA certificate to the output, producing a
  ready-to-serve chain. Omit for the leaf alone. `-` reads the CSR from stdin.

Each issuance allocates a unique per-CA serial atomically and records the
certificate in the `issued_certificates` table (used for renewal and listing).

**API** (`SIGN_CERTIFICATE` on the CA, or org-wide `cert:issue`):

```bash
curl -sk -u root:password -X POST https://localhost:8443/api/ca/{ca_id}/issue \
  -H 'Content-Type: application/json' \
  -d '{"csr":"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
       "profile":"server","validity_days":90}'
```

List what a CA has issued: `secsy-ca list-certs -ca "Issuing CA"` or
`GET /api/ca/{id}/certificates`.

The list endpoints are paginated and searchable so they scale to large
inventories. `GET /api/ca/{id}/certificates` accepts
`?limit=&cursor=&status=&profile=&q=&serial_prefix=&expires_before=` and returns
`{items, next_cursor, total, has_more}`; pass the returned `next_cursor` back in
`?cursor=` to page forward. Pages are keyset-ordered (newest first) so they stay
stable while new certificates are being issued. `q` matches a substring of the
subject/CN/SANs; `status` is one of `valid|revoked|held|expired`. The page size
defaults to 100 and is capped at 500. `GET /api/ca/{id}/revoked` and
`GET /api/discovery` take the same `limit`/`cursor` paging (revoked and discovery
support `serial_prefix`/`q` where applicable). On the CLI, `secsy-ca list-certs`
auto-follows every page for a full dump by default and accepts
`-limit/-cursor/-status/-profile/-filter/-serial-prefix/-expires-before` (and
`-page` for a single page); the gRPC `ListCertificates` RPC carries the same
paging and filter fields.

The flow above signs a CSR whose key the subscriber generated. When you instead
need to **deliver the private key** — for S/MIME or device enrollment — use
[PKCS#12 export](pkcs12.md): the server generates the subject key, issues the
leaf, and returns a password-protected `.p12` (key + leaf + full chain), with
optional M-of-N escrow of the subject key (`secsy-ca export-p12`, `POST
/api/ca/{id}/pkcs12`).

### Batch issuance (mass provisioning)

For fleet roll-outs, `secsy-ca issue-bulk` / `POST /api/ca/{id}/certificates:bulk`
issue an array of certificates in one operation — the issuance counterpart of
`revoke-bulk`. Each item is issued **independently through the same gate stack as
a single issuance** (lint, CAA, name constraints, certificate policies, the
policy-as-code CEL gate, CT, tenant lifecycle + daily quota), with bounded
concurrency over the HSM session pool. Semantics:

- **Partial success.** An item that trips a gate (a lint failure, a CAA denial,
  an exhausted tenant quota) fails only itself with a structured
  `error_code` (`invalid_request` | `quota_exceeded` | `tenant_suspended` |
  `gate_error` | `issuance_error`); the rest of the batch still issues. The
  response is a per-item result array (`status` = `issued` | `pending` |
  `failed`).
- **Approval parking.** An item under a `require_approval` profile (see
  [approvals](../security/approvals.md)) is **parked** and reported `pending` with an
  `approval_id` rather than failing the batch; fetch its certificate from
  `GET /api/approvals/{approval_id}/certificate` once approvers sign off. (The
  CLI, like `secsy-ca issue`, calls the CA directly and so bypasses the manual
  gate.)
- **Confirm-count guard.** A `dry_run` validates every item and returns the
  plan; a real run must set `confirm_count` to the number of items (a mismatch is
  refused with 409), guarding against an accidentally doubled input. One
  `cert.issue` audit event is written per issued item, plus one `cert.issue_bulk`
  summary tying them together by operation id.

Unlike bulk *revocation* (a CA-management, `ca:manage` operation), bulk issuance
requires only the ordinary **issue** capability, so a provisioning service
account can drive it.

CLI — a JSON manifest of `{ref, csr, profile, validity_days}` items (the `csr`
paths are resolved relative to the manifest):

```bash
secsy-ca -config config.yaml issue-bulk \
  -ca "Issuing CA" \
  -manifest fleet.json \
  -out-dir ./issued \
  -confirm 200          # must equal the item count (or -dry-run to preview)
```

API — an array of `{ref, csr, profile, validity_days}` items:

```bash
curl -sk -u root:password -X POST \
  https://localhost:8443/api/ca/{ca_id}/certificates:bulk \
  -H 'Content-Type: application/json' \
  -d '{"confirm_count":2,"items":[
        {"ref":"dev-1","csr":"-----BEGIN CERTIFICATE REQUEST-----\n...","profile":"server"},
        {"ref":"dev-2","csr":"-----BEGIN CERTIFICATE REQUEST-----\n...","profile":"server"}]}'
```

## 4a. List, filter & search issued certificates

The issued-certificate list endpoints are **paginated, filtered, and searchable**
server-side, so a CA with a large inventory returns a bounded page instead of the
whole table:

```
GET /api/ca/{id}/certificates?status=valid&profile=tls-server&q=example.com&limit=100&cursor=<opaque>
GET /api/ca/{id}/revoked?...          # same parameters, revoked-only
GET /api/discovery?...                # same parameters over the discovery inventory
```

| Parameter | Effect |
|---|---|
| `status` | `valid` / `revoked` / `expired` / `held` (the suspend/hold state) |
| `profile` | exact issuance-profile name |
| `q` | case-insensitive substring over subject / CN / SANs |
| `serial_prefix` | serials beginning with this hex prefix |
| `expires_before` | RFC 3339 timestamp or `YYYY-MM-DD` — certificates expiring before it (find soon-to-expire certs) |
| `limit` | page size; default **100**, hard-capped at **500** (a larger request is clamped and logged) |
| `cursor` | the opaque `next_cursor` from the previous page (keyset pagination — stable under concurrent inserts, unlike offset paging) |

The response envelope is `{ "items": [...], "next_cursor": "...", "total": N,
"has_more": true|false }`. Follow `next_cursor` until `has_more` is false to walk
the full set. When a response is truncated (client asked for more than 500, or
more rows remain), the server logs a page-truncation line so a partial view is
never silent.

The **CLI** exposes the same filters:

```bash
secsy-ca -config config.yaml list-certs -ca "Issuing CA" -status valid -profile tls-server -q example.com
```

The console **Certificates** page drives these parameters directly: a search box
(subject/CN/SAN), status and profile dropdowns, and a **Load more** button that
follows `next_cursor`. The **Inventory** page offers the same cross-CA filters
for reporting/CSV export.

## 5. Renew a certificate

Renewal issues a fresh certificate (new serial, new validity window) for an
existing one, identified by serial. By default it reuses the original public
key; pass a new CSR to **rekey**.

```bash
# Reuse the original key
secsy-ca -config config.yaml renew -ca "Issuing CA" -serial 0x03 -out renewed.crt

# Rekey with a new CSR
secsy-ca -config config.yaml renew -ca "Issuing CA" -serial 0x03 -csr new.csr -out renewed.crt
```

**API:** `POST /api/ca/{id}/renew` with `{"serial":"...","csr":"...optional...","validity_days":90}`.

Renewal does not revoke the old certificate — revoke it explicitly if it should
no longer be trusted (e.g. after a rekey following key compromise).

## 6. Revoke a certificate

Revocation is recorded in the authoritative `revoked_certificates` table, which
is the source of truth for both CRL and OCSP.

```bash
secsy-ca -config config.yaml revoke -ca "Issuing CA" -serial 0x03 -reason keyCompromise
```

`-reason` is an RFC 5280 reason name (default `unspecified`): `keyCompromise`,
`cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`,
`certificateHold`, `privilegeWithdrawn`, `aaCompromise`. (`removeFromCRL` is a
delta-CRL-only status, not a revocation reason — see suspend/release below.)
Revoking with these reasons is **permanent**. Re-revoking an already-revoked
serial updates its reason rather than failing.

**API:** `POST /api/ca/{id}/revoke` with `{"serial":"...","reason":"keyCompromise"}`.
List revocations: `GET /api/ca/{id}/revoked`.

**Mass revocation (compromise response):** `secsy-ca revoke-bulk` /
`POST /api/ca/{id}/revocations:bulk` revoke a whole selection (profile,
CN/SAN pattern, issuance window, serial list) in batches with a mandatory
dry-run count confirmation, one CRL+delta regeneration at the end, and
per-certificate + summary audit events. See the
[incident-response runbook](../operations/incident-response.md).

### Suspend and release (reversible hold)

A **hold** is a *reversible* revocation (RFC 5280 `certificateHold`, reason 6),
for when a certificate must be taken out of service temporarily — a lost device
that may be recovered, a policy review, a suspected but unconfirmed compromise —
without permanently burning the credential.

```bash
# Place on hold: OCSP reports revoked(certificateHold) and it appears on the CRL.
secsy-ca -config config.yaml suspend -ca "Issuing CA" -serial 0x03

# Release: OCSP reports good again; the certificate is back in service.
secsy-ca -config config.yaml release -ca "Issuing CA" -serial 0x03
```

**API:** `POST /api/ca/{id}/certificates/{serial}:suspend` and
`.../{serial}:release` (gRPC: `SuspendCertificate` / `ReleaseCertificate`; the
web console shows **Suspend**/**Release** buttons on the certificate list). Both
use the same authorization and tenant scope as single revocation.

Semantics (RFC 5280 §5.2.4 / §5.3.2):

- **While held** — OCSP returns `revoked` with reason `certificateHold`, and the
  serial is listed on the base CRL. The certificate's inventory status is `held`.
- **On release** — the hold is removed: OCSP returns `good`, the next base CRL
  omits the serial, and the next **delta CRL** carries a `removeFromCRL` (reason
  8) entry so relying parties holding an older base CRL (one that still lists the
  hold) drop the serial from their running revocation set.
- **Release is guarded** — only a certificate that is *on hold* can be released.
  A certificate that was permanently revoked (`keyCompromise`, etc.) cannot be
  released; the request is refused (HTTP 409 / gRPC `FAILED_PRECONDITION`). This
  is a safety invariant: a withdrawn credential is never silently resurrected.

Audit events `cert.suspend` and `cert.release` record every transition.

## 7. Publish revocation status

### CRL

Generate a signed CRL covering all recorded revocations for a CA. CRLs carry
monotonic RFC 5280 CRL numbers and are signed on the HSM.

```bash
# PEM to stdout, or a file
secsy-ca -config config.yaml gen-crl -ca "Issuing CA" -out issuing.crl.pem

# DER (what most relying parties expect at a distribution point)
secsy-ca -config config.yaml gen-crl -ca "Issuing CA" -der -out issuing.crl
```

A **public, unauthenticated** endpoint serves the CRL for relying parties. The
complete CRL is served from a published store and re-signed on the HSM only when
stale, so it stays a consistent pair with the delta CRL that references it:

```
GET /api/ca/{id}/crl        # complete (base) CRL, DER-encoded
```

```bash
curl -sk https://localhost:8443/api/ca/{ca_id}/crl -o issuing.crl
openssl crl -inform DER -in issuing.crl -noout -text
```

Verify a certificate against a CRL:

```bash
cat tls.crt issuing-ca.crt > chain.pem
openssl verify -crl_check -CRLfile issuing.crl.pem -CAfile chain.pem tls.crt
```

### Delta CRLs and CRL partitioning (RFC 5280)

For high-volume CAs, secsy-pki supports **delta CRLs** (small, frequently
refreshed CRLs listing only recent changes) and **partitioned/sharded CRLs**
(splitting revocations across N smaller CRLs). Both are configured under `crl:`
and served from public endpoints, all HSM-signed:

```yaml
crl:
  shards: 4                    # 0/1 = a single complete CRL; N>=2 = N partitions
  base_url: "https://pki.example.com"  # origin for CDP/IDP/Freshest-CRL URLs
                               # (falls back to acme.base_url when unset)
  delta_interval_minutes: 60   # how long a delta CRL is served before re-signing
  base_validity_hours: 168     # base CRL validity window (default 7 days)
```

**Endpoints** (all public, `?format=pem` for PEM):

```
GET /api/ca/{id}/crl                          # complete base CRL
GET /api/ca/{id}/crl/delta                    # delta for the complete scope
GET /api/ca/{id}/crl/partition/{shard}        # a partition's base CRL
GET /api/ca/{id}/crl/partition/{shard}/delta  # a partition's delta CRL
```

- **Delta CRLs** carry the critical **Delta CRL Indicator** (2.5.29.27)
  referencing the base CRL's number and list only certificates revoked since that
  base was cut. The base CRL advertises where to fetch its delta via the
  non-critical **Freshest CRL** extension (2.5.29.46). A relying party unions
  base + delta:

  ```bash
  cat base.crl.pem delta.crl.pem > crls.pem
  openssl verify -crl_check -use_deltas -extended_crl \
    -CRLfile crls.pem -CAfile chain.pem tls.crt
  ```

- **Partitioning** deterministically maps each certificate to a shard by hashing
  its serial (`sha256(serial) mod shards`). When `shards >= 2` and a `base_url`
  is set, each issued certificate is stamped with the **CRLDistributionPoints**
  URL of *its* shard, and that shard's CRL carries a matching **Issuing
  Distribution Point** (2.5.29.28), so a verifier fetches only the one small CRL
  relevant to the certificate in hand. A revoked serial always appears in exactly
  one shard.

Each scope keeps its own monotonic CRL-number sequence shared by its base and
delta CRLs (RFC 5280 §5.2.3). The `gen-crl` CLI mirrors the endpoints with
`-delta` and `-shard N` flags.

### OCSP

A **public, unauthenticated** OCSP responder answers status queries. Responses
are signed on the HSM (RSA/ECDSA issuers only — Ed25519 CAs cannot produce OCSP
responses, a limitation of the OCSP signature algorithms).

```
POST /api/ca/{id}/ocsp          # DER OCSP request in the body (standard)
GET  /api/ca/{id}/ocsp/{req}    # base64-encoded request in the path
```

Query with OpenSSL (POST is used automatically):

```bash
openssl ocsp -issuer issuing-ca.crt -cert tls.crt \
  -url https://localhost:8443/api/ca/{ca_id}/ocsp \
  -resp_text -no_nonce
```

Responses are `good`, `revoked` (with reason and time), or `unknown` for serials
this CA never issued, and are cacheable for up to 24 h. Non-signable requests are
answered with the correct RFC 6960 status: `malformed` (unparseable request),
`unauthorized` (unknown CA / not authoritative), or `tryLater` (the signing
backend is transiently unavailable).

#### Nonce (RFC 8954)

When a request carries an `id-pkix-ocsp-nonce` extension, the responder echoes it
in the signed response's `responseExtensions`, binding the response to that
request and defeating replay of a pre-captured response. Nonce-bearing requests
**bypass the response cache** and are signed freshly. Nonces must be 1–32 octets;
an out-of-range nonce is answered `malformed`. Nonce echoing is on by default
(`server.ocsp.nonce_enabled`), with a short validity window
(`server.ocsp.nonce_max_age_seconds`, default 60 s).

#### HTTP caching (RFC 5019)

A signed OCSP response is valid until its `nextUpdate`, so the responder emits the
[RFC 5019](https://www.rfc-editor.org/rfc/rfc5019) Lightweight-Profile caching
headers on the **GET** form so CDNs and clients can cache and revalidate it,
keeping the HSM off the public hot path (complementing pre-signing / static
publishing):

- `Cache-Control: public, max-age=<n>, no-transform` and `Expires`, derived from
  `nextUpdate` and bounded to a sane maximum (24 h for OCSP).
- `Last-Modified` from `thisUpdate`, and a strong `ETag` over the response bytes.
- Conditional requests are honored: `If-None-Match` / `If-Modified-Since` return
  **304 Not Modified** with no body.

A **nonce-bearing response is never cacheable** — it is bound to a single request
(RFC 8954) and is returned with `Cache-Control: no-store` and no validators, on
both the GET and POST forms.

The CRL and delta-CRL handlers apply the same semantics: `Cache-Control`/`Expires`
from the CRL `nextUpdate` (bounded to the base-CRL validity), `Last-Modified` from
`thisUpdate`, a strong `ETag` folding in the CRL number, and 304 conditional
handling — so a base CRL can be cached for its full validity while short-lived
deltas surface new revocations quickly.

#### Delegated responder certificate

Instead of signing OCSP responses with the CA key directly, the responder can use
a short-lived, HSM-backed **delegated OCSP-signing certificate** carrying the
`id-kp-OCSPSigning` EKU and the `id-pkix-ocsp-nocheck` extension (RFC 6960
§4.2.2.2). The delegated key is generated once per CA on the provider and reused;
the certificate is re-issued by the CA key as it nears expiry and is embedded in
each response so relying parties can build the `issuer → responder → response`
chain. Enable with `server.ocsp.delegated: true`
(`delegated_validity_hours`, `delegated_key_type`).

```yaml
server:
  ocsp:
    nonce_enabled: true
    nonce_max_age_seconds: 60
    delegated: true
    delegated_validity_hours: 168   # 7 days
    delegated_key_type: ecdsa-sha2-nistp256
    staple_ca_id: ""                # CA that issued the server's own TLS cert
```

#### TLS OCSP stapling

When `server.ocsp.staple_ca_id` names the CA that issued the server's own TLS
certificate, the server produces an HSM-signed OCSP staple for that certificate
and serves it in the TLS handshake (RFC 6066 `certificate_status`), refreshing it
at half the response validity. Clients then get revocation status without a
separate responder round-trip. `Manager.OCSPStapleForCertificate` is also
callable directly for custom TLS listeners.

### Pointing relying parties at these endpoints

When a `crl.base_url` (or `acme.base_url`) is configured, issued leaf
certificates are stamped with a **CRLDistributionPoints** URL — the per-shard CRL
when partitioning is enabled, otherwise the complete-CRL URL — so verifiers can
discover the CRL automatically. The issuance layer does not currently embed AIA
(OCSP) URLs, so configure the OCSP responder URL (`/api/ca/{id}/ocsp`) explicitly
in your TLS terminator, browser policy, or `openssl` invocation as shown above.
With no base URL configured, no CDP is stamped and both URLs must be configured
explicitly.

## Operational notes

- **Regenerate CRLs on a schedule.** A base CRL is valid for ~7 days and a delta
  for ~1 hour; the public endpoints re-sign on demand once the served copy nears
  expiry, so simply polling them keeps CRLs fresh. For offline distribution run
  `gen-crl` (add `-delta` / `-shard N`) well before expiry. Always revoke *and*
  refresh the CRL.
- **Deltas reference the published base.** A delta CRL's Delta CRL Indicator
  points at the base CRL served by the endpoints, not at ad-hoc `gen-crl` output.
  Publish the endpoint base CRL (or its stored copy) to the distribution point so
  relying parties can reconstruct base + delta.
- **Serials are per-issuer and gap-free**, allocated atomically; serial 1 is
  reserved for a root's self-signed certificate.
- **Everything is audited.** Issue, renew, and revoke append to the
  tamper-evident [event log](../security/rbac-and-audit.md#2-tamper-evident-audit-logging).
- **Key type choice.** Prefer ECDSA (P-256/P-384) for issuing CAs so OCSP works;
  reserve Ed25519 for CAs that will only ever publish CRLs.

## See also

- [Issuance preview (dry-run)](../issuance/preview.md) — validate a would-be
  issuance through every pre-issuance gate without signing (`issue -dry-run`,
  `POST …/certificates:preview`)
- [Chain / path validation](chain-validation.md) — validate a supplied leaf
  against a CA's trust anchors, with live revocation (`validate-cert`,
  `POST /api/validate`)
- [PKCS#12 (.p12/.pfx) export](pkcs12.md) — server-side-keygen key delivery
- [HSM / PKCS#11 configuration](../hsm/configuration.md)
- [RBAC, audit logging & config](../security/rbac-and-audit.md)
- [Production HSM migration](../hsm/production-migration.md)
- Full HTTP reference: [`../README.md`](../../README.md#api), the OpenAPI 3.1 spec
  served at `GET /openapi.json` (rendered at `/docs`), and the generated Go
  client SDK in [`../server/pkg/client`](../../server/pkg/client).
