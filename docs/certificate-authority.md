# Certificate authority: setup, issuance, revocation, CRL & OCSP

This guide covers the full X.509 lifecycle on the HSM-backed CA: standing up
root and intermediate CAs, issuing end-entity certificates from CSRs, renewing
and revoking them, and serving revocation status via CRL and OCSP.

Every signing operation — root/intermediate certs, leaf certs, CRLs, and OCSP
responses — is performed **on the key provider** (the HSM). CA private keys are
generated on the device and never leave it. Configure the provider first:
[HSM / PKCS#11 configuration](hsm-configuration.md).

Two interfaces drive the CA:

- **`secsy-ca`** — an operator CLI that shares the server's config, database, and
  key provider. Best for bootstrapping and back-office tasks.
- **HTTP API** — for programmatic issuance by authenticated users, subject to
  [RBAC and per-CA permissions](rbac-and-audit.md).

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
> [HSM configuration](hsm-configuration.md#key-labels-must-be-unique).

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
[`CASubject`](../server/internal/models/models.go) JSON body.

## 3. Certificate profiles

A **profile** fixes the key usages, extended key usages, and validity bounds of
an issued leaf, so callers don't hand-craft them. Requested validity is clamped
to the profile maximum *and* to the issuer's `notAfter`.

| Profile | Key usages | Ext key usages | Default / max validity |
|---------|-----------|----------------|------------------------|
| `server` | digitalSignature, keyEncipherment | serverAuth | 397 d / 397 d |
| `client` | digitalSignature | clientAuth | 365 d / 730 d |
| `server-client` | digitalSignature, keyEncipherment | serverAuth, clientAuth | 397 d / 397 d |
| `code-signing` | digitalSignature | codeSigning | 3 y / 3 y |
| `email` | digitalSignature, keyEncipherment | emailProtection | 365 d / 730 d |

```bash
secsy-ca profiles            # or: GET /api/profiles
```

Operators can add custom profiles or override a built-in (by reusing its name)
via the `profiles:` config block — see
[RBAC & config](rbac-and-audit.md#3-centralized-configuration).

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
`certificateHold`, `privilegeWithdrawn`, `aaCompromise`, `removeFromCRL`.
Re-revoking an already-revoked serial updates its reason rather than failing.

**API:** `POST /api/ca/{id}/revoke` with `{"serial":"...","reason":"keyCompromise"}`.
List revocations: `GET /api/ca/{id}/revoked`.

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

A **public, unauthenticated** endpoint serves the CRL freshly for relying
parties:

```
GET /api/ca/{id}/crl        # DER-encoded CRL
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
this CA never issued, and are cacheable for up to 24 h.

### Pointing relying parties at these endpoints

The issuance layer does **not** currently embed AIA / CRL-distribution-point
URLs into leaf certificates, so clients won't discover these endpoints
automatically. Configure verifiers explicitly — the CRL distribution URL
(`/api/ca/{id}/crl`) and OCSP responder URL (`/api/ca/{id}/ocsp`) — in your TLS
terminator, browser policy, or `openssl` invocation as shown above.

## Operational notes

- **Regenerate CRLs on a schedule.** A generated CRL is valid for ~7 days; run
  `gen-crl` (or fetch the public endpoint, which regenerates on demand) well
  before expiry. Always revoke *and* refresh the CRL.
- **Serials are per-issuer and gap-free**, allocated atomically; serial 1 is
  reserved for a root's self-signed certificate.
- **Everything is audited.** Issue, renew, and revoke append to the
  tamper-evident [event log](rbac-and-audit.md#2-tamper-evident-audit-logging).
- **Key type choice.** Prefer ECDSA (P-256/P-384) for issuing CAs so OCSP works;
  reserve Ed25519 for CAs that will only ever publish CRLs.

## See also

- [HSM / PKCS#11 configuration](hsm-configuration.md)
- [RBAC, audit logging & config](rbac-and-audit.md)
- [Production HSM migration](hsm-migration.md)
- Full HTTP reference: [`../README.md`](../README.md#api), the OpenAPI 3.1 spec
  served at `GET /openapi.json` (rendered at `/docs`), and the generated Go
  client SDK in [`../server/pkg/client`](../server/pkg/client).
