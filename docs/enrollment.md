# SCEP & EST: device / MDM certificate enrollment

secsy-pki includes **SCEP** ([RFC 8894](https://www.rfc-editor.org/rfc/rfc8894))
and **EST** ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)) enrollment
servers so network devices, MDM platforms (Jamf, Intune/NDES clients, Kandji,
…), routers/firewalls, and IoT fleets can auto-enroll for certificates. Like the
[ACME server](acme.md), every certificate is signed by an **HSM-backed CA**
through the same [`ca.Manager`](certificate-authority.md) used by the REST API
and CLI, reuses the shared **certificate profiles** and **revocation store**, and
writes every enrollment to the [tamper-evident audit log](rbac-and-audit.md).

Both protocols authenticate clients with their own schemes (a SCEP challenge
password, or EST HTTP Basic / TLS client certificate) rather than OIDC, so they
mount **outside** the OIDC auth middleware — exactly like ACME.

- [1. When to use SCEP vs EST](#1-when-to-use-scep-vs-est)
- [2. SCEP (RFC 8894)](#2-scep-rfc-8894)
- [3. EST (RFC 7030)](#3-est-rfc-7030)
- [4. Auditing](#4-auditing)
- [5. Security notes](#5-security-notes)
- [6. Endpoint reference](#6-endpoint-reference)

## 1. When to use SCEP vs EST

| | SCEP | EST |
|---|---|---|
| RFC | 8894 | 7030 |
| Transport | HTTP (message-level PKCS#7) | HTTPS (TLS) |
| Client auth | challenge password in the CSR | HTTP Basic or TLS client cert |
| CA key type | **must be RSA** (enveloped-data key transport) | any (RSA / ECDSA / Ed25519) |
| Message format | PKCS#7 `pkiMessage` wrapping PKCS#10 | base64 PKCS#10 → PKCS#7 |
| Typical clients | NDES-style MDM, routers, firewalls, IoT | modern MDM, `libest`, `est` CLI, IoT |

Both can be enabled at once, pointing at the same or different issuing CAs.

## 2. SCEP (RFC 8894)

SCEP is **off by default**. The issuing CA **must be an RSA CA**, because the
SCEP `pkiMessage` encrypts the PKCS#10 request in a PKCS#7 `EnvelopedData` that
uses RSA key transport. Create an RSA CA with `secsy-ca` first (see the
[CA guide](certificate-authority.md)), then enable SCEP:

```yaml
scep:
  enabled: true
  ca_label: "Secsy Issuing RSA CA"   # must be RSA; use ca_label OR ca_id
  profile: "client"                  # default profile for enrolled devices
  require_challenge: true            # require a matching grant challenge (default)
  allow_renewal: true               # allow challenge-free renewal (see below)
  grants:
    - name: "fleet-a"                # operator-provisioned enrollment credential
      challenge: "a-long-shared-secret"
      profile: "client"             # optional per-grant profile override
```

The endpoint is served at `/scep` (and the classic `/scep/pkiclient.exe`
alias). Point a client's SCEP URL at `https://pki.example.com/scep`.

### Challenge-password authorization (tied to RBAC)

SCEP has no transport authentication, so authorization rides on the **challenge
password** carried in the PKCS#10 `challengePassword` attribute. Each entry under
`scep.grants` is an **operator-provisioned enrollment credential** — the SCEP
analogue of an RBAC grant: an administrator issues a challenge secret to a device
fleet, and every certificate enrolled with it is constrained to the grant's
profile and attributed to the grant (`scep:<grant-name>`) in the audit log.
Provisioning grants is an admin (RBAC) operation. With `require_challenge: true`
(the default) an initial enrollment with no matching grant is rejected with a
SCEP `FAILURE`/`badRequest` response.

### The RA encryption key

The CA's signing key is deliberately **sign-only** (least privilege — see the
[security review](security-review.md)), so it cannot decrypt the enveloped
request. On first use the SCEP server therefore auto-provisions a dedicated,
**decrypt-capable RSA "RA" key on the HSM** (label `<ca-label>-scep-enc`) and
issues an RA certificate for it, signed by the CA. `GetCACert` returns **both**
the CA certificate and this RA certificate; clients encrypt requests to the RA
certificate (identified by its `keyEncipherment` usage) and trust issued
certificates through the CA. The RA private key never leaves the HSM — the
content-encryption-key unwrap runs on the device.

### Renewal

With `allow_renewal: true`, a client may renew by signing its `PKCSReq` with a
**currently-valid certificate this CA previously issued** (verified against the
CA and the revocation store) instead of presenting a challenge password. This is
the standard SCEP renewal flow and is attributed as `scep-renew:<cn>`.

### Client example (`sscep`)

```sh
# Fetch the CA + RA certificates (writes ca.crt-0, ca.crt-1)
sscep getca   -u http://pki.example.com/scep -c ca.crt

# Enrol (challenge goes in the CSR's challengePassword attribute)
sscep enroll  -u http://pki.example.com/scep \
              -c ca.crt-0 -e ca.crt-1 \
              -k device.key -r device.csr -l device.crt
```

## 3. EST (RFC 7030)

EST runs over TLS and is **off by default**. The issuing CA may be any key type.

```yaml
est:
  enabled: true
  ca_label: "Secsy Issuing CA"
  profile: "client"
  allow_tls_client_reenroll: true   # accept a prior client cert for (re)enroll
  enable_server_keygen: true        # enable POST /serverkeygen
  server_keygen_key_type: "rsa-2048"
  users:                            # HTTP Basic enrollment credentials
    device01:
      password: "a-long-shared-secret"
      profile: "client"
```

Endpoints are served under `/.well-known/est`:

- `GET  /.well-known/est/cacerts` — CA chain as a base64 certs-only PKCS#7 (unauthenticated).
- `POST /.well-known/est/simpleenroll` — initial enrollment (Basic auth or TLS client cert).
- `POST /.well-known/est/simplereenroll` — renewal.
- `POST /.well-known/est/serverkeygen` — server-side key generation (optional).

### Authentication

- **HTTP Basic** — credentials from `est.users`; the EST analogue of an RBAC
  grant, each constrained to a profile and audited as `est:<user>`.
- **TLS client certificate** — with `allow_tls_client_reenroll: true`, a client
  presenting a currently-valid, non-revoked certificate this CA issued is
  authorized without Basic credentials (audited as `est-cert:<cn>`). This is the
  recommended way to renew.

### /serverkeygen

`POST /serverkeygen` returns a `multipart/mixed` body containing a freshly
generated private key (PKCS#8) and the issued certificate (certs-only PKCS#7).
The private key is generated **in memory on the server** and returned to the
client — it is intentionally *not* an HSM key, since the private key must leave
the server. The CA signature is still produced on the HSM.

### Client example (`curl`)

```sh
# CA certs
curl -s https://pki.example.com/.well-known/est/cacerts | base64 -d | \
  openssl pkcs7 -inform DER -print_certs

# Enrol a CSR (base64 PKCS#10 in, base64 PKCS#7 out)
openssl req -new -newkey rsa:2048 -nodes -keyout device.key \
  -subj "/CN=device01" -out device.csr
curl -s -u device01:a-long-shared-secret \
  -H "Content-Type: application/pkcs10" \
  --data-binary @<(openssl req -in device.csr -outform DER | base64) \
  https://pki.example.com/.well-known/est/simpleenroll | \
  base64 -d | openssl pkcs7 -inform DER -print_certs
```

## 4. Auditing

Every enrollment appends an entry to the hash-chained
[audit log](rbac-and-audit.md) with the protocol-specific actor and action:

| Action | Emitted for |
|---|---|
| `scep.get_ca_cert` | SCEP GetCACert |
| `scep.enroll` / `scep.renew` | SCEP PKIOperation (initial / renewal) |
| `est.cacerts` | EST cacerts |
| `est.simpleenroll` / `est.simplereenroll` | EST enrollment / renewal |
| `est.serverkeygen` | EST server-side key generation |

Denied enrollments are recorded with result `denied`; issuance failures with
`error`.

## 5. Security notes

- **CA keys stay sign-only.** SCEP's decrypt requirement is served by a
  dedicated RA key, never the CA key; both live on the HSM and never leave it.
- **PKCS#1 v1.5.** SCEP mandates RSA PKCS#1 v1.5 key transport, which is subject
  to Bleichenbacher-style padding oracles. The server returns a single opaque
  error on any envelope-decryption failure and never signals the failure stage.
- **Challenge secrets / Basic passwords** are shared secrets — provision long,
  random values, scope them per fleet, and rotate them. Prefer EST with TLS
  client-certificate reenrollment for renewals so a long-lived secret is not
  repeatedly transmitted.
- **Serve over TLS.** EST requires it; run SCEP behind TLS too (the server
  refuses cleartext unless `SECSY_ALLOW_INSECURE_HTTP=1`).
- **Profiles constrain issuance.** Both protocols issue only under the
  configured profile(s), so a compromised enrollment credential cannot mint, for
  example, a CA or code-signing certificate.

## 6. Endpoint reference

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/scep?operation=GetCACaps` | none | Advertised capabilities |
| GET | `/scep?operation=GetCACert` | none | CA + RA certificates (PKCS#7) |
| GET/POST | `/scep?operation=PKIOperation` | challenge / issued cert | Enroll / renew (`pkiMessage`) |
| GET | `/.well-known/est/cacerts` | none | CA chain (PKCS#7) |
| POST | `/.well-known/est/simpleenroll` | Basic / client cert | Initial enrollment |
| POST | `/.well-known/est/simplereenroll` | Basic / client cert | Renewal |
| POST | `/.well-known/est/serverkeygen` | Basic / client cert | Server-side key generation |
