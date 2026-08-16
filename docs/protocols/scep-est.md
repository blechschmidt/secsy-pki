# SCEP, EST & CMP: device / MDM certificate enrollment

secsy-pki includes **SCEP** ([RFC 8894](https://www.rfc-editor.org/rfc/rfc8894)),
**EST** ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)), and
**Lightweight CMP** ([RFC 9483](https://www.rfc-editor.org/rfc/rfc9483),
profiling RFC 4210/4211) enrollment servers so network devices, MDM platforms
(Jamf, Intune/NDES clients, Kandji, …), routers/firewalls, industrial and IoT
fleets can auto-enroll for certificates. Like the [ACME server](acme.md), every
certificate is signed by an **HSM-backed CA** through the same
[`ca.Manager`](../ca/overview.md) used by the REST API and CLI, reuses the
shared **certificate profiles** and **revocation store**, and writes every
enrollment to the [tamper-evident audit log](../security/rbac-and-audit.md).

All three protocols authenticate clients with their own schemes (a SCEP challenge
password; EST HTTP Basic / TLS client certificate; CMP shared-secret MAC or a
signature from a previously-issued certificate) rather than OIDC, so they mount
**outside** the OIDC auth middleware — exactly like ACME.

For **zero-touch** onboarding of factory-fresh IoT/network devices — where there
is no shared secret to provision at all — layer **BRSKI**
([RFC 8995](https://www.rfc-editor.org/rfc/rfc8995)) on top of EST: the device's
manufacturer birth certificate (IDevID) and a manufacturer-signed voucher stand
in for the enrollment credential, and the operational certificate is then issued
over EST `simpleenroll`. See **[BRSKI: zero-touch device onboarding](brski.md)**.

- [1. When to use SCEP vs EST](#1-when-to-use-scep-vs-est)
- [2. SCEP (RFC 8894)](#2-scep-rfc-8894)
- [3. EST (RFC 7030)](#3-est-rfc-7030)
- [3.5. CMP (RFC 9483)](#35-cmp-rfc-9483)
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
[CA guide](../ca/overview.md)), then enable SCEP:

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
[security review](../security/security-review.md)), so it cannot decrypt the enveloped
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
- `GET  /.well-known/est/csrattrs` — advertised CSR attributes for the profile (unauthenticated; RFC 7030 §4.5).
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

### CSR Attributes (`/csrattrs`)

`GET /csrattrs` advertises, as a base64 DER `SEQUENCE OF AttrOrOID` (media type
`application/csrattrs`), the attributes/extensions a client should include in its
CSR for the configured profile ([RFC 7030 §4.5](https://www.rfc-editor.org/rfc/rfc7030#section-4.5)).
Like `/cacerts` it is unauthenticated; a request that presents valid EST
credentials is tailored to that credential's profile. A profile with nothing to
advertise returns `204 No Content`.

By default the advertisement is **derived from the resolved issuance profile**:

- the expected **subject public-key algorithm** — `rsaEncryption` for profiles
  that need key transport (`keyEncipherment`), an `id-ecPublicKey` hint carrying a
  named curve otherwise, or the ML-DSA parameter-set OID for post-quantum profiles;
- the **keyUsage** and **extended key usage** the CA will stamp on the leaf;
- for attestation-required profiles, the private **attestation-statement OID** so a
  client knows it must carry hardware key-attestation evidence in the CSR.

An operator can instead declare an explicit list per profile, advertised verbatim
in place of the derived set:

```yaml
est:
  enabled: true
  ca_label: "Secsy Issuing CA"
  profile: "client"
  csr_attr_ec_curve: "p-384"          # curve advertised with the derived EC hint (p-256 default)
  csr_attrs:                          # explicit per-profile override
    client:
      - oid: "1.2.840.113549.1.9.7"                 # require a challengePassword (bare OID)
      - oid: "1.2.840.10045.2.1"                    # id-ecPublicKey ...
        values: ["1.3.132.0.34"]                    # ... on secp384r1 (P-384)
```

Only profiles listed under `csr_attrs` are overridden; every other profile keeps
the derived set. Override values are OBJECT IDENTIFIERs, which covers what EST
clients act on (curves, key-purpose OIDs, signature algorithms, extension types).

The bundled [`secsy-agent`](agent.md) EST client fetches `/csrattrs` before
enrolling and honors it: with `key_type: "auto"` it adopts the advertised key
type/curve, and it reflects the advertised extended key usages into its CSR.

```sh
curl -s https://pki.example.com/.well-known/est/csrattrs | \
  base64 -d | openssl asn1parse -inform DER
```

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

## 3.5. CMP (RFC 9483)

**Lightweight CMP** serves enterprise clients and infrastructure that speak the
Certificate Management Protocol rather than ACME/EST. A single `POST /cmp`
endpoint (media type `application/pkixcmp`) handles the core PKIMessage flows:

| Flow | Body | Purpose | Client auth |
|---|---|---|---|
| **ir** | initialization request | first certificate for a device | shared-secret MAC (PBM) |
| **cr** | certification request | additional certificate | shared-secret MAC (PBM) |
| **kur** | key update request | rekey / renew an existing certificate | **signature** by the certificate being updated |
| **rr** | revocation request | revoke a certificate | signature (self-revocation) or operator MAC |

**Message protection.** Every request and response is integrity-protected. Two
schemes are supported:

- **PasswordBasedMac (PBM, RFC 4210 §5.1.3.1)** — a shared secret keyed by a
  *reference value* (the `senderKID`). Configure secrets under `cmp.secrets`; the
  MAC-protected response mirrors the same secret. Used for `ir`/`cr`.
- **Signature-based** — the message is signed by a certificate this CA
  previously issued (verified as currently-valid and non-revoked). Used for
  `kur` and self-service `rr`; the CA signs the response with its HSM key and
  returns its chain in `extraCerts`.

Each `ir`/`cr`/`kur` request also carries a **proof of possession**: a signature
over the CRMF `CertRequest` with the requested private key, which the server
verifies before issuing.

Enable it in `config.yaml`:

```yaml
cmp:
  enabled: true
  ca_label: "Secsy Issuing CA"
  profile: client
  allow_signature_protection: true    # kur + signature-based rr
  secrets:
    - reference: device-fleet-1
      secret: "long-random-shared-secret"
      profile: client
```

### Client example (`secsy-ca cmp`)

The bundled client performs an `ir` enrollment end-to-end (generate key → build
MAC-protected request → POST → parse the issued certificate):

```bash
secsy-ca cmp \
  -url https://pki.example.com:8443/cmp \
  -reference device-fleet-1 \
  -secret 'long-random-shared-secret' \
  -cn device-01.example.com \
  -dns device-01.example.com \
  -cert-out device-01.crt -key-out device-01.key
```

`-operation cr` sends a certification request instead; `-insecure` skips TLS
verification for lab testing. Any standards-compliant CMP client (e.g. OpenSSL
`openssl cmp`, `libcmp`) interoperates with the same endpoint.

## 4. Auditing

Every enrollment appends an entry to the hash-chained
[audit log](../security/rbac-and-audit.md) with the protocol-specific actor and action:

| Action | Emitted for |
|---|---|
| `scep.get_ca_cert` | SCEP GetCACert |
| `scep.enroll` / `scep.renew` | SCEP PKIOperation (initial / renewal) |
| `est.cacerts` | EST cacerts |
| `est.csrattrs` | EST CSR-attributes advertisement |
| `est.simpleenroll` / `est.simplereenroll` | EST enrollment / renewal |
| `est.serverkeygen` | EST server-side key generation |
| `cmp.ir` / `cmp.cr` | CMP initialization / certification request |
| `cmp.kur` | CMP key-update (rekey) request |
| `cmp.rr` | CMP revocation request |
| `cert.brski` | BRSKI voucher exchange / status telemetry (see [brski.md](brski.md)) |
| `cert.acme_email` | ACME RFC 8823 email-reply-00 challenge dispatched / validated (§7) |

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
- **Profiles constrain issuance.** All three protocols issue only under the
  configured profile(s), so a compromised enrollment credential cannot mint, for
  example, a CA or code-signing certificate.
- **CMP protection is verified fail-closed.** A PBM MAC is checked in constant
  time and a signature-protected `kur`/`rr` is accepted only from a currently
  valid, non-revoked certificate this CA issued; any protection or
  proof-of-possession failure is reported as a CMP error (`badMessageCheck` /
  `badPOP`) and never issues. Signature-based self-revocation may revoke only the
  signer's own certificate.

## 6. Endpoint reference

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/scep?operation=GetCACaps` | none | Advertised capabilities |
| GET | `/scep?operation=GetCACert` | none | CA + RA certificates (PKCS#7) |
| GET/POST | `/scep?operation=PKIOperation` | challenge / issued cert | Enroll / renew (`pkiMessage`) |
| GET | `/.well-known/est/cacerts` | none | CA chain (PKCS#7) |
| GET | `/.well-known/est/csrattrs` | none | Advertised CSR attributes (RFC 7030 §4.5) |
| POST | `/.well-known/est/simpleenroll` | Basic / client cert | Initial enrollment |
| POST | `/.well-known/est/simplereenroll` | Basic / client cert | Renewal |
| POST | `/.well-known/est/serverkeygen` | Basic / client cert | Server-side key generation |
| POST | `/cmp` | shared-secret MAC / signature | CMP ir / cr / kur / rr (`application/pkixcmp`) |
| POST | `/.well-known/brski/requestvoucher` | IDevID-signed request | BRSKI voucher exchange ([brski.md](brski.md)) |
| POST | `/.well-known/brski/voucher_status` | (over pledge TLS) | BRSKI voucher telemetry |
| POST | `/.well-known/brski/enrollstatus` | (over pledge TLS) | BRSKI enrollment telemetry |

## 7. ACME S/MIME certificates (RFC 8823 email-reply-00)

The ACME server ([acme.md](acme.md)) can also issue **S/MIME
(id-kp-emailProtection) certificates** for `email`-type identifiers, using the
RFC 8823 `email-reply-00` challenge. This lets standard tooling obtain
end-user/mailbox certificates through the same account → order → challenge →
finalize flow as a TLS certificate — no separate protocol. Issuance is gated by
the S/MIME profile family ([smime.md](../certificates/smime.md)): every leaf runs through
`applySMIMEPolicy` (mailbox normalization + domain allowlists) and the S/MIME
Baseline-Requirements lint rules before any HSM signature.

### How the challenge proves mailbox control

The token is split in two. The server generates **token-part-1** and delivers it
only in the challenge email's Subject; **token-part-2** is the ordinary challenge
`token`, delivered over HTTPS. The client concatenates them, computes the RFC
8555 key authorization over the full token, and replies to the challenge email
with `base64url(SHA-256(keyAuthorization))` between
`-----BEGIN ACME RESPONSE-----` / `-----END ACME RESPONSE-----` markers. Because
answering requires **both** halves (one from the mailbox, one from the account),
a correct reply proves the account holder controls the mailbox.

```
client ──newOrder{identifier: email}──▶ server
client ◀─authz: email-reply-00 (token = token-part-2, from = <sender>)─ server
client ──respond (POST challenge)──────▶ server ──signed challenge email
                                                   (Subject: "ACME: <token-part-1>")──▶ mailbox
mailbox ──reply: -----BEGIN ACME RESPONSE----- <digest> -----END…──▶ IMAP inbox
server (leader-elected poller) reads inbox, threads reply→challenge, validates digest
client ──finalize(CSR with rfc822Name SAN)──▶ server ──▶ S/MIME certificate
```

The challenge email is signed with **DKIM** (RFC 6376, rsa-sha256,
relaxed/relaxed) when a signing key is configured, so the receiving side can
verify authenticity (RFC 8823 §5). The reply MUST come **from the mailbox being
validated** — a reply whose `From` does not match is rejected.

### Enabling it

The challenge is offered **only when both an outbound SMTP sink and an inbound
IMAP poller are configured** — without the inbox the server cannot observe
replies, so `email` identifiers are rejected as unsupported. Add an `email`
block under `acme`:

```yaml
acme:
  enabled: true
  ca_label: "Issuing CA"
  email:
    enabled: true
    from: "acme-challenge@pki.example.com"   # sender; echoed as the challenge "from"
    profile: "smime"                          # S/MIME issuance profile (must have an smime config)
    poll_interval_seconds: 30                 # inbox poll cadence (leader-elected)
    subject_prefix: "ACME:"                   # challenge Subject label (default)
    smtp:
      host: smtp.example.com
      port: 587
      username: acme-challenge@pki.example.com
      password: "${SMTP_PASSWORD}"
      tls_mode: starttls                      # starttls (default) | implicit | none
    imap:
      host: imap.example.com
      port: 993
      username: acme-challenge@pki.example.com
      password: "${IMAP_PASSWORD}"
      mailbox: INBOX
      tls_mode: implicit                      # implicit (default, IMAPS) | starttls | none
      max_messages: 64                        # cap per poll cycle
    dkim:                                     # optional but recommended (RFC 8823 §5)
      domain: pki.example.com
      selector: acme                          # publish the pubkey at acme._domainkey.pki.example.com
      private_key_file: /etc/secsy/dkim-acme.key   # PEM RSA key (or private_key_pem inline)
```

Notes:

- **`profile`** must resolve to an S/MIME profile (`smime`, `smime-sign`,
  `smime-encrypt`, or a custom profile carrying an `smime:` block); startup fails
  otherwise. An email order is always issued under that profile even if a client
  selects a different [ACME profile](acme.md) — unless that selection is itself
  an S/MIME profile, in which case it is honored. Use an **RSA** subject key for
  the dual-use `smime` profile (its `keyEncipherment` usage is invalid for an EC
  key; use `smime-sign` for EC signing-only certificates).
- **Order composition.** An email order must contain only `email` identifiers
  (no mixing with `dns`/`ip`); the finalize CSR must carry exactly those
  addresses as `rfc822Name` SANs.
- **Multi-replica.** The inbound poller runs as a leader-elected job, so a single
  replica consumes the shared IMAP mailbox; SMTP dispatch happens inline on
  whichever replica handles the client's challenge response.
- **DKIM** is optional; when omitted, challenge emails are unsigned (RFC 8823
  recommends signing). The key may be supplied by file or inline PEM
  (`private_key_pem`).

### Client example (`acme.sh` / lego are TLS-focused)

Most general-purpose ACME clients do not yet drive `email-reply-00`; the flow is
typically used by S/MIME-aware MUAs and certificate agents. The exchange is
plain RFC 8555 with one added step — replying to the challenge email — so a thin
client is:

1. `newOrder` with `identifiers: [{ "type": "email", "value": "user@example.com" }]`.
2. Read the `email-reply-00` challenge's `token` (token-part-2) and `from`.
3. `POST` the challenge to trigger the challenge email; extract token-part-1 from
   its Subject (`ACME: <token-part-1>`).
4. `keyAuth = (token-part-1 ‖ token-part-2) + "." + base64url(thumbprint)`.
5. Reply to the challenge email with
   `-----BEGIN ACME RESPONSE-----\n<base64url(SHA-256(keyAuth))>\n-----END ACME RESPONSE-----`.
6. Poll the order to `ready`, then `finalize` with a CSR whose only SAN is the
   `rfc822Name` for the mailbox; download the S/MIME certificate.

### Security notes

- **Fail-closed.** A missing/incorrect response, a reply from the wrong mailbox,
  or an email dispatch failure marks the challenge (and the order) invalid.
- **S/MIME gate always runs.** Email orders are pinned to an S/MIME profile at
  both `newOrder` and `finalize`, so `applySMIMEPolicy` and the SMBR lint rules
  cannot be bypassed by profile selection.
- **Token entropy.** Both token halves carry ≥128 bits; token-part-1 never
  appears over HTTPS and token-part-2 never appears in email, so neither channel
  alone yields the key authorization.
- **Dedicated mailbox.** Point the IMAP poller at a mailbox used only for ACME
  challenges; processed replies are marked `\Seen` so they are not reprocessed.
