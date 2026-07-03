# PKCS#12 (.p12/.pfx) bundle export

PKCS#12 export is the **server-side-keygen key-delivery path** for end-entity
certificates. In one operation secsy-pki generates a subject keypair, issues a
leaf under a profile, and returns a **password-protected PKCS#12 bundle**
containing the subject private key, the leaf certificate, and the full issuer
chain (leaf → intermediate(s) → root).

It exists because some subscribers legitimately need their own private key
delivered to them — the two primary consumers are:

- **S/MIME** ([S/MIME e-mail protection](smime.md)): mail clients import a
  `.p12` to sign and decrypt mail. The encryption key in particular is often
  generated centrally and escrowed so encrypted mail is recoverable.
- **Device / MDM enrollment** ([SCEP & EST](enrollment.md)): an MDM or
  provisioning system that cannot run a CSR-based enrollment can be handed a
  ready-to-install `.p12`.

## The invariant: the CA key never leaves the HSM

Only the **freshly-generated subject key** is ever placed in the bundle. The CA
signing key lives in the HSM and is used solely as a signer during issuance — it
is never marshaled or exported. Concretely, export:

1. generates the subject keypair **in software, in memory**;
2. builds and self-signs a PKCS#10 CSR from it (proof of possession);
3. issues the leaf through the normal CA manager path (HSM-signed, with the same
   lint / CAA / CT / name-constraint gates as any other issuance);
4. packs the subject key + leaf + issuer chain into the PKCS#12;
5. scrubs the in-memory plaintext copy of the subject key.

This is exercised end-to-end against SoftHSM in the acceptance test
(`server/internal/pkcs12`): the CA key is on the token, the bundle decrypts to
the subject key alone, and the produced `.p12` round-trips through both the
go-pkcs12 decoder and `openssl pkcs12 -info`.

## Key types and encoders

**Key types:** `ecdsa` (default, P-256; `-key-bits 384|521` for P-384/P-521) or
`rsa` (default 3072-bit; minimum 2048). Ed25519 is intentionally unsupported —
PKCS#12 with Ed25519 keys interoperates poorly across common consumers.

**Encoders** (the PKCS#12 encryption/MAC algorithms):

| Encoder      | Algorithms                                       | Reads in |
|--------------|--------------------------------------------------|----------|
| `modern` (default) | PBES2 (PBKDF2-HMAC-SHA-256 + AES-256-CBC), HMAC-SHA-256 MAC | OpenSSL 1.1.1+, Java 12+, Windows Server 2019+ |
| `legacy`     | 3DES (certs + key), HMAC-SHA-1 MAC               | Very old software (OpenSSL `-descert` parity) |
| `legacyrc2`  | RC2 (certs) + 3DES (key), HMAC-SHA-1 MAC         | Oldest software; needs OpenSSL `-legacy` provider to read |

Prefer `modern` and a high-entropy password (e.g. `openssl rand -hex 16`);
PKCS#12 confidentiality rests entirely on the password. Under
[FIPS mode](fips.md) the legacy encoders (3DES/RC2 + SHA-1) are refused and only
`modern` is permitted.

## CLI: `secsy-ca export-p12`

```sh
# S/MIME certificate for a mailbox, ECDSA key, modern encoding.
SECSY_P12_PASSWORD='…' \
secsy-ca export-p12 \
  -ca corp-issuing-ca \
  -profile smime \
  -cn "Jane Doe" -email jane@example.com \
  -key-type ecdsa \
  -out jane.p12

# TLS client certificate for a device, RSA-3072, with SANs.
SECSY_P12_PASSWORD='…' \
secsy-ca export-p12 \
  -ca device-ca -profile client \
  -cn device-01 -dns device-01.example.com -ip 10.0.0.5 \
  -key-type rsa -key-bits 3072 \
  -out device-01.p12
```

The password is sourced (in priority order) from `-password-file`, `-password`,
or `$SECSY_P12_PASSWORD`; sourcing it outside the `-password` flag keeps it off
the process argument list. Run `secsy-ca export-p12 -h` for all flags (subject
DN, `-dns`/`-ip`/`-email`/`-uri` SANs, `-encoder`, `-validity-days`, `-escrow`).

Verify a bundle with OpenSSL:

```sh
openssl pkcs12 -info -in jane.p12 -passin pass:… -nodes
```

## REST API

`POST /api/ca/{id}/pkcs12` — gated by the same issue capability as `POST
/api/ca/{id}/issue` (a platform/tenant issuer role, or a per-CA
`SIGN_CERTIFICATE` grant), tenant-scoped to the CA's tenant.

```jsonc
// request
{
  "profile": "smime",
  "common_name": "Jane Doe",
  "emails": ["jane@example.com"],
  "key_type": "ecdsa",
  "encoder": "modern",
  "password": "…",
  "escrow": false
}
// 201 response (abridged)
{
  "serial": "…",
  "profile": "smime",
  "not_after": "2027-07-03T00:00:00Z",
  "pkcs12": "<base64 DER PKCS#12>",
  "chain": "-----BEGIN CERTIFICATE----- … (leaf + issuers)",
  "key_type": "ecdsa-p256",
  "encoder": "modern"
}
```

The private key is delivered only inside the password-protected `pkcs12` field;
it is never returned in the clear.

## Console

The **PKCS#12** page in the [operator console](web-console.md) drives the same
endpoint: pick a CA and profile, set the subject/SANs, key type, encoder and
password, optionally tick *Escrow subject key*, and the browser downloads the
`.p12` directly.

## Optional key escrow (M-of-N)

With `-escrow` (CLI) or `"escrow": true` (API) the freshly-generated subject key
is additionally escrowed under the configured
[M-of-N recovery policy](password-encryption.md#key-escrow-and-recovery-m-of-n-dual-control):
its data key is Shamir-split across the recovery agents and wrapped to
their keys, and the escrow envelope is returned (API) or written to
`-escrow-out` (CLI) for you to store in a break-glass vault. This is the
recommended posture for S/MIME **encryption** keys, so that encrypted mail
remains recoverable if the subscriber loses their key.

Escrow requires a secret KEK (`secret.kek_label`) and `secret.escrow` to be
configured. The escrow envelope is sealed under the CA tenant's KEK and bound to
the certificate serial via the encryption context `pkcs12/<serial>`; recovery is
the usual dual-control ceremony:

```sh
secsy-secret recover -in jane.escrow.json -context "pkcs12/<serial>" \
  -agent alice -agent bob   # a quorum of recovery agents
```

The recovered plaintext is the subject private key in PKCS#8 DER.

## Auditing & metrics

- **Audit:** every export appends a `cert.pkcs12` event (actor, CA, serial,
  profile/key/encoder detail). When escrow is used a paired `secret.escrow`
  event records the break-glass wrapping — an unauditable key-escrow operation is
  refused.
- **Metrics:** exports increment `secsy_certificates_total{operation="pkcs12"}`
  with the usual `success` / `error` / `denied` result label.

## See also

- [Certificate authority](certificate-authority.md) — issuance, profiles, CRL/OCSP
- [S/MIME e-mail protection](smime.md) — the primary consumer of `.p12` delivery
- [Password / secret encryption](password-encryption.md) — the escrow/recovery layer
