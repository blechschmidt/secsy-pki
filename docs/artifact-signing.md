# Artifact / Code Signing (CMS + RFC 3161)

secsy-pki includes a general-purpose **release-artifact signing service**: it
produces detached **CMS/PKCS#7 (RFC 5652) signatures** over files (or file
digests) with **HSM-backed code-signing keys**, using signer certificates the
PKI itself issues under the lint-gated `code-signing` profile
(EKU `id-kp-codeSigning`). A signature can optionally embed an
**RFC 3161 timestamp countersignature** from the built-in
[Time-Stamp Authority](timestamping.md), so it stays verifiable long after the
signing certificate expires.

Typical uses: signing release tarballs, container/image manifests, firmware,
installers, SBOMs — anything a downstream consumer should be able to verify
against your PKI's trust anchors with standard tooling (`openssl cms`,
`openssl ts`).

## How it works

```
caller ── artifact (or its digest) ──▶ POST /api/sign  /  secsy-ca sign
                                            │
                            resolve signer (key label + certificate)
                                            │
                            build CMS authenticated attributes
                            (contentType, messageDigest, signingTime,
                             ESS signing-certificate-v2)
                                            │
                            sign the attribute set on the HSM
                                            │           (optional)
                                            ├─▶ hash(signature) ─▶ in-process TSA
                                            │   ◀─ TimeStampToken (HSM-signed) ──
                                            │   embed as id-aa-timeStampToken
                                            │   unsigned attribute (RFC 3161 A.)
                                            ▼
caller ◀── detached SignedData (DER / PEM "PKCS7") ──
```

Key properties:

- **Detached, always.** The artifact is never embedded; the signature is a
  small sidecar file (`.p7s`) and the artifact's distribution channel is
  unchanged.
- **Keys never leave the provider.** One `crypto.Signer` operation per
  signature on the code-signing key, plus one on the TSA key when
  countersigning. Works with PKCS#11 HSMs (SoftHSM in tests), cloud KMS, or
  the software keystore; the backend is selectable per role via
  `key_provider.roles.signing`.
- **Digest input for large artifacts.** Callers may submit just the artifact's
  hash (in the signer's digest algorithm). The CMS `messageDigest` attribute is
  the hash, so the resulting signature is byte-for-byte the same as one made
  from the full content — and verifies against the full artifact. Use this for
  multi-GB images (the API caps request bodies at 8 MiB).
- **ECDSA and RSA signers.** The CMS layer emits `ecdsa-with-SHA*` or RSA
  PKCS#1 v1.5 signatures; both verify with `openssl cms -verify`.
- **Timestamps extend verifiability.** A countersigned artifact's chain is
  validated *at the token's genTime*; an unstamped one at the wall clock. After
  the signer certificate expires, only the countersigned signature keeps
  verifying — the reason release pipelines pair code signing with a TSA.

## Provisioning a signing key + certificate

```console
# 1. A CA must exist (see certificate-authority.md), e.g.:
secsy-ca init-root -cn "Example Root" -label "Example Root"

# 2. Generate the signing key on the provider and issue its certificate
#    through the ordinary issuance path (code-signing profile, pre-issuance
#    lint gate included):
secsy-ca signing-key -ca "Example Root" -label codesign-release \
    -cn "Release Signing" -o "Example Corp" -chain -out /etc/secsy/codesign.pem
```

`signing-key` flags: `-key-type` (`ecdsa-p256` default; `ecdsa-p384`,
`rsa-2048`, `rsa-4096`), `-validity-days` (0 = profile default, 3 years),
`-profile` (default `code-signing`; a custom profile must still carry the
`codeSigning` EKU — the command refuses otherwise), `-chain` (append the issuer
chain to the PEM). Re-running with the same `-label` **reuses the existing
key** and reissues the certificate — certificate renewal without key rotation.
The certificate is recorded in the store like any other leaf, so it shows up in
inventory, expiry monitoring, and can be revoked.

For the countersignature, provision the TSA once as well
(`secsy-ca tsa-key`, see [timestamping.md](timestamping.md)).

## Configuration

```yaml
signing:
  enabled: true
  signers:
    - name: release                                # callers reference this name
      key_label: codesign-release                  # provider label from signing-key
      certificate_file: /etc/secsy/codesign.pem    # written by signing-key
      ca_label: "Example Root"                     # or ca_id; completes the chain
                                                   # when the file holds only the leaf
      digest: sha256                               # sha256 | sha384 | sha512
      timestamp: true                              # RFC 3161 countersign by default
                                                   # (requires tsa.enabled)
      tenant: ""                                   # owning tenant ("" = default)
```

Multiple signers may be configured (e.g. `release`, `firmware`, `nightly`),
each with its own key, certificate, tenant, and timestamp default. The signing
keys may live on a dedicated backend via `key_provider.roles.signing`.

## HTTP API

All endpoints require operator authentication; see the OpenAPI spec
(`/api/docs`) for full schemas.

| Endpoint | Capability | Notes |
|---|---|---|
| `POST /api/sign` | `artifact:sign` (**signer** role) within the signer's tenant | body: `{"signer":"release","artifact":"<base64>"}` or `{"signer":"release","digest":"<hex>"}`, optional `"timestamp":true/false` override. Returns the DER signature (base64 + PEM), the signer certificate, digest, and timestamp details. |
| `POST /api/sign/verify` | any assigned role | body: `{"signature":"<base64-or-PEM>","artifact":"<base64>"}` (or `"digest"`), optional `"ca_id"`, `"require_timestamp"`. Trust anchors are the caller's tenants' CAs. Returns HTTP 200 with `valid:true/false` + reason. |
| `GET /api/sign/signers` | any assigned role | configured signers, filtered to the caller's tenants. |

The dedicated **`signer` RBAC role** grants `artifact:sign` and log reading —
and nothing else. It is deliberately separate from `issuer`: a CI credential
that signs builds cannot mint certificates, and vice versa. Assign it
platform-wide or per tenant exactly like the other roles (`rbac:` /
`tenants[].rbac:` / OIDC claim mappings).

`POST /api/sign` is **rate-limited and HSM-concurrency-guarded** (the
`/api/sign` prefix class of the Task 25 middleware, keyed per credential), so a
runaway pipeline cannot starve ACME issuance or OCSP signing. Every operation
is **audited**: `artifact.sign` records the signer, artifact digest, and
whether a countersignature was embedded; `artifact.verify` records verification
verdicts.

## CLI

```console
# Sign a file (writes release.tar.gz.p7s; -timestamp auto|yes|no, -format der|pem)
secsy-ca sign -signer release -in release.tar.gz

# Sign by digest (the artifact itself never leaves the build host)
secsy-ca sign -signer release -digest "$(sha256sum huge.iso | cut -d' ' -f1)" -out huge.iso.p7s

# Verify (no HSM needed — works anywhere with the store or a CA PEM)
secsy-ca verify-signature -sig release.tar.gz.p7s -in release.tar.gz -require-timestamp
secsy-ca verify-signature -sig huge.iso.p7s -digest "<hex>" -ca-file root.pem
```

`sign` uses the local provider directly (the pipeline-host counterpart of
`POST /api/sign`); `verify-signature` needs only public keys and exits non-zero
on any failure.

## Verifying with standard tools

```console
# Signature over the artifact (chain to your root; -purpose any because
# openssl's default S/MIME purpose check rejects codeSigning certificates):
openssl cms -verify -binary -inform DER -in release.tar.gz.p7s \
    -content release.tar.gz -CAfile root.pem -purpose any -out /dev/null

# The embedded RFC 3161 token covers the CMS signature *value*: extract the
# id-aa-timeStampToken attribute (secsy-ca verify-signature prints its details)
# and check it with openssl ts:
openssl ts -verify -digest <hex sha256 of the SignerInfo signature> \
    -token_in -in token.der -CAfile root.pem -untrusted tsa.pem
```

Both interop paths run in CI against SoftHSM
(`server/internal/signing/signing_softhsm_test.go`).

## Verification semantics

`secsy-ca verify-signature` / `POST /api/sign/verify` / `signing.Verify` are
fail-closed and check, in order:

1. the CMS signature cryptographically covers the supplied content (or digest);
2. the signer certificate has the code-signing shape (codeSigning EKU,
   digitalSignature KU, not a CA) and, when the ESS signing-certificate-v2
   attribute is present, that it binds this exact certificate;
3. an embedded timestamp token, if any, itself verifies: token signature,
   imprint over the signature value, TSA EKU, TSA chain to the same trust
   anchors at genTime, genTime not in the future;
4. the signer chain builds to the trust anchors **at the validation time** —
   the token's genTime when countersigned, else now — for the codeSigning EKU.

Revocation is *not* consulted during signature verification; check the signer
certificate against the PKI's CRL/OCSP when your policy requires it (the
certificate is in the issued-certificates inventory, so `secsy-ca revoke`
works on it like any leaf).

## Key-ceremony notes for signing keys

Code-signing keys sit between CA keys and TLS leaves in sensitivity: a stolen
signing key lets an attacker ship trusted malware until the certificate is
revoked and consumers notice. Recommended handling (see
[key-ceremony.md](key-ceremony.md) for the general HSM procedures):

- **Generate on-device, under ceremony.** Run `secsy-ca signing-key` against
  the production token so the key is born non-extractable
  (`CKA_EXTRACTABLE=false`, enforced by the provider). For high-value release
  keys, run it inside the same M-of-N witnessed procedure as an intermediate
  CA (`secsy-ca ceremony` records operator confirmations in the audit chain);
  the audit events (`cert.issue` with `requested_by="secsy-ca signing-key"`)
  are your provisioning record.
- **One key per purpose/pipeline.** Separate `release` from `nightly` from
  `firmware` signers; scope each to its tenant. Compromise or retirement of
  one does not invalidate the others, and per-signer metrics/audit make usage
  anomalies visible.
- **Separation of duties.** Grant pipelines the `signer` role only. Key
  provisioning stays with CA operators (`signing-key` needs direct
  provider/store access); nobody needs the raw key, ever.
- **Backup = replicate, don't export.** Signing keys follow the same rule as
  CA keys: never leave the device in software form. Use the HSM's native
  cloning/wrap-under-KEK mechanism to a backup token (see
  [hsm-migration.md](hsm-migration.md)), or accept key loss as a re-provision
  event — unlike a CA key, a signing key is cheap to replace (issue a new
  certificate, old signatures stay valid thanks to their timestamps).
- **Rotate by certificate, roll the key on schedule.** Re-running
  `signing-key` with the same label renews the certificate on the same key;
  use a fresh label (and a config update) to rotate the key itself — e.g.
  yearly, or immediately on any suspicion of compromise.
- **Revocation plan.** If a signing key is compromised: `secsy-ca revoke` the
  certificate (CRL/OCSP pick it up), remove the signer from `signing.signers`,
  and re-sign still-supported artifacts with a new key. Timestamped signatures
  made *before* the compromise window remain provably older than the
  revocation — one more reason `timestamp: true` should be the default for
  release signers.
- **Always countersign releases.** Signing certificates are deliberately
  shorter-lived than the artifacts they cover; the RFC 3161 token is what
  keeps a 3-year-old release verifiable. Keep `tsa.enabled` on and leave
  `timestamp: true` on release signers.

## Metrics

| Metric | Labels | Meaning |
|---|---|---|
| `secsy_artifact_signatures_total` | `signer`, `result` | signing operations (`success`/`denied`/`error`) — each success is one HSM signature |
| `secsy_artifact_timestamps_total` | `result` | RFC 3161 countersignature sub-step outcomes |
| `secsy_artifact_verifications_total` | `result` | verification verdicts (`valid`/`invalid`/`error`) |

Rate-limit visibility comes from the shared `secsy_ratelimit_*` /
`secsy_hsm_guard_*` families under the `artifact_sign` class.

## Limitations

- The countersigning TSA is the in-process one; pointing at an external
  RFC 3161 service is not supported (run secsy-pki's TSA next to the signer
  instead).
- CMS verification here does not consult CRL/OCSP (see above).
- The TSA key must be RSA (see [timestamping.md](timestamping.md)); the
  code-signing keys themselves may be ECDSA or RSA.
