# Post-Quantum & Hybrid Certificates (ML-DSA / catalyst)

secsy-pki can issue certificates signed with the NIST post-quantum signature
algorithm **ML-DSA (FIPS 204**, formerly CRYSTALS-Dilithium), either as
**pure-PQC** certificates (ML-DSA subject key + ML-DSA signature) or as
**hybrid "catalyst"** certificates that carry a classical (ECDSA/RSA) signature
*and* a parallel ML-DSA signature so both classical and PQC-aware relying parties
are satisfied by one certificate.

This is a defence against "harvest-now, decrypt/forge-later": long-lived roots
and intermediates can start carrying a quantum-resistant signature today while
remaining compatible with the installed base of classical verifiers.

> **Read the [Interoperability & trust-store caveats](#interoperability--trust-store-caveats)
> before deploying.** PQC in X.509 is still standards-track; interop is limited.

## Contents

- [Algorithms](#algorithms)
- [Modes](#modes)
- [Key provider & the SoftHSM fallback](#key-provider--the-softhsm-fallback)
- [Profiles](#profiles)
- [Creating PQC / hybrid CAs](#creating-pqc--hybrid-cas)
- [Issuing leaves](#issuing-leaves)
- [Verification](#verification)
- [Interoperability & trust-store caveats](#interoperability--trust-store-caveats)
- [Design & wire format](#design--wire-format)
- [Limitations](#limitations)

## Algorithms

| Key type    | FIPS 204 set | NIST OID                      | Security category |
|-------------|--------------|-------------------------------|-------------------|
| `ml-dsa-44` | ML-DSA-44    | `2.16.840.1.101.3.4.3.17`     | 2                 |
| `ml-dsa-65` | ML-DSA-65    | `2.16.840.1.101.3.4.3.18`     | 3 (default)       |
| `ml-dsa-87` | ML-DSA-87    | `2.16.840.1.101.3.4.3.19`     | 5                 |

ML-DSA is implemented via [Cloudflare CIRCL](https://github.com/cloudflare/circl).
The ML-DSA signatures produced here are the deterministic, empty-context "pure"
mode (the message signed is the DER `TBSCertificate` / `CertificationRequestInfo`).

## Modes

- **classical** (default) — ordinary ECDSA/RSA/Ed25519. Unchanged behaviour.
- **pqc** — the subject key and the issuer signature are both ML-DSA. The
  certificate is post-quantum end to end but is only *understood* by PQC-aware
  verifiers.
- **hybrid** — the primary key and signature are classical (so any verifier
  accepts the certificate), and a parallel ML-DSA public key and signature are
  carried in the ITU-T X.509 alternative-signature extensions
  (`subjectAltPublicKeyInfo` `2.5.29.72`, `altSignatureAlgorithm` `2.5.29.73`,
  `altSignatureValue` `2.5.29.74`). PQC-aware verifiers additionally check the
  ML-DSA dimension; classical verifiers ignore the (non-critical) extensions.

## Key provider & the SoftHSM fallback

ML-DSA keys are generated and used through the same
[`keyprovider`](../server/internal/keyprovider) abstraction as classical keys, but:

- **The software key provider is required for PQC keys.** Neither SoftHSM nor
  common PKCS#11 HSMs expose an ML-DSA mechanism yet. The PKCS#11 backend fails
  closed with an actionable error if asked to generate an ML-DSA key
  (`... not supported by the PKCS#11 backend ... use the software key provider`),
  rather than emitting an opaque Cryptoki error.
- ML-DSA private keys are stored in the software keystore as PKCS#8 (an internal
  at-rest encoding; it round-trips within this system and is not claimed to
  interoperate with other PKCS#8 ML-DSA encoders).
- ML-DSA keys have **no OpenSSH representation**, so `KeyInfo.SSHPublicKey` is
  empty for them and the CA record stores the DER `SubjectPublicKeyInfo` (PEM) as
  its public key instead.

A future HSM with native ML-DSA support would slot in behind the same interface
with no change to the CA/issuance layer, since ML-DSA keys are ordinary
`crypto.Signer` values here.

For a **hybrid CA** the provider holds *two* keys: the classical primary key
under the CA label, and the ML-DSA alternative key under `<label>-altpqc`. A
hybrid CA therefore requires the software provider for its alternative key.

## Profiles

Two built-in profiles demonstrate the feature; add your own via the profile
configuration ([`certificate-authority.md`](certificate-authority.md)):

| Profile         | Algorithm | Subject key                    | Signature(s)                        |
|-----------------|-----------|--------------------------------|-------------------------------------|
| `pqc-server`    | pqc       | ML-DSA-65                      | ML-DSA-65                           |
| `hybrid-server` | hybrid    | classical + ML-DSA-65 (alt)    | classical primary + ML-DSA-65 alt   |

Relevant profile fields:

```json
{
  "name": "pqc-server",
  "algorithm": "pqc",          // "" (classical) | "pqc" | "hybrid"
  "pqc_key_type": "ml-dsa-65", // ML-DSA param set; subject key (pqc) or alt key (hybrid)
  "key_usages": ["digitalSignature"],
  "ext_key_usages": ["serverAuth"]
}
```

Certificate Transparency is **not** applied to PQC/hybrid issuance (these are not
submitted to public CT logs). The pre-issuance lint gate still runs.

## Creating PQC / hybrid CAs

Use `secsy-ca` with a software-provider config:

```bash
# Pure post-quantum root (ML-DSA-65 key, ML-DSA self-signature)
secsy-ca init-root \
  -label pqc-root -algorithm pqc -key-type ml-dsa-65 \
  -cn "Example PQC Root CA"

# Pure post-quantum intermediate (must chain under a PQC parent)
secsy-ca issue-intermediate \
  -parent pqc-root -label pqc-int -algorithm pqc -key-type ml-dsa-65 \
  -cn "Example PQC Issuing CA"

# Hybrid root: classical primary (ECDSA P-256) + ML-DSA-65 alternative
secsy-ca init-root \
  -label hybrid-root -algorithm hybrid \
  -key-type ecdsa-p256 -alt-key-type ml-dsa-65 \
  -cn "Example Hybrid Root CA"
```

A `pqc` intermediate must be issued under a `pqc` parent; a `hybrid` intermediate
under a `hybrid` parent (the parent must hold the matching ML-DSA key). Mismatches
are rejected with a clear error.

## Issuing leaves

Issuance is CSR-driven, as for classical certificates, but the CSR must carry the
right key material for the profile:

- **pqc profile** → a pure-PQC PKCS#10 request (ML-DSA subject key, ML-DSA
  self-signature). Build one with `pqc.CreatePQCCSR`.
- **hybrid profile** → a hybrid PKCS#10 request: a classical request that also
  carries the ML-DSA alternative public key and an ML-DSA proof-of-possession in
  the alternative-signature extensions. Build one with `pqc.CreateHybridCSR`.

Then issue against a matching CA and profile via the CLI/API/`ca.Manager`
exactly as for classical certificates, selecting `-profile pqc-server` /
`hybrid-server`.

> Renew-in-place is **not** supported for PQC/hybrid certificates (crypto/x509
> cannot recover an ML-DSA subject key from the prior certificate). Re-issue from
> a fresh CSR instead.

## Verification

- **Pure PQC** chains: `pqc.VerifyChain` verifies each ML-DSA (or classical) link
  and the self-signed root, checking issuer/subject linkage, validity windows and
  CA basic constraints.
- **Hybrid** chains: `pqc.VerifyHybridChain` verifies *both* dimensions — the
  classical primary signatures (via the standard library) and the ML-DSA
  alternative signatures (each link against the alt key in its issuer's
  `subjectAltPublicKeyInfo`). A hybrid chain therefore also validates with any
  ordinary classical verifier (e.g. `openssl verify`, Go's `x509.Verify`) that
  ignores the unknown non-critical alt extensions.

## Interoperability & trust-store caveats

**This is the important part.** PQC in X.509 is standards-track and support is
uneven. Treat pure-PQC certificates as usable only between endpoints you control.

- **No public trust.** No public/browser root program will trust an ML-DSA or
  hybrid CA. These are for **internal / private PKI** (mTLS between your own
  services, device fleets, code/document signing you verify yourself).
- **OpenSSL.** OpenSSL **3.0–3.4 cannot verify pure-PQC certificates** — they
  parse the structure and recognise the ML-DSA OID as the signature algorithm but
  cannot load the ML-DSA public key ("Unable to load Public Key"). Native ML-DSA
  arrived in **OpenSSL 3.5**. Verified locally against OpenSSL 3.0.13.
- **Hybrid is backward compatible.** A hybrid certificate is a *valid classical
  certificate*: OpenSSL 3.0.13 and Go both parse and `verify` it as an ordinary
  ECDSA/RSA certificate, treating `2.5.29.72/73/74` as unknown non-critical
  extensions. This is the recommended migration path — deploy hybrid now, and
  PQC-aware verifiers gain quantum resistance automatically.
- **Go standard library** does not (as of the toolchain this project builds with)
  implement `crypto/mldsa`, so `crypto/x509` leaves the ML-DSA `PublicKey` as
  `nil` and reports `UnknownSignatureAlgorithm`. secsy-pki fills this gap for the
  fields it must encode/verify (SPKI, PKCS#8, the signing envelope) and verifies
  ML-DSA itself via CIRCL. When Go ships `crypto/mldsa`, these certificates should
  parse natively.
- **The alternative-signature pre-image** is the DER `TBSCertificate` with the
  `altSignatureValue` extension removed (it must be the final extension). This
  follows ITU-T X.509 (2019) / `draft-ietf-lamps-x509-alt`. Independent
  implementations must reconstruct the pre-image the same way to verify the alt
  signature.
- **Composite (single-key) signatures** per `draft-ietf-lamps-pq-composite-sigs`
  are *not* implemented; "hybrid" here means the parallel alternative-signature
  ("catalyst") construction, which keeps the classical certificate byte-for-byte
  standard.

## Design & wire format

secsy-pki keeps the PQC layer a thin, auditable shim rather than a second X.509
encoder (see [`internal/pqc`](../server/internal/pqc)):

- Everything the Go standard library *can* encode (names, validity, the standard
  v3 extensions, CSR attributes) is produced by `crypto/x509` and reused verbatim.
- Only the fields the standard library will not emit are hand-assembled with
  `golang.org/x/crypto/cryptobyte`: the ML-DSA `SubjectPublicKeyInfo` and PKCS#8
  wrappers, the signature `AlgorithmIdentifier`, and the signing envelope.
- **Pure PQC** certificates/CSRs: built by substituting the SPKI and signature
  algorithm into a crypto/x509-produced skeleton, then signing the DER
  `TBSCertificate` / `CertificationRequestInfo` with ML-DSA.
- **Hybrid** certificates/CSRs: built in two crypto/x509 passes — pass A carries
  `subjectAltPublicKeyInfo` + `altSignatureAlgorithm` and its TBS is the ML-DSA
  pre-image; pass B appends `altSignatureValue`. The classical signature covers
  the full TBS (including `altSignatureValue`); the ML-DSA signature covers pass
  A's TBS. Verifiers reconstruct pass A by stripping the final extension.

## Limitations

- Software key provider only for ML-DSA (no HSM ML-DSA mechanism available).
- No composite (single combined key) certificates; catalyst hybrid only.
- No renew-in-place for PQC/hybrid (re-issue from a fresh CSR).
- CT and public-trust BR linting are not meaningful for PQC/hybrid and are not
  applied (CT) / run in internal mode (lint).
- ML-KEM (FIPS 203, key encapsulation) is present in the Go toolchain but is a
  KEM, not a signature scheme, and is out of scope for certificate signing.
