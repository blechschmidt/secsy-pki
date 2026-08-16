# HSM-backed secret encryption (envelope encryption)

`secsy-pki` can encrypt passwords and other small secrets under a key that lives
in a hardware security module (HSM). The private key material never leaves the
HSM; decrypting a secret requires access to the device.

## How it works — envelope encryption

Each secret is protected with the standard *envelope* pattern used by cloud KMS
systems:

1. A fresh 256-bit **data-encryption key (DEK)** is generated per message.
2. The plaintext is sealed with **AES-256-GCM** under the DEK.
3. The DEK is **wrapped** (encrypted) with a long-lived **key-encryption key
   (KEK)** — an RSA key whose private half is held by the HSM (PKCS#11) or the
   software keystore. Wrapping uses **RSA-OAEP** against the KEK *public* key and
   needs no HSM. Unwrapping asks the token to RSA-OAEP-decrypt the wrapped DEK
   via `C_Decrypt`, so the KEK private key never leaves the device.

The output is a versioned, self-describing JSON **envelope** carrying everything
needed to decrypt *except* the KEK private key and any caller-supplied
encryption context.

```
plaintext ──AES-256-GCM(DEK)──► ciphertext
   DEK    ──RSA-OAEP(KEK_pub)──► wrapped_dek     (unwrap runs on the HSM)
```

### Ciphertext format (version 1)

```json
{
  "version": 1,
  "provider": "pkcs11",
  "kek_label": "secsy-kek",
  "kek_uri": "pkcs11:token=...;object=secsy-kek;type=private",
  "wrap_alg": "RSA-OAEP-SHA256",
  "data_alg": "AES-256-GCM",
  "wrapped_dek": "<base64>",
  "nonce": "<base64>",
  "ciphertext": "<base64 ciphertext||GCM-tag>",
  "context_bound": false
}
```

The `version` field is checked on decrypt; unknown versions are rejected rather
than mis-parsed, so the format can evolve safely.

## Security properties

- **Confidentiality + integrity** of the plaintext come from AES-256-GCM.
- **Algorithm & metadata binding:** the header (version, both algorithm names,
  KEK label, and any caller context) is bound into the GCM additional
  authenticated data (AAD). An attacker cannot swap algorithms, repoint the
  record at a different KEK, or replay it under a different context without GCM
  detecting the change.
- **Encryption context** (optional, KMS-style): a caller-supplied byte string
  mixed into the AAD. It is *not* stored in the envelope and must be supplied
  verbatim to decrypt — useful for binding a ciphertext to, e.g., a tenant or
  field name.
- **OAEP only:** PKCS#1 v1.5 decryption is never used, avoiding the
  Bleichenbacher padding-oracle class of attacks. Decrypt failures return a
  single generic error so the API does not behave as an oracle.
- **Least-privilege KEK:** on a PKCS#11 token the KEK private key is generated
  with `CKA_DECRYPT`/`CKA_UNWRAP` only (not `CKA_SIGN`), marked sensitive and
  non-extractable.
- **Fresh DEK + nonce per message:** no key or nonce reuse across messages.

### A note on SoftHSM and SHA-1

SoftHSM 2.6.x supports RSA-OAEP **only with SHA-1**, while production HSMs
(YubiHSM) and the software backend support SHA-256. The service therefore
negotiates the strongest OAEP hash the KEK can actually unwrap with (SHA-256
first, SHA-1 fallback) and records the chosen algorithm (`wrap_alg`) in every
envelope, so old ciphertext stays decryptable. OAEP's security does not rely on
the collision resistance of its hash, so the SHA-1 fallback does not expose the
scheme to SHA-1 collision attacks — but prefer a SHA-256-capable HSM in
production.

## Post-quantum hybrid mode (ML-KEM-1024, harvest-now-decrypt-later resistance)

A future adversary with a large quantum computer can record ciphertext today and
decrypt it later once RSA is broken ("harvest now, decrypt later"). To resist
that for data at rest, an **optional hybrid mode** protects each envelope's data
key with **both** the classical HSM KEK wrap **and** an **ML-KEM-1024** (FIPS
203, `crypto/mlkem`) encapsulation, combined through a KDF so an attacker must
defeat **both** primitives:

```
ssC              = a fresh 256-bit classical shared secret
WrappedDEK (env) = RSA-OAEP(KEK_pub, ssC)            # HSM unwraps ssC
(ssPQ, kem_ct)   = ML-KEM-1024.Encapsulate()          # kem_ct stored in the PQC block
wk               = HKDF-SHA256(ssC ‖ ssPQ, info)      # 256-bit wrapping key
PQC.wrapped_dek  = AES-256-GCM(wk, DEK)               # the real DEK, sealed under wk
```

Recovering the DEK needs `ssC` (only the HSM can unwrap it) **and** `ssPQ` (only
the ML-KEM decapsulation key produces it). Breaking RSA alone yields `ssC` but
not `ssPQ`; breaking ML-KEM alone yields `ssPQ` but not `ssC`. A quantum
adversary who harvests an envelope and later breaks its RSA still faces
ML-KEM-1024 to obtain `ssPQ`.

- **HSM stays in the trust path.** The ML-KEM decapsulation key is stored only as
  a 64-byte seed **sealed under the classical HSM KEK** (RSA-OAEP), so
  decapsulating any envelope requires an on-token unwrap. The sealed key lives
  once in the key store, never copied into each ciphertext, so it is not part of
  a harvested envelope.
- **Threat-model boundary (honest).** Because that sealed decapsulation key is
  itself protected only by the classical KEK, the harvest-now-decrypt-later
  guarantee holds for a harvest of the **ciphertext (envelopes)**. An adversary
  who *also* exfiltrates the single sealed decapsulation-key blob from the key
  store and later breaks RSA degrades back to classical security. This is the
  necessary consequence of keeping a classical HSM in the trust path (no shipping
  HSM performs ML-KEM); the win is real for the common case where ciphertext is
  stored/distributed far more widely than the central key store. Restrict and
  separately protect the `pqc_hybrid_keys` material for the strongest posture.
- **Software ML-KEM, HSM RSA.** SoftHSM/PKCS#11 tokens have no ML-KEM mechanism,
  so (following the Task 29 ML-DSA precedent) the ML-KEM operations run in
  software while the classical KEK may still live in the HSM.
- **Versioned & backward compatible.** Hybrid envelopes are format **version 3**
  and carry a `pqc` block; classical **version 1/2** envelopes open unchanged.
  Disabling the flag never strands hybrid ciphertext — the material stays
  available for decryption.
- **Downgrade-resistant.** The `pqc` block is bound into the GCM AAD and the DEK
  is committed, so the post-quantum layer cannot be stripped, tampered with, or
  swapped to force a weaker classical-only decryption.
- **FIPS.** ML-KEM-1024 is a FIPS 203 algorithm inside the Go Cryptographic
  Module, so hybrid mode is FIPS-approvable (unlike CIRCL ML-DSA). Under
  `security.fips` the only added constraint is that the classical RSA-OAEP wrap
  use SHA-256 (no SoftHSM SHA-1 fallback).

Enable it with `secret.pqc_hybrid: true` and provision ML-KEM material per KEK
family (`init-kek` does this automatically when the flag is on; use `pqc-enable`
for an existing family). Rotating the classical KEK re-wraps only the classical
shared secret; run `pqc-reseal` to move the sealed ML-KEM key onto a newer KEK
version before retiring the version that seals it.

```console
# Enable on a fresh KEK (init-kek provisions the ML-KEM material too):
$ secsy-secret init-kek                       # with secret.pqc_hybrid: true

# Or enable on an existing KEK family:
$ secsy-secret pqc-enable

# Inspect the material (metadata only; works with the HSM absent):
$ secsy-secret pqc-info

# After a classical rotate-kek, re-seal the ML-KEM decap key under the new version:
$ secsy-secret pqc-reseal
```

> Scope: the hybrid layer covers the **secret envelope** (encrypt/decrypt, stored
> secrets, KEK rotation/rewrap, and PKCS#12 escrow envelopes). Scheduled encrypted
> backups (Task 89/94) keep using the classical KEK wrap and are unaffected.

## Configuration

```yaml
secret:
  kek_label: "secsy-kek"   # RSA KEK in the configured key_provider
  pqc_hybrid: false        # true → also protect data keys with ML-KEM-1024 (Task 137)
  transforms: []           # format-preserving encryption / tokenization templates (see below)
```

`SECSY_SECRET_KEK_LABEL` overrides the KEK label and `SECSY_SECRET_PQC_HYBRID=1`
the hybrid flag via the environment. When `kek_label` is empty, the
`/api/secret/*` endpoints are disabled.

## CLI — `secsy-secret`

```console
# One-time: create the KEK on the configured provider (HSM or software)
$ secsy-secret -config config.yaml init-kek            # defaults to rsa-4096
$ secsy-secret -config config.yaml init-kek -key-type rsa-2048

# Encrypt (stdin → envelope on stdout)
$ printf 'my-db-password' | secsy-secret encrypt -out secret.json

# Decrypt (envelope → plaintext)
$ secsy-secret decrypt -in secret.json

# With an encryption context (must match on decrypt)
$ printf 'pw' | secsy-secret encrypt -context 'tenant=acme' -out s.json
$ secsy-secret decrypt -in s.json -context 'tenant=acme'

# Inspect the configured KEK
$ secsy-secret kek-info

# Named HSM-backed signing keys (sign / verify over arbitrary data)
$ secsy-secret signing-key create -name app-signer -algorithm ecdsa-p256
$ secsy-secret signing-key list
$ printf 'data' | secsy-secret sign   -key app-signer -out sig.bin
$ printf 'data' | secsy-secret verify -key app-signer -sig-in sig.bin

# Format-preserving encryption / tokenization (FF1)
$ secsy-secret transform encode -template pan -value 4111-1111-1111-1111
$ secsy-secret transform decode -template pan -value 4923-8471-2210-6634
```

`-kek <label>` overrides the configured KEK on any subcommand.

## HTTP API

All endpoints require authentication and are only registered when a KEK is
configured.

| Method & path                  | Purpose                                       |
| ------------------------------ | --------------------------------------------- |
| `GET  /api/secret/info`        | KEK metadata (label, bits, algorithms)        |
| `POST /api/secret/encrypt`     | Encrypt a secret into an envelope             |
| `POST /api/secret/decrypt`     | Decrypt an envelope back to plaintext         |
| `POST /api/secret/datakey`     | Mint a data key (plaintext + KEK-wrapped)     |
| `POST /api/secret/hmac`        | Compute a keyed HMAC over caller data         |
| `POST /api/secret/hmac/verify` | Verify a keyed HMAC (constant time)           |
| `POST /api/secret/random`      | CSPRNG bytes (HSM RNG when available)         |
| `POST /api/secret/signing-keys` | Create a named HSM-backed signing key        |
| `GET  /api/secret/signing-keys` | List named signing keys                      |
| `GET  /api/secret/signing-keys/{name}` | Get a key's public view (SPKI PEM/DER) |
| `POST /api/secret/signing-keys/{name}/sign`   | Sign data (raw digital signature) |
| `POST /api/secret/signing-keys/{name}/verify` | Verify a signature               |
| `POST /api/secret/transform/encode` | Format-preserving encrypt / tokenize     |
| `POST /api/secret/transform/decode` | Invert a transform (detokenize)          |

`encrypt` request / response:

```jsonc
// POST /api/secret/encrypt
{ "plaintext": "<base64>", "context": "<base64, optional>" }
// 200 OK
{ "envelope": { /* version-1 envelope object */ } }
```

`decrypt` request / response:

```jsonc
// POST /api/secret/decrypt
{ "envelope": { /* envelope object */ }, "context": "<base64, optional>" }
// 200 OK
{ "plaintext": "<base64>" }
```

Plaintext is capped at 64 KiB — this feature is for passwords and small secrets,
not bulk data.

## Stateless crypto service (data key, keyed HMAC, random)

Alongside encrypt/decrypt, the secret layer offers a **non-storing** crypto
service — an "encryption as a service" surface modelled on HashiCorp Vault
Transit. Nothing the caller submits is persisted; the server holds only keys.
All three operations are exposed over REST, gRPC (`SecretService`), the
`secsy-secret` CLI, and the operator [console](../operations/web-console.md) — the **Crypto
service** panel on the Secrets page mints data keys (with an optional context/AAD
binding), generates and verifies keyed HMACs, and draws random bytes — and each
authorizes its own tenant-scoped capability (`secret:datakey`, `secret:hmac`,
`secret:random`), audits, and meters.

### Data keys — high-volume client-side envelope encryption

`datakey` mints a fresh key and returns it **both** in the clear (for immediate
client-side use) and **wrapped** under the family KEK. The wrapped form is an
ordinary envelope: decrypt it later to recover the key. No plaintext key is ever
stored, so a client can seal unlimited data locally and keep only the wrapped key
next to its ciphertext.

```jsonc
// POST /api/secret/datakey   { "bits": 256, "context": "<b64?>", "wrapped_only": false }
// 200 OK
{ "plaintext": "<b64 key>", "wrapped": { /* envelope */ }, "bits": 256,
  "kek_label": "secsy-kek", "kek_version": 1 }
// Recover later:  POST /api/secret/decrypt { "envelope": <wrapped> }  → the same key
```

`bits` is 128, 256 (default), or 512; `wrapped_only` omits the plaintext.

```console
$ secsy-secret datakey -bits 256 -json          # plaintext + wrapped
$ secsy-secret datakey -wrapped-only -out dk.json
```

### Keyed HMAC — authenticate caller data

`hmac` computes an HMAC-SHA256 over caller data with a **versioned MAC key**
derived (HKDF) from a random seed that is itself sealed under the KEK — so the
MAC key never exists at rest and recovering it is an on-HSM operation. The seed
is provisioned on first use and re-derived per request; the returned `version`
identifies it so `hmac/verify` is unambiguous. Rotating the KEK does not
invalidate existing tags (the sealed seed re-wraps like any DEK).

```jsonc
// POST /api/secret/hmac         { "data": "<b64>" }
// 200 OK                        { "hmac": "<b64>", "version": 1, "algorithm": "HMAC-SHA256" }
// POST /api/secret/hmac/verify  { "data": "<b64>", "hmac": "<b64>", "version": 1 }
// 200 OK                        { "valid": true, "version": 1 }
```

An unknown version or a mismatch is a `valid:false` **result**, not an error;
the comparison is constant-time.

```console
$ printf 'payload' | secsy-secret hmac                 # prints the base64 tag
$ printf 'payload' | secsy-secret hmac-verify -hmac <tag>   # exits non-zero on mismatch
```

### Random bytes — CSPRNG from the HSM

`random` returns cryptographically-strong bytes, drawn from the **HSM RNG**
(`C_GenerateRandom`) when the backend supports it, otherwise the OS CSPRNG. The
response reports which via `source` (`hsm` | `software`).

```jsonc
// POST /api/secret/random   { "bytes": 32, "format": "base64" }   // format: base64 | hex
// 200 OK                    { "random": "<encoded>", "format": "base64", "bytes": 32, "source": "hsm" }
```

```console
$ secsy-secret random -bytes 32 -format hex
```

`bytes` is capped at 1024. Data-key mints and HMAC operations count against the
tenant's daily secret-op quota; random draws do not (the byte cap bounds abuse).

## Digital signatures (named signing keys, sign / verify)

Beyond the symmetric primitives above, the secret layer offers **asymmetric
digital signatures** — the sign/verify counterpart to Vault Transit — over
**named, HSM-backed signing keys**. A signing key is a real key pair whose
private half is generated **non-extractable inside the key provider** (the HSM
under PKCS#11); only the public half is exported and persisted. Signatures are
raw, application-level signatures over arbitrary data — deliberately distinct
from the CMS/X.509 [artifact-signing service](../signing/artifact-signing.md), which
produces structured signature containers. Everything here is exposed over REST,
gRPC (`SecretService`: `CreateSigningKey`, `ListSigningKeys`, `GetSigningKey`,
`Sign`, `Verify`), and the `secsy-secret` CLI.

The **algorithm is fixed when the key is created** — the curve or RSA modulus
and, for RSA, the PSS-vs-PKCS#1-v1.5 scheme:

| Algorithm            | Key                | Scheme            |
| -------------------- | ------------------ | ----------------- |
| `ecdsa-p256`         | NIST P-256         | ECDSA             |
| `ecdsa-p384`         | NIST P-384         | ECDSA             |
| `ecdsa-p521`         | NIST P-521         | ECDSA             |
| `ed25519`            | Edwards25519       | Ed25519 (EdDSA)   |
| `rsa-pss-2048`       | RSA 2048           | RSASSA-PSS        |
| `rsa-pss-3072`       | RSA 3072           | RSASSA-PSS        |
| `rsa-pss-4096`       | RSA 4096           | RSASSA-PSS        |
| `rsa-pkcs1v15-2048`  | RSA 2048           | RSASSA-PKCS1-v1_5 |
| `rsa-pkcs1v15-3072`  | RSA 3072           | RSASSA-PKCS1-v1_5 |
| `rsa-pkcs1v15-4096`  | RSA 4096           | RSASSA-PKCS1-v1_5 |

For ECDSA and RSA the **message hash** (`sha256` | `sha384` | `sha512`) is chosen
per signing request (empty selects the algorithm's default), and a caller may
sign either a **message** (hashed server-side) or a pre-computed **digest**
(signed verbatim, its length checked against the hash). RSASSA-PSS uses a salt
length equal to the hash length — the interoperable choice, so signatures verify
against `openssl` and JOSE libraries as well as this service. **Ed25519** is pure
EdDSA: it signs the message directly (no selectable hash, no pre-hashed digest),
and a request that supplies either is rejected.

Two capabilities separate the privileged key-management from day-to-day use:
creating and listing keys needs **`secret:signing-key`** (admins by default);
sign, verify, and public-key export need **`secret:sign`** (travels with the
crypto-service grant). Key creation and each signature are audited; signing meters
the daily secret-op quota (verify and public-key export do not — they touch only
public material).

```jsonc
// POST /api/secret/signing-keys          { "name": "app-signer", "algorithm": "ecdsa-p256" }
// 201 Created  { "id": "...", "name": "app-signer", "algorithm": "ecdsa-p256",
//                "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...", "public_key_der": "<b64>" , ... }

// POST /api/secret/signing-keys/app-signer/sign     { "message": "<b64>", "hash": "sha256" }
// 200 OK   { "signature": "<b64>", "algorithm": "ecdsa-p256", "hash": "sha256", "key": "app-signer" }

// POST /api/secret/signing-keys/app-signer/verify   { "message": "<b64>", "signature": "<b64>" }
// 200 OK   { "valid": true, "algorithm": "ecdsa-p256" }
```

A signature that does not match is a `valid:false` **result**, not an error.
Verification uses only the stored public key, so it works even without the HSM —
exactly what an external verifier does.

```console
$ secsy-secret signing-key create -name app-signer -algorithm ecdsa-p256
$ secsy-secret signing-key public -name app-signer -out app-signer.pub.pem
$ printf 'release-v1.2.3' | secsy-secret sign   -key app-signer -out sig.bin
$ printf 'release-v1.2.3' | secsy-secret verify -key app-signer -sig-in sig.bin   # exit 0 on match

# The exported SPKI verifies with standard tooling — no secsy-pki needed:
$ printf 'release-v1.2.3' > msg.bin
$ openssl dgst -sha256 -verify app-signer.pub.pem -signature sig.bin msg.bin
Verified OK
```

For an RSASSA-PSS key, `openssl` needs the padding mode and salt length:

```console
$ openssl dgst -sha256 -verify k.pub.pem \
    -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 \
    -signature sig.bin msg.bin
```

In the [operator console](../operations/web-console.md), the **Secrets** page carries a **Digital
signatures** panel: it lists the tenant's signing keys, creates a new key (algorithm
picker), shows and downloads a key's SPKI public-key PEM, and signs / verifies a
text message against a named key — the same authorized, audited, quota-metered
operations as the CLI and API.

## Format-preserving encryption & tokenization (FF1)

Where envelope encryption turns a value into an opaque blob, a **transform**
enciphers structured data — a card PAN, an SSN, an account number — into another
value of the **same length over the same alphabet**, using NIST SP 800-38G **FF1**
(AES-based format-preserving encryption). Legacy systems that validate the format
of a field keep working on the protected value. A **deterministic** template
yields **stable ciphertext for equal plaintext**, so a protected column can still
be searched for equality and de-duplicated.

The FF1 key never exists in the clear at rest. A random seed is sealed as an
ordinary envelope under the family KEK (exactly like the [keyed-HMAC](#keyed-hmac--authenticate-caller-data)
seed), and a **per-template** FF1 key is HKDF-derived from it per request —
so templates are cryptographically independent, and raw keys never leave the HSM
trust path. The seed does **not** rotate (a format-preserving token carries no
version to select an old key), but its KEK wrapping is re-sealed when the KEK
rotates (`secsy-secret rewrap -all`), keeping the derived keys — and every issued
token — stable. `secsy-secret retire-kek` refuses to withdraw a KEK version still
sealing the FPE seed until it has been re-sealed (or `-force`).

Templates are declared in config:

```yaml
secret:
  kek_label: "secsy-kek"
  transforms:
    - name: pan                 # referenced by callers; bound into the derived key
      alphabet: digits          # named set, or an inline "chars:<symbols>" literal
      min_length: 12            # >= the FF1 domain minimum for the radix (radix^len >= 1e6)
      max_length: 19
      deterministic: true       # convergent: equal PAN -> equal token (equality search)
      preserve_other: true      # copy separators (dashes/spaces) through verbatim
    - name: account
      alphabet: alphanumeric    # radix 62
      deterministic: false      # context mode
      tweak_source: request     # a per-request tweak (e.g. a record id); re-supply to decode
      roles: [issuer]           # optional per-template role allowlist
```

Named alphabets: `digits`, `hex-lower`, `hex-upper`, `letters-lower`,
`letters-upper`, `alphanumeric-lower`/`-upper` (radix 36), `alphanumeric`
(radix 62), `base32`, `base32-hex`. A custom set is `chars:<symbols>` (e.g.
`chars:ACGT`). **The name and alphabet of a template must never change once data
has been tokenized under it** — both are identity.

```jsonc
// POST /api/secret/transform/encode  { "template": "pan", "value": "4111-1111-1111-1111" }
// 200 OK                             { "template": "pan", "result": "4923-8471-2210-6634", "deterministic": true }

// POST /api/secret/transform/decode  { "template": "pan", "value": "4923-8471-2210-6634" }
// 200 OK                             { "template": "pan", "result": "4111-1111-1111-1111", "deterministic": true }
```

For a `request`-tweak template, pass a base64 `tweak`; present the same tweak to
decode. Access requires the `secret:transform` capability plus any per-template
`roles` allowlist. Only lengths (never the plaintext or token) are audited.

```console
$ secsy-secret transform encode -template pan -value 4111-1111-1111-1111
$ secsy-secret transform decode -template pan -value 4923-8471-2210-6634
$ secsy-secret transform encode -template account -value ACCT12345 -tweak "$(printf ctx-7 | base64)"
```

Both directions count against the tenant's daily secret-op quota. gRPC exposes
the same operations as `SecretService.TransformEncode` / `TransformDecode`.

## Key escrow and recovery (M-of-N, dual control)

Optionally, each secret can be escrowed so its data key can be recovered under
**dual control** if the original requester loses access — a break-glass path that
does not weaken day-to-day security.

### How escrow works

At encryption time, in addition to wrapping the DEK to the primary KEK, the DEK
is split with **Shamir's Secret Sharing** over GF(2⁸) into *N* shares under a
reconstruction threshold *M*. Each share is then **RSA-OAEP wrapped to one
recovery agent's public key**. The wrapped shares travel with the envelope in an
`escrow` block:

```
   DEK ──Shamir split (M-of-N)──► share₁ … shareₙ
 shareᵢ ──RSA-OAEP(agentᵢ_pub)──► wrapped_shareᵢ   (unwrap runs on the agent's HSM)
```

- Any **M** recovery agents can reconstruct the DEK; any **M-1** learn *nothing*
  about it (Shamir's information-theoretic guarantee). No sub-quorum can recover.
- The whole escrow block is bound into the envelope's AES-GCM authenticated data,
  so an attacker cannot substitute their own recovery agents, tamper with a
  wrapped share, or strip the escrow block without invalidating the ciphertext.
- Recovery-agent private keys stay in the HSM: each agent unwraps its share via
  `C_Decrypt` on the token, exactly like the primary KEK.

Escrow is **optional per secret** and does not change the primary decrypt path:
the KEK owner can still decrypt an escrowed envelope normally.

### Configuration

```yaml
secret:
  kek_label: "secsy-kek"
  escrow:
    enabled: true
    threshold: 2          # M — quorum required to recover (>= 2, dual control)
    agents:               # N recovery agents
      - id: "alice"
        key_label: "agent-alice"     # RSA key held by the provider/HSM
      - id: "bob"
        key_label: "agent-bob"
      - id: "carol"
        public_key_file: "carol.pub" # or an externally-held public key (wrap-only)
```

`threshold` must be at least 2 (dual control) and at most the number of agents.
Each agent needs a `key_label` to participate in recovery through this provider;
an agent given only a `public_key`/`public_key_file` can be wrapped to but must
recover on its own device.

### CLI

```sh
# Provision a recovery-agent RSA key on the HSM (repeat per agent)
$ secsy-secret escrow-init-agent -label agent-alice

# Show / validate the escrow policy (resolves every agent key with -verify)
$ secsy-secret escrow-config -verify

# Encrypt WITH escrow (records a secret.escrow audit event)
$ printf 'master-password' | secsy-secret encrypt -escrow -out secret.json

# Recover under a quorum (records a secret.recover audit event)
$ secsy-secret recover -in secret.json -agent alice -agent bob -out plain.txt

# Review escrow / recovery events and verify the audit chain
$ secsy-secret audit
$ secsy-secret audit -verify
```

A `recover` invocation **fails closed** if fewer than `threshold` distinct
agents are supplied, if a named agent is not a recovery agent of that envelope,
or if the envelope carries no escrow — and each of those outcomes is logged.

Over the HTTP API, add `"escrow": true` to a `POST /api/secret/encrypt` request
to escrow the data key using the configured policy (gated on the same
`secret:encrypt` capability). **Recovery is intentionally CLI-only**: exposing a
one-call recovery endpoint would let a single administrator obtain plaintext,
defeating dual control. Recovery is meant to be run as a deliberate, audited
ceremony (ideally on an isolated host with the required agents present).

### The recovery ceremony (runbook)

1. **Authorize.** Recovery is an admin-only, break-glass operation
   (`secret:recover`). Convene the required quorum of recovery agents per policy.
2. **Stage the envelope** to a host with access to the recovery agents' HSM keys.
3. **Run recovery**, naming each participating agent:
   `secsy-secret recover -in secret.json -agent <id> -agent <id> …`.
   The tool enforces the M-of-N quorum, unwraps each share on the token, and
   reconstructs the DEK only if the quorum is met.
4. **Record.** Every attempt — success, sub-quorum denial, or error — appends a
   distinct `secret.recover` event (with the participating agent IDs) to the
   tamper-evident audit log. Verify the chain afterward with
   `secsy-secret audit -verify`.
5. **Rotate.** Treat a recovered secret as exposed: rotate it and re-encrypt.

### RBAC and audit

| Capability        | Role   | Covers                                  |
| ----------------- | ------ | --------------------------------------- |
| `secret:encrypt`  | admin, issuer | encrypt, including escrow-on-encrypt |
| `secret:escrow`   | admin  | administering the escrow configuration  |
| `secret:recover`  | admin  | performing a recovery ceremony          |

Escrow and recovery are logged with their own event types — `secret.escrow` and
`secret.recover` — separate from routine `secret.encrypt` / `secret.decrypt`, so
break-glass activity stands out in the audit trail and in SIEM export.

## Testing

Unit tests (`internal/secret`) run with no HSM using the software backend.
HSM-gated tests (`*_softhsm_test.go`) run against SoftHSM when
`SECSY_PKCS11_MODULE` / `SECSY_TOKEN_LABEL` are set. See [`../TESTING.md`](../../TESTING.md)
and [HSM configuration](../hsm/configuration.md).
