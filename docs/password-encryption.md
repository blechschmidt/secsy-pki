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
All three operations are exposed over REST, gRPC (`SecretService`), and the
`secsy-secret` CLI, and each authorizes its own tenant-scoped capability
(`secret:datakey`, `secret:hmac`, `secret:random`), audits, and meters.

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
`SECSY_PKCS11_MODULE` / `SECSY_TOKEN_LABEL` are set. See [`../TESTING.md`](../TESTING.md)
and [HSM configuration](hsm-configuration.md).
