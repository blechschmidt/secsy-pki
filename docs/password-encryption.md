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

## Configuration

```yaml
secret:
  kek_label: "secsy-kek"   # RSA KEK in the configured key_provider
```

`SECSY_SECRET_KEK_LABEL` overrides it via the environment. When empty, the
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

| Method & path             | Purpose                                  |
| ------------------------- | ---------------------------------------- |
| `GET  /api/secret/info`   | KEK metadata (label, bits, algorithms)   |
| `POST /api/secret/encrypt`| Encrypt a secret into an envelope        |
| `POST /api/secret/decrypt`| Decrypt an envelope back to plaintext    |

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
