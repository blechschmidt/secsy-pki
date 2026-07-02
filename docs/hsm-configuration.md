# HSM / PKCS#11 configuration

Every private key in secsy-pki — CA signing keys and the secret-encryption KEK —
is created and used through a pluggable **key-provider**. In production that
provider is a hardware security module (HSM) reached over PKCS#11; for
development and CI it is [SoftHSM](https://github.com/opendnssec/SoftHSMv2) or an
on-disk software keystore. This guide covers how to configure each backend and
how the abstraction fits together.

> **Migrating from SoftHSM to a real HSM?** See the dedicated
> [production HSM migration guide](hsm-migration.md).

## The key-provider abstraction

The server never touches raw key files or the PKCS#11 API directly. All key
operations flow through the `key_provider` configured in `config.yaml`:

```yaml
key_provider:
  type: "pkcs11"        # "pkcs11" | "software" | "kms"
  software:
    keystore_dir: "keystore"
```

| `type`     | Where keys live | Use for |
|------------|-----------------|---------|
| `pkcs11`   | An HSM / PKCS#11 token (YubiHSM, SoftHSM, network HSM) | Production, staging, HSM tests |
| `software` | On-disk PKCS#8 keystore under `keystore_dir` | Local development without any HSM |
| `kms`      | AWS KMS or Azure Key Vault | Cloud deployments without a dedicated HSM — see [Cloud KMS backend](cloud-kms.md) |

If `type` is omitted it defaults to `pkcs11` when `pkcs11.module_path` is set,
to `kms` when `key_provider.kms.backend` is set, and to `software` otherwise. The
`kms` backend and per-role backend selection are documented in
[Cloud KMS backend (AWS KMS / Azure Key Vault)](cloud-kms.md).

**In both backends, private keys are never exported.** The software provider
generates keys on disk and signs with them in-process; the PKCS#11 provider
generates keys *on the device* and every sign / unwrap runs on the device via
`C_Sign` / `C_Decrypt`.

Supported key types (canonical names, aliases are normalized): `ed25519`,
`ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521`, `rsa-2048`, `rsa-4096`.

## Configuring a PKCS#11 backend

```yaml
pkcs11:
  module_path: "/usr/lib/pkcs11/yubihsm_pkcs11.so"  # the .so provided by your HSM vendor
  pin: "0001password"                                # PKCS#11 user PIN
  token_label: "YubiHSM"                             # select the token by CKA_LABEL
  token_serial: ""                                   # optional: match by serial
  token_manufacturer: ""                             # optional: match by manufacturer
```

- `module_path` is the vendor's PKCS#11 shared object. Common paths:
  - YubiHSM: `/usr/lib/pkcs11/yubihsm_pkcs11.so`
  - SoftHSM (Debian/Ubuntu): `/usr/lib/softhsm/libsofthsm2.so` or
    `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`
- `pin` is the **user** PIN used to log into the token for signing. Keep it out
  of the file where possible — see [Secrets and environment](#secrets-and-environment).
- `token_label` / `token_serial` / `token_manufacturer` select *which* token to
  use when a slot exposes more than one. Label alone is enough for SoftHSM.

### Key labels must be unique

secsy-pki addresses keys on a token by their `CKA_LABEL`. Two objects sharing a
label can resolve their public and private halves to *different* key pairs,
producing signatures that fail verification. The provider therefore **rejects**
generating a second key with an existing label. Choose one label per CA / KEK
and keep it stable — it is also how the CA is referenced everywhere else in the
system.

### High availability across multiple tokens

To make HSM access resilient, the PKCS#11 backend can span several tokens/slots
behind health-tracked failover: signing is routed to a healthy token and fails
over on error, with per-token health and failover metrics. Replicas of a key are
placed on each token under the *same* label (that is how failover finds the same
key), while the within-token uniqueness rule above still holds. See
[HSM high availability (multi-token failover)](hsm-ha.md).

### YubiHSM specifics

When the YubiHSM PKCS#11 module is used, the server also reads a `yubihsm:`
block and auto-generates `yubihsm_pkcs11.conf` from it:

```yaml
yubihsm:
  connector_url: "yhusb://"   # direct USB; or http://127.0.0.1:12345 via yubihsm-connector
  auth_key_id: 1
  password: "password"
  suppress_audit_warning: false
```

Set `YUBIHSM_PKCS11_CONF` yourself if you need to manage that file manually. The
YubiHSM path also unlocks the hardware audit-log verification described in the
[README](../README.md#audit-verification).

## Configuring the software backend

```yaml
key_provider:
  type: "software"
  software:
    keystore_dir: "keystore"
```

Keys are stored as PKCS#8 files under `keystore_dir` (created on first use).
This backend needs no HSM and is convenient for unit tests and local demos, but
offers **no hardware protection** — the private keys are ordinary files. Do not
use it for anything you care about protecting.

## Secrets and environment

The `SECSY_*` environment variables override the file-based configuration and
are the recommended way to inject secrets (so PINs need not live in
`config.yaml`). They also match what `scripts/setup-softhsm.sh --export-env`
emits, so a single `eval` wires the CLIs and the test suite to a token:

| Variable | Overrides |
|----------|-----------|
| `SECSY_KEY_PROVIDER` | `key_provider.type` |
| `SECSY_PKCS11_MODULE` | `pkcs11.module_path` |
| `SECSY_TOKEN_LABEL` | `pkcs11.token_label` |
| `SECSY_USER_PIN` | `pkcs11.pin` |
| `SECSY_SOFTWARE_KEYSTORE_DIR` | `software.keystore_dir` |

## SoftHSM for development and CI

`scripts/setup-softhsm.sh` initializes a SoftHSM2 token idempotently and prints
the module path plus the environment variables above.

```bash
# One-time: create/reuse a token labelled "secsy-pki-root"
./scripts/setup-softhsm.sh

# Wire the current shell to it (module path, token label, PINs)
eval "$(./scripts/setup-softhsm.sh --export-env)"

# Recreate the token from scratch
SOFTHSM_REINIT=1 ./scripts/setup-softhsm.sh
```

Defaults: token label `secsy-pki-root`, user PIN `1234`, SO PIN `5678`, token
dir `/tmp/softhsm/tokens`, config `/tmp/softhsm2.conf`. Override any of them via
`SOFTHSM_TOKEN_LABEL`, `SOFTHSM_USER_PIN`, `SOFTHSM_SO_PIN`, `SOFTHSM_TOKEN_DIR`,
`SOFTHSM2_CONF`.

Point `config.yaml` at the exported values, e.g.:

```yaml
key_provider:
  type: "pkcs11"
pkcs11:
  module_path: "/usr/lib/softhsm/libsofthsm2.so"
  pin: "1234"
  token_label: "secsy-pki-root"
```

### SoftHSM caveat: RSA-OAEP is SHA-1 only

SoftHSM 2.6.x can only perform RSA-OAEP unwrap with **SHA-1**, while YubiHSM and
the software backend support SHA-256. The secret-encryption feature negotiates
the strongest OAEP hash the KEK can actually use and records the choice in each
envelope, so ciphertext stays portable — but prefer a SHA-256-capable HSM in
production. See [password encryption](password-encryption.md#a-note-on-softhsm-and-sha-1).

Run HSM-gated Go tests serially, because a SoftHSM token is a single shared
resource:

```bash
eval "$(./scripts/setup-softhsm.sh --export-env)"
cd server
go test -p 1 -tags sqlite ./...
```

## Verifying the token works

```bash
# List objects on the token
pkcs11-tool --module "$SECSY_PKCS11_MODULE" --login --pin "$SECSY_USER_PIN" \
  --list-objects --token-label "$SECSY_TOKEN_LABEL"

# Create a CA key end-to-end through secsy-ca (see the CA guide)
secsy-ca -config config.yaml init-root -label "Root CA" -cn "Example Root CA"
secsy-ca -config config.yaml list
```

## See also

- [Certificate authority operations](certificate-authority.md) — create CAs and
  issue against this provider.
- [Password / secret encryption](password-encryption.md) — the HSM-backed KEK.
- [Production HSM migration](hsm-migration.md) — SoftHSM → real HSM.
