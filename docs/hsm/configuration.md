# HSM / PKCS#11 configuration

Every private key in secsy-pki — CA signing keys and the secret-encryption KEK —
is created and used through a pluggable **key-provider**. In production that
provider is a hardware security module (HSM) reached over PKCS#11; for
development and CI it is [SoftHSM](https://github.com/opendnssec/SoftHSMv2) or an
on-disk software keystore. This guide covers how to configure each backend and
how the abstraction fits together.

> **Migrating from SoftHSM to a real HSM?** See the dedicated
> [production HSM migration guide](production-migration.md).

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
| `kms`      | AWS KMS, Azure Key Vault, Google Cloud KMS, or HashiCorp Vault Transit | Cloud/enterprise deployments without a dedicated HSM — see [Cloud KMS backend](cloud-kms.md) and [Vault Transit backend](vault-transit.md) |

If `type` is omitted it defaults to `pkcs11` when `pkcs11.module_path` is set,
to `kms` when `key_provider.kms.backend` is set, and to `software` otherwise. The
`kms` backend and per-role backend selection are documented in
[Cloud KMS backend (AWS KMS / Azure Key Vault)](cloud-kms.md); the HashiCorp
Vault Transit variant (`kms.backend: vault`, with wrap/unwrap KEK support) is in
[Vault Transit backend](vault-transit.md).

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
- `pin` is the **user** PIN used to log into the token for signing. Storing it
  here (or in `SECSY_USER_PIN`) leaves an HSM credential in plaintext at rest;
  prefer an external
  [`pin_source`](#sourcing-the-user-pin-from-a-credential-store-pin_source), which
  fetches it lazily at login from a file, env var, Vault, or a cloud secrets
  manager.
- `token_label` / `token_serial` / `token_manufacturer` select *which* token to
  use when a slot exposes more than one. Label alone is enough for SoftHSM.

### Key labels must be unique

secsy-pki addresses keys on a token by their `CKA_LABEL`. Two objects sharing a
label can resolve their public and private halves to *different* key pairs,
producing signatures that fail verification. The provider therefore **rejects**
generating a second key with an existing label. Choose one label per CA / KEK
and keep it stable — it is also how the CA is referenced everywhere else in the
system.

### Addressing keys with RFC 7512 `pkcs11:` URIs

Every CA stores an [RFC 7512](https://www.rfc-editor.org/rfc/rfc7512) `pkcs11:`
URI describing its signing key, and both the config `pkcs11.uri` field and each
CA's stored URI are parsed with a complete RFC 7512 parser. A key can therefore
be addressed by any combination of:

- **object attributes** — `object=` (the `CKA_LABEL`), `id=` (the `CKA_ID`, as
  percent-encoded bytes), and `type=` (`private`/`public`/`cert`/…);
- **token attributes** — `token=`, `serial=`, `model=`, `manufacturer=`, and
  `slot-id=`;
- **library attributes** — `library-description=`, `library-manufacturer=`,
  `library-version=`;
- **query attributes** — `module-path=` / `module-name=`, and
  `pin-value=` / `pin-source=`.

Addressing by `id=` (`CKA_ID`) or by `serial=` / `slot-id=` matters in a
[high-availability set](#high-availability-across-multiple-tokens): replicas
deliberately share one `CKA_LABEL`, so the `CKA_ID` or the token serial is the
only unambiguous way to pin an operation to a specific replica. When a stored CA
URI names a token by serial/slot-id, issuance is routed only to the matching
token; a URI that matches no token in the set fails closed rather than signing on
the wrong replica.

The optional `pkcs11.uri` field lets you point at an HSM with a single
self-describing string instead of a block of fields. It **backfills only the
fields left unset** — explicit `module_path` / `token_*` / `pin` always win — and
its `pin-value` / `pin-source` feed the same
[PIN sourcing](#sourcing-the-user-pin-from-a-credential-store-pin_source) as the
structured `pin_source` block (`pin-source=file:/path` becomes a `file` source).
Any embedded `pin-value` is **redacted** from a dumped or logged config.

```yaml
pkcs11:
  # A single self-describing URI. Equivalent to setting module_path + token_label
  # + a file pin_source below.
  uri: "pkcs11:token=secsy-pki-root?module-path=/usr/lib/softhsm/libsofthsm2.so&pin-source=file:/etc/secsy/hsm.pin"
```

`secsy-ca doctor` includes a `pkcs11.uris` check that parses every configured
`pkcs11:` URI (the config `uri` fields and each CA's stored key URI), warns on an
embedded plaintext `pin-value` or an unrecognized attribute, and — against a live
token — confirms each CA key actually resolves under its full object/id/token
addressing.

### Sourcing the user PIN from a credential store (`pin_source`)

Storing the PKCS#11 user PIN as plaintext — in `pkcs11.pin` or the
`SECSY_USER_PIN` environment variable — leaves an HSM credential at rest in the
config file or the process environment. The `pkcs11.pin_source` block eliminates
that: the PIN is fetched **lazily, at HSM login time**, from a pluggable
credential source, is kept out of any logged or dumped config representation
(secret fields are redacted), and — if the source is unreachable — the login
**fails closed** with an actionable error rather than starting without a working
credential.

```yaml
pkcs11:
  module_path: "/usr/lib/softhsm/libsofthsm2.so"
  token_label: "secsy-pki-root"
  # pin: "…"           # ← omit; the PIN is sourced below instead
  pin_source:
    type: "file"        # inline | env | file | vault | aws | azure | gcp
    file:
      path: "/etc/secsy/hsm.pin"
```

Select the source with `type`; only the matching sub-block is read:

| `type`   | Where the PIN comes from | Key fields |
|----------|--------------------------|------------|
| `inline` | `pkcs11.pin` (default; **plaintext at rest**, emits a deprecation warning) | — |
| `env`    | An environment variable  | `env.var` (default `SECSY_USER_PIN`) |
| `file`   | A file (enforced `0600`) | `file.path`, `file.allow_insecure_perms` |
| `vault`  | A HashiCorp Vault KV secret | `vault.address` + auth, `vault.mount`, `vault.path`, `vault.field` |
| `aws`    | AWS Secrets Manager      | `aws.region`, `aws.secret_id`, `aws.field` |
| `azure`  | Azure Key Vault secret   | `azure.vault_url`, `azure.name`, `azure.field` |
| `gcp` (alias `gcpsm`) | Google Cloud Secret Manager | `gcp.project`, `gcp.secret`, `gcp.version`, `gcp.field` |

#### `file`

```yaml
pin_source:
  type: "file"
  file:
    path: "/etc/secsy/hsm.pin"      # contents are the PIN; a trailing newline is trimmed
    # allow_insecure_perms: false   # by default the file must be 0600
```

The file must not be readable by group or other; a looser mode fails closed with
a `chmod 600` hint (override only with `allow_insecure_perms: true`). Mount it
from a Kubernetes `Secret`, a tmpfs, or a systemd credential.

#### `env`

```yaml
pin_source:
  type: "env"
  env:
    var: "SECSY_USER_PIN"    # any variable name; defaults to SECSY_USER_PIN
```

Unlike a bare `SECSY_USER_PIN` override (which is treated as an inline PIN and
warns), an explicit `env` source is the sanctioned way to inject the PIN from the
environment (e.g. a Kubernetes `secretKeyRef`).

#### `vault` (HashiCorp Vault KV)

Reuses the same connection parameters as the
[Vault Transit backend](vault-transit.md) — address, token / AppRole auth,
namespace, and TLS:

```yaml
pin_source:
  type: "vault"
  vault:
    address: "https://vault.example:8200"    # or the VAULT_ADDR env var
    auth_method: "approle"                    # token | approle
    role_id: "…"
    secret_id: "…"
    mount: "secret"                           # KV mount (default "secret")
    path: "hsm/prod"                          # secret path within the mount
    field: "pin"                              # key within the secret (default "pin")
    kv_version: 2                             # 1 or 2 (default 2)
```

#### `aws` (AWS Secrets Manager)

Uses the standard AWS credential chain (environment, shared config, IRSA /
instance role):

```yaml
pin_source:
  type: "aws"
  aws:
    region: "eu-central-1"       # optional; SDK default resolution otherwise
    secret_id: "secsy/hsm-pin"   # secret name or ARN
    # field: "pin"               # optional: pick a key from a JSON secret value
```

#### `azure` (Azure Key Vault)

Uses `DefaultAzureCredential` (environment, workload identity, or managed
identity):

```yaml
pin_source:
  type: "azure"
  azure:
    vault_url: "https://my-vault.vault.azure.net/"
    name: "hsm-pin"
    # version: "…"    # optional; latest otherwise
    # field: "pin"    # optional: pick a key from a JSON secret value
```

#### `gcp` (Google Cloud Secret Manager)

Uses **Application Default Credentials** (the metadata server, Workload Identity
Federation, `GOOGLE_APPLICATION_CREDENTIALS`, or `gcloud auth application-default
login`), sharing the [Cloud KMS backend](cloud-kms.md#credentials) credential
wiring. The alias `gcpsm` selects the same source.

```yaml
pin_source:
  type: "gcp"
  gcp:
    project: "my-project"      # or give secret as a full projects/…/secrets/… name
    secret: "hsm-pin"          # secret id (or a full resource name)
    # version: "latest"        # optional; "latest" otherwise
    # field: "pin"             # optional: pick a key from a JSON secret value
    # credentials_file: "…"    # optional service-account JSON path (else ADC)
```

The secret must grant the runtime identity `roles/secretmanager.secretAccessor`.
The PIN is resolved lazily at HSM login, never at process start, and is never
logged.

#### Per-token override (HA)

Each token in a [high-availability set](#high-availability-across-multiple-tokens)
may carry its own `pin_source`; when omitted it inherits the set-level
`pkcs11.pin_source` (then the inline `pin`), exactly like the per-token `pin`
fallback:

```yaml
pkcs11:
  pin_source: { type: "vault", vault: { address: "…", path: "hsm/shared" } }
  tokens:
    - { name: "primary", token_label: "hsm-a" }        # inherits the vault source
    - { name: "backup",  token_label: "hsm-b",
        pin_source: { type: "file", file: { path: "/etc/secsy/hsm-b.pin" } } }
```

#### Verifying the source

`secsy-ca doctor` runs a **`pin.source`** check that resolves the configured
source(s) and confirms a PIN comes back — without ever printing it — so a
plaintext-free configuration is verified before the HSM actually needs the PIN:

```
✓ pass  pin.source   all 1 PIN source(s) reachable, PIN retrieved (pkcs11→file /etc/secsy/hsm.pin)
```

An unreachable source, a missing secret, or an insecure file mode fails the check
(and the HSM login) closed.

### High availability across multiple tokens

To make HSM access resilient, the PKCS#11 backend can span several tokens/slots
behind health-tracked failover: signing is routed to a healthy token and fails
over on error, with per-token health and failover metrics. Replicas of a key are
placed on each token under the *same* label (that is how failover finds the same
key), while the within-token uniqueness rule above still holds. See
[HSM high availability (multi-token failover)](high-availability.md).

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
[README](../../README.md#audit-verification).

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

The `SECSY_*` environment variables override the file-based configuration. They
match what `scripts/setup-softhsm.sh --export-env` emits, so a single `eval`
wires the CLIs and the test suite to a token. Note that `SECSY_USER_PIN` sets the
**inline** PIN (and so emits the plaintext deprecation warning); to source the
PIN from a credential store use
[`pkcs11.pin_source`](#sourcing-the-user-pin-from-a-credential-store-pin_source)
instead (its `env` type reads any variable without the warning):

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
production. See [password encryption](../secrets/password-encryption.md#a-note-on-softhsm-and-sha-1).

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

- [Certificate authority operations](../ca/overview.md) — create CAs and
  issue against this provider.
- [Password / secret encryption](../secrets/password-encryption.md) — the HSM-backed KEK.
- [Production HSM migration](production-migration.md) — SoftHSM → real HSM.
