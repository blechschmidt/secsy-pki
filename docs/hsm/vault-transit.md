# HashiCorp Vault Transit key-provider backend

secsy-pki generates and uses every private key through the pluggable
[key-provider abstraction](configuration.md). Alongside the PKCS#11/HSM,
on-disk software, and [cloud KMS](cloud-kms.md) backends, the **Vault Transit**
backend hosts CA, TSA, and OCSP responder signing keys — and, optionally,
key-encryption keys (KEKs) — inside a [HashiCorp Vault Transit secrets
engine](https://developer.hashicorp.com/vault/docs/secrets/transit).

Vault Transit is ubiquitous in enterprises, and it fits the abstraction cleanly:
it is selected as a **`kms` backend** (`kms.backend: vault`), reusing the same
per-role selection, metrics, health probe, and inventory surface as AWS KMS and
Azure Key Vault.

## Trust and non-extractability model

This is the property that makes Transit a valid alternative to an HSM:

- **Keys never leave Vault.** Signing keys are created inside the Transit engine
  with `exportable: false`. Signing, public-key export, and wrap/unwrap are all
  Transit REST calls; the backend interface (`keyprovider.KMSBackend`, and the
  private `kmsWrapBackend` capability) exposes **no operation that returns a
  private key**. The non-extractability invariant is enforced at the type level,
  exactly as for PKCS#11 and cloud KMS (see [security review](../security/security-review.md)).
- **The server holds only a token, not a key.** secsy-pki authenticates to Vault
  with a token or AppRole credentials. Compromising the server process yields the
  ability to *ask Vault to sign* for as long as the token is valid and the policy
  allows — it does **not** yield the private key. Scope the Vault policy tightly
  (below), set a short token TTL, and rotate the AppRole `secret_id`.
- **Vault is the cryptographic boundary.** For hardware-grade protection, back
  the Transit mount with a [seal-wrapped](https://developer.hashicorp.com/vault/docs/enterprise/sealwrap)
  or HSM-auto-unseal Vault, or Vault Enterprise with an HSM seal. Transit key
  material is then protected by that boundary at rest.
- `secsy-ca inventory` and `ListKeys` report every Transit key as
  **non-extractable / sensitive**, matching the HSM trust boundary.

The trade-off versus a directly-attached PKCS#11 HSM is that signing is a network
round-trip to Vault (availability and latency depend on Vault), and the trust
root is Vault's own key-protection posture rather than a local FIPS token.

## When to use it

| Backend | Where keys live | Use for |
|---------|-----------------|---------|
| `pkcs11` | HSM / PKCS#11 token | On-prem HSM, SoftHSM tests |
| `software` | On-disk PKCS#8 keystore | Local development |
| `kms` (aws/azure) | AWS KMS / Azure Key Vault | Cloud-managed KMS |
| **`kms` (vault)** | **HashiCorp Vault Transit** | Enterprises already running Vault; a single control point for signing keys and KEKs |

Supported signing key types mirror the other cloud-KMS backends: **ECDSA**
(P-256 / P-384 / P-521) and **RSA** (2048 / 4096). Transit also offers `ed25519`
and `rsa-3072`, but these are intentionally not exposed so the abstraction stays
uniform across backends. For the KEK (wrap/unwrap) role, Transit uses a symmetric
`aes256-gcm96` key.

> The TSA (RFC 3161) signing key **must be RSA** for `openssl ts -verify`
> interop; provision it as `rsa-2048`/`rsa-4096`.

## Configuration

```yaml
key_provider:
  type: kms                        # pkcs11 | software | kms
  kms:
    backend: vault
    key_prefix: "secsy/"           # namespaces this deployment's Transit key names
    vault:
      address: https://vault.example.com:8200   # or VAULT_ADDR
      mount: transit               # Transit secrets-engine mount path
      namespace: ""                # Vault Enterprise namespace (X-Vault-Namespace)
      auth_method: token           # token | approle
      token: ""                    # token auth (prefer VAULT_TOKEN from a Secret)
      # -- or, for AppRole auth: --
      # auth_method: approle
      # role_id: <role-id>
      # secret_id: <secret-id>     # prefer SECSY_VAULT_SECRET_ID from a Secret
      # approle_path: approle
      ca_cert_file: ""             # PEM bundle to verify Vault's TLS cert (private CA)
      insecure: false              # disable Vault TLS verification (dev only)
      timeout_seconds: 30
```

`key_prefix` is prepended to each key label to form the Transit key **name**,
namespacing several deployments within one Transit mount. Names are sanitized to a
flat, URL-safe charset (`/` becomes `-`) so keys never nest under a path segment;
prefer a flat prefix such as `secsy-`.

> `kms.vault_url` (note: **not** under `vault:`) is the *Azure* Key Vault URL and
> is unrelated to the HashiCorp Vault backend configured here.

### Authentication

Two auth methods are supported; **credentials are never required in
`config.yaml`** — inject them from the environment:

- **Token** (`auth_method: token`) — a static Vault token from `vault.token` or
  the `VAULT_TOKEN` environment variable.
- **AppRole** (`auth_method: approle`) — `role_id` + `secret_id`. The backend logs
  in lazily at first use, caches the resulting client token, and on a `401/403`
  (token expiry) **re-authenticates once and retries transparently**, so a short
  AppRole token TTL requires no operator intervention.

### Environment overrides

| Variable | Sets |
|----------|------|
| `VAULT_ADDR` | `kms.vault.address` |
| `VAULT_NAMESPACE` | `kms.vault.namespace` |
| `VAULT_TOKEN` | `kms.vault.token` |
| `SECSY_VAULT_ROLE_ID` | `kms.vault.role_id` |
| `SECSY_VAULT_SECRET_ID` | `kms.vault.secret_id` |
| `SECSY_KMS_BACKEND` | `kms.backend` (set to `vault`) |
| `SECSY_KMS_KEY_PREFIX` | `kms.key_prefix` |

### Per-role backend selection

Different signing roles can use different backends. For example, keep the CA key
on an on-prem PKCS#11 HSM while hosting the TSA key in Vault Transit:

```yaml
key_provider:
  type: pkcs11
  kms:
    backend: vault
    vault: { address: https://vault:8200, token: "" }   # VAULT_TOKEN from a Secret
  roles:
    ca:  pkcs11
    tsa: kms          # TSA signs in Vault Transit
```

Recognized roles: `ca` (CA signing key **and OCSP responder keys**; OCSP follows
`ca`), `tsa`, and `signing`. An unset role falls back to `key_provider.type`.

## Vault policy (least privilege)

Grant the server's token/AppRole only the Transit paths it uses. Drop the
key-create paths after provisioning to leave a sign-only runtime policy.

```hcl
# Provisioning (secsy-ca init-root / tsa-key): create keys and read them back.
path "transit/keys/secsy-*"          { capabilities = ["create", "update", "read"] }
path "transit/keys"                  { capabilities = ["list"] }   # inventory / doctor

# Runtime signing (CA cert, CRL, OCSP, TSA token) and public-key export.
path "transit/sign/secsy-*"          { capabilities = ["update"] }
path "transit/verify/secsy-*"        { capabilities = ["update"] }
path "transit/keys/secsy-*"          { capabilities = ["read"] }

# KEK wrap/unwrap (only if a role uses a Vault Transit KEK).
path "transit/encrypt/secsy-*"       { capabilities = ["update"] }
path "transit/decrypt/secsy-*"       { capabilities = ["update"] }

# The health probe (secsy-ca doctor / /readyz) uses token/lookup-self, which the
# default policy already permits — no extra rule needed.
```

Enable the engine once with `vault secrets enable transit`.

## Provisioning keys

`secsy-ca` and the server construct the key provider identically, so one config
drives both:

```bash
# With key_provider.type=kms and kms.backend=vault, keys land in Transit.
secsy-ca init-root -label root-ca -key-type ecdsa-p384 ...

# TSA key on the TSA-role backend (RSA for openssl ts interop):
secsy-ca tsa-key -ca root-ca -label tsa -key-type rsa-2048 -out tsa.pem

# Verify reachability, credentials, and per-role backends:
secsy-ca doctor
```

## openssl-verify interop path

Because the CA private key never leaves Vault, verification is always done
against the **exported public key** with standard tooling — nothing about a
certificate signed via Transit is Vault-specific once issued:

```bash
# 1. Issue a root CA whose key lives in Vault Transit (config above).
secsy-ca init-root -label root-ca -key-type ecdsa-p384 -out root.pem

# 2. Issue a leaf, then fetch the chain.
#    (via the CA API / ACME / EST as usual)

# 3. Verify the chain with plain openssl — no Vault involved:
openssl verify -CAfile root.pem leaf.pem
openssl x509 -in root.pem -noout -text          # inspect the Transit-signed cert

# 4. TSA tokens (RSA Transit key) verify with openssl ts:
openssl ts -verify -in token.tsr -queryfile req.tsq -CAfile tsa-chain.pem
```

The signer path requests **ASN.1 DER** marshaling for ECDSA and selects
`pkcs1v15`/`pss` for RSA, so signatures are already in the form X.509/CMS/openssl
expect. `internal/keyprovider/kms_vault_test.go` proves this by signing a real
X.509 certificate through the Vault signer and verifying it against the
Vault-exported public key (`CheckSignatureFrom`) for ECDSA P-256/P-384 and RSA —
the same guarantee openssl provides.

## Wrap / unwrap (KEK)

Beyond signing, the Transit backend can act as a **key-encryption key**. A KEK is
provisioned as a symmetric `aes256-gcm96` Transit key (usage `decrypt`); the
`keyprovider.KeyWrapper` capability seals and opens a data-encryption key through
the Transit `encrypt`/`decrypt` endpoints, so the KEK never leaves Vault:

```go
kek, _ := provider.(keyprovider.KeyWrapper)
ct, _ := kek.WrapKey(ctx, keyprovider.KeyRef{Label: "kek"}, dek)   // vault:v1:...
dek2, _ := kek.UnwrapKey(ctx, keyprovider.KeyRef{Label: "kek"}, ct)
```

This is distinct from the software/PKCS#11 envelope KEK, which is an **asymmetric
RSA-OAEP** key exposed as a `crypto.Decrypter` (`keyprovider.DecrypterProvider`).
Vault Transit's KEK is symmetric and backend-native (`KeyWrapper`); the two models
are mutually exclusive, and the `WrapKey`/`UnwrapKey` metrics (`wrap`/`unwrap`)
are recorded like every other backend operation.

## Testing without a real Vault

The full test suite runs with **no real Vault and no HSM**. Rather than an
in-process backend, `internal/keyprovider/kms_vault_test.go` starts a hermetic
`httptest` **fake Vault server** that implements the Transit REST surface
(create/read/list keys, sign/verify, encrypt/decrypt, AppRole login,
`token/lookup-self`) with real standard-library crypto, and points the *real*
`vaultTransitBackend` at it. This exercises the actual HTTP client, auth, and
request/response parsing — including AppRole re-login on token expiry — offline
and deterministically.

## How it maps to the Transit API

| Provider op | Vault Transit call |
|-------------|--------------------|
| GenerateKey (sign) | `POST transit/keys/<name>` (`type: ecdsa-p*`/`rsa-*`, `exportable: false`) |
| GenerateKey (KEK) | `POST transit/keys/<name>` (`type: aes256-gcm96`) |
| FindKey / PublicKey | `GET transit/keys/<name>` (PKIX PEM of the latest version) |
| Sign | `POST transit/sign/<name>` (`prehashed`, `marshaling_algorithm: asn1` for ECDSA) |
| Verify | `POST transit/verify/<name>` |
| WrapKey / UnwrapKey | `POST transit/encrypt/<name>` / `POST transit/decrypt/<name>` |
| ListKeys | `LIST transit/keys` (filtered by `key_prefix`) |
| Ping (readiness) | `GET auth/token/lookup-self` |

Signing-algorithm selection follows the standard-library signer contract: the
caller's digest hash picks `sha2-{256,384,512}`, and an `*rsa.PSSOptions` selects
`pss` over `pkcs1v15`. The `vault:v<n>:` self-describing prefix Vault returns on
signatures and ciphertext is stripped/parsed by the backend.
