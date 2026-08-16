# Cloud KMS key-provider backend (AWS KMS / Azure Key Vault / Google Cloud KMS)

secsy-pki generates and uses every private key through the pluggable
[key-provider abstraction](configuration.md). Alongside the PKCS#11/HSM and
on-disk software backends, the **cloud KMS** backend hosts CA, TSA, and OCSP
responder signing keys in **AWS KMS**, **Azure Key Vault**, or **Google Cloud
KMS**.

Like an HSM, a cloud KMS never releases private key material: key generation,
signing, and public-key export all happen through the cloud API, and the backend
interface (`keyprovider.KMSBackend`) deliberately exposes **no operation that
returns a private key**. This preserves the project's key non-extractability
invariant (see [security review](../security/security-review.md)) at the type level.

> A third `kms` backend, **HashiCorp Vault Transit** (`kms.backend: vault`),
> shares this abstraction and is documented separately in
> [vault-transit.md](vault-transit.md). It adds wrap/unwrap (KEK) support on top
> of signing.

## When to use it

| Backend | Where keys live | Use for |
|---------|-----------------|---------|
| `pkcs11` | HSM / PKCS#11 token | On-prem HSM, SoftHSM tests |
| `software` | On-disk PKCS#8 keystore | Local development |
| **`kms`** | **AWS KMS, Azure Key Vault, or Google Cloud KMS** | Cloud deployments without a dedicated HSM, or to offload a specific signing role to a managed KMS |

The cloud KMS backend supports **ECDSA** (P-256 / P-384 / P-521) and **RSA**
(2048 / 3072 / 4096) signing keys — the algorithms the managed KMSes offer for
the CA/TSA/OCSP roles. Ed25519 and post-quantum (ML-DSA) key types are **not**
available in cloud KMS and are rejected with a clear error; use the software or
PKCS#11 backend for those.

> **Google Cloud KMS** offers no `EC_SIGN_P521` algorithm, so `ecdsa-p521` is
> rejected on the `gcpkms` backend (AWS KMS and Azure Key Vault support it). Use
> `ecdsa-p256` / `ecdsa-p384` or an RSA key there.

> The TSA (RFC 3161) signing key **must be RSA** for `openssl ts -verify`
> interop; both KMS backends provision RSA keys for it.

## Configuration

```yaml
key_provider:
  type: kms                 # pkcs11 | software | kms
  kms:
    backend: aws            # aws | azure | gcpkms | vault | fake  (vault: see vault-transit.md)
    region: eu-central-1    # AWS region (AWS backend; optional, SDK-resolved when empty)
    key_prefix: "secsy/"    # namespaces this deployment's keys within the account/vault/ring
    vault_url: ""           # https://<vault>.vault.azure.net/ (Azure backend, required)
    gcp:                    # Google Cloud KMS backend (backend: gcpkms)
      project: my-project   #   GCP project id (required; or GOOGLE_CLOUD_PROJECT)
      location: europe-west1 #  Cloud KMS location, must match the key ring (required)
      key_ring: pki         #   pre-existing key ring id (required)
      protection_level: hsm #   software (default) | hsm (Cloud HSM) | external
      rsa_pss: false        #   create RSA keys as RSASSA-PSS instead of PKCS#1 v1.5
      credentials_file: ""  #   optional service-account JSON path (else ADC)
```

`key_prefix` is prepended to each key label to form the cloud-side identifier
(an AWS KMS **alias**, an Azure Key Vault **key name**, or a Google Cloud KMS
**CryptoKey id** within the key ring). It lets several deployments share one
account / vault / ring without label collisions. The backends sanitize the
prefix+label to each service's character rules (AWS aliases allow `/_-`; Azure
key names allow only alphanumerics and `-`; GCP CryptoKey ids allow `[a-zA-Z0-9_-]`,
≤63 chars).

### Per-role backend selection

Different signing roles can use different backends. For example, keep the CA key
on an on-prem PKCS#11 HSM while hosting the TSA key in AWS KMS:

```yaml
key_provider:
  type: pkcs11              # default backend (CA role, and everything sharing it)
  kms:
    backend: aws
    region: eu-central-1
    key_prefix: "secsy/"
  roles:
    ca:  pkcs11             # optional; defaults to key_provider.type
    tsa: kms                # TSA signs in AWS KMS
```

Recognized roles:

| Role | Covers |
|------|--------|
| `ca` | CA signing key, **and OCSP responder keys** (provisioned by the CA manager), plus ACME/SCEP/EST/CMP issuance and the secret KEK |
| `tsa` | The RFC 3161 timestamp-authority signing key |

An unset role falls back to `key_provider.type`. **OCSP** follows the `ca` role
because the OCSP responder key is provisioned and used by the CA manager; there
is no separate `ocsp` override. When the `tsa` role resolves to the same backend
as `ca`, the server and CLI share a single provider instance (one KMS client /
one HSM session pool).

### Environment overrides

All non-secret KMS settings can be injected from the environment (credentials
never come from config — see below):

| Variable | Sets |
|----------|------|
| `SECSY_KMS_BACKEND` | `key_provider.kms.backend` |
| `SECSY_KMS_REGION` | `key_provider.kms.region` |
| `SECSY_KMS_KEY_PREFIX` | `key_provider.kms.key_prefix` |
| `SECSY_KMS_VAULT_URL` | `key_provider.kms.vault_url` |
| `GOOGLE_CLOUD_PROJECT` / `SECSY_KMS_GCP_PROJECT` | `key_provider.kms.gcp.project` |
| `SECSY_KMS_GCP_LOCATION` | `key_provider.kms.gcp.location` |
| `SECSY_KMS_GCP_KEY_RING` | `key_provider.kms.gcp.key_ring` |
| `SECSY_KEY_PROVIDER_CA` | `key_provider.roles.ca` |
| `SECSY_KEY_PROVIDER_TSA` | `key_provider.roles.tsa` |
| `SECSY_KEY_PROVIDER_SIGNING` | `key_provider.roles.signing` |

## Credentials

Credentials are **never** read from `config.yaml`. Each backend uses its cloud
SDK's default credential chain, so the same binary works with static keys in
development and with workload/managed identity in production:

- **AWS** — `github.com/aws/aws-sdk-go-v2/config.LoadDefaultConfig`: environment
  (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_REGION`), shared config
  (`~/.aws/config`), EC2 instance role, or **IRSA** (IAM Roles for Service
  Accounts) on EKS.
- **Azure** — `azidentity.NewDefaultAzureCredential`: environment
  (`AZURE_CLIENT_ID` / `AZURE_TENANT_ID` / `AZURE_CLIENT_SECRET`), **workload
  identity**, or managed identity.
- **Google Cloud** — **Application Default Credentials**: `GOOGLE_APPLICATION_CREDENTIALS`
  (a service-account key file), **Workload Identity Federation** on GKE, the
  metadata server on GCE/Cloud Run, or `gcloud auth application-default login` in
  development. An explicit service-account key may instead be pointed at with
  `key_provider.kms.gcp.credentials_file` (a path) or `credentials_json` (inline;
  a credential, redacted from any dumped config) — prefer ADC / workload identity.

## IAM / RBAC requirements

### AWS KMS

The IAM principal the server runs as needs these actions. Scope the resource to
the alias/key ARNs under your `key_prefix` where possible.

| Action | Used for |
|--------|----------|
| `kms:CreateKey` | `secsy-ca` key generation (CA / TSA key) |
| `kms:CreateAlias` | Binding the key label → key (as `alias/<prefix><label>`) |
| `kms:DescribeKey` | Resolving a label to a key, duplicate-label guard |
| `kms:GetPublicKey` | Public-key export (certificate issuance, inventory) |
| `kms:Sign` | All signing (CA cert, CRL, OCSP, TSA token) |
| `kms:ListAliases` | Inventory (`secsy-ca inventory`) and the readiness probe |

Example least-privilege policy (day-to-day signing; drop `CreateKey`/`CreateAlias`
after provisioning):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey", "kms:ListAliases"],
      "Resource": "*",
      "Condition": { "StringLike": { "kms:RequestAlias": "alias/secsy/*" } }
    }
  ]
}
```

KMS keys are created as **asymmetric `SIGN_VERIFY`** keys (never exportable).

### Azure Key Vault

Grant the identity Key Vault **RBAC** roles (or an equivalent access policy) on
the target vault:

| Role | Actions | Needed for |
|------|---------|------------|
| **Key Vault Crypto Officer** | create/get keys | `secsy-ca` key generation |
| **Key Vault Crypto User** | sign, get public key | Runtime signing (CA/CRL/OCSP/TSA) |

For hardware-backed protection use an Azure Key Vault **Premium** tier or
**Managed HSM** (keys of type `EC-HSM` / `RSA-HSM`). Software-protected Key Vault
keys are still non-extractable via the API.

### Google Cloud KMS

Create the **key ring** ahead of time (secsy-pki creates CryptoKeys inside it,
but not the ring itself — an infrastructure/IAM concern):

```bash
gcloud kms keyrings create pki --location europe-west1
```

Grant the runtime identity these Cloud KMS permissions on the key ring (or bind
the predefined roles shown). Scope to the key ring where possible.

| Permission | Role | Used for |
|------------|------|----------|
| `cloudkms.cryptoKeys.create` | **Cloud KMS Admin** | `secsy-ca` key generation |
| `cloudkms.cryptoKeys.get` / `.list` | Cloud KMS Admin / Viewer | Resolve label → key, duplicate-guard, inventory |
| `cloudkms.cryptoKeyVersions.list` | Cloud KMS Viewer | Pick the active key version |
| `cloudkms.cryptoKeyVersions.viewPublicKey` | **Cloud KMS Viewer** | Public-key export |
| `cloudkms.cryptoKeyVersions.useToSign` | **Cloud KMS CryptoKey Signer** | All signing (CA/CRL/OCSP/TSA) |
| `cloudkms.keyRings.get` | Cloud KMS Viewer | The readiness probe (`secsy-ca doctor`, `/readyz`) |

Day-to-day signing needs only **Cloud KMS CryptoKey Signer/Verifier**
(`roles/cloudkms.signerVerifier`) plus `cloudkms.keyRings.get`; grant the admin
role only while provisioning.

Set `protection_level: hsm` to create keys in **Cloud HSM** (FIPS 140-2 Level 3),
keeping CA/TSA keys in a hardware module. Software-protection keys are still
non-extractable via the API. Cloud KMS binds the signature scheme to the key at
creation: RSA keys default to `RSA_SIGN_PKCS1_*_SHA256` (matching the CA default),
or `RSA_SIGN_PSS_*_SHA256` when `rsa_pss: true`; EC keys use
`EC_SIGN_P256_SHA256` / `EC_SIGN_P384_SHA384`.

## Provisioning keys

`secsy-ca` and the server construct the key provider identically, so the same
config drives both. Provision a CA key in the configured KMS backend and then
initialize the root:

```bash
# With key_provider.type=kms (or roles.ca=kms), keys land in the cloud KMS.
secsy-ca init-root -label root-ca -key-type ecdsa-p384 ...

# TSA key on the TSA-role backend (may differ from the CA):
secsy-ca tsa-key -ca root-ca -label tsa -key-type rsa-2048 -out tsa.pem
```

`secsy-ca inventory` lists cloud-KMS keys as **non-extractable / sensitive**,
matching the HSM trust boundary.

## Testing without cloud credentials

The backend selector accepts `backend: fake`, an in-process emulation
(`keyprovider.FakeKMSBackend`) that generates real keys with the Go standard
library and signs in-memory, but exposes only the `KMSBackend` surface — no
private-key export. It lets unit and integration tests exercise the full KMS
provider path (generate → resolve → sign → verify → list → probe) offline and
deterministically. See `internal/keyprovider/kms_test.go`, which signs a real
X.509 certificate through the KMS signer and verifies it against the KMS-exported
public key for both ECDSA and RSA.

```yaml
key_provider:
  type: kms
  kms:
    backend: fake
```

Each concrete backend is additionally unit-tested against an **in-memory fake of
its own cloud client** (real stdlib crypto, no network): the Vault Transit backend
talks to an `httptest` fake Vault, and the Google Cloud KMS backend talks to a
fake `gcpKMSClient` that models Cloud KMS's algorithm-bound signing and `CRC32C`
integrity checks. See `internal/keyprovider/kms_gcp_test.go`, which signs a real
X.509 certificate through the Cloud KMS signer path (ECDSA P-256/P-384, RSA
2048/3072/4096, and RSASSA-PSS) and verifies it against the exported public key.

## How it maps to the cloud APIs

| Provider op | AWS KMS | Azure Key Vault | Google Cloud KMS |
|-------------|---------|-----------------|------------------|
| GenerateKey | `CreateKey` (`SIGN_VERIFY`) + `CreateAlias` | `CreateKey` | `CreateCryptoKey` (`ASYMMETRIC_SIGN`, auto version 1) |
| FindKey / PublicKey | `DescribeKey` + `GetPublicKey` (DER SPKI) | `GetKey` (JWK) | `ListCryptoKeyVersions` + `GetPublicKey` (PEM SPKI) |
| Sign | `Sign` (`MessageType=DIGEST`) | `Sign` (digest value) | `AsymmetricSign` (`Digest` field) |
| ListKeys | `ListAliases` (+`DescribeKey`) | `ListKeyProperties` | `ListCryptoKeys` (`ASYMMETRIC_SIGN`) |
| Ping (readiness) | `ListAliases` (limit 1) | `GetKey` probe name | `GetKeyRing` |

Signing-algorithm selection follows the standard-library signer contract: the
caller's digest hash picks `ECDSA_SHA_{256,384,512}` / `RSASSA_PKCS1_V1_5_SHA_*`,
and an `*rsa.PSSOptions` selects `RSASSA_PSS_SHA_*`. Azure returns ECDSA
signatures in IEEE P1363 (`r‖s`) form; the backend converts them to the ASN.1 DER
encoding X.509/CMS verifiers expect (AWS already returns DER). **Google Cloud KMS**
binds the algorithm (scheme + hash) to the CryptoKeyVersion, so the scheme comes
from the key rather than the request; the backend selects the `Digest` field by
the caller's hash (Cloud KMS rejects a mismatch), returns ECDSA signatures already
in ASN.1 DER, and verifies the response `CRC32C` integrity checksums.
