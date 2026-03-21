# Secsy PKI

HSM-backed SSH Certificate Authority with OIDC authentication and a web UI.

Secsy PKI manages an SSH public key infrastructure where CA private keys are stored on hardware security modules (HSMs) via PKCS#11. Users authenticate through OpenID Connect and request SSH certificates signed by the HSM. Restriction sets allow CA administrators to enforce policies on certificate parameters.

## Features

- **HSM-backed signing** — CA private keys live on a YubiHSM (or any PKCS#11 device). Keys never leave the hardware.
- **Ed25519 and ECDSA** — Generate and sign with Ed25519 (YubiHSM) or ECDSA P-256/P-384/P-521 (SoftHSM/YubiHSM).
- **OIDC authentication** — Public client with PKCE. The issuer discovery URL is the root of trust; no client secret needed. Tokens are refreshed automatically before expiry.
- **Root user** — Configurable admin with basic auth, exempt from OIDC. Full global permissions.
- **Permission matrix** — `SIGN_CERTIFICATE`, `MANAGE_PERMISSIONS`, and `CONFIGURE_CA` per CA node, assignable to users or groups.
- **Restriction sets** — Enforce policies on signing: max validity duration, allowed principals, allowed cert types, forced email+reason key IDs, deny/allow extensions and critical options, and max valid-after offset. A default restriction set can be assigned to a CA, with per-user/group overrides.
- **SSH certificate signing** — User and host certificates with configurable principals, validity, extensions, and critical options (subject to restriction sets).
- **Key generation** — Generate ed25519, ECDSA, or RSA key pairs via the API.
- **CA key generation on HSM** — Create new CA keys directly on the HSM from the UI (no PKCS#11 URI needed).
- **Web UI** — Bootstrap 5 SPA with dark theme. CA management, certificate signing, key generation, groups, permissions, and restriction set configuration. The sign form dynamically disables restricted fields based on the user's effective restrictions.
- **SQLite backend** — Stores CA hierarchy, groups, members, permission matrix, and restriction sets.
- **Terraform provisioning** — Provision the root CA key on a YubiHSM using [terraform-provider-pkcs11](https://github.com/blechschmidt/terraform-provider-pkcs11).

## Architecture

```
Browser (SPA)
    |
    | HTTPS + Bearer token (OIDC) or Basic auth (root)
    v
Go HTTP Server
    |
    |--- SQLite (CAs, groups, permissions, restriction sets)
    |
    |--- PKCS#11 ---> YubiHSM (via yhusb:// or yubihsm-connector)
    |                  └── Ed25519/ECDSA CA private keys
    |
    v
OIDC Provider (e.g. KeyCloak)
    └── User authentication, ID token verification
```

## Quick Start

### Prerequisites

- Go 1.21+
- A PKCS#11 device (YubiHSM2 recommended) or SoftHSM for development
- Docker (for KeyCloak and integration tests)

### 1. Build

```bash
cd server
go build -o secsy-pki-server ./cmd/server
```

### 2. Generate TLS Certificates

```bash
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout certs/server.key -out certs/server.crt -days 365 -nodes \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

### 3. Configure

Edit `config.yaml`:

```yaml
server:
  host: "0.0.0.0"
  port: 8443
  tls_cert: "certs/server.crt"
  tls_key: "certs/server.key"

database:
  driver: "sqlite"
  dsn: "secsy-pki.db"

oidc:
  issuer_url: "http://localhost:8080/realms/secsy-pki"
  client_id: "secsy-pki"

root_user:
  username: "root"
  password: "change-me-in-production"

pkcs11:
  module_path: "/usr/lib/pkcs11/yubihsm_pkcs11.so"
  pin: "0001password"
  token_label: "YubiHSM"
```

For SoftHSM development, use `module_path: "/usr/lib/pkcs11/libsofthsm2.so"`.

### 4. Run

```bash
export YUBIHSM_PKCS11_CONF=/path/to/yubihsm_pkcs11.conf  # if using YubiHSM
./secsy-pki-server -config config.yaml
```

Open https://localhost:8443 and log in as `root`.

## Terraform

Provision the root CA key on a YubiHSM:

```bash
cd terraform
cp terraform.tfvars.example terraform.tfvars  # edit as needed
terraform init
terraform apply
```

The Ed25519 root key is generated on the YubiHSM via `yubihsm-shell` and imported into Terraform state:

```bash
terraform import 'pkcs11_key_pair.root_ca_ed25519[0]' 'key-label/key-id-hex'
```

### YubiHSM PKCS#11 Configuration

`yubihsm_pkcs11.conf`:
```
# Direct USB (no connector daemon needed)
connector = yhusb://
```

## API

All endpoints under `/api/` require authentication (Bearer token or Basic auth for root).

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/auth/config` | OIDC discovery config (issuer URL + client ID) |
| GET | `/api/me` | Current user info |
| GET | `/api/cas` | List CAs |
| POST | `/api/cas` | Create CA (omit `pkcs11_uri` to generate key on HSM) |
| GET | `/api/cas/{id}` | Get CA |
| DELETE | `/api/cas/{id}` | Delete CA |
| POST | `/api/cas/{id}/sign` | Sign an SSH certificate |
| GET | `/api/cas/{id}/my-restrictions` | Get effective restriction set for current user |
| POST | `/api/keys/generate` | Generate an SSH key pair |
| GET | `/api/groups` | List groups |
| POST | `/api/groups` | Create group |
| DELETE | `/api/groups/{id}` | Delete group |
| GET | `/api/groups/{id}/members` | List group members |
| POST | `/api/groups/{id}/members` | Add member |
| DELETE | `/api/groups/{id}/members/{sub}` | Remove member |
| GET | `/api/cas/{id}/permissions` | List permissions |
| POST | `/api/cas/{id}/permissions` | Grant permission (with optional restriction set) |
| DELETE | `/api/cas/{id}/permissions` | Revoke permission |
| GET | `/api/cas/{id}/restriction-sets` | List restriction sets for a CA |
| POST | `/api/cas/{id}/restriction-sets` | Create restriction set (requires CONFIGURE_CA) |
| PUT | `/api/restriction-sets/{id}` | Update restriction set |
| DELETE | `/api/restriction-sets/{id}` | Delete restriction set |
| PUT | `/api/cas/{id}/default-restriction-set` | Set CA default restriction set |

### Sign a Certificate

```bash
curl -sk -u root:password -X POST https://localhost:8443/api/cas/{ca_id}/sign \
  -H 'Content-Type: application/json' \
  -d '{
    "public_key": "ssh-ed25519 AAAA... user@host",
    "cert_type": "user",
    "principals": ["username"],
    "valid_before": "+52w",
    "key_id": "user@org",
    "reason": "deployment"
  }'
```

## Integration Tests

Run with Docker (KeyCloak + OpenSSH):

```bash
cd server
./scripts/run-integration-tests.sh
```

This starts KeyCloak, seeds a test realm, launches the server, and runs the full test suite including SSH certificate verification with OpenSSH.

## Test SSH Server

Validate certificate-based authentication:

```bash
cd test-ssh
docker build -t secsy-pki-test-sshd .
docker run -d -p 2222:22 secsy-pki-test-sshd

# Generate key + sign cert via the API, then:
ssh -i id_test -o CertificateFile=id_test-cert.pub -p 2222 testuser@localhost
```

## Permissions

Three permissions exist on each CA node:

| Permission | Description |
|------------|-------------|
| `SIGN_CERTIFICATE` | User may sign certificates through this CA (subject to restriction sets) |
| `MANAGE_PERMISSIONS` | User may grant/revoke permissions and assign restriction sets to users/groups |
| `CONFIGURE_CA` | User may create/edit/delete restriction sets and set the CA default restriction set |

Permissions can be assigned to individual users (by OIDC subject) or to groups. The root user bypasses all permission checks.

## Restriction Sets

Restriction sets enforce policies on certificate signing. They are created by users with `CONFIGURE_CA` permission and can be:

- **CA default** — applies to all signers unless overridden
- **Per-user/group override** — attached to a `SIGN_CERTIFICATE` permission grant via `MANAGE_PERMISSIONS`

Priority: user-specific > group-specific > CA default.

A restriction set can constrain:

| Field | Effect |
|-------|--------|
| `max_validity_secs` | Maximum certificate lifetime in seconds |
| `allowed_principals` | Only these principals can be specified (`*` for any) |
| `allowed_cert_types` | Only `user`, `host`, or both |
| `force_key_id_email_reason` | Key ID is forced to `{email}: {reason}` format |
| `deny_extensions` | No custom extensions allowed |
| `allowed_extensions` | Only these extensions allowed (when not denied) |
| `deny_critical_options` | No critical options allowed |
| `max_valid_after_offset` | Maximum seconds into the future for valid-after |

The web UI dynamically reflects restrictions: when a user selects a CA in the sign form, restricted fields are hidden or disabled based on their effective restriction set.

## License

MIT
