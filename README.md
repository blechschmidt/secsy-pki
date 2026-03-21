# Secsy PKI

HSM-backed SSH Certificate Authority with OIDC authentication and a web UI.

Secsy PKI manages an SSH public key infrastructure where CA private keys are stored on hardware security modules (HSMs) via PKCS#11. Users authenticate through OpenID Connect and request SSH certificates signed by the HSM.

## Features

- **HSM-backed signing** — CA private keys live on a YubiHSM (or any PKCS#11 device). Keys never leave the hardware.
- **Ed25519 and ECDSA** — Generate and sign with Ed25519 (YubiHSM) or ECDSA P-256/P-384/P-521 (SoftHSM/YubiHSM).
- **OIDC authentication** — Public client with PKCE. The discovery URL is the root of trust; no client secret needed.
- **Root user** — Configurable admin with basic auth, exempt from OIDC. Full global permissions.
- **Permission matrix** — `SIGN_CERTIFICATE` and `MANAGE_PERMISSIONS` per CA node, assignable to users or groups.
- **SSH certificate signing** — User and host certificates with configurable principals, validity, extensions, and critical options.
- **Key generation** — Generate ed25519, ECDSA, or RSA key pairs via the API.
- **CA key generation on HSM** — Create new CA keys directly on the HSM from the UI (no PKCS#11 URI needed).
- **Web UI** — Bootstrap 5 SPA with dark theme. CA management, certificate signing, key generation, groups, and permissions.
- **SQLite backend** — Stores CA hierarchy, groups, members, and the permission matrix.
- **Terraform provisioning** — Provision the root CA key on a YubiHSM using [terraform-provider-pkcs11](https://github.com/blechschmidt/terraform-provider-pkcs11).

## Architecture

```
Browser (SPA)
    |
    | HTTPS + Bearer token (OIDC) or Basic auth (root)
    v
Go HTTP Server
    |
    |--- SQLite (CAs, groups, permissions)
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
| GET | `/api/auth/config` | OIDC discovery config |
| GET | `/api/me` | Current user info |
| GET | `/api/cas` | List CAs |
| POST | `/api/cas` | Create CA (omit `pkcs11_uri` to generate key on HSM) |
| GET | `/api/cas/{id}` | Get CA |
| DELETE | `/api/cas/{id}` | Delete CA |
| POST | `/api/cas/{id}/sign` | Sign an SSH certificate |
| POST | `/api/keys/generate` | Generate an SSH key pair |
| GET | `/api/groups` | List groups |
| POST | `/api/groups` | Create group |
| DELETE | `/api/groups/{id}` | Delete group |
| GET | `/api/groups/{id}/members` | List group members |
| POST | `/api/groups/{id}/members` | Add member |
| DELETE | `/api/groups/{id}/members/{sub}` | Remove member |
| GET | `/api/cas/{id}/permissions` | List permissions |
| POST | `/api/cas/{id}/permissions` | Grant permission |
| DELETE | `/api/cas/{id}/permissions` | Revoke permission |

### Sign a Certificate

```bash
curl -sk -u root:password -X POST https://localhost:8443/api/cas/{ca_id}/sign \
  -H 'Content-Type: application/json' \
  -d '{
    "public_key": "ssh-ed25519 AAAA... user@host",
    "cert_type": "user",
    "principals": ["username"],
    "valid_before": "+52w",
    "key_id": "user@org"
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

Two permissions exist on each CA node:

| Permission | Description |
|------------|-------------|
| `SIGN_CERTIFICATE` | User may sign certificates through this CA |
| `MANAGE_PERMISSIONS` | User may grant/revoke permissions on this CA |

Permissions can be assigned to individual users (by OIDC subject) or to groups. The root user bypasses all permission checks.

## License

MIT
