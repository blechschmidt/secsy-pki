# Testing secsy-pki

This document describes how to set up a local/CI test environment for
secsy-pki, in particular the **SoftHSM2** software HSM used to exercise the
PKCS#11 code paths without real hardware.

## Prerequisites

| Tool | Package (Debian/Ubuntu) | Purpose |
|------|-------------------------|---------|
| `softhsm2-util` | `softhsm2` | Software PKCS#11 HSM + token management |
| `pkcs11-tool`   | `opensc`   | Generic PKCS#11 CLI (slots, keys, objects) |
| Go 1.25         | —          | Build & run the server / tests |

Install on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y softhsm2 opensc
```

Other platforms:

- **RHEL/Fedora:** `sudo dnf install -y softhsm opensc`
- **macOS:** `brew install softhsm opensc`

## Quick start: initialize a SoftHSM token

Run the helper script from the repo root. It is **idempotent** — re-running it
reuses an existing token rather than creating a duplicate.

```bash
./scripts/setup-softhsm.sh
```

This will:

1. Locate the `libsofthsm2.so` PKCS#11 module (probes common paths).
2. Write a SoftHSM2 config to `/tmp/softhsm2.conf` pointing at a token store
   under `/tmp/softhsm/tokens`.
3. Initialize a token with a known label, SO PIN, and user PIN.
4. Verify the result with `pkcs11-tool --list-slots`.
5. Print the values you need to configure the server.

### Default token parameters

These defaults match the CI workflow (`.github/workflows/test.yaml`) and the
integration test config so local and CI runs behave identically.

| Setting | Value | Env override |
|---------|-------|--------------|
| Token label | `secsy-pki-root` | `SOFTHSM_TOKEN_LABEL` |
| User PIN | `1234` | `SOFTHSM_USER_PIN` |
| SO PIN | `5678` | `SOFTHSM_SO_PIN` |
| Token store dir | `/tmp/softhsm/tokens` | `SOFTHSM_TOKEN_DIR` |
| SoftHSM2 config | `/tmp/softhsm2.conf` | `SOFTHSM2_CONF` |
| PKCS#11 module | auto-detected | — |

> ⚠️ These PINs are **test-only** credentials. Never reuse them for a real
> HSM or production token.

### Overriding defaults

```bash
SOFTHSM_TOKEN_LABEL=my-token \
SOFTHSM_USER_PIN=9999 \
SOFTHSM_SO_PIN=0000 \
  ./scripts/setup-softhsm.sh
```

### Recreating a token from scratch

```bash
SOFTHSM_REINIT=1 ./scripts/setup-softhsm.sh
```

## Loading the environment into your shell

The server and `pkcs11-tool` need `SOFTHSM2_CONF` set. Export the generated
environment with:

```bash
eval "$(./scripts/setup-softhsm.sh --export-env)"
```

This sets:

- `SOFTHSM2_CONF` — path to the generated SoftHSM2 config
- `SECSY_PKCS11_MODULE` — detected path to `libsofthsm2.so`
- `SECSY_TOKEN_LABEL`, `SECSY_USER_PIN`, `SECSY_SO_PIN`

`--export-env` has no side effects (it does not initialize anything), so it is
safe to call from other scripts.

## Verifying the token manually

```bash
export SOFTHSM2_CONF=/tmp/softhsm2.conf

# List slots — the initialized token should appear with label "secsy-pki-root"
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-slots

# Log in and list objects (empty on a fresh token)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label secsy-pki-root --login --pin 1234 --list-objects
```

Expected `--list-slots` output includes:

```
  token label        : secsy-pki-root
  token manufacturer : SoftHSM project
  token model        : SoftHSM v2
  token flags        : login required, rng, token initialized, PIN initialized ...
```

### Generating a test key pair

To create an EC key pair on the token (as CI does):

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
  --keypairgen --key-type EC:prime256v1 --label "secsy-pki-root-ca-priv" --id 01
```

## Wiring SoftHSM into the server config

Point the server's `pkcs11` block at the SoftHSM module and token:

```yaml
pkcs11:
  module_path: "/usr/lib/softhsm/libsofthsm2.so"
  pin: "1234"
  token_label: "secsy-pki-root"
```

Ensure `SOFTHSM2_CONF` is exported in the environment where the server runs.

## Running the test suites

Unit tests:

```bash
cd server
go test -tags sqlite -count=1 ./internal/...
```

Integration tests (spins up KeyCloak via Docker Compose, starts the server,
then runs the tagged tests):

```bash
cd server
./scripts/run-integration-tests.sh
```

## CI

The GitHub Actions workflow (`.github/workflows/test.yaml`) installs
`softhsm2` and `opensc`, initializes the same `secsy-pki-root` token, runs unit
and integration tests, and builds all binaries. Keeping local defaults aligned
with CI means "works on my machine" and "works in CI" stay in sync.

## Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| `pkcs11-tool: not found` | Install the `opensc` package. |
| `ERROR: Could not locate libsofthsm2.so` | Install `softhsm2`; if the module lives elsewhere, add its path to `find_module()` in the script. |
| `CKR_PIN_INCORRECT` on login | Wrong user PIN; default is `1234`. Recreate with `SOFTHSM_REINIT=1`. |
| Token not visible to the server | `SOFTHSM2_CONF` not exported in the server's environment. |
| Stale/corrupt token | `SOFTHSM_REINIT=1 ./scripts/setup-softhsm.sh` to wipe & recreate. |
