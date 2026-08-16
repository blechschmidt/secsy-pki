# Examples

Task-focused, copy-and-adapt recipes for common ways to run **Secsy PKI**. Each
folder is self-contained: a **minimal, heavily-commented server config** plus the
client-side glue (workflow YAML, `sshd_config` drop-ins, systemd units, verify
scripts) needed to make that one use case work end to end.

These configs are deliberately small. They are the opposite of
[`server/config.yaml`](../server/config.yaml), which is the *exhaustive annotated
reference* listing every knob. Start from an example here, then reach for the
reference (and the [`docs/`](../docs/README.md) guides) when you need a setting an
example does not show.

Every `config.yaml` under `examples/` is loaded and strict-decoded by the config
test suite, so they always parse against the current server and never reference a
config key that does not exist.

## Catalogue

| Example | Use case | Highlights |
|---------|----------|------------|
| [`ssh-pki/`](ssh-pki) | **SSH certificate authority** — replace `authorized_keys` sprawl with a single HSM-backed trust anchor | User + host certificate profiles, `sshd_config` trust drop-ins, `@cert-authority` client trust, KRL revocation refreshed by a systemd timer |
| [`github-oidc-signing/`](github-oidc-signing) | **Keyless software signing from GitHub Actions through OIDC** | GitHub's OIDC identity federated to the `signer` role — *no long-lived secret in the repo*; HSM-backed CMS signatures with RFC 3161 timestamps; a reusable release workflow and a downstream `openssl cms` verify script |
| [`acme-tls/`](acme-tls) | **Automated internal TLS** for services and ingress | RFC 8555 ACME server bound to an issuing CA; `certbot` / `acme.sh` / `lego` / Caddy / cert-manager clients; rate limiting for the public endpoint |
| [`mtls-internal/`](mtls-internal) | **Private CA for service-to-service mTLS** | `server` / `client` leaf profiles, a scoped API-token service account for CI issuance, and machine mTLS operator auth |

## Common prerequisites

All examples assume you have built the binaries and have a PKCS#11 token
available (SoftHSM works for evaluation — see
[`scripts/setup-softhsm.sh`](../scripts/setup-softhsm.sh) and
[`docs/hsm/configuration.md`](../docs/hsm/configuration.md)):

```console
# From the repo root — build the server and the CLIs (sqlite tag = embedded store)
$ cd server
$ go build -tags sqlite -o ../bin/secsy-pki-server ./cmd/server
$ go build -tags sqlite -o ../bin/secsy-ca         ./cmd/secsy-ca
$ go build              -o ../bin/secsy-agent       ./cmd/secsy-agent
$ cd ..

# Provision a SoftHSM evaluation token and export the SECSY_* env the tools read:
$ eval "$(scripts/setup-softhsm.sh --export-env)"
```

Then, for any example:

```console
# 1. Copy the example config and edit the placeholders (labels, hostnames, PINs).
$ cp examples/ssh-pki/config.yaml /etc/secsy-pki/config.yaml

# 2. Run any one-time provisioning commands from that example's README
#    (init a CA, create a signing key, etc.).

# 3. Start the server.
$ secsy-pki-server -config /etc/secsy-pki/config.yaml
```

Every config carries `root_user.password: "change-me-in-production"` and example
labels/hostnames (`pki.example.com`, `ops-ssh-ca`, …). **Replace these before any
real deployment**, and source the HSM PIN from a secret rather than inline
`pkcs11.pin` (see [`docs/hsm/configuration.md`](../docs/hsm/configuration.md),
"External PIN sourcing").

## See also

- [`docs/README.md`](../docs/README.md) — the full guide index
- [`server/config.yaml`](../server/config.yaml) — the exhaustive annotated config reference
- [`deploy/`](../deploy) — Kubernetes (Helm), cert-manager, systemd, and observability deployment assets
