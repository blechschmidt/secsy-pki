# Secsy PKI — Enterprise documentation

Deployment and operations guides for the **enterprise edition** of secsy-pki: an
HSM-backed X.509 + SSH certificate authority with envelope-based secret
encryption, role-based access control, and a tamper-evident audit log.

Start with the [project README](../README.md) for what secsy-pki is, how to
build it, and the SSH certificate workflow. The guides here cover the enterprise
CA, secret-encryption, and governance features.

## Guides

| Guide | Covers |
|-------|--------|
| [HSM / PKCS#11 configuration](hsm-configuration.md) | The key-provider abstraction, configuring a PKCS#11 HSM or the software backend, and SoftHSM for dev/CI |
| [Certificate authority](certificate-authority.md) | Initializing root & intermediate CAs, profiles, issuing / renewing / revoking certificates, and serving CRL & OCSP |
| [Key ceremony, backup & DR](key-ceremony.md) | M-of-N key ceremony (`secsy-ca ceremony`), key inventory, CA-metadata backup/restore, HSM token backup, and the disaster-recovery runbook & drill |
| [ACME server (RFC 8555)](acme.md) | Automated certificate issuance for certbot/lego/acme.sh: enabling ACME, ACME-enabled profiles, http-01 & dns-01, and External Account Binding |
| [Expiry monitoring & auto-renewal](expiry-monitoring.md) | The background expiry monitor, `secsy-ca expiring`/`monitor-run`, `/api/monitor/*`, notification sinks (log/webhook), auto-renewal, metrics & runbook |
| [Password / secret encryption](password-encryption.md) | HSM-backed envelope encryption for passwords and small secrets (`secsy-secret`, `/api/secret/*`) |
| [RBAC, audit logging & config](rbac-and-audit.md) | Organization-wide roles, per-CA permissions, the hash-chained event log, and centralized policy/profiles |
| [Observability](observability.md) | Prometheus `/metrics`, `/healthz` & `/readyz` (with HSM probe), structured JSON request logging, and a Prometheus/Grafana setup |
| [Kubernetes deployment](kubernetes.md) | Multi-stage container image, Helm chart (HSM/PKCS#11 module mount, PIN via Secret, TLS, RBAC/policy config, `/healthz`+`/readyz` probes), cert-manager ACME issuer for HSM-backed workload certs, and a kind/SoftHSM smoke test |
| [Production HSM migration](hsm-migration.md) | Moving from SoftHSM to a real HSM (YubiHSM / network HSM) for production |
| [Security review & hardening](security-review.md) | The security review of the enterprise branch: findings, fixes, residual risks, and how to re-verify |
| [Fuzz & property testing](fuzzing.md) | Native `go test -fuzz` over the untrusted-input parsers (CSR/DER, ACME JOSE/JWS, secret-envelope decrypt, OCSP/cert): targets, how to run local campaigns, CI smoke run, and handling crashes |

Related top-level docs: [architecture](../ARCHITECTURE.md) ·
[testing](../TESTING.md).

## Suggested reading order

1. **Deploying for the first time** →
   [HSM configuration](hsm-configuration.md) →
   [Certificate authority](certificate-authority.md) →
   [RBAC & audit](rbac-and-audit.md).
2. **Adding secret encryption** → [Password / secret encryption](password-encryption.md).
3. **Going to production** → [Production HSM migration](hsm-migration.md) →
   [Key ceremony, backup & DR](key-ceremony.md) →
   [Observability](observability.md).
4. **Deploying on Kubernetes** → [Kubernetes deployment](kubernetes.md)
   (container image, Helm chart, cert-manager issuer).

## The tools at a glance

| Binary | Purpose | Build |
|--------|---------|-------|
| `secsy-pki-server` | The HTTP server, web UI, and API | `go build -tags sqlite -o secsy-pki-server ./cmd/server` |
| `secsy-ca` | CA setup and certificate lifecycle | `go build -tags sqlite -o secsy-ca ./cmd/secsy-ca` |
| `secsy-secret` | HSM-backed secret encryption | `go build -tags sqlite -o secsy-secret ./cmd/secsy-secret` |
| `secsy-ssh` | OIDC SSH client wrapper | `go build -o secsy-ssh ./cmd/secsy-ssh` |
| `secsy-verify` | Offline HSM audit-log verifier | `go build -o secsy-verify ./cmd/verify` |

All CLIs accept `-config config.yaml` and share the server's configuration,
database, and key provider. Run any command with `-h` for its flags.
