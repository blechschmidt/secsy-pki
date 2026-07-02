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
| [Intermediate key rotation](ca-rotation.md) | Safe, HSM-backed rollover of intermediate CA signing keys: cross-signing under the root, the dual-chain overlap window, combined-chain publication (AIA/bundle), controlled retirement, monitor-triggered auto-rotation, `secsy-ca rotate-intermediate`/`rotation-status`/`retire-intermediate`/`publish-chain`, and the rotation drill |
| [ACME server (RFC 8555)](acme.md) | Automated certificate issuance for certbot/lego/acme.sh: enabling ACME, ACME-enabled profiles, http-01 & dns-01, and External Account Binding |
| [Certificate Transparency (RFC 6962)](certificate-transparency.md) | Optional precertificate submission and SCT embedding on the issuance path: registering CT logs, per-profile CT policy (min-SCTs, fail-open/closed, retries/timeouts), SCT signature verification, and CT status in the console/API/audit log |
| [CAA record checking (RFC 8659)](caa.md) | DNS Certification Authority Authorization as a fail-closed pre-issuance gate on every issuance path: the tree-climbing + CNAME/DNAME algorithm, `issue`/`issuewild`/`iodef` evaluation against the CA identifier, per-profile `off`/`permissive`/`enforce` mode, the DNS-answer TTL cache, and the `cert.caa` audit event + Prometheus metrics |
| [SCEP & EST enrollment](enrollment.md) | Device / MDM / IoT auto-enrollment: SCEP (RFC 8894) with challenge-password grants and an HSM RA key, and EST (RFC 7030) over TLS with Basic / client-cert auth and server-side keygen |
| [Time-stamping authority (RFC 3161)](timestamping.md) | HSM-backed trusted time-stamp tokens: provisioning the TSA key/cert (`secsy-ca tsa-key`), the `/tsa` endpoint, policy/accuracy/ordering config, nonce & hash validation, audit + metrics, and `openssl ts -verify` interop |
| [Post-quantum & hybrid certificates](pqc.md) | ML-DSA (FIPS 204) signatures on the CA/issuance paths: pure-PQC and catalyst-hybrid (classical + ML-DSA alternative-signature) certificates, per-profile algorithm selection (`pqc-server`/`hybrid-server`), the software-provider fallback for SoftHSM, `secsy-ca init-root -algorithm pqc\|hybrid`, chain verification, and the interop / trust-store caveats |
| [Expiry monitoring & auto-renewal](expiry-monitoring.md) | The background expiry monitor, `secsy-ca expiring`/`monitor-run`, `/api/monitor/*`, notification sinks (log/webhook), auto-renewal, metrics & runbook |
| [Password / secret encryption](password-encryption.md) | HSM-backed envelope encryption for passwords and small secrets (`secsy-secret`, `/api/secret/*`) |
| [RBAC, audit logging & config](rbac-and-audit.md) | Organization-wide roles, per-CA permissions, the hash-chained event log, and centralized policy/profiles |
| [Audit log export to SIEM](audit-siem-export.md) | Streaming the audit event log to syslog (TCP/TLS)/CEF/webhook with at-least-once delivery & a durable cursor, plus `secsy-ca audit verify` (tamper detection) and `audit export` (offline batch) |
| [Observability](observability.md) | Prometheus `/metrics`, `/healthz` & `/readyz` (with HSM probe), structured JSON request logging, and a Prometheus/Grafana setup |
| [Rate limiting & abuse protection](rate-limiting.md) | Tiered token-bucket rate limiting (global / per-IP / per-account) and a bounded in-flight HSM concurrency guard for the public ACME/OCSP/CRL/SCEP/EST endpoints, with `429`/`503` + `Retry-After` and Prometheus throttle/queue metrics |
| [Kubernetes deployment](kubernetes.md) | Multi-stage container image, Helm chart (HSM/PKCS#11 module mount, PIN via Secret, TLS, RBAC/policy config, `/healthz`+`/readyz` probes), cert-manager ACME issuer for HSM-backed workload certs, and a kind/SoftHSM smoke test |
| [Production HSM migration](hsm-migration.md) | Moving from SoftHSM to a real HSM (YubiHSM / network HSM) for production |
| [Security review & hardening](security-review.md) | The security review of the enterprise branch: findings, fixes, residual risks, and how to re-verify |
| [Fuzz & property testing](fuzzing.md) | Native `go test -fuzz` over the untrusted-input parsers (CSR/DER, ACME JOSE/JWS, secret-envelope decrypt, OCSP/cert): targets, how to run local campaigns, CI smoke run, and handling crashes |
| [Performance & load benchmarking](benchmarks.md) | Benchmark/load-test suite for the HSM hot paths (signing/issuance, OCSP/CRL, secret encrypt/decrypt), the bounded PKCS#11 session pool, baseline SoftHSM numbers, and the tuning knobs (session pool size, OCSP cache TTL) |

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
