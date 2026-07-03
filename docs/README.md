# Secsy PKI — Enterprise documentation

Deployment and operations guides for the **enterprise edition** of secsy-pki: an
HSM-backed X.509 + SSH certificate authority with envelope-based secret
encryption, role-based access control, and a tamper-evident audit log.

Start with the [project README](../README.md) for what secsy-pki is, how to
build it, and the SSH certificate workflow. The guides here cover the enterprise
CA, secret-encryption, and governance features.

**Operating a live deployment?** Jump to the
[operator runbook](RUNBOOK.md) for day-2 procedures (incident response, outage
handling, tuning, rotation, DR), and the
[Architecture Decision Records](adr/README.md) for the reasoning behind the
design.

## Guides

| Guide | Covers |
|-------|--------|
| [**Operator runbook**](RUNBOOK.md) | **Day-2 operations:** CA-key-compromise incident response, OCSP/CRL outage handling, ACME/SCEP/EST/TSA/CMP endpoint troubleshooting, rate-limit & HSM-concurrency tuning, CT log outage behavior, CA key rotation/retirement, the disaster-recovery drill, and preflight diagnostics (`secsy-ca doctor`: read-only config/HSM/KMS/DB/audit-chain/expiry/CRL/clock/TLS checks with CI exit codes) |
| [**Incident response: mass revocation**](incident-response.md) | Key-compromise bulk revocation against the CA/B 24-hour clock: scoping the selection (profile, CN/SAN glob, issuance window, serial lists incl. attacker-issued serials unknown to the inventory), the mandatory dry-run + confirmed-count contract, batched execution with resume-after-interruption, the single end-of-run CRL+delta regeneration, OCSP cache invalidation + presign refresh, per-certificate + summary audit events, and propagation verification (`secsy-ca revoke-bulk`, `POST /api/ca/{id}/revocations:bulk`, console panel) |
| [**Architecture Decision Records**](adr/README.md) | The load-bearing design decisions: key-provider abstraction, HSM non-extractability invariants, fail-closed security gates, dual-chain rotation overlap, and the PQC/hybrid algorithm choice |
| [HSM / PKCS#11 configuration](hsm-configuration.md) | The key-provider abstraction, configuring a PKCS#11 HSM or the software backend, and SoftHSM for dev/CI |
| [Cloud KMS backend (AWS KMS / Azure Key Vault)](cloud-kms.md) | Hosting CA/TSA/OCSP signing keys in AWS KMS or Azure Key Vault: `key_provider.type: kms` + backend selection, per-role backend routing (`roles.ca`/`roles.tsa`), credentials via the cloud SDK default chain, IAM/RBAC requirements, the non-extractability guarantee, and the in-memory `fake` backend for credential-free tests |
| [HSM high availability (multi-token failover)](hsm-ha.md) | Spanning several PKCS#11 tokens/slots behind health-tracked failover: `pkcs11.tokens` + `selection_policy` (primary-backup / round-robin), the failure-threshold & background recovery prober, replicated-key ceremony and the cross-token unique-label invariant, per-token health/failover metrics, and the SoftHSM mid-load failover test |
| [Certificate authority](certificate-authority.md) | Initializing root & intermediate CAs, profiles, issuing / renewing / revoking certificates, and serving CRL & OCSP |
| [Key ceremony, backup & DR](key-ceremony.md) | M-of-N key ceremony (`secsy-ca ceremony`), key inventory, CA-metadata backup/restore, HSM token backup, and the disaster-recovery runbook & drill |
| [Intermediate key rotation](ca-rotation.md) | Safe, HSM-backed rollover of intermediate CA signing keys: cross-signing under the root, the dual-chain overlap window, combined-chain publication (AIA/bundle), controlled retirement, monitor-triggered auto-rotation, `secsy-ca rotate-intermediate`/`rotation-status`/`retire-intermediate`/`publish-chain`, and the rotation drill |
| [Cross-signing & bridge CAs](cross-signing.md) | Certifying one subordinate key under multiple issuers for bridge-CA and root-transition trust: `local-ca`/`certificate`/`csr` subjects, tenant-scoped cross-sign records, alternate-chain selection by Subject Key Identifier, `secsy-ca cross-sign`/`list-cross-signs`, the `/api/ca/{id}/cross-signs` + `/chains` endpoints, and dual-chain `openssl verify` interop |
| [Externally-signed subordinate CA](external-ca.md) | The offline/third-party-root topology: `secsy-ca ca csr` (HSM key + PKCS#10 CSR with CA attributes), the out-of-band signing ceremony, `ca import-cert` fail-closed validation (key match against the HSM, cA=TRUE, keyUsage, validity, chain verification) with operator warnings, chain serving through to the external trust anchor, same-key renewal via `-replace`, and the openssl-as-external-root e2e |
| [ACME server (RFC 8555)](acme.md) | Automated certificate issuance for certbot/lego/acme.sh: enabling ACME, ACME-enabled profiles, http-01 & dns-01, and External Account Binding |
| [Certificate Transparency (RFC 6962)](certificate-transparency.md) | Optional precertificate submission and SCT embedding on the issuance path: registering CT logs, per-profile CT policy (min-SCTs, fail-open/closed, retries/timeouts), SCT signature verification, and CT status in the console/API/audit log |
| [CAA record checking (RFC 8659)](caa.md) | DNS Certification Authority Authorization as a fail-closed pre-issuance gate on every issuance path: the tree-climbing + CNAME/DNAME algorithm, `issue`/`issuewild`/`iodef` evaluation against the CA identifier, per-profile `off`/`permissive`/`enforce` mode, the DNS-answer TTL cache, and the `cert.caa` audit event + Prometheus metrics |
| [Name Constraints & Certificate Policies (RFC 5280)](name-constraints.md) | First-class Name Constraints (2.5.29.30) and the certificate-policy family (2.5.29.32/.33/.36) on CAs: configuring permitted/excluded DNS/IP/email/URI/dirName subtrees and policy OIDs on roots/intermediates, per-profile leaf policy assignment, the fail-closed pre-issuance name-constraint gate (`cert.nameconstraint` audit + metrics), rotation preservation, and `openssl verify` interop |
| [SCEP & EST enrollment](enrollment.md) | Device / MDM / IoT auto-enrollment: SCEP (RFC 8894) with challenge-password grants and an HSM RA key, and EST (RFC 7030) over TLS with Basic / client-cert auth and server-side keygen |
| [Host auto-enrollment agent (secsy-agent)](agent.md) | Client-side daemon that keeps host/service certificates fresh over EST or ACME http-01 (EAB/bootstrap onboarding, keys never leave the host): declarative YAML cert specs, ARI-driven renewal with fraction-of-lifetime fallback and deterministic jitter, chain-verified atomic installs with reload hooks (command/SIGHUP) and rollback, `run`/`once`/`status` CLI, Prometheus textfile/exporter metrics, and systemd units |
| [S/MIME e-mail protection](smime.md) | Mailbox-validated S/MIME certificates: the `smime`/`smime-sign`/`smime-encrypt` profiles, RFC 5321/6531 mailbox validation + punycode normalization of rfc822Name SANs, per-profile & per-tenant e-mail domain allowlists, the CA/B Forum S/MIME Baseline Requirements lint rules (`smime_*` checks, enforce/warn per profile), dual-key sign/encrypt deployment with encryption-key escrow, EST/SCEP enrollment, and `openssl smime` interop |
| [gRPC API](grpc-api.md) | The core certificate-lifecycle operations (issue/renew/revoke, get certificate/status, list, CRL/OCSP metadata) exposed over gRPC alongside REST: `PKIService` (`proto/pki/v1/pki.proto`), server reflection + health, the same Bearer/Basic/mTLS auth, RBAC, tenant scoping and audit as REST, gRPC status-code mapping, request-ID/trace propagation, and the `secsy-ca grpc` client |
| [SPIFFE X.509-SVID](spiffe.md) | HSM-backed SPIFFE workload identities: the short-lived `spiffe-svid` profile (single `spiffe://` URI SAN, CA:false, digitalSignature), `POST /api/ca/{id}/svid` + `secsy-ca svid`, the trust-domain allowlist (RBAC-layered), fraction-based short-TTL auto-renewal, the JWKS trust-bundle endpoint, and go-spiffe / SPIRE integration |
| [Time-stamping authority (RFC 3161)](timestamping.md) | HSM-backed trusted time-stamp tokens: provisioning the TSA key/cert (`secsy-ca tsa-key`), the `/tsa` endpoint, policy/accuracy/ordering config, nonce & hash validation, audit + metrics, and `openssl ts -verify` interop |
| [Artifact / code signing](artifact-signing.md) | HSM-backed CMS/PKCS#7 detached signatures over release artifacts: provisioning code-signing keys under the lint-gated `code-signing` profile (`secsy-ca signing-key`), `/api/sign` + `/api/sign/verify` (signer role, tenant-scoped, rate-limited, `artifact.sign` audit), `secsy-ca sign`/`verify-signature` with file & digest input, embedded RFC 3161 countersignatures with timestamp-time chain validation, key-ceremony notes for signing keys, and `openssl cms`/`openssl ts` interop |
| [SSH certificate authority](ssh-ca.md) | HSM-backed OpenSSH user/host certificate signing: `secsy-ca ssh` (ca-init, sign-user, sign-host, revoke, krl), per-profile principals/validity/extensions/critical-options policy, store-allocated serials, revocation published as OpenSSH KRLs over HTTP (`sshd` `RevokedKeys`), `/api/ssh/*` with RBAC + tenant scoping, `ssh.sign`/`ssh.revoke` audit, and `ssh-keygen -L`/`-Q` interop |
| [Post-quantum & hybrid certificates](pqc.md) | ML-DSA (FIPS 204) signatures on the CA/issuance paths: pure-PQC and catalyst-hybrid (classical + ML-DSA alternative-signature) certificates, per-profile algorithm selection (`pqc-server`/`hybrid-server`), the software-provider fallback for SoftHSM, `secsy-ca init-root -algorithm pqc\|hybrid`, chain verification, and the interop / trust-store caveats |
| [Expiry monitoring & auto-renewal](expiry-monitoring.md) | The background expiry monitor, `secsy-ca expiring`/`monitor-run`, `/api/monitor/*`, notification sinks (log/webhook), auto-renewal, metrics & runbook |
| [Password / secret encryption](password-encryption.md) | HSM-backed envelope encryption for passwords and small secrets (`secsy-secret`, `/api/secret/*`) |
| [RBAC, audit logging & config](rbac-and-audit.md) | Organization-wide roles, per-CA permissions, the hash-chained event log, and centralized policy/profiles |
| [Operator authentication (SSO, mTLS, WebAuthn)](authentication.md) | Strong console/API authentication: interactive OIDC/OAuth2 login with claim/group → RBAC role mapping, mutual-TLS client-cert binding for machine callers, WebAuthn/passkey step-up for high-risk operations, plus sessions, CSRF, and login/step-up audit + metrics |
| [Operator web console](web-console.md) | The embedded `/console/` SPA: every page and its backing endpoints, the CLI ↔ console feature-parity map (CA lifecycle incl. rotation/cross-signing, SSH CA, artifact signing, audit verify/export, lint, key inventory, SVIDs, secrets/escrow, tenants), and which commands stay deliberately CLI-only |
| [Multi-tenant isolation](multi-tenancy.md) | Serving several isolated organizations from one deployment: per-tenant CAs, profiles, revocation/CRL state, secret envelopes, RBAC (platform vs. tenant roles), and a tenant-scoped audit trail; cross-tenant access is denied |
| [Persistence backends (SQLite & PostgreSQL)](persistence.md) | The `Store` abstraction and its two engines; selecting a backend and pooling; the invariants preserved across both (audit-chain tamper-evidence, serial/CRL monotonicity); `secsy-ca db migrate` to lift a file store into PostgreSQL; and running multiple replicas for HA |
| [Multi-replica coordination & HA](high-availability.md) | Running `replicas > 1` safely: PostgreSQL advisory-lock leader election with lease renewal gating every singleton background job (expiry monitor/auto-renewal, CA rotation, OCSP pre-signing, CRL publishing, audit anchoring, SIEM export, discovery), idempotent leadership handover, `secsy_leader_*` metrics + `/readyz` leadership detail, and the Helm `replicaCount > 1` preconditions |
| [Audit log export to SIEM](audit-siem-export.md) | Streaming the audit event log to syslog (TCP/TLS)/CEF/webhook with at-least-once delivery & a durable cursor, plus `secsy-ca audit verify` (tamper detection) and `audit export` (offline batch) |
| [Observability](observability.md) | Prometheus `/metrics`, `/healthz` & `/readyz` (with HSM probe), structured JSON request logging, and a Prometheus/Grafana setup |
| [Rate limiting & abuse protection](rate-limiting.md) | Tiered token-bucket rate limiting (global / per-IP / per-account) and a bounded in-flight HSM concurrency guard for the public ACME/OCSP/CRL/SCEP/EST endpoints, with `429`/`503` + `Retry-After` and Prometheus throttle/queue metrics |
| [OCSP pre-signing & static publishing (CDN offload)](ocsp-presign-publish.md) | Batch pre-signing OCSP responses for all known serials into the response cache (HSM off the public hot path, responses survive an HSM outage), plus the static artifact publisher: CRLs/delta CRLs/shards/chains/pre-signed responses written to a directory or S3-compatible store with atomic swap + integrity manifest, the CDN URL-mapping rules, `secsy-ca publish`, and the staleness metrics |
| [Kubernetes deployment](kubernetes.md) | Multi-stage container image, Helm chart (HSM/PKCS#11 module mount, PIN via Secret, TLS, RBAC/policy config, `/healthz`+`/readyz` probes), cert-manager ACME issuer for HSM-backed workload certs, and a kind/SoftHSM smoke test |
| [Supply-chain security (SBOM, signing, SLSA)](supply-chain.md) | Hardened release pipeline for the container image and binaries: CycloneDX SBOMs (Go modules + image), cosign signing (keyless/OIDC or a configurable key), a cosign SBOM attestation, a SLSA Build L3 provenance attestation via `slsa-github-generator`, the `govulncheck` gating scan, the `make sbom`/`make sign`/`make verify` targets, and the `cosign verify`/`cosign verify-attestation`/`slsa-verifier` commands consumers run |
| [FIPS 140-3 mode](fips.md) | Running as a FIPS-capable PKI: the `make build-fips`/`GOFIPS140` build on the Go Cryptographic Module (verified at build time, reported by `-version`, the startup log, and `/healthz` build info), the fail-closed `security.fips` algorithm policy (no Ed25519 leaves, no SHA-1 anywhere, no RSA<2048, no software-PQC paths — enforced at config load, key generation, and issuance), the SoftHSM SHA-1-OAEP refusal + KEK re-wrap migration, the `fips.*` doctor checks, and the module-boundary-vs-HSM-validation scope |
| [Production HSM migration](hsm-migration.md) | Moving from SoftHSM to a real HSM (YubiHSM / network HSM) for production |
| [Security review & hardening](security-review.md) | The security review of the enterprise branch: findings, fixes, residual risks, and how to re-verify |
| [Fuzz & property testing](fuzzing.md) | Native `go test -fuzz` over the untrusted-input parsers (CSR/DER, ACME JOSE/JWS, secret-envelope decrypt, OCSP/cert): targets, how to run local campaigns, CI smoke run, and handling crashes |
| [Performance & load benchmarking](benchmarks.md) | Benchmark/load-test suite for the HSM hot paths (signing/issuance, OCSP/CRL, secret encrypt/decrypt), the bounded PKCS#11 session pool, baseline SoftHSM numbers, and the tuning knobs (session pool size, OCSP cache TTL) |

Related top-level docs: [architecture](../ARCHITECTURE.md) ·
[testing](../TESTING.md) · [operator runbook](RUNBOOK.md) ·
[decision records](adr/README.md).

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
5. **Running it day to day** → [Operator runbook](RUNBOOK.md) (keep it bookmarked
   for incidents) → [Architecture Decision Records](adr/README.md) (the "why").

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
