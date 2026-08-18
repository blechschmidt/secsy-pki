# Secsy PKI — enterprise documentation

Deployment and operations guides for the **enterprise edition** of secsy-pki: an
HSM-backed X.509 and SSH certificate authority with envelope-based secret
encryption, role-based access control, and a tamper-evident audit log.

The [project README](../README.md) covers what secsy-pki is, how to build it,
and the `secsy-ssh` workflow. Everything below is the enterprise reference,
grouped into 12 sections. Each section folder has its own index with fuller
descriptions; this page is the map.

These pages are also published — with search and navigation — at
<https://blechschmidt.github.io/secsy-pki/>, built from this tree by
[the documentation-site workflow](development/documentation-site.md).

## Start here

| If you want to… | Go to |
|-----------------|-------|
| **Copy a working setup** | [`examples/`](../examples/README.md) — whole use cases as a config plus the client-side glue: [SSH PKI](../examples/ssh-pki/), [keyless signing from GitHub Actions](../examples/github-oidc-signing/), [ACME TLS automation](../examples/acme-tls/), [a private mTLS CA](../examples/mtls-internal/) |
| **Deploy for the first time** | [HSM configuration](hsm/configuration.md) → [Certificate authority](ca/overview.md) → [RBAC & audit](security/rbac-and-audit.md) |
| **Add secret encryption** | [Password / secret encryption](secrets/password-encryption.md) |
| **Move to production** | [Production HSM migration](hsm/production-migration.md) → [Key ceremony & DR](hsm/key-ceremony.md) → [Observability](operations/observability.md) |
| **Run it on Kubernetes** | [Kubernetes deployment](deployment/kubernetes.md) → [Multi-replica coordination](deployment/high-availability.md) |
| **Operate a live deployment** | [Operator runbook](operations/runbook.md) — keep it bookmarked |
| **Respond to a key compromise** | [Incident response: mass revocation](operations/incident-response.md) |
| **Prepare for a WebTrust / CA-Browser-Forum audit** | [Certificate Policy / CPS](compliance/certificate-policy.md) and the [compliance control mapping](compliance/compliance-mapping.md) |
| **Understand why it is built this way** | [Architecture overview](../ARCHITECTURE.md) and the [decision records](adr/README.md) |

## Documentation map

### 1. HSM & key management — [`hsm/`](hsm/README.md)

*Where private keys live, and the proof they never leave.*

| Page | Covers |
|------|--------|
| [HSM / PKCS#11 configuration](hsm/configuration.md) | Key-provider abstraction, PKCS#11/HSM and SoftHSM setup, PIN sourcing |
| [HSM high availability (multi-token failover)](hsm/high-availability.md) | Health-tracked failover across several PKCS#11 tokens |
| [Cloud KMS backend (AWS / Azure / Google)](hsm/cloud-kms.md) | AWS KMS, Azure Key Vault and Google Cloud KMS backends |
| [HashiCorp Vault Transit backend](hsm/vault-transit.md) | Signing keys and KEKs in a Vault Transit engine; token/AppRole auth |
| [Key ceremony, backup & DR](hsm/key-ceremony.md) | M-of-N key ceremony, key inventory, backup and disaster recovery |
| [Production HSM migration](hsm/production-migration.md) | SoftHSM → real HSM (YubiHSM / network HSM) cutover |
| [Remotely verifiable HSM audit log](hsm/audit-log.md) | Third-party-checkable proof that a given key signed nothing beyond what was published, and that the log came from the HSM whose serial it names |
| [YubiHSM key attestation](hsm/key-attestation.md) | Hardware-signed proof a key was born in the HSM and cannot be exported |

### 2. Certificate authority — [`ca/`](ca/README.md)

*Standing up CAs and running the certificate lifecycle.*

| Page | Covers |
|------|--------|
| [CA setup & certificate lifecycle](ca/overview.md) | Root and intermediate CAs, profiles, issue/renew/revoke, CRL and OCSP |
| [Intermediate key rotation](ca/rotation.md) | Intermediate signing-key rollover with a dual-chain overlap window |
| [Cross-signing & bridge CAs](ca/cross-signing.md) | Bridge CAs and root transitions through alternate trust chains |
| [Externally-signed subordinate CA](ca/external-ca.md) | A subordinate CA signed by an offline or third-party root |
| [SSH certificate authority](ca/ssh-ca.md) | HSM-backed OpenSSH user and host certificates, KRL revocation |
| [PKCS#12 (.p12/.pfx) export](ca/pkcs12.md) | Server-side key generation with password-protected bundle delivery |
| [Chain / path validation](ca/chain-validation.md) | Validating a supplied chain: path building, revocation, policy, key strength |
| [Certificate-inventory retention & archival](ca/retention.md) | Bounding a high-volume inventory with a fail-safe age-out policy |

### 3. Issuance policy & pre-issuance gates — [`issuance/`](issuance/README.md)

*What is checked before the HSM is ever asked to sign.*

| Page | Covers |
|------|--------|
| [Issuance preview (dry-run)](issuance/preview.md) | Dry-run a would-be issuance through every gate without signing anything |
| [Pre-issuance certificate linting](issuance/certlint.md) | CA/Browser Forum Baseline Requirements lint gate, with optional zlint |
| [CAA record checking (RFC 8659)](issuance/caa.md) | Fail-closed DNS authorization, incl. accounturi/validationmethods |
| [Name Constraints & Certificate Policies (RFC 5280)](issuance/name-constraints.md) | Permitted/excluded subtrees and policy OIDs on CAs and leaves |
| [Weak-key & compromised-key gate](issuance/key-checks.md) | ROCA, RSA policy, the Debian blocklist and an operator SPKI denylist |
| [Certificate Transparency (RFC 6962)](issuance/certificate-transparency.md) | CT precertificate submission, SCT embedding and inclusion-proof monitoring |

### 4. Certificate types & profiles — [`certificates/`](certificates/README.md)

*The specialized certificate shapes the CA can issue.*

| Page | Covers |
|------|--------|
| [S/MIME e-mail protection](certificates/smime.md) | Mailbox validation, domain allowlists and the S/MIME BR lint rules |
| [Smartcard-logon & Kerberos PKINIT](certificates/smartcard-logon.md) | Windows smartcard logon and Kerberos PKINIT client certificates |
| [eIDAS qualified certificates (ETSI EN 319 412-5)](certificates/qualified-certificates.md) | QcCompliance/QcType/QcSSCD and the PSD2 QcStatement |
| [SPIFFE SVID workload identity](certificates/spiffe.md) | Short-lived workload identities and the JWKS trust bundle |
| [TLS Delegated Credentials (RFC 9345)](certificates/delegated-credentials.md) | The delegationUsage extension; minting and verifying credentials |
| [Post-quantum & hybrid certificates](certificates/pqc.md) | Pure ML-DSA and catalyst-hybrid signatures, with interop caveats |

### 5. Enrollment protocols & integrations — [`protocols/`](protocols/README.md)

*How clients and devices actually get their certificates.*

| Page | Covers |
|------|--------|
| [ACME server (RFC 8555)](protocols/acme.md) | Challenges, EAB, ARI, client-selectable profiles, STAR, S/MIME |
| [ACME Multi-Perspective Issuance Corroboration (SC-067)](protocols/acme-mpic.md) | Corroborating domain control from several network vantage points |
| [SCEP & EST enrollment](protocols/scep-est.md) | Device, MDM and IoT enrollment with challenge or client-cert auth |
| [BRSKI zero-touch onboarding (RFC 8995)](protocols/brski.md) | Voucher-based onboarding of factory-fresh devices through a MASA |
| [Windows autoenrollment (MS-XCEP + MS-WSTEP)](protocols/windows-autoenrollment.md) | GPO-driven autoenrollment for AD-joined machines, Kerberos-free |
| [Host auto-enrollment agent (secsy-agent)](protocols/agent.md) | Declarative cert specs, ARI-driven renewal, atomic install and rollback |
| [gRPC API](protocols/grpc-api.md) | PKIService over gRPC, with reflection, health checks and mTLS |

### 6. Signing & timestamping services — [`signing/`](signing/README.md)

*Using the HSM to sign things that are not certificates.*

| Page | Covers |
|------|--------|
| [Artifact / code signing](signing/artifact-signing.md) | HSM-backed CMS/PKCS#7 code and artifact signing, CAdES B/T/LT |
| [Time-stamping authority (RFC 3161)](signing/timestamping.md) | Provisioning the TSA key, the /tsa endpoint, `openssl ts` interop |
| [Trusted external time source (NTS / Roughtime)](signing/trusted-time.md) | Cross-checking the host clock before signing, and refusing on drift |
| [Long-term preservation — Evidence Records (RFC 4998)](signing/evidence-records.md) | Renewable archive timestamps that outlive algorithm obsolescence |

### 7. Secret & password encryption — [`secrets/`](secrets/README.md)

*The HSM-backed encryption service that sits alongside the PKI.*

| Page | Covers |
|------|--------|
| [Password / secret encryption](secrets/password-encryption.md) | Envelope encryption, escrow, KEK rotation, FPE and the crypto service |

### 8. Security, access control & governance — [`security/`](security/README.md)

*Who may do what, and the evidence that they did it.*

| Page | Covers |
|------|--------|
| [RBAC, audit logging & config](security/rbac-and-audit.md) | Roles, per-CA permissions, the hash-chained event log, centralized config |
| [Operator authentication (SSO, mTLS, WebAuthn)](security/authentication.md) | OIDC SSO, LDAP/AD, mTLS binding, WebAuthn step-up, scoped API tokens |
| [Four-eyes / maker-checker approvals](security/approvals.md) | Dual control over CA lifecycle, bulk revocation and issuance |
| [Multi-tenant isolation](security/multi-tenancy.md) | Serving several isolated organizations from one deployment |
| [Rate limiting & abuse protection](security/rate-limiting.md) | Tiered rate limits and the bounded HSM concurrency guard |
| [Audit log export to SIEM](security/audit-siem-export.md) | Streaming the audit log to syslog/CEF/webhook, and offline verification |
| [FIPS 140-3 mode](security/fips.md) | The GOFIPS140 build plus the fail-closed algorithm policy |
| [Security review & hardening](security/security-review.md) | Findings, fixes, residual risks, and how to re-verify them |

### 9. Deployment & scaling — [`deployment/`](deployment/README.md)

*Getting it running, and running more than one of it.*

| Page | Covers |
|------|--------|
| [Kubernetes deployment](deployment/kubernetes.md) | Container image, Helm chart, cert-manager issuer, kind/SoftHSM smoke test |
| [Persistence backends (SQLite & PostgreSQL)](deployment/persistence.md) | SQLite and PostgreSQL stores, pooling, and migration between them |
| [Multi-replica coordination & HA](deployment/high-availability.md) | Multiple replicas with leader-elected singleton background jobs |
| [Unix-domain-socket listeners](deployment/unix-socket.md) | Serving HTTP/gRPC on a socket instead of a port, with filesystem permissions as the boundary |
| [Self-managed serving-TLS certificate](deployment/serving-cert.md) | Issuing the server's own HTTPS certificate from an internal CA |

### 10. Day-2 operations — [`operations/`](operations/README.md)

*Running it, watching it, and fixing it when it breaks.*

| Page | Covers |
|------|--------|
| [Operator runbook](operations/runbook.md) | Day-2 procedures: incidents, outages, tuning, rotation, DR, diagnostics |
| [Incident response: mass revocation](operations/incident-response.md) | Key-compromise mass revocation against the CA/B 24-hour clock |
| [Observability](operations/observability.md) | Prometheus metrics, health/readiness probes, dashboards, alerts and SLOs |
| [Distributed tracing (OpenTelemetry)](operations/tracing.md) | Request-to-HSM span trees over OTLP, with log↔trace correlation |
| [Expiry monitoring & auto-renewal](operations/expiry-monitoring.md) | Expiry scanning, notification sinks and automated renewal |
| [Synthetic issuance canary](operations/canary.md) | A probe that continuously proves the issuance path end to end |
| [Scheduled encrypted backups](operations/backup.md) | Leader-elected encrypted DR artifacts, and proving they restore |
| [OCSP pre-signing & static publishing (CDN offload)](operations/ocsp-presign-publish.md) | Taking the HSM off the public hot path; CRL/OCSP to a CDN |
| [Outbound webhooks (eventing)](operations/webhooks.md) | At-least-once delivery with HMAC signatures and dead-lettering |
| [DANE TLSA & SSHFP DNS records](operations/dns-records.md) | Zone-file pinning records for TLS services and SSH hosts |
| [Operator web console](operations/web-console.md) | The embedded operator console and its CLI feature-parity map |

### 11. Compliance & audit readiness — [`compliance/`](compliance/README.md)

*The documents a WebTrust or CA/Browser Forum audit asks for.*

| Page | Covers |
|------|--------|
| [Certificate Policy / CPS (RFC 3647)](compliance/certificate-policy.md) | The audit-facing CP/CPS, all nine sections, from the code |
| [Compliance control mapping](compliance/compliance-mapping.md) | CA/B BR, S/MIME BR and WebTrust controls traced to implementing code |

### 12. Development, testing & release — [`development/`](development/README.md)

*The quality gates a change has to clear.*

| Page | Covers |
|------|--------|
| [Performance & load benchmarking](development/benchmarks.md) | HSM hot-path benchmarks, session-pool tuning, the regression gate |
| [Test-coverage measurement & ratchet gate](development/coverage.md) | A committed baseline that coverage may only ratchet above |
| [Fuzz & property testing](development/fuzzing.md) | Native `go test -fuzz` targets over the untrusted-input parsers |
| [Resilience & fault-injection testing](development/resilience.md) | Deliberately breaking dependencies to prove the PKI fails closed |
| [Authorization & tenant-isolation regression matrix](development/authz-regression-matrix.md) | A pinned RBAC/tenant decision for every REST route and RPC |
| [Supply-chain security (SBOM, signing, SLSA)](development/supply-chain.md) | SBOMs, cosign signing, SLSA provenance and the govulncheck gate |
| [Documentation site (GitHub Pages)](development/documentation-site.md) | How these pages are published, and how to build the site locally |


### Architecture Decision Records — [`adr/`](adr/README.md)

*The load-bearing design decisions, and what they cost.*

[Key-provider abstraction](adr/0001-key-provider-abstraction.md) ·
[HSM non-extractability invariants](adr/0002-hsm-non-extractability-invariants.md) ·
[Fail-closed security gates](adr/0003-fail-closed-security-gates.md) ·
[Dual-chain rotation overlap](adr/0004-dual-chain-rotation-overlap.md) ·
[PQC / hybrid algorithm choice](adr/0005-pqc-hybrid-algorithm-choice.md) ·
[Four-eyes approval gate](adr/0006-four-eyes-approval-gate.md)

## Project-level documents

These live at the repository root, where contributors and tooling expect them:

| Document | Covers |
|----------|--------|
| [README](../README.md) | What secsy-pki is, quick start, the `secsy-ssh` client, the REST API |
| [ARCHITECTURE](../ARCHITECTURE.md) | Component map, request flows, and the feature-to-code index |
| [TESTING](../TESTING.md) | How to run every suite: unit, SoftHSM integration, e2e, race, lint |
| [`examples/`](../examples/README.md) | Runnable end-to-end use-case recipes |

## The tools at a glance

| Binary | Purpose | Build |
|--------|---------|-------|
| `secsy-pki-server` | The HTTP server, web console, and API | `go build -tags sqlite -o secsy-pki-server ./cmd/server` |
| `secsy-ca` | CA setup and certificate lifecycle | `go build -tags sqlite -o secsy-ca ./cmd/secsy-ca` |
| `secsy-secret` | HSM-backed secret encryption | `go build -tags sqlite -o secsy-secret ./cmd/secsy-secret` |
| `secsy-agent` | Host auto-enrollment / renewal daemon | `go build -o secsy-agent ./cmd/secsy-agent` |
| `secsy-ssh` | OIDC SSH client wrapper | `go build -o secsy-ssh ./cmd/secsy-ssh` |
| `secsy-verify` | Offline HSM audit-log verifier | `go build -o secsy-verify ./cmd/verify` |

All CLIs accept `-config config.yaml` and share the server's configuration,
database, and key provider. Run any command with `-h` for its flags.
