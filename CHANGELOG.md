# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file is not decorative: `scripts/release-guard.sh` refuses to release a tag
whose version has no dated, non-empty section here, and the section for the
version being released becomes the body of the GitHub release. See
[docs/development/releasing.md](docs/development/releasing.md).

## [Unreleased]

Nothing yet. Add entries here as changes land; the release that follows moves
them into a dated section of their own.

## [1.0.0] - 2026-08-19

The first tagged release of the enterprise edition: an HSM-backed X.509 and SSH
certificate authority with envelope-based secret encryption, governed by RBAC
and recorded in a tamper-evident audit log.

### Added

**Keys and HSMs.** A backend-agnostic key provider (`internal/keyprovider`)
routes every key operation to a PKCS#11 HSM, a cloud KMS (AWS KMS, Azure Key
Vault, Google Cloud KMS), HashiCorp Vault Transit, or a software keystore for
development. Keys are generated on the device and never exported. Multi-token
high availability with health-tracked failover, a bounded session pool, RFC 7512
PKCS#11 URI addressing, external PIN sourcing (file, environment, Vault, AWS,
Azure, GCP), and a native YubiHSM driver speaking SCP03 over usbfs.

**Certificate authority.** Root and intermediate CA bootstrap, end-entity
issue/renew/revoke from CSRs against named profiles, reversible suspend/hold,
bulk issuance and bulk revocation, intermediate key rotation with a dual-chain
overlap window, cross-signing and bridge CAs, externally-signed subordinate CAs,
PKCS#12 export, and chain/path validation. Revocation through signed CRLs
— including delta CRLs and sharding — and an OCSP responder with nonces, a
delegated responder certificate, pre-signing and static artifact publishing.

**Enrollment protocols.** ACME (RFC 8555) with http-01, dns-01, tls-alpn-01,
device-attest-01 and email-reply-00 challenges, plus ARI, Profiles, alternate
chains, pre-authorization, STAR short-term certificates, EAB and multi-perspective
validation. SCEP, EST (including `/csrattrs`), CMP (RFC 9483), BRSKI (RFC 8995)
zero-touch onboarding, Microsoft Windows autoenrollment (MS-XCEP/MS-WSTEP), and a
host auto-enrollment agent.

**Issuance gates.** A fail-closed pre-issuance stack: CA/Browser Forum Baseline
Requirements linting (hand-rolled, with an optional zlint backend), CAA checking
per RFC 8659 and 8657, RFC 5280 name constraints and certificate policies,
weak-key and compromised-key blocklists, hardware key attestation, Certificate
Transparency SCT embedding with inclusion-proof monitoring and log-operator
diversity, policy-as-code expressions, and per-profile manual approval.

**Certificate types.** TLS server and client, S/MIME, smartcard logon and PKINIT,
eIDAS qualified certificates with QCStatements, SPIFFE X.509 and JWT SVIDs, TLS
delegated credentials, OCSP Must-Staple, and post-quantum ML-DSA and hybrid
certificates.

**SSH.** An HSM-backed OpenSSH user and host certificate authority with KRL
revocation, and DANE TLSA / SSHFP pinning-record generation.

**Signing and timestamping.** Detached CMS artifact and code signing with CAdES
B/T/LT levels, an RFC 3161 timestamping authority, a trusted external time source
(NTS/Roughtime) with fail-closed drift detection, and RFC 4998 evidence records.

**Secrets.** HSM-backed envelope encryption for passwords and small secrets, with
KEK rotation and DEK re-wrap, M-of-N escrow and recovery, FF1 format-preserving
tokenization, asymmetric signing, a stateless crypto service (data keys, HMAC,
CSPRNG), and optional post-quantum hybrid KEK wrapping.

**Security and governance.** Role-based access control, operator authentication
through OIDC SSO, LDAP/Active Directory, mTLS and WebAuthn step-up, scoped API
tokens and service accounts, four-eyes maker-checker approvals, multi-tenant
isolation with per-tenant quotas, tiered rate limiting, and a FIPS 140-3 build
mode.

**Audit.** An append-only hash-chained event log with RFC 3161 anchoring, SIEM
export (syslog/CEF/webhook), a live SSE and gRPC event stream, and a remotely
verifiable HSM audit log proving a named public key signed nothing beyond what
was published.

**Interfaces.** A REST API with an OpenAPI 3.1 specification and generated Go
client, a gRPC service with reflection and server streaming, the `secsy-ca`,
`secsy-secret`, `secsy-ssh`, `secsy-verify` and `secsy-agent` command-line tools,
and an operator web console embedded in the server binary.

**Operations.** Prometheus metrics with Grafana dashboards, alert rules and
multi-window SLO burn-rate alerts; OpenTelemetry tracing; expiry monitoring with
automated renewal; a synthetic issuance canary; external certificate discovery;
scheduled encrypted backups with automated restore verification; leader-elected
background jobs for multi-replica deployments; a self-issued serving-TLS
certificate; Unix-domain-socket listeners; and the `secsy-ca doctor` preflight
diagnostics.

**Deployment.** A multi-stage container image for `linux/amd64` and
`linux/arm64`, a Helm chart, a cert-manager external issuer, and SQLite and
PostgreSQL persistence backends.

**Supply chain.** CycloneDX SBOMs for the Go modules and the image, cosign
signatures and SBOM attestations, SLSA Build L3 provenance, a gating
`govulncheck` scan, and reproducible release archives built from the same
Dockerfile as the image.

[Unreleased]: https://github.com/blechschmidt/secsy-pki/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/blechschmidt/secsy-pki/releases/tag/v1.0.0
