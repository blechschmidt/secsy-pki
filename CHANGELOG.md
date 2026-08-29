# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file is not decorative: `scripts/release-guard.sh` refuses to release a tag
whose version has no dated, non-empty section here, and the section for the
version being released becomes the body of the GitHub release. See
[docs/development/releasing.md](docs/development/releasing.md).

## [Unreleased]

### Added

**Importing existing keys, and adopting a CA that already exists.** An
organization migrating onto secsy-pki generally cannot re-key: its root
certificate is already in trust stores it does not control. `secsy-ca ca import`
takes such a CA's private key *and* its existing certificate and produces an
ordinary, issuing CA record — after which certificates it signs still verify
against the root the world already trusts. `secsy-ca import-key` places a bare
key into any provider role (`ca`/`tsa`/`signing`/`secret`, signing or RSA-KEK
usage), and `secsy-secret signing-key import` adopts an application signing key
whose public half is already embedded in shipped clients.

Key files are accepted in the formats operators actually hold: PKCS#8 (plain and
PBES2/PBKDF2-encrypted), PKCS#1, SEC1, legacy `DEK-Info` PEM, OpenSSH (including
bcrypt-encrypted), PKCS#12 — which supplies the certificate too, so a `.p12` is
a complete adoption — and bare DER. Passphrases come from a file or the
environment, never a flag.

Adoption is fail-closed at every step: the key must match the certificate
(checked *before* anything is written, so a mismatch strands nothing on the
token), the certificate must be a currently valid CA certificate, a self-signed
one must verify under its own key, the key must pass the weak/compromised-key
gate, and the provider must demonstrably sign a random challenge with it before
a CA record is persisted. Subordinates link automatically to a parent already in
the PKI, or record the supplied chain as external chain material. The new
`keyprovider.KeyImporter` capability is implemented by the software and PKCS#11
backends — a high-availability set imports onto every token, and reports which
tokens hold the key if one rejects it — while the cloud-KMS backends report
plainly that they cannot. On a token the imported key gets exactly the
least-privilege template a generated key gets (`CKA_SENSITIVE`,
`CKA_EXTRACTABLE=false`, single-purpose).

What it deliberately does not do is launder provenance: hardware attestation
still reports the key as imported, every copy made before the import is still a
copy, and the CLI says so. The commands are CLI-only by design — their input is
raw private key material. New `key.import`, `ca.import` and
`secret.signing_key_import` audit events; adoption passes the four-eyes
`ca.create` gate. See [docs/ca/import.md](docs/ca/import.md).

**A `-yubihsm` container variant.** Every published image tag now has a
counterpart with `-yubihsm` appended — `latest-yubihsm`, `1.2.3-yubihsm`,
`edge-yubihsm` — built from the same commit in the same job, for `linux/amd64`
and `linux/arm64`. It carries Yubico's PKCS#11 module, `libyubihsm` with both
the USB and HTTP transports, `yubihsm-shell`, `yubihsm-connector` and the host
udev rule, so a YubiHSM 2 needs nothing mounted in from the host. The module is
symlinked to `/usr/lib/pkcs11/yubihsm_pkcs11.so` so one `pkcs11.module_path` is
correct on both architectures. Both images are signed, carry a CycloneDX SBOM
attestation of their own and, on a release, SLSA Build L3 provenance.
`verify-published-image.sh --expect-yubihsm` requires the module to be present
and to load; without the flag it requires the default image *not* to carry it,
so the two tags cannot quietly converge. See
[docs/deployment/container.md](docs/deployment/container.md#the-yubihsm-variant).

**An append-only second copy of the YubiHSM device audit log, and a drain that
follows every operation.** On a force-audited YubiHSM the 62-entry log ring is
not a buffer that overflows into older entries — once full, the device refuses
every audited command, including signing. Collection was already driven by
operations, but only those passing through `internal/keyprovider`; key
attestation, device attestation, audit-head commitments and option changes reach
the hardware directly and left entries nothing drained. A process-wide observer
on the driver's single command path now covers those too, so a deployment that
mostly attests can no longer wedge its own HSM. An explicit
`audit_collect_per_operation: false` is ignored on a force-audited device rather
than allowed to take the CA offline minutes after startup.

Because acknowledging the ring is irreversible and the device keeps no copy,
whatever holds the records afterwards *is* the audit log — and the database is
not append-only: anyone with its credentials can delete the newest rows, which
no digest chain can detect, since a shorter chain is a valid chain. The new
`yubihsm.audit_log_file` writes a second copy as one JSON record per line,
carrying the device's own 32-byte record verbatim, meant for `chattr +a`, a WORM
mount, or a log shipper that moves it off the host. Sinks are written before the
database and long before the acknowledgement, and a sink failure aborts the
cycle. `secsy-ca hsm-audit verify-file` re-derives the chain from the raw
records with no database, device or configuration, and `-anchor` / `-serial` /
`-tail` bind the file to a known commissioning, a device and an independently
obtained collection tail. `hsm-audit status` makes the tail comparison
automatically. See
[docs/hsm/audit-log.md](docs/hsm/audit-log.md#where-the-collected-records-go).

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
