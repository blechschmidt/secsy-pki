# Security, access control & governance

*Who may do what, and the evidence that they did it.*

Authentication, authorization, dual control, tenancy and abuse protection, plus
the tamper-evident audit log that records the outcome of every privileged
operation and the export path that ships it to a SIEM.

| Guide | Covers |
|-------|--------|
| [**RBAC, audit logging & config**](rbac-and-audit.md) | Organization-wide roles, per-CA permissions, the hash-chained event log, and centralized policy/profiles |
| [**Operator authentication (SSO, mTLS, WebAuthn)**](authentication.md) | Strong console/API authentication: interactive OIDC/OAuth2 login with claim/group → RBAC role mapping, mutual-TLS client-cert binding for machine callers, WebAuthn/passkey step-up for high-risk operations, plus sessions, CSRF, and login/step-up audit + metrics |
| [**Four-eyes / maker-checker approvals**](approvals.md) | Holding high-risk operations for distinct-approver sign-off: the guarded classes (CA create/rotate/retire, bulk revocation, KEK rotation) and the per-profile manual issuance gate (`require_approval` → `cert.issue`) — park on 202, approve, then fetch the certificate; the `approver` role & self-approval denial, `secsy-ca approvals` + `/api/approvals/{id}/certificate` + console, why ACME/EST/SCEP/CMP always bypass the gate, and the `cert.issue.*` audit events/metrics |
| [**Multi-tenant isolation**](multi-tenancy.md) | Serving several isolated organizations from one deployment: per-tenant CAs, profiles, revocation/CRL state, secret envelopes, RBAC (platform vs. tenant roles), and a tenant-scoped audit trail; cross-tenant access is denied |
| [**Rate limiting & abuse protection**](rate-limiting.md) | Tiered token-bucket rate limiting (global / per-IP / per-account) and a bounded in-flight HSM concurrency guard for the public ACME/OCSP/CRL/SCEP/EST endpoints, with `429`/`503` + `Retry-After` and Prometheus throttle/queue metrics |
| [**Audit log export to SIEM**](audit-siem-export.md) | Streaming the audit event log to syslog (TCP/TLS)/CEF/webhook with at-least-once delivery & a durable cursor, plus `secsy-ca audit verify` (tamper detection) and `audit export` (offline batch) |
| [**FIPS 140-3 mode**](fips.md) | Running as a FIPS-capable PKI: the `make build-fips`/`GOFIPS140` build on the Go Cryptographic Module (verified at build time, reported by `-version`, the startup log, and `/healthz` build info), the fail-closed `security.fips` algorithm policy (no Ed25519 leaves, no SHA-1 anywhere, no RSA<2048, no software-PQC paths — enforced at config load, key generation, and issuance), the SoftHSM SHA-1-OAEP refusal + KEK re-wrap migration, the `fips.*` doctor checks, and the module-boundary-vs-HSM-validation scope |
| [**Security review & hardening**](security-review.md) | The security review of the enterprise branch: findings, fixes, residual risks, and how to re-verify |

---

↩ Back to the [documentation map](../README.md) · [project README](../../README.md)
