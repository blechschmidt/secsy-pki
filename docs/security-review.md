# Security review & hardening — enterprise branch

This document records the Task 12 security review of the secsy-pki **enterprise**
branch, the findings, and the fixes applied. It is a living record: re-run the
verification steps (below) after significant changes.

- **Date:** 2026-07-02
- **Scope:** the `enterprise` branch — HSM-backed CA (`internal/ca`, `internal/pki`),
  key-provider abstraction (`internal/keyprovider`), envelope secret encryption
  (`internal/secret`), RBAC/audit/config (`internal/rbac`, `internal/audit`,
  `internal/middleware`, `internal/handlers`), and the CLIs/server
  (`cmd/*`).
- **Method:** manual code review across six dimensions (HSM key
  non-extractability, PIN handling, authenticated-encryption ciphertext formats,
  secret logging, revocation/chain validation, and dependency vulnerabilities),
  supported by `govulncheck`, `go vet`, and the SoftHSM end-to-end suite.

## Review objectives and outcomes

| Objective (from the task) | Outcome |
|---|---|
| Private keys never leave the HSM | **Fixed** — CA signing-key templates now enforce non-extractability (were relying on token defaults) |
| PINs handled securely | **Verified OK** — PIN flows from config/env straight to `C_Login`; never logged or error-formatted; no struct-dump path |
| Ciphertext uses authenticated encryption | **Verified OK** — AES-256-GCM with algorithm/metadata bound into AAD; RSA-OAEP DEK wrapping; a decrypt-oracle nuance was tightened |
| No secrets are logged | **Verified OK** — plaintext/DEK/PIN/keys never logged; secrets zeroed after use; one decrypt error message genericized |
| Revocation & chain validation correct | **Fixed** — CA-forgery vector closed, revoked certs can no longer be renewed, serials made unpredictable |
| Dependencies free of known vulns | **Fixed** — two reachable vulnerabilities remediated; `govulncheck` clean |

## Findings and dispositions

Severity uses CRITICAL / HIGH / MEDIUM / LOW. "Fixed" findings have regression
tests or an integration check where practical.

### Fixed

| # | Sev | Finding | Fix |
|---|-----|---------|-----|
| F1 | CRITICAL | **CA signing keys were not provably non-extractable.** PKCS#11 private-key templates set `CKA_SENSITIVE` but omitted `CKA_EXTRACTABLE=false` and `CKA_PRIVATE=true`; on tokens whose defaults are permissive (SoftHSM included) a CA private key could be wrapped/exported — breaking the core invariant. | `internal/pki/signer.go`: all key templates now set `CKA_PRIVATE=true`, `CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`, and least-privilege `CKA_SIGN=true`/`CKA_DECRYPT=false`/`CKA_UNWRAP=false`. Verified on SoftHSM by the e2e suite. |
| F2 | CRITICAL | **CSR-driven CA forgery.** The legacy `POST /api/keys/{id}/sign-x509` path copied `csr.Extensions` verbatim, letting any principal with signing rights request a BasicConstraints `CA:TRUE` (or `keyCertSign`) extension and mint a subordinate CA under the trust anchor. | `internal/pki/x509.go`: raw CSR extensions are no longer copied; the template is forced to a leaf (`IsCA=false`, explicit `cA=FALSE`). Only subject and parsed SANs are honored. Regression test `TestSignX509CertificateRejectsCAForgery`. |
| F3 | CRITICAL | **Broken access control on read endpoints.** CA inventory, issued/revoked certificates, group membership, and restriction-set policy were reachable by any authenticated principal — including one holding **no** role. | `internal/handlers`: added `canRead` (deny-by-default; any of admin/issuer/auditor) and gated `ListCAs`, `GetCA`, `GetPublicKey`, `GetCAChildren`, `ListIssuedCertificates`, `ListRevokedCertificates`, `ListGroups`, `GetGroupMembers`, `ListAllRestrictionSets`, `ListRestrictionSets`, `ParseCSR`. |
| F4 | HIGH | **Revoked certificates could be renewed**, silently resurrecting a withdrawn identity (e.g. after key compromise). | `internal/ca/issue.go`: `RenewCertificate` now rejects renewal when the revocation store (authoritative) or the cached status shows the serial is revoked. Regression test `TestRenewRejectsRevokedCertificate`. |
| F5 | HIGH | **Predictable serial numbers.** Leaves used a sequential counter (1, 2, 3…), removing the RFC 5280 / CA-B-Forum entropy defense against chosen-prefix collisions. | `internal/ca/issue.go`: leaves now get 128-bit `crypto/rand` serials (`newSerial`). Regression test `TestLeafSerialsAreHighEntropy`. |
| F6 | HIGH | **Cleartext HTTP fallback.** Without TLS the server silently served the whole API (bearer tokens, basic-auth root, secret ops) over plaintext, gated only by a log warning. | `cmd/server/main.go`: fail-closed — refuses to start without TLS unless the operator explicitly sets `SECSY_ALLOW_INSECURE_HTTP=1` (for a trusted TLS-terminating proxy). |
| F7 | HIGH | **RBAC roles from an unverified email claim.** Email-keyed role assignments were honored even if the IdP had not verified the email, letting a user with a settable email claim another principal's roles. | `internal/auth/oidc.go` + `cmd/server/main.go`: email-keyed assignments are applied only when `email_verified` is true; subject- and group-based assignments are always trusted. |
| F8 | HIGH | **Two reachable dependency vulnerabilities**: `golang.org/x/crypto` SSH DoS (GO-2026-5018) and `go-jose/v4` JWE decryption panic (GO-2026-4945, on the OIDC verify path). | Upgraded `golang.org/x/crypto` v0.49.0 → v0.52.0 and `go-jose/v4` v4.1.3 → v4.1.4. `govulncheck ./...` now reports no vulnerabilities. |
| F9 | HIGH | **Audit-log head deletion / re-genesis undetected.** The hash chain caught modification and mid-log deletion, but a full-log verify did not require the log to start at genesis, so head-truncation or a full wipe-and-restart verified clean. | `internal/audit/audit.go`: added `VerifyFullChain` (requires seq 1 + genesis prev-hash); `VerifyEventChain` uses it. Regression test `TestVerifyFullChainDetectsHeadDeletion`. See residual note on tail-truncation below. |
| F10 | MEDIUM | **RSA key floor was 1024 bits.** | `internal/pki/keygen.go`: minimum raised to 2048. |
| F11 | MEDIUM | **Secret decrypt returned the underlying error** (`"decryption failed: %v"`), a mild format/decryption oracle distinguishing bad-envelope from auth failure. | `internal/handlers/secret.go`: returns a fixed `"decryption failed"` with no detail (client and audit both). |
| F12 | MEDIUM | **No request body-size limit** on most handlers (memory-exhaustion DoS). | `cmd/server/main.go`: global 8 MiB `MaxBytesReader` wrapper; the secret endpoints keep their tighter caps. |

### Verified secure (no change needed)

- **HSM private-key confinement (KEK & sign/decrypt paths).** The secret KEK
  template already sets `CKA_SENSITIVE`/`CKA_EXTRACTABLE=false`/`CKA_PRIVATE`
  with `CKA_SIGN=false` least privilege. No code path reads back, serializes, or
  logs private key material; signing and unwrapping run on-device via `C_Sign` /
  `C_Decrypt`.
- **PIN handling.** PIN is read from config (`pkcs11.pin`) or `SECSY_USER_PIN`
  and passed directly to `C_Login`; it is never logged, never placed in an error
  string, and no `String()`/marshal path dumps the config struct.
- **Authenticated encryption.** Envelope uses AES-256-GCM (confidentiality +
  integrity) with the version, both algorithm identifiers, KEK label, and any
  caller context length-prefixed into the GCM AAD; unknown versions/algorithms
  are rejected; DEK + nonce are fresh per message; DEKs are zeroed after use.
- **No PKCS#1 v1.5 decryption** anywhere (avoids the Bleichenbacher class); DEK
  wrapping is RSA-OAEP only.
- **Randomness.** `crypto/rand` everywhere; no `math/rand`.
- **SQL** is fully parameterized; no command injection from HTTP input; software
  key-provider labels are path-traversal guarded.
- **Constant-time** root-credential comparison (`subtle.ConstantTimeCompare`).
- **OCSP/CRL** are HSM-signed with correct `thisUpdate`/`nextUpdate`, monotonic
  CRL numbers, and correct good/revoked/unknown status; the public CRL/OCSP
  endpoints are intentionally unauthenticated (revocation data is public).
- **Write-side RBAC** is fail-closed (deny for nil/role-less users).

## Residual risks & recommendations (accepted / follow-up)

These were assessed and consciously deferred (lower severity or requiring
deployment-specific configuration). They are documented here so operators can
make an informed decision.

1. **Audit-log tail truncation.** Even with `VerifyFullChain`, deleting the
   *newest* entries cannot be detected from the log alone. The production
   mitigation already exists: the HSM audit log is Ed25519-signed and anchors a
   `last_hash` (see `cmd/verify`). For the application event log, periodically
   anchor the current `(seq, hash)` out-of-band (e.g. sign it with the HSM) if
   you need tail-truncation detection.
2. **Software key-provider at rest.** In the no-HSM/dev backend, CA and KEK
   private keys are stored as unencrypted PKCS#8 PEM (files `0600`, dir `0700`).
   This is the documented dev/CI fallback — **use a real HSM (or PKCS#11 token)
   in production**; see [HSM migration](hsm-migration.md).
3. **OCSP nonce (RFC 6960 §4.4.1) is not echoed**, so a captured "good" response
   is replayable until `nextUpdate` (24 h). Consider shortening OCSP validity or
   adding nonce echo for high-assurance deployments.
4. **Issued leaves carry no CRL Distribution Point / OCSP AIA.** The CRL/OCSP
   services exist but issued certs don't advertise them, so relying parties must
   be told where to check revocation out-of-band. Populate `CRLDistributionPoints`
   / `OCSPServer` from config when a public base URL is available.
5. **`X-Forwarded-For` is trusted for the audit source IP.** Only meaningful
   behind a trusted proxy; do not expose the server directly if you rely on the
   logged IP for forensics.
6. **`writeError` returns internal error strings on 5xx.** Aids reconnaissance
   (DB/HSM/path detail). Current messages are non-secret; consider generic 5xx
   client messages with detail logged server-side only.
7. **RSA signatures use PKCS#1 v1.5** (not PSS). Standard and acceptable; PSS is
   preferable for new deployments.
8. **Root basic-auth is enabled by default.** A standing superuser credential
   (constant-time compared, never logged). Disable it in production via
   `policy.allow_root_basic_auth: false` once OIDC + RBAC is in place.

## Verification

Run from `server/`:

```console
# Static analysis and unit tests (no HSM needed)
$ go build ./... && go vet ./... && go test ./...

# Dependency vulnerability scan — expect "No vulnerabilities found."
$ go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Full HSM-backed end-to-end flow against SoftHSM (one command, from repo root)
$ ./scripts/integration-test.sh
```

The security regression tests added by this review:

- `internal/pki` → `TestSignX509CertificateRejectsCAForgery` (F2)
- `internal/ca` → `TestRenewRejectsRevokedCertificate` (F4),
  `TestLeafSerialsAreHighEntropy` (F5)
- `internal/audit` → `TestVerifyFullChainDetectsHeadDeletion` (F9)

Non-extractability of HSM CA keys (F1) is exercised by the SoftHSM e2e suite,
which generates CA keys with the hardened templates and completes the full
issue → verify → revoke → CRL/OCSP → encrypt/decrypt flow.
