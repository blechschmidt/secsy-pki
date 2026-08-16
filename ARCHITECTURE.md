# secsy-pki — Architecture

> This document has two parts:
>
> - **[Part I — Current architecture](#part-i--current-architecture)** describes
>   the enterprise system as it stands on the `enterprise` branch: an HSM-backed
>   X.509 + SSH certificate authority with envelope-based secret encryption,
>   multi-protocol enrollment, governance, and multi-tenant/HA operation.
> - **[Part II — Original starting-point audit](#part-ii--original-starting-point-audit-historical)**
>   preserves the day-one gap analysis (commit `32d368c`, 2026-07-02) that scoped
>   the work. Every "gap" it lists has since been built; it is kept for historical
>   context only and is **not** an accurate description of the current code.
>
> The load-bearing design decisions are recorded as
> [Architecture Decision Records](docs/adr/README.md); day-2 procedures are in the
> [operator runbook](docs/operations/runbook.md); per-feature guides are in
> [`docs/`](docs/README.md).

---

# Part I — Current architecture

## What secsy-pki is today

secsy-pki is a **full-featured, HSM-backed enterprise PKI and secret-encryption
platform**. CA (and TSA, OCSP-delegate, SSH-CA, code-signing) private keys are
generated **on-device and never extractable** ([ADR 0002](docs/adr/0002-hsm-non-extractability-invariants.md));
every key operation is routed through a backend-agnostic **key-provider
abstraction** ([ADR 0001](docs/adr/0001-key-provider-abstraction.md)) that speaks
PKCS#11 (SoftHSM/YubiHSM/network HSM), a cloud KMS (AWS KMS / Azure Key Vault),
HashiCorp Vault Transit, or an on-disk software keystore for dev. Everything sits
behind RBAC, a hash-chained tamper-evident audit log, and fail-closed
pre-issuance policy gates ([ADR 0003](docs/adr/0003-fail-closed-security-gates.md)).

It delivers, in one deployment:

- **X.509 lifecycle** — root/intermediate hierarchy, profile-driven issuance,
  renewal/rekey, revocation, reversible suspend/hold, CRL (base/delta/sharded),
  and OCSP (nonce, delegated responder, pre-signing/CDN offload).
- **Enrollment protocols** — ACME (RFC 8555, incl. ARI, Profiles, http-01/dns-01/
  tls-alpn-01, EAB, device-attest), SCEP, EST, CMP (RFC 9483), and BRSKI
  (RFC 8995) zero-touch onboarding.
- **SSH CA** — HSM-backed OpenSSH user/host certificates with KRL revocation.
- **Secret encryption** — HSM-backed envelope encryption of passwords/secrets,
  with KEK rotation, versioning/TTL, and M-of-N key escrow/recovery.
- **Governance** — organization RBAC, four-eyes/maker-checker approvals
  ([ADR 0006](docs/adr/0006-four-eyes-approval-gate.md)), strong operator authn
  (OIDC + mTLS + WebAuthn step-up), native scoped API tokens, multi-tenant
  isolation with per-tenant quotas, and SIEM audit export + RFC 3161 audit
  anchoring.
- **Assurance & compliance** — pre-issuance CA/B-Forum linting (hand-rolled +
  optional zlint), Certificate Transparency (SCT embedding **and** inclusion-proof
  monitoring), CAA (RFC 8659 + 8657), Name Constraints / certificate policies,
  FIPS 140-3 build mode, and PQC/hybrid (ML-DSA) certificates.
- **Operations** — Prometheus metrics + Grafana/alerts, health/readiness probes,
  OpenTelemetry tracing, expiry monitoring + auto-renewal, an issuance canary,
  external cert discovery, scheduled encrypted backups + restore-verification,
  leader-elected background jobs for multi-replica HA, and a `secsy-ca doctor`
  preflight.

Core value proposition, unchanged since day one but now realized end-to-end:
*auditable certificate and secret operations where you can prove, cryptographically,
that the signing key was born on hardware, never left it, and was used only as the
tamper-evident log records.*

## Module layout

```
server/
  cmd/
    server/       HTTP/gRPC API server + embedded console (main entrypoint)
    secsy-ca      CA + certificate/SSH/TSA/signing lifecycle CLI
    secsy-secret  HSM-backed secret encryption + escrow CLI
    secsy-agent   Host auto-enrollment daemon (EST/ACME client)
    secsy-ssh     OIDC SSH client wrapper (login → sign → exec ssh)
    verify        Offline HSM audit-log / bijection verifier
  internal/
    Crypto & keys:  pki, keyprovider, hsm, fips
    CA & issuance:  ca, certlint, caa, nameconstraints, certpolicy, ct, ctmonitor,
                    pqc, spiffe, pkcs12
    Revocation:     (ca/crl, ca/ocsp), publish
    Secret layer:   secret
    Enrollment:     acme, scep, est, cmp, brski, cms, attestation
    SSH CA:         sshca
    Signing/time:   tsa, signing, anchor
    Governance:     rbac, authn, auth, approval, issueapproval, multi-tenancy (in
                    ca/models/database), middleware
    Persistence:    database, models
    Operations:     monitor, canary, discovery, backup, leader, ratelimit,
                    metrics, tracing, doctor, siem, report, dnsrecords
    API & UI:       handlers, grpcapi, console
    Test harness:   e2e, chaos, interop
  web/static/       Legacy Bootstrap SPA (Keys/Sign/HSM);  the enterprise console
                    is internal/console (embedded at /console/)
terraform/          HSM key provisioning via terraform-provider-pkcs11
deploy/, Dockerfile Helm chart, container image, Grafana/Prometheus assets
docs/               Per-feature guides, grouped by topic; each folder has an
                    index and docs/README.md is the map:
    hsm/            Key providers: PKCS#11, cloud KMS, Vault, ceremony, attestation
    ca/             CA hierarchy, certificate lifecycle, rotation, SSH CA
    issuance/       Fail-closed pre-issuance gates (lint, CAA, name constraints, CT)
    certificates/   Specialized profiles: S/MIME, smartcard, eIDAS, SPIFFE, PQC
    protocols/      ACME, SCEP/EST, BRSKI, Windows autoenrollment, agent, gRPC
    signing/        Artifact signing, RFC 3161 TSA, trusted time, evidence records
    secrets/        Envelope encryption, escrow, crypto service
    security/       RBAC, authn, approvals, tenancy, rate limiting, FIPS, SIEM
    deployment/     Kubernetes, persistence, multi-replica HA, serving TLS
    operations/     Runbook, incident response, observability, backups, console
    compliance/     RFC 3647 CP/CPS, CA/B Forum + WebTrust control mapping
    development/    Benchmarks, coverage, fuzzing, chaos, authz matrix, supply chain
    adr/            Architecture Decision Records
```

## Subsystem map

| Subsystem | Packages | Guide |
|---|---|---|
| Key handling (HSM/KMS/Vault/software) | `keyprovider`, `pki`, `hsm` | [HSM config](docs/hsm/configuration.md) · [Cloud KMS](docs/hsm/cloud-kms.md) · [Vault Transit](docs/hsm/vault-transit.md) |
| CA hierarchy & issuance | `ca`, `models` | [Certificate authority](docs/ca/overview.md) |
| Pre-issuance policy gates (fail-closed) | `certlint`, `caa`, `nameconstraints`, `certpolicy` | [certlint](docs/issuance/certlint.md) · [CAA](docs/issuance/caa.md) · [Name constraints](docs/issuance/name-constraints.md) |
| Transparency | `ct` (embedding), `ctmonitor` (inclusion) | [Certificate Transparency](docs/issuance/certificate-transparency.md) |
| Revocation (CRL/OCSP + offload) | `ca` (crl/ocsp), `publish` | [CA](docs/ca/overview.md) · [OCSP presign/publish](docs/operations/ocsp-presign-publish.md) |
| Secret encryption + escrow | `secret` | [Password/secret encryption](docs/secrets/password-encryption.md) |
| Enrollment protocols | `acme`, `scep`, `est`, `cmp`, `brski`, `cms`, `attestation` | [ACME](docs/protocols/acme.md) · [SCEP/EST](docs/protocols/scep-est.md) · [CMP](docs/operations/runbook.md#cmp) · [BRSKI](docs/protocols/brski.md) |
| SSH CA | `sshca` | [SSH CA](docs/ca/ssh-ca.md) |
| Time / signing / anchoring | `tsa`, `signing`, `anchor` | [Timestamping](docs/signing/timestamping.md) · [Artifact signing](docs/signing/artifact-signing.md) |
| Governance (RBAC/authn/approvals/tenancy) | `rbac`, `authn`, `auth`, `approval`, `issueapproval` | [RBAC & audit](docs/security/rbac-and-audit.md) · [Authentication](docs/security/authentication.md) · [Approvals](docs/security/approvals.md) · [Multi-tenancy](docs/security/multi-tenancy.md) |
| Audit & SIEM | `audit` (in database), `siem`, `anchor` | [SIEM export](docs/security/audit-siem-export.md) |
| Persistence | `database`, `models` | [Persistence](docs/deployment/persistence.md) |
| Multi-replica HA | `leader` + leader-gated jobs | [High availability](docs/deployment/high-availability.md) |
| Operations & observability | `monitor`, `canary`, `discovery`, `backup`, `ratelimit`, `metrics`, `tracing`, `doctor`, `report`, `dnsrecords` | [Observability](docs/operations/observability.md) · [Expiry](docs/operations/expiry-monitoring.md) · [Canary](docs/operations/canary.md) · [Backup](docs/operations/backup.md) · [Rate limiting](docs/security/rate-limiting.md) · [DANE/SSHFP](docs/operations/dns-records.md) |
| API & console | `handlers`, `grpcapi`, `console` | [gRPC](docs/protocols/grpc-api.md) · [Web console](docs/operations/web-console.md) |
| Assurance modes | `fips`, `pqc` | [FIPS](docs/security/fips.md) · [PQC](docs/certificates/pqc.md) |

## Cross-cutting invariants

These hold across every path and are the things not to regress (see
[security review](docs/security/security-review.md) and the ADRs):

1. **HSM key non-extractability** — private keys are generated on-device and never
   exported; the software/PQC paths are the explicit, documented exceptions.
   ([ADR 0002](docs/adr/0002-hsm-non-extractability-invariants.md))
2. **Every key op goes through `keyprovider`** — no direct PKCS#11 in feature code;
   this is what makes HSM/KMS/Vault/software interchangeable.
   ([ADR 0001](docs/adr/0001-key-provider-abstraction.md))
3. **Security gates fail closed** — TLS, certlint, CAA, name constraints, and
   attestation refuse rather than issue when they cannot confirm authorization;
   CT is the one per-profile fail-open opt-in.
   ([ADR 0003](docs/adr/0003-fail-closed-security-gates.md))
4. **Tamper-evident audit** — the hash-chained `event_log` proves internal
   consistency; RFC 3161 anchoring + SIEM export guard against truncation/rewrite.
5. **Dual control where it matters** — sensitive admin/issuance operations route
   through the enumerated-class four-eyes chokepoint.
   ([ADR 0006](docs/adr/0006-four-eyes-approval-gate.md))
6. **Tenant isolation** — CAs, profiles, revocation, secrets, RBAC, and audit are
   tenant-scoped; cross-tenant access is denied.
7. **Multi-replica singleton jobs are leader-gated** — every background loop
   (monitor, rotation, presign, publish, anchoring, SIEM, discovery, CT inclusion,
   backup/verify) runs under PostgreSQL advisory-lock leader election, never a
   bare goroutine.

## Recent additions (Tasks 79–98)

Where the most recently-added capabilities live, for orientation:

| Feature | Package(s) | Guide |
|---|---|---|
| ACME tls-alpn-01 (RFC 8737) | `acme/tlsalpn.go` | [ACME §3](docs/protocols/acme.md#3-challenge-types-http-01-dns-01-tls-alpn-01) |
| PKCS#12 export | `pkcs12` | [PKCS#12](docs/ca/pkcs12.md) |
| Four-eyes approvals | `approval`, `issueapproval` | [Approvals](docs/security/approvals.md) · [ADR 0006](docs/adr/0006-four-eyes-approval-gate.md) |
| Suspend/hold + release | `ca` | [CA §6](docs/ca/overview.md) |
| Inventory pagination/filter/search | `handlers/pagination.go`, `database/pagination.go` | [CA §4a](docs/ca/overview.md) |
| Per-profile issuance-approval gate | `issueapproval` | [Approvals](docs/security/approvals.md) |
| Static-analysis gate | `.golangci.yml`, CI | [Testing](TESTING.md#static-analysis-lint--vet) |
| Native API tokens | `authn` | [Authentication](docs/security/authentication.md#4-native-scoped-api-tokens-service-accounts) |
| BRSKI onboarding | `brski` | [BRSKI](docs/protocols/brski.md) |
| Optional zlint backend | `certlint` (`-tags zlint`) | [certlint](docs/issuance/certlint.md) |
| Scheduled backups + restore-verify | `backup` | [Backup](docs/operations/backup.md) |
| Vault Transit keyprovider | `keyprovider` (kms/vault) | [Vault Transit](docs/hsm/vault-transit.md) |
| CT inclusion monitoring | `ctmonitor` | [CT §inclusion](docs/issuance/certificate-transparency.md#inclusion-proof-monitoring-post-issuance) |
| RFC 8657 CAA (accounturi/methods) | `caa` | [CAA](docs/issuance/caa.md) |
| Shared ACME nonce store | `acme` | [ACME §nonces](docs/protocols/acme.md) |
| DANE TLSA / SSHFP records | `dnsrecords` | [DANE/SSHFP](docs/operations/dns-records.md) |

---

# Part II — Original starting-point audit (historical)

> The remainder of this document is the **day-one audit** (commit `32d368c`,
> 2026-07-02) preserved verbatim. It scoped the enterprise work as a gap analysis;
> **every gap below has since been built** (see Part I). Read it as history, not as
> a description of the current system.

---

## 1. What secsy-pki is today

secsy-pki is an **HSM-backed SSH and X.509 Certificate Authority** with a web UI,
OIDC authentication, per-CA fine-grained permissions, and a cryptographically
verifiable audit trail anchored in a YubiHSM 2 hardware hash chain.

CA private keys live inside an HSM and are accessed via **PKCS#11**; they are
generated on-device and never exported. Every signing operation is recorded both
in an application audit log (database) and, on YubiHSM, in the device's internal
signed hash chain, which can be verified offline.

Core value proposition today: *auditable certificate issuance where you can
prove, cryptographically, that the CA key was born on hardware, never left it,
and signed exactly the certificates in the log.*

---

## 2. Module layout

```
server/
  cmd/
    server/        HTTP API server (main entrypoint)
    secsy-ssh/     Client-side SSH wrapper: OIDC login → sign → in-memory cert → exec ssh
    verify/        Offline audit-log verifier (hash chain, Ed25519 sig, attestation chain)
  internal/
    pki/           Crypto core
      keygen.go    Software key generation (RSA / ECDSA / Ed25519) → OpenSSH format
      signer.go    PKCS11Signer: crypto.Signer over an HSM key; on-HSM keygen; PKCS#11 URIs
      ssh.go       SSH certificate signing (user/host, principals, extensions, critical opts)
      x509.go      X.509 certificate signing from a CSR
    keyprovider/   Backend-agnostic key provider abstraction (Task 4)
      keyprovider.go  Provider/Signer interfaces, Config, New() selector, key-type normalization
      software.go  SoftwareProvider: on-disk PKCS#8 keystore (keys never exported)
      pkcs11.go    PKCS11Provider: delegates to pki.PKCS11Signer / pki.GenerateKeyOnHSM
    yubihsm/       Native YubiHSM 2 driver: SCP03 secure channel over direct USB
                   (Linux usbfs) or a yubihsm-connector; no vendor binaries, no cgo
    hsm/
      yubihsm.go   YubiHSM 2 ops on that driver: audit log, attestation, provisioning, reset
    handlers/      HTTP API (handlers.go), OpenAPI spec (openapi.yaml / openapi.go)
    config/        YAML config loading (incl. key_provider selection + SECSY_* env overrides)
    database/      SQLite + PostgreSQL, schema migration, all persistence
    auth/          OIDC provider / token verification
    middleware/    auth.go (basic + bearer), audit.go (access log)
    models/        Domain types: CA, Permission, RestrictionSet, audit records
  web/static/      Bootstrap 5 SPA (Keys, Sign, Groups, Permissions, Restrictions, Audit, HSM)
terraform/         Provisions HSM keys via a custom terraform-provider-pkcs11 (YubiHSM/SoftHSM)
.github/workflows/ CI: integration tests against SoftHSM2 + Keycloak (Docker Compose)
```

**Dependency stack:** Go 1.25.7; `github.com/miekg/pkcs11` v1.1.2 (HSM access);
`github.com/coreos/go-oidc/v3` (OIDC); `golang.org/x/crypto` (SSH/crypto);
`lib/pq` + `mattn/go-sqlite3` (DB); `google/uuid`. No HSM connector library is
vendored — the runtime relies on a system PKCS#11 module (`yubihsm_pkcs11.so` in
production, `libsofthsm2.so` in CI/tests).

---

## 3. Key handling & storage

| Concern | Current behavior |
| --- | --- |
| CA private keys | HSM-resident only, referenced by a PKCS#11 URI stored in the `cas` table. Accessed through `PKCS11Signer` (implements `crypto.Signer`). Never exported. |
| On-HSM keygen | `pki.GenerateKeyOnHSM` creates Ed25519 / ECDSA P-256/384/521 / RSA 2048/4096 keypairs on the device and returns the URI + SSH public key. |
| Signing | `PKCS11Signer.Sign` dispatches to `CKM_EDDSA` / `CKM_ECDSA` (r‖s → ASN.1 DER) / `CKM_RSA_PKCS` (with DigestInfo prefix). |
| Software keygen | `pki.GenerateKey` produces RSA/ECDSA/Ed25519 keys in OpenSSH format for clients; returned to caller, **not persisted**. |
| Session model | One PKCS#11 session per signer instance; no pooling. |
| Key export / wrap | Not implemented. PKCS#11 and YubiHSM wrap/unwrap opcodes exist as constants only. No backup / migration path. |

---

## 4. Certificate issuance

**SSH (`pki.SignSSHCertificate`, handler `POST /api/keys/{id}/sign`)**
- User/host certs, custom principals, validity window, extensions, critical
  options; random 64-bit serial; default user extensions (`permit-pty`, etc.).
- **Restriction sets are enforced** here via `enforceRestrictions` (deny-all,
  allowed principals/cert-types, extension allow/deny, critical-option deny,
  max validity, max valid-after offset, force-email key ID, require-reason).

**X.509 (`pki.SignX509Certificate`, handler `POST /api/keys/{id}/sign-x509`)**
- Parses & validates a PKCS#10 CSR; copies subject DN + SANs + extensions;
  random 128-bit serial; `KeyUsage = DigitalSignature`; validity `now .. valid_before`.
- Permission (`SIGN_CERTIFICATE`) **is** checked, but **restriction sets are NOT
  enforced** on this path (no `enforceRestrictions` equivalent — see gaps).
- The "issuer" template is `&x509.Certificate{PublicKey: caPub}` with **no
  issuer DN, no BasicConstraints/IsCA, no path length** — so it does not model a
  real CA certificate or a chain.

**CA hierarchy:** the `cas` table has `parent_id` and the `CA` model supports it,
but there is **no logic** that builds issuer→subject DN chains, sets CA basic
constraints, or enforces path length. Hierarchy is schema-only today.

**Revocation:** none. No CRL generation, no OCSP responder, no revoked-cert
store, no CRL distribution point / AIA extensions. (`RevokePermission` is
unrelated — it revokes *access-control grants*, not certificates.)

---

## 5. HSM / PKCS#11 integration

Two distinct paths coexist:

1. **`internal/pki/signer.go`** — the live signing path, using `miekg/pkcs11`
   directly. Generic across any PKCS#11 token (works with SoftHSM and YubiHSM).
2. **`internal/hsm/yubihsm.go`** — YubiHSM-2-specific management on top of the
   native driver in **`internal/yubihsm`**: factory reset, **forced-audit
   provisioning**, audit-log fetch / consume / hash-chain verification, device +
   key **attestation** certs, and Ed25519 signing of the last audit hash for
   offline proof. These are vendor commands with no PKCS#11 equivalent.

   The driver speaks the device's own protocol — a GlobalPlatform SCP03 secure
   channel carried over direct USB bulk transfers (Linux usbfs) or a
   yubihsm-connector — so no vendor binary is on the path of evidence the audit
   subsystem later has to stand behind. It replaced a layer that drove
   `yubihsm-shell` and recovered results by regular expression over its output,
   which mattered because that binary exits 0 even when a scripted command is
   rejected: a refused option write read as a success.

The verifier binary (`cmd/verify`) validates the full chain: HSM hash chain →
Ed25519 signature over the last hash → attestation cert → device cert → Yubico
root/intermediate, plus a bijection check between HSM sign operations and issued
certificates.

**Testing:** CI uses **SoftHSM2** (token init, EC P-256 key via `pkcs11-tool`)
with Keycloak for OIDC, driven by `docker-compose.test.yaml`. YubiHSM-specific
tests are behind a `yubihsm` build tag and skipped in CI. This SoftHSM baseline
is what Task 3 will build on.

---

## 6. API, auth & persistence (summary)

- **Auth:** HTTP Basic (root user, config-defined, constant-time compare) **or**
  OIDC bearer token (`sub`/`email`/`name` claims). Root bypasses all checks.
- **Authorization:** per-CA permissions `SIGN_CERTIFICATE`, `MANAGE_PERMISSIONS`,
  `CONFIGURE_CA`, grantable to users or groups. Effective restriction set
  resolves user-specific → group → CA default.
- **API surface:** CA CRUD + public-key export; SSH & X.509 signing + CSR parse;
  groups & members; permissions grant/revoke; restriction-set CRUD + defaults;
  application audit log + access log; HSM info / attestation / audit-log /
  signed / combined / provision / factory-reset; `/api/me`, `/api/health`,
  `/api/auth/config`. A complete OpenAPI 3.1 spec is served at `/openapi.json`
  (and `/openapi.yaml`), rendered as Redoc at `/docs` (Swagger UI at `/api/docs`);
  a generated, typed Go client SDK lives in `server/pkg/client`.
- **Database tables:** `cas`, `groups_`, `group_members`, `permissions`,
  `restriction_sets` (+ `ssh_restriction_details`, `x509_restriction_details`),
  `audit_log`, `access_log`, `hsm_audit_entries`. Built-in permit-all / deny-all
  restriction sets for SSH and X.509. Cert dedup via a `(ca_id, cert_hash)`
  unique constraint. SQLite (dev) / PostgreSQL (prod).
- **Audit:** every sign op → `audit_log` (linked to the HSM entry via
  `sign_audit_id`); every protected request → `access_log`. Application audit log
  is not itself cryptographically signed (the HSM chain provides that).

---

## 7. Gap analysis — toward HSM-backed enterprise PKI + password encryption

Priority: **P0** = required for the stated goal, **P1** = important for
"enterprise", **P2** = hardening/nice-to-have. Task numbers reference the project
plan.

### CA hierarchy (P0 — Task 5)
- No root/intermediate modeling: X.509 issuance ignores `parent_id`, sets no
  issuer DN, no `IsCA`/BasicConstraints, no path length.
- **Needed:** self-signed root CA creation; intermediate CA issuance signed by a
  parent; proper issuer DN chaining; BasicConstraints (`CA=true`, pathlen);
  Subject Key Identifier / Authority Key Identifier; certificate chain assembly &
  export (`GET .../chain`).

### Certificate lifecycle: issuance / renewal / revocation (P0 — Task 6)
- X.509 issuance does not honor restriction sets (key usages, ext key usages,
  SAN types/patterns, subject-field allow-list, `max_path_length`, `deny_ca` are
  defined in the model but never enforced) — **enforcement parity with SSH is
  missing**.
- No renewal / re-key workflow.
- No revocation at all: **needed** — revoked-cert store, CRL generation & signing
  (HSM-backed), CRL distribution point + AIA extensions, and an OCSP responder.

### Key storage abstraction (P0 — Task 4) — **DONE**
- Signing was hard-wired to `PKCS11Signer` with no backend interface.
- **Resolved:** `internal/keyprovider` introduces a `Provider` interface
  (GenerateKey / FindKey / Signer / PublicKey / Close) plus a `Signer`
  (`crypto.Signer` + `Close`). Two implementations ship: `SoftwareProvider`
  (on-disk PKCS#8 keystore; private keys never leave the server) and
  `PKCS11Provider` (delegates to the existing, HSM-tested `pki` code). The
  backend is chosen by `key_provider.type` in config, defaulting to `pkcs11`
  when a module is set and overridable via `SECSY_*` env vars. Handlers
  (`CreateCA`, `SignCertificate`, `SignX509Certificate`) now go through the
  provider, so all backends are pluggable. A latent session leak in
  `NewPKCS11Signer` (post-login error paths) was fixed as part of this work —
  it was breaking consecutive SoftHSM operations with
  `CKR_USER_ALREADY_LOGGED_IN`.

### PKCS#11 integration breadth (P0/P1 — Tasks 3–4)
- Currently validated against SoftHSM only in CI, YubiHSM behind a build tag.
- **Needed:** SoftHSM as a first-class, documented test backend (Task 3);
  generalize the YubiHSM-shell-specific audit features or make them optional so
  the core works on any PKCS#11 module; session pooling.

### Password / data encryption feature (P0 — Task 7) — **entirely absent**
- No encryption/decryption feature exists anywhere in the codebase (no symmetric
  ops, no envelope encryption, no password vault).
- **Needed:** HSM-backed encryption — e.g. an HSM-resident wrapping key (AES/RSA)
  used for envelope encryption of secrets/passwords; API + UI for encrypt/decrypt
  or store/retrieve; per-secret access control tied to the existing permission
  model; audit entries for decrypt operations.

### Enterprise features (P1 — Task 8)
- Authorization is per-CA only; no org-wide **RBAC roles**, no admin delegation
  model beyond the single root basic-auth user, no root-credential rotation.
- Application audit log is not tamper-evident on its own; access log lacks export
  hardening. **Needed:** richer RBAC, structured/centralizable audit logging,
  config management (secrets not in plaintext YAML), MFA-capable OIDC.

### Operational hardening (P2 — Tasks 10, 12)
- No rate limiting / quotas on signing; no DB replication/HA guidance; no
  certificate templates/profiles; no batch operations; no notifications/webhooks.
- CSR content is trusted as-is on the X.509 path (policy validation missing —
  overlaps with the restriction-enforcement gap above).

### Summary table

| Capability | Today | Target | Gap size |
| --- | --- | --- | --- |
| HSM key gen + signing (PKCS#11) | ✅ (SoftHSM/YubiHSM) | ✅ pluggable backend | small |
| SSH cert issuance + restriction enforcement | ✅ | ✅ | done |
| X.509 cert issuance | ⚠️ flat, no policy enforcement | full CA-aware issuance | medium |
| CA hierarchy (root/intermediate/chain) | ❌ schema only | ✅ | large |
| Revocation (CRL / OCSP) | ❌ | ✅ | large |
| Key-store abstraction / pooling | ❌ hard-wired | ✅ | medium |
| Password / data encryption | ❌ none | ✅ HSM-backed envelope | large |
| Enterprise RBAC / audit / config mgmt | ⚠️ per-CA perms + basic audit | ✅ | medium |
| SoftHSM test environment | ⚠️ CI only | ✅ documented, first-class | small |

---

## 8. Recommended next steps (aligned to the task plan)

1. **Task 3** — Stand up a documented SoftHSM dev/test environment reusing the CI
   token setup as the local baseline.
2. **Task 4** — Introduce a `Signer`/`KeyStore` abstraction with session pooling;
   route SSH + X.509 signing through it.
3. **Task 5** — Implement real root/intermediate CA issuance (issuer DN, basic
   constraints, path length, chain export) on top of the abstraction.
4. **Task 6** — Add X.509 restriction enforcement + renewal + revocation
   (revoked store, HSM-signed CRL, OCSP).
5. **Task 7** — Build the HSM-backed password/data encryption feature (envelope
   encryption under an HSM wrapping key) with its own API/UI and audit.
