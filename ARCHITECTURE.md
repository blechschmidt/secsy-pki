# secsy-pki — Architecture & Gap Analysis

> Status of this document: audit of the codebase as of the `enterprise` branch
> starting point (commit `32d368c`, 2026-07-02). It captures the **current**
> design and a gap analysis toward the project goal: a full-featured,
> **HSM-backed enterprise PKI and password/data encryption solution**, tested
> against SoftHSM.

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
    hsm/
      yubihsm.go   YubiHSM 2 ops via `yubihsm-shell`: audit log, attestation, provisioning, reset
    handlers/      HTTP API (handlers.go), OpenAPI spec (openapi.yaml / openapi.go)
    config/        YAML config loading
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
2. **`internal/hsm/yubihsm.go`** — YubiHSM-2-specific management, shelling out to
   `yubihsm-shell`: factory reset, **forced-audit provisioning**, audit-log fetch
   / consume / hash-chain verification, device + key **attestation** certs, and
   Ed25519 signing of the last audit hash for offline proof.

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
  `/api/auth/config`, Swagger at `/api/docs`.
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

### Key storage abstraction (P0 — Task 4)
- Signing is hard-wired to `PKCS11Signer`; there is no interface abstracting
  "key backend". **Needed:** a `KeyStore`/`Signer` abstraction so software,
  SoftHSM, YubiHSM (and future PKCS#11 tokens) are pluggable, with session
  pooling/lifecycle management and consistent error surfacing.

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
