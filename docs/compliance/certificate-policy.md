# Certificate Policy & Certification Practice Statement (CP/CPS)

> **RFC 3647 §** — combined Certificate Policy (CP) and Certification Practice
> Statement (CPS) for a Certification Authority operated with **secsy-pki
> (enterprise edition)**.

## About this document

This is a **template CP/CPS** structured according to
[RFC 3647](https://www.rfc-editor.org/rfc/rfc3647) (the IETF framework every
WebTrust / CA/Browser-Forum audit expects). It is populated from the **actual
secsy-pki implementation**: each subsection describes the *technical control the
software enforces*, and, where relevant, cites the package or file that
implements it. The companion
[compliance control mapping](compliance-mapping.md) traces individual
CA/Browser-Forum Baseline-Requirement clauses to the same code with an explicit
gaps column.

A CP/CPS is a legal and organizational document, not only a technical one. A
running CA is a *deployment* of secsy-pki operated by a specific organization
inside a specific facility under specific contracts — facts this repository
cannot know. Wherever the policy requires an organizational, physical, legal, or
procedural fact that the software cannot itself assert, the text uses an
explicit placeholder:

> **[OPERATOR: …]** — a fact the deploying organization MUST supply and formally
> adopt before this document describes a real, auditable CA.

Do **not** publish this file verbatim as your CA's policy. Complete every
`[OPERATOR: …]` placeholder, assign your registered policy OID(s), have it
reviewed by counsel and your auditor, and version it under change control.
Software capabilities are described in the present tense ("the CA signs on the
HSM"); they are accurate for a default enterprise build and verifiable against
the cited code.

- **Software version / scope:** secsy-pki enterprise branch (this repository).
- **Document status:** `[OPERATOR: draft | approved]`
- **Policy OID(s):** `[OPERATOR: your registered arc, asserted via profiles.*.policies — see §7.1.6]`
- **Effective date / version:** `[OPERATOR: …]`
- **Policy administration & approval authority (Policy Authority / PMA):** `[OPERATOR: …]`

---

## 1. Introduction

### 1.1 Overview

secsy-pki is an HSM-backed X.509 (and OpenSSH) Certification Authority with
envelope-based secret encryption, role-based access control, and a
tamper-evident audit log. The defining architectural property, from which the
rest of this policy follows, is that **CA private keys are generated inside a
hardware security module and never leave it** — there is no software path that
exports a CA private key
([ADR 0002](../adr/0002-hsm-non-extractability-invariants.md);
`internal/pki/signer.go`, `internal/keyprovider`).

The CA supports a hierarchy of one or more **root** CAs and subordinate
**intermediate** CAs, each backed by its own non-extractable HSM key. Roots
normally stay offline; day-to-day issuance is delegated to intermediates. End
entities are issued from named **issuance profiles** (§7.1) that pin key usage,
extended key usage, validity caps, and policy extensions, and every issuance
runs a **fail-closed pre-issuance gate pipeline** (§4.2) before any signature.

### 1.2 Document name and identification

This document is the *secsy-pki CP/CPS*. The CA MAY assert one or more
certificate-policy OIDs in issued certificates via a profile's `policies`
configuration (`internal/certpolicy`); those OIDs, and the CPS-URI pointer
carried alongside them, are the on-certificate identifiers that bind a leaf to
this document. **[OPERATOR: register a policy OID arc and record it here and in
`profiles.*.policies.oids`; set `policies.cps` to the published URL of this
document.]**

### 1.3 PKI participants

- **Certification Authorities.** The root and intermediate CAs operated by this
  deployment (`internal/ca`). Each has a non-extractable HSM key and issues per
  §4.
- **Registration Authority (RA) functions.** Identity/authorization validation
  is performed by the automated enrollment protocols and by human operators:
  ACME (RFC 8555, `internal/acme`), EST (RFC 7030, `internal/est`), SCEP
  (RFC 8894, `internal/scep`), CMP (RFC 9483, `internal/cmp`), and BRSKI
  (RFC 8995, `internal/brski`). Operator/API issuance is authorized through
  RBAC (§5.2). See §3 for the identity-validation each performs.
- **Subscribers.** Entities (servers, workloads, devices, people via S/MIME,
  SSH principals) that hold a certificate/key pair issued by the CA.
- **Relying parties.** Entities that validate certificates issued by the CA,
  including consuming the repository artifacts in §2.
- **Other participants.** Certificate Transparency logs (`internal/ct`),
  time-stamping authority (RFC 3161, `internal/tsa`), and any external HSM/KMS,
  MASA (BRSKI), or SIEM the deployment integrates. **[OPERATOR: name your
  chosen CT logs, HSM vendor/model, and SIEM.]**

### 1.4 Certificate usage

- **Appropriate uses.** Each profile constrains use through key usage / EKU
  (§7.1.2). Built-in profiles include `server` (TLS serverAuth), `client`
  (clientAuth/mTLS), `server-client`, `code-signing`, the `smime*` family
  (emailProtection), `spiffe-svid` (workload identity), and PQC/hybrid variants
  (`internal/ca/profile.go`).
- **Prohibited uses.** Any use inconsistent with a certificate's key usage / EKU
  and with **[OPERATOR: the CA's acceptable-use terms]**. Certificates issued
  from non-`Public` internal profiles are not publicly trusted and MUST NOT be
  represented as such.

### 1.5 Policy administration

- **Organization administering the CP/CPS:** `[OPERATOR: …]`
- **Contact / problem-report address:** `[OPERATOR: security@…, and the
  certificate-problem-report intake that feeds the revocation workflow in §4.9]`
- **CPS approval procedures:** `[OPERATOR: your Policy Authority review/approval
  and change-control process.]`

### 1.6 Definitions and acronyms

Standard PKI terminology (CA, RA, CSR, CRL, OCSP, HSM, EKU, SAN, SCT, MPIC) is
used as defined in RFC 5280, the CA/Browser Forum Baseline Requirements, and
RFC 6960/6962. Product-specific terms: **profile** (§7.1), **key provider**
(the HSM/KMS abstraction, [ADR 0001](../adr/0001-key-provider-abstraction.md)),
**pre-issuance gate** (§4.2), **audit anchor** (§5.5).

---

## 2. Publication and repository responsibilities

### 2.1 Repositories

The server publishes CA and revocation artifacts over its API, and can mirror
them to a static repository (directory or S3-compatible object store) for CDN
offload (`internal/publish`, [docs](../operations/ocsp-presign-publish.md)). Publication uses
an **atomic swap plus a SHA-256 integrity manifest** so relying parties never
read a half-written artifact.

### 2.2 Publication of certification information

| Artifact | Endpoint (default) | Notes |
|----------|--------------------|-------|
| CA certificate / chain (AIA `caIssuers`) | `GET /api/ca/{id}/chain` | Combined overlap chain across key rollover (`internal/ca` rotation). |
| Complete/base CRL | `GET /api/ca/{id}/crl` | Public, unauthenticated (`handlers.go`). |
| Delta CRL | `GET /api/ca/{id}/crl/delta` | RFC 5280 delta (§7.2). |
| Sharded CRLs | `GET /api/ca/{id}/crl/partition/{shard}[/delta]` | When partitioning is enabled (§7.2). |
| OCSP | `POST /api/ca/{id}/ocsp`, `GET /api/ca/{id}/ocsp/{req}` | RFC 6960 (§7.3). |
| DANE TLSA / SSHFP records | `GET /api/ca/{id}/dns-records/tlsa`, `POST /api/ssh/cas/{id}/dns-records/sshfp` | Pinning-record generation (`internal/dnsrecords`). |
| Enrollment directories | `/acme`, `/.well-known/est`, `/.well-known/brski`, `/scep`, `/cmp` | Automated issuance (§3, §4). |
| Time-stamp authority | `/tsa` | RFC 3161 (`internal/tsa`). |
| CPS pointer | `id-qt-cps` qualifier in `certificatePolicies` | Set per profile via `policies.cps` (`internal/certpolicy`). |

**[OPERATOR: publish the URLs actually stamped into your certificates' CDP/AIA
and this document's canonical URL; keep them stable.]**

### 2.3 Time or frequency of publication

CRLs are re-issued on revocation and on a schedule so a fresh CRL is always
available before the previous `nextUpdate`; base and delta CRL validity are
configurable (`crl` config; delta default validity ~1 hour). Pre-signed OCSP
responses are refreshed on a background schedule so the responder answers
without an HSM round-trip and survives an HSM outage
(`internal/ca/presign.go`). The audit head is anchored on a schedule via
RFC 3161 (§5.5). **[OPERATOR: state your CRL `nextUpdate` interval, OCSP
freshness, and CA-certificate/CP-CPS publication cadence.]**

### 2.4 Access controls on repositories

Repository read endpoints (CRL, OCSP, chain) are public and read-only. All
mutating and administrative endpoints are authenticated and RBAC-gated (§5.2),
and public endpoints are rate-limited with a bounded HSM-concurrency guard
(`internal/ratelimit`). **[OPERATOR: front the repository with your CDN/WAF and
state its availability SLA.]**

---

## 3. Identification and authentication

### 3.1 Naming

- **Name forms.** Subject DN and Subject Alternative Names are taken from the
  CSR/profile; profiles constrain SAN types and, for public TLS, require the SAN
  and that a DNS/IP-shaped CN also appear in the SAN (`internal/certlint`,
  §7.1.4). S/MIME profiles validate, normalize (punycode), and allowlist
  rfc822Name SANs (`internal/smime`). SPIFFE SVIDs carry a single `spiffe://`
  URI SAN (`internal/spiffe`).
- **Meaningful names / uniqueness / dispute resolution.** `[OPERATOR: your
  naming, name-uniqueness, and name-dispute policy — organizational.]`

### 3.2 Initial identity validation

The *method* of proving control/authorization depends on the enrollment path;
the CA does not assert possession of an identity it did not validate.

- **Proof of private-key possession.** Every CSR-based path verifies the CSR
  signature; challenge/POP is enforced per protocol (ACME key authorization,
  CMP POP, EST/SCEP).
- **Domain control (TLS).** ACME implements challenge-based domain validation:
  `http-01`, `dns-01`, and `tls-alpn-01` (RFC 8737). Every DNS-named issuance —
  ACME or operator-driven — additionally passes the **fail-closed CAA gate**
  (RFC 8659 + RFC 8657 `accounturi`/`validationmethods`), so a domain owner's
  CAA records can pin issuance to this CA and to a specific account/method
  (`internal/caa`, §4.2).
- **Device / IoT identity.** EST/SCEP use challenge-password grants and
  optional hardware **key attestation** (TPM/YubiKey, `internal/attestation`).
  BRSKI validates a manufacturer **IDevID** against trust anchors and an
  RFC 8366 voucher before bootstrapping (`internal/brski`).
- **Mailbox control (S/MIME).** ACME `email-reply-00` (RFC 8823) proves control
  of the mailbox via a signed reply; mailbox SANs are validated and allowlisted
  (`internal/mailtransport`, `internal/smime`).
- **Organization / individual identity (OV/EV).** **[OPERATOR: automated
  validation covers domain/mailbox/device control (DV-class). Any
  organization- or individual-identity vetting (OV/EV, RA registration
  procedures, evidence retention) is an operator RA process — describe it
  here.]**

### 3.3 Identification and authentication for re-key requests

Renewal/re-key over ACME/EST/CMP re-runs the same domain/device validation and
gates as initial issuance. Operator-driven renewal is RBAC-authorized (§5.2).
The host agent (`internal/agent`) re-enrolls before expiry using ARI-driven
scheduling. **[OPERATOR: state any re-validation interval / reuse limits.]**

### 3.4 Identification and authentication for revocation requests

Revocation requests are authenticated: operator/API revocation requires the
`cert:issue` capability (and WebAuthn step-up for high-risk operations, §5.2);
ACME revocation requires control of the account or certificate key. Bulk /
incident revocation is an approver-gated, dry-run-first workflow
(`internal/ca` bulk revoker, `internal/approval`, [incident
runbook](../operations/incident-response.md)). **[OPERATOR: publish how a third party files a
Certificate Problem Report and your acknowledgement SLA.]**

---

## 4. Certificate life-cycle operational requirements

### 4.1 Certificate application

Applications arrive as CSRs via an enrollment protocol (§3.2) or an authenticated
operator/API/console request. The requesting profile determines the certificate
shape and the gates that must pass.

### 4.2 Certificate application processing — the pre-issuance gate pipeline

Every end-entity issuance runs the following **fail-closed** checks *before any
HSM signature* ([ADR 0003](../adr/0003-fail-closed-security-gates.md);
`internal/ca/ct.go` `buildLeaf`). If a gate cannot positively authorize the
request, issuance is refused and an audit event + metric is emitted.

1. **FIPS policy gate** (when `security.fips` is on): rejects non-approved
   algorithm profiles (`internal/fips`, §6.7).
2. **S/MIME policy gate**: validate/normalize/allowlist mailbox SANs for S/MIME
   profiles (`internal/smime`).
3. **Certificate-policy extension assembly**: stamp the profile's policy OIDs so
   the linter sees the final certificate (`internal/certpolicy`).
4. **Pre-issuance lint gate**: hand-rolled CA/Browser-Forum Baseline-Requirements
   checks (always on), plus the optional `zlint` suite under the `zlint` build
   tag (`internal/certlint`, §7.1). An enforce-mode finding aborts issuance.
5. **CAA gate** (RFC 8659/8657): resolve and evaluate CAA for DNS identifiers;
   in `enforce` mode a prohibiting record *or a resolution failure* blocks
   issuance (`internal/caa`).
6. **Name Constraints gate** (RFC 5280 §4.2.1.10): reject a leaf outside the
   issuing CA's permitted subtrees / inside an excluded subtree
   (`internal/nameconstraints`).
7. **Certificate Transparency** (when enabled per profile): HSM-sign a
   precertificate, submit to logs, enforce the min-SCT policy, embed the SCT
   list, then HSM-sign the final certificate (`internal/ct`). CT is fail-closed
   by default, per-profile fail-open opt-in.

Operator/API issuance under a profile with `require_approval` is additionally
held for four-eyes approval before the certificate is delivered
(`internal/issueapproval`, §5.2). Automated protocol flows deliberately bypass
the manual gate.

### 4.3 Certificate issuance

On passing all gates the CA signs the leaf on the HSM (`internal/pki`), records
it (with a per-CA SHA-256 uniqueness constraint), and emits a `cert.issue` audit
event. Serial numbers are 128-bit CSPRNG values (§6.1, §7.1.3).

### 4.4 Certificate acceptance

Delivery is via the enrollment-protocol response, the API/console, or a
server-side-keygen PKCS#12 bundle where the subject key is generated server-side
and the CA key never leaves the HSM (`internal/pkcs12`). **[OPERATOR: define
what constitutes subscriber acceptance in your Subscriber Agreement.]**

### 4.5 Key pair and certificate usage

Subscribers and relying parties must use certificates consistently with their
key usage / EKU and this policy (§1.4). CA key usage is limited to signing by
HSM attributes (§6.2).

### 4.6–4.8 Renewal, re-key, modification

Renewal/re-key re-run validation and the gate pipeline (§3.3, §4.2). Certificate
modification is issuance of a new certificate; fields are never edited in place.
Intermediate CA **key rollover** uses a dual-chain overlap window so relying
parties trust both the old and new keys during transition
([ADR 0004](../adr/0004-dual-chain-rotation-overlap.md), [rotation
docs](../ca/rotation.md)).

### 4.9 Certificate revocation and suspension

- **Circumstances / who can request / grace period.** Key compromise, misissuance,
  affiliation change, cessation, superseded, etc. (reason codes in §7.2).
  Requests are authenticated per §3.4. **[OPERATOR: adopt the CA/Browser-Forum
  revocation timelines — 24 hours for §4.9.1(1) reasons, 5 days for the rest —
  as a binding SLA; the software provides the tooling but does not itself
  enforce the wall-clock deadline.]**
- **Mechanisms.** Revocation is published via **CRL** (base + delta + optional
  sharding) and **OCSP** (`internal/ca/crl.go`, OCSP responder). Bulk/incident
  revocation regenerates CRL+delta once at the end of the run and invalidates the
  OCSP cache + refreshes presigned responses ([incident
  runbook](../operations/incident-response.md)).
- **Suspension (certificateHold) and release.** Reversible hold
  (`certificateHold`, reason 6) and release (`removeFromCRL`, reason 8 in the
  next delta) are supported (`internal/handlers/hold.go`, [suspend/hold
  docs](../ca/overview.md)). **[OPERATOR: the BRs prohibit suspension for
  publicly-trusted TLS server certificates — restrict hold to internal/other
  profiles, or disable it, per your policy.]**
- **Status checking availability.** See §4.10.

### 4.10 Certificate status services

- **CRL** with monotonic CRL numbers, `nextUpdate`, delta CRLs (2.5.29.27),
  issuing distribution point (2.5.29.28), and freshest-CRL (2.5.29.46).
- **OCSP** per RFC 6960 with nonce (RFC 8954), an optional HSM-backed delegated
  responder (`id-kp-OCSPSigning` + `id-pkix-ocsp-nocheck`), TLS stapling, and
  batch pre-signing for CDN offload / HSM-outage survivability.

### 4.11–4.12 End of subscription; key escrow and recovery

CA private keys are **never escrowed** (non-extractable, [ADR
0002](../adr/0002-hsm-non-extractability-invariants.md)). The optional M-of-N
**escrow applies only to the separate secret-encryption layer's data keys**
(Shamir-split DEK wrapped per recovery agent, `internal/secret`), and to
optional escrow of *subject* encryption keys in server-side-keygen S/MIME/PKCS#12
flows — never to any CA signing key. **[OPERATOR: state whether subject-key
escrow is offered and its governance.]**

---

## 5. Facility, management, and operational controls

### 5.1 Physical security controls

**[OPERATOR: entirely organizational — data-center/rack physical access,
HSM tamper protection tier, environmental controls, offline-root storage
(safe/vault), media handling and destruction. secsy-pki assumes the HSM and
hosts run in a physically controlled facility.]**

### 5.2 Procedural controls — trusted roles and dual control

- **Role-based access control** (`internal/rbac`) defines the trusted roles.
  Built-in roles: **`admin`** (full control), **`issuer`** (issue/renew/revoke,
  read audit, secret encrypt/decrypt), **`signer`** (artifact signing only —
  deliberately cannot mint certificates), **`auditor`** (read-only: audit/access/
  event logs, approval queue), **`approver`** (approve/reject four-eyes requests
  only). Capabilities are expressed as actions (`cert:issue`, `ca:manage`,
  `rbac:manage`, `secret:*`, `approval:approve`, `token:manage`, …). Roles are
  **platform-** or **tenant-scoped**; a per-CA permission matrix
  (`SIGN_CERTIFICATE`/`MANAGE_PERMISSIONS`/`CONFIGURE_CA`) overlays fine-grained
  grants.
- **Separation of duties / dual control.** The **four-eyes / maker-checker gate**
  (`internal/approval`) requires N distinct approvers for guarded operation
  classes — `ca.create`, `ca.rotate`, `ca.retire`, `revocation.bulk`,
  `secret.kek_rotate`, `token.create`, and per-profile `cert.issue`. **Self-approval
  is denied by identity**, and the `approver` role is separate from the roles
  that request the operations ([ADR
  0006](../adr/0006-four-eyes-approval-gate.md), [approvals docs](../security/approvals.md)).
- **Step-up authentication.** High-risk operations (root init, intermediate
  issue, cross-sign, rotate/retire, revoke, bulk revoke/issue) require WebAuthn
  step-up for console sessions (`internal/authn`, §5.2 & authentication docs).
- **Identification and authentication for each role.** Operators authenticate via
  OIDC SSO (claim/group→role mapping), mutual-TLS client-cert binding, native
  scoped API tokens (`secsy_pat_`, SHA-256 at rest), or a configured root
  account; sessions use HttpOnly cookies + CSRF ([authentication
  docs](../security/authentication.md)).

**[OPERATOR: number of persons per role, background-check and training
requirements, and which specific individuals hold trusted roles.]**

### 5.3 Personnel security controls

**[OPERATOR: organizational — background checks, training, sanctions,
contractor controls, role-qualification and separation-of-duties enforcement in
HR terms.]**

### 5.4 Audit logging procedures

- **What is logged.** An append-only event log records who did what, when, with
  what result — including *denied* attempts. Event types cover the full lifecycle:
  `cert.issue/renew/revoke/revoke_bulk/suspend/release`, gate outcomes
  (`cert.lint`, `cert.caa`, `cert.nameconstraint`, `cert.attestation`,
  `cert.brski`), CA lifecycle (`ca.create/init_root/issue_intermediate/rotate/
  retire/cross_sign`), CRL publication, auth (`auth.login/login_failed/logout/
  step_up`, WebAuthn), permission and approval events, and audit anchoring
  (`internal/audit`).
- **Tamper-evidence.** Entries are **SHA-256 hash-chained** (each row binds its
  content and the previous hash; a genesis hash starts the chain). Deletion,
  reordering, or content edits break the chain and are detected by
  `VerifyChain` / `secsy-ca audit verify` (§8).
- **Anchoring.** See §5.5.
- **Export & monitoring.** At-least-once streaming to SIEM (syslog RFC 5424 /
  CEF / webhook) with a durable per-sink cursor (`internal/siem`); live operator
  SSE feed (`internal/eventstream`).
- **Retention / review / vulnerability of the log.** `[OPERATOR: retention
  period (BRs: audit-log records ≥ 2 years / per your auditor), review cadence,
  and off-box storage.]`

### 5.5 Records archival & audit anchoring

The hash chain proves internal consistency but not against a party who can
rewrite the *entire* store. **RFC 3161 audit anchoring** defeats that: the CA
periodically obtains a time-stamp token over the chain head `(seq, head_hash)`
from a TSA it does not control (internal `/tsa` or an external TSA), stored in
`audit_anchors` (`internal/anchor`; `secsy-ca audit anchor`). Verification
detects truncation or rewrite behind an anchor. **[OPERATOR: archival media,
retention, and off-site copies of the DB dump, config, and audit chain — see
§5.7 backups.]**

### 5.6 Key changeover

Intermediate signing keys are rotated with a dual-chain overlap window (§4.6,
[ADR 0004](../adr/0004-dual-chain-rotation-overlap.md)); combined chains are
published so validation succeeds across the change. **[OPERATOR: root
changeover procedure and schedule.]**

### 5.7 Compromise and disaster recovery

- **Incident handling.** Key-compromise mass revocation is a scoped,
  dry-run-first, resumable, approver-gated workflow ([incident
  runbook](../operations/incident-response.md)).
- **Backups.** A leader-elected job produces a DR artifact (logical DB dump +
  config + **public** CA material + audit-head fingerprint), envelope-encrypts it
  under the HSM-backed KEK, and writes it to a directory/S3 store with retention
  (`internal/backup`, [backup docs](../operations/backup.md)). **No private CA key is ever in
  a backup** ([ADR 0002](../adr/0002-hsm-non-extractability-invariants.md)).
- **Restore verification.** A companion job restores the newest artifact into an
  isolated scratch database, runs the integrity gate, and confirms the audit-head
  fingerprint — closing the loop that a backup is actually restorable.
- **DR drills.** `scripts/dr-drill.sh` and `scripts/dr-drill-full.sh` exercise
  token/DB loss → restore → verify, including PostgreSQL PITR and audit-chain
  continuity ([key ceremony & DR](../hsm/key-ceremony.md)).
- **HSM-shaped recovery.** Because CA keys are non-extractable, recovery restores
  the HSM token (or re-runs a key ceremony) and *reattaches* metadata; you cannot
  reconstitute a CA from a file backup alone.

### 5.8 CA or RA termination

**[OPERATOR: termination plan — final CRL issuance, revocation/expiry of
subordinate CAs, notification of relying parties, archival transfer, and
key-material destruction procedures.]**

---

## 6. Technical security controls

### 6.1 Key pair generation and installation

- **Generation.** CA key pairs are **generated on the HSM** through the key
  provider (`internal/keyprovider`, `internal/pki/signer.go`); the private key is
  created on the device and there is **no export API**
  ([ADR 0002](../adr/0002-hsm-non-extractability-invariants.md)).
- **Algorithms & sizes.** RSA-2048 / RSA-4096, ECDSA P-256 / P-384 / P-521, and
  Ed25519 on PKCS#11; RSA < 2048 is rejected. ML-DSA (FIPS 204) pure-PQC and
  hybrid are supported only on the software provider, outside the validated
  module boundary (`internal/keyprovider`, `internal/pqc`).
- **Ceremony.** Root/intermediate generation can be run as an **M-of-N quorum
  key ceremony** with recorded, hash-committed operator confirmations
  (`secsy-ca ceremony`, [key ceremony docs](../hsm/key-ceremony.md)).
- **Serial numbers.** 128-bit CSPRNG (`crypto/rand`), exceeding the ≥ 64-bit
  entropy requirement (`internal/pki`, §7.1.3).
- **Signature/hash.** SHA-256 or stronger, selected by key type (SHA-384/512 for
  P-384/P-521); SHA-1 is never used for signing and is rejected under FIPS
  policy.

### 6.2 Private-key protection and cryptographic-module controls

CA (and TSA, KEK) private keys are generated with PKCS#11 attributes enforcing
non-extractability and least privilege: `CKA_TOKEN=true`, `CKA_PRIVATE=true`,
`CKA_SENSITIVE=true`, `CKA_EXTRACTABLE=false`, and capability-scoping
(`CKA_SIGN=true`, `CKA_DECRYPT=false`, `CKA_UNWRAP=false` for signing keys) —
`internal/pki/signer.go`. Labels are kept unique to avoid ambiguous key
resolution ([duplicate-label pitfall](../adr/0002-hsm-non-extractability-invariants.md)).
Multi-token HSM high availability with health-tracked failover is supported
(`internal/keyprovider` HA provider). **[OPERATOR: the FIPS 140-2/3 *validation
level* of the CA is a property of your chosen HSM — SoftHSM is for dev/CI only
and is NOT validated; state your production HSM's certificate.]**

### 6.3 Activation data

The HSM PIN / credential is sourced at login-time from a file, environment
variable, HashiCorp Vault, or a cloud secret manager, with redaction and a
`doctor pin.source` check (`internal/keyprovider` PIN sourcing, [Task
111](../hsm/configuration.md)). **[OPERATOR: PIN custody, M-of-N HSM auth if your
device supports it, and activation-data handling.]**

### 6.4 Computer / network / lifecycle security controls

- **Transport is TLS and fail-closed**: a missing/unreadable key/cert is a
  startup failure, never a cleartext downgrade
  ([ADR 0003](../adr/0003-fail-closed-security-gates.md)).
- Public endpoints are **rate-limited** with a bounded HSM-concurrency guard
  (`internal/ratelimit`).
- **Static analysis, race detection, fuzzing, and govulncheck** gate the build
  (`make lint`/`test-race`/`fuzz`, `internal/certlint`/fuzz targets,
  [supply-chain docs](../development/supply-chain.md)); releases carry SBOMs, cosign
  signatures, and SLSA provenance.
- **[OPERATOR: host hardening, patching, network segmentation, and change
  management for the servers and HSM network path.]**

### 6.5 Time-stamping

An HSM-backed RFC 3161 TSA is available (`internal/tsa`, `/tsa`) and is used to
anchor the audit chain (§5.5). A `doctor clock.skew` check flags host↔database
clock divergence that would distort validity windows, CRL freshness, and audit
ordering. **[OPERATOR: your trusted time source (NTP) and its integrity.]**

### 6.6 Cryptographic module engineering / FIPS mode

A FIPS build (`GOFIPS140`, `make build-fips`) runs on the Go Cryptographic
Module and, with `security.fips` on, fail-closed rejects Ed25519 leaves, SHA-1
anywhere, RSA < 2048, and software-PQC paths at config load, key generation, and
issuance (`internal/fips`, [FIPS docs](../security/fips.md)).

---

## 7. Certificate, CRL, and OCSP profiles

### 7.1 Certificate profile

- **7.1.1 Version.** X.509 v3.
- **7.1.2 Certificate extensions.** Basic Constraints (leaves `cA=FALSE`,
  enforced by the linter), Key Usage and Extended Key Usage per profile,
  Subject Alternative Name, Authority/Subject Key Identifier, CRL Distribution
  Points, Authority Information Access (OCSP + caIssuers), Certificate Policies
  (with optional CPS URI), Name Constraints on CAs, SCT list (when CT enabled),
  and — for hybrid profiles — alternative-signature extensions. Built-in profile
  key-usage/EKU/validity (`internal/ca/profile.go`):

  | Profile | EKU | Default / Max validity |
  |---------|-----|------------------------|
  | `server` | serverAuth | 397 d / 397 d |
  | `server-client` | serverAuth+clientAuth | 397 d / 397 d |
  | `client` | clientAuth | 365 d / 730 d |
  | `code-signing` | codeSigning | 3 y / 3 y |
  | `smime` / `-sign` / `-encrypt` | emailProtection | 365 d / 730 d |
  | `spiffe-svid` | serverAuth+clientAuth | 1 h / 24 h |
  | `pqc-server` / `hybrid-server` | serverAuth[+clientAuth] | 365 d / 397 d |
  | `canary` | clientAuth | 1 h / 24 h |

- **7.1.3 Algorithm object identifiers / serial.** Signature algorithms are
  SHA-256/384/512 with RSA or ECDSA (or Ed25519, or ML-DSA on the software
  provider). Serials are 128-bit CSPRNG; the linter requires ≥ 64 bits of
  entropy (`internal/certlint` `serial_entropy`, `serial_positive`).
- **7.1.4 Name forms / constraints.** Under a `Public` profile the linter
  enforces: SAN present, CN∈SAN, no reserved/internal TLDs, no single-label or
  underscore DNS names, no non-globally-routable IP SANs, single leftmost
  wildcard only (`internal/certlint` `san_present`, `cn_in_san`,
  `internal_name`, `reserved_ip`, `wildcard`). CA Name Constraints (2.5.29.30)
  are enforced pre-issuance (`internal/nameconstraints`).
- **7.1.5 Validity.** Per-profile `MaxValidity`, plus a public TLS cap of
  **398 days** under `Public` policy (`internal/certlint` `validity_tls_max`,
  `validity_cap`, `validity_order`).
- **7.1.6 Policy OIDs.** Assigned per profile via `policies.oids` with an
  optional `id-qt-cps` URI and RFC 5280 policy mappings/constraints
  (`internal/certpolicy`). **[OPERATOR: register and assert your policy OID.]**

### 7.2 CRL profile

X.509 v2 CRLs with monotonically increasing CRL numbers, `thisUpdate`/
`nextUpdate`, **Delta CRL Indicator (2.5.29.27)**, **Issuing Distribution Point
(2.5.29.28)** for sharding/partitioning, and **Freshest CRL (2.5.29.46)**
pointing base→delta (`internal/pki/crl.go`, `internal/ca/crl.go`). Sharding maps
serials deterministically by SHA-256. Supported reason codes: unspecified(0),
keyCompromise(1), cACompromise(2), affiliationChanged(3), superseded(4),
cessationOfOperation(5), certificateHold(6), removeFromCRL(8, delta only),
privilegeWithdrawn(9), aACompromise(10).

### 7.3 OCSP profile

RFC 6960 responses with statuses good / revoked / unknown and the error
responses malformed / internalError / tryLater / sigRequired / unauthorized;
**nonce** per RFC 8954 (1–32 octets, echoed); optional **delegated responder**
certificate carrying `id-kp-OCSPSigning` and `id-pkix-ocsp-nocheck`; TLS
stapling; and batch pre-signing (nonce requests always bypass the cache and are
signed fresh) — `internal/pki/ocsp.go`, `internal/ca/ocsp.go`,
`internal/ca/presign.go`.

---

## 8. Compliance audit and other assessments

- **Self-assessment tooling (continuous / on-demand).** `secsy-ca audit verify`
  (hash-chain + RFC 3161 anchor verification), the offline `secsy-verify`
  chain-of-trust proof (HSM attestation: key generated-on-device, never-exported,
  sign-only), `secsy-ca db verify` (HSM-independent integrity gate), `secsy-ca
  doctor` (config/HSM/KMS/DB/audit-chain/CT-inclusion/clock/TLS preflight), the
  synthetic **issuance canary** (`internal/canary`), automated **restore
  verification** (§5.7), and an **external-client interop/conformance suite**
  (`scripts/interop-test.sh` against acme.sh, openssl cmp/ocsp/ts, EST).
- **Control mapping.** The [compliance control mapping](compliance-mapping.md)
  traces CA/Browser-Forum TLS BR, S/MIME BR, and WebTrust-for-CA principles to
  the implementing code with an explicit gaps column.
- **Independent audit.** **[OPERATOR: a WebTrust for CA / ETSI EN 319 411 or
  CA/Browser-Forum audit is performed by a qualified external auditor on the
  operating organization — the software does not and cannot self-certify. Record
  your audit scheme, auditor, period, frequency, and last report.]**

---

## 9. Other business and legal matters

RFC 3647 §9 is almost entirely organizational and legal. secsy-pki is
distributed under the **MIT license** (see repository `LICENSE`); that license
governs the *software*, not the *CA service*. Every clause below is an operator
responsibility:

- **9.1 Fees** — `[OPERATOR]`
- **9.2 Financial responsibility** (insurance, warranty reserves) — `[OPERATOR]`
- **9.3 Confidentiality of business information** — `[OPERATOR]`
- **9.4 Privacy of personal information** — `[OPERATOR: note that the audit log
  and issued certificates may contain personal data (e.g. S/MIME mailbox,
  operator identity); define your privacy handling.]`
- **9.5 Intellectual-property rights** — `[OPERATOR]`
- **9.6 Representations and warranties** (CA, RA, subscriber, relying-party
  obligations) — `[OPERATOR]`
- **9.7 Disclaimers of warranties** — `[OPERATOR]`
- **9.8 Limitations of liability** — `[OPERATOR]`
- **9.9 Indemnities** — `[OPERATOR]`
- **9.10 Term and termination** — `[OPERATOR]`
- **9.11 Individual notices and communications** — `[OPERATOR]`
- **9.12 Amendments** — `[OPERATOR: CP/CPS change-control and notification.]`
- **9.13 Dispute-resolution provisions** — `[OPERATOR]`
- **9.14 Governing law** — `[OPERATOR]`
- **9.15 Compliance with applicable law** — `[OPERATOR]`
- **9.16 Miscellaneous / other provisions** — `[OPERATOR]`

---

## Change history

| Version | Date | Author | Notes |
|---------|------|--------|-------|
| Template | — | secsy-pki | Initial RFC 3647 CP/CPS template generated from the implementation. Complete every `[OPERATOR: …]` placeholder before adoption. |

## See also

- [Compliance control mapping](compliance-mapping.md) — CA/B-Forum & WebTrust → code.
- [Architecture Decision Records](../adr/README.md) — the load-bearing design decisions.
- [Security review & hardening](../security/security-review.md) · [Key ceremony & DR](../hsm/key-ceremony.md) ·
  [RBAC & audit](../security/rbac-and-audit.md) · [Certificate authority](../ca/overview.md) ·
  [CAA](../issuance/caa.md) · [Certificate Transparency](../issuance/certificate-transparency.md) ·
  [Pre-issuance linting](../issuance/certlint.md) · [FIPS mode](../security/fips.md).
