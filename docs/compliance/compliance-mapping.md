# Compliance control mapping

This document traces the controls required by the **CA/Browser Forum TLS
Baseline Requirements (BR)**, the **S/MIME Baseline Requirements (SMBR)**, and
the **WebTrust for Certification Authorities** principles to the secsy-pki
feature, package, and file that implements them — with an explicit
**gaps & assumptions** column. It is the technical companion to the
[Certificate Policy / CPS](certificate-policy.md).

Every entry was checked against the code on the `enterprise` branch. The goal is
an **accurate** map, not an aspirational one: where a requirement is only
partially met, is config-dependent, or is an operator responsibility the
software cannot discharge, the row says so plainly.

### How to read this

| Column | Meaning |
|--------|---------|
| **Control** | The requirement, with the closest normative clause. Clause numbers track the BR/SMBR/WebTrust versions current at the time of writing; **[OPERATOR: re-verify clause numbers against the exact version you are audited to.]** |
| **Implementation** | The feature and the `server/…` package/file that provides it. |
| **Status** | ✅ enforced in code · ⚙️ implemented but **config-dependent** (must be enabled/tuned) · 👤 **operator/organizational** control the software supports but cannot itself satisfy · ⛔ **not implemented** (gap). |
| **Gaps & assumptions** | What the control does *not* cover, what must be assumed true, or what the operator must do. |

> **Scope caveat.** secsy-pki is CA *software*. Publicly-trusted status,
> WebTrust/ETSI attestation, physical/personnel security, and the legal CP/CPS
> are properties of the **operating organization and its audit**, not of the
> code. Rows marked 👤 are included because a real audit will ask for them; the
> "Implementation" column then points at the supporting tooling, and the gap
> column names the operator obligation.

---

## 1. CA/Browser Forum TLS Baseline Requirements

### 1.1 Key generation, sizes, and protection

| Control | Implementation | Status | Gaps & assumptions |
|---------|----------------|--------|--------------------|
| **CA & subscriber key sizes** — RSA ≥ 2048, ECDSA P-256/P-384/P-521 (BR §6.1.5) | Key provider generates RSA-2048/4096, ECDSA P-256/384/521, Ed25519; RSA < 2048 rejected. `internal/keyprovider`, `internal/pki/keygen.go`; FIPS floor in `internal/fips` | ✅ | Ed25519 & ML-DSA/hybrid are offered for non-public/internal use; they are **not** publicly-trusted TLS algorithms — restrict public profiles to RSA/ECDSA. RSA 3072 not a distinct built-in size. |
| **Approved signature algorithms / hashes** — SHA-256+ (BR §7.1.3.2) | Signature algorithm selected by key type (SHA-256/384/512); SHA-1 never used and rejected under FIPS. `internal/pki`, `internal/fips` (`CheckSignatureAlgorithm`) | ✅ | — |
| **CA private key generated in & protected by a validated cryptographic module; non-exportable** (BR §6.1.1, §6.2) | Keys generated on-device with `CKA_TOKEN/PRIVATE/SENSITIVE=true`, `CKA_EXTRACTABLE=false`, sign-only; **no export API**. `internal/pki/signer.go:536-548`, `internal/keyprovider`; [ADR 0002](../adr/0002-hsm-non-extractability-invariants.md) | ✅ / 👤 | The **FIPS 140-2/3 validation level is a property of the operator's HSM**. SoftHSM (dev/CI) is **not validated**. Operator must run a validated HSM and record its certificate. |
| **Key generation ceremony / witnessed, scripted, logged** (BR §6.1.1.1; WebTrust key-lifecycle) | M-of-N quorum ceremony with hash-committed operator confirmations, audit-anchored. `secsy-ca ceremony`, [key ceremony](../hsm/key-ceremony.md) | ⚙️ / 👤 | Software provides the quorum + transcript; operator supplies witnesses, script sign-off, and video/records per their policy. |
| **Random serial numbers ≥ 64 bits entropy** (BR §7.1) | 128-bit CSPRNG serials; linter requires ≥ 64 bits. `internal/pki` (`crypto/rand`), `internal/certlint` (`serial_entropy`, `serial_positive`) | ✅ | Linter measures bit-length as a proxy; the generation path is truly 128-bit random, so the proxy is conservative. |
| **CA key activation data protection** (BR §6.4; WebTrust) | HSM PIN sourced at login from file/env/Vault/AWS/Azure with redaction; `doctor pin.source`. `internal/keyprovider` PIN sourcing | ⚙️ / 👤 | Custody of the PIN/secret and any HSM M-of-N auth are operator controls. |

### 1.2 Domain / identity validation (issuance authorization)

| Control | Implementation | Status | Gaps & assumptions |
|---------|----------------|--------|--------------------|
| **Proof of key possession** (BR §3.2.1) | CSR signature verified on every path; ACME key-authorization, CMP POP, EST/SCEP challenge. `internal/acme`, `internal/cmp`, `internal/est`, `internal/scep` | ✅ | — |
| **Domain-control validation methods** (BR §3.2.2.4) | ACME `http-01`, `dns-01`, `tls-alpn-01` (RFC 8737). `internal/acme`, `internal/acme/tlsalpn.go` | ⚙️ | Implements the ACME-based §3.2.2.4 methods only. Other methods (e.g. email-to-DNS-contact, phone, IP §3.2.2.5) are **not** implemented. Validation-reuse windows are operator policy. |
| **CAA checking, fail-closed** (BR §3.2.2.8, RFC 8659) | Fail-closed pre-issuance CAA gate on every DNS issuance; `issue`/`issuewild`/`iodef`. `internal/caa`, gate in `internal/ca/ct.go` `buildLeaf` | ✅ / ⚙️ | Operator **must** set `caa.identifier` to the CA's domain. Mode is per-profile (`off`/`permissive`/`enforce`); `enforce` is required for public trust. |
| **CAA `accounturi` / `validationmethods`** (RFC 8657) | Enforced with per-request context threaded from ACME finalize. `internal/caa` (`RequestContext`) | ✅ | Account-URI matching depends on the ACME account URL the operator publishes. |
| **Multi-Perspective Issuance Corroboration (MPIC)** (BR §3.2.2.9 / SC-067) | — | ⛔ | **Not implemented.** DNS/validation is single-vantage-point. A CA seeking public trust after the MPIC effective date must add multi-perspective corroboration (proxy or external service) in front of validation. |
| **Data-source / document-age & reuse limits; OV/EV identity vetting** (BR §3.2, §4.2.1) | Automated paths validate domain/mailbox/device control (DV-class). RA vetting is manual. | 👤 | OV/EV organizational-identity validation, evidence retention, and reuse limits are **operator RA processes**; not automated. |

### 1.3 Certificate profile & content

| Control | Implementation | Status | Gaps & assumptions |
|---------|----------------|--------|--------------------|
| **Max validity (398-day public TLS)** (BR §6.3.2) | `Public` policy caps at 398 days; `server` profile default/max 397 d. `internal/certlint` (`validity_tls_max`), `internal/ca/profile.go` | ✅ / ⚙️ | The **phased reductions** (SC-081: 200/100/47-day) are **not auto-enforced** by date — tighten `profiles.*.max_validity_days` to comply as each milestone lands. Non-public profiles use their own caps. |
| **`cA=FALSE` on end-entity certs** (BR §7.1.2.7) | Leaf-not-CA lint check. `internal/certlint` (`leaf_not_ca`) | ✅ | — |
| **Key usage / EKU present & consistent** (BR §7.1.2.7.6–.11) | Per-profile KU/EKU; linter forbids `keyCertSign`/`cRLSign` on leaves and checks EKU↔KU consistency. `internal/certlint` (`key_usage_leaf`, `eku_ku_consistency`), `internal/ca/profile.go` | ✅ | — |
| **SAN required; CN must be in SAN** (BR §7.1.2.7.6, §7.1.4.2) | `Public` policy requires SAN present and CN∈SAN. `internal/certlint` (`san_present`, `cn_in_san`) | ✅ / ⚙️ | Requires the profile's `Public` flag (public-facing profiles). |
| **No internal/reserved names or non-routable IPs; wildcard rules** (BR §7.1.4.2.1, §3.2.2.6) | Rejects reserved TLDs, single-label, underscore names, reserved-IP SANs, multi-label wildcards. `internal/certlint` (`internal_name`, `reserved_ip`, `wildcard`) | ✅ | Uses a built-in reserved-TLD/CIDR list (RFC 1918/6598/6761 etc.); not the live public-suffix list — add domains to the profile if your policy is stricter. |
| **Certificate Policies extension / CPS URI / policy identifier** (BR §7.1.2.7.9) | Per-profile policy OIDs with `id-qt-cps` URI + RFC 5280 mappings. `internal/certpolicy` | ⚙️ / 👤 | Software emits whatever OIDs the operator configures; the CA does **not** ship a registered policy OID — **operator must register and assert one**. |
| **Name Constraints on technically-constrained sub-CAs** (BR §7.1.2.5, RFC 5280) | Name Constraints (2.5.29.30) on CAs + fail-closed pre-issuance gate. `internal/nameconstraints` | ✅ / ⚙️ | Operator must configure the permitted/excluded subtrees on the sub-CA. |
| **AIA (OCSP + caIssuers) & CDP present** (BR §7.1.2.7.7) | AIA/CDP stamped on leaves; chain endpoint for caIssuers; CDP for CRL/shard. `internal/ca`, `internal/pki`; `GET /api/ca/{id}/chain` | ⚙️ | Operator must set the externally-reachable AIA/CDP base URLs so the stamped URLs resolve. |
| **Precertificate + SCTs / Certificate Transparency** (browser CT policy) | RFC 6962 precert submission + SCT embedding; inclusion-proof monitoring. `internal/ct`, `internal/ctmonitor` | ⚙️ | Per-profile; **fail-open is a supported opt-in** ([ADR 0003](../adr/0003-fail-closed-security-gates.md)). Operator must configure qualified logs and enough SCTs to meet current browser CT policy — the software does not track browser-specific log-diversity rules. |
| **Pre-issuance linting** (industry best practice; misissuance prevention) | Hand-rolled BR checks always on; optional `zlint` suite under `-tags zlint`. `internal/certlint`, `internal/certlint/zlint.go` | ✅ / ⚙️ | The always-on checks are a **curated subset**, not the full zlint corpus. For maximal coverage build with `-tags zlint` and set the profile `lint.zlint` level. |
| **Reject known-weak keys (ROCA, Debian, small factors)** (BR §4.9.1.1(4), §6.1.1.3) | Fail-closed **pre-issuance** key-quality gate on every issuance surface (REST/ACME/EST/SCEP/CMP/SPIFFE) and the dry-run preview: ROCA/CVE-2017-15361 fingerprint, RSA exponent (e≥65537, odd) and modulus (odd, ≥2048-bit) checks, optional Debian OpenSSL weak-key blocklist, and an operator-managed compromised-key blocklist. `internal/keycheck`, `internal/ca/keycheck.go`; [key-checks](../issuance/key-checks.md) | ✅ / ⚙️ | Per-profile enforce/warn. The Debian weak-key list is **operator-supplied** (no blob vendored); load it via `keychecks.weak_key_blocklist_paths`. Small-factor/Fermat cofactor scanning is not performed (structural ROCA + blocklists only). |

### 1.4 Revocation & certificate status

| Control | Implementation | Status | Gaps & assumptions |
|---------|----------------|--------|--------------------|
| **CRL issuance, format, monotonic CRL number, `nextUpdate`** (BR §4.9.7, §7.2, RFC 5280) | X.509 v2 CRLs, monotonic numbers, `thisUpdate`/`nextUpdate`; HSM-signed. `internal/pki/crl.go`, `internal/ca/crl.go` | ✅ / ⚙️ | Operator sets the CRL `nextUpdate` interval to meet the BR freshness window. |
| **Delta CRLs, IDP/sharding, freshest-CRL** (RFC 5280 §5.2) | Delta CRL (2.5.29.27), IDP (2.5.29.28), Freshest-CRL (2.5.29.46), SHA-256 sharding. `internal/pki/crl.go`, `internal/ca/crl.go` | ✅ / ⚙️ | Optional; enable partitioning via `crl` config for large CAs. |
| **Reason codes** (RFC 5280 §5.3.1) | unspecified/keyCompromise/cACompromise/affiliationChanged/superseded/cessationOfOperation/certificateHold/removeFromCRL/privilegeWithdrawn/aACompromise. `internal/pki/crl.go` | ✅ | `removeFromCRL(8)` only in deltas, as required. |
| **OCSP responder, RFC 6960** (BR §4.9.9, §4.10.2) | good/revoked/unknown + malformed/internalError/tryLater/sigRequired/unauthorized; nonce (RFC 8954); delegated responder (`id-kp-OCSPSigning` + `ocsp-nocheck`); stapling. `internal/pki/ocsp.go`, `internal/ca/ocsp.go` | ✅ / ⚙️ | Delegated responder is optional (else the CA key signs). |
| **OCSP must not answer "good" for a non-issued serial** (BR §4.9.10) | Responder returns `unknown` for unrecorded serials and `unauthorized` when not the issuer. `internal/ca/ocsp.go:133`, `:157-161` | ✅ | **Assumes** the issued-certificate store reflects every serial the CA has signed (true for the normal issuance path; migrated/imported inventories must be complete). |
| **Status availability during HSM outage / CDN offload** (availability) | Batch OCSP pre-signing into the cache (survives HSM outage); static publisher (dir/S3, atomic swap + manifest). `internal/ca/presign.go`, `internal/publish` | ⚙️ | Nonce requests always bypass the cache (signed fresh), as intended. |
| **Revocation within 24 h / 5 days of a valid problem report** (BR §4.9.1.1) | Bulk/incident revocation tooling: scoped, dry-run-first, resumable, approver-gated; single end-of-run CRL+delta + OCSP refresh. `internal/ca` bulk revoker, [incident runbook](../operations/incident-response.md) | ⚙️ / 👤 | The software does **not** enforce the wall-clock deadline. Operator must staff the Certificate-Problem-Report intake and meet the SLA. |
| **Certificate Problem Report intake, 24×7** (BR §4.9.3, §1.5.2) | — | 👤 | Organizational: publish the reporting address and run the 24×7 process. |
| **No suspension for public TLS** (BR §4.9.1) | certificateHold/release exists (`internal/handlers/hold.go`) and is reversible. | ⚙️ / 👤 | **Operator must not enable hold on publicly-trusted TLS profiles** (BRs forbid it); restrict to internal/other profiles. |

### 1.5 Audit, logging, and CA operations

| Control | Implementation | Status | Gaps & assumptions |
|---------|----------------|--------|--------------------|
| **Complete, tamper-evident audit log of CA lifecycle events** (BR §5.4.1; WebTrust logging) | Append-only, **SHA-256 hash-chained** event log incl. denied attempts; issuance/revocation/gate/CA/auth/approval events. `internal/audit` (`ComputeHash`, `VerifyChain`) | ✅ | — |
| **Log integrity against wholesale rewrite** (WebTrust monitoring) | RFC 3161 **audit anchoring** of the chain head to an independent TSA; truncation/rewrite detection. `internal/anchor`, `secsy-ca audit anchor` | ✅ / ⚙️ | Enable `audit.anchor`; strongest when anchored to an **external** TSA the store-writer does not control. |
| **Log retention & off-box storage** (BR §5.4.3 / §5.5.2) | SIEM export (syslog RFC 5424 / CEF / webhook), at-least-once + durable cursor; encrypted DR backups include the audit log. `internal/siem`, `internal/backup` | ⚙️ / 👤 | Operator sets retention (BRs: ≥ 2 years for certain records) and the destination store. |
| **Independent verifiability of issuance** (assurance) | Offline `secsy-verify` proves HSM chain-of-trust (key generated-on-device, never-exported, sign-only, 1:1 sign-op↔cert bijection). `cmd/verify` | ✅ | Full cryptographic proof requires a YubiHSM-class device with hardware attestation + forced audit; SoftHSM gives the hash-chain checks without the hardware attestation. |
| **Segregation of duties / trusted roles** (BR §5.2.1; WebTrust personnel) | RBAC roles (`admin`/`issuer`/`signer`/`auditor`/`approver`), platform vs tenant scope, per-CA permission matrix. `internal/rbac` | ✅ / 👤 | Operator assigns individuals and enforces the headcount/background policy. |
| **Dual control / multi-party for sensitive ops** (BR §5.2.2; WebTrust) | Four-eyes gate: N distinct approvers for CA create/rotate/retire, bulk revoke, KEK rotate, token create, gated issuance; **self-approval denied**. `internal/approval`; [ADR 0006](../adr/0006-four-eyes-approval-gate.md) | ✅ / ⚙️ | Enable `approvals` and set per-class thresholds ≥ 2. |
| **Strong operator authentication / access control** (WebTrust system access) | OIDC SSO (claim→role), mTLS binding, WebAuthn step-up on high-risk ops, scoped API tokens (SHA-256 at rest), sessions+CSRF. `internal/authn` | ✅ / ⚙️ | Operator wires the IdP and step-up policy; root basic-auth should be disabled in production. |
| **Multi-tenant isolation** (segregation) | Platform vs tenant roles; cross-tenant access denied at the authorization chokepoint. `internal/handlers` (`canInTenant`), `internal/rbac` | ✅ | Single-tenant deployments use the `default` tenant. |
| **Physical, personnel, environmental security** (BR §5.1, §5.3; WebTrust environmental) | — | 👤 | Entirely operator: facility, HSM tamper tier, background checks, training, offline-root storage. |

### 1.6 Business continuity & assessments

| Control | Implementation | Status | Gaps & assumptions |
|---------|----------------|--------|--------------------|
| **Backup & disaster recovery, tested** (BR §5.7; WebTrust business continuity) | Leader-elected encrypted DR backups (no private keys) + **automated restore-verification** + DR drills (incl. PostgreSQL PITR + audit-chain continuity). `internal/backup`, `scripts/dr-drill*.sh` | ✅ / 👤 | HSM key recovery is token-restore or re-ceremony (keys never in a file backup). Operator schedules and stores backups off-site. |
| **Key changeover / rollover** (BR §6.3.2, §5.6) | Dual-chain intermediate rotation with overlap; combined-chain publication. `internal/ca` rotation; [ADR 0004](../adr/0004-dual-chain-rotation-overlap.md) | ✅ | Root changeover is an operator ceremony. |
| **Continuous self-assessment / monitoring** (WebTrust monitoring) | `doctor` preflight, issuance canary, CT-inclusion monitor, restore-verify, external-client interop suite, Prometheus/Grafana + alerts. `internal/doctor`, `internal/canary`, `internal/ctmonitor`, `scripts/interop-test.sh` | ✅ / ⚙️ | Operator wires alerting destinations. |
| **Independent WebTrust / ETSI / BR audit** (BR §8; WebTrust attestation) | Control mapping (this doc) + self-audit tooling supports the auditor. | 👤 | The **attestation itself is performed by a qualified external auditor** on the operating organization — the software cannot self-certify. |
| **Published CP/CPS conforming to RFC 3647** (BR §2.2, §3647) | RFC 3647 CP/CPS template populated from the implementation. [certificate-policy.md](certificate-policy.md) | ⚙️ / 👤 | Operator completes every `[OPERATOR: …]` placeholder, assigns policy OIDs, and formally adopts/publishes it. |

---

## 2. S/MIME Baseline Requirements (mailbox-validated profiles)

Applies to the `smime` / `smime-sign` / `smime-encrypt` profiles.
`internal/certlint/smime.go`, `internal/smime`.

| Control (SMBR) | Implementation | Status | Gaps & assumptions |
|----------------|----------------|--------|--------------------|
| **Mailbox validation / `rfc822Name` SAN present** (§7.1.4.2.1) | Validate + normalize (punycode) + allowlist mailbox SANs; require ≥ 1 rfc822Name. `internal/smime`, `internal/certlint/smime.go` (`smime_san_present`) | ✅ | Mailbox **control** proof for public S/MIME is via ACME `email-reply-00` (RFC 8823, `internal/mailtransport`); operator-driven issuance relies on the RA process. |
| **Forbid non-mailbox SAN types** (§7.1.4.2.1) | Reject dNSName/iPAddress/URI SANs in mailbox certs. `internal/certlint/smime.go` (`smime_san_types`) | ✅ | — |
| **rfc822Name syntax / normalized form** (§7.1.4.2) | RFC 5321 addr-spec, lowercase A-label domain. `internal/certlint/smime.go` (`smime_email_syntax`) | ✅ | — |
| **EKU: `emailProtection` required; exclusions; strict = only emailProtection** (§7.1.2.3(f)) | Require emailProtection; forbid serverAuth/codeSigning/timeStamping/OCSPSigning/anyEKU; strict allows no other. `internal/certlint/smime.go` (`smime_eku`) | ✅ / ⚙️ | Class (`legacy`/`multipurpose`/`strict`) is per-profile. |
| **Key-usage split (sign vs encrypt vs dual)** (§7.1.2.3(e)) | Enforce KU per variant (RSA keyEncipherment / EC keyAgreement). `internal/certlint/smime.go` (`smime_key_usage`) | ✅ | Built-in encrypt/dual profiles expect RSA subject keys; EC-ECDH needs a custom profile. |
| **Validity caps by class** (§6.3.2) | 1185 d legacy, 825 d multipurpose/strict. `internal/certlint/smime.go` (`smime_validity`) | ✅ | — |
| **Subject `emailAddress` / mailbox CN must match a SAN** | Match subject email / mailbox-shaped CN against rfc822Name SANs. `internal/certlint/smime.go` (`smime_subject_email`) | ✅ | — |
| **Encryption-key escrow governance** | Optional M-of-N escrow of the *encryption* subject key only (never signing keys). `internal/secret` escrow | ⚙️ / 👤 | Operator decides whether to offer escrow and its quorum. |

---

## 3. WebTrust for CA — principle coverage

WebTrust's criteria are organizational; this table maps each principle to the
supporting software control and names the operator obligation. See §1.5–1.6
above for the detailed BR rows.

| WebTrust principle | Supporting implementation | Status | Operator obligation |
|--------------------|---------------------------|--------|---------------------|
| **CA business-practices & CP/CPS disclosure** | [certificate-policy.md](certificate-policy.md) (RFC 3647) + this mapping | ⚙️ / 👤 | Complete, approve, version, and publish the CP/CPS. |
| **CA key lifecycle mgmt** (generation, protection, backup, changeover, destruction) | HSM non-extractable keys, ceremony, dual-chain rotation, no-key backups. `internal/keyprovider`, `internal/pki`, `internal/ca`, `internal/backup` | ✅ / 👤 | Witnessed ceremonies; HSM validation level; key-destruction on termination. |
| **Certificate lifecycle mgmt** (registration, issuance, revocation, status) | Enrollment protocols + fail-closed gate pipeline + CRL/OCSP + revocation tooling. `internal/acme|est|scep|cmp|brski`, `internal/ca`, `internal/caa`, `internal/certlint`, `internal/ct` | ✅ / ⚙️ | RA identity vetting; revocation SLA staffing. |
| **Subordinate-CA lifecycle** | Intermediate issuance, technically-constrained sub-CAs (Name Constraints), external/offline-root import, cross-signing. `internal/ca`, `internal/nameconstraints` | ✅ / ⚙️ | Governance of externally-signed / cross-signed relationships. |
| **CA environmental controls — security mgmt, asset classification, personnel, physical, ops** | RBAC, four-eyes, strong authn, rate limiting, TLS fail-closed, static-analysis/fuzz/race/vuln gates. `internal/rbac`, `internal/approval`, `internal/authn`, `internal/ratelimit` | ✅ / 👤 | Physical facility, personnel security, patching, change management. |
| **System access mgmt & monitoring/logging** | Tamper-evident anchored audit log, SIEM export, live SSE feed, metrics/alerts, doctor/canary self-checks. `internal/audit`, `internal/anchor`, `internal/siem`, `internal/metrics`, `internal/doctor`, `internal/canary` | ✅ / ⚙️ | Log retention, alert routing, SOC/on-call. |
| **Systems development & maintenance** | SBOM + cosign signatures + SLSA provenance + govulncheck; reproducible-ish tagged releases. root `Makefile`, `release.yaml`; [supply-chain](../development/supply-chain.md) | ✅ / 👤 | Operator's own change-control and deployment pipeline. |
| **Business continuity / disaster recovery** | Encrypted DR backups + automated restore-verification + DR drills. `internal/backup`, `scripts/dr-drill*.sh` | ✅ / 👤 | Off-site storage, RTO/RPO targets, periodic live drills. |
| **Independent attestation** | This mapping + self-audit tooling as auditor evidence. | 👤 | Engage a qualified WebTrust/ETSI auditor. |

---

## 4. Summary of known gaps (do not skip)

These are the honest limitations an auditor will find. They are design choices
or unimplemented items, **not** claims the software makes and fails.

1. **MPIC (BR §3.2.2.9) is not implemented** — validation is single-vantage.
   Required for public trust after its effective date.
2. **Weak-key rejection is structural, not full-factoring** — the pre-issuance
   gate ([key-checks](../issuance/key-checks.md)) covers ROCA/CVE-2017-15361, RSA
   exponent/modulus policy, the Debian OpenSSL weak-key list, and an operator
   compromised-key blocklist, but does not scan for small factors / Fermat-close
   primes / shared-factor (batch-GCD) weaknesses.
3. **Validity-cap phased reductions (SC-081)** are not date-driven — the cap is
   398 days unless the operator tightens the profile.
4. **CT can be configured fail-open** per profile, and browser-specific log
   diversity/SCT-count policy is not tracked by the software.
5. **Always-on linting is a curated subset**; full zlint coverage requires the
   `-tags zlint` build.
6. **DV-class only**: OV/EV organization/individual identity vetting is a manual
   RA process, not automated.
7. **Publicly-trusted status, HSM FIPS-validation level, physical/personnel
   security, revocation SLA, and the legal CP/CPS** are operator/organizational
   responsibilities the software supports but cannot satisfy.
8. **`certificateHold` exists** and must be disabled for public TLS profiles by
   the operator (the BRs forbid TLS suspension).

## See also

- [Certificate Policy / CPS (RFC 3647)](certificate-policy.md) — the policy this maps to.
- [Architecture Decision Records](../adr/README.md) · [Security review](../security/security-review.md) ·
  [Pre-issuance linting](../issuance/certlint.md) · [CAA](../issuance/caa.md) ·
  [Certificate Transparency](../issuance/certificate-transparency.md) · [FIPS mode](../security/fips.md) ·
  [RBAC & audit](../security/rbac-and-audit.md) · [Key ceremony & DR](../hsm/key-ceremony.md).
