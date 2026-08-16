# Issuance policy & pre-issuance gates

*What is checked before the HSM is ever asked to sign.*

Every issuance path — REST, gRPC, CLI, ACME, SCEP/EST, CMP, BRSKI — funnels
through the same ordered stack of **fail-closed** gates. A gate that cannot
reach its dependency refuses the issuance rather than waving it through. Each
page documents one gate: what it enforces, how to set it to
`off`/`permissive`/`enforce` per profile, and the audit event and metric it
emits.

| Guide | Covers |
|-------|--------|
| [**Issuance preview (dry-run)**](preview.md) | Validating a would-be issuance through the full fail-closed pre-issuance gate stack (lint/CAA/name-constraints/policy/S-MIME/key-checks/UPN/QC/validity + the four-eyes "would-park" and attestation-posture verdicts) **without** signing, allocating a serial, persisting a record, auditing, or taking a rate-limit/quota reservation — for operators and CI: `secsy-ca issue -dry-run` (exits non-zero if rejected), `POST /api/ca/{id}/certificates:preview`, gRPC `PreviewCertificate`, and the console Issue-page preview button; the gate evaluators are shared with real issuance so the verdict cannot drift |
| [**Pre-issuance certificate linting**](certlint.md) | The fail-closed pre-issuance lint gate: the dependency-free hand-rolled CA/Browser-Forum Baseline Requirements checks (always on) plus the **optional industry-standard `github.com/zmap/zlint` backend** compiled in only under `-tags zlint` (default/FIPS/supply-chain builds stay dependency-free), the per-profile `lint.zlint` level→enforce/warn/ignore mapping + source/name filters, the pre-issuance "linting certificate" synthesis, `secsy-ca lint -zlint` (PEM/DER) + `/api/lint` + console, the `zlint/`-namespaced findings in `cert.lint` audit + metrics, and the dependency / `govulncheck -tags zlint` implications |
| [**CAA record checking (RFC 8659)**](caa.md) | DNS Certification Authority Authorization as a fail-closed pre-issuance gate on every issuance path: the tree-climbing + CNAME/DNAME algorithm, `issue`/`issuewild`/`iodef` evaluation against the CA identifier, per-profile `off`/`permissive`/`enforce` mode, the DNS-answer TTL cache, and the `cert.caa` audit event + Prometheus metrics |
| [**Name Constraints & Certificate Policies (RFC 5280)**](name-constraints.md) | First-class Name Constraints (2.5.29.30) and the certificate-policy family (2.5.29.32/.33/.36) on CAs: configuring permitted/excluded DNS/IP/email/URI/dirName subtrees and policy OIDs on roots/intermediates, per-profile leaf policy assignment, the fail-closed pre-issuance name-constraint gate (`cert.nameconstraint` audit + metrics), rotation preservation, and `openssl verify` interop |
| [**Weak-key & compromised-key gate**](key-checks.md) | The fail-closed pre-issuance key-quality gate (CA/Browser Forum BR §6.1.1.3) on every issuance surface and the dry-run preview: ROCA/CVE-2017-15361 fingerprint detection, RSA exponent (e≥65537, odd) and modulus (odd, ≥2048-bit) policy, the optional operator-supplied **Debian OpenSSL weak-key blocklist**, an operator-managed **compromised-key blocklist** (`secsy-ca blocked-keys`, keyed by the SPKI SHA-256 fingerprint), and opt-in duplicate/reused-subject-key detection; per-profile enforce/warn, `cert.keycheck` audit + metrics, and `doctor keychecks.*` |
| [**Certificate Transparency (RFC 6962)**](certificate-transparency.md) | Optional precertificate submission and SCT embedding on the issuance path: registering CT logs, per-profile CT policy (min-SCTs, fail-open/closed, retries/timeouts), SCT signature verification, CT status in the console/API/audit log, and the leader-elected **SCT inclusion-proof monitor** (get-sth / get-proof-by-hash Merkle verification, log-misbehavior alerting, `secsy-ca ct` + doctor `ct.inclusion`) |

---

↩ Back to the [documentation map](../README.md) · [project README](../../README.md)
