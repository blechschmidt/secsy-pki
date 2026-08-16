# Compliance & audit readiness

*The documents a WebTrust or CA/Browser Forum audit asks for.*

Two audit-facing documents. Both are populated from the actual implementation
and mark, explicitly, the organizational facts an operator must supply and the
controls that are genuinely not met.

| Guide | Covers |
|-------|--------|
| [**Certificate Policy / CPS (RFC 3647)**](certificate-policy.md) | The governance document WebTrust / CA-Browser-Forum audits require: an RFC 3647-structured Certificate Policy & Certification Practice Statement (all nine sections) populated from the actual implementation — HSM key generation/non-extractability, the fail-closed pre-issuance gate pipeline (lint/CAA/name-constraints/CT), revocation (CRL/delta/OCSP), tamper-evident + RFC 3161-anchored audit logging, key ceremony, DR, and trusted roles/RBAC — with explicit `[OPERATOR: …]` placeholders for the organizational/legal facts a deployment must supply |
| [**Compliance control mapping**](compliance-mapping.md) | CA/Browser-Forum TLS Baseline Requirements, S/MIME BR, and WebTrust-for-CA principles traced to the implementing feature/package/file, each with a status (enforced / config-dependent / operator / gap) and an explicit **gaps-and-assumptions** column — verified against the code (including honestly-listed gaps: MPIC, pre-issuance weak-key blocklisting, SC-081 phased validity) |

---

↩ Back to the [documentation map](../README.md) · [project README](../../README.md)
