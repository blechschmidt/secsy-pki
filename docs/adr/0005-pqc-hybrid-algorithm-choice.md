# ADR 0005 — ML-DSA (FIPS 204) for post-quantum and catalyst-hybrid certs

- **Status:** Accepted
- **Deciding task:** Task 29
- **Code:** `server/internal/pqc`

## Context

Certificates issued today may need to resist an adversary with a
cryptographically-relevant quantum computer within their validity or archival
lifetime. Two questions had to be answered: *which* post-quantum signature
scheme, and *how* to deploy it without breaking classical relying parties that
have never heard of it.

## Decision

- **Algorithm: ML-DSA (FIPS 204).** ML-DSA is the NIST-standardized lattice
  signature (derived from CRYSTALS-Dilithium). It is a finalized standard with
  a stable OID and a maintained Go implementation in Cloudflare CIRCL, which the
  code depends on. We did not pick a pre-standard or experimental scheme.
- **Two deployment modes, selected per profile:**
  - **Pure PQC** (`pqc-server`) — the certificate is signed with ML-DSA only.
    For relying parties that understand ML-DSA.
  - **Catalyst hybrid** (`hybrid-server`) — a classical certificate (ECDSA/RSA)
    additionally carries an ML-DSA alternative signature and subject public key
    in non-critical extensions. Classical verifiers ignore the extensions and
    validate normally; PQC-aware verifiers additionally check the alternative
    signature. This preserves interop while adding quantum resistance.
- **Software provider only.** ML-DSA keys are handled by the software backend,
  not the HSM, because SoftHSM (and most current PKCS#11 HSMs) do not implement
  ML-DSA. This is a **deliberate, documented exception** to
  [ADR 0002](0002-hsm-non-extractability-invariants.md): PQC/hybrid CA keys are
  *not* hardware-protected. Selection is explicit
  (`secsy-ca init-root -algorithm pqc|hybrid`), so an operator never gets a
  non-HSM key by accident.

## Consequences

- **Quantum-ready issuance today**, with a clear upgrade path to HSM-backed
  ML-DSA once hardware and PKCS#11 support arrive — at which point the software
  fallback can be retired.
- **Interop caveats are real.** Pure-PQC chains fail to verify in trust stores
  that lack ML-DSA; hybrid is the safe default for mixed environments. These
  caveats are documented in [PQC & hybrid certificates](../certificates/pqc.md).
- Because PQC keys are software-held, the [runbook](../operations/runbook.md) treats a
  PQC/hybrid CA-key compromise differently from an HSM-backed one: file-system
  key protection and backups matter, and the non-extractability proof from
  `secsy-verify` does not apply.
