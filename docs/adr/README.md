# Architecture Decision Records

This directory records the load-bearing design decisions of the secsy-pki
**enterprise edition**. Each ADR captures one decision that is already
implemented on the `enterprise` branch: the context that forced it, the choice
made, and the consequences operators live with.

ADRs are immutable once accepted. If a decision changes, add a new ADR that
supersedes the old one rather than editing history.

| ADR | Decision | Status |
|-----|----------|--------|
| [0001](0001-key-provider-abstraction.md) | Backend-agnostic key-provider abstraction | Accepted |
| [0002](0002-hsm-non-extractability-invariants.md) | HSM keys are generated on-device and never extractable | Accepted |
| [0003](0003-fail-closed-security-gates.md) | Pre-issuance and transport gates fail closed | Accepted |
| [0004](0004-dual-chain-rotation-overlap.md) | Intermediate-CA rotation via dual-chain overlap | Accepted |
| [0005](0005-pqc-hybrid-algorithm-choice.md) | ML-DSA (FIPS 204) for post-quantum and catalyst-hybrid certs | Accepted |
| [0006](0006-four-eyes-approval-gate.md) | Four-eyes (maker-checker) approval for sensitive operations | Accepted |

## Related documentation

- [Architecture overview](../../ARCHITECTURE.md)
- [Operator runbook](../RUNBOOK.md) — day-2 procedures that put these decisions
  into practice
- [Security review & hardening](../security-review.md)
