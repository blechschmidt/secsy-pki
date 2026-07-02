# ADR 0004 — Intermediate-CA rotation via dual-chain overlap

- **Status:** Accepted
- **Deciding task:** Task 24
- **Code:** `server/internal/ca/rotation.go`, `server/cmd/secsy-ca/rotation.go`

## Context

Intermediate CA signing keys must be rotatable — on a schedule, on suspected
compromise, or to change algorithm. A naive "revoke old, issue new" cutover
breaks every unexpired leaf the old key signed: relying parties can no longer
build a valid chain. We need to rotate the key without invalidating outstanding
leaves, and without asking every subscriber to re-enroll on the same day.

## Decision

Rotation uses a **dual-chain overlap** window with three explicit stages:

1. **Rotate** (`secsy-ca rotate-intermediate`). Generate a fresh keypair on the
   HSM and issue a new intermediate certificate under the same parent (root),
   carrying the **identical subject DN**. Only the key changes, so it is a
   drop-in issuer. The old CA is marked `superseded` (with `successor_id`); the
   new CA is `active` (with `predecessor_id`). New issuance immediately targets
   the new key via `ActiveIssuerID()`.

2. **Overlap** (`secsy-ca publish-chain`, `/api/ca/{id}/chain`). Both
   intermediates are published together as a combined bundle. A leaf signed by
   the old key chains through the old intermediate; a leaf signed by the new key
   chains through the new intermediate. Relying parties pick the right issuer by
   Authority Key Identifier. No leaf breaks.

3. **Retire** (`secsy-ca retire-intermediate`). Once no leaves signed by the old
   key remain valid — they expired or renewed onto the new key — the old
   intermediate is revoked under its parent and the parent CRL/OCSP is
   refreshed. The old CA becomes `retired` and drops from freshly published
   chains. Premature retirement (while old-key leaves are outstanding) is
   refused unless forced.

A `retire_after` deadline is computed as the latest `NotAfter` among leaves the
old key signed; `secsy-ca rotation-status` reports lineage and readiness.

## Consequences

- **Zero-downtime key rollover** for correctly-behaving relying parties, at the
  cost of running two valid issuers during the overlap.
- **Retirement is gated on drain**, so the safe path is enforced by tooling, not
  by operator memory. The `-force` flag exists for compromise scenarios where
  breaking outstanding leaves is the *goal*.
- The whole flow is exercised end-to-end by `scripts/rotation-drill.sh` against
  SoftHSM, and the monitor can trigger auto-rotation. See
  [intermediate key rotation](../ca-rotation.md) and the
  [runbook rotation procedure](../RUNBOOK.md#ca-key-rotation-and-retirement).
- Rotation preserves [ADR 0002](0002-hsm-non-extractability-invariants.md): the
  new key is generated on the HSM and never extracted; the old key is retired,
  not exported.
