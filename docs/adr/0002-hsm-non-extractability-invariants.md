# ADR 0002 — HSM keys are generated on-device and never extractable

- **Status:** Accepted
- **Deciding tasks:** Tasks 4, 5, 12, 16
- **Code:** `server/internal/keyprovider`, `server/internal/pki`

## Context

The security claim of an HSM-backed CA is only as strong as the guarantee that
private key material never exists outside the device. A CA key that can be
exported — even once, even by an administrator — voids the audit story: no log
can prove the key did not sign something off-system. The same reasoning applies
to the secret-encryption KEK and the TSA key.

## Decision

Private keys are **generated on the device** and are created with
non-extractable, sign-only (or, for the KEK, unwrap-only) attributes. The
system never has an API that exports a private key. Concretely:

- `GenerateKey` sets PKCS#11 attributes so the key is `CKA_SENSITIVE`,
  `CKA_TOKEN`, non-`CKA_EXTRACTABLE`, and capability-scoped (sign-only for CA
  and TSA keys; decrypt/unwrap-only for the KEK).
- On YubiHSM the key's attestation certificate proves `origin=generated`,
  never-exported, and sign-only capabilities — this is what `secsy-verify`
  checks in the chain-of-trust proof.
- **Backup never touches private keys.** `secsy-ca backup` exports CA metadata
  and a DR manifest only; key material is recovered by restoring the HSM
  token's own encrypted blob under its wrap key, never as plaintext (see
  [key ceremony & DR](../key-ceremony.md)).
- **Labels are unique.** Two token objects sharing a `CKA_LABEL` can resolve a
  public and private half from different key pairs, yielding intermittently
  unverifiable signatures. `GenerateKey` refuses to create a second key with an
  existing label; this is a regression-tested Provider contract.

## Consequences

- The [security invariants](../security-review.md) are testable and tested:
  fuzz and integration suites assert non-extractability and reject raw CSR
  extension smuggling.
- **Disaster recovery is HSM-shaped.** You cannot restore a CA from a file
  backup alone; you restore the token (or re-run a key ceremony) and then
  reattach metadata. The [DR drill](../key-ceremony.md) exercises exactly this.
- Losing the token without a token-level backup means losing the key — by
  design. This is why the [key ceremony](../key-ceremony.md) and DR procedures
  are mandatory before production issuance.
- This invariant is a hard constraint on every later feature: rotation
  ([ADR 0004](0004-dual-chain-rotation-overlap.md)), escrow, and PQC
  ([ADR 0005](0005-pqc-hybrid-algorithm-choice.md)) all had to preserve it, and
  the PQC software fallback is explicitly *not* HSM-backed and documented as
  such.
