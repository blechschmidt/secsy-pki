# ADR 0001 — Backend-agnostic key-provider abstraction

- **Status:** Accepted
- **Deciding task:** Task 4
- **Code:** `server/internal/keyprovider`

## Context

Every cryptographic operation in the system — CA signing (leaves, CRLs, OCSP,
delegated responders), the secret-encryption KEK, TSA signing, escrow
recovery-agent keys — ultimately needs a private key. That key may live on a
YubiHSM, a network HSM reached over PKCS#11, SoftHSM in dev/CI, or (for the
PQC software fallback) an on-disk keystore. If each feature reached for PKCS#11
directly, the HSM contract (session pooling, login handling, unique labels,
non-extractability) would be re-implemented — and re-broken — in a dozen
places.

## Decision

All key operations route through a single abstraction in
`internal/keyprovider`. A `Provider` exposes a small, backend-neutral surface:
generate a key by `KeySpec`, find one by `KeyRef` (label), obtain a
`crypto.Signer`, and `Ping` for readiness. The PKCS#11 backend
(`PKCS11Provider`) is the production path; a software backend serves dev and the
PQC fallback. Providers are decorated with an instrumentation wrapper
(`Instrument`) that emits metrics and exposes the `Prober` interface consumed by
`/readyz`.

Higher layers (`internal/ca`, `internal/secret`, `internal/tsa`) never import
`miekg/pkcs11`; they hold a `Provider` and speak in labels.

## Consequences

- **One place to get the HSM contract right.** Session pooling
  (`pki/pool.go`), login lifecycle, and the unique-label invariant
  ([ADR 0002](0002-hsm-non-extractability-invariants.md)) are implemented once.
- **SoftHSM is a first-class backend**, so the full stack is testable in CI
  without hardware. The same code path runs against a real HSM in production;
  migration is a config change (see [HSM migration](../hsm/production-migration.md)).
- **Readiness is uniform.** `/readyz` probes the provider via `Prober.Ping`;
  a wrong PIN or unreachable token surfaces as *not ready* rather than as
  per-request failures.
- **Cost:** the abstraction is deliberately narrow. Backend-specific features
  (YubiHSM attestation, audit hash chain) live behind capability interfaces and
  are only available when the backend supports them.
