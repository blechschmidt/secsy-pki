# ADR 0003 — Pre-issuance and transport gates fail closed

- **Status:** Accepted
- **Deciding tasks:** Tasks 12 (TLS), 27 (certlint), 31 (CAA)
- **Code:** `server/internal/ca` (`buildLeaf`), `server/internal/certlint`,
  `server/internal/caa`

## Context

Several checks guard certificate issuance and transport: TLS on the server
socket, CA/Browser Forum Baseline-Requirements linting, and DNS CAA
authorization. Each has a "what happens when the check can't run?" failure mode.
An availability-first (fail-open) default is tempting — a DNS hiccup shouldn't
break issuance — but for a CA the cost of issuing a certificate that *should
have been refused* is far higher than the cost of a failed request the client
will retry. A mis-issued, CAA-violating, or non-compliant certificate is
already in the wild the moment it is signed.

## Decision

Security gates **fail closed**: if the gate cannot positively confirm the
operation is allowed, issuance is refused.

- **TLS is mandatory and fail-closed.** The server does not fall back to
  cleartext; a missing or unreadable key/cert is a startup failure, not a
  downgrade.
- **certlint** runs inside `buildLeaf` before signing. In `enforce` mode a lint
  error aborts issuance; `warn` mode records findings without blocking. Enforce
  is the default posture for public-facing profiles. See
  [certlint](../security/security-review.md) and the `secsy-ca lint` CLI.
- **CAA** (RFC 8659) is checked in `buildLeaf` for DNS identifiers. The
  per-profile mode is `off` / `permissive` / `enforce`; in `enforce` a
  DNS-resolution failure or a prohibiting record blocks issuance (fail-closed),
  and only an explicit `permissive` mode treats resolution failure as
  authorized. See [CAA record checking](../issuance/caa.md).

Every blocked issuance emits an audit event (`cert.lint`, `cert.caa`) and a
Prometheus metric, so a fail-closed refusal is observable, not silent.

## Consequences

- **A DNS or CT outage can stop issuance.** That is the intended trade-off for
  `enforce`/fail-closed configuration. The [runbook](../operations/runbook.md) documents
  how to distinguish an outage-induced refusal from a genuine policy violation,
  and how to reach `permissive`/`warn` deliberately (per profile) if a
  short-term availability exception is justified.
- **Note the deliberate exception:** Certificate Transparency
  ([Task 26](../issuance/certificate-transparency.md)) is configurable *per profile* as
  fail-open **or** fail-closed via `fail_open`, because CT logs are third-party
  infrastructure with independent availability. The default is fail-closed;
  operators who need issuance to survive a CT log outage opt into `fail_open`
  knowingly. This is the one gate where fail-open is a supported first-class
  choice — see [ADR rationale in the runbook](../operations/runbook.md#ct-log-outage).
- The posture is uniform and greppable: a fail-open behavior anywhere in the
  issuance path is a bug unless it is one of the explicitly-opted-in modes
  above.
