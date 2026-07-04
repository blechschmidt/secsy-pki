# ADR 0006 — Four-eyes (maker-checker) approval for sensitive operations

- **Status:** Accepted
- **Deciding tasks:** Task 81 (admin-op approvals), Task 84 (per-profile issuance gate)
- **Code:** `server/internal/approval` (engine + classes), `server/internal/issueapproval`
  (pull-model issuance parking), the `protectStepUp`/gate chokepoints in
  `server/internal/handlers` and `server/internal/ca`

## Context

Some operations are catastrophic if performed by a single compromised or mistaken
operator: creating or rotating/retiring a CA, bulk-revoking certificates, rotating
the secret-layer KEK, minting a machine API token, or issuing a high-value leaf.
RBAC answers "may this principal do X?" but not "should *two* people agree before
X happens?" Regulated PKI operation (WebTrust, CA/Browser Forum network-security
requirements) expects **dual control** over exactly these actions.

Bolting an approval check onto each call site invites drift — a new issuance path
or a new admin endpoint silently skips the check. And an approval workflow that
*fails open* (proceeds when the approval store is unreachable) is worse than none:
it turns a control into theater.

## Decision

A single **maker-checker gate** guards a fixed, enumerated set of operation
**classes**, enforced as a **fail-closed chokepoint** rather than a per-call-site
courtesy check.

- **Enumerated classes** (`approval.Classes`): `ClassCACreate`, `ClassCARotate`,
  `ClassCARetire`, `ClassBulkRevoke`, `ClassKEKRotate`, `ClassTokenCreate`,
  `ClassProfileChange`, `ClassEscrowPolicy`, and `ClassCertIssue` (the per-profile
  issuance gate). Each guarded operation routes through the gate before it takes
  effect; the gate is the one place issuance/admin can be held.
- **Distinct approvers.** An operation needs *N* approvals from principals holding
  the `approver` role, and **the maker cannot be a checker** — self-approval is
  refused, enforced by a `UNIQUE(approval_id, approver)` constraint plus an
  explicit maker≠approver check. `N` is per-class (default 1 checker → two people
  total; raise for higher-assurance classes).
- **Pull model for issuance** (Task 84). A gated `cert.issue` does not block the
  request thread: it **parks** with `202 Accepted` + an approval id, persisting the
  full issuance payload. After approval the client fetches the freshly-signed
  certificate from `GET /api/approvals/{id}/certificate`. Signing happens only
  once the checker clears it, so no HSM work is done for a request that may be
  rejected.
- **Fail closed.** If the approval cannot be recorded/confirmed, the operation
  does **not** proceed. A guarded action with the gate misconfigured is refused,
  not waved through.
- **Automated enrollment bypasses the issuance gate by design.** ACME, EST, SCEP,
  and CMP are machine protocols that cannot block on a human; the per-profile
  `require_approval` gate applies to the interactive REST/gRPC/CLI issuance paths
  only. Dual control for those protocols is exercised at profile/CA configuration
  time (itself a gated class), not per certificate.

Every gate transition is audited (`*.pending` / `*.approved` / `*.rejected`, and
`cert.issue.*` for issuance) with a Prometheus metric, so held and cleared
operations are observable.

## Consequences

- **A single operator can be fully blocked from a guarded action** — that is the
  point. Break-glass (a genuine lone-operator emergency) means an admin lowers the
  class's approver count in config and restarts, recording the exception; the
  system does not provide a silent self-approval escape hatch. The
  [runbook](../RUNBOOK.md#governance-approvals-suspendhold--api-tokens) documents
  the stuck-queue and break-glass procedures.
- **Gated issuance is asynchronous.** Callers must handle `202 + poll`, not a
  synchronous certificate. This is why the gate is opt-in per profile: turn it on
  only where a human-in-the-loop is worth the latency.
- **Adding a new sensitive operation means adding a class and routing it through
  the gate**, not inventing a new check. The enumerated-class list is the audit
  surface for "what requires dual control here?"
- Composes with the other fail-closed gates ([ADR 0003](0003-fail-closed-security-gates.md))
  and with WebAuthn step-up ([authentication](../authentication.md)): step-up
  proves *who* is acting; four-eyes proves *two* independent people agreed.
