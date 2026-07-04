# Enterprise features: RBAC, audit logging, and configuration

This document describes the enterprise access-control, tamper-evident audit
logging, and centralized configuration added to secsy-pki (Task 8). These build
on the HSM-backed CA (Tasks 4–6) and secret-encryption (Task 7) features.

## 1. Role-based access control (RBAC)

Two complementary authorization layers govern every protected endpoint:

| Layer | Scope | Configured in | Answers |
|-------|-------|---------------|---------|
| **Org-wide roles** | whole system | `rbac:` config block | "what class of user is this?" |
| **Per-CA permissions** | a single CA | `/api/keys/{id}/permissions` | "may this subject sign with *this* CA?" |

The built-in **root** user (HTTP basic auth) is always a superuser and can be
disabled in production (`policy.allow_root_basic_auth: false`).

### Roles

| Role | Capabilities |
|------|--------------|
| `admin` | Everything: create/delete CAs, init roots/intermediates, manage groups & permissions, administer the HSM, issue certificates, read all logs, encrypt/decrypt secrets. Equivalent to root. |
| `issuer` | Issue / renew / revoke certificates and SSH/X.509 sign on **any** CA (that CA's restriction sets are still enforced), encrypt/decrypt secrets, and read logs. **Cannot** create/delete CAs, manage access control, or administer the HSM. |
| `auditor` | **Read-only**: the audit log, access log, tamper-evident event log (and its verification), and HSM audit log. Cannot perform or authorize any signing or administrative operation. |

Roles are assigned centrally to OIDC **subjects** (by `sub` claim or email) and
to **group IDs**. A user's effective roles are the union of its subject and
group assignments, resolved at authentication time and attached to the request
identity. Unknown role names are rejected at startup.

```yaml
rbac:
  subjects:
    "1a2b3c-oidc-subject": [admin]
    "auditor@example.com": [auditor]
  groups:
    "group-uuid-for-pki-ops": [issuer]
```

### Capability model

Endpoints check a coarse capability (`cert:issue`, `audit:read`, `ca:manage`,
`ca:configure`, `rbac:manage`, `hsm:manage`, `secret:encrypt`,
`secret:decrypt`). `admin`/root satisfy all of them. For **signing** endpoints,
access is granted by *either* the org-wide `cert:issue` capability *or* a per-CA
`SIGN_CERTIFICATE` grant — so existing per-CA delegation keeps working
unchanged, and an org-wide `issuer` no longer needs a grant on every CA.

## 2. Tamper-evident audit logging

Every security-sensitive operation is recorded in an **append-only,
hash-chained event log** (`event_log` table), capturing **who, what, when, which
target, and the result** (`success` / `denied` / `error`). Denied attempts are
logged too, which is essential for detecting probing.

Recorded actions include: CA creation, root/intermediate initialization, CA
deletion, certificate issue/renew/revoke, SSH and X.509 signing, secret
encrypt/decrypt, permission grant/revoke, and HSM provision/factory-reset.

### How tamper-evidence works

Each entry stores:

```
hash = SHA256( seq ‖ prev_hash ‖ id ‖ timestamp ‖ actor ‖ … ‖ result ‖ detail ‖ ip )
```

- Every field is **length-prefixed** before hashing, so no rearrangement of
  characters across field boundaries can forge a colliding entry.
- `prev_hash` links each entry to its predecessor; the first entry anchors to a
  fixed genesis hash.
- The `seq` sequence number is gap-free and assigned by the server under a mutex
  inside the same transaction that reads the previous hash, so the chain stays
  consistent even under concurrent writers.

Any modification, deletion, or reordering of a historical entry breaks the chain
from that point forward. `audit.VerifyChain` (and the `GET /api/events/verify`
endpoint) recompute the chain and report the sequence number of the first
inconsistency.

The chain alone cannot prove the log ever extended further than it does now — a
writer with store access could drop the newest entries or re-seal a rewritten
history. Enabling **audit-chain anchoring** (`audit.anchor` config) closes that
gap: the chain head is periodically bound into an RFC 3161 timestamp token
(internal HSM-backed TSA or an external TSA URL), persisted in `audit_anchors`,
and validated by `secsy-ca audit verify`. See the
[Audit-chain anchoring runbook section](RUNBOOK.md#audit-chain-anchoring).

### Endpoints (require `audit:read` — admin or auditor)

| Method & path | Purpose |
|---------------|---------|
| `GET /api/events` | Paginated event log (newest first); `?action=` and `?actor=` filters |
| `GET /api/events/verify` | Verify chain integrity; returns `200` if intact, `409` if tampered |
| `GET /api/audit-log` | Legacy per-signature certificate audit log |
| `GET /api/access-log` | HTTP access log |

### Exporting the log to a SIEM

The event log can be streamed to external syslog/CEF/webhook collectors and
verified or exported from the CLI (`secsy-ca audit verify` / `audit export`).
See [Audit log export to SIEM](audit-siem-export.md).

## 3. Centralized configuration

All governance lives in one YAML file (`config.yaml`) alongside the existing
server, database, OIDC, key-provider, PKCS#11/HSM, and secret settings:

- **`rbac`** — role assignments (above).
- **`policy`** — system-wide guardrails:
  - `max_cert_validity_days` — global cap on issued end-entity validity
    (0 = uncapped; per-profile / per-CA limits still apply).
  - `require_reason` — require a reason on sign requests that carry the field.
  - `allow_root_basic_auth` — enable/disable the built-in root user.
- **`profiles`** — custom certificate profiles layered over the built-ins
  (`server`, `client`, `server-client`, `code-signing`, `email`). A custom
  profile with a built-in's name overrides it, letting an operator tighten
  validity or add issuance shapes without a code change. Referenced key usages
  are validated at startup.

```yaml
policy:
  max_cert_validity_days: 90
  require_reason: true
  allow_root_basic_auth: false

profiles:
  - name: short-lived-client
    description: "Ephemeral mTLS client certificate"
    key_usages: [digitalSignature]
    ext_key_usages: [clientAuth]
    default_validity_days: 7
    max_validity_days: 30
```

See `server/config.yaml` for a fully-commented example.

## Security notes

- **Least privilege by default.** `auditor` cannot sign; `issuer` cannot
  administer CAs or the HSM. Secret encrypt/decrypt now require an explicit
  capability rather than mere authentication.
- **Non-repudiation.** The event log binds each action to the authenticated
  subject, the roles it held at the time, and the client IP.
- **Defense in depth.** Application-level hash chaining complements the
  device-level HSM audit log (YubiHSM), giving tamper-evidence even if the
  database is writable by an attacker who cannot forge SHA-256 preimages.
- **Fail-safe logging.** A failure to append an audit event is logged as a
  warning but never silently changes an authorization decision; the chain's
  integrity is independent of any single external side effect.
- **Systematic authorization coverage.** A table-driven regression matrix
  (`server/internal/handlers/authz_matrix_test.go` and the gRPC mirror
  `server/internal/grpcapi/authz_matrix_test.go`) asserts, for **every**
  registered route/RPC, that an unauthenticated caller gets `401`, a
  capability-lacking principal gets `403`, a cross-tenant principal is refused
  with no data leak, and a correctly-capable principal succeeds. The suite fails
  the build if a newly registered route has no declared RBAC/tenant intent, so
  access-control coverage cannot silently regress. See
  [authz-regression-matrix.md](authz-regression-matrix.md).
