# Four-eyes / maker-checker approvals

Secsy PKI can hold high-risk operations at a fail-closed gate until a
configurable number of **distinct** approvers — never the requester — sign off.
This implements separation of maker (who requests) from checker (who approves),
a standard control for high-assurance certificate authorities.

The gate is **disabled** unless `approvals.enabled` is set, so existing
deployments are unaffected until they opt in.

## Roles

- The **`approver`** role (capability `approval:approve`) may approve or reject
  requests. It is deliberately separate from the roles that *request* the guarded
  operations (e.g. `issuer`, `admin`): separating maker from checker is the whole
  point, and the gate additionally denies **self-approval by identity** (the
  requester can never approve their own request, even if they hold `approver`).
- The **`auditor`** role has read-only visibility into the queue
  (`approval:read`).

## Guarded operation classes

| Class               | Guards                                             |
|---------------------|----------------------------------------------------|
| `ca.create`         | Creating a root or intermediate CA                 |
| `ca.rotate`         | Intermediate-CA key rotation                       |
| `ca.retire`         | Retiring a superseded intermediate CA              |
| `revocation.bulk`   | Bulk certificate revocation                        |
| `secret.kek_rotate` | Secret-layer KEK rotation                          |
| `cert.issue`        | **Operator/API leaf issuance** (per-profile)       |
| `profile.change`    | (reserved) issuance-profile changes                |
| `escrow.policy`     | (reserved) key-escrow-policy changes               |

## Configuration

```yaml
approvals:
  enabled: true
  default_threshold: 2        # distinct approvers for any guarded class
  request_ttl_hours: 72       # a pending request expires after this window
  thresholds:                 # per-class overrides (0 = leave that class ungated)
    cert.issue: 2
    ca.create: 2
    revocation.bulk: 3
```

- A bare `enabled: true` (no thresholds) guards **every** class at threshold 2.
- When only per-class `thresholds` are given, unlisted classes stay **ungated**,
  so you can guard just a subset (e.g. only `cert.issue`).
- Tightening the policy never weakens an in-flight request: each request
  snapshots its `required_approvals` at creation time.

## Per-profile manual issuance approval (`cert.issue`)

Routine leaf issuance normally executes immediately. For high-assurance,
wildcard, or otherwise sensitive certificate shapes, mark the **profile** with
`require_approval: true` so operator/API issuance under it is held for approval:

```yaml
profiles:
  - name: wildcard-tls
    description: "Wildcard TLS certificate — held for manual approval"
    key_usages: [digitalSignature, keyEncipherment]
    ext_key_usages: [serverAuth]
    default_validity_days: 90
    max_validity_days: 397
    require_approval: true
```

Enforcement requires **both** `require_approval: true` on the profile **and** the
`cert.issue` class guarded (via `approvals.enabled` + a positive threshold). When
the gate is off, `require_approval` is inert and issuance proceeds immediately.

### Flow

1. A caller `POST /api/ca/{id}/issue` under a `require_approval` profile. Instead
   of a certificate, the server validates the CSR, parks the request, and returns
   **`202 Accepted`** with the pending-approval id (also in the
   `X-Secsy-Approval-Id` header) and a `certificate_url`. No certificate is
   issued. Audit: `cert.issue.pending`.
2. The request appears in the approval queue. Distinct approvers approve it
   (`POST /api/approvals/{id}/approve`), reusing the same engine that guards the
   admin operations. Self-approval and repeat votes by the same approver are
   refused.
3. Once the threshold is met, fetch the certificate from
   **`GET /api/approvals/{id}/certificate`**. The server performs the held
   issuance on the HSM **exactly once**, records the serial, and returns the
   certificate; subsequent fetches redeliver the same certificate. Audit:
   `cert.issue.approved`.
4. On **rejection** or **expiry** the request is terminal and no certificate is
   ever issued. Audit: `cert.issue.denied`.

The request fingerprint pins the exact issuance (profile + subject + SANs +
requester), so an approval cannot authorize a different certificate than the one
requested.

### Scope: automated protocol flows bypass the manual gate

The manual gate applies **only** to operator/API-driven issuance — the REST and
gRPC `IssueCertificate` paths. The automated enrollment protocols —
**ACME, EST, SCEP, and CMP** — enroll machines and call the issuance engine
directly, so they **always bypass** the `cert.issue` gate regardless of a
profile's `require_approval` flag. This is deliberate: those flows are
machine-to-machine and are governed by their own controls (EAB, mTLS, hardware
key attestation, CAA, rate limits). If you need a profile approved-only for
humans but automatable for machines, that is exactly the behavior you get.

> The `secsy-ca issue` CLI (which calls the CA manager directly, like the
> `init-root` / `issue-intermediate` bootstrap commands) is likewise not gated;
> the CLI's role in this workflow is the **approval queue**, below.

## CLI

```console
# List / inspect requests (works for every class, including cert.issue)
secsy-ca approvals list [-status pending] [-class cert.issue]
secsy-ca approvals show <id>

# Approve / reject (a DIFFERENT approver than the requester is required)
secsy-ca approvals approve <id> -approver alice -comment "reviewed"
secsy-ca approvals reject  <id> -approver alice -comment "denied"

# Once a cert.issue request is approved, complete and fetch the certificate
secsy-ca approvals certificate <id>            # prints the leaf PEM
secsy-ca approvals certificate <id> -chain     # leaf + issuer
secsy-ca approvals certificate <id> -out leaf.pem
```

`approvals certificate` signs on the HSM, so it builds the CA key provider; the
other subcommands need only the database.

## Console

The **Approvals** page lists the queue with Approve / Reject buttons. A
`cert.issue` request that has reached `approved`/`executed` shows a
**Certificate** button that fetches (and, the first time, completes) the issued
certificate and downloads the PEM.

## Audit & metrics

- Engine lifecycle events (all classes): `approval.request`, `approval.approve`,
  `approval.reject`, `approval.execute`, `approval.expire` — in the
  tamper-evident hash-chained event log.
- Issuance-domain events: `cert.issue.pending`, `cert.issue.approved`,
  `cert.issue.denied`.
- Metric `secsy_cert_issue_approvals_total{result=pending|approved|denied|error}`.

Stale requests are retired by a leader-elected background sweep and are also
enforced fail-closed at read time.
