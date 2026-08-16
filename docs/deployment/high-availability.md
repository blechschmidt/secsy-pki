# Multi-replica coordination & high availability

A single secsy-pki server runs a set of **singleton background jobs**: the
certificate-expiry monitor with auto-renewal, intermediate-CA auto-rotation,
OCSP pre-signing, the scheduled CRL/artifact publisher, audit-chain anchoring,
SIEM export, the external discovery scanner, and the synthetic issuance
canary. Run two replicas naively and
every one of those jobs runs twice — duplicate expiry alerts, racing renewals,
double HSM batch load, and two processes advancing the same SIEM cursor.

Task 68 makes `replicas > 1` first-class: replicas sharing one PostgreSQL
store elect a **background-job leader**, and every singleton job runs only on
the current leader. API traffic (issuance, OCSP/CRL serving, enrollment
protocols, the console) is served by **all** replicas — leadership only
schedules the background work.

## How the election works

The election is a **session-level PostgreSQL advisory lock**
(`pg_try_advisory_lock`) held on a dedicated, never-recycled connection:

- **Acquire.** Every replica retries `pg_try_advisory_lock(key)` on its
  election session every `retry_interval_seconds`. PostgreSQL grants the lock
  to at most one session, so at most one replica leads at any moment — there
  is no timestamp arithmetic to race on.
- **Lease = session.** The lock is held exactly as long as the session lives.
  The leader re-confirms every `renew_interval_seconds` by asking its own
  backend whether the lock is still granted (`pg_locks`), and **steps down the
  moment it cannot confirm** — connection loss, query timeout, or a PostgreSQL
  restart. Stepping down cancels the job contexts and waits for the jobs to
  exit before the replica campaigns again.
- **Failover.** A cleanly stopping leader (rolling update, scale-down)
  explicitly unlocks, so a standby takes over within one retry interval. A
  crashed leader's lock is freed when PostgreSQL observes its session end; a
  fully black-holed leader is bounded by TCP keepalives on the PostgreSQL side
  (tune `tcp_keepalives_*`, or add `keepalives_interval` to the DSN, if your
  network makes silent drops likely).
- **Fail closed, not split.** A leader that cannot confirm its lease stops its
  jobs locally even if the lock might still be held server-side. The failure
  mode is therefore a brief period with **no** leader (jobs pause), never two.

The lock key is the FNV-64a hash of `coordination.lock_name`
(default `secsy-pki/background-jobs`). Advisory locks are scoped per database,
so deployments in separate PostgreSQL databases never interact; if two
deployments must share one database, give each its own `lock_name`.

On **SQLite** there is nothing to elect — the store cannot be shared between
replicas — so the server holds leadership statically and behaves exactly as
before. This is also why the Helm chart refuses `replicaCount > 1` on SQLite.

## Leader-gated jobs

| Job | Why singleton | Why a handover is safe (idempotency) |
|-----|---------------|--------------------------------------|
| Expiry monitor / auto-renewal | duplicate alerts; racing renewals | a renewed certificate supersedes the old one — the next scan (any replica) sees it fresh and never renews twice |
| Intermediate-CA auto-rotation | two replicas would double-rotate | rotation runs inside the monitor scan; a rotated CA is no longer in the rotate-before window |
| OCSP pre-signing | full-store batch signing would multiply HSM load per replica | cache fill only; the new leader's first batch runs immediately and simply re-signs |
| CRL regeneration / artifact publishing | racing snapshot swaps against one store/bucket | CRL numbers are allocated monotonically under `FOR UPDATE`; publishing is an atomic snapshot swap — the new leader's snapshot supersedes |
| Audit-chain anchoring | one anchor per head is the point | the idle-skip rule refuses to re-anchor an unchanged head, so the new leader's first run is a no-op unless events arrived |
| SIEM export | the per-sink cursor is shared state | delivery is at-least-once from the durable cursor; a handover at worst redelivers the last unacknowledged batch |
| Discovery scanner | N replicas would probe every external endpoint N times | inventory records are upserted by fingerprint |
| Issuance canary | N replicas would multiply HSM probe load and tenant quota consumption | each probe is self-contained (issue → verify → revoke); a handover simply probes again on the new leader's schedule |
| ACME nonce GC | N replicas would each scan the shared consumed-set | the sweep is a plain `DELETE … WHERE expires_at < now` — idempotent, so a redundant run on another replica is harmless (an expired nonce is already rejected by its embedded timestamp before the set is consulted) |

Per-instance loops are deliberately **not** gated: the TLS OCSP staple
refresher (each replica staples its own listener certificate) and the gRPC/HTTP
listeners themselves.

## Shared vs per-replica request state

API traffic is served by every replica, so any state a public request touches
must either live in the shared store or be safe to keep per-replica:

- **ACME anti-replay nonces are shared** (correctness). Nonces are
  self-authenticating (HMAC over a timestamp + random bytes, keyed by a
  store-shared secret), and single use is enforced by a shared consumed-set, so
  a nonce minted by one replica is accepted — exactly once — by any other behind
  a load balancer. Before this, an in-process nonce map produced spurious
  `badNonce` retries on round-robin traffic. No configuration is required (the
  secret is generated once and persisted); see [ACME](../protocols/acme.md#11-operational-notes).
- **Rate-limit token buckets remain per-replica** (known follow-up). Each
  replica meters ACME/OCSP/CRL/SCEP/EST traffic against its own in-memory
  buckets, so the effective global limit is roughly `configured_rate ×
  replica_count`, and a client pinned to one replica sees that replica's bucket.
  Size the per-replica limits accordingly, or terminate rate limiting at a shared
  ingress/gateway in front of the fleet. A future shared/distributed limiter
  would remove this caveat; see [Rate limiting](../security/rate-limiting.md). The bounded
  HSM-concurrency guard is likewise per-replica by design (it protects each
  replica's own token sessions).

**Follower OCSP behavior.** Pre-signing fills an in-memory cache, so follower
replicas answer OCSP from their own per-request signing path and TTL cache
instead of the pre-signed batch. If you rely on pre-signing to keep the public
responder off the HSM entirely, front the responder with the published static
artifacts (the intended pairing — see
[OCSP pre-signing & publishing](../operations/ocsp-presign-publish.md)); the leader keeps
those artifacts fresh for every replica.

## Configuration

Nothing is required: the default mode `auto` elects via PostgreSQL when
`database.driver` is `postgres` and holds statically on SQLite.

```yaml
coordination:
  # auto (default) | postgres (require election; rejected on sqlite) |
  # static (always lead — single replica only)
  mode: auto
  # Advisory-lock namespace. Keep it stable: renaming it during a rolling
  # update briefly lets old-name and new-name replicas lead simultaneously.
  lock_name: secsy-pki/background-jobs
  renew_interval_seconds: 5   # leader lease confirmation cadence
  retry_interval_seconds: 5   # follower acquisition retry (bounds failover)
```

Failover latency ≈ session teardown + one `retry_interval_seconds` (clean
stops release the lock explicitly, so takeover is nearly immediate).

## Observability

- **`/readyz`** reports a `leadership` component on every replica:

  ```json
  "leadership": {"status": "leader", "detail": "mode=postgres"}
  ```

  A follower reports `"follower"` and is still **ready** — leadership is
  informational and never fails the probe.

- **Metrics** (see [observability](../operations/observability.md)):

  | Metric | Meaning |
  |--------|---------|
  | `secsy_leader_is_leader` | 1 on the replica running the singleton jobs, 0 elsewhere. Fleet-wide `max` should always be 1. |
  | `secsy_leader_transitions_total{to="leader"\|"follower"}` | Leadership gains/losses seen by this replica. A burst means flapping. |

- **Alerts** (shipped in the Prometheus rules): `SecsyPKINoJobLeader` (no
  replica leads for 10m — jobs are paused) and `SecsyPKILeadershipFlapping`
  (the election store is unhealthy).

- The election session is visible in PostgreSQL:

  ```sql
  SELECT pid, classid, objid FROM pg_locks WHERE locktype = 'advisory' AND granted;
  ```

## Kubernetes / Helm

```yaml
replicaCount: 3
externalDatabase:
  enabled: true
  dsnSecret: {name: secsy-db, key: database-dsn}
hsm:
  module:
    mode: hostPath        # every replica must reach the SAME HSM
persistence:
  enabled: false          # PostgreSQL is the source of truth
```

The chart enforces the preconditions at render time — `replicaCount > 1` fails
fast on the SQLite driver (single-node by construction) and on
`hsm.module.mode=softhsm` (each pod would provision its own token and hold
different CA keys). With multiple replicas the Deployment switches from
`Recreate` to `RollingUpdate`: followers keep serving during the roll and
leadership hands over as the leader pod stops. See
[Kubernetes deployment](kubernetes.md) for the rest of the chart.

## Testing

- `internal/leader` unit tests cover mode resolution and the job gate (start on
  gain, cancel on loss, restart on re-gain, no same-replica overlap), and —
  against a real PostgreSQL (`SECSY_TEST_PG_DSN`) — prove exactly-one-leader,
  clean-stop handover, and step-down after a server-side session kill
  (`pg_terminate_backend`).
- The chaos suite (`scripts/chaos-test.sh`) runs
  `TestChaosLeaderElectionTwoReplicas`: two in-process server instances against
  one PostgreSQL, asserting the follower runs zero jobs, an expiring
  certificate is renewed **exactly once** fleet-wide, every audit anchor covers
  a distinct head, stopping the leader fails over, and the post-handover leader
  neither double-renews nor re-anchors an unchanged head — with the audit
  chain intact throughout. See [resilience](../development/resilience.md).

## See also

- [Persistence backends](persistence.md) — pointing replicas at a shared
  PostgreSQL and sizing its pool.
- [Expiry monitoring](../operations/expiry-monitoring.md), [CA rotation](../ca/rotation.md),
  [OCSP presign & publishing](../operations/ocsp-presign-publish.md),
  [audit SIEM export](../security/audit-siem-export.md), and
  [RBAC & audit](../security/rbac-and-audit.md) (anchoring) — the gated jobs.
