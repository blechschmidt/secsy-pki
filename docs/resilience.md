# Resilience & fault-injection testing

An enterprise CA must not just be correct on the happy path — it must **fail
closed** when a dependency degrades and **degrade gracefully** rather than
corrupt state. Task 55 adds a chaos / fault-injection suite that deliberately
breaks the PKI's runtime dependencies under concurrent load and asserts the
invariants below still hold.

The suite lives in [`server/internal/chaos`](../server/internal/chaos) and runs
with one command:

```sh
./scripts/chaos-test.sh          # SoftHSM + ephemeral PostgreSQL, full suite
./scripts/chaos-test.sh -run TestChaosHSMFailoverUnderLoad -v
SECSY_TEST_PG_DSN=postgres://user:pw@host/db ./scripts/chaos-test.sh   # bring your own PG
```

It provisions a SoftHSM token (via `setup-softhsm.sh`) and, when Docker is
available or `SECSY_TEST_PG_DSN` is set, an ephemeral PostgreSQL for the
connection-drop scenario. Scenarios whose dependency is missing skip cleanly, so
a bare `go test ./...` stays green. CI runs it as the **non-required**
`chaos-resilience` job (SoftHSM + a PostgreSQL service) — a red run is a signal
to investigate, not a merge blocker.

## Invariants asserted

| Invariant | Meaning |
| --- | --- |
| **No partial issuance** | An issuance either fully succeeds (leaf signed on the HSM **and** recorded in the store) or fails cleanly. It never leaves a signed-but-unrecorded or recorded-but-unsigned artifact. |
| **No duplicate serials** | Concurrent serial allocation — CA subordinate counters (`FOR UPDATE`) and RFC 5280 random leaf serials — never collides, even when the DB connection is dropped mid-flight. |
| **No audit-chain gaps** | The tamper-evident hash-chained `event_log` stays contiguous, correctly back-linked, and verifiable under concurrent appends and DB faults. |
| **Fail closed on crypto faults** | A wrong HSM PIN, an unreachable token, or an unsupported RSA-OAEP hash yields an error — never a silent success or a signature/plaintext that verifies against the wrong key. |
| **Correct backpressure** | Rate-limit saturation returns `429`, HSM-guard saturation returns `503`, both with `Retry-After`, and both record the rejection in the metrics registry. |

## Scenarios

### 1. Mid-load HSM token failure & session-pool saturation (Tasks 44, 20)

`TestChaosHSMFailoverUnderLoad` imports one EC CA key into two SoftHSM tokens as
a genuine replica, drives a concurrent signing load through the
[HA provider](hsm-ha.md), and pulls the primary token out mid-load. Every
signature — before, during, and after the fault — verifies against the single CA
public key, so failover never produces a signature against the wrong key. The
per-token `secsy_hsm_token_up` gauge drops to 0 for the failed token and a
`secsy_hsm_token_failovers_total` failover is charged; once the fault clears the
background prober returns the token to rotation.

`TestChaosSessionPoolSaturationAndRecovery` drives far more concurrent signers
than the bounded [session pool](benchmarks.md) has slots and asserts every
signature is still valid (correct serialization under saturation). A
canceled-context borrow never deadlocks and never yields a corrupt signature —
it either sheds cleanly or returns a fully valid one — and the pool keeps working
afterward.

### 2. PostgreSQL connection drops & counter contention (Tasks 38, 8)

Against SQLite (always) and PostgreSQL (when configured):

- `TestChaosSerialAllocationContention` and `TestChaosCRLNumberContention`
  hammer `AllocateSerial`, `NextCRLNumber`, and `NextScopedCRLNumber`
  concurrently and assert every allocated value is unique.
- `TestChaosAuditChainUnderConcurrency` appends events from many goroutines and
  verifies the chain stays contiguous and valid.
- `TestChaosConcurrentIssuanceNoPartial` issues many leaves at once and asserts
  no duplicate serial and that the stored-record count equals the successful
  issuance count (no partial issuance).
- `TestChaosPostgresConnectionDrop` (PostgreSQL only) runs concurrent serial
  allocation and audit appends while a killer goroutine repeatedly calls
  `pg_terminate_backend`. Some operations fail — that is expected — but the store
  is never corrupted: no duplicate serial is ever returned, the audit chain stays
  intact, and `VerifyStoreIntegrity` passes afterward.

> **Regression this suite caught.** The lazy CRL-number counters
> (`NextCRLNumber`, `NextScopedCRLNumber`) had a first-insert race on PostgreSQL:
> a `SELECT … FOR UPDATE` cannot lock a not-yet-existent row, so two concurrent
> transactions both took the "no row" branch and both `INSERT`ed, and the loser
> hit the primary-key unique constraint. `AllocateSerial` was immune because its
> counter row is seeded at CA creation. The fix (`nextLazyCounter` in
> `internal/database/crl.go`) tolerates the conflict by retrying the loser into
> the locked update path. See [persistence](persistence.md).

### 3. HSM authentication & crypto-parameter faults (Tasks 4, 7)

`TestChaosWrongPINFailsClosed` points a provider at a valid token with the wrong
PIN and asserts every key operation fails cleanly — no key is created (no partial
state) — while the correct-PIN path keeps working. A bad credential degrades to
"no service", never "wrong service".

`TestChaosOAEPHashMismatchFailsClosed` provisions an RSA KEK and asserts the
fail-closed property the [secret layer](../server/internal/secret)'s hash
negotiation relies on: an OAEP ciphertext decrypted under the wrong hash never
yields the original plaintext, while the hash the token actually supports
round-trips exactly. (SoftHSM is RSA-OAEP **SHA-1 only**, which is exactly why
the negotiation exists.)

### 4. Rate-limit & HSM concurrency-guard saturation (Task 25)

`TestChaosRateLimitReturns429` drives the real public-endpoint
[middleware](rate-limiting.md) with a one-token burst and asserts the second
request from the same IP gets `429` with `Retry-After` and — for ACME — an
RFC 8555 `problem+json` body, while a different IP is unaffected.

`TestChaosHSMGuardReturns503` pins the single guard slot with a blocking request
and asserts the overflow is shed with `503` + `Retry-After`, the admitted request
still completes, and the guard recovers. `TestChaosGuardAcquireTimeoutSheds`
asserts a queued acquire times out (rather than blocking forever). Every
rejection increments the matching `secsy_ratelimit_throttled_total` /
`secsy_hsm_guard_rejected_total` counter.

### 5. Multi-replica leader election & job failover (Task 68, PostgreSQL only)

`TestChaosLeaderElectionTwoReplicas` assembles two in-process server instances
— each with its own store pool, key provider, and leader-gated background jobs
(expiry monitor with auto-renew, audit anchoring), wired exactly as
`cmd/server` does — against one PostgreSQL, plus a certificate seeded one hour
from expiry. It asserts the Task 68
[coordination](high-availability.md) invariants:

- Exactly one replica acquires leadership; the follower starts **zero** jobs.
- The expiring certificate is auto-renewed **exactly once** fleet-wide.
- Anchor ticks on a 200 ms interval **idle-skip** an unchanged head instead of
  re-anchoring it, and every stored anchor covers a distinct head sequence.
- Stopping the leader fails leadership over to the standby, which starts the
  jobs it had never run — and its immediate first scan/anchor pass does **not**
  double-renew or re-anchor (supersession + idle-skip idempotency).
- The concurrently appended-to audit chain stays contiguous throughout.

The election primitive itself (advisory-lock mutual exclusion, lease
confirmation, step-down on `pg_terminate_backend`) is covered by the
`internal/leader` tests, which run in the store-integrity CI job against the
same PostgreSQL service.

## Guarantees observed

Running the full suite against SoftHSM + PostgreSQL confirms, under concurrent
load and injected faults:

- Failover keeps issuance available on the surviving token with **zero invalid
  signatures**, and the failed token returns to rotation automatically.
- The bounded session pool serializes overload correctly and never corrupts or
  deadlocks, even under context cancellation.
- Concurrent counter allocation is **collision-free** on both backends, including
  through a storm of dropped PostgreSQL connections.
- The audit hash chain remains **gap-free and verifiable** through concurrent
  appends and connection drops; `VerifyStoreIntegrity` passes after the storm.
- Wrong PIN, unreachable token, and OAEP-hash mismatch all **fail closed** with
  no partial state and no wrong-key result.
- Overload backpressure returns the **correct status codes with `Retry-After`**
  and is fully observable in metrics.
- With two replicas on one PostgreSQL, singleton background jobs run on
  **exactly one** replica, leadership fails over when the leader stops, and a
  handover never double-renews a certificate or double-anchors the audit head.

## Data-race detection (`make test-race`)

The chaos suite proves the system behaves correctly under concurrent load; Go's
**race detector** proves the concurrency itself is sound — that no two goroutines
touch the same memory without synchronization. Given how much of the stack is
concurrent (the bounded PKCS#11 session pool, HSM-HA failover health tracking,
the rate-limit token buckets, leader-elected background jobs, the SSE
audit-event fan-out, and the OCSP/CRL/metrics caches), `-race` is run across the
whole suite:

```sh
make test-race          # whole suite: HSM-free parallel + SoftHSM/PG serial
make test-race-unit     # HSM-free packages only (parallel, no token needed)
make test-race-serial   # SoftHSM/PostgreSQL-backed packages (-p 1)
```

`test-race-unit` covers the HSM-free packages in parallel. `test-race-serial`
covers the packages that exercise a shared external resource — the single
SoftHSM token or a shared PostgreSQL — serialized with `-p 1` so cross-package
contention on that one resource cannot flake the run (that collision is a
test-fixture conflict, not a Go data race). Both skip cleanly when no token/DSN
is configured, so `make test-race` is useful locally with neither; provision
them to exercise those code paths under the detector:

```sh
eval "$(scripts/setup-softhsm.sh --export-env)"        # SoftHSM token
export SECSY_TEST_PG_DSN=postgres://user:pw@host/db     # optional PostgreSQL
make test-race
```

`-race` requires cgo, which the SQLite driver and the PKCS#11 module already
need, so the target sets `CGO_ENABLED=1` explicitly. CI runs it as the
**non-required** `race-detector` job (SoftHSM + a PostgreSQL service), alongside
the chaos and interop jobs — a red run is a race to fix, not a merge blocker,
until it has proven stable. The committed baseline is clean.

> **Regression this gate caught.** The from-scratch Prometheus registry
> (`internal/metrics`) rendered each metric by snapshotting its per-series map
> *keys* under the metric's lock but then reading the map itself **after**
> releasing the lock — an alias (`children := c.series`), not a copy. A
> `/metrics` scrape concurrent with a request handler recording a new label set
> was therefore an unsynchronized map read racing a map write: a data race, and
> in the Go runtime a `fatal error: concurrent map read and map write` that would
> crash the server mid-scrape under real load. The existing unit tests never
> rendered while updating, so it stayed hidden until the detector ran against a
> concurrent scrape-vs-update test (`internal/metrics/concurrency_test.go`). The
> fix copies the series map under the lock before rendering (`Counter`, `Gauge`,
> and `Histogram` `write`); the per-series child structs keep their own
> synchronization (an atomic counter, a mutex-guarded gauge/histogram value), so
> their values are still read lock-free after the snapshot.
