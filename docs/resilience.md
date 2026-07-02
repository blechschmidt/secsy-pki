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
