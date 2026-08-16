// Package chaos holds the fault-injection / resilience test suite for
// secsy-pki. It deliberately degrades the PKI's runtime dependencies — the
// PKCS#11 HSM (Task 44 high availability and Task 20 session pool), the
// PostgreSQL/SQLite persistence backend (Task 38), and the public-endpoint
// rate-limiter and HSM concurrency guard (Task 25) — under concurrent load,
// then asserts that the system fails closed and degrades gracefully rather
// than corrupting state.
//
// The invariants exercised across the scenarios are:
//
//   - No partial issuance: an issuance either fully succeeds (cert signed AND
//     recorded) or fails cleanly; it never leaves a signed-but-unrecorded or
//     recorded-but-unsigned artifact behind.
//   - No duplicate serials: concurrent serial allocation (CA subordinate
//     counters, RFC 5280 random leaf serials) never yields a collision, even
//     when the DB connection is dropped mid-flight.
//   - No audit-chain gaps: the tamper-evident hash-chained event_log stays
//     contiguous and verifiable under concurrent appends and DB faults.
//   - Fail closed on crypto faults: a wrong HSM PIN, an unreachable token, or
//     an unsupported RSA-OAEP hash produces an error — never a silent success
//     or a signature/plaintext that verifies against the wrong key.
//   - Correct backpressure: rate-limit saturation returns 429 and HSM-guard
//     saturation returns 503, both with a Retry-After header, and both record
//     the rejection in the metrics registry.
//
// All non-trivial fault seams are real, not mocked: HSM faults use SoftHSM
// tokens and the documented test-only unreachable atomic on the HA provider,
// DB faults use pg_terminate_backend against an ephemeral PostgreSQL, and the
// rate-limit/guard faults drive the real middleware over httptest. Tests that
// require SoftHSM or PostgreSQL skip cleanly when those dependencies are not
// configured, so `go test ./...` stays green on a bare checkout.
//
// See docs/development/resilience.md for the guarantees this suite observes and
// scripts/chaos-test.sh for the one-command runner used locally and in CI.
package chaos
