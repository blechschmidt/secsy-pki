# Performance & load benchmarking

This document describes the benchmark and load-test suite for the HSM-backed
paths of secsy-pki, publishes a set of baseline numbers measured against
SoftHSM, and documents the two performance tuning knobs: the **PKCS#11 session
pool size** and the **OCSP response cache TTL**.

- [What is measured](#what-is-measured)
- [The session pool](#the-session-pool-why-throughput-scales)
- [Running the suite](#running-the-suite)
- [Baseline results](#baseline-results-softhsm)
- [Tuning knobs](#tuning-knobs)
- [Security invariants](#security-invariants)

## What is measured

Every operation that reaches the HSM is on a request-serving hot path:

| Path | HSM operation per request | Benchmark |
|------|---------------------------|-----------|
| Certificate issuance / renewal | 1 signature (leaf) | `BenchmarkCA_IssueCertificate` |
| OCSP responder | 1 signature (response) — unless served from cache | `BenchmarkCA_OCSPRespond` |
| CRL distribution | 1 signature (CRL) | `BenchmarkCA_GenerateCRL` |
| Secret decrypt (envelope open) | 1 RSA-OAEP unwrap | `BenchmarkSecretDecrypt`, `BenchmarkPKCS11DecryptThroughput` |
| Secret encrypt (envelope seal) | none (public-key wrap, CPU only) | `BenchmarkSecretEncrypt` |
| Raw signing | 1 signature | `BenchmarkPKCS11SignThroughput`, `BenchmarkPKCS11SignLatency` |

The benchmarks live next to the code they exercise:

- `server/internal/keyprovider/bench_test.go` — signing and RSA-OAEP unwrap
  throughput/latency, and the cost of obtaining a signer.
- `server/internal/ca/bench_test.go` — end-to-end issuance, OCSP, and CRL
  (`//go:build sqlite`).
- `server/internal/secret/bench_test.go` — envelope encrypt/decrypt.

All of them **skip** unless SoftHSM is configured (`SECSY_PKCS11_MODULE` /
`SECSY_TOKEN_LABEL`), so `go test ./...` on a machine without an HSM stays green.

## The session pool: why throughput scales

The original key provider opened a fresh Cryptoki context **per operation**
(`pkcs11.New` → `C_Initialize` → `OpenSession` → `Login`) and tore it all down
on close (`Logout` → `CloseSession` → `C_Finalize` → `C_Destroy`). That is both
slow (a login round-trip per request) and, more seriously, **unsafe under
concurrency** on tokens whose Cryptoki state is per-application rather than
per-session — SoftHSM among them: one request's `C_Finalize`/`C_Logout` during
teardown disrupts another request's in-flight session in the same process.

The provider now keeps a bounded pool of long-lived, already-logged-in sessions
over a single shared, reference-counted module context
(`server/internal/pki/pool.go`). An operation borrows a session, uses it, and
returns it — no per-operation module load, login, or finalize. Because
miekg/pkcs11 initializes Cryptoki with `CKF_OS_LOCKING_OK`, distinct sessions
run concurrently, so **N pooled sessions yield up to N concurrent on-device
operations**. Borrowing blocks when every session is busy, which bounds
concurrency (backpressure) rather than overwhelming the token.

The pool is guarded entirely by the existing `keyprovider` abstraction: the rest
of the application (CA issuance, OCSP/CRL, secret decrypt) is unchanged and
still talks to `keyprovider.Provider`.

## Running the suite

```sh
# One-time: set up SoftHSM (creates a token, exports SECSY_* env vars).
eval "$(scripts/setup-softhsm.sh --export-env)"

# Run everything (sign, issue, ocsp, crl, secret), 3s per benchmark:
scripts/loadtest.sh

# Just one suite, longer runs, save raw output:
scripts/loadtest.sh -t 5s -o /tmp/results.txt sign

# Directly with go test (e.g. the CA suite needs the sqlite build tag):
go test -tags sqlite -run '^$' -bench 'CA_' -benchtime=2s ./server/internal/ca/
go test -run '^$' -bench 'PKCS11' -benchmem ./server/internal/keyprovider/
```

`scripts/loadtest.sh` sets up the SoftHSM env automatically if it is not already
exported, sweeps the session-pool size for each concurrent benchmark, and
optionally writes the raw results to a file for `benchstat`.

## Baseline results (SoftHSM)

Measured with SoftHSM2 on an AMD EPYC-Milan host, `GOMAXPROCS=4`,
`-benchtime=2s`. These are a **software-token baseline**, not a hardware-HSM
figure: SoftHSM performs the cryptography in-process on the CPU, so throughput
plateaus near `GOMAXPROCS`. A network-attached HSM has very different
characteristics (per-op latency is dominated by the round-trip, so a larger pool
helps more) — re-run `scripts/loadtest.sh` against your device to tune.

### Signing throughput vs. pool size (ECDSA P-256)

| Pool size | ns/op | ~ops/sec | speedup vs. size 1 |
|-----------|-------|----------|--------------------|
| 1 | 81,600 | 12,300 | 1.00× |
| 2 | 53,600 | 18,700 | 1.52× |
| 4 | 45,300 | 22,100 | **1.80×** |
| 8 | 51,000 | 19,600 | 1.60× |
| 16 | 50,400 | 19,800 | 1.62× |

Throughput rises sharply from pool size 1→4 and then plateaus as SoftHSM
saturates the 4 available cores. Past the plateau, extra sessions add no
throughput (and cost a little contention).

### Single-operation signing latency

| Key type | ns/op |
|----------|-------|
| ECDSA P-256 | 69,000 |
| Ed25519 | 182,000 |
| RSA-2048 | 979,000 |

### Obtaining a signer

`BenchmarkPKCS11SignerOpen`: **~400 ns/op** (a cached, session-local key lookup).
The previous design paid a full module load + `C_Login` — milliseconds — on every
`Signer()` call, so this is a ~1000× reduction on the signer-open path.

### RSA-2048 OAEP unwrap throughput (secret decrypt) vs. pool size

| Pool size | ns/op | ~ops/sec | speedup |
|-----------|-------|----------|---------|
| 1 | 1,003,000 | 1,000 | 1.00× |
| 2 | 505,000 | 1,980 | 1.99× |
| 4 | 425,000 | 2,350 | **2.36×** |
| 8 | 447,000 | 2,240 | 2.24× |

RSA private-key operations are the most expensive on the token, so pooling helps
them the most: ~2.4× at pool size 4.

### OCSP & CRL serving (uncached, per request signature)

| Operation | Pool 1 | Pool 2 | Pool 4 | Pool 8 |
|-----------|--------|--------|--------|--------|
| OCSP respond (ns/op) | 223,000 | 192,000 | 199,000 | 195,000 |
| CRL generate (ns/op) | 233,000 | 204,000 | 205,000 | 207,000 |

These figures are for the **uncached** path (CA manager, one HSM signature per
request). With the OCSP response cache enabled (the default), a cache **hit**
serves the pre-signed response straight from memory — no HSM signature, no
database lookup — which is orders of magnitude faster (a map lookup and a copy)
and does not consume a session at all. The cache is the right lever for OCSP
scale; the pool is the right lever for the unavoidable first (and post-TTL)
signature.

### End-to-end certificate issuance

`BenchmarkCA_IssueCertificate` (single-threaded, CSR → HSM-signed cert + DB
insert): **~1.41 ms/op** (~700 certs/sec on one core). Under concurrency,
issuance is partly bounded by SQLite's single-writer model (serial allocation +
certificate insert), not by the HSM; scale the database (e.g. Postgres) for
higher concurrent issuance.

### Secret encrypt (envelope seal)

`BenchmarkSecretEncrypt`: **~16 µs/op**. Sealing wraps the data key with the
KEK's *public* half and does not touch the HSM, so it is CPU-bound and scales
with cores.

## Tuning knobs

### Session pool size

Config: `pkcs11.session_pool_size` (or env `SECSY_PKCS11_SESSION_POOL_SIZE`).
Default: `8` (`keyprovider.DefaultSessionPoolSize`).

```yaml
pkcs11:
  module_path: /usr/lib/softhsm/libsofthsm2.so
  token_label: secsy-pki-root
  session_pool_size: 8   # max concurrent on-device operations
```

Guidance:

- It bounds concurrent HSM operations; requests beyond it queue (bounded
  backpressure) rather than failing.
- **Software token (SoftHSM):** cryptography runs on the CPU, so returns
  diminish near `GOMAXPROCS`. 4–8 is a good range.
- **Network / hardware HSM:** per-op latency is dominated by the round-trip, so
  a larger pool hides that latency — size it toward the device's supported
  concurrent-session limit (e.g. YubiHSM 2 supports up to 16 concurrent
  sessions; many PKCS#11 HSMs document a max session count). Do not exceed the
  device's limit, or session opens will fail.
- Re-run `scripts/loadtest.sh` against the real device and pick the size at the
  knee of the throughput curve.

### OCSP response cache TTL

Config: `server.ocsp_cache_ttl_seconds`. Default: `3600` (1 hour,
`handlers.DefaultOCSPCacheTTL`). `0` keeps the default; a **negative** value
disables caching (every request is answered freshly on the HSM).

```yaml
server:
  ocsp_cache_ttl_seconds: 3600   # reuse signed OCSP responses for 1h; -1 disables
```

An OCSP response is a signed object valid until its `NextUpdate` (24 h here), so
reusing it for a bounded window is safe and standard. The cache is keyed by
`(CA, certificate serial)` and, crucially for correctness, is **invalidated
immediately when a certificate is revoked**, so a revocation is never masked by
a stale "good" response. The TTL additionally bounds staleness for any status
change that does not flow through the revocation path. Keep the TTL well under
`defaultOCSPValidity` (24 h). The cache is bounded (`DefaultOCSPCacheMaxEntries`,
16384) to resist memory growth under a flood of distinct serials.

## Security invariants

The pool changes *how* the token is accessed, not *what* is allowed. The Task 12
hardening invariants are preserved and were re-verified after the change:

- **Key non-extractability.** Key generation still sets `CKA_SENSITIVE=true` and
  `CKA_EXTRACTABLE=false` with least-privilege usage flags — the pool reuses the
  exact same generation core (`generateKeyPairOnSession` /
  `generateRSAKEKOnSession`). `TestPKCS11ListKeys` still asserts generated keys
  report sensitive + non-extractable.
- **Private keys never leave the HSM.** Signing and unwrapping still happen on
  the device via `C_Sign` / `C_Decrypt` on a borrowed session; no private
  material is ever read.
- **No PKCS#1 v1.5 decryption.** The OAEP-only decrypt path is unchanged.
- **Duplicate-label rejection**, random serials, and TLS fail-closed behavior
  are unaffected.

The OCSP cache only ever stores the CA's own signed responses and returns them
verbatim within their validity window; it cannot change a certificate's status
(only revocation, which invalidates the entry, can).
