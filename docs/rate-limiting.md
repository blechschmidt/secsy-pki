# Rate limiting, quotas & abuse protection

The public-facing endpoints of secsy-pki — ACME (`newOrder`/`newAccount`/…),
the OCSP responder, CRL distribution, and SCEP/EST device enrollment — are
reachable without an operator login. Left unbounded, a misbehaving client or an
attacker could exhaust the HSM (every issuance and OCSP/CRL signature is a
PKCS#11 operation) or drive runaway certificate issuance (Task 25).

secsy-pki protects these endpoints with two cooperating mechanisms:

| Mechanism | What it bounds | Response when exceeded |
|-----------|----------------|------------------------|
| **Tiered token-bucket limiter** | Request *rate*, per global / per-IP / per-account tier | `429 Too Many Requests` + `Retry-After` |
| **In-flight concurrency guard** | Concurrent *signing/enrollment* work hitting the HSM | `503 Service Unavailable` + `Retry-After` |

Both are disabled by default and enabled with a single `rate_limit.enabled:
true`. The middleware sits inside the observability layer, so every shed request
is still logged and metered, and only the recognized public endpoints are
affected — the authenticated admin API and console are never rate limited here.

## Token-bucket tiers

The limiter is a lazily-refilled **token bucket** (the standard mechanism that
approximates a sliding window while allowing a configurable short burst). A
request must obtain a token from **every applicable tier** to proceed:

- **`global`** — one shared bucket capping aggregate request rate across all
  clients. The backstop against a distributed flood.
- **`per_ip`** — one bucket per source IP. Honors `X-Forwarded-For` (the
  deployment terminates TLS at a trusted proxy), matching the observability and
  audit layers.
- **`per_account`** — one bucket per authenticated identity: the ACME account
  (extracted from the JWS `kid`) or the EST HTTP-Basic username. Requests with
  no account yet (ACME `newAccount`, OCSP, CRL, SCEP) fall back to the IP and
  global tiers.

Each tier is `rate` (sustained requests/second) plus `burst` (bucket capacity).
A tier with a non-positive `rate` or `burst` is inert. Admission is
**all-or-nothing**: a token consumed from an earlier tier is refunded if a later
tier rejects, so a rejected request never silently drains an unrelated budget.

Per-IP and per-account buckets are held in a **bounded** map (`max_keys`,
default 100 000) with idle eviction (`idle_ttl_seconds`, default 600), so an
attacker spraying unique IPs or account IDs cannot exhaust memory.

### Graceful degradation

Rejections carry a `Retry-After` header (whole seconds, derived from the bucket
refill time). For ACME endpoints the body is an RFC 8555
`application/problem+json` document with
`type: urn:ietf:params:acme:error:rateLimited`, which certbot / lego / acme.sh
recognize and honor — a legitimate client under load backs off and eventually
completes rather than failing hard.

## HSM in-flight concurrency guard

Rate limiting bounds *how often* requests arrive; the concurrency guard bounds
*how many run at once* against the HSM. It sits in front of the Task 20 PKCS#11
session pool for the signing/enrollment endpoints (ACME `finalize`, EST
`simpleenroll`/`simplereenroll`/`serverkeygen`, SCEP `PKIOperation`).

- Up to `max_in_flight` requests hold a slot concurrently. When unset it derives
  from `pkcs11.session_pool_size`, so the guard tracks the backend it protects —
  keeping the pool busy without letting excess requests pile up behind the
  pool's own `borrow()` backpressure as unbounded blocked goroutines.
- Up to `max_queue` (default 64) further requests wait for a slot; beyond that,
  requests are **shed immediately** with `503` — fast-fail instead of a
  latency collapse.
- A queued request waits at most `acquire_timeout_ms` (default 5000) for a slot,
  and is released early if the client disconnects (request-context cancellation).

## Configuration

```yaml
rate_limit:
  enabled: true
  global:      { rate: 200, burst: 400 }   # aggregate cap
  per_ip:      { rate: 20,  burst: 40  }   # per source IP
  per_account: { rate: 50,  burst: 100 }   # per ACME account / EST user
  max_keys: 100000            # bound on distinct per-IP/per-account buckets
  idle_ttl_seconds: 600       # idle bucket eviction window
  concurrency:
    enabled: true             # defaults on when rate_limit.enabled is true
    max_in_flight: 0          # 0 => derived from pkcs11.session_pool_size
    max_queue: 64             # queued requests before shedding with 503
    acquire_timeout_ms: 5000  # max wait for a slot
```

The configuration is validated at startup: a positive `rate` with a zero
`burst` (a bucket that could never admit a request), a negative knob, or
`enabled: true` with no active tier *and* no guard all fail loudly rather than
silently blackholing traffic.

## Metrics

The following Prometheus series are exported on `/metrics` (see
[Observability](observability.md)):

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `secsy_ratelimit_throttled_total` | counter | `endpoint`, `tier` | Requests rejected by a rate-limit tier |
| `secsy_ratelimit_admitted_total` | counter | `endpoint` | Requests that passed all tiers |
| `secsy_hsm_guard_rejected_total` | counter | `endpoint`, `reason` | Requests shed by the concurrency guard (`queue_full`/`timeout`/`canceled`) |
| `secsy_hsm_guard_in_flight` | gauge | — | Requests currently holding a guard slot |
| `secsy_hsm_guard_queue_depth` | gauge | — | Requests currently waiting for a slot |

`endpoint` is a low-cardinality class label (`acme_new_order`, `acme_finalize`,
`ocsp`, `crl`, `est_enroll`, `scep_enroll`, …). A rising `throttled_total`,
`queue_depth`, or `guard_rejected_total{reason="queue_full"}` are the primary
overload signals to alert on.

## Deployment note

The limiter is process-local. In a horizontally-scaled deployment each replica
enforces its own buckets, so set per-replica tiers with the replica count in
mind, or terminate at a shared ingress limiter for a strict global cap. The
per-instance HSM guard is already correct per replica, since each replica has
its own session pool.

This per-replica limiter is a **known follow-up** for full multi-replica
parity: the effective global limit is roughly `configured_rate × replica_count`,
and a client pinned to one replica sees only that replica's bucket. It is not a
correctness bug — over-admitting requests only weakens abuse protection, it never
mis-issues — which is why it is deferred. By contrast the ACME anti-replay
**nonce store is shared** across replicas (a correctness requirement: an
unshared nonce would cause spurious `badNonce` rejections and, worse, could let a
replay slip through on a different replica). See
[High availability → shared vs per-replica request state](high-availability.md#shared-vs-per-replica-request-state).
