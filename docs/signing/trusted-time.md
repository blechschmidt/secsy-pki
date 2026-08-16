# Trusted external time source (NTS / Roughtime)

A time-stamping authority is only as trustworthy as the clock it signs. The RFC
3161 TSA (`/tsa`, see [timestamping.md](timestamping.md)) and the audit-chain
anchor service (see the RUNBOOK's *Audit-chain anchoring* section) both take
their `genTime` from the host wall clock. If that clock is rewound, advanced, or
silently drifts, the server keeps producing correctly-signed tokens — with the
wrong time inside. Nothing downstream can tell.

The trusted-time guard (`time.source`) removes that single point of failure.
Before signing any timestamp token or creating any audit anchor, secsy-pki
cross-checks the host clock against one or more **authenticated** external time
sources and **fails closed** — refusing to sign — when the measured offset
exceeds a configurable threshold.

It is opt-in. The zero-config default (`type: system`, or no `time` block at
all) trusts the host clock unconditionally, exactly as before, so existing
deployments are unaffected.

## Why authenticated time

Plain NTP (UDP/123) is unauthenticated: an on-path attacker can forge responses
and move the client's clock at will. That is precisely the threat a TSA must
resist, so the guard only speaks protocols whose responses are cryptographically
verifiable:

- **NTS — Network Time Security (RFC 8915).** Authenticated NTPv4. A TLS 1.3
  key-establishment handshake (NTS-KE, ALPN `ntske/1`) yields per-session AEAD
  keys and opaque cookies; the NTP request/response then carries an AES-SIV
  authenticator over the packet. A response is accepted only if its authenticator
  verifies under the server-to-client key and it echoes the request's unique
  identifier — so a spoofed or modified response is rejected.
- **Roughtime.** A UDP protocol in which the server signs its timestamp with an
  Ed25519 key. secsy-pki verifies the full chain — the server's long-term key
  certifies a delegated key over a validity window, the delegated key signs the
  response, and the client's random nonce is proven to be committed to by a
  Merkle root — so the returned time is unforgeable and verifiable offline
  against the server's published public key.

Both make the returned time unforgeable by a network attacker, which is the
property a trust anchor needs.

## Configuration

```yaml
time:
  source:
    type: nts                 # system (default) | nts | roughtime
    max_drift: 10s            # fail closed beyond this |host - source| offset
    refresh_interval: 60s     # cache a successful check this long
    timeout: 5s               # per-source query timeout
    min_sources: 1            # minimum reachable sources per check
    on_source_error: fail_closed   # fail_closed (default) | fail_open
    servers:
      - address: time.cloudflare.com    # NTS-KE host; KE port defaults to 4460
      - name: nist
        address: time.nist.gov
```

Roughtime uses the same block with per-server Ed25519 public keys:

```yaml
time:
  source:
    type: roughtime
    max_drift: 10s
    servers:
      - name: cloudflare
        address: roughtime.cloudflare.com:2002
        public_key: gD63hSj3ScS+wuOeGrubXlq35N1c5Lby/S+T7MNTjxo=   # base64 or hex
```

### Fields

| Field | Default | Meaning |
|-------|---------|---------|
| `type` | `system` | `system` trusts the host clock (no check); `nts` / `roughtime` enable the guard. |
| `max_drift` | `10s` | Maximum tolerated absolute offset between the host clock and any reachable source before signing fails closed. |
| `refresh_interval` | `60s` | A successful check is cached this long and reused, so a busy TSA does not query the upstream on every request (nor spam the audit log). A failed check is cached only briefly so recovery is picked up quickly. |
| `timeout` | `5s` | Per-source query timeout. |
| `min_sources` | `1` | Minimum number of reachable sources a check requires before the unreachable-source policy applies. Must not exceed the number of configured servers. |
| `on_source_error` | `fail_closed` | Unreachable-source policy: `fail_closed` refuses to sign when fewer than `min_sources` answer; `fail_open` keeps signing on the host clock. **Drift always fails closed regardless.** |
| `servers[].address` | — | NTS: the NTS-KE host (`host` or `host:port`; KE port defaults to 4460, the NTP port is negotiated). Roughtime: the UDP endpoint `host:port`. |
| `servers[].public_key` | — | **Required for Roughtime**: the server's long-term Ed25519 public key (base64 std/URL, padded or raw, or hex). Ignored for NTS. |
| `servers[].name` | `address` | Label used in metrics, audit, and logs. |

### Choosing `max_drift`

This is the correctness/availability trade-off, and it is **not** an accuracy
target (set the TSA `accuracy` field for that). The threshold exists to catch a
clock that is *badly* wrong — minutes or hours off, the signature of a rewound,
mis-set, or unsynchronised host — without tripping on ordinary NTP jitter or a
brief excursion. The 10s default comfortably distinguishes the two. Tighten it
only if your hosts are tightly disciplined and you want a stricter guarantee;
tightening below a second risks false fail-closed events from network variance.

### Multiple sources

Every *reachable* source must agree with the host clock within `max_drift`. A
single source reporting a large offset fails the check, because you cannot tell
which clock is right — and a TSA must not sign a time it cannot vouch for. Use
`min_sources` to require a quorum of reachable sources (e.g. 2 of 3) so a single
unreachable server does not block signing while still requiring corroboration.

## Behavior when the check fails

While the host clock is untrusted:

- The **TSA** returns an RFC 3161 `timeNotAvailable` rejection (PKIFailureInfo
  bit 14) instead of a token. Clients see a well-formed rejection, not an opaque
  error.
- **Audit anchoring** returns an error and persists nothing — no falsely-dated
  anchor is created.
- A `time.check` audit event (`ResultDenied`) is appended with the offset,
  threshold, and per-source detail.
- `secsy_time_check_failures_total{reason}` increments (`reason` is `drift` or
  `unreachable`).

Signing resumes automatically once the clock is disciplined or the source
restored — the next check (within `refresh_interval`) passes; no restart needed.

## Observability

| Metric | Type | Meaning |
|--------|------|---------|
| `secsy_time_drift_seconds{source}` | gauge | Last measured host-minus-source offset, in seconds (positive: host ahead), per source. |
| `secsy_time_checks_total{result}` | counter | Cross-checks by result: `pass`, `fail`, `cached`. |
| `secsy_time_check_failures_total{reason}` | counter | Checks that could not confirm the clock, by reason: `drift`, `unreachable`. Under the default fail-closed policy each also refuses to sign (`secsy_time_checks_total{result="fail"}`). |

Alerts (`deploy/observability/prometheus/secsy-pki-rules.yaml`):

- **`SecsyPKITrustedTimeCheckFailing`** (critical) — a check is failing closed;
  the TSA is refusing to sign.
- **`SecsyPKIClockDriftHigh`** (warning) — drift exceeds 5s but has not yet
  crossed the default threshold; discipline the clock before it fails closed.

## Preflight (`secsy-ca doctor`)

The `time.trusted` check performs one live, uncached probe of the configured
source(s) and reports whether the host clock currently passes, warning as the
offset approaches the threshold:

```bash
secsy-ca -config config.yaml doctor    # look for the time.trusted line
```

It is `skip` when no external source is configured, `pass`/`warn` with the
measured offset when the clock is trusted, and `fail` when the clock drifts
beyond the threshold or no source is reachable under a fail-closed policy.

## How it fits together

```
              time.source (nts / roughtime)
                        │
                        ▼
        ┌─────────────────────────────┐
        │  timesource.Checker         │   cross-check host clock,
        │  (fail-closed, cached)      │   fail closed on drift
        └─────────────────────────────┘
              │                    │
              ▼                    ▼
      tsa.Authority.Stamp   anchor.Service.AnchorOnce
      (timeNotAvailable      (refuse; persist nothing)
       on drift)
```

The guard is wired through the existing `SetClock` seam on `tsa.Authority` and
`anchor.Service`, so it is transparent to the rest of the issuance/anchoring
paths. The server applies it to the public `/tsa` endpoint (`SetTrustedClock` on
the authority) and to the leader-elected audit-anchor background job
(`SetTrustedClock` on the anchor service), which are the always-on production
paths.

## Operational notes

- **Network reach.** NTS needs outbound TCP to the NTS-KE port (default 4460)
  plus the negotiated NTP UDP port; Roughtime needs outbound UDP to the server
  port. If the guard reports `unreachable`, check egress firewall rules first.
- **Roughtime keys.** Public keys are published by each operator (e.g.
  Cloudflare, Google's ecosystem list). Pin the exact key you trust — the guard
  verifies every response against it.
- **Upstream load.** `refresh_interval` bounds how often the upstream is queried
  regardless of TSA request rate, so a public TSA under load still queries each
  source at most about once per interval.
