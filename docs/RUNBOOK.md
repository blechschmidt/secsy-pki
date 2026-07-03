# Secsy PKI — Enterprise operator runbook

Day-2 operations for a running secsy-pki enterprise deployment. This runbook
assumes the CA is already deployed and issuing; for first-time setup follow the
[deployment guides](README.md). Each section is written to be actionable under
pressure: symptom → diagnosis → procedure.

Every CLI command and endpoint below is verified against the code on the
`enterprise` branch. Binaries are `secsy-ca`, `secsy-secret`, and
`secsy-pki-server`; see the [tools table](README.md#the-tools-at-a-glance).
The design decisions behind these procedures are recorded in
[Architecture Decision Records](adr/README.md).

## Contents

1. [Suspected CA-key compromise](#suspected-ca-key-compromise)
2. [OCSP / CRL outage](#ocsp--crl-outage)
3. [Endpoint troubleshooting (ACME / SCEP / EST / TSA / CMP)](#endpoint-troubleshooting)
4. [Rate-limit and HSM-concurrency tuning](#rate-limit-and-hsm-concurrency-tuning)
5. [CT log outage](#ct-log-outage)
6. [CA key rotation and retirement](#ca-key-rotation-and-retirement)
7. [Disaster-recovery drill](#disaster-recovery-drill)
8. [Observability: dashboards & alerts](#observability-dashboards--alerts)
9. [Audit-chain anchoring](#audit-chain-anchoring)
10. [Supply-chain / image verification failure](#supply-chain--image-verification-failure)
11. [Preflight diagnostics (`secsy-ca doctor`)](#preflight-diagnostics-secsy-ca-doctor)
12. [First-response quick reference](#first-response-quick-reference)

---

## Suspected CA-key compromise

**This is the highest-severity incident.** A compromised CA key can sign
arbitrary certificates. Treat any of these as a trigger: HSM tamper alert,
unexplained entries in the audit chain, a signature the audit log cannot
account for, or loss of physical control of the HSM.

### 1. Confirm before you burn the CA

A revocation of an intermediate is disruptive and hard to reverse. First
establish whether the key actually signed anything unexpected.

```bash
# Re-walk the tamper-evident event log end to end; reports the first broken link.
secsy-ca -config config.yaml audit verify -json

# For HSM-backed (YubiHSM) CAs: prove the on-device sign count matches the
# certificates on record (the bijection proof). See README "Audit Verification".
secsy-verify verify-combined-log \
  --signed-log signed-audit-log.json \
  --combined-log combined-audit-log.json \
  --ca-key ca-public-key.pub \
  --yubico-ca yubico-root.pem \
  --yubico-intermediate yubico-intermediate.pem
```

Pull the signed and combined HSM logs live if needed:
`GET /api/hsm/signed-audit-log`, `GET /api/hsm/combined-audit-log`,
`GET /api/events` and `GET /api/events/verify`.

- **Audit chain intact + bijection holds** → the key did not sign anything
  off-log. The exposure is potential, not realized. You may have time for a
  planned rotation rather than an emergency revoke.
- **Chain broken or extra signatures** → treat as confirmed compromise; proceed
  to containment immediately.

Because CA keys are non-extractable and every sign op is force-audited on the
HSM ([ADR 0002](adr/0002-hsm-non-extractability-invariants.md)), a clean
bijection is strong evidence the key was not misused. A **PQC/hybrid** CA key is
the exception — it is software-held
([ADR 0005](adr/0005-pqc-hybrid-algorithm-choice.md)), so this proof does not
apply and you must assume the worst if the host was compromised.

### 2. Contain — stop new issuance under the suspect CA

```bash
# Fastest lever: rate-limit / concurrency guard to zero for public endpoints,
# or take the server offline. See "Rate-limit tuning" below.
# For a targeted stop, disable the CA's profiles in config and reload.
```

Revoke outstanding leaves you believe are affected (`secsy-ca revoke -ca <ca>
-serial <hex> -reason keyCompromise`) and regenerate revocation material (next
section) so the compromise propagates to relying parties.

### 3. Rotate or retire the compromised key

- **Intermediate CA:** rotate to a fresh HSM key, then **force-retire** the old
  one so its leaves stop validating — this is the compromise path, where
  breaking outstanding leaves is the goal:

  ```bash
  secsy-ca -config config.yaml rotate-intermediate -ca <ca> -operators 3 -quorum 2
  secsy-ca -config config.yaml retire-intermediate  -ca <ca> -reason keyCompromise -force \
    -crl-out root-crl.der
  ```

  See [CA key rotation](#ca-key-rotation-and-retirement) for the normal
  (drain-first) flow.

- **Root CA:** there is no online recovery. Distribute a revocation/notice out
  of band, stand up a new root via a fresh [key ceremony](key-ceremony.md), and
  re-issue the intermediate hierarchy. Rehearse with the
  [DR drill](#disaster-recovery-drill) before you ever need it.

### 4. Publish new revocation state and the new chain

```bash
secsy-ca -config config.yaml gen-crl -ca <parent-ca> -out root-crl.der -der
secsy-ca -config config.yaml publish-chain -ca <ca> -out chain.pem
```

Confirm relying parties see revocation via the public OCSP/CRL endpoints
(next section), and confirm the retired intermediate is listed on the parent
CRL.

### 5. Post-incident

Preserve the HSM audit log and event-log export (`secsy-ca audit export`) as
evidence. File the timeline. If the root of cause was operational (not a key
leak), a planned rotation may suffice next time.

---

## OCSP / CRL outage

Relying parties fail *closed* on revocation checking when it is strict, so an
OCSP/CRL outage can look like a widespread certificate failure. Move fast.

### Public endpoints

| Purpose | Method | Path |
|---------|--------|------|
| OCSP (binary GET) | GET | `/api/ca/{id}/ocsp/{base64-request}` |
| OCSP (POST) | POST | `/api/ca/{id}/ocsp` |
| CRL (complete/base) | GET | `/api/ca/{id}/crl` |
| Delta CRL | GET | `/api/ca/{id}/crl/delta` |
| Partition (shard) CRL | GET | `/api/ca/{id}/crl/partition/{shard}` |
| Partition delta CRL | GET | `/api/ca/{id}/crl/partition/{shard}/delta` |
| CA chain (rollover-aware) | GET | `/api/ca/{id}/chain` |

### Diagnose

```bash
# Is the responder up and answering?
openssl ocsp -issuer intermediate.pem -cert leaf.pem \
  -url https://pki.example.com/api/ca/<id>/ocsp -resp_text

# Is the CRL fresh and well-formed?
curl -s https://pki.example.com/api/ca/<id>/crl -o crl.der
openssl crl -inform DER -in crl.der -noout -text | grep -E 'Last Update|Next Update'
```

Check `/readyz` (HSM probe) and `/metrics` — OCSP signing is an HSM operation,
so an OCSP outage is frequently an HSM-availability or HSM-concurrency problem,
not an OCSP-code problem.

### Common causes and fixes

- **`/readyz` failing / HSM unreachable.** The responder cannot sign. Fix HSM
  connectivity (PIN, token, connector). See
  [HSM configuration](hsm-configuration.md).
- **`503` / `Retry-After` from the concurrency guard.** OCSP signing is being
  shed under load. Raise `rate_limit.concurrency.max_in_flight` /
  `pkcs11.session_pool_size`, or extend the OCSP cache TTL — see
  [tuning](#rate-limit-and-hsm-concurrency-tuning). The OCSP response cache
  (`server.ocsp_cache_ttl_seconds`) absorbs repeated queries; a longer TTL
  sharply cuts HSM load.
- **Stale CRL (`Next Update` in the past).** Regenerate and republish:
  ```bash
  secsy-ca -config config.yaml gen-crl -ca <id> -out crl.der -der
  ```
  Automate CRL refresh ahead of `Next Update`; a lapsed CRL is an outage. The
  public endpoints re-sign automatically as the served copy nears expiry, so
  polling them (or fronting them with a cache) keeps CRLs fresh without cron.
- **Delta CRL not reflecting a recent revocation.** Deltas are served for up to
  `crl.delta_interval_minutes` (default 60) before re-signing; a client will see
  the revocation once the served delta refreshes, or immediately via OCSP. The
  delta references the *published* base CRL — if you republish a base from ad-hoc
  `gen-crl` output the numbers won't line up; publish the endpoint's base CRL.
- **Partitioned CRL 400 / wrong shard.** `/crl/partition/{shard}` requires
  `crl.shards >= 2` and `shard` in `0..shards-1`. A certificate's shard is
  `sha256(serial) mod shards`; verify with the CDP stamped in the certificate
  (`openssl x509 -in leaf.pem -noout -text | grep -A1 'CRL Distribution'`).
- **Nonce responses not cached.** By design — RFC 8954 nonce-bearing requests
  (`ocsp.nonce_enabled`) bypass the cache and are freshly signed, so a flood of
  nonce requests hits the HSM directly. If a client is hammering with nonces and
  causing shedding, that is expected behavior, not a bug.
- **Delegated-responder cert expired.** When `ocsp.delegated` is on, the
  short-lived responder cert (`ocsp.delegated_validity_hours`, default 168h) is
  re-issued automatically as it nears expiry; a failure to re-issue points back
  at HSM/CA availability.

### Degraded-mode guidance

CRL is a static artifact and cheap to serve; if the OCSP responder is
struggling under HSM load, ensure CRL is fresh and well-distributed so
CRL-capable relying parties have a fallback. Extending
`server.ocsp_cache_ttl_seconds` trades staleness for availability during an
incident.

### Pre-signing / CDN offload (recommended)

With `server.ocsp.presign.enabled`, responses for **all known serials** are
batch-signed on a schedule and served from the response cache, so the public
responder does not touch the HSM at all on the hot path — and keeps serving
valid responses through an HSM outage until they reach their `NextUpdate`
(up to `presign.validity_minutes`). Nonce requests still bypass per RFC 8954.
The `publish:` block additionally writes CRLs, chains, and the pre-signed
responses as static artifacts (directory or S3) for CDN fronting, with
`secsy-ca publish -verify` proving snapshot integrity **without the HSM**.
Alert on `secsy_ocsp_presign_staleness_seconds` and
`secsy_publish_staleness_seconds`. Full procedure, layout, CDN mapping rules,
and outage timelines: [OCSP pre-signing & static publishing](ocsp-presign-publish.md).

---

## Endpoint troubleshooting

All enrollment/management protocols share the same CA, HSM, RBAC, audit, and
rate-limit machinery, so triage starts the same way: check `/healthz`
(liveness), `/readyz` (DB + HSM), and `/metrics`, then the audit/event log for a
denied-operation reason.

Default paths (each is configurable — see the per-feature guide):

| Protocol | Path(s) | Guide |
|----------|---------|-------|
| ACME (RFC 8555) | `/acme/directory`, `/acme/new-nonce`, `/acme/new-account`, `/acme/new-order`, `/acme/order/{id}`, `/acme/order/{id}/finalize`, `/acme/authz/{id}`, `/acme/chall/{id}`, `/acme/cert/{id}`, `/acme/revoke-cert`, `/acme/key-change` | [acme.md](acme.md) |
| ACME ARI | `/acme/renewal-info/{certid}` | [acme.md](acme.md) |
| SCEP (RFC 8894) | `/scep` (and `/scep/pkiclient.exe`), `?operation=getcacaps\|getcacert\|pkioperation` | [enrollment.md](enrollment.md) |
| EST (RFC 7030) | `/.well-known/est/cacerts`, `/simpleenroll`, `/simplereenroll`, `/serverkeygen` | [enrollment.md](enrollment.md) |
| TSA (RFC 3161) | `/tsa` | [timestamping.md](timestamping.md) |
| CMP (RFC 9483) | `/cmp` | [§ CMP below](#cmp) |

### ACME

- **`newOrder`/`finalize` rejected.** Usually authorization or policy:
  check the challenge (`/acme/chall/{id}`) actually validated, and that the
  requested identifiers pass the profile's restriction set,
  [CAA](adr/0003-fail-closed-security-gates.md), and certlint gates. A
  fail-closed refusal is logged as `cert.caa` / `cert.lint`.
- **`badNonce` loops.** Client clock skew or a proxy stripping the
  `Replay-Nonce` header. Confirm `GET /acme/new-nonce` returns a nonce and the
  header survives your load balancer.
- **EAB failures.** External Account Binding mismatch — verify the client's
  key/MAC against the configured EAB credentials.
- **Renewal timing.** Point clients at ARI (`/acme/renewal-info/{certid}`);
  a revoked or rotating certificate returns a shortened window so clients renew
  early.

### SCEP

- SCEP is query-parameter driven on a single path. Verify capabilities first:
  `GET /scep?operation=getcacaps`. If `getcacacert` returns the wrong cert, the
  SCEP RA/CA binding is misconfigured.
- **SCEP requires an RSA CA** (its CMS/PKCS#7 enveloping is RSA-based). An
  ECDSA/Ed25519 CA cannot back SCEP — use a dedicated RSA intermediate.
- Enrollment (`pkioperation`) failures are almost always the challenge password
  (grant) or the RA key; check the audit log for the denial reason.

### EST

- EST runs over TLS; **client-cert or Basic auth** gates `simpleenroll`.
  A `401` is auth; a `403` is RBAC/policy.
- `simplereenroll` requires a currently-valid client certificate.
- `serverkeygen` is optional and only responds when enabled in config.
- `GET /.well-known/est/cacerts` should always work unauthenticated; if it
  fails, the problem is TLS or the CA chain, not EST auth.

### TSA

- `/tsa` accepts a DER time-stamp request (POST). Verify interop with
  `openssl ts -verify`.
- **TSA requires an RSA key** provisioned via `secsy-ca tsa-key -ca <ca>`.
  A missing/expired TSA cert, or nonce/hash-algorithm mismatch in the request,
  yields a rejection — check the response status and the audit log.

### CMP

- `/cmp` dispatches on message type (`ir`/`cr`/`kur`/`rr`). Protection is PBM
  (shared secret) or signature-based; a protection failure is the usual `400`.
  The `secsy-ca cmp` subcommand is a client for smoke-testing:
  ```bash
  secsy-ca cmp -url https://pki.example.com/cmp -reference <ref> -secret <pbm-secret> \
    -cn device01 -operation ir -cert-out device.pem -key-out device.key
  ```

---

## Rate-limit and HSM-concurrency tuning

Two independent mechanisms protect the public endpoints
([rate-limiting.md](rate-limiting.md)). Both live under `rate_limit:` in
`config.yaml`.

- **Token-bucket rate limiting** — fairness: caps *request rate* globally,
  per-IP, and per-account. Excess gets `429 Too Many Requests` + `Retry-After`.
- **Bounded HSM-concurrency guard** — overload protection: caps how many
  HSM-bound (signing/enrollment) requests run *at once* against the PKCS#11
  session pool. Excess queues briefly, then is shed with `503` + `Retry-After`.

```yaml
rate_limit:
  enabled: true
  global:      { rate: 200.0, burst: 400.0 }   # req/s, bucket capacity
  per_ip:      { rate: 20.0,  burst: 40.0 }
  per_account: { rate: 50.0,  burst: 100.0 }
  max_keys: 100000            # distinct per-IP/per-account buckets before eviction
  idle_ttl_seconds: 600       # idle-bucket eviction TTL
  concurrency:
    enabled: true             # defaults to rate_limit.enabled
    max_in_flight: 0          # <=0 derives from pkcs11.session_pool_size
    max_queue: 64             # waiters before 503 shedding
    acquire_timeout_ms: 5000  # queue wait timeout (0 = wait until ctx canceled)

pkcs11:
  session_pool_size: 8        # concurrent PKCS#11 sessions

server:
  ocsp_cache_ttl_seconds: 60  # OCSP response cache; <0 disables, 0 = default
```

### Tuning by symptom

| Symptom | Likely cause | Action |
|---------|--------------|--------|
| Clients see `429` | Rate tier too tight | Raise `global`/`per_ip`/`per_account` `rate` & `burst` |
| Clients see `503` + `Retry-After` | Concurrency guard shedding | Raise `concurrency.max_in_flight` and `pkcs11.session_pool_size` together |
| High p99 signing latency, no shedding | Session pool starvation | Raise `pkcs11.session_pool_size` (bounded by what the HSM sustains) |
| OCSP flooding the HSM | Cache too short / bypassed | Raise `server.ocsp_cache_ttl_seconds`; note nonce requests bypass the cache |
| Memory growth under a scan/attack | Bucket cache unbounded | Lower `max_keys`, shorten `idle_ttl_seconds` |

**Key relationship:** `max_in_flight <= 0` derives the ceiling from
`pkcs11.session_pool_size`, so the guard tracks the backend it protects. Raise
the pool and the guard follows. Do not set `max_in_flight` far above the pool
size — you would just move the queue from the guard into the HSM driver, where
it is invisible. Size the pool to the HSM's real concurrency (benchmark with
[the load-test suite](benchmarks.md)); a YubiHSM sustains far fewer concurrent
signs than a network HSM.

Watch the guard/throttle Prometheus metrics
([observability.md](observability.md)) while tuning; `429`/`503` counters and
queue-depth gauges tell you which mechanism is firing.

---

## CT log outage

Certificate Transparency submission happens on the issuance path
([certificate-transparency.md](certificate-transparency.md)). Behavior on a CT
log outage is **per-profile** and is the one gate where fail-open is a supported
first-class choice ([ADR 0003](adr/0003-fail-closed-security-gates.md)).

Per-profile config:

```yaml
profiles:
  tls-server:
    ct:
      enabled: true
      logs: []            # names from the global registry; empty = all
      min_scts: 2         # policy minimum (0 → treated as 1)
      fail_open: false    # false = fail-closed (default); true = fail-open
      timeout_seconds: 10 # per-log attempt timeout (0 → 10s default)
      retries: 1          # extra attempts per log after the first
```

- **Fail-closed (`fail_open: false`, default).** If fewer than `min_scts` SCTs
  are obtained, **issuance aborts** with a per-log failure summary; no
  certificate is signed. A CT log outage stops issuance for that profile. Safe
  for high-assurance deployments.
- **Fail-open (`fail_open: true`).** Issuance **proceeds** embedding whatever
  SCTs were obtained (possibly zero); `CTStatus.failed_open` is set and
  recorded in the audit trail / issuance response. A CT log outage does not
  block issuance. Suitable when availability outranks guaranteed logging.

### Handling an outage

1. **Identify** which log is down and which profiles are affected — the
   issuance error (fail-closed) or the `failed_open` flag and `cert.*` audit
   events (fail-open) name the failing logs.
2. **If fail-closed and issuance must continue:** either point `logs` at a
   healthy subset of the registry, lower `min_scts` to what healthy logs can
   satisfy, or — as a deliberate, temporary exception — flip that profile to
   `fail_open: true`. Record the change; revert when the log recovers.
3. **If fail-open:** issuance already survived; monitor `failed_open` counts so
   you know how many certs lack full SCT coverage, and backfill/re-submit once
   the log is healthy if your policy requires it.
4. Add resilient logs and set `retries`/`timeout_seconds` so a single flaky log
   does not dominate issuance latency.

---

## CA key rotation and retirement

The normal (non-compromise) rollover of an **intermediate** signing key uses a
dual-chain overlap window so no outstanding leaf breaks
([ADR 0004](adr/0004-dual-chain-rotation-overlap.md),
[ca-rotation.md](ca-rotation.md)). Three stages:

### 1. Rotate — mint the new key alongside the old

```bash
secsy-ca -config config.yaml rotate-intermediate -ca <ca> \
  -new-label <ca>-2026 -key-type ecdsa-p256 -validity-days 1825 \
  -operators 3 -quorum 2 -chain-out chain.pem
```

Generates a fresh HSM keypair, cross-signs a new intermediate under the same
parent with the **same subject DN**, marks the old CA `superseded`, and points
new issuance at the new key. The `-operators`/`-quorum` flags gate the operation
behind an M-of-N confirmation (omit for single-operator environments;
`-non-interactive` + `-confirm-file` for automation).

### 2. Overlap — publish the combined chain and let leaves drain

```bash
secsy-ca -config config.yaml rotation-status -ca <ca> -json   # lineage + retire_after
secsy-ca -config config.yaml list-rotations                   # all CAs mid-rollover
secsy-ca -config config.yaml publish-chain -ca <ca> -out chain.pem
```

Serve the combined bundle (also at `GET /api/ca/{id}/chain`). During overlap,
old-key leaves chain through the old intermediate and new-key leaves through the
new one; relying parties disambiguate by Authority Key Identifier. Wait until
`retire_after` (the latest `NotAfter` among old-key leaves) has passed, or renew
subscribers onto the new key sooner.

### 3. Retire — remove the drained old key

```bash
secsy-ca -config config.yaml retire-intermediate -ca <ca> \
  -reason superseded -crl-out root-crl.der -operators 3 -quorum 2
```

Revokes the old intermediate under its parent, refreshes the parent CRL/OCSP,
marks the old CA `retired`, and drops it from freshly published chains.
**Retirement is refused while old-key leaves are still valid** unless you pass
`-force` (the compromise path — see
[CA-key compromise](#suspected-ca-key-compromise)).

The monitor can trigger auto-rotation on an approaching intermediate expiry; see
[ca-rotation.md](ca-rotation.md) and [expiry-monitoring.md](expiry-monitoring.md).

**Rehearse first.** `scripts/rotation-drill.sh` runs the full rotate → overlap →
drain → retire cycle against an isolated SoftHSM token, including the
premature-retirement refusal. Keep the workspace for inspection with
`ROT_KEEP=1 ./scripts/rotation-drill.sh`.

---

## Disaster-recovery drill

DR for an HSM-backed CA is HSM-shaped: you recover the *token* (or re-run a key
ceremony) and reattach CA metadata — you never restore a private key from a file
([ADR 0002](adr/0002-hsm-non-extractability-invariants.md)). The end-to-end
procedure and rationale live in [key-ceremony.md](key-ceremony.md); rehearse it
with the drill.

### Run the drill

```bash
./scripts/dr-drill.sh              # provisions an isolated SoftHSM token, cleans up on success
DR_KEEP=1 ./scripts/dr-drill.sh    # keep the workspace to inspect artifacts
```

The drill exercises the real recovery path:

1. Provisions an isolated SoftHSM token in a temp workspace.
2. Runs an M-of-N key ceremony (`secsy-ca ceremony`) creating root + intermediate
   with keys generated on the token.
3. Verifies non-extractability via `secsy-ca inventory`.
4. Backs up CA metadata + DR manifest (`secsy-ca backup -out …`) and the token's
   encrypted key blobs.
5. Simulates disaster — wipes the metadata DB and the token directory.
6. Restores token state and metadata, verifies with `secsy-ca restore -in …`
   (fingerprints match, audit chain intact).
7. Proves the recovered intermediate can still sign fresh leaves.

### Real recovery (production)

1. Restore the HSM token from its backup (vendor-specific for a real HSM; for
   SoftHSM, the token directory). Key material is only ever recovered as the
   HSM's own wrapped blob, never as plaintext.
2. Restore CA metadata: `secsy-ca -config config.yaml restore -in backup.json
   -load-metadata`.
3. Verify: `secsy-ca restore` (fingerprint match) and `secsy-ca audit verify`.
4. Regenerate and publish fresh CRLs (`secsy-ca gen-crl`) and chains
   (`secsy-ca publish-chain`); confirm OCSP/`/readyz` are green.

If the token is unrecoverable, there is no way to recover the key — you fall
back to a fresh [key ceremony](key-ceremony.md) and re-issue the hierarchy, as
in the [root-compromise path](#suspected-ca-key-compromise).

### Full-stack drill (HSM + PostgreSQL store)

`scripts/dr-drill.sh` covers the HSM half. When the deployment uses the
PostgreSQL persistence backend ([persistence.md](persistence.md)), the database
carries the state a restore must not lose or rewind: the tamper-evident audit
chain, the per-CA serial and CRL-number counters, the issued-cert inventory, and
the revocation store. `scripts/dr-drill-full.sh` extends the drill to that half
and rehearses **both** database recovery strategies in one command against an
ephemeral Postgres container:

```bash
./scripts/dr-drill-full.sh            # full drill, cleans up on success
DR_KEEP=1 ./scripts/dr-drill-full.sh  # keep the workspace + containers to inspect
```

It:

1. Provisions an ephemeral PostgreSQL primary (WAL archiving on) + a SoftHSM token.
2. Runs the key ceremony, issues/revokes certs, and cuts CRLs — building real
   audit-chain, counter, inventory, and revocation state.
3. Captures a **pre-disaster integrity fingerprint** (`secsy-ca db verify -json`).
4. **Logical path** — `pg_dump` → destroy the primary → restore into a fresh
   container → gate on `secsy-ca db verify` → re-issue and re-validate a
   certificate end-to-end against the restored DB + HSM.
5. **Physical PITR path** — `pg_basebackup` + archived-WAL replay to a recovery
   target time → gate on `secsy-ca db verify` → confirm the recovery landed on
   exactly the target (work committed before it survives; work after it is
   correctly excluded; the audit head hash matches the pre-disaster fingerprint).

The post-restore gate, `secsy-ca db verify`, is HSM-independent and asserts the
four invariants a restore must preserve. Run it by hand against any restored
database before returning it to service:

```bash
secsy-ca -config config.yaml db verify            # human-readable, non-zero exit on failure
secsy-ca -config config.yaml db verify -json      # includes the continuity fingerprint
# Point it at a specific restored DB instead of the configured one:
secsy-ca db verify -driver postgres -dsn 'postgres://…/secsy_pki?sslmode=disable'
```

| Check | What it proves |
| --- | --- |
| `audit_chain` | the hash-chained `event_log` verifies end-to-end from genesis (no truncation or rewrite) |
| `serial_monotonicity` | every CA's serial counter is strictly ahead of every serial it has issued (no duplicate-serial hazard) |
| `crl_continuity` | every CA/scope CRL-number counter is strictly ahead of every published CRL (RFC 5280 §5.2.3) |
| `revocation_consistency` | the inventory's revoked set and the revocation store agree both ways (nothing served as "good" that is revoked) |

The `-json` fingerprint (`audit_head_hash` + the monotonic counter sums + row
counts) is the **continuity check**: capture it before a backup and compare it
after a restore. The audit head hash must match a faithful restore exactly; the
counter sums must never be smaller after a restore than before (a smaller value
means the counters were rewound behind already-issued artifacts — a split-brain
hazard that would re-issue duplicate serials or stale CRL numbers).

### Choosing a database backup strategy

- **Logical (`pg_dump`)** — simplest; a consistent snapshot restorable into any
  compatible Postgres. Coarser RPO (you lose everything since the last dump).
  Good for a scheduled belt-and-suspenders export.
- **Physical + WAL archiving (`pg_basebackup` + continuous archiving)** — enables
  point-in-time recovery and a tight RPO. This is the recommended production
  posture. Archive WAL continuously to durable, off-host storage; take periodic
  base backups so replay time (and thus RTO) stays bounded.

### RPO / RTO expectations

Recovery objectives are dominated by the **database** — the HSM token is a small,
rarely-changing artifact restored in minutes, and the CA private keys are never
in the database. Set and monitor objectives against the persistence backend.

| Backup strategy | RPO (data loss window) | RTO (time to service) |
| --- | --- | --- |
| Logical `pg_dump`, hourly | up to the dump interval (≈ 1h) | minutes: restore dump + `db verify` + reattach HSM |
| Physical base backup + **continuous WAL archiving** | seconds — bounded by `archive_timeout` and WAL shipping latency (typically < 1 min) | minutes-to-tens-of-minutes: restore base backup + replay WAL to target + `db verify`; grows with WAL volume since the last base backup |
| HSM token restore (either strategy) | n/a (keys are static between ceremonies/rotations) | minutes (vendor restore, or SoftHSM token-dir copy) |

**Targets to hold in production:** RPO ≤ 5 minutes and RTO ≤ 30 minutes for the
issuing tier, achieved with continuous WAL archiving, a daily base backup, and
off-host, access-controlled backup storage. Rehearse quarterly with
`dr-drill-full.sh` and after any schema-affecting upgrade; a green run is the
evidence the objectives are actually met. The non-HSM subset of this drill runs
on every push (the *DR store integrity* CI job) so schema/migration regressions
that would break a restore are caught before release, not during an incident.

### Real database recovery (production)

1. **Stop issuance** so no new work races the restore (rate-limit to zero or take
   the node offline).
2. Recover the database:
   - *Logical:* create an empty database and `psql -f dump.sql`.
   - *PITR:* restore the base backup's data directory, set `restore_command`,
     `recovery_target_time` (or `_lsn`/`_name`), and `recovery_target_action =
     promote`, drop a `recovery.signal`, and start Postgres; wait for it to
     promote out of recovery.
3. **Gate on integrity:** `secsy-ca db verify` (and `secsy-ca audit verify`) —
   do not return the node to service on a failed check.
4. Restore/attach the HSM token (see [Real recovery](#real-recovery-production)
   above) and reattach the CA metadata now in the recovered DB.
5. Regenerate and publish fresh CRLs (`secsy-ca gen-crl`) and chains
   (`secsy-ca publish-chain`); confirm OCSP and `/readyz` are green; then lift the
   issuance stop.

---

## Observability: dashboards & alerts

The Grafana dashboard and Prometheus alerting rules ship in the repo and Helm
chart. See [observability.md](observability.md#packaged-dashboard--alerting-rules)
for import/deploy steps and the full threshold table. Each shipped alert carries
a `runbook_url` pointing back to the matching subsection below.

- Dashboard JSON: `deploy/helm/secsy-pki/files/grafana-dashboard.json`
- Alert rules: `deploy/helm/secsy-pki/files/prometheus-rules.yaml`
- Helm gates: `serviceMonitor.enabled`, `prometheusRule.enabled`,
  `grafanaDashboard.enabled` (all default off).

### Observability alert response

General triage for any secsy-pki page (and for `SecsyPKITargetDown`):

1. `GET /healthz` (process) and `GET /readyz` (DB + HSM). A `503` from `/readyz`
   names the failing component.
2. Open the **secsy-pki — PKI & HSM overview** dashboard, scope the `job`
   variable to the affected instance, and read top-to-bottom (Overview →
   HSM/pool → Revocation → Rate limiting → Monitor/Audit).
3. If the scrape target itself is down, check pod status/logs and the readiness
   probe before trusting derived alerts — most go stale when the target is down.

### HSM probe down

`SecsyPKIHSMProbeDown` — `secsy_component_up{component="hsm"}=0`. All signing is
blocked. Follow [OCSP / CRL outage](#ocsp--crl-outage) diagnosis for the HSM leg:
verify the PKCS#11 module/token is reachable, the PIN secret is mounted, and the
network-HSM (if any) is up. The instance fails `/readyz` and is pulled from the
Service until the probe recovers.

### HSM pool exhaustion

`SecsyPKIHSMPoolExhausted` (queueing), `SecsyPKIHSMGuardShedding` (503s), and
`SecsyPKIHSMSignLatencyHigh` all point at the HSM being the bottleneck. Use the
dashboard's *Session-pool saturation* and *HSM latency* panels, then apply the
levers in [Rate-limit and HSM-concurrency tuning](#rate-limit-and-hsm-concurrency-tuning):
raise `pkcs11.session_pool_size` and `rate_limit.concurrency.max_in_flight`,
scale replicas, or offload OCSP with a longer `ocsp_cache_ttl_seconds`. Rising
sign latency with a healthy HSM usually means the pool is too small for the
offered concurrency.

### Issuance error-rate SLO burn

`SecsyPKIIssuanceErrorBudgetBurn{Fast,Slow}` — multi-window burn on the 99.5%
issuance SLO. Slice `secsy_certificates_total{result="error"}` by `operation`,
then check whether failures are signing (HSM), policy (CAA/lint rejections —
`secsy_certificate_caa_checks_total`, `secsy_certificate_lints_total`), or store
errors. The fast burn (14.4x) pages; the slow burn (6x) is a ticket. Adjust the
`0.005` budget in the rules if your SLO target differs.

### Certificate expiry backlog

`SecsyPKICertificatesExpired` (already past `notAfter`),
`SecsyPKIExpiryBacklog` (critical window filling), and `SecsyPKIAutoRenewFailing`
mean the renewal pipeline is behind. Confirm the monitor is enabled and
auto-renew is on (`monitor.enabled`, `monitor.autoRenew`), check
`secsy_certificate_auto_renewals_total{result="error"}` for the cause (signing,
profile, RBAC), and renew manually if expiry is imminent. Tune
`SecsyPKIExpiryBacklog`'s `> 25` threshold to your fleet size.

### CRL/delta staleness

`SecsyPKICRLNotRegenerating` — no base CRL signed on the HSM within a full base
lifetime while CRLs are still served, so served CRLs risk passing `nextUpdate`.
Set the rule's `25h` window to just over your `crl.baseValidityHours`, verify HSM
signing and the CRL scheduler, and force-regenerate with
`secsy-ca gen-crl -ca <id> -out crl.der -der`. Because the metrics expose no CRL
`nextUpdate`, add a blackbox-exporter probe of the CDP URL and alert on the
parsed `nextUpdate` for an authoritative freshness SLO. Serving errors are
covered by `SecsyPKICRLServingErrors`/`SecsyPKIOCSPErrorRateHigh` — see
[OCSP / CRL outage](#ocsp--crl-outage).

### Rate-limit guard rejections spiking

`SecsyPKIRateLimitThrottleSpike` — a large fraction of public traffic is 429'd.
Distinguish abuse from an over-tight limit using the dashboard's *throttles by
endpoint & tier* panel: a single IP/account tier dominating suggests abuse (let
the limiter shed it); broad throttling across tiers suggests the limit is too low
for legitimate load — relax `rate_limit.{global,per_ip,per_account}` per
[Rate-limit and HSM-concurrency tuning](#rate-limit-and-hsm-concurrency-tuning).
Note 429 (rate limit) and 503 (HSM guard) are different levers.

### Monitor and audit health

`SecsyPKIMonitorStalled` — the expiry monitor has not completed a scan in >36h,
so expiry gauges are stale and auto-renew is not running; match the rule window
to `monitor.intervalHours` and check the monitor loop/logs.
`SecsyPKIAuditExportLagHigh` / `SecsyPKIAuditExportStalled` — audit events are
piling up undelivered to a SIEM sink (lag high) or delivery is stuck (backlog +
no ack in 30m), risking a compliance gap. Check the named sink's reachability and
the exporter cursor; see [audit-siem-export.md](audit-siem-export.md).
`SecsyPKIAuditAnchorStale` / `SecsyPKIAuditAnchorFailures` — the audit-chain
anchor job is not producing RFC 3161 head attestations; see
[Audit-chain anchoring](#audit-chain-anchoring).

---

## Audit-chain anchoring

The hash-chained event log proves *internal* consistency: editing, reordering,
or deleting an entry breaks the chain from that point on. What it cannot prove
by itself is that the log ever extended further than it does now — a party with
write access to the store can drop the newest entries (truncation) or re-seal
every entry after an edit (whole-chain rewrite) and present a shorter,
internally consistent log.

Anchoring closes that gap. On a fixed cadence (and on demand) the server takes
the chain head `(seq, hash)`, has an RFC 3161 TSA sign a timestamp token over
its canonical digest, and stores the token in `audit_anchors`. The token is
produced by a key the store writer does not hold (the HSM-resident TSA key, or
an external TSA entirely), so after each anchor point the log's existence and
exact head hash are independently attested. Every anchoring also appends an
`audit.anchor` event — which the SIEM export streams off-host, giving an
external copy of each anchored head even if the local anchor rows are deleted.

### Configuration and cadence

```yaml
tsa:
  enabled: true            # internal TSA (HSM-backed); provision with: secsy-ca tsa-key
  key_label: tsa
  certificate_file: tsa.pem
audit:
  anchor:
    enabled: true
    interval_hours: 24     # default; each interval bounds the truncation window
    # tsa_url: https://tsa.example/tsa   # external TSA for full independence
    # timeout_seconds: 30
```

Choosing the cadence: an attacker who rewrites or truncates the log can only
hide events appended **since the last anchor**, so the interval is your maximum
undetectable-truncation window. Daily is the default; high-assurance
deployments run hourly (each anchor costs one TSA signature and a ~4 KB row).
Anchoring skips automatically while the log is idle, so a quiet deployment does
not accumulate anchors.

Internal vs. external TSA: the internal TSA keeps the trust boundary at the
HSM — a database-level attacker cannot re-anchor a rewritten log because the
TSA key never leaves the token. If your threat model includes an attacker who
controls this host *and* can drive its HSM, set `audit.anchor.tsa_url` to an
independent TSA (or run both: anchor internally and periodically re-anchor
externally with `secsy-ca audit anchor` from another machine's config).

### Operating it

```bash
# Anchor the current head now (e.g. before maintenance or a restore):
secsy-ca -config config.yaml audit anchor

# List stored anchors; -json includes the base64 DER tokens for archival:
secsy-ca -config config.yaml audit anchor -list

# Verify: chain walk + every anchor (linkage and token signature). Non-zero
# exit on any failure. -tsa-ca additionally chains the TSA cert to a root.
secsy-ca -config config.yaml audit verify -tsa-ca tsa-root.pem
```

Metrics: `secsy_audit_anchor_age_seconds` (seconds since the newest anchor,
seeded from the store at startup), `secsy_audit_anchor_pending_events` (events
appended since it), `secsy_audit_anchors_total{result}` (success/error/skipped),
and `secsy_audit_anchor_head_seq`.

### Interpreting verification failures

`audit verify` reports the chain result and each anchor separately. Read them
together:

- **Chain BROKEN, anchors OK/irrelevant** — in-place tampering after the break
  point, the case the chain alone already catches. Investigate from the
  reported seq; see [Suspected CA-key compromise](#suspected-ca-key-compromise).
- **Chain OK, anchor fails `log was truncated: anchored head seq N is beyond
  the current tail M`** — the log verifies but used to extend past its current
  tail: entries after seq M were deleted. Everything between M and N (and
  anything after) is missing; recover the events from the SIEM export or a
  backup and treat the store as compromised.
- **Chain OK, anchor fails `chain hash at seq N does not match the anchored
  head`** — the whole chain was rewritten and re-sealed: history up to N was
  altered even though every link now checks out. The SIEM copy (exported before
  the rewrite) is the authoritative record to diff against.
- **Anchor fails token checks (`timestamp token signature`, `does not cover
  this anchor's (seq, head hash)`)** — the anchor row itself was tampered with
  or corrupted. The chain may still be fine; cross-check against the remaining
  anchors and the off-host `audit.anchor` events.
- **After a restore/PITR** — old anchors must still verify against the restored
  log (they attest prefixes). A newest anchor failing with "truncated" tells
  you the backup predates it: events after the restore point were lost — walk
  the SIEM export from the restored head seq to reconstruct. Anchor immediately
  after any restore (`secsy-ca audit anchor -force`) to attest the new baseline.

An anchor only ever attests history **up to** its seq. Events after the newest
anchor carry no external evidence yet — that residual window is what
`SecsyPKIAuditAnchorStale` guards (it fires when unanchored events exist and no
anchor happened for >48h).

---

## Supply-chain / image verification failure

Symptom: `cosign verify`, `cosign verify-attestation`, `slsa-verifier`, or an
admission controller (Kyverno / policy-controller) **rejects** a secsy-pki image
that you expect to be legitimate, or a deploy is blocked by policy. Treat a hard
verification failure as a potential tampering event until proven otherwise —
**do not bypass the check to unblock a deploy.**

1. **Confirm you are verifying by digest, with the right identity.** Resolve the
   tag to a digest and pin both the signer identity and the OIDC issuer:
   ```bash
   cosign verify \
     --certificate-identity-regexp "^https://github.com/<owner>/secsy-pki/" \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
     ghcr.io/<owner>/secsy-pki@sha256:<digest>
   ```
   A mismatch on identity/issuer (not signature) usually means a stale policy
   after the repo/owner moved — update the pinned identity, don't disable it.
2. **Distinguish "unsigned" from "bad signature".** No signature found on a
   *release* tag means the `release.yaml` pipeline didn't complete its sign step
   — check the workflow run. A signature that fails to verify against a valid
   identity is a genuine red flag: stop, and escalate as a suspected
   [supply-chain compromise](#suspected-ca-key-compromise) (same containment
   posture — halt rollout, preserve the artifact).
3. **govulncheck gate is failing the build.** The pipeline refuses to publish
   when a reachable CVE is present. For a stdlib CVE, bump the `toolchain`
   directive in `server/go.mod` to the fixed patch release; for a module CVE,
   `go get` the fixed version. Re-run `make govulncheck` locally to confirm
   before re-tagging.
4. **Provenance mismatch.** `slsa-verifier` failing on `--source-uri`/`--source-tag`
   means the image wasn't built from the expected repo/tag — do not deploy it.

Full producer/consumer reference (SBOMs, keyless vs. key signing, admission
enforcement, the `make` targets): [supply-chain.md](supply-chain.md).

---

## Preflight diagnostics (`secsy-ca doctor`)

Run the read-only diagnostic suite before starting a node and after anything
that could change its dependencies — an upgrade, a config edit, a restore, a
key or certificate rotation, an HSM/KMS migration:

```bash
secsy-ca -config config.yaml doctor           # human table
secsy-ca -config config.yaml doctor -json     # machine-readable, for CI/automation
secsy-ca -config config.yaml doctor -deep     # + full store-integrity gate (walks the whole audit chain)
```

The doctor never mutates anything: no keys are generated, no rows written, no
schema migrations applied (the store is opened read-inspect-only), and the key
self-tests sign inside the provider and verify against the public half — no
private material leaves the backend, per
[ADR 0002](adr/0002-hsm-non-extractability-invariants.md). It reuses the same
probes the server trusts: `keyprovider.Prober` (the `/readyz` HSM probe),
`audit.VerifyChain`, and — with `-deep` — the `secsy-ca db verify` integrity
gate.

### Exit codes (CI contract)

| Code | Meaning | Typical CI policy |
|------|---------|-------------------|
| `0` | every check passed (or was skipped as not-applicable) | proceed |
| `1` | at least one check **failed** — the node is broken or will refuse to start | block |
| `2` | no failures, but at least one **warning** (expiring cert, degraded HA set, config typo, …) | proceed + page/annotate; tolerate with `secsy-ca doctor \|\| [ $? -eq 2 ]` |

### What is checked

| Check | Verifies | Fails when / warns when |
|-------|----------|--------------------------|
| `config.parse` | config file parses and passes the same validation the server runs | fail: malformed YAML or invalid values |
| `config.unknown_keys` | strict re-decode flags keys that map to no known field | warn: typo'd keys that would be silently ignored |
| `keyprovider.<role>` | per signing role (`ca`, `tsa`, `signing`): PKCS#11 module/slot/PIN login, cloud-KMS credentials, or software keystore access | fail: module missing, wrong PIN, token absent, KMS credentials rejected |
| `hsm.ha_tokens` | every token of a multi-token HA set is actively probed (not just the rotation state, which starts optimistic) | warn: some tokens unreachable; fail: all |
| `db.connectivity` | store reachable, opened **without** migrating; a missing SQLite file is never created | fail: unreachable/missing |
| `db.schema` | pending-migration detection against the canonical table list | warn: tables missing (created on next normal start) |
| `keys.ca` | sign/verify self-test per CA key (X.509 and SSH), against the exact label the issuance path uses; provider key must match the certificate on record; PKCS#11 keys must be non-extractable | fail: key missing, sign fails, key↔cert mismatch; warn: CKA_EXTRACTABLE set |
| `keys.tsa`, `keys.signing` | same self-test for the TSA and artifact-signing keys on their role backends | fail: missing/unusable |
| `keys.secret_kek` | envelope KEKs (deployment-wide + per-tenant) present and RSA | warn: not yet provisioned; fail: wrong type |
| `keys.ocsp_delegate` | delegated OCSP responder keys usable (certificates are short-lived and re-issued automatically) | fail: present but unusable |
| `audit.chain_head` | hash-chain of the newest `-audit-sample` events (default 1000): contiguous seq, back-links, content hashes | fail: tampering/breakage in the sampled window |
| `db.integrity` | (`-deep` only) full `db verify`: whole chain from genesis + serial/CRL/revocation monotonicity | fail: any invariant broken |
| `certs.ca_expiry` | CA certificate headroom (superseded CAs cap at warn; retired skipped) | fail < `-expiry-fail-days` (7); warn < `-expiry-warn-days` (30) |
| `certs.tsa_expiry`, `certs.signing_expiry` | the configured `certificate_file`s parse and have headroom | fail: unreadable or expiring |
| `crl.freshness` | every persisted base/delta/shard CRL vs `nextUpdate` | fail: stale while `publish.enabled` (static consumers); warn: stale (regenerated on next fetch) or inside the final ¼ of its window |
| `clock.skew` | host↔PostgreSQL clock offset; newest audit event not future-dated | fail > 60s; warn > 10s (tune via code defaults) |
| `listener.tls` | `server.tls_cert/tls_key` load and match, leaf headroom; if the listener is up, a live handshake must present the configured certificate | fail: no TLS (server fails closed) or broken pair; warn: running server serves a different certificate (restart pending) |

An unreachable listener is *not* a finding — doctor normally runs before the
server starts. `-no-listener` skips the live probe entirely.

### Rehearsing failure detection

The SoftHSM test suite (`server/internal/doctor`) injects each failure mode
deliberately — wrong PIN, a CA row whose key is missing from the token, a
stale CRL, a tampered audit event, a dead HA token — and asserts the doctor
catches it with the right severity. To rehearse by hand against a scratch
token: point `pkcs11.pin` at a wrong value (expect `keyprovider.ca` FAIL,
exit 1), or age a persisted CRL and expect `crl.freshness` WARN, exit 2.

---

## First-response quick reference

| Situation | First command / check |
|-----------|-----------------------|
| Preflight a node (config/HSM/DB/expiry/…) | `secsy-ca doctor` (`-json` in CI; exit 0/1/2) |
| Is the service healthy? | `GET /healthz` (live), `GET /readyz` (DB + HSM) |
| Is the HSM reachable? | `GET /readyz`; inspect HSM probe in `/metrics` |
| Prove the CA key wasn't misused | `secsy-ca audit verify -json` + `secsy-verify verify-combined-log` |
| Revocation not propagating | Regenerate CRL: `secsy-ca gen-crl -ca <id> -out crl.der -der` |
| Clients getting `429` | Loosen `rate_limit.{global,per_ip,per_account}` |
| Clients getting `503` | Raise `rate_limit.concurrency.max_in_flight` + `pkcs11.session_pool_size` |
| OCSP overloading HSM | Raise `server.ocsp_cache_ttl_seconds` |
| CT log down, issuance stopped | Per-profile `logs`/`min_scts`/`fail_open` (see [CT outage](#ct-log-outage)) |
| Rotate an intermediate | `rotate-intermediate` → `publish-chain` → (drain) → `retire-intermediate` |
| Rehearse DR | `./scripts/dr-drill.sh` |
| Image signature/policy rejected | Verify by digest with pinned identity; treat a bad signature as tampering ([supply-chain](#supply-chain--image-verification-failure)) |
| Build blocked by govulncheck | Bump `toolchain` in `server/go.mod` (stdlib) or `go get` fixed dep; re-run `make govulncheck` |

See also: [observability](observability.md) for the metrics/alerts to wire up,
[security review](security-review.md) for the hardening baseline, and the
[ADRs](adr/README.md) for why the system behaves as it does.
