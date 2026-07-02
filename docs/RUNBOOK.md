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
8. [First-response quick reference](#first-response-quick-reference)

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
| CRL | GET | `/api/ca/{id}/crl` |
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
  Automate CRL refresh ahead of `Next Update`; a lapsed CRL is an outage.
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

---

## First-response quick reference

| Situation | First command / check |
|-----------|-----------------------|
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

See also: [observability](observability.md) for the metrics/alerts to wire up,
[security review](security-review.md) for the hardening baseline, and the
[ADRs](adr/README.md) for why the system behaves as it does.
