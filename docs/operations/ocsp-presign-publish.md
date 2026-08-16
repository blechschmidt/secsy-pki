# OCSP pre-signing and static artifact publishing (CDN offload)

The public revocation endpoints — OCSP, CRLs, chains — are the PKI's highest
volume surface, and in the naive design every OCSP request costs an on-HSM
signature. Task 58 removes the HSM from that hot path twice over:

1. **OCSP pre-signing** — a background batch signs a response for *every known
   serial* on a schedule and places it in the response cache. The public
   responder then answers from memory; the HSM is only touched by the batch,
   by nonce-bearing requests (RFC 8954 requires a fresh, request-bound
   signature), and by cache misses.
2. **Static artifact publishing** — a publisher writes the CRLs, delta CRLs,
   partition shards, issuer chains, and the pre-signed OCSP responses as
   static files to a local directory or an S3-compatible object store, in a
   layout a CDN (or any static file server) can front. The PKI can then be
   entirely absent from the serving path.

Because a pre-signed response is an ordinary signed OCSP response valid until
its `NextUpdate`, both layers double as an availability hedge: **an HSM outage
does not interrupt revocation serving** until the already-signed material
actually expires (see the runbook section below).

---

## OCSP pre-signing

### What gets signed

Each batch covers, per CA:

- every **issued** certificate whose `NotAfter` is within the expired-grace
  window (default: expired less than 24h ago) → status `good`,
- every **revocation** record (always, so `revoked` answers never age out
  while relying parties still ask) → status `revoked`,
- when enabled, serials **recently queried** through the online responder —
  including serials the store does not know (answered `unknown`). The tracker
  is a bounded LRU (default 4096), which caps the extra signing an
  adversarial scanner can induce.

The batch resolves all statuses up front, opens **one** HSM signer for the
whole CA, and signs sequentially — no per-request session churn. When the
delegated responder is enabled (`server.ocsp.delegated`), pre-signed responses
are signed by the same short-lived delegated OCSP-signing certificate as
online responses, keeping the CA key cold.

Responses are placed in the shared response cache with an expiry equal to
their own `NextUpdate` (not the demand-fill TTL), and the cache prefers
evicting demand-filled entries under pressure so a flood of distinct serials
cannot evict the pre-signed set. Revoking a certificate still invalidates its
cache entry immediately — the next request is answered freshly with `revoked`.

### Configuration

```yaml
server:
  ocsp:
    presign:
      enabled: true
      validity_minutes: 1440   # NextUpdate window (default 24h)
      refresh_minutes: 360     # batch cadence (default validity/4)
      recently_queried: true   # track+cover serials seen online (default)
      recent_capacity: 4096
      expired_grace_minutes: 1440  # keep signing 24h past leaf expiry; -1 disables
```

Validation refuses `refresh_minutes > validity_minutes / 2` (a missed batch or
two must never mean serving expired responses) and refuses pre-signing when
the response cache is disabled (`server.ocsp_cache_ttl_seconds < 0`).

**Choosing the windows.** `validity` is simultaneously (a) the maximum
revocation-propagation delay for consumers of pre-signed/published responses
and (b) the maximum HSM outage the responder can ride out. 24h/6h is a
sensible default; high-security deployments shorten validity, availability-
focused ones lengthen it. Nonce-bearing and demand-signed responses are always
fresh regardless.

### Metrics

| Metric | Meaning |
|---|---|
| `secsy_ocsp_presign_batch_duration_seconds` | Histogram of full batch runs |
| `secsy_ocsp_presign_responses_total{result}` | Responses signed / failed |
| `secsy_ocsp_presigned_responses` | Unexpired pre-signed entries servable now |
| `secsy_ocsp_presign_last_success_timestamp_seconds` | Last successful batch |
| `secsy_ocsp_presign_staleness_seconds` | Seconds since the last successful batch, computed at scrape; absent until the first batch |

Alert when `secsy_ocsp_presign_staleness_seconds` approaches the validity
window (e.g. `> validity/2`): responses are aging with no fresh batch behind
them.

---

## Static artifact publishing

### Layout

All paths are relative to the publish root (directory backend: `<path>/current/`;
S3 backend: `s3://<bucket>/<prefix>/`):

```
<caID>/ca.der, ca.pem                  CA certificate (AIA caIssuers payload)
<caID>/chain.pem                       rollover-overlap chain bundle
<caID>/chain-<crossSignID>.pem         alternate (cross-signed) chains
<caID>/crl.der                         complete base CRL
<caID>/crl-delta.der                   delta CRL
<caID>/crl-partition-<n>.der           shard base CRL (when crl.shards >= 2)
<caID>/crl-partition-<n>-delta.der     shard delta CRL
<caID>/ocsp/by-serial/<serial>.der     pre-signed OCSP response (decimal serial)
<caID>/ocsp/by-request/<b64url>.der    same bytes, keyed by the canonical request
manifest.json                          snapshot manifest, written last
```

The `by-request` key is the **base64url (unpadded)** encoding of the canonical
RFC 6960 OCSP GET request for that serial: SHA-1 certID, no extensions —
byte-identical to what RFC 5019-profile clients send. A CDN function fronting
`GET {base}/api/ca/{id}/ocsp/{b64}` maps the URL path onto the static object by
url-decoding the path segment and translating standard base64 to base64url
(`+`→`-`, `/`→`_`, strip `=`). Requests that don't match a static key (nonce
requests, exotic certID hashes) fall through to the origin responder, which is
exactly the RFC-required behavior.

Example CDN mappings:

```
/api/ca/{id}/crl                     → /{id}/crl.der
/api/ca/{id}/crl/delta               → /{id}/crl-delta.der
/api/ca/{id}/crl/partition/{n}       → /{id}/crl-partition-{n}.der
/api/ca/{id}/crl/partition/{n}/delta → /{id}/crl-partition-{n}-delta.der
/api/ca/{id}/chain                   → /{id}/chain.pem
/api/ca/{id}/ocsp/{b64}              → /{id}/ocsp/by-request/{b64url(b64)}.der
```

### Atomicity and integrity

- Every artifact is **validated before inclusion**: CRLs must parse, verify
  against the CA, and be unexpired; chains must parse as certificates;
  expired pre-signed responses are dropped.
- **Directory backend**: each snapshot is written to its own versioned
  directory under `snapshots/`, every file is **read back and its SHA-256
  compared** to the manifest, and only then is the `current` symlink flipped
  over it with a single `rename(2)` — consumers see the old snapshot or the
  new one, never a mixture. Old snapshots beyond `keep_snapshots` (default 3)
  are pruned afterwards. Point your CDN origin / rsync / file server at
  `<path>/current`.
- **S3 backend**: objects offer no multi-key atomicity, so the contract is
  *manifest-last*: `manifest.json` is only uploaded after every artifact
  succeeded, and each PUT carries a `Content-MD5` the server verifies, with
  the returned ETag checked against the local digest. Manifest-driven
  consumers never see a partial snapshot; per-object consumers see atomic
  object replacement.
- `manifest.json` records the SHA-256, size, kind, and validity horizon of
  every artifact plus the snapshot-wide `earliest_expiry`.

### Configuration

```yaml
publish:
  enabled: true
  interval_minutes: 360      # default: the presign refresh cadence
  cas: []                    # ids/labels; empty = all unexpired X.509 CAs
  include_ocsp: true
  dir:
    path: /var/lib/secsy/publish
    keep_snapshots: 3
  # or an S3-compatible store (setting s3.bucket selects it):
  s3:
    endpoint: http://minio.internal:9000   # empty = AWS S3
    region: us-east-1
    bucket: pki-artifacts
    prefix: rev/prod
    access_key_id: "..."                   # empty = AWS default chain
    secret_access_key: "..."
    concurrency: 8
```

`publish.enabled` with OCSP artifacts requires `server.ocsp.presign.enabled`
(or an explicit `include_ocsp: false`) — the two are designed to run off the
same batch so the CDN serves exactly what the origin cache serves.

### Metrics

`secsy_publish_runs_total{backend,result}`, `secsy_publish_duration_seconds`,
`secsy_publish_artifacts{kind}`, `secsy_publish_last_success_timestamp_seconds{backend}`,
and `secsy_publish_staleness_seconds` (scrape-time, absent until the first
publish). Alert on staleness approaching the shortest artifact validity —
`manifest.json`'s `earliest_expiry` is the authoritative horizon.

---

## CLI

```
secsy-ca publish [-ca id,label,...] [-out DIR] [-skip-ocsp] [-ocsp-validity 24h] [-quiet]
secsy-ca publish -verify
```

`publish` runs one snapshot: it (re)signs any stale CRLs, pre-signs the OCSP
response set fresh, and writes the snapshot to the configured backend (`-out`
forces a directory). `publish -verify` audits the **currently published**
snapshot — it re-reads every artifact and checks it against the manifest
digests. Verification deliberately needs neither the HSM nor the key provider,
so it works mid-outage.

---

## Runbook

### HSM outage while CDN-offloaded

Symptoms: `secsy_hsm_operations_total{result="error"}` climbing,
`secsy_component_up{component="hsm"} == 0`, presign batches logging
`WARNING: OCSP pre-signing batch failed`.

What still works, and for how long:

| Surface | Behavior during outage |
|---|---|
| OCSP for pre-signed serials (cache or CDN) | Served normally until each response's `NextUpdate` (up to `presign.validity`) |
| OCSP nonce-bearing requests | `tryLater` (correct: they must be freshly signed) |
| OCSP for uncached serials | `tryLater` |
| CRLs (server and published) | Served from the store/snapshot until `NextUpdate`; base CRLs are typically 7-day objects |
| Issuance / renewal / revocation signing | Unavailable (HSM required) |

Operator actions:

1. Confirm scope with `secsy-ca publish -verify` — the published snapshot's
   integrity is provable without the HSM.
2. Watch `secsy_ocsp_presign_staleness_seconds` against `presign.validity`
   and `manifest.json`'s `earliest_expiry`: that is the hard deadline for HSM
   recovery before revocation serving degrades.
3. On recovery, the next presign batch and publish run restore the full
   window automatically; run `secsy-ca publish` for an immediate refresh.

Note that a *revocation performed during an outage cannot be signed into new
material*: the server invalidates the online cache entry (those requests get
`tryLater` rather than a stale `good`), but a CDN keeps serving the previously
published `good` response until a fresh snapshot replaces it. This is the
standard OCSP trade-off — bound it with `presign.validity`.

### Revocation propagation when CDN-offloaded

After `secsy-ca revoke` (or the API/gRPC equivalents):

- the online responder answers `revoked` immediately (cache invalidated);
- pre-signed/published copies update on the next presign + publish cycle —
  worst case `presign.refresh + publish.interval`, bounded by
  `presign.validity` plus CDN TTL.

For an urgent revocation, force the cycle: `secsy-ca publish` (fresh presign +
snapshot), then invalidate the CDN cache for
`/{caID}/ocsp/by-serial/{serial}.der`, the matching `by-request` key, and the
CRL paths.

### Storage sizing

Per CA: 2 CRL objects (+2 per shard), 1–2 chain bundles, and — with OCSP
enabled — **two objects per serial** (by-serial + by-request), each roughly
0.5–2 KB. 100k certificates ≈ 200k objects ≈ ~300 MB per snapshot; the
directory backend retains `keep_snapshots` of those. Disable `include_ocsp`
(and front the live responder with a caching CDN instead) if object count is a
concern.

## Tests

- `internal/ca/presign_test.go` — batch statuses (good/revoked/unknown),
  cache fill and eviction preference, delegated signing, expired-grace window,
  and `TestOCSPPresignSurvivesHSMOutage`: pre-signed responses stay valid and
  servable across a simulated outage, on both the software provider and
  **SoftHSM**.
- `internal/handlers/ocsp_presign_test.go` — HTTP-level proof: GET/POST served
  from cache with the provider down, nonce requests degrade to `tryLater`,
  recently-queried serials join the next batch, revocation invalidates.
- `internal/publish/` — directory layout + manifest + atomic swap + prune,
  corruption detection, S3 fake-endpoint publish/verify, ETag integrity
  failure, manifest-last on partial failure, and the full snapshot test
  (sharded CRLs, by-request keys, `publish.Verify`).
