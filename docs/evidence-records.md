# Long-Term Preservation — Evidence Records (RFC 4998)

secsy-pki can wrap its tamper-evident audit chain and signed artifacts in
[RFC 4998](https://www.rfc-editor.org/rfc/rfc4998) **Evidence Records (ERS)** so
their existence survives the eventual obsolescence of any single hash or
signature algorithm.

An [RFC 3161 audit anchor](timestamping.md) proves the audit chain's head
existed at a point in time — but that proof rests on one timestamp token, and
once its hash or the TSA's signature algorithm is broken the proof is worthless.
This is the LTANS / eIDAS long-term-preservation gap. An Evidence Record instead
carries a **renewable** chain of archive timestamps: before a timestamp's
certificate expires it is re-stamped (time-stamp renewal), and before its hash
algorithm weakens the protected data is re-hashed under a stronger algorithm and
re-stamped (hash-tree renewal). Each renewal is itself timestamped *while the
previous one is still trustworthy*, so the unbroken sequence preserves the
original existence proof indefinitely.

Every archive timestamp is an **HSM-backed** RFC 3161 token from the internal
[TSA](timestamping.md) (or an external one) — the signing key never leaves the
device.

## What it protects

- **The audit chain.** The leader-elected preservation job folds recent
  `event_log` events into Evidence Records. Because an audit-scope record stores
  only the covered sequence range, verification re-derives the events from the
  live log and re-hashes them — so a valid Evidence Record also proves the live
  audit chain still matches what was preserved.
- **Signed artifacts.** `secsy-ca ers generate FILE...` preserves arbitrary
  files (e.g. [CAdES-LT](artifact-signing.md) signatures with their revocation
  material) as an artifact-scope record.

## Structure

An Evidence Record is a DER `EvidenceRecord` (RFC 4998 §4):

```
EvidenceRecord
└─ ArchiveTimeStampSequence          SEQUENCE OF ArchiveTimeStampChain
   ├─ ArchiveTimeStampChain          (hash algorithm H1 — e.g. SHA-256)
   │  ├─ ArchiveTimeStamp            initial: reduced hash tree + RFC 3161 token over the root
   │  └─ ArchiveTimeStamp            time-stamp renewal: covers the previous token
   └─ ArchiveTimeStampChain          (hash algorithm H2 — e.g. SHA-512)
      └─ ArchiveTimeStamp            hash-tree renewal: re-binds the objects + all prior chains
```

The protected objects of one record form a single RFC 4998 **data group**: each
object is hashed into a leaf, the leaves (binary-ascending sorted) are the first
`PartialHashtree` list, and the group root — `H` over the sorted concatenation of
the leaves — is what the archive timestamp covers. Verification recomputes the
root from the reduced hash tree (RFC 4998 §4.3) and checks it against the token's
message imprint.

- **Time-stamp renewal** (RFC 4998 §5.2) appends an `ArchiveTimeStamp` over the
  hash of the previous timestamp token, in the **same** chain, keeping the hash
  algorithm. It fires before the newest TSA certificate expires.
- **Hash-tree renewal** (RFC 4998 §5.2) starts a **new** chain: each object is
  re-hashed under the stronger algorithm and bound to the hash of the entire
  prior `ArchiveTimeStampSequence` (`h(i)' = H_new(H_new(d(i)) || H_new(atsc))`),
  a fresh root is timestamped, and the new chain is appended. It fires when the
  current algorithm is deprecated.

## The preservation job

Enabling `ers.enabled` registers a leader-elected background loop (one replica at
a time, like [backups](backup.md) and [anchoring](timestamping.md)). Each cycle:

1. **Generate** — folds new audit events (since a durable cursor) into Evidence
   Records, `ers.batch_size` events per record. The cursor advances only after a
   record is persisted, so a crash re-preserves rather than loses the batch.
2. **Renew** — scans every record and renews those that are due: a hash-tree
   renewal when the current algorithm is deprecated or weaker than `ers.hash`,
   otherwise a time-stamp renewal when the newest TSA certificate is within
   `ers.renewal_lookahead_days` of expiry.

**Algorithm deprecation is driven by the [FIPS policy](fips.md).** When
`security.fips` is enforced, any hash the policy does not approve is treated as
deprecated and its records are migrated to `ers.hash` automatically. Raising
`ers.hash` (e.g. `sha256` → `sha512`) also migrates every weaker record.

## Configuration

```yaml
tsa:
  enabled: true          # the archive-timestamp source (or set ers.tsa_url)
  key_label: "tsa-key"
  certificate_file: "/etc/secsy/tsa.pem"

ers:
  enabled: true
  schedule:
    interval_hours: 24          # cycle cadence (default 24)
  hash: "sha256"                # hash-tree algorithm & renewal target (sha256|sha384|sha512)
  renewal_lookahead_days: 30    # time-stamp renewal fires this long before TSA cert expiry
  batch_size: 256               # audit events per record (capped at 4096)
  preserve_audit: true          # generate over audit events (default true)
  # tsa_url: "https://tsa.example.com/tsa"   # external TSA instead of the internal one
  # timeout_seconds: 30
```

`ers.enabled` requires either the internal TSA (`tsa.enabled: true`) or an
external `ers.tsa_url`. The `secsy-ca ers` CLI works regardless of the flag.

## CLI

The provider is opened lazily, so `verify`, `export`, and `list` never touch the
HSM.

```bash
# Preserve a range of audit events, or one or more artifact files.
secsy-ca ers generate -audit-from 1 -audit-to 500
secsy-ca ers generate signature.p7s -description "Q3 release CAdES-LT"

# Renew a record: time-stamp renewal (default) or hash-tree renewal to a stronger hash.
secsy-ca ers renew -id <record-id>
secsy-ca ers renew -id <record-id> -hashtree -hash sha512

# Verify a stored record (audit objects are re-derived from the log) or a
# standalone Evidence Record DER, optionally chaining the TSA certs to a root.
secsy-ca ers verify -id <record-id> -tsa-ca tsa-root.pem
secsy-ca ers verify -in record.der artifact.bin

# Export the DER, or inspect the structure.
secsy-ca ers export -id <record-id> -out record.der
secsy-ca ers list
```

`ers verify` exits non-zero when a record does not verify, so it drops into cron
/ CI. Add `-json` to any subcommand for machine-readable output.

## API

`POST /api/ers/verify` verifies a stored record (by `id`) or a standalone record
(base64 `record` + `objects`) end to end, returning the structured verdict. It is
read-gated (`audit:read`), a pure read (no HSM), and returns `200` when the
record verifies or `409` when it does not — a clean monitoring signal.
Certificate-path verification against TSA trust anchors is left to the CLI's
`-tsa-ca`.

## Verification

A record verifies when, for every embedded token: the CMS signature checks
against the TSA certificate it carries, the certificate has the time-stamping
EKU (and, with `-tsa-ca`, chains to a trust anchor at `genTime`), the reduced
hash tree recomputes to the token's imprint, consecutive timestamps in a chain
link (each covers the previous token), each protected object is provable in the
first timestamp of every chain (so coverage survives each algorithm transition),
and `genTime`s never run backwards.

## Observability

- **Metrics:** `secsy_ers_generated_total`, `secsy_ers_renewed_total{kind}`,
  `secsy_ers_cycle_errors_total`, `secsy_ers_cycle_duration_seconds`,
  `secsy_ers_records_total`, `secsy_ers_last_success_timestamp_seconds`, and the
  `secsy_ers_staleness_seconds` / `secsy_ers_records_pending_renewal` gauges.
- **Audit:** `ers.generate`, `ers.renew` (detail carries the renewal kind), and
  `ers.verify` events — themselves preserved by the next cycle.
- **Doctor:** `secsy-ca doctor` runs an `ers.freshness` check that fails when the
  last cycle errored and warns when the job has stalled past 3× its interval.

## Notes

- Evidence Records are public integrity proofs — they contain no private key
  material and no secret data — so they are safe to export and archive off-host.
- Renewal must run *before* an algorithm or certificate becomes untrustworthy;
  keep the job enabled and watch `ers.freshness`. The default 24-hour cadence and
  30-day lookahead leave a wide margin.
- See also: [Time-Stamping Authority](timestamping.md),
  [CAdES artifact signing](artifact-signing.md),
  [Audit log & SIEM export](audit-siem-export.md), [FIPS mode](fips.md).
```
