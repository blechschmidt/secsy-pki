# Scheduled encrypted backups

Backup and restore (the [key ceremony & DR](key-ceremony.md) tooling) and the
[full-stack DR drill](../scripts/dr-drill-full.sh) are *manual* procedures. Task
89 closes the loop with a **leader-elected background job** that produces the
disaster-recovery backup artifact on a schedule, encrypts it with the
HSM-backed [secret/envelope layer](password-encryption.md), and writes it to a
durable destination with retention — so a deployment always has a recent,
restorable, off-box copy without an operator remembering to run anything.

It is built entirely from existing subsystems:

- the **backup artifact** extends the Task 16 backup bundle;
- **leadership** is the Task 68 [advisory-lock elector](high-availability.md);
- **encryption** is the Task 7 envelope layer (AES-256-GCM DEK wrapped under the
  RSA KEK held on the HSM);
- the **destination** reuses the Task 58 [publish sinks](ocsp-presign-publish.md)
  (local directory / S3-compatible object store) with their atomic swap and
  integrity manifest.

## What is in a backup

Each run produces one artifact: an uncompressed **tar**, then sealed into a
secret-layer envelope so the destination only ever holds ciphertext. The tar
contains:

| Member | Contents |
| --- | --- |
| `manifest.json` | Self-describing manifest: driver, KEK label/version, the audit-chain head (seq + hash), the Task 52 store **fingerprint** (monotonic serial/CRL counters, issued/revoked counts), CA summaries, and a SHA-256 of every other member |
| `cas.json` | The full CA records — public CA material (certificates, key labels, public keys). **Never** private keys |
| `events.json` | The complete hash-chained audit log, ascending by sequence |
| `config.yaml` | The running configuration (optional; `backup.include_config`) |
| `metadata.db` **or** `postgres.sql` | The authoritative store: an online SQLite `VACUUM INTO` snapshot, or a `pg_dump` logical dump for PostgreSQL |

Private keys are **never** included — the HSM token blobs (still
non-extractable) are backed up separately with the token's own tooling; see
[key ceremony & DR](key-ceremony.md). The artifact restores independently of the
HSM: the store fingerprint proves no committed state was lost or rewound.

Alongside the encrypted artifact the job writes a small **plaintext** outer
manifest (at the sink's `manifest.json`) carrying only coarse metadata — created
time, driver, artifact digest/size, audit head, counts — for freshness
monitoring **without** revealing CA identities, which live only inside the
ciphertext.

## Configuration

```yaml
backup:
  enabled: true
  schedule:
    interval_hours: 24        # default 24; one backup runs immediately on
                              # leadership gain, then every interval
  kek_label: ""               # KEK to encrypt under; empty inherits secret.kek_label
  include_config: true        # bundle the running config into the artifact
  retention:
    keep: 7                   # keep the N most-recent backups
    max_age_days: 30          # also delete backups older than this (0 = no age limit)
  dir:
    path: /var/lib/secsy-pki/backups
  s3:                         # set s3.bucket to use S3 instead of dir
    bucket: ""
    region: us-east-1
    endpoint: ""              # e.g. http://minio:9000 for S3-compatible stores
    prefix: secsy-backups
  verify:                     # automated restore-verification drill (Task 94)
    enabled: false            # opt-in: PG path needs psql + CREATE/DROP scratch DB
    interval_hours: 0         # 0 = same cadence as the backup schedule
```

A KEK is **required** when backups are enabled (a backup that could not be
encrypted defeats the purpose): set `backup.kek_label`, or rely on the
deployment-wide `secret.kek_label`. The KEK must be an RSA key on the configured
key provider (see [password encryption](password-encryption.md) for
provisioning).

### Retention

- **Directory backend** — each backup is a timestamped snapshot; the job keeps
  the newest `keep` and deletes any others older than `max_age_days`. The most
  recent backup is **always** retained, even past `max_age_days`, so there is
  never zero restorable copies. `<dir>/current` points at the latest.
- **S3 backend** — the object store overwrites fixed keys, so it holds only the
  **latest** backup. Historical keep-N / max-age retention is delegated to S3
  **bucket versioning + lifecycle policies** (the object-store-native mechanism).
  The server logs this once at startup so the bounded coverage is never silent.

## Guarantees

- **Never blocks issuance.** The job only reads the store and takes an online
  snapshot (SQLite `VACUUM INTO`, which takes a shared read lock) or a `pg_dump`
  on its own MVCC-consistent connection. The HSM is touched only briefly to bind
  the KEK ring; sealing wraps the DEK against the KEK *public* key with no HSM
  round-trip.
- **No-op on non-leaders.** The loop is registered on the leader elector, so on
  a multi-replica deployment exactly one replica backs up at a time. A handover
  is idempotent — the new leader's first backup supersedes the old leader's last.
- **Tamper-evident restore.** Every archive member is checksummed in the
  manifest; `OpenArchive` rejects a mismatch. A restored store's fingerprint is
  compared against the manifest and the source to prove fidelity.

## Observability

Metrics (Prometheus):

| Metric | Meaning |
| --- | --- |
| `secsy_backup_runs_total{result}` | Completed runs by result (`success`/`error`) |
| `secsy_backup_duration_seconds` | Run duration histogram |
| `secsy_backup_last_success_timestamp_seconds` | Unix time of the last success |
| `secsy_backup_staleness_seconds` | Seconds since the last success (absent until the first — alert on its **existence** and value) |
| `secsy_backup_artifact_bytes` | Size of the most recent encrypted artifact |
| `secsy_backup_retained_snapshots` | Backups retained after the last retention pass |
| `secsy_backup_verify_total{result}` | Restore-verification drills by result (`success`/`error`) |
| `secsy_backup_verify_duration_seconds` | Restore-verification drill duration histogram |
| `secsy_backup_verify_last_success_timestamp_seconds` | Unix time of the last verified restore |
| `secsy_backup_restore_verified_staleness_seconds` | Seconds since a backup was last proven restorable (absent until the first — alert on its **existence** and value) |

Audit: each cycle appends one `backup.run` event (actor `backup`, `system`
role) recording the backend, driver, artifact size, retained count — or the
failure; each restore-verification drill appends one `backup.verify` event
(actor `backup-verify`) recording the driver, integrity result, and
fingerprint-match — or the stage it failed at. Both are part of the same
hash-chained, tamper-evident log.

Doctor: `secsy-ca doctor` runs a **`backup.freshness`** check that reads the
newest `backup.run` event offline and **fails** when the last run errored or the
last successful backup is older than `retention.max_age_days` (a real data-loss
window), **warns** when the job is stalled (enabled but silent beyond three
intervals), and passes with the last-success age otherwise. A companion
**`backup.restore-verified`** check applies the same logic to the newest
`backup.verify` event — it fails when a backup could not be proven restorable
(or the last proof is older than the retention window, so nothing current is
verified) and warns when verification is stalled.

## Restore-verification (an untested backup is not a backup)

Producing artifacts is only half the loop: nothing proves those artifacts can
actually be restored until someone tries. Task 94 adds an automated
**restore-verification drill** — a second leader-elected background job (and the
`secsy-ca backup verify-restore` CLI) that periodically:

1. pulls the newest artifact from the backup destination and checks it against
   the published outer-manifest digest;
2. decrypts it via the secret-envelope layer (binding the same KEK) and opens
   the archive, re-checksumming every member;
3. restores the DB dump into an **isolated scratch database** — a SQLite temp
   file, or a throwaway PostgreSQL database created on the configured server and
   **always dropped** afterward (`DROP DATABASE … WITH (FORCE)`), never touching
   the live store;
4. runs the HSM-independent integrity gate (the same `secsy-ca db verify`
   invariants) against the restored store;
5. confirms the restored **audit-head fingerprint** matches the artifact
   manifest.

A failure at any stage means disaster recovery would silently fail, so it is
**metered** (`secsy_backup_verify_total{result="error"}`), **audited**
(`backup.verify`), and **alerted** through the same
[monitor notification sinks](certificate-monitoring.md) the expiry monitor uses
(critical severity). Success resets the restore-verified staleness gauge. The
drill is off by default (`backup.verify.enabled`) because the PostgreSQL path
needs `psql` on `PATH` and permission to create/drop a scratch database.

Run it on demand any time — as a DR drill, a cron job, or a CI step:

```console
$ secsy-ca backup verify-restore
Restore-verification of the sqlite backup on dir:
  artifact:      backup.tar.enc (740728 bytes, sha256 5fc962e1097…)
  ✓ audit_chain             …
  ✓ serial_monotonicity     …
  restored head: 6d60b1a792d1…
  manifest head: 6d60b1a792d1…

Backup restore-verification OK: the newest backup decrypts, restores into a
scratch database, passes the integrity gate, and its audit head matches the
manifest.
```

It exits non-zero if the backup could not be proven restorable (or none is
published yet), so a pipeline can trip on it. Add `-json` for machine output.

## Restore

A backup restores with the standard DR procedure. Fetch the encrypted artifact
from the destination (`<dir>/current/backup.tar.enc`, or the S3 key), decrypt it
with the same KEK, and unpack:

- **SQLite** — write `metadata.db` out and open it as the store; run
  `secsy-ca db verify` and compare its fingerprint to the manifest.
- **PostgreSQL** — restore `postgres.sql` with `psql`/`pg_restore` into a fresh
  database, then `secsy-ca db verify`.

The bundled `config.yaml`, `cas.json`, and `events.json` provide the running
configuration and an engine-agnostic fallback. Then restore the **HSM token
state** separately and confirm the keys with `secsy-ca restore` / the
[DR runbook](key-ceremony.md). The `internal/backup` package exposes
`Decrypt` → `OpenArchive` → `RestoreSQLite` for programmatic restore and a
`Verifier` that automates the whole round-trip (fetch → decrypt → restore into a
scratch DB → integrity gate → fingerprint match), both exercised end-to-end by
`internal/backup` tests (produce a scheduled backup, then verify it restores to a
fingerprint-matching store — for SQLite hermetically, and for PostgreSQL against
a real server when `SECSY_TEST_PG_DSN` is set).
