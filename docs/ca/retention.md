# Certificate-inventory retention & archival

A high-volume CA — short-lived [ACME STAR](../protocols/acme.md) certificates, automated
ACME/EST issuance — grows the `issued_certificates` table without bound. Task 157
adds a **leader-elected background job** that safely ages out old rows under an
explicit, fail-safe policy, so the operational inventory stays bounded without an
operator remembering to prune anything.

It is built from existing subsystems:

- **leadership** is the Task 68 [advisory-lock elector](../deployment/high-availability.md) — a
  singleton, so replicas never race each other's archive/prune transactions;
- **freshness** surfaces through the [tamper-evident audit log](../security/audit-siem-export.md)
  and the `secsy-ca doctor` `retention.freshness` check;
- **observability** is the Task 14 Prometheus registry.

The job never touches the HSM: it operates only on already-terminal store rows.

## The fail-safe policy

A row in `issued_certificates` is **eligible** only when **all** of:

1. its `not_after` passed more than `retention.min_age_days` ago (long expired,
   past a grace window); **and**
2. it is not on hold (`status != 'held'` — a hold is reversible, so the row is
   not terminal); **and**
3. no open (pending/approved) four-eyes [approval](../security/approvals.md) pins its serial.

Condition (1) alone is what makes the job safe. A certificate that is **still
valid** or **revoked but not yet expired** has a `not_after` in the *future*, so
it is never selected — these are exactly the rows the OCSP responder and CRL
generator depend on. The job also **never reads or writes the authoritative
`revoked_certificates` table**, so revocation status is entirely independent of
inventory retention.

> **Why OCSP/CRL for retained serials is unaffected.** OCSP resolves a serial by
> consulting `revoked_certificates` first (→ *revoked*) and `issued_certificates`
> second (→ *good*); CRL generation reads only `revoked_certificates`. A retained
> serial's `issued_certificates` row is untouched and the revocation table is
> never modified, so both reads return byte-identical results before and after a
> run. Even a serial that *is* aged out but was revoked keeps its
> `revoked_certificates` row, so it still resolves *revoked* / stays on the CRL.
> (An aged-out serial that was never revoked is, by definition, long expired —
> relying parties reject it on expiry grounds, and an OCSP *unknown* for an
> expired serial is standard.)

## Modes

| Mode | Effect |
| --- | --- |
| `archive` (default) | **Moves** eligible rows into the `issued_certificates_archive` table in one transaction — the archive `INSERT` commits before the source `DELETE`, so a row never leaves the hot table without its archive copy. Nothing is lost; the hot table shrinks and stays fast. |
| `prune` | Archives (as above — the durable "successful archive"), then **hard-deletes** archive rows whose `not_after` passed more than `prune_after_days` ago. With `prune_after_days: 0` that window equals `min_age_days`, so eligible rows are deleted as soon as they are archived — "delete after successful archive". A larger `prune_after_days` keeps archived rows queryable in cold storage for longer before deletion. |

Everything runs in bounded batches (`retention.batch_size`, default 500 rows per
transaction) so the job is online-safe on a large inventory.

## Audit-chain continuity

Every run appends one `inventory.retention` event to the hash-chained audit log,
recording the mode, the archived/pruned counts, the eligibility window, the
remaining backlog, and a **manifest digest** — a streaming SHA-256 over the
`ca_id · serial · not_after · status` of every archived/pruned certificate. The
tamper-evident log is therefore a durable, verifiable record of *exactly which
certificates left the hot inventory*, even after a prune removes the rows.

## Configuration

```yaml
retention:
  enabled: false          # start the leader-elected loop (CLI works regardless)
  mode: "archive"         # archive | prune
  min_age_days: 90        # grace window past not_after before a row is eligible
  prune_after_days: 0     # prune mode: hard-delete archive rows past this window
                          # (0 => min_age_days; values below it are clamped up)
  schedule:
    interval_hours: 24    # one run on leadership gain, then every interval
  batch_size: 500         # rows per transaction
```

The window getters are deliberately conservative: an unset or non-positive
`min_age_days` defaults to **90 days**, never zero — retention must never be
aggressive by accident.

## CLI

The `secsy-ca inventory retention` commands read and write only the store (no
HSM), so they run during an HSM outage and obey the identical policy the
background loop uses:

```console
# What would a run do right now? (no mutation)
$ secsy-ca inventory retention dry-run
DRY RUN — no rows were modified.
Mode:              archive
Grace window:      90d (eligible: not_after before 2026-05-02T00:00:00Z)
Eligible:          14231
Would archive:     14231
Backlog remaining: 14231
Archive size:      0
Manifest digest:   sha256:…

# Execute one pass (records an inventory.retention audit event).
$ secsy-ca inventory retention run

# Current policy + how much is eligible/prunable + the newest recorded run.
$ secsy-ca inventory retention status
```

All three accept `-json`.

## Observability

| Metric | Meaning |
| --- | --- |
| `secsy_inventory_retention_runs_total{result}` | Completed runs, by `success`/`error` |
| `secsy_inventory_retention_duration_seconds` | Run duration histogram |
| `secsy_inventory_retention_archived_total` | Cumulative rows moved to the archive |
| `secsy_inventory_retention_pruned_total` | Cumulative rows hard-deleted (prune mode) |
| `secsy_inventory_retention_archive_size` | Archive table size after the last run |
| `secsy_inventory_retention_last_run_timestamp_seconds` | Unix time of the last successful run |
| `secsy_inventory_retention_staleness_seconds` | Seconds since the last successful run (FuncGauge; absent until the first run) |
| `secsy_inventory_retention_backlog` | Eligible rows still awaiting processing after the last run (FuncGauge; should trend to zero) |

`secsy-ca doctor` adds a `retention.freshness` check: it FAILs when the newest
run errored, WARNs when the loop is enabled but silent or stalled beyond three
intervals, and otherwise reports the last-run age — reading the audit log, so it
works out-of-process without the HSM.
