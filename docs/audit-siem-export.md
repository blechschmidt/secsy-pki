# Audit log export to SIEM

secsy-pki can stream its tamper-evident audit event log (see
[RBAC, audit logging & config](rbac-and-audit.md)) to external Security
Information and Event Management (SIEM) systems, and provides CLI tools to
verify the hash chain and export it for offline batch delivery (Task 23).

There are three ways to get audit events out of the system:

| Mechanism | Transport | Use case |
|-----------|-----------|----------|
| **Streaming export** | RFC 5424 syslog (TCP/TLS), CEF, NDJSON webhook | Continuous, near-real-time forwarding to a SOC/SIEM |
| **`audit export` CLI** | A file / stdout in any format | Scheduled batch jobs, air-gapped transfer, back-fill |
| **`audit verify` CLI** | — | Independent tamper detection over the whole chain |

Every mechanism reads the same append-only, hash-chained `event_log`. Nothing
here mutates the log.

## Streaming export

When `audit.export.enabled` is true, the server starts one background worker per
configured sink. Each worker streams events forward from a **durable per-sink
cursor** and only advances that cursor after the sink acknowledges a batch.

### Delivery guarantees

- **At-least-once, lossless across restarts.** The cursor is persisted (in the
  `siem_export_cursor` table) only after a successful delivery. If the process
  crashes between delivery and cursor commit, the batch is redelivered on
  restart — never dropped. Downstreams should treat records as idempotent
  (dedup on the event `id` / `seq`, both of which are exported).
- **Backpressure.** Each worker reads at most `batch_size` events per iteration,
  so a slow or down sink can never accumulate an unbounded in-flight set, and a
  large backlog is drained in bounded chunks.
- **Independent sinks.** A failing sink retries with exponential backoff
  (`retry_backoff_seconds` doubling up to `max_backoff_seconds`) without
  advancing its cursor, and never blocks or stalls a healthy sink — each has its
  own worker and cursor.

### Formats

| Format | Value | Notes |
|--------|-------|-------|
| RFC 5424 syslog | `rfc5424` | Fields carried in a `[secsyAudit@<PEN> …]` STRUCTURED-DATA element; severity derives from the result (`success`→info, `denied`→warning, `error`→error). |
| ArcSight CEF | `cef` | `CEF:0|secsy|secsy-pki|<ver>|<action>|<action>|<sev>|<ext>`; standard keys (`rt`, `suser`, `act`, `outcome`, `src`) plus `cs*`/`cn1` for target, hashes, and `seq`. |
| Newline-delimited JSON | `json` | The full `audit.Event` object per line, **including `prev_hash`/`hash`**, so a downstream can re-verify chain integrity. Webhook only. |

### Transports

- **syslog** over `tcp` (cleartext) or `tls`. TLS supports a custom CA bundle,
  SNI/server-name override, and mutual TLS (client cert). Stream framing is
  RFC 6587 **octet-counting** by default (unambiguous even with embedded
  newlines) or trailing-**lf** for collectors that require it.
- **webhook**: each batch is POSTed as `application/x-ndjson` (one record per
  line); custom headers (e.g. `Authorization`) are forwarded. Delivery is
  acknowledged only on a `2xx` response.

### Configuration

```yaml
audit:
  export:
    enabled: true
    poll_interval_seconds: 5   # how often a caught-up worker re-checks
    batch_size: 256            # backpressure knob (events per delivery)
    retry_backoff_seconds: 1
    max_backoff_seconds: 30
    sinks:
      - name: soc-syslog       # unique & stable — it keys the durable cursor
        type: syslog
        format: rfc5424
        network: tls
        address: siem.example.com:6514
        framing: octet-counting
        tls:
          ca_file: /etc/secsy/siem-ca.pem
          # server_name: siem.example.com
          # client_cert_file: /etc/secsy/siem-client.pem   # mutual TLS
          # client_key_file:  /etc/secsy/siem-client.key
      - name: soc-webhook
        type: webhook
        format: json
        url: https://collector.example.com/ingest
        headers:
          Authorization: "Bearer <token>"
```

> **Sink names are load-bearing.** A sink's `name` keys both its durable cursor
> and its metrics. Renaming a sink resets its cursor (it re-exports from the
> genesis); keep names stable.

### Metrics

The exporter publishes these Prometheus series (see
[observability](observability.md)), all labelled by `sink`:

| Metric | Meaning |
|--------|---------|
| `secsy_audit_export_lag_events` | Events sealed but not yet delivered (head seq − cursor). **Primary alert signal.** |
| `secsy_audit_export_cursor_seq` | Highest sequence number durably delivered. |
| `secsy_audit_export_events_total{result}` | Events delivered / failed. |
| `secsy_audit_export_batch_failures_total` | Failed delivery attempts (retried). |
| `secsy_audit_export_last_success_timestamp_seconds` | Wall-clock of the last acknowledged batch. |

Example alert — a sink falling behind or stalled:

```promql
max by (sink) (secsy_audit_export_lag_events) > 1000
  or (time() - max by (sink) (secsy_audit_export_last_success_timestamp_seconds)) > 900
```

## CLI: `secsy-ca audit verify`

Re-walks the entire hash chain from the genesis and reports the **first broken
link**, detecting content tampering, hash forgery, deletion, reordering, and
head deletion. Exits non-zero on any break, so it drops into cron/monitoring
cleanly.

```console
$ secsy-ca audit verify
audit chain OK: 12048 event(s) verified, hash chain intact.

$ secsy-ca audit verify           # after a row was tampered with
audit chain BROKEN at seq 5177: content hash mismatch (entry was modified)
verified 5176 event(s) before the break.
$ echo $?
1
```

`-json` emits the machine-readable `VerifyResult` for pipelines.

This complements the online `GET /api/events/verify` endpoint: the CLI needs
only the database (not the HSM or a running server), so an auditor can run it
independently and out-of-band.

## CLI: `secsy-ca audit export`

Batch-exports events over a time range for offline delivery to a SIEM — a
scheduled shipper, an air-gapped export, or a back-fill after a sink outage.

```console
# Everything, as NDJSON, to a file:
$ secsy-ca audit export -out audit.ndjson

# A single day, in CEF, to stdout:
$ secsy-ca audit export -from 2026-07-01T00:00:00Z -to 2026-07-02T00:00:00Z \
      -format cef

# RFC 5424 syslog records:
$ secsy-ca audit export -format rfc5424 -out audit.log
```

Records are written one per line using the **same formatters** as the streaming
exporter, so offline and streaming output are byte-compatible.

## See also

- [RBAC, audit logging & config](rbac-and-audit.md) — the event log and its
  hash-chain design.
- [Observability](observability.md) — the metrics endpoint the export series are
  published on.
