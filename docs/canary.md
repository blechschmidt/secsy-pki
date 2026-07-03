# Synthetic issuance canary

The issuance canary is an opt-in, end-to-end self-test loop that continuously
proves the certificate issuance and revocation path works — before a real
client discovers it doesn't. Each interval, for every configured CA, the
canary walks a real (but synthetic) certificate through its entire lifecycle
and measures every stage:

| Stage | What it proves |
|---|---|
| `resolve` | The configured CA reference (id or label) exists |
| `issue` | HSM-signed issuance works end to end: tenant lifecycle/quota gate, the fail-closed pre-issuance lint gate, serial allocation, signing on the token, and the store record |
| `chain` | The fresh leaf verifies against the CA's full chain bundle (rotation-overlap siblings and externally signed parents included) |
| `ocsp_good` | The OCSP responder returns a correctly signed, fresh `good` answer for the new serial |
| `crl` | The serial's CRL scope (sharding-aware) is signed by the issuer, fresh (`thisUpdate`/`nextUpdate` bracket now), and does not list the serial |
| `revoke` | Revocation of the probe certificate is accepted and newly applied |
| `ocsp_revoked` | "Revoked" propagates: the revocation store has the entry and OCSP now answers `revoked` |

The probe deliberately uses the ordinary issuance path — the same
`ca.Manager` entry points the API, ACME, and CLI use — so what the canary
proves is exactly what a real caller would experience. That includes the
tenant quota gate: canary certificates consume the probed CA's tenant quota
(one issuance per probe), which is intentional — if quota exhaustion would
break real issuance, the canary should turn red too.

If a stage after issuance fails, the prober best-effort revokes the orphaned
probe certificate on a fresh context (revocation is a store write and works
even during an HSM outage). Probe certificates are short-lived (1 hour by
default) regardless, so nothing valuable lingers.

## Configuration

```yaml
canary:
  enabled: true
  interval_minutes: 15      # default 15; each probe costs a few HSM signatures
  timeout_seconds: 60       # per-CA probe budget; must be < interval
  cas: [issuing-ca]         # required: CAs to probe, by id or label
  profile: canary           # default; must be a classical (non-PQC) profile
monitor:
  notifications:            # canary failures ride these same sinks
    - type: webhook
      url: https://alerts.example.com/hook
      min_severity: critical
```

- **CAs must be listed explicitly** — probing issues (and revokes) real
  certificates, so opting a CA in is a deliberate choice. References follow
  key-rotation lineage: a rotated CA's probe automatically targets its active
  successor.
- The built-in **`canary` profile** is non-public (internal names lint
  cleanly), pinned to lint **enforce** mode (every probe also proves the
  fail-closed lint gate), `clientAuth`/`digitalSignature` only, and
  short-lived (1h default / 24h max). A custom profile can be substituted via
  `canary.profile`.
- Probes run as the leader-elected `issuance-canary` background job — with
  multiple replicas, exactly one probes at a time.

## Canary marker

Probe certificates are stamped with the `canary` marker
(`issued_certificates.marker`). The marker keeps synthetic artifacts out of
operational reporting:

- The **expiry monitor** never warns on or auto-renews marked certificates —
  without this, every probe would land in the critical/expired buckets and
  the renewal storm logic would reissue expired probes forever.
- **Inventory and compliance reports** exclude marked certificates by default
  (`Filter.IncludeSynthetic` opts them back in).

Revocation-side artifacts (CRL entries, OCSP `revoked` answers) are *not*
filtered: the probe serials are real revocations and relying parties must be
able to see them.

## Observability

Metrics (all labeled by CA label; stage-labeled where noted):

| Metric | Meaning |
|---|---|
| `secsy_canary_last_success_timestamp_seconds{ca}` | Last fully successful probe per CA (absent until the first success) — the primary alert signal |
| `secsy_canary_failures_total{ca,stage}` | Probe failures, by the lifecycle stage that broke |
| `secsy_canary_probes_total{ca,result}` | All probes, by result (`success`/`error`) |
| `secsy_canary_stage_duration_seconds{stage}` | Histogram of per-stage latency — issue/OCSP stages ride the HSM signing path, so a creeping p95 is early warning of HSM latency |

Alerts (`deploy/observability/prometheus/secsy-pki-rules.yaml`):

| Alert | Fires when | Severity |
|---|---|---|
| `SecsyPKICanaryFailing` | any probe failures in 15m, sustained 5m | critical — the issuance path is broken for real clients too |
| `SecsyPKICanaryStalled` | no successful probe in >1h (4× default interval) | warning — adjust if `interval_minutes` differs |

The Grafana dashboard (`deploy/observability/grafana/`) has an **Issuance
canary** row: last-success age per CA, probe/failure rates by stage, and
stage-duration p95.

Failures are also:

- dispatched through the **expiry monitor's notification sinks** (log +
  webhook, `monitor.notifications`) as `canary_failures` payloads — a log
  sink is always installed, so failures are never silently dropped;
- recorded as **`canary.probe` audit events** (actor `canary`, target = the
  probed CA, detail = serial + per-stage timings + failed stage).

## Doctor

`secsy-ca doctor` includes a `canary.last_probe` check that reads the newest
`canary.probe` audit event per probed CA — usable offline, without scraping
metrics:

- **fail** — any CA's newest probe errored (detail carries the failed stage);
- **warn** — canary enabled but never ran, or the last success is older than
  3× the configured interval (stalled);
- **pass/skip** — fresh successes everywhere / canary disabled.

## Testing

`server/internal/canary` is exercised against both the software keystore and
SoftHSM (`go test -tags sqlite ./internal/canary/` with the
`setup-softhsm.sh` environment), including failure injection via the
gated-provider pattern: a simulated HSM outage must fail the probe at the
`issue` stage and alert, an outage *mid-probe* must still revoke the orphaned
probe certificate, and recovery must turn the canary green again.
