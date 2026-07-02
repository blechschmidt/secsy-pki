# Certificate expiry monitoring & automated renewal

The **expiry monitor** guards against the single most common PKI outage: a
certificate silently expiring in production. It periodically scans the issuing
authority's copy of every certificate it has minted, classifies each by how much
validity remains, warns operators through pluggable notification sinks, and can
optionally **auto-renew** eligible leaf certificates ahead of expiry through the
same HSM-backed issuance path used everywhere else (every renewal is signed on
the token).

It is exposed three ways, all sharing one implementation
(`server/internal/monitor`):

- a **background monitor** in the server (interval-driven, with notifications),
- a **CLI** (`secsy-ca expiring`, `secsy-ca monitor-run`), and
- an **API** (`GET /api/monitor/expiring`, `POST /api/monitor/scan`).

## Concepts

### Severity

Each non-revoked certificate is classified by its remaining validity against two
thresholds (in days):

| Severity | Condition | Default |
|----------|-----------|---------|
| `ok` | more than `warning_days` left | > 30d |
| `warning` | `critical_days` < remaining ≤ `warning_days` | ≤ 30d |
| `critical` | 0 < remaining ≤ `critical_days` | ≤ 7d |
| `expired` | `NotAfter` is in the past | — |

`critical_days` must not exceed `warning_days`.

### Superseded certificates

When a certificate is renewed, the original is left intact (renewal issues a new
serial). To avoid warning on — or repeatedly renewing — a credential that already
has a fresh replacement, the monitor marks the older certificate **superseded**
whenever another **non-revoked** certificate exists for the same identity
(same CA + subject + profile) with a later `NotAfter`. Superseded certificates
are excluded from warnings and from auto-renewal. This is also what prevents an
**auto-renewal storm**: once a near-expiry cert is renewed, the next scan sees it
as superseded and does not renew it again.

### Revocation safety

Revoked certificates are excluded from the scan entirely — they are never warned
on and never auto-renewed. (Renewal on the CA layer independently refuses a
revoked serial as defense-in-depth.)

### Auto-renewal eligibility

With auto-renew enabled, a certificate is renewed when **all** hold:

- its remaining validity is ≤ `renew_before_days`,
- it is not revoked and not superseded, and
- its profile is in `renew_profiles` (or `renew_profiles` is empty = all).

The reissued certificate uses the profile's **default** validity, so it is
long-lived and immediately drops back to `ok`. Renewal reuses the original public
key and subject/SANs (no CSR is required), so the subscriber keeps its key.

Each auto-renewal emits a `cert.auto_renew` audit event (actor `monitor`, or the
API caller's subject) and increments the `secsy_certificate_auto_renewals_total`
metric.

## Configuration

Add a `monitor:` block to `config.yaml`:

```yaml
monitor:
  enabled: true            # run the background monitor (default: false)
  interval_hours: 12       # scan cadence (default: 12)
  warning_days: 30         # default 30
  critical_days: 7         # default 7
  auto_renew: false        # reissue eligible leaves before expiry (default: false)
  renew_before_days: 7     # renew at/under this remaining validity (default: critical_days)
  renew_profiles: []       # restrict auto-renew to these profiles ([] = all)
  notifications:
    - type: log            # write warnings to the server log (always safe)
      min_severity: warning
    - type: webhook
      url: https://hooks.example.com/pki-expiry
      min_severity: critical      # warning | critical | expired
      timeout_seconds: 10
      headers:
        Authorization: "Bearer <token>"
```

`min_severity` filters which certificates a sink receives: `warning` sends
warning + critical + expired; `critical` sends critical + expired; `expired`
sends only already-expired certs. When no sinks are configured, a single `log`
sink at `warning` is installed so warnings are never silently dropped.

Two environment overrides help the SoftHSM/CI harness toggle the monitor without
editing YAML: `SECSY_MONITOR_ENABLED=1` and `SECSY_MONITOR_AUTO_RENEW=1`.

> **Auto-renew is opt-in and powerful.** It issues certificates unattended. Start
> with `auto_renew: false` and watch the warnings; enable it only once you trust
> the thresholds and profile allowlist.

### Webhook payload

A webhook receives a JSON POST (only when there is something to report):

```json
{
  "generated_at": "2026-07-02T05:21:31Z",
  "min_severity": "critical",
  "counts": {"warning": 4, "critical": 2, "expired": 0},
  "warnings": [
    {"ca_label":"Issuing CA","serial":"418412...","common_name":"api.example.com",
     "profile":"server","severity":"critical","expires_in":"3d",
     "not_after":"2026-07-05T00:00:00Z"}
  ],
  "renewed": [
    {"serial":"418412...","new_serial":"622118...","common_name":"api.example.com"}
  ]
}
```

## CLI

Build: `go build -tags sqlite -o secsy-ca ./cmd/secsy-ca`.

### List certificates by remaining validity

```console
$ secsy-ca expiring                       # all CAs, all severities
$ secsy-ca expiring -ca "Issuing CA"      # one CA
$ secsy-ca expiring -days 14              # only expiring within 14 days
$ secsy-ca expiring -severity critical    # only critical + expired
$ secsy-ca expiring -superseded           # include stale, superseded certs
$ secsy-ca expiring -json                 # machine-readable report
```

```
Expiry report (2026-07-02T05:21:31Z) — warning<=30d, critical<=7d
  ok=0 warning=0 critical=1 expired=0

SEVERITY  EXPIRES IN  SERIAL          CA          PROFILE  COMMON NAME    NOT AFTER
critical  23h         418412...       smoke-root  server   smoke.example  2026-07-03
```

Thresholds come from the `monitor:` config block, so the CLI, API, and background
monitor all agree.

### Run a scan on demand (optionally auto-renewing)

```console
$ secsy-ca monitor-run                    # scan + report only
$ secsy-ca monitor-run -auto-renew        # scan + reissue eligible leaves
$ secsy-ca monitor-run -ca "Issuing CA" -auto-renew -json
```

```
Scan complete (2026-07-02T05:21:31Z): ok=0 warning=0 critical=1 expired=0
Auto-renew: 1 renewed, 0 failed
  renewed 418412... -> 622118... (CN="smoke.example")
```

`monitor-run -auto-renew` is a good fit for an ops cron job if you prefer not to
run the in-server background monitor.

## API

| Method & path | Auth | Purpose |
|---------------|------|---------|
| `GET /api/monitor/expiring` | any role (read) | List certs by remaining validity |
| `POST /api/monitor/scan` | read (plain) / **issue** (auto-renew) | Run a scan, optionally auto-renewing |

`GET /api/monitor/expiring` query parameters: `ca=<id>`, `days=<n>`,
`severity=warning|critical|expired`, `include_superseded=true`.

`POST /api/monitor/scan` body: `{"ca_id":"<id>","auto_renew":true}`. Requesting
`auto_renew` requires the org-wide **issue** capability (admin or issuer role),
because it reissues certificates on the HSM; a plain scan only needs read access.

```console
$ curl -sk -u root:$PW "https://pki:8443/api/monitor/expiring?days=14&severity=critical"
$ curl -sk -u root:$PW -H 'Content-Type: application/json' \
    -d '{"auto_renew":true}' https://pki:8443/api/monitor/scan
```

## Metrics

The monitor refreshes these on every scan (see the
[observability guide](observability.md)):

| Metric | Type | Meaning |
|--------|------|---------|
| `secsy_certificates_expiring{severity}` | gauge | Certs in each window as of the last scan (`warning`/`critical`/`expired`) |
| `secsy_certificate_auto_renewals_total{result}` | counter | Auto-renewals by outcome (`success`/`error`) |
| `secsy_certificate_monitor_scans_total{result}` | counter | Scan cycles |
| `secsy_certificate_monitor_last_scan_timestamp_seconds` | gauge | Unix time of the last completed scan |

Suggested alerts:

- `secsy_certificates_expiring{severity="critical"} > 0` — a cert is about to
  expire and (if auto-renew is off) needs manual attention.
- `increase(secsy_certificate_auto_renewals_total{result="error"}[1h]) > 0` —
  auto-renewal is failing (HSM unreachable, CA expiring, profile removed).
- `time() - secsy_certificate_monitor_last_scan_timestamp_seconds > 2*interval` —
  the monitor has stopped running.

## Operational runbook

### Enable monitoring (recommended first step)

1. Add a `monitor:` block with `enabled: true`, sensible thresholds, and at least
   a `log` sink. Leave `auto_renew: false`.
2. Restart the server. On boot it logs
   `cert-expiry monitor started (interval=…, auto_renew=false)` and runs an
   immediate scan.
3. Scrape `secsy_certificates_expiring` and add the critical alert above.

### Turn on auto-renewal

1. Decide which profiles are safe to renew unattended and set `renew_profiles`
   (e.g. `["server"]`). Leaf profiles are the intended target; do not expect CA
   certs to be auto-renewed — the monitor renews previously-issued leaves.
2. Set `renew_before_days` comfortably above your deployment/rollout window (a
   cert renewed at ≤ `renew_before_days` still needs to be *deployed* before the
   old one expires).
3. Set `auto_renew: true` and restart. Watch
   `secsy_certificate_auto_renewals_total` and the `cert.auto_renew` audit events
   (`GET /api/events?action=cert.auto_renew`).
4. **Deploy the renewed material.** Auto-renewal reissues on the CA; it does not
   push certificates to subscribers. Fetch renewed certs via
   `GET /api/ca/{id}/certificates` (or use ACME for fully automated deployment).

### "A certificate expired anyway"

- Confirm the monitor is running: check the boot log line and
  `secsy_certificate_monitor_last_scan_timestamp_seconds`.
- Confirm the cert was not **superseded** (a newer reissue already exists — the
  identity is covered; only the old serial expired). `secsy-ca expiring
  -superseded` shows superseded entries.
- If auto-renew was expected: check `secsy_certificate_auto_renewals_total{result="error"}`
  and the error `cert.auto_renew` audit events for the cause (revoked, profile
  removed, CA itself expiring, HSM unreachable).

### Auto-renewal is failing

Inspect the error detail on the `cert.auto_renew` / `ResultError` audit events:

- *revoked* — expected; revoked certs are never renewed. Issue a fresh cert.
- *profile not found* — the profile was removed/renamed; restore it or exclude it
  from `renew_profiles`.
- *validity clamped to CA expiry* — the **issuing CA** is close to expiry; renew
  the CA (see the [CA guide](certificate-authority.md)) before its leaves.
- *HSM / signer errors* — check `/readyz` and the
  [HSM configuration](hsm-configuration.md) guide.

### Renewal storms

By design a certificate is renewed at most once: after renewal the old serial is
superseded. If you see repeated renewals of the same identity, it usually means
the reissued certificate itself is short-lived (its validity is being clamped by
a near-expiry issuing CA). Renew the CA first.

## Testing

The monitor logic is covered by unit tests
(`server/internal/monitor/monitor_test.go`, no HSM required) and by a SoftHSM
integration test (`server/internal/e2e/monitor_test.go`, build tag `sqlite`) that
exercises near-expiry detection, HSM-backed auto-renewal with chain verification
and audit-event assertions, storm prevention, and revocation safety. Run the HSM
test with the shared harness:

```console
eval "$(scripts/setup-softhsm.sh --export-env)"   # or set SECSY_PKCS11_MODULE/SECSY_TOKEN_LABEL/SECSY_USER_PIN
go test -tags sqlite -p 1 -run TestExpiryMonitorAndAutoRenew ./internal/e2e/
```
