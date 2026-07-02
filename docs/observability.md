# Observability — metrics, health checks, and structured logging

The enterprise server exposes production observability so you can monitor
certificate issuance, HSM health, and request behavior, and wire it into
Prometheus / Grafana and a Kubernetes (or load-balancer) health-check setup.

Three things are provided:

1. A Prometheus **`/metrics`** endpoint (text exposition format).
2. **`/healthz`** (liveness) and **`/readyz`** (readiness, including an HSM
   connectivity probe) endpoints.
3. **Structured JSON request logging** with a per-request correlation ID that is
   also stored on the access log and the tamper-evident audit events.

All three are always on — there is nothing to enable in `config.yaml`.

---

## Endpoints

| Path | Auth | Purpose |
|------|------|---------|
| `GET /metrics` | none | Prometheus metrics in text exposition format |
| `GET /healthz` | none | Liveness: the process is up and serving HTTP |
| `GET /readyz` | none | Readiness: DB reachable **and** HSM/key-provider reachable |

These endpoints are **unauthenticated by design**: monitoring systems scrape them
before any user context exists, and they expose no secrets, key material, or
per-subject data. If your threat model requires it, restrict them at the network
layer (e.g. only allow your Prometheus/kubelet source ranges to reach
`/metrics`, `/readyz`), since the server is expected to sit behind a
TLS-terminating proxy anyway.

### Liveness vs readiness

- **`/healthz`** returns `200` as long as the process can serve HTTP. It does
  **not** check the database or HSM, so a transient dependency outage does not
  cause an orchestrator to kill an otherwise-healthy process.
- **`/readyz`** returns `200` only when every checked dependency is healthy,
  otherwise `503`. Use it to gate traffic (readiness probe / load-balancer
  health check) so an instance that cannot issue certificates stops receiving
  requests.

`/readyz` response body (healthy):

```json
{
  "status": "ready",
  "components": {
    "database": { "status": "up" },
    "hsm": { "status": "up" }
  }
}
```

When a dependency is down the overall `status` becomes `not_ready`, the HTTP
status is `503`, and the failing component carries an `error`:

```json
{
  "status": "not_ready",
  "components": {
    "database": { "status": "up" },
    "hsm": { "status": "down", "error": "logging in: pkcs11: 0xA0: CKR_PIN_INCORRECT" }
  }
}
```

The **HSM probe goes through the key-provider** (`keyprovider.Prober`): for the
PKCS#11 backend it loads the module, finds the configured token, opens a session,
and logs in with the user PIN — the exact steps a signing operation performs,
minus the key lookup. A healthy result therefore means the HSM can sign *right
now*. The software backend reports up when its keystore directory is accessible.
A provider with no probe capability is reported as `skipped` and does not fail
readiness.

The probe is bounded by a short timeout (3 s) so a hung backend cannot stall the
health check.

---

## Metrics

`/metrics` is the standard Prometheus text format. All series are prefixed
`secsy_`. Labels are kept low-cardinality (the HTTP route label is the **matched
route pattern**, e.g. `GET /api/ca/{id}/issue`, never the raw path with its
embedded IDs/serials).

| Metric | Type | Labels | Meaning |
|--------|------|--------|---------|
| `secsy_http_requests_total` | counter | `method`, `route`, `status` | HTTP requests handled |
| `secsy_http_request_duration_seconds` | histogram | `method`, `route` | HTTP request latency |
| `secsy_http_requests_in_flight` | gauge | — | Requests currently being served |
| `secsy_certificates_total` | counter | `operation` (`issue`/`renew`/`revoke`), `result` (`success`/`error`/`denied`) | Certificate lifecycle operations |
| `secsy_ocsp_requests_total` | counter | `result` (`success`/`error`/`malformed`) | OCSP responder requests |
| `secsy_crl_requests_total` | counter | `result` | CRL distribution requests |
| `secsy_hsm_operations_total` | counter | `operation` (`sign`/`decrypt`/`generate`/`find`/`public_key`/`ping`), `result` | Key-provider operations |
| `secsy_hsm_operation_duration_seconds` | histogram | `operation` | Key-provider (HSM) operation latency |
| `secsy_envelope_operations_total` | counter | `operation` (`encrypt`/`decrypt`), `result` | HSM-backed envelope encryption operations |
| `secsy_authz_decisions_total` | counter | `action`, `decision` (`allow`/`deny`) | RBAC authorization decisions |
| `secsy_component_up` | gauge | `component` (`database`/`hsm`) | Last readiness-probe result (1 = up) |
| `secsy_certificates_expiring` | gauge | `severity` (`warning`/`critical`/`expired`) | Certs in each expiry window as of the last monitor scan |
| `secsy_certificate_auto_renewals_total` | counter | `result` (`success`/`error`) | Certificates auto-renewed by the expiry monitor |
| `secsy_certificate_monitor_scans_total` | counter | `result` | Expiry-monitor scan cycles |
| `secsy_certificate_monitor_last_scan_timestamp_seconds` | gauge | — | Unix time of the last completed monitor scan |

Histogram buckets are in seconds and span the sub-millisecond to multi-second
range suited to HSM and HTTP operations.

### Sample Prometheus scrape config

```yaml
scrape_configs:
  - job_name: secsy-pki
    metrics_path: /metrics
    scheme: https              # the server runs behind TLS in production
    # tls_config:
    #   ca_file: /etc/prometheus/secsy-ca.pem
    static_configs:
      - targets: ["pki.example.com:8443"]
    # Optional: scrape more often than the default while validating.
    scrape_interval: 15s
```

If you terminate TLS at a proxy and scrape plaintext internally, set
`scheme: http` and point `targets` at the internal address. To keep `/metrics`
private, restrict it at the proxy/network layer to your Prometheus source.

### Kubernetes probes

```yaml
livenessProbe:
  httpGet: { path: /healthz, port: 8443, scheme: HTTPS }
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet: { path: /readyz, port: 8443, scheme: HTTPS }
  initialDelaySeconds: 5
  periodSeconds: 10
  failureThreshold: 3
```

With Prometheus scraping in-cluster, the pod annotations equivalent to the scrape
config above are:

```yaml
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/path: "/metrics"
    prometheus.io/port: "8443"
    prometheus.io/scheme: "https"
```

---

## Packaged dashboard & alerting rules

Ready-to-use observability assets ship in the repo (single source of truth in
the Helm chart, with convenience symlinks under `deploy/observability/`):

| Asset | Path |
|-------|------|
| Grafana dashboard JSON | `deploy/helm/secsy-pki/files/grafana-dashboard.json` (also `deploy/observability/grafana/secsy-pki-dashboard.json`) |
| Prometheus alerting rules | `deploy/helm/secsy-pki/files/prometheus-rules.yaml` (also `deploy/observability/prometheus/secsy-pki-rules.yaml`) |

The dashboard (`uid: secsy-pki-overview`) covers issuance rate/latency, HSM
session-pool saturation and queueing, OCSP/CRL request rates and derived cache
hit ratio, rate-limit 429/503 counts, and expiry-monitor + audit-export health.
It uses two template variables: a Prometheus **datasource** and a multi-select
**job** filter.

### Import — standalone Prometheus + Grafana

- **Grafana:** *Dashboards → New → Import → Upload JSON file* and select the
  dashboard JSON, then pick your Prometheus datasource. (Or provision it via a
  file-provider entry.)
- **Prometheus:** add the rules file to `rule_files:` and reload:

  ```yaml
  rule_files:
    - /etc/prometheus/secsy-pki-rules.yaml
  ```

  Validate before shipping: `promtool check rules deploy/observability/prometheus/secsy-pki-rules.yaml`.

### Deploy — Helm (Prometheus Operator / kube-prometheus-stack)

The chart renders an optional `PrometheusRule` and a Grafana-sidecar dashboard
`ConfigMap`, both **off by default**:

```yaml
# values.yaml
serviceMonitor:
  enabled: true                 # scrape /metrics (Task 19)
prometheusRule:
  enabled: true
  labels:
    release: kube-prometheus-stack   # MUST match your Prometheus ruleSelector
grafanaDashboard:
  enabled: true
  sidecarLabel: grafana_dashboard    # whatever your Grafana sidecar watches
```

The rule bodies are embedded verbatim from `files/prometheus-rules.yaml`, so the
Helm and standalone deployments never drift. Add site-specific rules via
`prometheusRule.additionalGroups` without editing the shipped file.

### Recommended alert thresholds

The shipped rules default to the values below. Tune them to your fleet size and
CRL/monitor cadence; the rationale and response steps live in the
[operator runbook](RUNBOOK.md#observability-dashboards--alerts).

| Alert | Condition (default) | Severity | Tune when |
|-------|---------------------|----------|-----------|
| `SecsyPKITargetDown` | scrape `up == 0` for 3m | critical | — |
| `SecsyPKIHSMProbeDown` | `secsy_component_up{component="hsm"}==0` for 2m | critical | — |
| `SecsyPKIHSMPoolExhausted` | `secsy_hsm_guard_queue_depth > 0` for 10m | warning | expected bursty queueing |
| `SecsyPKIHSMGuardShedding` | guard-reject rate `> 0.1/s` for 5m | critical | — |
| `SecsyPKIHSMSignLatencyHigh` | p99 sign latency `> 2s` for 10m | warning | slow network-HSM baseline |
| `SecsyPKIIssuanceErrorBudgetBurn{Fast,Slow}` | 14.4x/1h+5m, 6x/6h+30m on a 99.5% SLO | crit/warn | change SLO target |
| `SecsyPKICertificatesExpired` | `secsy_certificates_expiring{severity="expired"} > 0` for 15m | critical | — |
| `SecsyPKIExpiryBacklog` | `…{severity="critical"} > 25` for 1h | warning | scale to fleet size |
| `SecsyPKIMonitorStalled` | last scan older than 36h | warning | match `monitor.intervalHours` |
| `SecsyPKIAutoRenewFailing` | auto-renew error rate `> 0` for 30m | warning | — |
| `SecsyPKIOCSPErrorRateHigh` | OCSP error ratio `> 5%` for 10m | warning | — |
| `SecsyPKICRLServingErrors` | CRL error rate `> 0` for 10m | warning | — |
| `SecsyPKICRLNotRegenerating` | no base-CRL signing in 25h while served | warning | match `crl.baseValidityHours` |
| `SecsyPKIRateLimitThrottleSpike` | throttled fraction `> 30%` for 10m | warning | expected abuse baseline |
| `SecsyPKIAuditExportLagHigh` | lag `> 5000` events for 15m | warning | sink throughput |
| `SecsyPKIAuditExportStalled` | backlog + no ack in 30m | critical | — |

> **CRL/delta staleness caveat:** `SecsyPKICRLNotRegenerating` is a best-effort
> cadence check — the metrics expose no CRL `nextUpdate` timestamp. For an
> authoritative freshness SLO, additionally blackbox-probe the CDP URL and alert
> on the CRL's `nextUpdate` (see the runbook).

## Grafana dashboard notes

Prefer the packaged dashboard above. To build custom panels, the metrics are
standard Prometheus types — start from these queries:

**Issuance overview**

- Issuance rate by result:
  `sum by (result) (rate(secsy_certificates_total{operation="issue"}[5m]))`
- Renewals / revocations:
  `sum by (operation) (rate(secsy_certificates_total{operation=~"renew|revoke"}[5m]))`
- Error ratio (single stat / gauge):
  `sum(rate(secsy_certificates_total{result="error"}[5m])) / sum(rate(secsy_certificates_total[5m]))`

**HSM health & latency**

- HSM signing p95 latency:
  `histogram_quantile(0.95, sum by (le,operation) (rate(secsy_hsm_operation_duration_seconds_bucket{operation="sign"}[5m])))`
- HSM error rate by operation:
  `sum by (operation) (rate(secsy_hsm_operations_total{result="error"}[5m]))`
- HSM up (state timeline / stat): `secsy_component_up{component="hsm"}`

**Revocation serving**

- OCSP request rate by result:
  `sum by (result) (rate(secsy_ocsp_requests_total[5m]))`
- CRL fetches: `sum(rate(secsy_crl_requests_total[5m]))`

**API traffic**

- Request rate by route/status:
  `sum by (route,status) (rate(secsy_http_requests_total[5m]))`
- Request p95 latency by route:
  `histogram_quantile(0.95, sum by (le,route) (rate(secsy_http_request_duration_seconds_bucket[5m])))`
- In-flight requests: `secsy_http_requests_in_flight`

**Security / governance**

- Authorization denials (spot brute-forced or misconfigured access):
  `sum by (action) (rate(secsy_authz_decisions_total{decision="deny"}[5m]))`
- Envelope encrypt/decrypt rate:
  `sum by (operation,result) (rate(secsy_envelope_operations_total[5m]))`

**Suggested alerts**

| Alert | Expression (for) |
|-------|------------------|
| HSM down | `secsy_component_up{component="hsm"} == 0` for 1m |
| Database down | `secsy_component_up{component="database"} == 0` for 1m |
| Issuance failures | `rate(secsy_certificates_total{result="error"}[10m]) > 0` for 10m |
| HSM signing slow | `histogram_quantile(0.95, sum by (le)(rate(secsy_hsm_operation_duration_seconds_bucket{operation="sign"}[5m]))) > 1` for 10m |
| Authz denial spike | `sum(rate(secsy_authz_decisions_total{decision="deny"}[5m])) > 1` for 10m |

---

## Structured request logging & correlation

Every HTTP request emits one JSON log line to stdout:

```json
{"time":"2026-07-02T05:01:44.241Z","level":"info","msg":"http_request",
 "request_id":"1160eabb-9106-4cc9-96e7-e14ef6aa66d3","method":"GET",
 "route":"GET /api/ca/{id}/issue","path":"/api/ca/abc/issue","status":201,
 "duration_ms":42.7,"bytes_out":1834,"remote_ip":"10.0.0.5","user_agent":"lego/4"}
```

Fields are deliberately limited to non-sensitive request metadata — method,
matched route, path (never the query string), status, latency, response size,
client IP, and user agent. **Request/response bodies, the `Authorization` and
`Cookie` headers, basic-auth credentials, and query strings are never logged**,
so no secrets or key material reach the log.

### Request IDs

- A correlation ID is assigned to every request. If the client sends an
  `X-Request-ID` header with a safe value (≤128 chars, `[A-Za-z0-9._-]`), it is
  honored; otherwise a UUID is generated. Unsafe inbound values are rejected and
  replaced (no header/log injection).
- The ID is echoed back in the `X-Request-ID` response header.
- The same ID is written to the **access log** (`GET /api/access-log`) and to the
  **tamper-evident audit events** (`GET /api/events`) produced while serving the
  request, as a `request_id` field.

This lets you pivot from a request log line to the audit trail (and vice versa)
by a single ID. The `request_id` on audit events is **correlation metadata only
and is deliberately excluded from the event hash chain**, so it never affects
tamper-evidence and remains backward-compatible with logs written before this
field existed.

> Consuming JSON logs: pipe stdout to your log shipper (Loki, Fluent Bit, etc.).
> With Grafana + Loki you can link a metric spike to the exact requests via
> `{job="secsy-pki"} | json | request_id="…"`.

## See also

- [RBAC, audit logging & config](rbac-and-audit.md) — the event log the request
  IDs correlate to.
- [Certificate authority](certificate-authority.md) — the issuance/OCSP/CRL
  operations the metrics count.
- [HSM configuration](hsm-configuration.md) — the key-provider the readiness
  probe and HSM metrics measure.
```
