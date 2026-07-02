# Distributed tracing — OpenTelemetry (OTLP)

The enterprise server can emit **OpenTelemetry distributed traces** over OTLP,
complementing the Prometheus [`/metrics`](observability.md) and the structured
JSON request log. A trace shows a single request end-to-end — the HTTP handler,
the CA signing operation, every HSM/PKCS#11 call (including session-pool wait
time and multi-token failover), the pre-issuance lint/CAA/name-constraint gates,
CT submission, CRL/OCSP generation, and the persistence-store writes — as a tree
of timed spans, so you can see *where* a slow or failed issuance actually spent
its time.

Tracing is **disabled by default**. With it off, the server installs a no-op
tracer and starts no exporter, so the instrumentation costs effectively nothing.

---

## What is instrumented

| Span | Where | Notes |
|------|-------|-------|
| `<METHOD> <route>` (root) | request middleware | one per HTTP request; renamed to the matched route (bounded cardinality). Carries `request_id`, `http.route`, `http.response.status_code`. Continues an inbound W3C `traceparent`. |
| `ca.issue_leaf` | issuance | leaf issue/renew; carries `ca.id`, `ca.profile`, `cert.serial`. |
| `ca.build_leaf` | issuance | template assembly + the pre-issuance gates below. |
| `ca.gate.lint` / `ca.gate.caa` / `ca.gate.name_constraints` | issuance | each fail-closed pre-issuance gate; a rejection is recorded as a span error. |
| `ca.ct.submit` | issuance | Certificate Transparency precert submission; carries SCT count. |
| `ca.sign_certificate` | issuance | certificate DER construction (`ca.cert.kind` = precert/final). |
| `ca.generate_crl` | CRL | carries `ca.id`, `crl.revoked_count`. |
| `ca.ocsp_respond` | OCSP | carries `ca.id`. |
| `store.record_issued_certificate` | persistence | the Postgres/SQLite write on the issuance path. |
| `hsm.signer` / `hsm.sign` / `hsm.decrypt` / `hsm.generate_key` / `hsm.find_key` / `hsm.public_key` | keyprovider | HSM/PKCS#11 (or software/KMS) operations; carry `hsm.operation`, `hsm.key.label`, `hsm.provider`. |

### Span events

Point-in-time occurrences are recorded as **events** on the surrounding span:

- **`hsm.session.acquired`** — a PKCS#11 session was borrowed from the bounded
  pool ([Task 20](benchmarks.md)); carries `hsm.session.wait_ms` and
  `hsm.pool.size`. A large wait means the pool — not the on-device crypto — is
  the bottleneck.
- **`hsm.token.error`**, **`hsm.failover`**, **`hsm.failover.served`** — the
  multi-token high-availability path ([HSM HA](hsm-ha.md)). When an operation
  errs on one token and is retried on another, these events name the token that
  failed (`hsm.token`), the from/to tokens (`hsm.token.from` / `hsm.token.to`),
  and the token that ultimately served the request. They appear **only** on an
  actual failover, so they are a true signal rather than per-request noise.

---

## Log ↔ trace correlation

The structured request log line carries `trace_id` and `span_id` (when the
request is sampled) alongside the existing `request_id`. The same `request_id`
is set as a span attribute. So you can pivot from a log line to its trace (and
back), and from a trace to the tamper-evident audit events for the same request.

---

## Configuration

```yaml
tracing:
  enabled: true
  endpoint: "otel-collector:4317"   # OTLP receiver host:port (no scheme)
  protocol: grpc                    # grpc (:4317) | http (:4318)
  insecure: true                    # disable transport TLS (trusted network)
  sample_ratio: 0.1                 # head-based [0,1]; parent-sampled kept regardless
  service_name: secsy-pki           # service.name resource attribute
  service_version: "1.0.0"          # optional
  timeout_seconds: 10               # per-export attempt timeout
  headers:                          # optional static export headers
    authorization: "Bearer ..."
```

Notes:

- **`endpoint`** is `host:port` form with **no scheme**. TLS is controlled by
  `insecure`, not by an `https://` prefix.
- **`sample_ratio`** is head-based and *parent-respecting*: a trace already
  sampled upstream is always continued so it is not truncated at this hop.
  `0` (or unset) with tracing enabled samples everything — dial it down in
  production (e.g. `0.05`).
- Misconfiguration fails **loudly** at startup (missing endpoint, unknown
  protocol, out-of-range ratio) rather than silently disabling tracing.
- Environment `OTEL_RESOURCE_ATTRIBUTES` is honored and merged into the resource.

---

## Trying it locally

A ready-to-run OpenTelemetry Collector (+ optional Jaeger UI) lives in
[`deploy/observability/tracing/`](../deploy/observability/tracing/):

```bash
docker compose -f deploy/observability/tracing/docker-compose.otel.yaml up -d
```

Then enable tracing in the server config pointing at `localhost:4317` (or
`otel-collector:4317` if the server also runs in the compose network), issue a
certificate, and watch spans arrive:

```bash
docker compose -f deploy/observability/tracing/docker-compose.otel.yaml logs -f otel-collector
```

Browse traces in the Jaeger UI at <http://localhost:16686> (after enabling the
`otlp/jaeger` exporter in `otel-collector-config.yaml`).

---

## Kubernetes (Helm)

The Helm chart renders the `tracing` config block from `values.yaml`:

```yaml
config:
  tracing:
    enabled: true
    endpoint: "otel-collector.observability.svc:4317"
    protocol: grpc
    insecure: true
    sampleRatio: 0.1
    serviceName: secsy-pki
```

Point `endpoint` at your in-cluster OTLP collector Service. See
[docs/kubernetes.md](kubernetes.md).
