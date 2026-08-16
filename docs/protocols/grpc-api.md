# gRPC API

secsy-pki exposes the core certificate-lifecycle operations over a **gRPC API**
alongside the existing REST surface. The gRPC server is a thin transport over the
same `ca.Manager` issuance/revocation logic and the same authorization, tenant
scoping, audit, HSM-audit, rate-limit, and tracing plumbing that backs REST — so
both protocols behave identically, with no duplicated business logic.

- **Service definition:** [`proto/pki/v1/pki.proto`](../../proto/pki/v1/pki.proto)
- **Generated Go:** `server/internal/grpcapi/pkiv1/`
- **Service name:** `secsy.pki.v1.PKIService`

## Operations

| RPC | Purpose | Authorization |
|-----|---------|---------------|
| `IssueCertificate` | Sign a PKCS#10 CSR into an end-entity certificate under a CA + profile | issue capability on the CA's tenant, or a per-CA `SIGN_CERTIFICATE` grant |
| `RenewCertificate` | Reissue a certificate by serial with a fresh serial/validity (optionally rekeying from a CSR) | same as issue |
| `RevokeCertificate` | Revoke a serial and invalidate its cached OCSP response | same as issue |
| `GetCertificate` | Return the authority's stored copy of a certificate + status | read standing in the CA's tenant |
| `GetCertificateStatus` | Return only the coarse status (valid / expired / revoked / unknown) | read standing |
| `ListCertificates` | List the certificates a CA has issued | read standing |
| `GetCRLMetadata` | CRL number, this/next update, and public base/delta URLs (regenerates on the HSM only when stale) | read standing |
| `GetOCSPMetadata` | OCSP responder URL(s) and hardening options (nonce, delegated responder) | read standing |
| `StreamEvents` | Server-stream the live tamper-evident audit/lifecycle event feed (gRPC peer of the REST SSE endpoint) | `audit:read` (admin/issuer/auditor); tenant-scoped |

The full request/response shapes are in the `.proto`. Timestamps use
`google.protobuf.Timestamp`; a validity of `0` days means "use the profile
default" (and is clamped to the profile maximum, the CA's own expiry, and any
global `policy.max_cert_validity_days` cap, exactly as REST).

### Event streaming (`StreamEvents`)

`StreamEvents` is the only server-streaming RPC. It subscribes the caller to the
same in-process publisher that backs the REST Server-Sent-Events feed
(`GET /api/events/stream`), so both surfaces observe an identical stream of
hash-chained audit/lifecycle events fanned out from the single audit-append
chokepoint — no eventing logic is duplicated. Each `StreamEventsResponse` frame is
a `oneof`: an `AuditEvent`, a periodic `EventHeartbeat` (so idle streams and
half-open connections are detected), or an `EventLag` notice when a slow consumer
had its oldest undelivered events dropped (the feed never blocks the append hot
path).

Authorization and tenant scoping match the SSE feed exactly (`audit:read`; a
platform operator sees every tenant, optionally narrowed with the request's
`tenant`, while a tenant-scoped principal is confined to its own tenant's events).
Request fields:

- `action` — narrow to a single audit action (e.g. `cert.issue`).
- `tenant` — tenant selector (a platform operator narrowing to one tenant; a
  principal that belongs to several tenants must name one).
- `resume_from_seq` — when `> 0`, first replays matching events past that sequence
  number from the durable `event_log` cursor before switching to the live tail,
  de-duplicating any overlap by sequence number, so a reconnecting client resumes
  without a gap. `EventHeartbeat.last_seq` advertises the current resume cursor.
- `heartbeat_seconds` — override the idle heartbeat cadence (default 15s, clamped).

## Enabling it

The gRPC listener is **disabled by default** and binds its own port. Enable it in
the server config:

```yaml
grpc:
  enabled: true
  address: ":9443"   # defaults to :9443
  # tls_cert / tls_key fall back to server.tls_cert / server.tls_key
  mtls: false        # request+bind mutual-TLS client certs (requires auth.mtls)
```

TLS is mandatory: like the REST listener, the server refuses to serve cleartext
gRPC unless the operator has opted into insecure HTTP
(`SECSY_ALLOW_INSECURE_HTTP=1`), which is only appropriate behind a trusted
TLS-terminating proxy or in tests. When `grpc.tls_cert`/`grpc.tls_key` are unset
the server reuses the REST listener's certificate, so a single certificate covers
both protocols.

Server **reflection** and a gRPC **health service** (`grpc.health.v1.Health`) are
always registered when the listener is enabled.

## Authentication

The gRPC interceptor accepts the same credentials as the REST middleware, so the
same principals, RBAC roles, and tenant scoping apply:

- **Bearer OIDC token** — `authorization: Bearer <token>` call metadata.
- **Basic root credentials** — `authorization: Basic base64(user:password)` call
  metadata (only when root basic-auth is enabled).
- **Mutual-TLS client certificate** — a certificate presented on the TLS
  connection and bound to an operator principal by the `auth.mtls` binder (set
  `grpc.mtls: true`). As on REST, a presented certificate is verified-if-given,
  so Bearer/Basic callers still connect.

Application RPCs require authentication; unauthenticated calls return
`UNAUTHENTICATED`. The reflection and health services are reachable without
credentials so tooling (e.g. `grpcurl`) can discover the schema and load
balancers can probe health.

## Error codes

Manager and authorization errors map to canonical gRPC status codes:

| Condition | Code |
|-----------|------|
| Missing/invalid credential | `UNAUTHENTICATED` |
| No capability for the operation | `PERMISSION_DENIED` |
| Unknown CA / certificate (not visible) | `NOT_FOUND` |
| Missing/malformed argument, profile/lint/CAA/policy rejection | `INVALID_ARGUMENT` |
| Context cancelled / deadline exceeded | `CANCELLED` / `DEADLINE_EXCEEDED` |
| Unexpected failure | `INTERNAL` |

`GetCertificateStatus` for a serial the authority never issued returns a
successful response with status `UNKNOWN` (not an error), so callers can
distinguish "no record" from "denied".

## Observability

Each call continues any upstream **W3C trace context** propagated in call
metadata, opens a per-call span (`grpc <FullMethod>`), and assigns/echoes an
`x-request-id` correlation ID — the same request-ID and tracing plumbing as the
HTTP path. State-changing RPCs append a tamper-evident **audit event** attributed
to the caller, tenant, correlation ID, and gRPC peer address. Issuance/renewal/
revocation increment the same Prometheus certificate counters as REST. A
`StreamEvents` subscription is counted by the same event-stream subscriber gauge
and connection/drop counters as the REST SSE feed (it shares one publisher).

## Client subcommand

`secsy-ca grpc` is a self-contained gRPC client that demonstrates the API. The
default `demo` operation runs a full issue → status → revoke → status round-trip:

```bash
# End-to-end issue + revoke against a running server (root basic-auth over TLS).
secsy-ca grpc \
  -addr pki.example.com:9443 \
  -operation demo \
  -ca <ca-id> -profile server \
  -cn demo.example.com \
  -basic root:"$ROOT_PASSWORD" \
  -cacert /etc/secsy/ca-bundle.pem

# Individual operations: issue | renew | revoke | suspend | release | get |
# status | list | crl-metadata | ocsp-metadata | stream-events. Authenticate with
# -token (Bearer), -basic, or -client-cert/-client-key (mTLS). Use -plaintext for a
# local cleartext server.
secsy-ca grpc -addr localhost:9443 -operation issue -ca <ca-id> -profile server \
  -cn app.example.com -token "$OIDC_TOKEN" -cert-out app.pem

# Live-tail the audit/lifecycle event feed (server stream). Runs until Ctrl-C or
# -duration elapses; -resume-from replays the durable log first, -action/-tenant
# narrow the view, and -json emits one JSON frame per line (NDJSON).
secsy-ca grpc -addr pki.example.com:9443 -operation stream-events \
  -basic root:"$ROOT_PASSWORD" -cacert /etc/secsy/ca-bundle.pem \
  -action cert.issue -resume-from 1024 -json
```

Because reflection is enabled, `grpcurl` also works out of the box:

```bash
grpcurl -H "authorization: Bearer $OIDC_TOKEN" pki.example.com:9443 list
grpcurl -H "authorization: Bearer $OIDC_TOKEN" \
  -d '{"ca_id":"<ca-id>","serial":"12345"}' \
  pki.example.com:9443 secsy.pki.v1.PKIService/GetCertificateStatus
```

## Kubernetes

The Helm chart exposes the gRPC port when enabled — see
[Kubernetes deployment](../deployment/kubernetes.md#grpc-api). Set `config.grpc.enabled=true`;
the deployment adds a `grpc` container port and the Service adds a `grpc` port
(`service.grpcPort`, default 9443). Reach it from outside the cluster with a
gRPC-aware (HTTP/2) ingress or gateway.

## Regenerating the generated code

The `.proto` is the source of truth; the generated Go is committed. Regenerate
after editing the schema:

```bash
make proto            # or: scripts/gen-proto.sh
```

This needs `protoc` plus the Go plugins (`protoc-gen-go`, `protoc-gen-go-grpc`);
see the header of `scripts/gen-proto.sh` for install commands.
