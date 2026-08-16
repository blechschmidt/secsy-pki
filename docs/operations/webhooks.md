# Outbound webhooks (eventing)

secsy-pki has three distinct event paths; this document covers the third:

| Path | Audience | Delivery |
| --- | --- | --- |
| [Live audit SSE feed](web-console.md) | Humans watching the console | In-process, **lossy** (drop-oldest on a slow reader) |
| [SIEM export](../security/audit-siem-export.md) | Log collectors (syslog/CEF/webhook) | Streams the **whole** audit log to fixed sinks with a durable cursor |
| **Outbound webhooks** (this doc) | External automation / integrations | **Durable, per-subscription**, at-least-once, retried, signed |

Where the monitor's [notification sinks](expiry-monitoring.md) push *alerts*
(expiry/canary/CT/backup) to one configured URL fire-and-forget, outbound
webhooks are a first-class, operator-managed integration surface: each external
system registers its own subscription for the certificate lifecycle events it
cares about, and every matching event is delivered reliably.

## Model

- A **subscription** (`webhook_subscriptions`) binds a target URL + HMAC secret
  to an event-type filter, a tenant scope, and an enabled flag.
- A **delivery** (`webhook_deliveries`) is one durable unit of work: a single
  event bound for a single subscription, tracked through its retry lifecycle.
- A **fan-out cursor** (`webhook_fanout_cursor`) records how far the delivery
  worker has scanned the audit log — the same pattern the SIEM exporter uses.

### Events

The subscribable event types are the certificate lifecycle audit actions, used
verbatim (no translation table to drift):

| Event type | Emitted when |
| --- | --- |
| `cert.issue` | A leaf certificate is issued |
| `cert.renew` | A certificate is renewed |
| `cert.revoke` | A certificate is revoked |
| `cert.suspend` | A certificate is placed on hold (RFC 5280 `certificateHold`) |
| `cert.release` | A certificate hold is removed |

An empty event-type filter subscribes to **all** of them. Only *successful*
lifecycle events are delivered; a denied or errored attempt is not a lifecycle
transition. Bulk issuance/revocation is covered by the per-item `cert.issue` /
`cert.revoke` events they already emit — there is no separate bulk event.

## How events reach the queue

There is **no** webhook-emit call sprinkled through `ca.Manager`. Instead the
delivery worker reuses the single audit-append chokepoint:

1. Every lifecycle operation appends one hash-chained event to the durable
   `event_log` (the same append that feeds the audit SSE feed and SIEM export).
2. The leader-elected **fan-out** scans `event_log` forward from the durable
   cursor and, for each matching event × enabled subscription, enqueues a
   delivery. The enqueue is idempotent
   (`UNIQUE(subscription_id, event_seq)`), so a re-scan after a crash never
   double-delivers.
3. The audit-append hook additionally *nudges* the fan-out so it runs promptly
   rather than waiting for the poll tick — a latency optimization only;
   durability comes from the cursor sweep.

On first enablement the cursor seeds to the **current** log head, so enabling
webhooks does not replay the entire certificate history — subscriptions receive
events from enablement forward.

## Delivery semantics

- **At-least-once.** A delivery survives restarts and leadership handovers; a
  handover at worst redelivers the last unacknowledged attempt. Receivers must
  deduplicate on the `event_id`.
- **Retries with exponential backoff.** A non-2xx response (or a transport
  error) schedules a retry `backoff_base × 2^(attempt-1)`, capped at
  `backoff_max`.
- **Dead-lettering.** After `max_attempts` failed attempts the delivery moves to
  the terminal `dead` state and stops retrying — the signal that an endpoint is
  misconfigured or down.
- **Leader-elected.** The worker runs as a singleton
  [leader-elected job](../deployment/high-availability.md), so a multi-replica deployment
  never double-delivers.

## Request format

Each delivery is an HTTP `POST` with a JSON body and these headers:

| Header | Value |
| --- | --- |
| `Content-Type` | `application/json` |
| `X-Secsy-Event` | the event type, e.g. `cert.issue` |
| `X-Secsy-Delivery` | the delivery id |
| `X-Secsy-Webhook-Id` | the subscription id |
| `X-Secsy-Attempt` | 1-based attempt counter |
| `X-Secsy-Signature` | `t=<unix-seconds>,v1=<hex-hmac>` |

The body:

```json
{
  "specversion": "1.0",
  "type": "cert.issue",
  "id": "<delivery-id>",
  "event_id": "<audit-event-id>",
  "sequence": 1234,
  "time": "2026-07-04T12:00:00Z",
  "tenant": "default",
  "subscription_id": "<subscription-id>",
  "data": {
    "action": "cert.issue",
    "result": "success",
    "actor": "alice",
    "ca_id": "<issuing-ca-id>",
    "serial": "0A1B2C…",
    "target": "<issuing-ca-id>",
    "target_name": "0A1B2C…",
    "detail": "profile=server …"
  }
}
```

### Verifying the signature

`X-Secsy-Signature` is `t=<unix>,v1=<hmac>` where the HMAC is:

```
HMAC-SHA256(secret, "<unix>.<raw-body>")
```

Binding the timestamp into the signed message lets a receiver reject a stale
(replayed) delivery: compare `t` against your own clock and drop deliveries
outside a freshness window (e.g. 5 minutes), then constant-time-compare the
HMAC over the exact received body. Example (pseudo-code):

```
t, v1  := parse("X-Secsy-Signature")           // "t=…,v1=…"
if abs(now - t) > 5*minute { reject }           // replay / skew guard
want   := hex(hmac_sha256(secret, t + "." + body))
if !constant_time_equal(want, v1) { reject }
```

The signing secret is shown **once** at creation (or supply your own) and is
never returned again.

## Authorization

Managing webhooks requires the **`webhook:manage`** capability (admin role),
tenant-scoped exactly like `token:manage`:

- a **tenant admin** manages subscriptions within their tenant, which receive
  only that tenant's events;
- a **platform admin** may create a `platform`-scoped subscription that receives
  every tenant's events.

Cross-tenant isolation is enforced on both the management API (a tenant-a admin
cannot touch a tenant-b subscription → `403`) and the delivery path (a
tenant-scoped subscription only ever matches its own tenant's events).

## Configuration

The subscription-management API/CLI work regardless of configuration; the
**delivery worker** runs only when `webhook.enabled` is set:

```yaml
webhook:
  enabled: true              # start the leader-elected delivery worker
  poll_interval_seconds: 5   # fan-out/delivery poll cadence (also woken by new events)
  batch_size: 100            # events scanned / deliveries claimed per iteration
  max_attempts: 8            # dead-letter after this many failed attempts
  timeout_seconds: 10        # per-POST timeout
  backoff_base_seconds: 30   # first retry delay; doubles each attempt
  backoff_max_seconds: 3600  # retry-delay cap
  dead_letter_stale_hours: 24 # doctor escalation threshold for un-triaged dead-letters
  # audit_deliveries: true   # record a webhook.deliver audit event on each terminal outcome
```

If subscriptions exist but `webhook.enabled` is false, deliveries are queued but
not sent; the `webhook.dead_letters` doctor check flags this.

## CLI

```bash
# Register (prints the signing secret once)
secsy-ca webhook create -url https://example.com/hook -events cert.issue,cert.revoke
secsy-ca webhook create -url https://example.com/hook -scope platform

secsy-ca webhook list [-tenant acme]
secsy-ca webhook disable <id>          # pause; cancels pending deliveries
secsy-ca webhook enable  <id>
secsy-ca webhook test    <id>          # live signed test POST, immediate result
secsy-ca webhook deliveries <id> -status dead -limit 50
secsy-ca webhook delete  <id>          # removes the subscription and its history
```

## REST

| Method & path | Purpose |
| --- | --- |
| `GET /api/webhooks` | List subscriptions (`?tenant=` filter) |
| `POST /api/webhooks` | Create (returns the secret once) |
| `GET /api/webhooks/{id}` | Read one |
| `DELETE /api/webhooks/{id}` | Delete |
| `POST /api/webhooks/{id}/enable` \| `/disable` | Toggle |
| `POST /api/webhooks/{id}/test` | Queue a test delivery |
| `GET /api/webhooks/{id}/deliveries` | Delivery history (`?status=`, `?limit=`) |

All are gated by `webhook:manage` and tenant-scoped. The **Webhooks** console
page wraps the same endpoints.

## Observability

- **Audit:** `webhook.create`, `webhook.update` (enable/disable/test),
  `webhook.delete`, and `webhook.deliver` (terminal outcome — success or
  dead-lettered; retries are not audited to keep the hash-chained log lean).
- **Metrics:** `secsy_webhook_deliveries_total{result}`,
  `secsy_webhook_delivery_duration_seconds`, `secsy_webhook_queue_depth`,
  `secsy_webhook_dead_letters`, `secsy_webhook_subscriptions_active`,
  `secsy_webhook_last_success_timestamp_seconds`, and the
  `secsy_webhook_staleness_seconds` gauge.
- **Doctor:** `webhook.dead_letters` — warns on dead-lettered deliveries and
  escalates to a failure once the oldest exceeds `dead_letter_stale_hours`; also
  flags queued deliveries with the worker disabled.

## Security notes

- The HMAC secret must be stored to sign deliveries; it is kept in the
  `webhook_subscriptions.secret` column (consistent with how the monitor sink
  stores its headers) and is never returned via the API after creation.
- A subscription egresses certificate metadata (subject names, serials) to an
  operator-chosen URL — a data-egress decision, which is why registering one is
  admin-only. Prefer HTTPS endpoints.
