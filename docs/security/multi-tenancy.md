# Multi-tenant isolation

secsy-pki can serve several isolated organizations from a single deployment. A
**tenant** is a first-class isolation boundary: each tenant owns its own
certificate authorities, issuance profiles (restriction sets), revocation/CRL
state, secret envelopes, RBAC role assignments, and audit trail. A principal may
only reach resources of a tenant it belongs to — cross-tenant access is denied
at the authorization layer and, defensively, at the read (listing) layer.

The feature is fully backward compatible. Every deployment always has the
built-in **`default`** tenant; single-organization installs use it implicitly
and never need to think about tenants. When the schema is upgraded, all
pre-existing CAs, restriction sets, groups, and audit events are backfilled to
the default tenant.

## What is scoped by tenant

| Resource | How it is scoped |
| --- | --- |
| CAs (root & intermediate) | `cas.tenant_id`; an intermediate always inherits its parent's tenant |
| Issued / revoked certs, serial & CRL counters, published CRLs | transitively, via their `ca_id` (a CA belongs to exactly one tenant) |
| Restriction sets (issuance profiles) | `restriction_sets.tenant_id` (NULL = global built-ins, shared) |
| RBAC groups | `groups_.tenant_id` |
| Audit events | `event_log.tenant`, bound into the tamper-evident hash chain |
| Secret envelopes | per-tenant KEK label (`tenants.kek_label`) |
| Rate-limit accounts | per-account buckets namespaced by the `X-Secsy-Tenant` selector |

## Roles: platform vs. tenant

RBAC roles (`admin`, `issuer`, `auditor`) can now be granted at two scopes:

- **Platform-wide** — assigned in the top-level `rbac:` block. These roles apply
  in *every* tenant and are reserved for platform operators. The built-in `root`
  user is always a platform superuser.
- **Tenant-scoped** — assigned in a tenant's own `rbac:` block. These roles
  apply *only* within that tenant.

A principal that holds `issuer` in tenant A has no capability in tenant B. This
is the mechanism that enforces cross-tenant isolation: authorization for a
CA-scoped request resolves the CA's tenant and checks the caller's roles *within
that tenant*.

```yaml
# Platform operators (span all tenants):
rbac:
  subjects:
    "platform-admin-oidc-sub": [admin]

# Isolated organizations:
tenants:
  - id: acme-corp
    slug: acme
    name: "ACME Corporation"
    kek_label: "kek-acme"        # optional: seals ACME's secrets under its own KEK
    rbac:
      subjects:
        "acme-admin-oidc-sub":   [admin]
        "issuer@acme.example.com": [issuer]
  - id: globex
    slug: globex
    name: "Globex"
    rbac:
      subjects:
        "globex-admin-oidc-sub": [admin]
```

Config-declared tenants are provisioned idempotently at startup. Tenants can also
be created at runtime by a platform admin (see the API/CLI below).

## API

Tenant administration (platform-admin only unless noted):

| Method & path | Description |
| --- | --- |
| `GET /api/tenants` | List all tenants |
| `POST /api/tenants` | Create a tenant (`{slug, name, kek_label?}`) |
| `GET /api/tenants/{id}` | Get a tenant (members may read their own) |
| `PUT /api/tenants/{id}/status` | Activate / suspend (`{status}`) |
| `DELETE /api/tenants/{id}` | Delete an empty tenant |

The default tenant cannot be suspended or deleted, and a tenant that still owns
CAs cannot be deleted.

Tenant selection on existing endpoints:

- **CA creation** (`POST /api/keys`, `POST /api/ca/init-root`) accepts an
  optional `tenant_id` (defaults to `default`). Intermediates inherit the
  parent's tenant.
- **Secret encrypt/decrypt** honor the `X-Secsy-Tenant` request header (tenant id
  or slug) to select the tenant whose KEK seals/opens the envelope.
- **`GET /api/events`** accepts `?tenant=`. Platform operators may narrow the
  view; a tenant-scoped auditor is always confined to its own tenant.

## CLI

```console
# List / create / suspend / activate tenants
secsy-ca tenant list
secsy-ca tenant create -slug acme -name "ACME Corporation" -kek-label kek-acme
secsy-ca tenant suspend acme
secsy-ca tenant activate acme

# Create a CA owned by a specific tenant
secsy-ca init-root -tenant acme -label acme-root -cn "ACME Root CA"
```

## Public protocol endpoints (ACME / EST / OCSP / CRL / SCEP / CMP)

Each public protocol instance is bound to a single issuing CA in configuration
(`acme.ca_id`, `est.ca_id`, …). Because a CA belongs to exactly one tenant, the
tenant of every certificate a protocol issues — and of the OCSP/CRL responses it
serves — is deterministically the tenant that owns the configured CA. OCSP and
CRL endpoints are already addressed per-CA (`/api/ca/{id}/…`), so they resolve
their tenant directly from the CA. To serve multiple tenants over the same
protocol, run one protocol instance per tenant, each pointed at that tenant's CA.

## Audit and tamper-evidence

Each audit event carries the owning tenant. The tenant is bound into the
hash-chained `event_log` under a domain-separating tag, so an event cannot be
silently re-attributed to another tenant without breaking chain verification.
Events written before multi-tenancy (and platform-level events with no tenant)
have an empty tenant and hash exactly as before, so historical chains continue to
verify.

## Migration & persistence

The schema adds a `tenants` table and `tenant_id`/`tenant` columns to `cas`,
`restriction_sets`, `groups_`, and `event_log`. The migration seeds the default
tenant and backfills existing rows to it. Both SQLite and PostgreSQL are
supported, and `secsy-ca db migrate` copies the `tenants` table first so foreign
keys from `cas`/`restriction_sets` are satisfied. See
[persistence.md](../deployment/persistence.md).

## Tenant lifecycle, quotas, and usage (Task 61)

### Lifecycle

`active` and `suspended` are the two lifecycle states. Suspension freezes a
tenant without destroying anything:

- **Blocked while suspended:** every certificate-minting path — REST
  issue/renew, ACME, SCEP, EST, CMP, gRPC, SVID, the SSH CA, and the legacy
  sign endpoint — plus secret envelope encrypt/decrypt and new CA creation.
  The check lives inside the CA manager (`ca.GateTenantIssuance`), so it holds
  for every protocol without per-protocol code, and it is **fail-closed**: if
  tenant state cannot be read, issuance is refused. When the public-endpoint
  middleware is installed it additionally answers `403` on the whole
  enrollment surface of a suspended tenant's protocols (cached ~3 s).
- **Still working while suspended:** OCSP and CRL for already-issued
  certificates (relying parties keep validating), certificate revocation (the
  operator can still withdraw credentials), and all read APIs. Reactivate with
  `secsy-ca tenant activate <slug>` or `PUT /api/tenants/{id}/status`.

The default tenant can never be suspended or deleted.

### Quotas

Per-tenant ceilings live on the tenant record (`quotas`); zero means
unlimited. Enforcement is fail-closed on the same paths as suspension:

| Quota | Meters | Exhaustion answer |
|---|---|---|
| `max_certs_per_day` | Certificates issued per UTC day (X.509 + SSH), all protocols | `429`, `code=quota_exceeded`, `Retry-After` until UTC midnight |
| `max_active_certs` | Unexpired, unrevoked X.509 inventory | `429`, `code=quota_exceeded` (revoke/expiry frees room) |
| `max_secret_ops_per_day` | Envelope encrypt/decrypt per UTC day | `429`, `code=quota_exceeded`, `Retry-After` |
| `rate_limit_per_second` / `rate_limit_burst` | Request rate on public enrollment endpoints | `429` from the rate limiter (`tier=per_tenant`) |

Protocol mappings: ACME returns an RFC 8555 `rateLimited` problem (quota) or
`unauthorized` (suspended); EST returns 429/403; SCEP returns a CertRep
failure with a distinguishing `failInfoText`; CMP returns `systemUnavail`
(quota) or `notAuthorized` (suspended); gRPC returns `RESOURCE_EXHAUSTED` /
`PERMISSION_DENIED`.

The daily counter is reservation-style: it is consumed atomically **before**
the HSM signs (a single conditional `UPDATE`, correct under concurrency on
both SQLite and PostgreSQL) and released if issuance later fails, so failed
signings never burn quota. Revocations are accounted but never gated.

```console
# Show, then set quotas (0 clears back to unlimited)
secsy-ca tenant quota acme
secsy-ca tenant quota acme -certs-per-day 500 -active-certs 2000 -secret-ops-per-day 10000 -rate 25 -burst 50

# Usage report: inventory counts + rolling daily window
secsy-ca tenant usage acme -days 14
```

Or over the API (platform admin): `PUT /api/tenants/{id}` with a `quotas`
object, and `GET /api/tenants/{id}/usage?days=N` for the report (tenant
members may read their own tenant's report). The console has a **Tenants**
page for the same operations.

### Per-tenant rate-limit tier

`rate_limit.per_tenant` sets the deployment-wide default request rate for one
tenant's enrollment endpoints (ACME/EST/SCEP/CMP, resolved from the protocol's
bound CA); a tenant's `rate_limit_per_second`/`rate_limit_burst` quota fields
override it per tenant, applied live without a restart. OCSP/CRL are never
metered per tenant.

```yaml
rate_limit:
  enabled: true
  per_tenant: { rate: 50, burst: 100 }
```

### Usage accounting and metrics

Usage is accounted in the `tenant_usage` table — one row per (tenant, UTC
day) with `certs_issued`, `certs_revoked`, `secret_ops` — on both the SQLite
file store and PostgreSQL, and included in `secsy-ca db migrate`. Inventory
counts (active/total/revoked) are computed live from `issued_certificates`.

Prometheus metrics carry a **cardinality-guarded** `tenant` label (first 100
distinct tenants; the rest fold into `_other_`):

- `secsy_tenant_certificates_issued_total{tenant}`
- `secsy_tenant_secret_ops_total{tenant,operation}`
- `secsy_tenant_denied_total{tenant,reason}` with `reason` one of
  `suspended|certs_per_day|active_certs|secret_ops_per_day|rate_limit`

Every gate refusal is also an audit event (`tenant.quota`, `ResultDenied`)
bound into the hash chain.
