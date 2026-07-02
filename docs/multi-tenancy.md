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
[persistence.md](persistence.md).
