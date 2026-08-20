# Per-CA and per-key authorization — resource grants

*Delegating one authority, or one key, to a team — without handing over the
tenant.*

The [role model](rbac-and-audit.md) answers "what class of operator is this?"
across a whole tenant. A principal holding `admin` in tenant *acme*
administers **every** CA and every key in *acme*. That is the right granularity
for a platform operator and the wrong granularity for the most common
enterprise arrangement:

> The platform team owns the offline root CA. Each product team administers
> exactly its own subordinate CA, and nothing else.

A **resource grant** expresses that directly. It binds a user or a group to a
named bundle of capabilities at **one individually addressed resource** — a
specific CA, or a specific signing key — optionally extending to that CA's
subordinates.

This page covers the model, how to configure and administer it, and how to
audit the result. For a runnable end-to-end walkthrough, see the
[delegated CA administration example](../../examples/delegated-ca-administration/README.md).

---

## 1. Where grants sit in the authorization stack

Three layers decide every per-resource request. They are consulted in order, and
they are **purely additive** — a grant can only widen what a principal may do,
never narrow it:

| Layer | Scope | Configured in | Answers |
|-------|-------|---------------|---------|
| **Platform roles** | every tenant | top-level `rbac.subjects` / `rbac.groups` | "is this a platform operator?" |
| **Tenant roles** | one tenant | `tenants[].rbac` | "what class of operator is this *within this organization*?" |
| **Resource grants** | one CA or one key | `rbac.grants`, `/api/grants`, `secsy-ca grant` | "who owns *this particular* authority?" |

The decision a per-resource endpoint makes is:

```
allow  ⇔  root
       ∨  a platform role grants the capability
       ∨  a role in the resource's tenant grants the capability
       ∨  a grant on the resource — or on an ancestor CA, when the grant is
          subtree-scoped — grants the capability
```

Because the grant layer is consulted **last and only on failure**, a platform or
tenant operator's request costs no extra lookup, and enabling grants cannot
change any existing authorization outcome.

Two consequences worth stating plainly:

- **Delegation adds an owner; it does not remove one.** Granting a group
  `ca-admin` on a subordinate does not lock the platform administrator out of
  it. If you need the root CA to be unreachable by a team, do not give that team
  a role in the tenant that owns it — a grant elsewhere cannot take authority
  away.
- **A grant is enough on its own.** A principal holding no platform role and no
  tenant role, but holding a grant, can see and operate exactly the resource it
  was given. That is the least-privilege case the model exists for.

---

## 2. Resources

A resource is written `<type>/<id>`:

| Type | Identifier | Covers |
|------|-----------|--------|
| `ca` | the CA id (see `secsy-ca list`) | one certification authority — root or subordinate, signing X.509 *or* SSH certificates |
| `signing-key` | the key name | one named HSM-backed [signing key](../signing/artifact-signing.md) on the secret layer |

X.509 and SSH authorities are deliberately **one** resource type. They share a
table and an ID namespace, so splitting them would mean a grant written for an
SSH CA silently failing to match the identical ID checked as an X.509 CA.

Resource identifiers may not contain whitespace or control characters. A value
that does is rejected rather than stored — it always indicates a mangled
argument (a shell pipeline that captured two lines, say), and an embedded
newline would forge a record boundary in the audit trail.

---

## 3. Resource roles

A grant carries a **resource role**: a fixed bundle of capabilities, conferred
only at the resource the grant names.

| Role | Applies to | Capabilities at that resource |
|------|-----------|-------------------------------|
| `ca-admin` | `ca` | `ca:manage`, `ca:configure`, `cert:issue`, `audit:read`, **`resource:delegate`** |
| `ca-manager` | `ca` | `ca:manage`, `ca:configure`, `cert:issue`, `audit:read` |
| `ca-issuer` | `ca` | `cert:issue`, `audit:read` |
| `ca-auditor` | `ca` | `audit:read` |
| `key-admin` | `signing-key` | `secret:signing-key`, `secret:sign`, `audit:read`, **`resource:delegate`** |
| `key-signer` | `signing-key` | `secret:sign`, `audit:read` |
| `key-auditor` | `signing-key` | `audit:read` |

`secsy-ca grant roles` prints this table from the live capability model, so it
cannot drift from what the server enforces.

Three properties are worth understanding:

- **The names are deliberately not the platform role names.** `ca-admin` on one
  subordinate is authority over one authority; `admin` is authority over the
  deployment. Keeping the vocabularies distinct means a YAML reader can never
  confuse the two.
- **There is no allow-all resource role.** Unlike the platform `admin` role,
  every capability a resource role confers is listed explicitly, so a newly
  added capability is denied through grants until someone deliberately adds it
  to a bundle.
- **`ca-manager` cannot delegate.** Day-to-day operation of a CA must not be
  escalatable into control over who *else* may operate it. Only the `*-admin`
  roles carry `resource:delegate`, and it applies to that one resource — a
  `ca-admin` on a subordinate may hand that subordinate to its team, and has no
  authority over its siblings, its parent, or the tenant's role assignments.

A role must match its resource type. Granting `key-signer` on a CA is refused at
every entry point (config load, API, CLI, and the store) rather than accepted
and silently authorizing nothing.

---

## 4. Scope: `self` and `subtree`

| Scope | Reach |
|-------|-------|
| `self` *(default)* | exactly the named resource |
| `subtree` | the named CA **and every CA beneath it**, including subordinates created later |

`self` is the default because it is the safe reading: delegating a subordinate
CA must not silently hand over authorities someone creates underneath it next
year. Reach `subtree` for when a team genuinely owns a *branch* of the PKI —
it saves re-granting on every new subordinate, and it applies to CAs created
after the grant was written.

Inheritance is strictly **downward**. A subtree grant on a subordinate never
reaches its parent or its siblings.

`subtree` is meaningful only on CAs, which are the only resources with a
hierarchy; it is rejected on a signing key.

To prevent a delegated administrator widening its own blast radius, a principal
whose authority comes from a **self-scoped** `ca-admin` grant cannot mint a
**subtree** grant. Issuing subtree reach requires either tenant-wide
`rbac:manage`, or a delegating grant that is itself subtree-scoped.

---

## 5. Who a grant can name

| `entity_type` | Matched against |
|---------------|-----------------|
| `user` | the principal's authenticated subject, **or** its email address when the identity provider marked it verified |
| `group` | the union of the principal's internal (database) groups and the groups asserted by its identity provider |

The email rule is the same one the platform role assignments use: an
**unverified** email never picks up authority, so a self-asserted address cannot
claim someone else's grant. Subject comparison is exact; email comparison is
case-insensitive.

Both group sources matter, and a grant does not care which one a name came
from:

- **Internal groups** (`/api/groups`, `groups_` / `group_members`) let a
  deployment model teams without touching the IdP.
- **Directory groups** — an OIDC `groups` claim, or LDAP/AD membership resolved
  at login — let an existing enterprise group be handed a CA without mirroring
  its membership here. These are carried on the principal at authentication;
  see [operator authentication](authentication.md).

---

## 6. Configuring grants declaratively

Grants in the `rbac.grants` block are the reviewable baseline: they live in
version control, survive a database rebuild, and are validated at startup.

```yaml
rbac:
  subjects:
    "platform-ops@example.com": [admin]      # keeps the root CA

  grants:
    # The payments team administers its own subordinate CA — and only that one.
    - resource: ca/1660ce02-bfb4-4a9f-8f38-1e91855d9531
      role: ca-manager
      groups: [pki-payments]

    # The team's leads own the whole payments branch, including sub-CAs created
    # later, and may delegate it onward.
    - resource: ca/1660ce02-bfb4-4a9f-8f38-1e91855d9531
      role: ca-admin
      scope: subtree
      groups: [pki-payments-leads]
      users: [payments-lead@example.com]

    # A release pipeline gets exactly the key it signs with.
    - resource: signing-key/release
      role: key-signer
      groups: [ci-release]
```

A tenant's own `tenants[].rbac.grants` block works identically. No extra scoping
is needed there: a grant already names one resource, and that resource already
belongs to exactly one tenant.

Validation is strict and happens at config load, so a mistake fails the server
start rather than quietly denying a team its CA:

- an unknown resource type, role, or scope is an error;
- a role that does not apply to the resource type is an error;
- an entry naming **no** users and **no** groups is an error — a grant that
  authorizes nobody is always a typo, and accepting it would hide the mistake.

---

## 7. Administering grants at runtime

Runtime grants live in the `resource_grants` table and are unioned with the
configured ones at decision time. Use them for delegations that change more often
than your configuration deploys.

Authority to administer grants is either `rbac:manage` **within the resource's
tenant**, or `resource:delegate` on the resource itself.

### Command line

```console
$ secsy-ca grant roles                       # what each role confers

$ secsy-ca grant add    -resource ca/1660ce02 -role ca-manager -group pki-payments
$ secsy-ca grant add    -resource ca/1660ce02 -role ca-admin   -group pki-leads -scope subtree
$ secsy-ca grant add    -resource signing-key/release -role key-signer -group ci-release

$ secsy-ca grant list   -resource ca/1660ce02          # both sources, one table
$ secsy-ca grant list                                  # every grant in the deployment

$ secsy-ca grant remove -resource ca/1660ce02 -role ca-manager -group pki-payments
```

The CLI operates directly on the store, like the rest of `secsy-ca`: it is the
bootstrap and break-glass path, usable before any operator can log in and while
the server is down. It refuses a grant on a CA id that does not exist, since an
inert grant is almost always a mistyped identifier.

### REST API

| Endpoint | Purpose |
|----------|---------|
| `GET /api/grants?resource=<type>/<id>` | list the grants on one resource (both sources; each carries `source: database \| config`) |
| `POST /api/grants` | delegate a resource role |
| `DELETE /api/grants` | revoke a stored grant |
| `GET /api/grants/effective?resource=…[&subject=…]` | what a principal may do here, and why |

```console
$ curl -X POST https://pki.example.com/api/grants \
    -H 'Authorization: Token secsy_pat_…' -H 'Content-Type: application/json' \
    -d '{"resource":"ca/1660ce02","entity_type":"group","entity_id":"pki-payments","role":"ca-manager"}'
```

Grants declared in configuration are **read-only** through the API: deleting one
returns `409` with a pointer to `rbac.grants`. Letting an API call silently
override a rule that version control still shows as active would make the
configuration unreadable as a source of truth.

### Console

The **Access** page lists the grants on a selected CA or key, grants new ones,
revokes stored ones (config-declared rows are marked and cannot be revoked
there), and renders the effective-access review described below.

---

## 8. Reviewing effective access

The hard question in any delegated model is not "what did I grant?" but "what
can this person actually do here, and why?". Both the CLI and the API answer it
by **replaying the real authorization decision** for every capability, so the
report cannot drift from what the gates enforce.

```console
$ secsy-ca grant effective -resource ca/382f01ad -subject lead@example.com -groups pki-payments-leads
Subject:  lead@example.com
Resource: ca/382f01ad-0118-4df6-bac1-538f188ad61f
Groups:   pki-payments-leads

Resource roles: ca-admin
Capabilities at this resource: audit:read, ca:configure, ca:manage, cert:issue, resource:delegate

Matching grants:
  RESOURCE     ROLE      ENTITY                    SCOPE    VIA
  ca/1660ce02  ca-admin  group:pki-payments-leads  subtree  inherited (subtree)
```

Note the `VIA` column: this CA was created *after* the grant was written, and
authority reached it by inheritance from an ancestor.

`GET /api/grants/effective` returns the same decision as JSON, including the
platform roles, tenant roles, resource roles, resulting capability set, and the
individual grants that matched. A caller may always introspect **itself**;
naming another subject is an access-control review and requires the same
authority as administering grants.

One limitation is worth knowing: reviewing *another* subject can only account
for group memberships recorded in the database. Groups asserted by an identity
provider are known at that subject's own login and are unknowable from another
operator's request. The CLI's `-groups` flag lets you supply them for a
"what-if" review.

---

## 9. What a grant reaches

A grant on a CA authorizes the endpoints that operate **that** CA:

- **Administration** (`ca-admin`, `ca-manager`) — rotate, retire, publish the
  chain, cross-sign, import an externally-signed certificate, delete the CA,
  create subordinates beneath it, and run a
  [bulk revocation](../operations/incident-response.md) on it.
- **Issuance** (`ca-issuer` and above) — issue, renew, revoke, suspend, and
  release certificates. That CA's profiles, restriction sets, and every
  pre-issuance gate ([lint](../issuance/certlint.md), [CAA](../issuance/caa.md),
  [CT](../issuance/certificate-transparency.md), name constraints, key
  blocklist) still apply exactly as they do for a tenant issuer: a grant decides
  *who may ask*, never *what may be minted*.
- **Configuration** (`ca-admin`, `ca-manager`) — that CA's profiles, restriction
  sets, and defaults.
- **Visibility** (all roles, including `ca-auditor`) — the CA appears in
  listings and its detail endpoints resolve. Without this a delegated operator
  would be told it may administer a CA it cannot see. A CA it was *not* granted
  stays invisible: the read path answers `404`, not `403`, so existence is not
  disclosed.

A grant on a signing key authorizes sign, verify, and public-key export
(`key-signer` and above) and key creation (`key-admin`) for **that key name**.
The key listing narrows to the granted keys for a principal with no tenant-wide
capability.

Deleting a CA deletes its grants, so an identifier that is later reused cannot
inherit authority delegated over the CA that is gone.

### Deliberate boundaries

Some capabilities are **never** reachable through a grant, because they are not
properties of one resource:

- `hsm:manage`, `token:manage`, `webhook:manage`, `server:profile`, and
  tenant-wide `rbac:manage` — a grant on one CA must not become deployment-wide
  authority.
- Creating a **root** CA, or any CA with no parent, is tenant-level: there is no
  resource to hold the grant. It requires `ca:manage` in the tenant.
- [Four-eyes approval](approvals.md) gates are unaffected. If CA rotation is a
  guarded class, a delegated `ca-admin` requesting a rotation still parks for a
  distinct approver. A grant satisfies the capability check, not dual control.
- The legacy per-CA `SIGN_CERTIFICATE` / `MANAGE_PERMISSIONS` / `CONFIGURE_CA`
  permissions keep working unchanged and are evaluated alongside grants.

---

## 10. Audit

Delegation is itself a privileged operation and is recorded in the
[hash-chained event log](rbac-and-audit.md#2-tamper-evident-audit-logging):

| Action | Recorded when |
|--------|---------------|
| `resource.grant` | authority over a resource is delegated (or the attempt is denied) |
| `resource.revoke` | a stored grant is withdrawn |

Each entry carries the resource, the entity, the role, and the scope. These are
kept distinct from the legacy `permission.grant` / `permission.revoke` actions so
an access review can tell a three-verb CA ACL change apart from a role-bearing
resource delegation.

Authorization decisions made through grants are counted by the existing
`secsy_authz_decisions_total{action,result}` metric, so a spike in denials at a
delegated CA is visible on the
[usual dashboards](../operations/observability.md).

---

## See also

- [Delegated CA administration example](../../examples/delegated-ca-administration/README.md) — a runnable walkthrough of this page
- [RBAC, audit logging & config](rbac-and-audit.md) — the platform/tenant role layer beneath grants
- [Multi-tenant isolation](multi-tenancy.md) — the boundary a grant lives inside
- [Operator authentication](authentication.md) — how a principal's subject, verified email, and groups are established

---

↩ Back to [security & governance](README.md) · [documentation map](../README.md)
