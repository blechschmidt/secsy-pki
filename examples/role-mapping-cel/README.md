# CEL role mappings — group names that encode the tenant

*One mapping per role instead of one per role × tenant, and a dry-run that
proves what a login will resolve to before anyone logs in.*

A deployment serving three business units. Identity lives in Active Directory
and reaches the console through the corporate IdP. Both assert group names that
**carry** the structure:

```
pki-admins-acme-corp     pki-issuers-acme-corp
pki-admins-globex        pki-issuers-globex
pki-admins-initech       pki-issuers-initech
CN=PKI-Auditors-globex,OU=Groups,DC=corp,DC=example,DC=com
```

Enumerated as exact-value mappings that is 3 roles × 3 tenants = **9 rows**,
growing by three every time a business unit is onboarded — and silently wrong
the day someone creates a group nobody added to the file.
[`config.yaml`](config.yaml) writes the *rule* instead:

```yaml
- expression: 'groups.exists(g, g.matches("^pki-issuers-[a-z0-9-]+$"))'
  tenant_expression: |
    groups.filter(g, g.matches("^pki-issuers-[a-z0-9-]+$"))
          .map(g, g.replace("pki-issuers-", ""))
  roles: ["issuer"]
```

Onboarding a business unit is then one `tenants:` row. The mappings already
cover it.

## What the example shows

| | |
|---|---|
| **One row per role** | `pki-admins-<tenant>` → `admin` in that tenant, `pki-issuers-<tenant>` → `issuer`, for every tenant |
| **A list of tenants** | `tenant_expression` yields a *list*, so an operator in `pki-admins-globex` **and** `pki-issuers-acme-corp` gets both roles in their own tenants |
| **Directory DNs** | `regex.extract` pulls the tenant out of `CN=PKI-Auditors-<tenant>,OU=Groups,…`, with the OU anchored so a look-alike in `OU=Contractors` cannot match |
| **An identity-field rule** | `email_verified && email.endsWith("@audit.corp.example.com")` grants read-only without any group at all |
| **A machine pattern** | one anchored `subject` pattern covers every repository in the GitHub org, for the `release` environment only |
| **The fence** | a derived tenant id must name a tenant declared in `tenants:` — `pki-issuers-acme-crop` grants nothing |

## Walk through it offline

No IdP, no directory, no HSM, no database: `role-mapping` reads the config file
and nothing else, and answers with the same compiled mappers the server builds
at startup.

```console
$ cd examples/role-mapping-cel
$ secsy-ca -config config.yaml role-mapping list
auth.oidc (console provider "default") — groups claim "groups"
  #  MATCH                                                             TENANT                                  ROLES
  0  CEL: groups.exists(g, g.matches("^pki-admins-[a-z0-9-]+$"))       CEL: groups.filter(g, g.matches("^pki…  admin
  1  CEL: groups.exists(g, g.matches("^pki-issuers-[a-z0-9-]+$"))      CEL: groups.filter(g, g.matches("^pki…  issuer
  2  groups="pki-platform-admins"                                      <platform-wide>                         admin
  3  CEL: email_verified && email.endsWith("@audit.corp.example.com")  <platform-wide>                         auditor
…
```

**An operator who administers one unit and issues in another.** One mapping set,
two tenants, no platform-wide authority:

```console
$ secsy-ca -config config.yaml role-mapping test -source default \
    -group pki-admins-globex -group pki-issuers-acme-corp
  [0] MATCHED  expression=groups.exists(g, g.matches("^pki-admins-…")) … roles=[admin]
        tenants: globex
  [1] MATCHED  expression=groups.exists(g, g.matches("^pki-issuers-…")) … roles=[issuer]
        tenants: acme-corp
  [2] —        <groups claim>="pki-platform-admins" tenant=<platform-wide> roles=[admin]
  [3] —        expression=email_verified && email.endsWith("@audit.corp.example.com") …
  => platform roles: (none)
  => tenant "acme-corp" roles: issuer
  => tenant "globex" roles: admin
```

**A directory auditor.** `-group` is repeatable and taken **verbatim** — the
commas in a DN are part of it, not separators:

```console
$ secsy-ca -config config.yaml role-mapping test -source ldap \
    -group 'CN=PKI-Auditors-initech,OU=Groups,DC=corp,DC=example,DC=com' \
    -group 'CN=PKI-Auditors-evil,OU=Contractors,DC=corp,DC=example,DC=com'
  [0] MATCHED  expression=groups.exists(g, g.matches("^CN=PKI-Auditors-…,OU=Groups,…$")) … roles=[auditor]
        tenants: initech
  => tenant "initech" roles: auditor
```

The contractor-tree group is ignored: the pattern is anchored on `OU=Groups`,
so a group named to look like a PKI group elsewhere in the directory matches
nothing.

**A group naming a tenant that does not exist.** The pattern fires, the id does
not name a declared tenant, and the mapping therefore grants nothing — said out
loud rather than reported as a plain non-match:

```console
$ secsy-ca -config config.yaml role-mapping test -source ldap \
    -group 'CN=PKI-Auditors-newco,OU=Groups,DC=corp,DC=example,DC=com'
  [0] FIRED    expression=groups.exists(…) …
        refused tenant "newco": not a declared tenant id, or not a usable one
  => platform roles: (none)
```

`FIRED` rather than `—`: the match half applied and the mapping still granted
nothing. That is the difference between "fix the pattern" and "fix the tenant
expression", and the report says which.

Declare `newco` under `tenants:` and the same group starts working. That is the
onboarding step, and it is the only one.

**Writing a new expression.** Try it before it goes in the file:

```console
$ secsy-ca -config config.yaml role-mapping test \
    -expression 'groups.exists(g, g.startsWith("pki-signers-"))' \
    -tenant-expression 'groups.filter(g, g.startsWith("pki-signers-")).map(g, g.replace("pki-signers-", ""))' \
    -roles signer -group pki-signers-globex
```

And the vocabulary the deployment actually supports — variables with their
types, every function family, the cost ceiling:

```console
$ secsy-ca role-mapping reference
```

Add `-json` to any of these for the structured form: the per-mapping decisions,
the resolved roles, and the identity exactly as the expression saw it.

## Two rules worth internalizing

**An unextracted tenant grants nothing.** In static configuration an omitted
`tenant:` means *platform-wide* — authority across every tenant. A
`tenant_expression` that resolved to nothing is deliberately **not** read that
way; the mapping contributes nothing at all. A pattern that fails to find the
tenant must never escalate out of it.

**Make the tenant filter as strict as the match.** The two expressions are
evaluated independently. If `expression` anchors on `OU=Groups` but
`tenant_expression` filters on a bare `startsWith("CN=PKI-Auditors-")`, the
tenant expression will happily extract an id out of a group the match expression
rejected — leaving the declared-tenant list as the only thing between a
contractor group and a role. The config here repeats the full anchored pattern
in both for exactly that reason.

## Try it for real

```console
# From the repo root, with SoftHSM set up (scripts/setup-softhsm.sh)
$ cd server && go build -tags sqlite -o ../bin/secsy-pki-server ./cmd/server
$ go build -tags sqlite -o ../bin/secsy-ca ./cmd/secsy-ca

# Point the config at your IdP / directory, then
$ ../bin/secsy-pki-server -config ../examples/role-mapping-cel/config.yaml
```

A mapping whose expression does not compile is a **startup error** with a line
and a caret in it — the server refuses to start rather than coming up and
denying the operators it was configured to admit. An expression that fails at
*evaluation* (an unguarded `claims.x` on a token that omits it) is per-request:
that mapping grants nothing, the others still apply, and the server logs a
warning naming the mapping.

---

**Reference:** [role-mapping expressions](../../docs/security/role-mapping-expressions.md)
· [operator authentication](../../docs/security/authentication.md)
· [multi-tenant isolation](../../docs/security/multi-tenancy.md)
· [per-CA authorization](../../docs/security/resource-grants.md)

↩ Back to the [examples catalogue](../README.md)
