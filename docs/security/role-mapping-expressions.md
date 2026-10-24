# Role-mapping expressions (CEL)

*Mapping an identity provider's group names to RBAC roles when the group names
encode structure — without a config change per team.*

A [role mapping](authentication.md#claim--group--rbac-role-mapping) says which
RBAC roles an identity gets. The simplest form names one claim value:

```yaml
role_mappings:
  - { value: "pki-admins", roles: ["admin"] }
```

That is the right answer for a handful of named groups, and it should stay the
default. It stops being the right answer the moment the organization's group
names *carry* the structure:

```
pki-issuers-acme-corp        pki-issuers-globex        pki-issuers-initech
CN=PKI-Admins-emea,OU=Groups,DC=corp,DC=example,DC=com
repo:example-org/app:environment:release
```

Enumerating those means one mapping per team per environment, a config change
and a deploy for every new team, and an enumeration that silently drifts from
the directory the day someone adds a group. A **CEL expression** says the rule
instead of the instances:

```yaml
role_mappings:
  # Any group named pki-issuers-<tenant> grants issuer in THAT tenant.
  - expression: 'groups.exists(g, g.startsWith("pki-issuers-"))'
    tenant_expression: |
      groups.filter(g, g.startsWith("pki-issuers-"))
            .map(g, g.replace("pki-issuers-", ""))
    roles: ["issuer"]
```

A new team creates `pki-issuers-newco` in the IdP, the tenant `newco` exists in
this deployment, and the mapping already covers it.

> **Where this applies.** Every `role_mappings:` list takes the same fields:
> `auth.oidc.role_mappings` and each `auth.oidc.providers[].role_mappings`
> (console login), each `oidc.providers[].role_mappings` (machine Bearer
> tokens), and `auth.ldap.role_mappings` (directory login). One implementation
> serves all of them, so an expression behaves identically whichever
> mechanism authenticated the caller.

---

## 1. Why CEL, and not a scripting language

[CEL](https://cel.dev) (Common Expression Language) is non-Turing-complete by
construction: no loops, no recursion, no I/O, no mutation, no state. An
expression is a **total function of the inputs it is handed** — it terminates,
and its cost is bounded before it runs.

That is what makes it safe to evaluate operator-written text on the
authentication path. The expression cannot read a file, open a socket, read the
clock, or reach anything other than the variables below; embedding a general
interpreter there would be a remote-code-execution surface wearing a config
field's clothing.

Three further guards apply:

- **Expressions compile at startup**, not at login. A syntax error, an
  undeclared variable, or an expression whose result is not the right type is a
  **load error** with a line and a caret in it. The server refuses to start
  rather than coming up and denying the operators it was configured to admit.
- **Every evaluation is cost-bounded** (500,000 CEL cost units). An anchored
  `groups.exists(g, g.matches(…))` costs ~10 units per group inspected; the
  heaviest shape a mapping has reason to write — filter the groups, extract a
  tenant id from each survivor — costs ~87 units per group, so ~44,000 over a
  500-group principal. What the ceiling stops is a quadratic comprehension over
  a claim whose size the caller controls.
- **Every failure is fail-closed.** `false`, an evaluation error, or a cost
  overrun all mean *this mapping grants nothing*. A broken mapping never denies
  what the other mappings authorize, and it never grants more than it matched.

---

## 2. The variables

An expression sees the authenticated identity, whichever mechanism produced it:

| Variable | Type | Holds |
|---|---|---|
| `subject` | `string` | The stable principal id — the OIDC `sub` claim, or the directory subject |
| `email` | `string` | The asserted address, `""` when there is none |
| `email_verified` | `bool` | Whether the IdP (or the directory) vouched for that address |
| `name` | `string` | Display name, `""` when there is none |
| `username` | `string` | Directory username / `preferred_username`, `""` when there is none |
| `issuer` | `string` | The token issuer (`iss`); `""` for a directory login |
| `provider` | `string` | The configured name of the provider that authenticated this caller |
| `groups` | `list(string)` | Group memberships: the configured `groups_claim`, the directory groups, and the internal groups the store records — the union the login resolved |
| `claims` | `map(string, dyn)` | Every verified claim, by name |

The scalar fields are always present and default to empty, so the common
expression needs no guard:

```yaml
- expression: 'email_verified && email.endsWith("@corp.example.com")'
  roles: ["auditor"]
```

Anything outside that fixed set is reached through `claims`, where a missing key
is an **error** rather than a null — so guard it with `has()`:

```yaml
- expression: 'has(claims.department) && claims.department == "pki"'
  roles: ["auditor"]
```

An unguarded `claims.department` on a token that omits the claim is an
evaluation error: the mapping grants nothing and the server logs a warning. That
is deliberate — silently reading a typo'd claim name as "no match" is how a
mapping comes to look correct and do nothing.

Print the live list, with types, from the deployment itself:

```console
$ secsy-ca role-mapping reference
```

---

## 3. The functions

The CEL standard library, plus four upstream extension libraries. Nothing else:

| Family | Functions |
|---|---|
| Operators | `== != < <= > >= && \|\| ! in`, ternary `a ? b : c` |
| Macros | `has(claims.x)`, `l.all(x, p)`, `l.exists(x, p)`, `l.exists_one(x, p)`, `l.map(x, f)`, `l.filter(x, p)` |
| Strings (standard) | `size(s)`, `s.contains(sub)`, `s.startsWith(p)`, `s.endsWith(p)`, `s.matches(re2)` |
| Strings (ext) | `s.charAt(i)`, `s.indexOf(sub)`, `s.lastIndexOf(sub)`, `s.lowerAscii()`, `s.upperAscii()`, `s.replace(old, new)`, `s.split(sep)`, `s.substring(i, j)`, `s.trim()`, `s.reverse()`, `l.join(sep)`, `strings.quote(s)`, `s.format([…])` |
| Regex | `regex.replace(s, re, repl)`, `regex.extract(s, re) → optional<string>`, `regex.extractAll(s, re)` |
| Optionals | `opt.orValue(default)`, `opt.hasValue()`, `opt.value()` |
| Sets | `sets.contains(a, b)`, `sets.equivalent(a, b)`, `sets.intersects(a, b)` |
| Lists | `l.distinct()`, `l.flatten()`, `l.reverse()`, `l.slice(i, j)`, `l.sort()`, `l.sortBy(x, k)`, `lists.range(n)` |

Regular expressions are **RE2** (Go's `regexp`): linear-time matching, no
backtracking, so a pattern cannot be made to run away. `regex.replace` takes
numeric capture-group references (`\1`…`\9`); `regex.extract` returns an
*optional*, so no match is an explicit `none` and `.orValue("")` is how the
expression states what it wants to happen then.

---

## 4. Deriving the tenant

`tenant_expression` yields the tenant id — or a **list** of them, so one mapping
can grant the same role in every tenant a principal's groups encode:

```yaml
# Group names: pki-issuers-acme-corp, pki-issuers-globex
- expression: 'groups.exists(g, g.startsWith("pki-issuers-"))'
  tenant_expression: |
    groups.filter(g, g.startsWith("pki-issuers-"))
          .map(g, g.replace("pki-issuers-", ""))
  roles: ["issuer"]

# Active Directory group DNs: CN=PKI-Admins-emea,OU=Groups,DC=corp,DC=example,DC=com
- expression: 'groups.exists(g, g.matches("^CN=PKI-Admins-[a-z0-9-]+,OU=Groups,DC=corp,DC=example,DC=com$"))'
  tenant_expression: |
    groups.filter(g, g.startsWith("CN=PKI-Admins-"))
          .map(g, regex.extract(g, "^CN=PKI-Admins-([a-z0-9-]+),").orValue(""))
  roles: ["admin"]
```

Two rules make this safe to write:

1. **An empty result grants nothing.** In static configuration an omitted
   `tenant:` means *platform-wide* — authority across every tenant. A
   `tenant_expression` that extracted nothing is **not** read that way: the
   mapping contributes nothing at all. A pattern that fails to find the tenant
   must never escalate out of it.
2. **A derived id must name a declared tenant.** When the deployment declares
   `tenants:`, a derived id outside that set grants nothing — so
   `pki-issuers-ACME` against a tenant called `acme` is a visible no-grant
   rather than roles in a tenant that does not exist and would start granting
   the day somebody creates it. A derived id must also *look* like an id
   (`[A-Za-z0-9][A-Za-z0-9._:@-]{0,63}`): unlike a literal in the config file,
   it is a function of claim values the IdP controls, and it goes on to key role
   maps, log lines and audit records.

`tenant` and `tenant_expression` are mutually exclusive, as are `value` and
`expression` — a mapping that matched two ways would be a mapping nobody can
read.

---

## 5. Worked example: a CI pipeline

A machine-token provider can key on the workload identity itself. GitHub
Actions puts the repository, the ref and the environment in `sub`:

```yaml
oidc:
  providers:
    - name: github
      issuer_url: "https://token.actions.githubusercontent.com"
      client_id: "secsy-pki-signing"          # the audience the workflow requests
      role_mappings:
        # Any repository in the org, but only its `release` environment.
        - expression: 'subject.matches("^repo:example-org/[a-z0-9-]+:environment:release$")'
          roles: ["signer"]
```

`signer` and `issuer` are deliberately separate roles, so a pipeline credential
that signs artifacts cannot mint certificates. See
[GitHub OIDC signing](../../examples/github-oidc-signing/README.md) for the
full workflow, and [multiple OIDC providers](authentication.md#multiple-oidc-providers)
for why a provider's mappings are evaluated only for tokens it verified.

---

## 6. Try it before you ship it

`secsy-ca role-mapping` reads the config file and nothing else — no database, no
HSM, no reachable IdP — and answers with the same compiled mappers the server
builds at startup.

```console
$ secsy-ca role-mapping list
auth.oidc (console provider "corp") — groups claim "groups"
  #  MATCH                                                TENANT                                     ROLES
  0  groups="pki-admins"                                  <platform-wide>                            admin
  1  CEL: groups.exists(g, g.startsWith("pki-issuers-"))  CEL: groups.filter(g, g.startsWith("pki…   issuer
```

Dry-run an identity. `-group` is repeatable and is taken **verbatim** (the
commas in a DN are part of it, not separators):

```console
$ secsy-ca role-mapping test \
    -email alice@corp.example.com -email-verified \
    -group pki-issuers-globex \
    -group 'CN=PKI-Admins-acme-corp,OU=Groups,DC=corp,DC=example,DC=com'
auth.oidc (console provider "corp") — groups claim "groups"
  [0] —        groups="pki-admins" tenant=<platform-wide> roles=[admin]
  [1] MATCHED  expression=groups.exists(…) tenant_expression=groups.filter(…) roles=[issuer]
        tenants: globex
  [2] MATCHED  expression=groups.exists(g, g.matches("^CN=PKI-Admins-…")) roles=[admin]
        tenants: acme-corp
  => platform roles: (none)
  => tenant "acme-corp" roles: admin
  => tenant "globex" roles: issuer
```

A mapping is reported `MATCHED` only when it actually grants something. When the
match half applied and the mapping *still* granted nothing, it is reported
`FIRED` instead, with the reason — the refused tenant id, the evaluation error
that `ResolveIdentity` swallows at login, or a tenant expression that resolved
to nothing. That distinction is the difference between "fix the pattern" and
"fix the tenant expression":

```console
$ secsy-ca role-mapping test -group pki-issuers-typo
  [1] FIRED    expression=groups.exists(…) …
        refused tenant "typo": not a declared tenant id, or not a usable one
  => platform roles: (none)
```

Write an expression without touching the config file at all:

```console
$ secsy-ca role-mapping test \
    -expression 'groups.exists(g, g.startsWith("pki-signers-"))' \
    -tenant-expression 'groups.filter(g, g.startsWith("pki-signers-")).map(g, g.replace("pki-signers-", ""))' \
    -roles signer -group pki-signers-acme-corp
```

Add `-json` to any of these for the structured form — the decisions, the
resolved roles, and the identity exactly as the expression saw it. `-claims
'{"…": …}'` (or `-claims @file.json`) supplies the full claim set when an
expression reads `claims`.

---

## 7. Writing expressions that cannot be gamed

An expression decides who administers the PKI. The group names it reads are
asserted by the IdP, and in some directories a user can influence them.

- **Anchor every pattern.** `g.matches("^CN=PKI-Admins-[a-z0-9-]+,OU=Groups,DC=corp,DC=example,DC=com$")`
  — not `g.contains("PKI-Admins")`, which also matches
  `CN=PKI-Admins-x,OU=Contractors,…` and `CN=Not-PKI-Admins-x,…`. The regression
  test for this feature asserts exactly those near misses.
- **Constrain the extracted part.** `[a-z0-9-]+`, not `.*`: the capture becomes
  a tenant id. The declared-tenant check is a backstop, not the fence.
- **Prefer `email_verified` over `email` alone.** An IdP where a user sets their
  own address otherwise lets them claim another principal's roles — the same
  rule the central `rbac` email assignments enforce.
- **Scope cross-issuer trust deliberately.** Mappings written under
  `auth.oidc.role_mappings` apply to *every* console provider; a mapping that
  should only honour one IdP belongs on that provider.
- **Keep platform-wide grants few.** A platform role spans all tenants. Prefer a
  `tenant` or a `tenant_expression`, and let the central
  [`rbac`](rbac-and-audit.md) block name the handful of platform operators.

Roles resolved from mappings are **unioned** with the central
`rbac.subjects` / `rbac.groups` assignments and with the
[resource grants](resource-grants.md); mappings can only ever add. An operator
who resolves to no role at all is denied at login unless
`auth.oidc.allow_zero_role` is set.

---

## 8. Where it lives

| Concern | Code |
|---|---|
| The CEL environment, function library, compile + cost ceiling | `server/internal/celexpr` |
| Mapping evaluation, tenant derivation, fail-closed rules | `server/internal/authn/mapping.go` |
| Load-time validation of every `role_mappings` list | `server/internal/config/config.go` (`validateClaimMappings`) |
| Startup wiring, per-provider mappers, error logging | `server/cmd/server/auth.go` (`newClaimMapper`) |
| The dry-run CLI | `server/cmd/secsy-ca/rolemapping.go` |

---

↩ Back to [security & governance](README.md) · [operator authentication](authentication.md) · [documentation map](../README.md)
