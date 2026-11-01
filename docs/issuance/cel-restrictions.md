# CEL issuance restrictions

*Operator-written rules, evaluated before every signature, that say **why** a
certificate was refused.*

The other pre-issuance gates each encode somebody else's rules: the
[lint gate](certlint.md) the CA/Browser Forum's, [CAA](caa.md) the domain
owner's, [name constraints](name-constraints.md) the issuing CA's own, the
[key-quality gate](key-checks.md) the Baseline Requirements'. This one encodes
**yours** — the policy an enterprise invents that no fixed configuration field
anticipated:

- a wildcard only for a caller whose token carries the `pki.wildcard`
  entitlement;
- DNS names only under the namespace the requester's directory group encodes;
- a two-year lifetime only with an `O=` that matches the tenant;
- IP SANs only inside `10.0.0.0/8`;
- a change ticket in the request body, or no certificate.

Each of those is a relationship between facts that live in different places —
the CSR, the token, the HTTP request — which is exactly what a declarative
allow-list cannot express. Enumerating them as configuration fields would mean a
new field, a new release and a new deploy for every policy anyone invents.

## At a glance

| | |
|---|---|
| **Where it runs** | `ca.Manager.buildLeaf`, last of the pre-issuance gates, before any HSM signature |
| **Which paths** | every one: REST, gRPC, CLI, ACME, EST, SCEP, CMP, MS-WSTEP, BRSKI, bulk, PKCS#12, SPIFFE SVID, the canary |
| **Where rules live** | the `cel_policy_rules` table — editable at runtime, no restart, no config reload |
| **Who may edit** | `ca:configure` (admin). Reading and dry-running: any role |
| **Console** | the **Issuance Policy** view: table, editor with a compile check, dry-run, vocabulary reference |
| **CLI** | `secsy-ca issuance-policy list\|show\|add\|update\|enable\|disable\|delete\|test\|reference` |
| **REST** | `/api/issuance-policies` (+ `/{id}`, `/{id}/enabled`, `/validate`, `/test`, `/reference`) |
| **Refusal** | HTTP **422** with `{error, code: "policy_denied", violations: [{rule, message}]}` |
| **Audit** | `cert.policy` (the gate), `policy.rule.create` / `.update` / `.delete` (administration) |
| **Metrics** | `secsy_certificate_policy_checks_total`, `…_violations_total`, `…_rule_errors_total` |
| **Failure mode** | **fail-closed** — a rule that cannot be evaluated refuses the request |

## Why CEL

[CEL](https://cel.dev) (Common Expression Language) is non-Turing-complete by
construction: no loops, no recursion, no I/O, no mutation. A rule is a total
function of the facts it is handed, it terminates, and its cost is bounded
*before* it runs. Those properties are what make it safe to evaluate
operator-written text on the signing path, where an embedded interpreter would
be a remote-code-execution surface.

Three consequences worth knowing:

- **A field typo is a load error, not a denied certificate.** The request, the
  URL and the caller are declared as *typed objects*, so `request.dsn_names`
  fails to compile with a column number instead of failing at issuance time.
- **An expression cannot reach ambient state.** There is no way to read a file,
  open a socket, read the clock or see anything other than the variables it was
  handed. (Evaluation time arrives as the `now` variable, read by the server.)
- **A pathological expression cannot burn the signing path.** Every evaluation is
  bounded at 500,000 CEL cost units; exceeding that aborts and — fail-closed —
  refuses the request.

The same engine and the same function library back the
[role-mapping expressions](../security/role-mapping-expressions.md).

## What a rule sees

| Variable | Type | Holds |
|---|---|---|
| `request` | object | the certificate request: subject, every SAN type, requested validity, key, profile, issuing CA |
| `jwt` | map | every **verified** claim of the token the caller presented; empty when they presented none |
| `url` | object | the HTTP request: `method`, `scheme`, `host`, `port`, `path`, `segments`, `query`, `raw_query`, `client_ip`, `present` |
| `path` | string | the full request path — the same value as `url.path`, for the common case |
| `body` | map | the decoded request body parameters, by name |
| `principal` | object | the authenticated caller: `subject`, `email`, `roles`, `tenant_roles`, `tenants`, `groups`, `is_root`, `authenticated` |
| `now` | timestamp | evaluation time, UTC |

The authoritative list — including every field of each object, with its type — is
served by the running server and rendered by the console and the CLI:

```bash
secsy-ca issuance-policy reference          # or: curl /api/issuance-policies/reference
```

### `request`

The certificate facts are read from the **to-be-signed template**, not from any
one surface's request shape. That is what makes a rule true of the certificate
rather than of one protocol's JSON: a validity clamped to the profile maximum, a
mailbox normalized by the S/MIME gate, a Must-Staple extension stamped by the
profile — a rule sees the values the certificate will actually carry.

| Field | Type | Notes |
|---|---|---|
| `source` | string | the surface: `rest`, `grpc`, `acme`, `est`, `scep`, `cmp`, `wstep`, `bulk`, `pkcs12`, `spiffe`, `canary`, `cli`, `preview`, `unknown` |
| `operation` | string | `issue`, `renew`, `preview` |
| `profile` | string | the issuance profile's name |
| `ca` | object | `id`, `label`, `tenant`, `subject` (RFC 2253), `not_after` |
| `subject` | object | `common_name`, `organization`, `organizational_unit`, `country`, `locality`, `province`, `street_address`, `postal_code`, `serial_number`, `dn` |
| `dns_names`, `ip_addresses`, `email_addresses`, `uris`, `upns` | list(string) | the SANs; IPs and URIs rendered as strings so `ip()`/`cidr()` and the string functions consume them |
| `san_count` | int | the total across every SAN type |
| `wildcard` | bool | true when any DNS name is a leading-label wildcard |
| `key_usages`, `ext_key_usages` | list(string) | named as a profile names them (`digitalSignature`, `serverAuth`) |
| `extension_oids` | list(string) | dotted OIDs of the extra extensions the template carries |
| `is_ca`, `max_path_len` | bool, int | `max_path_len` is `-1` when the request sets none |
| `must_staple` | bool | the resolved RFC 7633 decision |
| `not_before`, `not_after` | timestamp | the resolved validity window |
| `validity` | duration | `not_after - not_before`, exactly |
| `validity_days` | int | the same in **whole days, truncated** — the figure the preview and the API report |
| `key` | object | `algorithm` (`RSA`/`ECDSA`/`Ed25519`/`unknown`), `size`, `curve`, `fingerprint` (`SHA256:…`) |
| `algorithm` | string | the signature family: `classical`, `pqc`, `hybrid` |
| `serial` | string | the allocated serial, decimal |
| `requested_by` | string | the identity the issuance is attributed to |

!!! note "`validity_days` truncates"
    A template's `notBefore` is backdated by a few minutes of clock skew, so a
    90-day request spans 90 days *and change*. `validity_days` truncates to whole
    days — the same arithmetic the preview response and the API's
    `validity_days` use — so `request.validity_days <= 90` does not refuse the
    very request the profile was configured to allow. Compare
    `request.validity` (a duration) when you need the exact window.

### `jwt`

Only claims a verifier **accepted** reach a rule. `sub`, `email`, `iss` and
`aud` are filled in from what the verifier resolved (and `aud` is always a list,
even when the token carried a bare string), so those four can be relied on;
everything else is the raw claim set, which is what lets a rule inspect
`jwt.groups`, `jwt.repository` or whatever entitlement vocabulary the identity
provider uses without this PKI enumerating them.

A map lookup of a key that is not present is a **runtime error**, which
fail-closed means *refused*. Guard it:

```cel
has(jwt.entitlements) && "pki.wildcard" in jwt.entitlements
```

### `url`, `path` and `body`

Captured at the HTTP edge for every request and carried to the gate on the
request context. `body` is decoded when the body is a JSON object or an HTML
form, and only up to 256 KiB — a binary enrollment payload (PKCS#10, PKCS#7,
CMP) or an oversize body is passed through untouched and exposes no parameters,
because a *truncated* view would be worse than none. `client_ip` is the peer
address, deliberately **not** `X-Forwarded-For`: a header the client sets must
not be what a restriction rule trusts.

An automated enrollment carries no token, no JSON body and no console URL. Those
facts are then empty and `url.present` is false — so a rule that requires an
entitlement **refuses** such a request rather than passing it. That is the
correct reading, and `request.source` is how a rule treats a protocol enrollment
differently on purpose.

## What a rule says

A rule's expression may evaluate to one of three shapes, and the shape is how it
reports itself:

| Result | Meaning |
|---|---|
| `bool` | the condition that must hold (effect `require`) or must not (effect `deny`). The reason reported is the rule's `message` |
| `string` | **the reason itself**: `""` means satisfied, any other text refuses and is what the requester is shown |
| `list(string)` | several reasons at once — one per offending name. An empty list means satisfied |

The string forms are why this engine exists in an enterprise PKI. Compare:

```cel
# bool: correct, but the requester learns only "too long"
request.validity_days <= 90
```

```cel
# string: the requester learns the number they exceeded
request.validity_days <= 90 ? "" :
  "requested %d days of validity; this profile allows at most 90".format([request.validity_days])
```

```cel
# list(string): the requester learns every offending name at once
request.dns_names
  .filter(d, !(d.endsWith(".example.com") || d == "example.com"))
  .map(d, "DNS name " + d + " is outside example.com, which this CA may not certify")
```

Every applicable rule is evaluated — a requester who got three things wrong is
told three things, rather than discovering them one retry at a time. `priority`
(ascending) fixes the order the reasons are read in.

## Rule fields

| Field | Default | Meaning |
|---|---|---|
| `name` | — | unique, whitespace-free. It appears in the refusal and in the audit record, and resolves the rule through `GET /api/issuance-policies/{name}` |
| `expression` | — | the CEL text |
| `message` | — | the reason a **boolean** rule reports; ignored when the expression produces its own text. Falls back to `description`, then to a sentence naming the rule |
| `effect` | `require` | `require` — the condition must hold; `deny` — it must not. Boolean results only |
| `mode` | `enforce` | `enforce` — refuse; `monitor` — record the finding and issue anyway |
| `profiles` | all | profile names or globs the rule applies to, case-insensitive |
| `cas` | all | issuing CA ids or labels or globs, case-insensitive |
| `tenant_id` | all | restrict the rule to one tenant's CAs |
| `priority` | `0` | ascending evaluation order; fixes the order reasons are reported in |
| `enabled` | `true` (API) / `false` (console form) | a disabled rule is kept, not deleted |
| `fail_open` | `false` | permit issuance when **this rule's own** evaluation fails |

!!! warning "Fail-closed is the default, and it is the point"
    A rule that errors at runtime, returns an unusable type or blows the cost
    ceiling **refuses** the request, with a message that says the rule could not
    be checked rather than blaming the requester. A restriction engine that
    permits what it could not check is not a restriction engine. `fail_open`
    exists for a rule an operator deliberately accepts as best-effort.

## Writing a rule safely

A wrong rule refuses every certificate under its scope, so the workflow is
**write disabled → dry-run → enable** (or **monitor → measure → enforce**).

```bash
# 1. Write it, switched off.
secsy-ca issuance-policy add -name max-lifetime -disabled \
  -expr 'request.validity_days <= 90 ? "" :
         "requested %d days of validity; this profile allows at most 90".format([request.validity_days])'

# 2. Dry-run it against a real CSR under the real CA and profile. The facts are
#    derived by the same code the gate uses, so this is not an approximation.
secsy-ca issuance-policy test -rule max-lifetime \
  -ca issuing -profile server -csr request.pem -validity-days 400
# WOULD BE REFUSED — 1 rule(s) evaluated, 0 skipped
# Reasons:
#   - max-lifetime: requested 397 days of validity; this profile allows at most 90

# 3. Switch it on.
secsy-ca issuance-policy enable max-lifetime
```

`issuance-policy test` exits non-zero when the request would be refused, so a
pipeline can gate on it.

The dry-run also accepts a JSON fact set for everything a CSR cannot carry — the
token's claims, the request URL, the body parameters, the caller's identity:

```bash
cat > facts.json <<'JSON'
{
  "request": { "profile": "server", "dns_names": ["*.example.com"] },
  "jwt":     { "sub": "ops@example.com", "entitlements": ["pki.issue"] },
  "url":     { "method": "POST", "path": "/api/ca/ca-1/issue", "present": true },
  "body":    { "reason": "CHG-10482" },
  "principal": { "subject": "ops@example.com", "roles": ["issuer"], "authenticated": true }
}
JSON
secsy-ca issuance-policy test -rule wildcard-entitlement -facts facts.json
```

### Monitor mode

`-mode monitor` records what a rule *would* have refused — in the decision, in
the `cert.policy` audit event (with `ResultSuccess`, because the certificate was
issued) and in `secsy_certificate_policy_violations_total{mode="monitor"}` — and
issues anyway. It is the difference between a policy an enterprise can adopt and
one it dare not switch on. Measure, then flip the rule to `enforce`; the next
request is governed, with no restart.

### The preview agrees with the gate

[`secsy-ca issue -dry-run`](preview.md), `POST
/api/ca/{id}/certificates:preview` and the console's preview button all report a
`cel_policy` gate verdict, evaluated through the same evaluator the issuance path
enforces — `pass`, `fail` (with one finding per reason), `warn` (monitor-mode
findings only), or `skipped` when no rule applies. A dry-run that says "accept"
is not promising something a rule will then refuse.

## What the requester sees

```http
POST /api/ca/ca-1/issue
→ 422 Unprocessable Content

{
  "error": "requested 365 days of validity; this profile allows at most 30 (policy rule \"max-lifetime\"); DNS name a.evil.test is outside example.com (policy rule \"dns-suffix\")",
  "code": "policy_denied",
  "violations": [
    { "rule": "max-lifetime", "message": "requested 365 days of validity; this profile allows at most 30", "mode": "enforce" },
    { "rule": "dns-suffix",   "message": "DNS name a.evil.test is outside example.com",                    "mode": "enforce" }
  ]
}
```

**422, not 403.** The caller's credentials were accepted and their permission to
issue was never in question — the *content* of the request is what policy
refused. A client that tells the two apart can fix the request rather than go
hunting for a missing role. The reasons travel twice: once as a sentence in
`error`, for a human or a CLI, and once per rule in `violations`, for a client
that renders them.

On the protocol paths the refusal becomes that protocol's error, carrying the
same text — an ACME `urn:ietf:params:acme:error:*` problem document, an EST/SCEP
failure response.

## Worked examples

The console offers these as insertable starting points, and the test suite
evaluates every one of them, so an example copied out of the console compiles.
`secsy-ca issuance-policy reference` prints the current set.

**Restrict DNS names to a suffix** — and name the ones that do not fit:

```cel
request.dns_names
  .filter(d, !(d.endsWith(".example.com") || d == "example.com"))
  .map(d, "DNS name " + d + " is outside example.com, which this CA may not certify")
```

**Wildcards need an entitlement in the token** (`message:` *a wildcard
certificate requires the pki.wildcard entitlement in your token*):

```cel
!request.wildcard || (has(jwt.entitlements) && "pki.wildcard" in jwt.entitlements)
```

**Forbid internal names on a public CA** (`effect: deny`):

```cel
request.dns_names.exists(d, d.endsWith(".internal") || d.endsWith(".local"))
  || request.subject.common_name.endsWith(".internal")
```

**IP SANs must be inside the corporate ranges** — containment written with the
network library rather than a string comparison that gets `10.0.0.0/8` subtly
wrong:

```cel
request.ip_addresses
  .filter(a, !(cidr("10.0.0.0/8").containsIP(a) || cidr("192.168.0.0/16").containsIP(a)))
  .map(a, "IP address " + a + " is outside the corporate ranges 10.0.0.0/8 and 192.168.0.0/16")
```

**Minimum key strength:**

```cel
(request.key.algorithm == "RSA" && request.key.size >= 3072) ||
(request.key.algorithm == "ECDSA" && request.key.size >= 256) ||
request.key.algorithm == "Ed25519"
```

**Service accounts may only name their own namespace** — the group name encodes
it, a regex extracts it:

```cel
cel.bind(ns,
  has(jwt.groups)
    ? jwt.groups.map(g, regex.extract(g, "^pki-ns-([a-z0-9-]+)$").orValue("")).filter(s, s != "")
    : [],
  ns.size() == 0
    ? "your token carries no pki-ns-<namespace> group, so no name can be certified for you"
    : (request.dns_names.all(d, ns.exists(n, d.endsWith("." + n + ".svc.cluster.local")))
        ? ""
        : "every DNS name must sit under one of your namespaces: " + ns.join(", ")))
```

**Only an admin may mint a subordinate CA:**

```cel
!request.is_ca || (principal.authenticated && ("admin" in principal.roles || principal.is_root))
```

**Automated enrollment may not request long-lived certificates:**

```cel
request.source in ["rest", "grpc", "cli"] || request.validity_days <= 30
```

**The request body must carry a change ticket** — a parameter the API accepts
but the certificate does not carry:

```cel
has(body.reason) && string(body.reason).matches("^(CHG|INC)-[0-9]{4,}$")
```

## The function library

The CEL standard library plus nine upstream extension libraries. The
authoritative list is `GET /api/issuance-policies/reference`; the summary:

| Group | Functions |
|---|---|
| operators, macros | `== != < <= > >= && \|\| ! in`, `a ? b : c`, `has()`, `size()`, `all` / `exists` / `exists_one` / `map` / `filter` |
| two-variable comprehensions | `all(i, x, p)`, `exists(i, x, p)`, `existsOne(i, x, p)`, `transformList`, `transformMap` — the element index a rule otherwise cannot see |
| bindings | `cel.bind(name, init, expr)` — name a subexpression so it is evaluated once |
| strings | `contains`, `startsWith`, `endsWith`, `matches` (RE2), `charAt`, `indexOf`, `lastIndexOf`, `lowerAscii`, `upperAscii`, `replace`, `split`, `substring`, `trim`, `reverse`, `join`, `strings.quote`, `format` |
| regex | `regex.replace`, `regex.extract` → `optional<string>`, `regex.extractAll`; `orValue`, `hasValue`, `value` |
| lists, sets | `distinct`, `flatten`, `reverse`, `slice`, `sort`, `sortBy`, `lists.range`, `sets.contains`, `sets.equivalent`, `sets.intersects` |
| math | `math.greatest`, `math.least`, `math.abs`, `math.sign`, `math.ceil`, `math.floor`, `math.round`, `math.trunc`, `math.isInf`/`isNaN`/`isFinite`, the bit operations |
| network | `isIP`, `ip`, `ip.isCanonical`, `<ip>.family`/`isLoopback`/`isGlobalUnicast`/`isLinkLocal*`/`isUnspecified`, `isCIDR`, `cidr`, `<cidr>.containsIP`/`containsCIDR`/`ip`/`masked`/`isMask`/`prefixLength` |
| encoding | `base64.encode`, `base64.decode` |
| time | `timestamp()`, `duration()`, arithmetic on both, `getFullYear`/`getMonth`/`getDayOfWeek`/`getHours`… |

## Operating it

### Audit

- **`cert.policy`** — written whenever a rule produced a finding. `ResultError`
  is a blocked issuance (including a rule that failed closed); `ResultSuccess` a
  monitor-mode finding that let the certificate through. The detail carries the
  surface, the profile, the number of rules evaluated and every finding with its
  rule name and mode — the same text the requester was given, so the log answers
  "why was this refused" on its own.
- **`policy.rule.create` / `.update` / `.delete`** — administration, with the
  rule's name and its expression. A restriction engine is only as trustworthy as
  the record of who changed it.

### Metrics

| Series | Labels | Use |
|---|---|---|
| `secsy_certificate_policy_checks_total` | `result` = `pass`\|`deny`\|`monitor`\|`error` | is the gate running, and how often does it refuse |
| `secsy_certificate_policy_violations_total` | `rule`, `mode` | which rule is actually refusing traffic |
| `secsy_certificate_policy_rule_errors_total` | `rule` | **alert on this** — a non-zero rate means a rule is refusing for a reason that has nothing to do with the requests |

### Multi-tenancy

A rule with no `tenant_id` applies to every tenant's CAs; one with a `tenant_id`
applies only to that tenant's. The gate loads the deployment-wide rules plus the
issuing CA's own tenant's, so a tenant's policy cannot reach another tenant's
authorities. See [multi-tenancy](../security/multi-tenancy.md).

### Performance

Rules are read from the database on every issuance — one indexed query — and
compiled programs are memoized by their expression text, so the steady state is
a map lookup per rule. Editing a rule in the console is therefore immediate and
needs no invalidation: new text is simply a new key. Evaluation is bounded at
500,000 cost units per rule.

### Store migration

`cel_policy_rules` is copied by `secsy-ca db migrate`, so a SQLite → PostgreSQL
migration carries the policy with it. A migrated store that had lost its rules
would issue certificates the source store refused.

---

↩ Back to [issuance policy & pre-issuance gates](README.md) ·
[documentation map](../README.md)
