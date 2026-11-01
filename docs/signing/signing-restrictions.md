# CEL signing restrictions

*The same operator-written restriction engine, in front of the signatures that
are not certificates: an OpenSSH certificate, a CMS/CAdES artifact signature, a
raw signature with a named key.*

[CEL issuance restrictions](../issuance/cel-restrictions.md) put operator-written
rules in front of certificate generation. They left every *other* signature this
deployment's keys produce ungoverned — and those are the same act: a key the
deployment is responsible for is asked to attest to something, and somebody has
to decide whether it may.

The gap showed up as soon as the engine existed. An enterprise that can say
"this CA may not certify `*.internal`" has every reason to also say:

- an OpenSSH certificate may not name `root`, on any CA, by anyone;
- a SPIFFE JWT-SVID is minted only for audiences inside its own trust domain,
  and never for longer than fifteen minutes;
- `force-command` is fixed on this SSH CA and not negotiable per request;
- a user certificate is signed only for a **FIDO-resident** key;
- the release-signing key is reserved for one repository's pipeline token —
  a human with the console cannot use it at all;
- an artifact signature must carry a trusted timestamp, or it stops verifying
  the day its certificate expires;
- this key signs *content*, never a digest the caller computed;
- nothing is signed outside business hours without a change ticket.

Each is a relationship between the request, the caller's token and the key —
exactly what a declarative allow-list cannot express, and exactly what the
restriction engine is for.

## At a glance

| | |
|---|---|
| **Rule kind** | `signing` (the other kind is `certificate` — see [CEL issuance restrictions](../issuance/cel-restrictions.md)) |
| **Vocabulary** | `signing`, plus the shared `jwt`, `url`, `path`, `body`, `principal`, `now` |
| **Operations** | `ssh-certificate`, `artifact`, `data`, `jwt-svid` |
| **Where it runs** | inside each signing service, below every transport: `sshca.Authority.Sign`, `signing.Service.Sign`, `secret.Sign`, `ca.Manager.IssueJWTSVID` |
| **Which paths** | REST, gRPC and CLI alike — the gate is in the service, not in a handler |
| **Where rules live** | the same `cel_policy_rules` table, editable at runtime; no restart, no config reload |
| **Who may edit** | `ca:configure` (admin). Reading and dry-running: any role |
| **Console** | the **Signing Policy** view, with `kind = signing` selected |
| **CLI** | `secsy-ca issuance-policy … -kind signing` |
| **REST** | `/api/issuance-policies?kind=signing` (+ `/validate`, `/test`, `/reference` with `kind=signing`) |
| **Refusal** | HTTP **422** with `{error, code: "policy_denied", violations: [{rule, message}]}`; gRPC `FAILED_PRECONDITION` |
| **Audit** | `sign.policy` (the gate), `policy.rule.create` / `.update` / `.delete` (administration) |
| **Metrics** | `secsy_signing_policy_checks_total`, `…_violations_total`, `…_rule_errors_total` |
| **Failure mode** | **fail-closed** — a rule that cannot be evaluated refuses the signature |

## One engine, two vocabularies

A rule carries a **kind**, and the kind decides three things at once: which
facts the expression sees, which gate consults it, and which environment it is
compiled in.

| | `kind: certificate` | `kind: signing` |
|---|---|---|
| Restricts | certificate generation | OpenSSH certificates, artifact signatures, raw signatures |
| Reads | `request` | `signing` |
| Enforced by | the pre-issuance gate in `ca.Manager.buildLeaf` | the gate inside each signing service |
| Scope selectors | `profiles`, `cas`, `tenant_id` | `keys`, `operations`, `profiles`, `cas`, `tenant_id` |
| Refusal names | "certificate request denied: …" | "SSH certificate request denied: …" etc. |

Everything else is shared: the effects (`require` / `deny`), the modes
(`enforce` / `monitor`), `fail_open`, `priority`, the three result shapes (bool,
string, list of strings), the fail-closed reading, the function library, the
cost ceiling, the store, and the editors.

!!! note "The two vocabularies are separate environments"
    A signing rule that mentions `request.dns_names` does not compile, and a
    certificate rule that mentions `signing.key.name` does not compile either.
    That is deliberate. A merged environment would accept both and then evaluate
    the wrong one against an empty object — a rule that *reads* as working and in
    fact never fires. A rule's kind is therefore fixed at creation: changing it
    is refused rather than silently reinterpreting the text.

## Where the gates sit

Each gate is inside the service that owns the key, below every transport, so a
rule cannot be avoided by asking over a different protocol — the same property
that makes the certificate gate's position in `buildLeaf` worth having.

| Operation | Gate | Reached by |
|---|---|---|
| `ssh-certificate` | `sshca.Authority.Sign`, after the profile defaults and the CA's validity ceiling are applied and the serial is allocated, before the HSM signature | `POST /api/ssh/cas/{id}/sign`, `secsy-ca ssh sign-user` / `sign-host`, and the legacy `POST /api/keys/{id}/sign` |
| `artifact` | `signing.Service.Sign`, after the effective CAdES level is resolved and the artifact digest computed, before the key is opened | `POST /api/sign`, `secsy-ca sign` |
| `data` | `secret.Sign`, after the message hash and digest are resolved, before the key is opened | `POST /api/secret/signing-keys/{name}/sign`, gRPC `SecretService.Sign`, `secsy-secret sign` |
| `jwt-svid` | `ca.Manager.IssueJWTSVID`, after the TTL is clamped and the audience normalized, before the token is signed | `POST /api/ca/{id}/svid/jwt`, `secsy-ca svid jwt` |

Two consequences worth knowing:

- **The facts describe the signature, not the request.** An SSH certificate's
  facts are read from the fully resolved `ssh.Certificate` — profile defaults
  applied, the CA's ceiling applied, the serial allocated — so a rule written
  about a certificate's lifetime cannot be fooled by asking for more than the CA
  will grant. An artifact signature's facts carry the *resolved* CAdES level and
  the digest the signature will actually cover.
- **A refused request does not touch the HSM** (except for an SSH certificate,
  which has already consumed a serial from the CA's monotonic counter —
  deliberately, because the serial is one of the facts a rule may read).

### The one path that is gated by *certificate* rules

`POST /api/keys/{id}/sign-x509` is the low-level endpoint that hands a CSR
straight to the CA key, bypassing `buildLeaf` and therefore every pre-issuance
gate. What it produces is a certificate, and its facts are a certificate's
facts, so it is gated by the **certificate** rules — the ones an operator has
already written. Before this, it was a documented way around all of them.

The request carries no issuance profile, so `request.profile` is empty and a
profile-scoped rule does not apply; only the unscoped and CA-scoped ones do.
`request.source` is `rawsign`, so a rule can treat the endpoint specially:

```cel
request.source == "rawsign" && !("admin" in principal.roles)
```

with effect `deny` restricts the raw endpoint to administrators while leaving
ordinary issuance alone.

## What a signing rule sees

| Variable | Type | Holds |
|---|---|---|
| `signing` | object | the signing operation: what is being signed, with which key, and the per-operation facts |
| `jwt` | map | every **verified** claim of the token the caller presented; empty when they presented none |
| `url` | object | the HTTP request: `method`, `scheme`, `host`, `port`, `path`, `segments`, `query`, `raw_query`, `client_ip`, `present` |
| `path` | string | the full request path — the same value as `url.path` |
| `body` | map | the decoded request body parameters, by name |
| `principal` | object | the authenticated caller: `subject`, `email`, `roles`, `tenant_roles`, `tenants`, `groups`, `is_root`, `authenticated` |
| `now` | timestamp | evaluation time, UTC |

The authoritative list — every field of every object, with its type — is served
by the running server:

```bash
secsy-ca issuance-policy reference -kind signing
# or: curl '/api/issuance-policies/reference?kind=signing'
```

### `signing`

| Field | Type | Notes |
|---|---|---|
| `operation` | string | `ssh-certificate`, `artifact` or `data` |
| `source` | string | the surface: `rest`, `grpc`, `cli`, `preview`, `unknown` |
| `tenant` | string | the tenant the key belongs to; empty for a platform-level key |
| `requested_by` | string | the identity the signature is attributed to |
| `purpose` | string | the free-text reason the caller gave (`-reason`, `"reason"`), where the surface collects one |
| `key` | object | the key that would sign — see below |
| `payload` | object | what would be signed — see below |
| `ssh`, `artifact`, `data`, `jwt_svid` | objects | the per-operation facts; exactly one has `present` set |

`signing.key`:

| Field | Type | Notes |
|---|---|---|
| `name` | string | how the caller addressed the key: the signer name, the signing-key name, or the SSH CA's label |
| `label`, `ref` | string | the provider label and the provider reference (a PKCS#11 URI, a KMS key id) |
| `algorithm` | string | `RSA` / `ECDSA` / `Ed25519` for a CA key, or the stored algorithm identifier (`ecdsa-p256`, `rsa-pss-3072`) for a named signing key |
| `type` | string | the key type as the key provider names it (`rsa-2048`, `ed25519`) |
| `size`, `curve` | int, string | the modulus/curve size in bits, and the curve name |
| `fingerprint` | string | the public key's SPKI SHA-256 fingerprint, `SHA256:…` — the same form the inventory search and the blocklist use |
| `provider` | string | the key backend: `pkcs11`, `pkcs11-ha`, `awskms`, `azurekeyvault`, `gcpkms`, `vaulttransit`, `software` |
| `tenant` | string | the key's tenant |

`signing.payload` — deliberately shallow. A rule has no business reading the
content of a release artifact, and a service signing a 4 GiB image never sees
the bytes:

| Field | Type | Notes |
|---|---|---|
| `present` | bool | false when the surface reveals nothing about the payload |
| `size` | int | the byte length the caller supplied; **0** when they supplied a digest instead (an unknown message length, not a tiny one), and 0 for an SSH certificate |
| `digest` | string | lowercase hex of what is being signed |
| `digest_algorithm` | string | `SHA-256`, `SHA-384`, … ; empty for Ed25519, which hashes internally as part of the scheme |
| `prehashed` | bool | the caller supplied the digest, so the service never saw what it is attesting to. A key whose signatures imply review should refuse this |

### `signing.ssh`

| Field | Type | Notes |
|---|---|---|
| `present` | bool | true for an `ssh-certificate` operation |
| `cert_type` | string | `user` or `host` |
| `key_id` | string | the certificate's key ID — what the target host writes to its auth log |
| `principals` | list(string) | the user names (user certs) or host names (host certs) the certificate is valid for |
| `principal_count` | int | their number, so a "one principal per certificate" rule needs no `size()` |
| `extensions` | list(string) | the **resolved** permission names, sorted (`permit-pty`, `permit-port-forwarding`, …) |
| `critical_options` | list(string) | the resolved critical-option names, sorted |
| `critical_option_values` | map(string, string) | each critical option's value — where `force-command` and `source-address` live |
| `profile` | string | the SSH signing profile's name |
| `serial` | string | the allocated serial, decimal |
| `valid_after`, `valid_before` | timestamp | the certificate's window (the zero time for an OpenSSH "forever") |
| `validity` | duration | `valid_before - valid_after`, exactly |
| `validity_days` | int | the same in whole days, truncated |
| `public_key` | object | `type` (`ssh-ed25519`, `ecdsa-sha2-nistp256`, `sk-ssh-ed25519@openssh.com`), `fingerprint` (`SHA256:…`), `bits`, `hardware_backed` |
| `ca` | object | `id`, `label`, `tenant`, `subject`, `not_after` |

!!! tip "`hardware_backed` is the one thing a public key proves about its private half"
    An OpenSSH `sk-` key type is a FIDO/U2F credential: the private half lives on
    a security key and cannot be copied off it. An enterprise that mandates
    hardware-backed SSH keys can enforce exactly that, with no attestation
    machinery:

    ```cel
    signing.operation != "ssh-certificate" || signing.ssh.cert_type == "host"
      || signing.ssh.public_key.hardware_backed
    ```

### `signing.artifact`

| Field | Type | Notes |
|---|---|---|
| `present` | bool | true for an `artifact` operation |
| `signer` | string | the configured signing identity's name |
| `level` | string | the **resolved** CAdES baseline level: `b`, `t` or `lt` |
| `timestamped` | bool | whether the signature will carry an RFC 3161 countersignature |
| `name` | string | the artifact name the caller supplied. Caller-asserted metadata — a detached CMS signature binds the digest, not the name; read `payload.digest` when you want a bound fact |
| `certificate` | object | the signing certificate that will be embedded: `subject`, `issuer`, `serial`, `not_before`, `not_after`, `ext_key_usages` |

### `signing.jwt_svid`

A [JWT-SVID](../certificates/spiffe.md) is minted with a CA's issuer key but it is
not a certificate: there is no to-be-signed template, nothing is recorded in the
inventory, and the pre-issuance gate never sees it. It is a **bearer token with
no revocation**, so the two facts worth restricting are its audience and its
lifetime.

| Field | Type | Notes |
|---|---|---|
| `present` | bool | true for a `jwt-svid` operation |
| `spiffe_id` | string | the workload identity the token asserts, verbatim |
| `trust_domain`, `path` | string | the same value split, so a rule can bound a namespace without parsing a URI |
| `audience` | list(string) | the **normalized** audience set the token will carry (`aud`) — the services permitted to accept it |
| `algorithm`, `key_id` | string | the JWS `alg` the issuer key implies, and the RFC 7638 thumbprint published in the trust bundle |
| `not_before`, `expiry` | timestamp | the token's window |
| `ttl` | duration | the **clamped** lifetime — after `JWTSVIDMaxTTL`, not as requested |
| `ttl_seconds` | int | the same in whole seconds, the unit a JWT-SVID lifetime is written in |
| `ca` | object | `id`, `label`, `tenant`, `subject`, `not_after` |

### `signing.data`

| Field | Type | Notes |
|---|---|---|
| `present` | bool | true for a `data` operation |
| `key` | string | the signing key's name |
| `algorithm` | string | its fixed algorithm (`ecdsa-p256`, `rsa-pss-3072`, `ed25519`) |
| `hash` | string | the message hash this signature uses; empty for Ed25519 |

## Scoping a rule

A rule with no selectors applies to every signature. Narrowing it:

| Selector | Matches |
|---|---|
| `operations` | `signing.operation` — `ssh-certificate`, `artifact`, `data`, `jwt-svid` (globs allowed). An operation that does not exist is rejected when the rule is written, because a rule scoped to one would look switched on and apply to nothing |
| `keys` | the key, by **any** name it is known by: the name the caller used, the provider label, and the signing CA's label/id for an SSH certificate or a JWT-SVID — so `keys: release-signing` works without knowing which of those the surface records |
| `profiles` | the SSH signing profile, for an `ssh-certificate` operation |
| `cas` | the signing CA's id or label, for the operations minted with a CA key (`ssh-certificate`, `jwt-svid`) |
| `tenant_id` | the key's tenant. A rule with none applies to every tenant |

All are case-insensitive and accept shell-style globs, so `ssh-*` selects a
family of CAs without listing them.

## Worked rules

Every example here is compiled and evaluated by the test suite, and the same set
is offered in the console's editor and by
`secsy-ca issuance-policy reference -kind signing`.

**No privileged principals, with one reason per offending name:**

```cel
signing.ssh.principals
  .filter(p, p.lowerAscii() in ["root", "admin", "ec2-user"])
  .map(p, "principal " + p + " is a shared privileged account; use a named account and sudo")
```

**A lifetime ceiling that tells the requester the number they exceeded:**

```cel
signing.operation != "ssh-certificate" || signing.ssh.validity <= duration("12h")
  ? ""
  : "requested %s of SSH certificate validity; this CA signs at most 12h".format([string(signing.ssh.validity)])
```

**The release key is the pipeline's, not a person's** (`keys: release-signing`):

```cel
has(jwt.iss) && string(jwt.iss).startsWith("https://token.actions.githubusercontent.com")
  && has(jwt.repository) && string(jwt.repository) == "example/product"
```

**An artifact signature must outlive its certificate** (`operations: artifact`):

```cel
signing.artifact.timestamped
```

**This key signs content, not a digest somebody else computed:**

```cel
!signing.payload.prehashed
```

**`force-command` is not negotiable** (effect `deny`):

```cel
"force-command" in signing.ssh.critical_option_values &&
  signing.ssh.critical_option_values["force-command"] != "/usr/local/bin/session-wrapper"
```

**A JWT-SVID stays inside its trust domain:**

```cel
signing.operation != "jwt-svid" ||
  signing.jwt_svid.audience.all(a, a.startsWith("spiffe://" + signing.jwt_svid.trust_domain + "/"))
```

**Provider-resident keys only** — the software keystore is for tests:

```cel
signing.key.provider in ["pkcs11", "pkcs11-ha", "awskms", "azurekeyvault", "gcpkms", "vaulttransit"]
```

**Out-of-hours signing needs a change ticket** — the clock is read by the
server, never by the expression, and `body` carries a parameter the signature
itself does not:

```cel
now.getHours() >= 8 && now.getHours() < 18 && now.getDayOfWeek() >= 1 && now.getDayOfWeek() <= 5
  ? ""
  : (has(body.reason) && string(body.reason).matches("^(CHG|INC)-[0-9]{4,}$")
      ? "" : "signing outside 08:00-18:00 Mon-Fri requires a \"reason\" naming a change or incident ticket")
```

## Writing and trying a rule

### CLI

```bash
# Write it switched off, then dry-run it.
secsy-ca issuance-policy add -kind signing -name no-root-principals -effect deny \
    -expr 'signing.ssh.principals.exists(p, p.lowerAscii() == "root")' \
    -message 'an SSH certificate may not name root; use a named account and sudo' \
    -disabled

cat > /tmp/facts.json <<'JSON'
{
  "signing": {
    "operation": "ssh-certificate",
    "key": { "name": "ssh-user-ca" },
    "ssh": { "present": true, "cert_type": "user", "principals": ["root"] }
  },
  "principal": { "subject": "ops@example.com", "roles": ["issuer"], "authenticated": true }
}
JSON
secsy-ca issuance-policy test -kind signing -rule no-root-principals -facts /tmp/facts.json
# WOULD BE REFUSED — 1 rule(s) evaluated, 0 skipped
#   - no-root-principals: an SSH certificate may not name root; use a named account and sudo

secsy-ca issuance-policy enable no-root-principals
secsy-ca issuance-policy list -kind signing
```

`test` exits non-zero when the signature would be refused, so a pipeline can
gate on its own request shape.

### Console

The **Signing Policy** view holds both kinds. Set **Kind** to *signing* in the
editor and the vocabulary panel, the insertable examples and the compile check
all switch to the signing environment; the **Keys** and **Operations** selectors
appear. The dry-run has its own kind selector and a worked signing fact set —
switching the kind replaces the facts, because certificate facts in a signing
dry-run would evaluate every rule against an empty signing request and report
that nothing is refused.

### REST

```bash
curl -X POST /api/issuance-policies -d '{
  "kind": "signing",
  "name": "artifacts-need-a-timestamp",
  "operations": ["artifact"],
  "expression": "signing.artifact.timestamped",
  "message": "an artifact signature must be timestamped (level t or lt)"
}'

curl -X POST /api/issuance-policies/validate \
  -d '{"kind":"signing","expression":"signing.ssh.cert_type == \"host\""}'

curl -X POST /api/issuance-policies/test -d '{
  "kind": "signing",
  "all_rules": true,
  "signing_input": {"signing": {"operation": "artifact", "artifact": {"present": true, "level": "b"}}}
}'
```

The dry-run takes signing facts in `signing_input` rather than in `input`: two
differently-shaped fact sets under one field name would be a request nobody
could document, and a client that sent the wrong one would be told that nothing
is refused.

!!! tip "Durations in a hand-written fact set"
    Write a duration the way you say it — `"validity": "8h"`,
    `"ttl": "15m"` — or as a whole number of nanoseconds; both decode. A
    malformed one is an error rather than a silent zero, because a lifetime rule
    against a zero validity would report that nothing is refused. The facts a
    dry-run echoes back use the readable form, so they can be pasted into the
    next run.

## What a refusal looks like

```http
HTTP/1.1 422 Unprocessable Content
Content-Type: application/json

{
  "error": "an SSH certificate may not name root; use a named account and sudo (policy rule \"no-root-principals\")",
  "code": "policy_denied",
  "violations": [
    {"rule": "no-root-principals", "message": "an SSH certificate may not name root; use a named account and sudo", "mode": "enforce"}
  ]
}
```

422 rather than 403: the caller's credentials were accepted and their capability
was never in question — the *content* of the request is what policy refused, and
a client that distinguishes the two can fix its request instead of hunting for a
missing role. gRPC answers `FAILED_PRECONDITION` for the same reason.

A **gate failure** — the rule set could not be read at all — is a different
answer: **503**, because nothing could be checked, the refusal is the server's
fault, and retrying is the right response. The store's own error stays in the
`sign.policy` audit event rather than going to the client.

Every applicable rule runs, so a requester who got three things wrong is told
three things rather than discovering them one retry at a time.

## Operating it

### Audit

- **`sign.policy`** — written whenever a rule produced a finding. `ResultError`
  is a refused signature (including a rule that failed closed); `ResultSuccess`
  a monitor-mode finding that let the signature through. The detail carries the
  operation, the surface, the key, the number of rules evaluated and every
  finding with its rule name and mode.
- **`policy.rule.create` / `.update` / `.delete`** — administration, for both
  kinds, with the rule's kind, scope and expression.

### Metrics

| Series | Labels | Use |
|---|---|---|
| `secsy_signing_policy_checks_total` | `operation`, `result` = `pass`\|`deny`\|`monitor`\|`error` | is each gate running, and which operation is being refused |
| `secsy_signing_policy_violations_total` | `rule`, `mode` | which rule is actually refusing traffic |
| `secsy_signing_policy_rule_errors_total` | `rule` | **alert on this** — a non-zero rate means a rule is refusing (or, if `fail_open`, silently not enforcing) for a reason that has nothing to do with the requests |

### Adopting a rule safely

The same two mechanisms as the issuance half, and for the same reason — a
fail-closed engine is only adoptable if a wrong rule can be discovered without
refusing real work:

- **monitor mode** records what a rule would have refused and signs anyway;
- **`fail_open`** is the explicit opt-out for a rule accepted as best-effort.

Everything else fails closed: a rule set that cannot be loaded, a rule that does
not compile, a rule that errors at evaluation and a rule that blows the 500,000
cost-unit ceiling all refuse the signature.

### What is *not* gated

- **CRL and OCSP signing**, and the OCSP responder's pre-signed artifacts.
  Refusing these would withhold revocation information, which is the opposite of
  the safe failure.
- **RFC 3161 time-stamp tokens.** The TSA is a protocol service with its own
  policy surface (`tsa.policy`, accuracy, ordering) and a public, high-volume
  endpoint; see [time-stamping](timestamping.md).
- **The audit chain's own signatures** — the anchor timestamps and the signed
  audit-log exports. A rule that could refuse those could break the evidence
  the engine's own findings are recorded in.
- **Protocol message protection** — a CMP message's protection signature, a
  BRSKI voucher request. Those authenticate a transport exchange rather than
  attest to a credential; refusing one breaks the protocol rather than
  restricting anything.
- **CA-lifecycle signatures** — creating a root or intermediate, rotating a
  signing key, cross-signing. These are administrative operations behind
  `ca:configure` and the four-eyes queue, not requests from a caller; see
  [the approval workflow](../security/approvals.md).
- **Certificate generation**, which is the other kind's job — see
  [CEL issuance restrictions](../issuance/cel-restrictions.md).

### Multi-tenancy

A rule with no `tenant_id` applies to every tenant's keys; one with a
`tenant_id` applies only to that tenant's. Each gate loads the deployment-wide
rules plus the key's own tenant's, so a tenant's policy cannot reach another
tenant's keys. See [multi-tenancy](../security/multi-tenancy.md).

### Performance

Rules are read from the store on each signature — one indexed query, filtered by
kind so a deployment with a hundred certificate rules and one signing rule does
not load the hundred — and compiled programs are memoized by expression text and
kind, so the steady state is a map lookup per rule.

---

↩ Back to [signing & timestamping services](README.md) ·
[CEL issuance restrictions](../issuance/cel-restrictions.md) ·
[documentation map](../README.md)
