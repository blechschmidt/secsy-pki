# Delegated CA administration

**Use case:** the platform team owns the root CA. Each product team administers
exactly its own subordinate CA — and nothing else. A security auditor sees one
authority without tenant-wide read. A release pipeline signs with one key.

The tenant-wide role model cannot express this: an `admin` in a tenant
administers *every* CA in it, and an `issuer` issues on *every* CA in it. This
example uses **resource grants** — per-CA and per-key authorization for users
and groups — to draw the boundary at the individual authority instead.

Full reference: [`docs/security/resource-grants.md`](../../docs/security/resource-grants.md).

## Highlights

- One group administers **one** subordinate CA; its sibling stays out of reach.
- A `subtree` grant hands a team a whole **branch** of the PKI, including
  sub-CAs created later.
- A delegated operator holds **no tenant role at all** — its grants are its
  entire authority, and the CAs it was not given are invisible to it (`404`, so
  existence is not disclosed).
- Delegation **adds** an owner and never removes one: the platform administrator
  keeps every CA.
- The same model covers signing keys, so a CI pipeline gets exactly the key it
  signs with.
- `secsy-ca grant effective` explains any decision, including authority
  inherited from an ancestor CA.

## Prerequisites

Build the binaries and provision a token — see
[the shared setup](../README.md#common-prerequisites). Then copy the config:

```console
$ cp examples/delegated-ca-administration/config.yaml /etc/secsy-pki/config.yaml
```

## 1. Build the CA hierarchy

Create a root and two subordinates. The subordinate ids are what the grants
address, so note them.

```console
$ secsy-ca init-root -label demo-root -cn "Example Root CA"
$ ROOT=$(secsy-ca list | awk '$2=="demo-root"{print $1}')

$ secsy-ca issue-intermediate -parent "$ROOT" -label sub-payments -cn "Payments Issuing CA"
$ secsy-ca issue-intermediate -parent "$ROOT" -label sub-web      -cn "Web Issuing CA"

$ secsy-ca list
ID                                    LABEL         KEY TYPE             PARENT     SUBJECT
adafef49-cdd5-4861-9668-f1e881f26639  demo-root     ecdsa-sha2-nistp384  -          CN=Example Root CA
1660ce02-bfb4-4a9f-8f38-1e91855d9531  sub-payments  ecdsa-sha2-nistp256  demo-root  CN=Payments Issuing CA
92930351-1b5e-446e-b9a4-b1b4199c05ba  sub-web       ecdsa-sha2-nistp256  demo-root  CN=Web Issuing CA
```

Put those ids into `rbac.grants` in the config (the shipped file uses exactly
these placeholders), or grant at runtime as shown next. The two paths are
equivalent — the server unions them on every decision.

## 2. Delegate one subordinate to one group

`secsy-ca grant roles` prints what each role confers:

```console
$ secsy-ca grant roles
ROLE         APPLIES TO   CAPABILITIES
ca-admin     ca           audit:read, ca:configure, ca:manage, cert:issue, resource:delegate
ca-manager   ca           audit:read, ca:configure, ca:manage, cert:issue
ca-issuer    ca           audit:read, cert:issue
ca-auditor   ca           audit:read
key-admin    signing-key  audit:read, resource:delegate, secret:sign, secret:signing-key
key-signer   signing-key  audit:read, secret:sign
key-auditor  signing-key  audit:read
```

Hand `sub-payments` to the payments team:

```console
$ PAY=$(secsy-ca list | awk '$2=="sub-payments"{print $1}')
$ secsy-ca grant add -resource "ca/$PAY" -role ca-manager -group pki-payments
Granted ca-manager on ca/1660ce02-bfb4-4a9f-8f38-1e91855d9531 to group:pki-payments (scope self)
```

`ca-manager` is deliberate: the team runs the CA day to day but **cannot
delegate it onward**. Use `ca-admin` for a team that should manage its own
access list.

## 3. Confirm the boundary

The grant applies where it was made:

```console
$ secsy-ca grant effective -resource "ca/$PAY" -subject alice@example.com -groups pki-payments
Subject:  alice@example.com
Resource: ca/1660ce02-bfb4-4a9f-8f38-1e91855d9531
Groups:   pki-payments

Resource roles: ca-manager
Capabilities at this resource: audit:read, ca:configure, ca:manage, cert:issue

Matching grants:
  RESOURCE     ROLE        ENTITY              SCOPE  VIA
  ca/1660ce02  ca-manager  group:pki-payments  self   direct
```

…and nowhere else — not on the root, not on the sibling:

```console
$ ROOT=$(secsy-ca list | awk '$2=="demo-root"{print $1}')
$ secsy-ca grant effective -resource "ca/$ROOT" -subject alice@example.com -groups pki-payments
Subject:  alice@example.com
Resource: ca/adafef49-cdd5-4861-9668-f1e881f26639
Groups:   pki-payments

No resource grants apply. Any access this subject has here comes from
its platform or tenant roles (see the rbac.subjects / rbac.groups config).
```

Over the API, the same principal sees only what it was given:

```console
$ curl -s -H "Authorization: Bearer $ALICE_TOKEN" https://pki.example.com/api/keys | jq -r '.[].label'
sub-payments
```

## 4. Delegate a whole branch

Scope `subtree` covers the named CA *and everything beneath it, including CAs
created later* — so a new regional sub-CA needs no new grant:

```console
$ secsy-ca grant add -resource "ca/$PAY" -role ca-admin -group pki-payments-leads -scope subtree

# A sub-CA created AFTER the grant:
$ secsy-ca issue-intermediate -parent "$PAY" -label sub-payments-eu -cn "Payments EU CA"
$ LEAF=$(secsy-ca list | awk '$2=="sub-payments-eu"{print $1}')

$ secsy-ca grant effective -resource "ca/$LEAF" -subject lead@example.com -groups pki-payments-leads
Resource roles: ca-admin
Capabilities at this resource: audit:read, ca:configure, ca:manage, cert:issue, resource:delegate

Matching grants:
  RESOURCE     ROLE      ENTITY                    SCOPE    VIA
  ca/1660ce02  ca-admin  group:pki-payments-leads  subtree  inherited (subtree)
```

Inheritance is strictly **downward**: a subtree grant on a subordinate never
reaches its parent or its siblings.

## 5. Delegate one signing key

Same model, different resource type — a release pipeline that signs artifacts
gets that key and no other:

```console
$ secsy-ca signing-key create -name release -algorithm ecdsa-p256
$ secsy-ca grant add -resource signing-key/release -role key-signer -group ci-release
```

`key-signer` uses the key; it cannot create or replace it (`key-admin`) and it
cannot reach the tenant's other keys.

## 6. Review who has what

```console
$ secsy-ca grant list -resource "ca/$PAY"
RESOURCE     ROLE        ENTITY                    SCOPE    SOURCE
ca/1660ce02  ca-manager  group:pki-payments        self     database
ca/1660ce02  ca-admin    group:pki-payments-leads  subtree  database
ca/1660ce02  ca-auditor  group:sec-audit-payments  self     config

$ secsy-ca grant list        # every grant in the deployment
```

`SOURCE` distinguishes runtime delegations (`database`, revocable through the
CLI/API/console) from the declarative baseline in `rbac.grants` (`config`,
removed by editing the config file). The console's **Access** page shows the
same table and marks config rows read-only.

Revoke a runtime grant with:

```console
$ secsy-ca grant remove -resource "ca/$PAY" -role ca-manager -group pki-payments
```

## Notes for real deployments

- **Group names come from wherever your operators do.** A grant's `groups`
  match both internal groups (`/api/groups`) and the groups your IdP asserts —
  the OIDC `groups` claim or LDAP/AD membership. An existing enterprise group
  can be handed a CA without mirroring it here.
- **Set `auth.oidc.allow_zero_role: true`** when delegated operators hold no
  tenant role, as in this example. Otherwise a login that resolves to no RBAC
  role is refused before its grants are ever consulted.
- **User grants need a verified email.** `users:` entries match the principal's
  subject, or its email address only when the IdP marked it verified — a
  self-asserted address cannot claim someone else's grant.
- **Grants decide who may ask, never what may be minted.** Profiles, restriction
  sets, and every pre-issuance gate (lint, CAA, CT, name constraints, key
  blocklist) apply to a delegated operator exactly as they do to a tenant
  issuer.
- **Four-eyes still applies.** If CA rotation is a guarded class, a delegated
  `ca-admin` requesting one still parks for a distinct approver. A grant
  satisfies the capability check, not dual control.
- **Every delegation is audited** as `resource.grant` / `resource.revoke` in the
  hash-chained event log, carrying the resource, entity, role, and scope.

## See also

- [`docs/security/resource-grants.md`](../../docs/security/resource-grants.md) — the full model
- [`docs/security/rbac-and-audit.md`](../../docs/security/rbac-and-audit.md) — the platform/tenant role layer beneath grants
- [`docs/security/multi-tenancy.md`](../../docs/security/multi-tenancy.md) — when teams need separate tenants rather than separate CAs
- [`docs/security/authentication.md`](../../docs/security/authentication.md) — how subjects, verified emails, and groups are established
