# Name Constraints and Certificate Policies (RFC 5280)

secsy-pki supports first-class X.509 **Name Constraints** (2.5.29.30) and the
**certificate-policy** family — **Certificate Policies** (2.5.29.32), **Policy
Mappings** (2.5.29.33), and **Policy Constraints** (2.5.29.36) — on CA
certificates, plus per-profile certificate-policy assignment on leaves.

Name-constrained intermediates are the standard way to delegate a *scoped*
subtree of the namespace to a subordinate CA: an intermediate that is permitted
only `internal.example.com` (and `10.0.0.0/8`) cannot mint a certificate for
`example.org` even if its key is compromised, because every conforming path
validator — including `openssl verify` — rejects such a leaf.

## What is enforced, and where

Enforcement mirrors the [CAA](caa.md) and [certlint](security-review.md) gates
and follows [ADR 0003 — fail-closed security gates](adr/0003-fail-closed-security-gates.md):

- **On CA setup / rotation** (`internal/ca`): the configured permitted/excluded
  subtrees and certificate-policy OIDs are emitted as the correct extensions on
  the root or intermediate certificate. A key rotation
  ([Task 24](ca-rotation.md)) copies these extensions forward verbatim, so the
  replacement key stays a drop-in issuer for the same scope.
- **On the issuance path** (`internal/ca` `buildLeaf`): a **fail-closed
  pre-issuance Name Constraints gate** runs before any HSM signature. It parses
  the issuing CA's own name constraints and rejects a leaf whose subject or SAN
  falls **outside** a permitted subtree or **inside** an excluded subtree. The
  gate is unconditional — a CA always honors the limits encoded in its own
  certificate; there is no per-profile opt-out. Every block emits a
  `cert.nameconstraint` audit event and increments
  `secsy_certificate_name_constraint_checks_total{result="fail"}` plus
  `secsy_certificate_name_constraint_violations_total{kind}`.

The gate covers DNS, IP, e-mail, and URI SANs, the subject `directoryName`, and
— to match the behavior of common validators — a subject **CN that syntactically
looks like a hostname** (so a CN cannot smuggle an out-of-scope name past DNS
constraints).

Because Go's `crypto/x509` cannot emit or parse `directoryName` subtrees (or
policy mappings / policy constraints), secsy-pki hand-rolls the ASN.1 for all
five general-name forms and the whole policy family in
`internal/nameconstraints` and `internal/certpolicy`.

## Configuring a name-constrained intermediate (CLI)

```bash
secsy-ca issue-intermediate \
  -parent root -label corp-issuing -cn "Corp Issuing CA" \
  -permit-dns internal.example.com \
  -permit-ip 10.0.0.0/8 \
  -exclude-dns secret.internal.example.com \
  -permit-email .corp.example.com \
  -permit-dirname "O=Acme,C=US" \
  -policy-oid 1.3.6.1.4.1.99999.1.1 -policy-cps https://cps.example.com \
  -require-explicit-policy 0
```

All `-permit-*` / `-exclude-*` flags are repeatable and also accept a
comma-separated value. Name constraints are marked critical by default (as
RFC 5280 requires). The same flags exist on `init-root` for a constrained root.

## Configuring via the REST API

`POST /api/ca/{id}/issue-intermediate` (and `POST /api/ca/init-root`) accept
optional `name_constraints` and `policies` objects:

```json
{
  "label": "corp-issuing",
  "key_type": "ecdsa-p256",
  "subject": { "cn": "Corp Issuing CA" },
  "name_constraints": {
    "permitted": { "dns": ["internal.example.com"], "ip": ["10.0.0.0/8"] },
    "excluded":  { "dns": ["secret.internal.example.com"] }
  },
  "policies": {
    "oids": ["1.3.6.1.4.1.99999.1.1"],
    "cps": "https://cps.example.com",
    "require_explicit_policy": 0
  }
}
```

## Per-profile certificate policies (leaves)

An issuance profile may assign certificate-policy OIDs to every leaf it issues.
In the server config:

```yaml
profiles:
  - name: corp-tls
    key_usages: [digitalSignature, keyEncipherment]
    ext_key_usages: [serverAuth]
    default_validity_days: 90
    max_validity_days: 90
    policies:
      oids: ["1.3.6.1.4.1.99999.2.1"]
      cps: "https://cps.example.com"
```

The OIDs are emitted as a `certificatePolicies` extension, appended so the
precertificate and final certificate stay TBS-aligned for
[SCT embedding](certificate-transparency.md).

## Matching rules (RFC 5280 §4.2.1.10)

- **DNS / URI**: a subtree `example.com` matches `example.com` and any
  subdomain, case-insensitively at a label boundary. URI matching applies to the
  host component.
- **IP**: the leaf IP must be contained in a permitted CIDR (and in no excluded
  CIDR).
- **E-mail**: a full-mailbox constraint matches that address; a bare host
  (`example.com`) matches any mailbox on that host; a `.domain` constraint
  matches any mailbox within the domain.
- **directoryName**: the leaf subject matches when the subtree's attributes are
  all present in the subject (organization/geography scoping).
- A name form with **no permitted subtree** is unconstrained except by
  exclusions. A name form **with** a permitted subtree admits only names inside
  it.

## Verifying with OpenSSL

`openssl verify` independently enforces name constraints during path validation:

```bash
openssl verify -CAfile root.pem -untrusted intermediate.pem leaf.pem
```

An in-scope leaf validates; an out-of-scope leaf is rejected with an
`excluded`/`permitted subtree` error. The SoftHSM test
`internal/ca` `TestNameConstraintOpenSSLVerify` proves both directions against a
real HSM-signed chain.
