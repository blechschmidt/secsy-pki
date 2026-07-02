# CAA record checking (RFC 8659)

secsy-pki can enforce DNS **Certification Authority Authorization** (CAA, [RFC
8659](https://www.rfc-editor.org/rfc/rfc8659), with the property-tag semantics of
[RFC 8657](https://www.rfc-editor.org/rfc/rfc8657)) as a **pre-issuance gate**.
Before the HSM signs any certificate carrying DNS-name SANs, the CA resolves the
CAA RRset governing each name and, under enforce mode, refuses to issue when the
domain owner has not authorized this CA. It runs on **every** issuance path —
REST API, ACME, SCEP/EST, and auto-renewal — because they all funnel through the
same `buildLeaf` choke point, right alongside the [pre-issuance
lint](certificate-authority.md) gate.

The check is **fail-closed**: a forbidding CAA set, an unrecognized
critical-flagged property, or a DNS lookup that cannot establish authorization
all block issuance under enforce mode. Nothing is signed, and a `cert.caa` audit
event plus a Prometheus metric record the decision.

## What it does

For each DNS-name SAN (IP-only certificates are skipped) the CA:

1. **Walks the domain tree** (RFC 8659 §3): it looks up the CAA RRset at the name
   and, if none is published, climbs to the parent domain, up to the root. The
   closest ancestor that publishes a CAA set is the one that governs the name;
   ancestors above it are not consulted or merged.
2. **Follows CNAME/DNAME aliases**: a recursive resolver transparently returns the
   CAA of a CNAME target, and when an aliased name has no CAA of its own the
   search continues at the *target's* tree rather than the alias's (guarded
   against alias loops).
3. **Evaluates `issue` / `issuewild`** against this CA's configured identifier.
   `issuewild` governs wildcard (`*.example.com`) requests and takes precedence
   over `issue`, falling back to `issue` when no `issuewild` is present. A set
   that authorizes some CA but not this one **forbids** issuance; an `issue ";"`
   (empty value) authorizes no CA at all.
4. **Honors the critical flag**: a record with the Issuer-Critical bit set and a
   property tag the CA does not understand forbids issuance (RFC 8659 §4.1).
5. **Collects `iodef`** incident-reporting endpoints from the governing set into
   the audit detail so operators can honor RFC 8659 §4.4 reporting.

A name with **no CAA policy anywhere** in its tree is permitted — CAA restricts
issuance only where a domain owner has published a record.

## Configuration

CAA is **opt-in per issuance profile** and disabled by default. Two pieces of
configuration are involved:

```yaml
# The CA's own identity, inherited by every profile that does not override it.
caa:
  identifier: pki.example.com   # the value a domain owner publishes in
                                # `issue "pki.example.com"` to authorize this CA
  cache_ttl_seconds: 300        # how long resolved CAA/CNAME answers are reused

profiles:
  - name: public-tls
    key_usages: [digitalSignature, keyEncipherment]
    ext_key_usages: [serverAuth]
    default_validity_days: 90
    max_validity_days: 397
    caa:
      mode: enforce             # off (default) | permissive | enforce
      # identifier: pki.example.com   # optional per-profile override
      # timeout_seconds: 5            # bounds all DNS lookups for one certificate
```

### Modes

| Mode | Behavior |
|------|----------|
| `off` (default) | The gate does not run for the profile. |
| `permissive` | The CAA set is resolved and evaluated, and a forbidding record is audited (`cert.caa`, result `success`) and counted — but issuance is **never blocked**. Use it to stage a policy or to gain visibility on an internal PKI. |
| `enforce` | A forbidding CAA set (or a lookup that leaves authorization undetermined) **blocks** issuance (`cert.caa`, result `error`), fail-closed. Requires a non-empty identifier — the server refuses to start otherwise. |

The `identifier` is this CA's CAA domain identifier. A domain owner authorizes it
by publishing, e.g.:

```
example.com.  IN  CAA  0 issue "pki.example.com"
```

### DNS resolver

When any profile enables CAA, the server builds a DNS resolver from
`/etc/resolv.conf` (UDP with TCP fallback) and wraps it in a TTL cache shared
across requests. If enforcement is enabled but no resolver can be built, startup
fails; a permissive profile logs a warning and continues (allowing issuance).

## Observability

- **Audit** — a `cert.caa` event is appended to the tamper-evident event log
  whenever the check produces a finding: `error` result when enforce mode blocked
  issuance, `success` when permissive mode reported a forbidding record without
  blocking. The detail carries the profile, a compact summary of the blocked
  names, and any `iodef` endpoints.
- **Metrics** —
  `secsy_certificate_caa_checks_total{result="pass|fail|skip|error"}` counts
  every run (`skip` = no DNS-name SANs), and
  `secsy_certificate_caa_findings_total{reason="forbidden|critical_unknown|lookup_error"}`
  counts individual forbidding names for fine-grained alerting.

## Notes & caveats

- CAA is evaluated against the DNS names as they appear in the request; it does
  not perform certificate validation of any kind — it only answers "is this CA
  authorized to issue for this name?".
- Enforce mode makes issuance depend on DNS reachability and correctness for the
  requested names. For an internal PKI whose names are not publicly resolvable,
  use `permissive` (or leave CAA `off`) and rely on the [lint
  gate](certificate-authority.md) and RBAC for control.
- The cache reuses both positive and negative (NODATA/NXDOMAIN) answers up to the
  TTL; transient lookup failures are never cached and are always retried.
