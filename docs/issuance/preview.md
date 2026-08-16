# Issuance preview (pre-issuance dry-run)

secsy-pki can validate a **would-be certificate issuance** through its full
fail-closed pre-issuance gate stack **without signing it**. The preview runs
every gate a real issuance runs — certificate linting, CAA, Name Constraints,
certificate policy, S/MIME mailbox policy, weak/compromised-key checks, the UPN
and eIDAS/PSD2 gates, and the validity caps — resolves the exact extensions the
leaf would carry, and reports each gate's verdict. It never calls the HSM to
sign, allocates no serial, persists no record, appends no audit event, and takes
no rate-limit or tenant-quota reservation.

That makes it the tool for two jobs:

- **Operators** can confirm a CSR + profile combination will be accepted before
  spending an HSM signature — useful when a request routes through a
  `require_approval` profile ([approvals](../security/approvals.md)) and you want to know the
  outcome before parking it.
- **CI / policy pipelines** can gate a change on "would this certificate still
  issue under our policy?" without polluting the audit trail or the issuance
  metrics with throwaway certificates.

The preview is **side-effect-free by design**: because it records nothing and
increments no issuance metric, it can be run as often as you like.

## What it evaluates

The preview shares the exact gate evaluators the issuance path uses (they are
factored out so the preview can never drift from real issuance). Each gate
returns one of four dispositions:

| Status | Meaning |
|---------|---------|
| `pass` | The gate ran and the request satisfied it. |
| `fail` | The gate ran and would **reject** the request (fail-closed). A single `fail` makes the overall decision `reject`. |
| `warn` | The gate produced findings that do not block issuance (warn-mode lint, permissive CAA, informational attestation posture). |
| `skipped` | The gate does not apply to this request (feature disabled for the profile, or nothing to evaluate). |

Gates covered: `lint` ([certlint](certlint.md), incl. the optional zlint
backend), `caa` ([CAA](caa.md), incl. RFC 8657 account/method binding on ACME
requests), `name_constraints` ([Name Constraints](name-constraints.md)),
`certificate_policy`, `smime` ([S/MIME](../certificates/smime.md)), `keycheck`
([weak-key & compromised-key gate](key-checks.md)), `upn`
([smartcard-logon / PKINIT](../certificates/smartcard-logon.md)), `qcstatements`
([eIDAS qualified certificates](../certificates/qualified-certificates.md)), `validity`, plus
two verdicts refined by the serving layer:

- **`approval`** — reports whether a real operator/API issuance would be *parked*
  for four-eyes approval (the `WouldPark` signal), resolved against the live
  approvals-engine state. Automated protocol paths (ACME/EST/SCEP/CMP) always
  bypass the approval gate and are not previewed here.
- **`attestation`** — the profile's enrollment key-attestation posture
  ([enrollment attestation](../protocols/scep-est.md)). Attestation is enforced on the
  EST/SCEP/ACME enrollment paths, not on the direct CSR issue path, so the
  preview surfaces it **informationally** (a `require` profile is reported as a
  warning, not a rejection).

## The verdict

The response resolves the overall outcome plus the leaf the certificate would
carry:

- `decision` — `accept` (would issue immediately), `park` (would be held for
  four-eyes approval), or `reject` (a fail-closed gate would refuse it).
- `would_issue` — true when no gate would reject (decision `accept` or `park`).
- `would_park` / `requires_approval` — the approval outcome and the profile's
  intent.
- Resolved leaf fields: `subject`, `sans`, `key_usages`, `ext_key_usages`,
  `not_before` / `not_after`, `validity_days` vs `requested_validity_days` vs
  `max_validity_days`, `subject_key_id` / `authority_key_id`, `must_staple`, and
  the full `extensions` list (OID, name, critical).
- `subject_key_provided` — false when no CSR was supplied, in which case a
  throwaway subject key is synthesized only to resolve the extension layout (the
  reported subject-key identifier is then indicative rather than final).
- `gates` — every gate's verdict, in evaluation order.

## Supplying the request

Provide **either** a PEM PKCS#10 CSR (its subject, public key, and SANs are
previewed exactly as issuance would take them) **or** the explicit identity
fields (`common_name` + SANs), in which case the subject key is synthesized.

## Interfaces

| Surface | How |
|---------|-----|
| CLI | `secsy-ca issue -ca <id> -csr req.csr -profile <p> -dry-run` — runs the full gate stack, prints the verdict, and **exits non-zero if the request would be rejected** (so it drops straight into a CI gate). No HSM, no serial, no record. |
| REST | `POST /api/ca/{id}/certificates:preview` with a `PreviewCertRequest` body (`csr` **or** `common_name`+SANs, `profile`, `validity_days`, and the optional `must_staple` / `upns` / `psd2` / `private_key_usage_period` overrides). Returns a `PreviewCertResult`. |
| gRPC | `PKIService.PreviewCertificate(PreviewCertificateRequest) → PreviewCertificateResponse` — the transport-agnostic mirror of the REST endpoint. |
| Console | The **Issue** page's *Preview (dry run)* button posts the current form (CA / profile / CSR / validity / Must-Staple / UPNs) to the preview endpoint and renders the decision banner and per-gate table without issuing. |

### Authorization

The preview requires **exactly the `issue` capability on the target CA** that a
single `POST …/issue` needs (`canIssueOn`, tenant-scoped). It is not a lower
privilege bar — a caller who could not issue cannot preview.

## Examples

CI gate — fail the build if a request would be rejected:

```bash
secsy-ca issue -ca web-ica -csr candidate.csr -profile server -dry-run
# prints each gate + the decision; exit code 0 = would issue, non-zero = rejected
```

REST preview of an explicit-identity request (no CSR):

```bash
curl -sS -u operator:… -X POST \
  https://pki.example.com/api/ca/web-ica/certificates:preview \
  -H 'Content-Type: application/json' \
  -d '{"profile":"server","common_name":"api.example.com","dns_names":["api.example.com"],"validity_days":90}' \
| jq '{decision, would_issue, gates: [.gates[] | {name, status}]}'
```

## Notes

- The requested validity is passed through **uncapped** so the `validity` gate
  can report a request that exceeds the profile maximum (rather than silently
  clamping it, as issuance does).
- The preview is a pure read: no `cert.issue` audit event, no issuance metric,
  no serial consumption. Compare with a real issuance, which is fully audited.
- Because the gate evaluators are shared with issuance, a preview verdict is an
  accurate predictor of the issuance outcome for the same inputs — the two
  cannot diverge in policy.

## See also

- [Weak-key & compromised-key gate](key-checks.md) — the keycheck gate the
  preview reports.
- [Certificate authority](../ca/overview.md) — the real issuance path.
- [Four-eyes / maker-checker approvals](../security/approvals.md) — the `park` decision.
- [Operator web console](../operations/web-console.md) — the Issue page's preview button.
