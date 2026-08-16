# Certificate chain / path validation

secsy-pki can **validate a supplied certificate against a CA's configured trust
anchors** and return a structured, human-readable verdict — the diagnostic
counterpart of issuance. Given a leaf (and any intermediates you can supply), it
builds a path to one of the CA's trust anchors, checks the validity window, looks
up **live revocation status** (CRL + OCSP, including reversible on-hold), and
evaluates name-constraint and certificate-policy conformance plus weak
key/signature flags. **Nothing is signed** and the HSM is never touched.

It answers the questions an operator asks during an incident or a client-side
"why won't this verify?": *did a chain build at all, is every certificate in
date, is any of them revoked or on hold, and does the leaf actually conform to
the issuing CA's constraints and policies?*

## Why a dedicated validator (not `openssl verify`)

The engine (`internal/certvalidate`) is a **tolerant, structural** path builder,
deliberately *not* `crypto/x509`'s `Verify`. `x509.Verify` is all-or-nothing: the
first problem aborts with a single opaque error, and it cannot report revocation
or the CA-specific name-constraint/policy state. This validator instead:

- builds the path by a tolerant depth-first search over the supplied
  intermediates and the CA's trust anchors, so it can still **report a partial
  chain** and say exactly where the path broke;
- runs each dimension as an **independent check** and reports all of them, so one
  failure never hides the others; and
- resolves **live revocation** against the CA's own CRL/OCSP state (the same
  revocation store the responders serve), including the reversible `on-hold`
  state ([suspend/hold & release](overview.md)).

Because it reads only the database (trust anchors + revocation store) and never
the HSM, it works **during an HSM outage** — the CLI dispatches it before the key
provider is even constructed.

## The report

| Field | Meaning |
|-------|---------|
| `valid` | Overall verdict: a chain built to a trust anchor and no check failed. |
| `chain_built` | Whether a path to a trust anchor was found at all. |
| `checks[]` | Per-dimension results, each `pass` / `fail` / `warn` / `skipped` with a detail and optional findings. |
| `chain[]` | The resolved path: for each certificate its position, subject, serial, `not_after`, live revocation state, and flags (`anchor` / `CA` / `expired` / `not-yet-valid` / `weak-key` / `weak-signature`). |
| `reasons[]` / `warnings[]` | Top-level failure reasons and non-fatal warnings. |
| `trust_anchor` / `ca_label` | The CA the leaf was validated against. |

The `checks` dimensions are:

- **`chain`** — a path was built to a configured trust anchor.
- **`validity`** — every certificate in the path is within its validity window.
- **`revocation`** — live CRL + OCSP status for each certificate (`skipped` when
  you ask to skip it, e.g. offline).
- **`name_constraints`** — the leaf's names lie within every issuer's RFC 5280
  Name Constraints ([Name Constraints](../issuance/name-constraints.md)); `skipped` when no
  CA in the path carries constraints.
- **`certificate_policy`** — certificate-policy consistency down the path;
  `skipped` when no policies are asserted.
- **`key_usage`** — CA and leaf `keyUsage` / `basicConstraints` are consistent
  (a `warn` flags anomalies rather than hard-failing).

## Interfaces

| Surface | How |
|---------|-----|
| CLI | `secsy-ca validate-cert -ca <id\|label> [-intermediate file …] [-skip-revocation] [-json] <cert>` — `<cert>` is PEM or DER (`-` for stdin); a PEM bundle's first certificate is the leaf and the rest are treated as supplied intermediates. Exits **non-zero when the chain is not valid**, so it drops into a monitoring script. HSM-independent. |
| REST | `POST /api/validate` with `{ "ca": "<id>", "certificate": "<PEM>", "intermediates": ["<PEM>", …], "skip_revocation": false }` → a `ChainValidationReport`. |
| gRPC | `PKIService.ValidateChain(ValidateChainRequest) → ValidateChainResponse` — the same structured verdict over gRPC. |
| Console | The **Validate** page: pick a trust-anchor CA, paste the leaf (+ optional intermediates), optionally skip revocation, and read the verdict banner, per-dimension check table, and resolved-chain table. |

Authorization is the standard read authorization on the target CA (tenant-scoped
like every other CA read).

## Examples

CLI, validating a served leaf against an issuing CA (revocation live):

```bash
# Grab what a server presents and validate the leaf against our CA
openssl s_client -connect api.example.com:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 > leaf.pem
secsy-ca validate-cert -ca web-ica leaf.pem
#   VALID — chain built against "web-ica Issuing CA"
#   chain           pass   path: leaf -> web-ica -> Example Root
#   validity        pass   all certificates in date
#   revocation      pass   good (CRL + OCSP)
#   name_constraints pass  all names within issuer constraints
#   …
```

REST, skipping revocation (offline / air-gapped check):

```bash
curl -sS -u operator:… -X POST https://pki.example.com/api/validate \
  -H 'Content-Type: application/json' \
  -d '{"ca":"web-ica","certificate":"-----BEGIN CERTIFICATE-----\n…","skip_revocation":true}' \
| jq '{valid, chain_built, checks: [.checks[] | {name, status}]}'
```

## Notes

- The validator is **read-only**: no serial, no audit event, no HSM. It is safe
  to run continuously (e.g. from a monitoring probe).
- Supply intermediates when the leaf's issuers are not among the CA's stored
  anchors/intermediates — the tolerant builder will bridge the path and still
  report where it could not.
- Revocation resolution honours the reversible `on-hold` state, so a suspended
  certificate is reported as held (not permanently revoked) — matching what the
  OCSP responder returns.

## See also

- [Certificate authority](overview.md) — issuance, revocation, and
  suspend/hold, the states this validator reports.
- [Name Constraints & Certificate Policies](../issuance/name-constraints.md) — the
  constraint/policy dimensions.
- [Weak-key & compromised-key gate](../issuance/key-checks.md) — the weak-key flags shown per
  chain certificate.
- [gRPC API](../protocols/grpc-api.md) — the `ValidateChain` RPC.
- [Operator web console](../operations/web-console.md) — the Validate page.
