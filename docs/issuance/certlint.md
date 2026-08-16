# Pre-issuance certificate linting

secsy-pki runs a **fail-closed pre-issuance lint gate** on every to-be-signed
certificate, *before* the HSM produces a signature. A lint violation in
`enforce` mode aborts issuance — nothing is signed, recorded, or published. The
gate has two backends:

1. **Hand-rolled Baseline Requirements checks** (`internal/certlint`, Task 27) —
   a small, dependency-free rule set covering the essentials of the CA/Browser
   Forum Baseline Requirements and RFC 5280: serial-number entropy, validity
   ordering and caps (incl. the 398-day public-TLS cap), leaf-not-CA,
   key-usage/EKU consistency, SAN-vs-CN handling, public-vs-internal name rules,
   and the S/MIME Baseline Requirements rule set. These always run.

2. **The optional `zlint` backend** (Task 88) — the industry-standard
   [`github.com/zmap/zlint`](https://github.com/zmap/zlint) suite of ~hundreds of
   RFC 5280 / CA/Browser Forum / Mozilla / Apple / ETSI lints. It **supplements**
   (never replaces) the hand-rolled checks and is **compiled in only under the
   `zlint` build tag**, so the default, FIPS, and supply-chain-hardened builds
   remain dependency-free. This document focuses on the zlint backend.

Both backends feed the same fail-closed gate, the same `cert.lint` audit event,
the same metrics, and the same `secsy-ca lint` CLI and `/api/lint` endpoint.

---

## Why a build tag

`zlint` pulls in `github.com/zmap/zlint/v3` and `github.com/zmap/zcrypto` (a
fork of the standard library's `crypto/x509`) plus a couple of transitive
dependencies. To keep the default binary — and the FIPS and
supply-chain-hardened builds — free of that dependency surface, the backend
lives behind the `zlint` build tag:

| File | Build tag | Contents |
| --- | --- | --- |
| `internal/certlint/zlint.go` | *(none)* | Config type `ZLintPolicy`, level→disposition mapping, `ZLintFindings`, `ZLintAvailable`. |
| `internal/certlint/zlint_stub.go` | `!zlint` | No-op `runZLint` (returns nothing). The default build. |
| `internal/certlint/zlint_backend.go` | `zlint` | The **only** file importing `zmap/zlint` and `zmap/zcrypto`. |

`certlint.ZLintAvailable()` reports whether the backend was compiled in. A
profile may enable zlint in config regardless; if the binary lacks the backend,
the hand-rolled checks still run and a **warning is logged at startup**
(`profile %q enables the zlint backend, but this binary was not built with
-tags zlint`).

### Building with zlint

```bash
# server + CLI with the zlint backend linked in
cd server && go build -tags zlint ./...

# or via the root Makefile
make build-zlint
```

The image build accepts the same tag:

```bash
make image GO_TAGS="sqlite zlint"
```

---

## How zlint is applied

zlint parses **DER**. secsy-pki wires it in at three points:

- **Pre-issuance gate (`ca.lintLeaf`).** The to-be-signed leaf is only a template
  at gate time — nothing is signed yet, so there is no DER to lint. secsy-pki
  synthesizes a faithful **linting certificate** (`pki.LintCertificateDER`): the
  exact leaf template the CA would sign — same subject, SANs, validity, serial,
  key usage, EKU, basic constraints, subject/authority key identifiers, CRL
  distribution points, AIA, and certificate-policy extensions — signed with a
  process-local **throwaway key** whose algorithm matches the issuer's. The
  signature bytes are cryptographically meaningless (structural lints do not
  verify them) and the artifact is never persisted or served. This is the same
  "linting certificate" technique production CAs use. Certificate-policy OIDs are
  assigned *before* the lint gate so zlint sees the `certificatePolicies`
  extension the leaf will carry.
- **`secsy-ca lint <file>`** and **`POST /api/lint`.** These lint an
  already-encoded certificate, so zlint runs on its real DER directly.

Post-quantum / hybrid profiles are **not** linted by zlint (it does not
understand ML-DSA); synthesis is skipped for them. SCT-list lints are not
evaluated at the pre-issuance gate, because Signed Certificate Timestamps do not
exist until the precertificate has been submitted to the CT logs (see
[certificate-transparency.md](certificate-transparency.md)).

---

## Configuration

zlint is configured per issuance profile under `profiles[].lint.zlint`:

```yaml
profiles:
  - name: public-tls
    max_validity_days: 397
    lint:
      public: true            # hand-rolled public-trust rules
      zlint:
        enabled: true         # effective only in a -tags zlint binary
        # Map each zlint severity level to the gate's disposition:
        #   enforce → blocks issuance | warn → reports only | ignore → dropped
        error_mode: enforce   # default: enforce
        warn_mode: warn       # default: warn
        notice_mode: ignore   # default: ignore
        # Restrict which lints run (optional). Empty include = all lints.
        include_sources: [CABF_BR, RFC5280]   # by source
        exclude_sources: []
        include_names: []                       # by individual lint name
        exclude_names: [w_sub_cert_aia_does_not_contain_issuing_ca_url]
        # Per-lint disposition override (wins over the level mapping):
        overrides:
          n_subject_common_name_included: ignore
          e_dnsname_not_valid_tld: enforce
```

### Level → disposition mapping

zlint assigns each lint a status; secsy-pki maps the actionable statuses onto the
gate:

| zlint status | Default disposition | Config key |
| --- | --- | --- |
| `error` / `fatal` | `enforce` (blocks issuance) | `error_mode` |
| `warn` | `warn` (reports only) | `warn_mode` |
| `notice` | `ignore` (dropped) | `notice_mode` |
| `pass` / `NA` / `NE` | — (never a finding) | — |

A per-lint `overrides` entry takes precedence over the level mapping, so you can
demote one noisy `error` lint to `warn`/`ignore`, or promote a `notice` to
`enforce`, without changing the global level mapping.

Known lint **sources** (for `include_sources` / `exclude_sources`): `RFC5280`,
`RFC5480`, `RFC5891`, `RFC6960`, `RFC6962`, `CABF_BR`, `CABF_CS_BR`,
`CABF_SMIME_BR`, `CABF_EV`, `Mozilla`, `Apple`, `Chrome`, `Community`,
`ETSI_ESI`.

---

## CLI

`secsy-ca lint` lints a certificate file (PEM **or** DER, or `-` for stdin):

```bash
# Hand-rolled checks only
secsy-ca lint cert.pem

# Add the industry-standard zlint suite (needs a -tags zlint binary)
secsy-ca lint -zlint cert.pem

# Restrict zlint to specific sources, apply a profile's policy
secsy-ca lint -profile public-tls -zlint -zlint-sources CABF_BR,RFC5280 cert.der
```

The policy line reports whether zlint is active:

```
Policy: mode=enforce public=true max_validity=0s zlint=on
  [ENFORCE] zlint/e_sub_cert_certificate_policies_missing: ERROR CABF_BR (BRs: 7.1.2.3)
  [WARN]    zlint/w_subject_common_name_included: WARN CABF_BR (BRs: 7.1.2.7.1)
Result: lint=fail errors=1 warnings=1 ...
```

If `-zlint` is requested but the binary lacks the backend, the CLI prints a note
(`zlint requested but this binary was not built with -tags zlint`) and reports
the hand-rolled checks only. The command exits non-zero when any `enforce`
finding is present.

`POST /api/lint` accepts a `"zlint": true` field and returns `zlint` (requested)
and `zlint_available` (compiled in) alongside the findings; the operator console
exposes a **zlint** checkbox on the Compliance → Lint page.

---

## Findings, audit, and metrics

zlint findings are namespaced with a `zlint/` code prefix so they are
distinguishable from hand-rolled checks everywhere:

- **Audit.** A run with findings appends a `cert.lint` event (result `error`
  when the gate blocks, `success` for warnings-only), with the failing/warning
  check codes — including `zlint/...` codes — in the detail.
- **Metrics.** `secsy_certificate_lints_total{result}` counts each run
  (`pass|warn|fail`); `secsy_certificate_lint_findings_total{code,mode}` counts
  each finding — zlint findings appear with `code="zlint/<lint_name>"`.

Because zlint has a fixed, bounded set of lint names, the `code` label
cardinality stays bounded.

---

## Dependency & `govulncheck` implications

Adding the zlint backend introduces these modules to `server/go.mod`:

- `github.com/zmap/zlint/v3` (direct)
- `github.com/zmap/zcrypto` (direct)
- `github.com/weppos/publicsuffix-go`, `github.com/pelletier/go-toml` (indirect)

**They are present in `go.mod` regardless of build tag** — Go modules are not
build-tag-aware, and `go mod tidy` records any import reachable under *any* tag.
However, they are **linked only under `-tags zlint`**:

```bash
go list -deps ./cmd/server            | grep -c zmap   # 0  (default build)
go list -tags zlint -deps ./cmd/server | grep -c zmap  # >0 (zlint build)
```

Consequences:

- **The default `govulncheck` gate is unaffected.** `make govulncheck` runs in
  source/reachability mode with `-tags sqlite` (no `zlint`), so the zmap
  packages are unreachable and their vulnerabilities — if any — are never
  reported. The default, FIPS, and supply-chain-hardened builds carry none of
  this code.
- **To scan the zlint dependency tree**, run the reachability scan *with* the
  tag:

  ```bash
  cd server && govulncheck -tags "sqlite zlint" ./...
  ```

  Operators who ship a `-tags zlint` build should add this to their pipeline. As
  of this writing it reports no vulnerabilities.
- **SBOMs.** The Go-module SBOM (`cyclonedx-gomod mod`) lists zmap because it is
  in the module graph; a per-binary SBOM of a default-tag build does not link it.

See [supply-chain.md](../development/supply-chain.md) for the release pipeline and the
`govulncheck` gate.

---

## Limitations

- **Throwaway signature.** The pre-issuance linting certificate is signed with an
  ephemeral key, so signature-*verification* lints are not meaningful; the
  signature *algorithm* matches the issuer, so algorithm lints are faithful.
- **SCTs.** Pre-issuance, no SCTs exist, so CT SCT-count lints are `notice`/`NE`
  and (by default) ignored at the gate. The CT subsystem enforces SCT policy
  separately.
- **PQC/hybrid.** zlint does not lint ML-DSA certificates; those profiles skip
  the zlint backend (the hand-rolled checks still apply).
