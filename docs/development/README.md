# Development, testing & release

*The quality gates a change has to clear.*

Contributor-facing documentation for the automated gates that guard the
codebase, and for the release pipeline that signs what ships. See also
[`TESTING.md`](../../TESTING.md) at the repository root for how to run the
suites.

| Guide | Covers |
|-------|--------|
| [**Performance & load benchmarking**](benchmarks.md) | Benchmark/load-test suite for the HSM hot paths (signing/issuance, OCSP/CRL, secret encrypt/decrypt), the bounded PKCS#11 session pool, baseline SoftHSM numbers, and the tuning knobs (session pool size, OCSP cache TTL) |
| [**Test-coverage measurement & ratchet gate**](coverage.md) | HSM-free statement-coverage gate that ratchets a committed baseline (`coverage/baseline.txt`) so coverage can only rise: `make cover`/`cover-check`/`cover-baseline`, the per-package + total table, the tolerance band, HTML/summary artifacts, the required no-HSM CI job, and the baseline-refresh workflow for contributors adding covered code |
| [**Fuzz & property testing**](fuzzing.md) | Native `go test -fuzz` over the untrusted-input parsers (CSR/DER, ACME JOSE/JWS, secret-envelope decrypt, OCSP/cert): targets, how to run local campaigns, CI smoke run, and handling crashes |
| [**Resilience & fault-injection testing**](resilience.md) | The chaos suite that deliberately degrades the PKI's runtime dependencies under concurrent load and asserts it still fails closed rather than corrupting state: HSM failover and session-pool exhaustion, PostgreSQL connection-drop storms, wrong-PIN and OAEP refusals, and 429/503 load shedding — `./scripts/chaos-test.sh` plus the advisory CI job. |
| [**Authorization & tenant-isolation regression matrix**](authz-regression-matrix.md) | The table-driven matrix that pins an explicit RBAC and tenant decision to every one of the ~116 REST routes and the gRPC `PKIService`, plus the AST-based route-completeness guard that fails CI when a new route ships without an entry — the standing defence against broken function-level and object-level authorization. |
| [**Supply-chain security (SBOM, signing, SLSA)**](supply-chain.md) | Hardened release pipeline for the container image and binaries: CycloneDX SBOMs (Go modules + image), cosign signing (keyless/OIDC or a configurable key), a cosign SBOM attestation, a SLSA Build L3 provenance attestation via `slsa-github-generator`, the `govulncheck` gating scan, the `make sbom`/`make sign`/`make verify` targets, and the `cosign verify`/`cosign verify-attestation`/`slsa-verifier` commands consumers run |

---

↩ Back to the [documentation map](../README.md) · [project README](../../README.md)
