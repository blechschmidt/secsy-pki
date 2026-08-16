# Continuous integration: workflows, gates & runner minutes

This document describes what runs in CI, which jobs can block a change and which
only advise, and how the suite is kept affordable on a **private** repository's
GitHub Actions allowance.

- [The workflows](#the-workflows)
- [Required vs advisory gates](#required-vs-advisory-gates)
- [Runner minutes](#runner-minutes)
- [Diagnosing a red run](#diagnosing-a-red-run)
- [Reproducing every gate locally](#reproducing-every-gate-locally)

## The workflows

| Workflow | File | Triggers | What it gates |
|----------|------|----------|---------------|
| **Enterprise CI (SoftHSM)** | `enterprise-ci.yaml` | push/PR on `enterprise`, nightly, dispatch | The main suite: the HSM-backed integration flow plus the static-analysis, coverage, OpenAPI, docs-structure, FIPS, fuzz and Postgres/DR gates |
| **Test** | `test.yaml` | push/PR on `enterprise`, dispatch | The upstream project's original job. Its unique coverage is the root-package `integration_test.go`, which drives a live server over HTTP behind a real OIDC provider (KeyCloak); everything else it runs is a subset of Enterprise CI |
| **Supply chain** | `supply-chain.yaml` | push/PR on `enterprise`, dispatch | `govulncheck` (gating) and the CycloneDX Go-module SBOM — see [supply-chain security](supply-chain.md) |
| **Kubernetes smoke** | `k8s-smoke.yaml` | push/PR on `enterprise` touching the image/chart/server | Builds the image and deploys the Helm chart on an ephemeral kind cluster against SoftHSM |
| **Documentation site** | `docs.yaml` | push/PR on `enterprise` touching docs sources | The `--strict` Material for MkDocs build, and publishing to GitHub Pages — see [documentation site](documentation-site.md) |

## Required vs advisory gates

Nine jobs in `enterprise-ci.yaml` are **required**: a failure is a real defect to
fix. Four are **advisory** (`continue-on-error: true`) because they exercise
timing-sensitive faults, third-party clients or machine-dependent numbers, and
so can go red for reasons that are not a regression in this repository:

| Advisory job | Why it cannot block | Detail |
|--------------|--------------------|--------|
| Chaos / fault-injection | Injects timing-sensitive faults | [resilience](resilience.md) |
| Data-race detector | Long, dependency-heavy run under `-race` | `make test-race` |
| External-client interop | Depends on pinned third-party clients fetched at run time | `scripts/interop-test.sh` |
| Benchmark regression | `ns/op` is noisy on shared hosted runners | [benchmarks](benchmarks.md#benchmark-regression-gate) |

Because they cannot block anything, they run on the **nightly schedule and on
manual dispatch only** — not on every push. That is the single largest lever on
the suite's cost (see below). To run one against a specific commit, dispatch
*Enterprise CI (SoftHSM)* from the Actions tab.

## Runner minutes

GitHub Actions is free for public repositories but **metered for private ones**.
secsy-pki is private, so every job on every push draws on the account's monthly
allowance, and the suite is large: a full run is 12 jobs in `enterprise-ci.yaml`
alone, plus four more workflows.

The allowance was exhausted on **2026-07-04**. The symptom is distinctive and
worth recognising, because it looks nothing like a test failure:

> Every job in every workflow completes in ~2 seconds, with **no runner
> assigned and zero steps executed**. The GitHub UI reports the run as failed
> without any log output.

That is GitHub declining to *schedule* the jobs, not the jobs failing. It
persisted across a monthly billing reset, which rules out simple minute
exhaustion and points at an account-level block (a spending limit that is still
at its cap, or a billing problem). **Only the repository owner can clear it**,
by one of:

- making the repository **public** — Actions is unmetered for public repositories;
- raising the **spending limit** / attaching a payment method for private minutes;
- running the suite on **self-hosted runners**, which are not metered.

Until then no workflow can run, regardless of the state of the code.

Three measures keep the suite within a realistic allowance once it is restored:

1. **Advisory suites are nightly, not per-push** (above). They are the most
   expensive half of `enterprise-ci.yaml` and gate nothing.
2. **Every workflow has a `concurrency` group with `cancel-in-progress`**, so a
   burst of pushes does not run superseded jobs to completion. `test.yaml`
   previously had neither this nor a branch filter — it matched
   `branches: ['**']`, and on 2026-07-02 alone that produced 52 runs in a day.
3. **Path filters** on the image/chart and documentation workflows, so a
   docs-only change does not start a kind cluster.

## Diagnosing a red run

Work down this list — the first two cost nothing and explain most red runs:

1. **Zero steps, no runner, ~2s duration?** Billing, not code. See
   [runner minutes](#runner-minutes).
2. **`startup_failure` conclusion?** The workflow YAML is invalid; the job list
   will be empty.
3. **A single job red?** Reproduce it locally — every gate has a one-command
   equivalent (next section).

The job-level detail the UI hides is available from the API:

```sh
gh run list --branch enterprise --limit 10
gh run view <run-id> --log-failed
```

## Reproducing every gate locally

Each required gate is a Makefile target or script that CI invokes verbatim, so a
local run and a CI run cannot drift:

| Job | Command |
|-----|---------|
| SoftHSM integration suite | `./scripts/integration-test.sh` |
| Static analysis | `make vet && make lint` |
| Test-coverage ratchet | `make cover-check` |
| OpenAPI spec & client SDK | `server/scripts/openapi-check.sh` |
| Documentation structure | `./scripts/check-docs.sh` |
| Documentation site (strict) | `make docs-site` |
| Fuzz smoke | `FUZZTIME=20s server/scripts/fuzz.sh` |
| FIPS 140-3 | `make build-fips` |
| DR store integrity | `SECSY_TEST_PG_DSN=… go test -tags sqlite -p 1 ./internal/database/... ./internal/leader/...` |
| govulncheck | `make govulncheck` |
| Chaos (advisory) | `./scripts/chaos-test.sh -v` |
| Data race (advisory) | `make test-race` |
| Interop (advisory) | `./scripts/interop-test.sh` |
| Benchmarks (advisory) | `make bench-compare` |

Two environment notes that cause local-only failures:

- The Postgres-backed packages must be serialized with **`-p 1`**. Running the
  whole tree in parallel against one database exhausts connections and reports
  `driver: bad connection`, which is a harness artifact, not a regression.
- The coverage gate must run **without** an HSM or Postgres in the environment,
  matching the job that generated the baseline. Unset `SECSY_PKCS11_MODULE`,
  `SOFTHSM2_CONF` and `SECSY_TEST_PG_DSN` before `make cover-check`, or the
  numbers will not be comparable. See [coverage](coverage.md).

**Never commit a coverage baseline generated on a developer machine.** Env vars
are not the only thing that moves the numbers — *attached hardware* does too. A
host with a YubiHSM 2 on USB covers device paths in `internal/yubihsm` that a
hosted runner cannot reach, which recorded that package 18.6pp too high and
failed the ratchet on the next push. Refresh the baseline on the runner class
that enforces it: dispatch *Enterprise CI (SoftHSM)* with
`refresh_coverage_baseline=true`, then download the `coverage-baseline`
artifact and commit it verbatim. The same applies to `bench/baseline.txt`
(`refresh_baseline=true`).

---

↩ Back to the [development index](README.md) · [documentation map](../README.md)
