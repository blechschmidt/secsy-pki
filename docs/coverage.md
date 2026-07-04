# Test-coverage measurement & ratchet gate

This document describes how secsy-pki measures Go test coverage and the
**ratcheting coverage gate** that keeps it from silently regressing as the
codebase grows. The gate is HSM-free, deterministic, and modeled on the
[benchmark-regression gate](benchmarks.md#benchmark-regression-gate): a committed
baseline that can only move **up**.

- [What is measured](#what-is-measured)
- [The Makefile targets](#the-makefile-targets)
- [How the ratchet works](#how-the-ratchet-works)
- [Refreshing the baseline](#refreshing-the-baseline)
- [The CI job](#the-ci-job)
- [How percentages are computed](#how-percentages-are-computed)
- [Tuning & troubleshooting](#tuning--troubleshooting)

## What is measured

The gate measures **statement coverage** across the server module's
`./internal/...` packages, run with the `sqlite` build tag and **without a
SoftHSM/PKCS#11 token**:

```
go test -tags sqlite -covermode=set -coverprofile=dist/coverage.out -count=1 ./internal/...
```

Running HSM-free is deliberate. It makes the measurement reproducible on any
machine — including the CI runner, which installs no SoftHSM for this job — and
it is exactly the subset the gate can enforce deterministically. HSM-backed tests
(`ca`, `e2e`, `secret`, `handlers`, `pkcs12`, `signing`, `sshca`, `tsa`,
`keyprovider`, `doctor`, …) detect the missing token and **skip cleanly**, so each
package contributes only the coverage reachable in software. That HSM-free subset
is what the committed baseline captures. Loading a token later only *raises*
coverage (more tests run), which never trips the ratchet.

Two numbers are tracked:

- **Total** — statements covered across the whole subset. Rock-stable
  run-to-run.
- **Per package** — one percentage per `internal/*` package, matching Go's own
  `coverage: N% of statements` line exactly.

Packages with test files but no measurable statements of their own (the pure
integration packages `internal/e2e` and `internal/chaos`) report
`coverage: [no statements]` and are simply absent from the baseline — they carry
no floor.

## The Makefile targets

Everything is driven from the root `Makefile`; the `go test` invocation lives in
a single `run_cover` definition so the measurement, the gate, and the baseline
can never diverge.

| Target | What it does |
|--------|--------------|
| `make cover` | Runs the HSM-free coverage set and emits artifacts: `dist/coverage.out` (raw profile), `dist/coverage.html` (browsable line-by-line report), and `dist/coverage-summary.txt` (per-package + total table). |
| `make cover-check` | Runs `cover`, then ratchets the result against `coverage/baseline.txt`. **Exits non-zero** — failing the build — if the total or any package dropped, listing which packages regressed. |
| `make cover-baseline` | Regenerates `coverage/baseline.txt` (HSM-free) via `scripts/cover-baseline.sh`. Run this intentionally after you add covered code, then commit the file. |

Overridable knobs (all on the `make` line): `COVER_TAGS` (default `sqlite`),
`COVER_PKGS` (default `./internal/...`), `COVER_TOLERANCE` (default `1.0`), and
`COVER_BASELINE` (default `coverage/baseline.txt`).

Artifacts land in `dist/` (git-ignored); only `coverage/baseline.txt` is
committed.

## How the ratchet works

`scripts/cover-check.sh` aggregates the fresh profile into per-package and total
percentages and compares them to the committed baseline. A package **fails the
gate only when its coverage drops more than `COVER_TOLERANCE` percentage points
(default 1.0) below its baseline entry.** The total is ratcheted the same way.

The tolerance is the coverage analogue of benchstat's `~` noise band. Measured
run-to-run jitter is tiny — the total is identical across runs, and only a couple
of timing/goroutine-sensitive packages wobble, by well under one point — so a
1.0pp band absorbs the noise while still catching a genuine regression (deleting a
test, or adding a chunk of untested code, moves the affected package by several
points). Concretely:

- **Coverage dropped > 1.0pp** on a package (or the total) → **FAIL**, and the
  offending packages are printed with their baseline and delta.
- **New package** not in the baseline → reported as new, does **not** fail (refresh
  to adopt it).
- **Removed package** in the baseline but gone now → reported for information,
  does **not** fail.
- **Coverage rose, unchanged, or dropped ≤ 1.0pp** → **PASS**.

The full ratchet table is printed to the terminal and, in CI, to the GitHub job
**step summary**.

## Refreshing the baseline

The baseline is a floor, so you update it whenever coverage legitimately goes
**up** — you added tests, or added code your tests exercise — or when a genuine,
intended drop needs to be re-accepted (e.g. you removed dead code that had tests).
In both cases:

```bash
scripts/cover-baseline.sh      # or: make cover-baseline
git add coverage/baseline.txt  # commit it in the SAME change as the code
```

`scripts/cover-baseline.sh` **clears any SoftHSM/PKCS#11 environment** before
measuring, so the committed baseline is always the reproducible HSM-free floor
regardless of what your shell has loaded. (If a token were loaded, the baseline
would capture the higher HSM-inclusive numbers, and the HSM-free CI gate would
then fail.) It reuses `make cover` for the run itself, so the baseline is measured
with the identical invocation the gate uses.

`coverage/baseline.txt` is a generated, human-readable table (`<package>\t<pct>`,
sorted, with a `total` line and a comment header). Review its diff before
committing — it makes coverage changes visible in code review.

> **Machine-class note.** Statement coverage is largely machine-independent
> (it records *which* statements executed, not timing), so a locally generated
> baseline is normally valid in CI. If a timing-sensitive package ever diverges on
> the runner beyond the tolerance, regenerate the baseline **authoritatively on the
> runner** — dispatch the workflow with `refresh_coverage_baseline: true` and commit
> the uploaded artifact (see below).

## The CI job

The **Test-coverage ratchet gate (no HSM)** job in
`.github/workflows/enterprise-ci.yaml` runs `make cover-check` on every push and
PR. It is a **required** gate (it blocks merges on a regression) — unlike the
benchmark gate, which is advisory because absolute ns/op is machine-noise-
sensitive; statement coverage is deterministic enough to enforce. The job:

- installs **no SoftHSM** and runs **no Postgres** service — matching exactly the
  environment `scripts/cover-baseline.sh` generates the baseline in;
- writes the per-package ratchet table to the GitHub **step summary**;
- uploads `dist/coverage.html` + `dist/coverage-summary.txt` as the
  **`coverage-report`** artifact **even on failure**, so a drop can be inspected
  line-by-line from the run.

To refresh the baseline on the runner class, trigger the workflow manually
(`workflow_dispatch`) with **`refresh_coverage_baseline: true`**: the job runs
`make cover-baseline` on the runner and uploads `coverage/baseline.txt` as the
**`coverage-baseline`** artifact — download it, drop it in place, and commit.

## How percentages are computed

The numbers come straight from the merged coverage profile, not from scraping
`go test` output, so they are stable and single-sourced. In `covermode=set` each
statement is covered (execution count > 0) or not; for a package,
`pct = 100 × covered_statements / total_statements`, summed over that package's
files. This reproduces Go's own per-package `coverage: N%` and the
`go tool cover -func` total exactly. `scripts/cover-check.sh --summary <profile>`
prints the table for any profile if you want to compute it by hand.

## Tuning & troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| `make cover-check` fails after you added tests | You raised coverage but did not move the floor. Refresh: `scripts/cover-baseline.sh && git add coverage/baseline.txt`. |
| A package you didn't touch shows a small drop | Run-to-run jitter on a timing-sensitive package. If it is under the tolerance the gate passes; a persistent drop above 1.0pp is real — investigate, or refresh if intended. |
| Gate fails only in CI, not locally | Your local run may have had a token loaded (inflating coverage). Reproduce the gate's environment: clear `SECSY_PKCS11_MODULE`/`SOFTHSM2_CONF` and re-run `make cover-check`. |
| `baseline not found` | The baseline is missing/renamed. Regenerate with `make cover-baseline`. |
| Want a stricter/looser gate | Override `COVER_TOLERANCE` (e.g. `make cover-check COVER_TOLERANCE=0.5`). Keep the workflow and Makefile in mind if you change the default. |
