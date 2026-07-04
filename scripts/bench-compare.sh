#!/usr/bin/env bash
#
# bench-compare.sh — compare fresh benchmark results against the committed
# baseline with benchstat and surface statistically-significant regressions.
#
# It is the comparator behind `make bench-compare` and the advisory
# benchmark-regression CI job. The benchmark *run* lives in the Makefile
# (single source of the `go test -bench` invocation); this script only diffs an
# already-produced results file against the baseline, so the two cannot drift.
#
# Usage:
#   scripts/bench-compare.sh <new-results-file> [baseline-file]
#
#   <new-results-file>  raw `go test -bench` output for the current tree
#                       (produced by `make bench` -> dist/bench-new.txt).
#   [baseline-file]     committed baseline (default: bench/baseline.txt).
#
# benchstat reports "~" when a difference is indistinguishable from noise and a
# signed percentage only when it is statistically significant (p < alpha). This
# script fails (exit 1) when any significant *regression* — a slower sec/op or a
# larger B/op / allocs/op — is at or above BENCH_REGRESS_PCT (default 10%).
# Improvements ("-N%") and noise ("~") never fail it. When run under GitHub
# Actions it also writes the full benchstat table to the job step summary.
#
# Cross-machine note: absolute ns/op differs by CPU, so the committed baseline is
# only an apples-to-apples reference when it was generated on the same machine
# class the gate runs on (GitHub ubuntu-latest). That is why the CI job is
# advisory (continue-on-error) and why `make bench-baseline` prints a reminder.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

NEW="${1:-}"
BASELINE="${2:-$REPO_ROOT/bench/baseline.txt}"
if [ -z "$NEW" ]; then
  echo "usage: $0 <new-results-file> [baseline-file]" >&2
  exit 2
fi
if [ ! -f "$NEW" ]; then
  echo "!! new results file not found: $NEW (run 'make bench' first)" >&2
  exit 2
fi
if [ ! -f "$BASELINE" ]; then
  echo "!! baseline not found: $BASELINE" >&2
  echo "   generate it with 'make bench-baseline' and commit it." >&2
  exit 2
fi

# Ensure the Go toolchain is on PATH (matches the project convention) and pin
# benchstat so its output format cannot drift across runs. BENCHSTAT_VERSION is
# passed by the Makefile; the default here keeps the script runnable standalone.
export PATH="/usr/local/go/bin:$PATH"
export GOTOOLCHAIN=auto
BENCHSTAT_VERSION="${BENCHSTAT_VERSION:-v0.0.0-20260615155930-9e4b9ddef5b6}"
BENCH_REGRESS_PCT="${BENCH_REGRESS_PCT:-10}"
BENCHSTAT=(go run "golang.org/x/perf/cmd/benchstat@${BENCHSTAT_VERSION}")

echo ">> baseline: $BASELINE"
echo ">> current:  $NEW"
echo ">> regression threshold: ${BENCH_REGRESS_PCT}% (significant slowdown / allocation increase)"
echo

# Human-readable comparison table (also captured for the CI step summary).
TABLE="$("${BENCHSTAT[@]}" "$BASELINE" "$NEW" 2>/dev/null)"
echo "$TABLE"
echo

# Machine-readable comparison for the regression check. benchstat groups results
# into per-metric blocks (sec/op, B/op, allocs/op); the "vs base" column (field
# 6) is "~" for noise or a signed percentage when significant.
CSV="$("${BENCHSTAT[@]}" -format csv "$BASELINE" "$NEW" 2>/dev/null)"

REGRESSIONS="$(printf '%s\n' "$CSV" | awk -F',' -v thr="$BENCH_REGRESS_PCT" '
  /^pkg: / { pkg=$0; sub(/^pkg: /,"",pkg); next }
  $1=="" && ($2=="sec/op" || $2=="B/op" || $2=="allocs/op") { metric=$2; next }
  $1!="" && $1!="geomean" && NF>=6 {
    vs=$6
    if (vs ~ /^\+[0-9]/) {
      pct=vs; gsub(/[+%]/,"",pct)
      if (pct+0 >= thr+0)
        printf("  %-30s %-42s %-10s %s\n", pkg, $1, metric, vs)
    }
  }
')"

# GitHub Actions step summary: surface the whole table prominently on the PR.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Benchmark regression gate"
    echo
    echo "Baseline \`$(basename "$BASELINE")\` vs current tree — threshold ${BENCH_REGRESS_PCT}%."
    echo
    echo '```'
    echo "$TABLE"
    echo '```'
    if [ -n "$REGRESSIONS" ]; then
      echo
      echo "**⚠️ Significant regressions (≥ ${BENCH_REGRESS_PCT}%):**"
      echo
      echo '```'
      echo "$REGRESSIONS"
      echo '```'
    else
      echo
      echo "✅ No significant regressions."
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ -n "$REGRESSIONS" ]; then
  echo "!! significant benchmark regression(s) detected (>= ${BENCH_REGRESS_PCT}%):" >&2
  echo "$REGRESSIONS" >&2
  echo >&2
  echo "   Investigate before merging. If the change is expected, refresh the baseline:" >&2
  echo "     make bench-baseline && git add bench/baseline.txt" >&2
  exit 1
fi

echo ">> no significant regressions at or above ${BENCH_REGRESS_PCT}%."
