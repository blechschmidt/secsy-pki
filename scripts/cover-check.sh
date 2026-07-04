#!/usr/bin/env bash
#
# cover-check.sh — aggregate Go statement coverage per package from a coverage
# profile and enforce a *ratcheting* baseline: total and per-package coverage may
# only rise. It is the comparator behind `make cover-check` and the HSM-free
# coverage-gate CI job, and the summarizer behind `make cover` / the baseline.
#
# The coverage *run* (`go test -coverprofile`) lives in the Makefile (single
# source of the invocation, reused by `make cover` and the baseline refresh); this
# script only (a) summarizes an already-produced profile and (b) diffs that
# summary against the committed baseline, so the two cannot drift.
#
# Usage:
#   cover-check.sh --summary <profile>          # print "<pkg>\t<pct>" table (+ total); no gate
#   cover-check.sh <profile> [baseline-file]    # ratchet <profile> against the baseline
#
#   <profile>        merged coverage profile for the current tree
#                    (produced by `make cover` -> dist/coverage.out).
#   [baseline-file]  committed baseline (default: coverage/baseline.txt).
#
# Ratchet semantics: a package fails the gate only when its coverage drops MORE
# than COVER_TOLERANCE percentage points (default 1.0) below its baseline entry.
# The small tolerance absorbs run-to-run coverage jitter — a handful of
# timing/goroutine-sensitive packages wobble under 1pp between runs — exactly as
# benchstat's "~" band absorbs benchmark noise, so the gate fails only on a real,
# repeatable drop. New packages (absent from the baseline) never fail it; refresh
# the baseline to adopt them. Removed packages are reported but do not fail it.
#
# HSM-free note: the profile must be produced WITHOUT a token (the CI gate runs
# HSM-free). Packages whose tests need SoftHSM contribute only their HSM-free
# reachable coverage; that is deterministic and is exactly what the committed
# baseline captures. Running with a token loaded only *raises* coverage, which
# never trips the ratchet.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

MODULE_PREFIX="github.com/blechschmidt/secsy-pki/server/"
COVER_TOLERANCE="${COVER_TOLERANCE:-1.0}"

# summarize <profile> -> "total\t<pct>" then "<pkg>\t<pct>" sorted by package.
# Percentages are computed straight from the profile (covermode=set: a statement
# is covered when its execution count is > 0), which matches Go's own per-package
# `coverage: N% of statements` and `go tool cover -func` total exactly. Note the
# per-statement percentage is folded into a variable BEFORE printf — a bare ">"
# inside printf's argument list is parsed by awk as output redirection.
summarize() {
  local profile="$1"
  if [ ! -f "$profile" ]; then
    echo "!! coverage profile not found: $profile (run 'make cover' first)" >&2
    return 2
  fi
  awk '
    /^mode:/ { next }
    { t += $2; if ($3 + 0 > 0) c += $2 }
    END { p = 0; if (t > 0) p = 100.0 * c / t; printf "total\t%.1f\n", p }
  ' "$profile"
  awk -v pre="$MODULE_PREFIX" '
    /^mode:/ { next }
    {
      fp = $1
      sub(/:[0-9]+\.[0-9]+,[0-9]+\.[0-9]+$/, "", fp)   # strip :startL.col,endL.col
      sub(/\/[^\/]+\.go$/, "", fp)                       # strip /file.go -> package dir
      if (index(fp, pre) == 1) fp = substr(fp, length(pre) + 1)
      tot[fp] += $2
      if ($3 + 0 > 0) cov[fp] += $2
    }
    END {
      for (pp in tot) {
        pc = 0; if (tot[pp] > 0) pc = 100.0 * cov[pp] / tot[pp]
        printf "%s\t%.1f\n", pp, pc
      }
    }
  ' "$profile" | sort
}

# --- summary mode ----------------------------------------------------------
if [ "${1:-}" = "--summary" ]; then
  if [ -z "${2:-}" ]; then
    echo "usage: $0 --summary <profile>" >&2
    exit 2
  fi
  summarize "$2"
  exit 0
fi

# --- ratchet mode ----------------------------------------------------------
NEW="${1:-}"
BASELINE="${2:-$REPO_ROOT/coverage/baseline.txt}"
if [ -z "$NEW" ]; then
  echo "usage: $0 <profile> [baseline-file]   (or: $0 --summary <profile>)" >&2
  exit 2
fi
if [ ! -f "$NEW" ]; then
  echo "!! coverage profile not found: $NEW (run 'make cover' first)" >&2
  exit 2
fi
if [ ! -f "$BASELINE" ]; then
  echo "!! baseline not found: $BASELINE" >&2
  echo "   generate it with 'make cover-baseline' (scripts/cover-baseline.sh) and commit it." >&2
  exit 2
fi

CUR="$(mktemp)"
trap 'rm -f "$CUR"' EXIT
summarize "$NEW" > "$CUR"

# Compare current summary (file 2) against the baseline (file 1). The report is
# emitted on stdout; awk exits 1 when a package (or the total) regressed beyond
# the tolerance so the caller can fail the build.
REPORT="$(
  awk -F'\t' -v tol="$COVER_TOLERANCE" -v baseline="$(basename "$BASELINE")" '
    function abs(x) { return x < 0 ? -x : x }
    # File 1: committed baseline. Skip comment/blank lines.
    FNR == NR {
      if ($0 ~ /^[[:space:]]*#/ || NF < 2) next
      base[$1] = $2; bseen[$1] = 1; bord[++nb] = $1
      next
    }
    # File 2: current summary (already sorted; total first).
    { cur[$1] = $2; cseen[$1] = 1; cord[++nc] = $1 }
    END {
      teff = tol + 1e-9

      # Total ratchet.
      totline = "  (total not present)"
      totalfail = 0
      if (("total" in cur) && ("total" in base)) {
        d = cur["total"] - base["total"]
        mark = "ok"
        if (d < -teff) { mark = "REGRESSED"; totalfail = 1 }
        else if (d > teff) mark = "up"
        totline = sprintf("  total%*s%6.1f%%   (baseline %5.1f%%,  %+.1fpp)   %s",
                          28, "", cur["total"], base["total"], d, mark)
      } else if ("total" in cur) {
        totline = sprintf("  total%*s%6.1f%%   (no baseline)", 28, "", cur["total"])
      }

      # Per-package: regressions and new packages, in current (sorted) order.
      for (i = 1; i <= nc; i++) {
        p = cord[i]; if (p == "total") continue
        if (p in base) {
          d = cur[p] - base[p]
          if (d < -teff)
            reg[++nreg] = sprintf("  %-34s %6.1f%%   (baseline %5.1f%%,  %+.1fpp)", p, cur[p], base[p], d)
        } else {
          neu[++nnew] = sprintf("  %-34s %6.1f%%", p, cur[p])
        }
      }
      # Removed packages, in baseline (sorted) order.
      for (i = 1; i <= nb; i++) {
        p = bord[i]; if (p == "total") continue
        if (!(p in cur)) rem[++nrem] = sprintf("  %-34s (was %.1f%%)", p, base[p])
      }

      printf "Coverage ratchet — baseline %s, tolerance %.1fpp\n\n", baseline, tol
      print totline
      print ""
      if (nreg > 0) {
        printf "Regressions (coverage dropped > %.1fpp below baseline):\n", tol
        for (i = 1; i <= nreg; i++) print reg[i]
        print ""
      }
      if (nnew > 0) {
        print "New packages (not in baseline — refresh to adopt them):"
        for (i = 1; i <= nnew; i++) print neu[i]
        print ""
      }
      if (nrem > 0) {
        print "Removed packages (in baseline, absent now — informational):"
        for (i = 1; i <= nrem; i++) print rem[i]
        print ""
      }

      if (nreg > 0 || totalfail) {
        printf "RESULT: FAIL — %d package(s)%s regressed beyond %.1fpp.\n",
               nreg, (totalfail ? " and the total" : ""), tol
        exit 1
      }
      printf "RESULT: PASS — no package regressed beyond %.1fpp (%d covered, %d new).\n",
             tol, nc - 1, nnew
    }
  ' "$BASELINE" "$CUR"
)" && RC=0 || RC=$?

printf '%s\n' "$REPORT"

# Surface the ratchet result prominently on the PR when run under GitHub Actions.
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Test-coverage ratchet"
    echo
    echo "Baseline \`$(basename "$BASELINE")\` vs current tree — tolerance ${COVER_TOLERANCE}pp (HSM-free)."
    echo
    echo '```'
    printf '%s\n' "$REPORT"
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [ "$RC" -ne 0 ]; then
  echo >&2
  echo "!! test coverage regressed. Investigate the drop above. If it is intended" >&2
  echo "   (e.g. you deleted dead code that had tests), refresh and commit the baseline:" >&2
  echo "     scripts/cover-baseline.sh && git add coverage/baseline.txt" >&2
  exit 1
fi
