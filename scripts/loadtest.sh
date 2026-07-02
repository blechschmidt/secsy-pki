#!/usr/bin/env bash
#
# loadtest.sh — HSM performance & load-test harness for secsy-pki.
#
# Runs the Go benchmark suites that measure the HSM-bound hot paths — signing /
# certificate issuance, OCSP & CRL serving, and secret encrypt/decrypt — under
# concurrency against SoftHSM, sweeping the PKCS#11 session pool size. It is the
# tool used to (re)generate the baseline numbers in docs/benchmarks.md and to
# tune the session-pool size / OCSP cache TTL for a given HSM.
#
# Usage:
#   scripts/loadtest.sh [-t BENCHTIME] [-c COUNT] [-o OUTFILE] [SUITE ...]
#
#   -t BENCHTIME  per-benchmark duration or iterations (default: 3s). Accepts Go
#                 -benchtime syntax, e.g. "3s" or "2000x".
#   -c COUNT      repeat each benchmark COUNT times (default: 1). Use with
#                 benchstat for statistically meaningful comparisons.
#   -o OUTFILE    also write the raw benchmark output to OUTFILE.
#   SUITE ...     one or more of: sign issue ocsp crl secret all (default: all)
#
# It requires SoftHSM to be set up (scripts/setup-softhsm.sh). If the SECSY_*
# env vars are not already exported, it sets them up automatically. Without an
# HSM the benchmarks skip, and this harness reports that.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
SERVER_DIR="$REPO_ROOT/server"

BENCHTIME="3s"
COUNT="1"
OUTFILE=""
SUITES=()

while getopts ":t:c:o:h" opt; do
  case "$opt" in
    t) BENCHTIME="$OPTARG" ;;
    c) COUNT="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    \?) echo "unknown option -$OPTARG" >&2; exit 2 ;;
    :) echo "option -$OPTARG requires an argument" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
SUITES=("$@")
[ ${#SUITES[@]} -eq 0 ] && SUITES=("all")

# Ensure the Go toolchain is on PATH (matches the project convention).
export PATH="/usr/local/go/bin:$PATH"

# Set up SoftHSM env vars if the caller has not already.
if [ -z "${SECSY_PKCS11_MODULE:-}" ] || [ -z "${SECSY_TOKEN_LABEL:-}" ]; then
  if [ -x "$HERE/setup-softhsm.sh" ]; then
    echo ">> configuring SoftHSM environment via setup-softhsm.sh"
    eval "$("$HERE/setup-softhsm.sh" --export-env)"
  fi
fi

if [ -z "${SECSY_PKCS11_MODULE:-}" ] || [ -z "${SECSY_TOKEN_LABEL:-}" ]; then
  echo "!! SoftHSM is not configured (SECSY_PKCS11_MODULE / SECSY_TOKEN_LABEL unset)." >&2
  echo "   The benchmarks will skip. Run scripts/setup-softhsm.sh first." >&2
  exit 1
fi

echo ">> SoftHSM module: $SECSY_PKCS11_MODULE"
echo ">> token:          $SECSY_TOKEN_LABEL"
echo ">> benchtime=$BENCHTIME count=$COUNT suites=${SUITES[*]}"
echo

# want SUITE — is SUITE (or "all") requested?
want() {
  local s
  for s in "${SUITES[@]}"; do
    [ "$s" = "all" ] && return 0
    [ "$s" = "$1" ] && return 0
  done
  return 1
}

TMP_OUT="$(mktemp)"
trap 'rm -f "$TMP_OUT"' EXIT

run_bench() {
  local pkg="$1" pattern="$2" tags="${3:-}"
  local -a cmd=(go test)
  [ -n "$tags" ] && cmd+=(-tags "$tags")
  cmd+=(-run '^$' -bench "$pattern" -benchtime="$BENCHTIME" -count="$COUNT" -benchmem "$pkg")
  echo ">> ${cmd[*]}"
  ( cd "$SERVER_DIR" && "${cmd[@]}" ) | tee -a "$TMP_OUT"
  echo
}

# Map suites to (package, benchmark-regex, build-tags).
if want sign; then
  run_bench ./internal/keyprovider "BenchmarkPKCS11Sign"    ""
fi
if want secret; then
  run_bench ./internal/keyprovider "BenchmarkPKCS11Decrypt" ""
  run_bench ./internal/secret      "BenchmarkSecret"        ""
fi
if want issue; then
  run_bench ./internal/ca          "BenchmarkCA_IssueCertificate" "sqlite"
fi
if want ocsp; then
  run_bench ./internal/ca          "BenchmarkCA_OCSPRespond"      "sqlite"
fi
if want crl; then
  run_bench ./internal/ca          "BenchmarkCA_GenerateCRL"      "sqlite"
fi

if [ -n "$OUTFILE" ]; then
  cp "$TMP_OUT" "$OUTFILE"
  echo ">> raw results written to $OUTFILE"
fi

echo ">> done."
