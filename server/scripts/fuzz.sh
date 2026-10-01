#!/usr/bin/env bash
#
# fuzz.sh — run the secsy-pki native fuzz targets over the untrusted-input
# parsing surfaces (CSR/DER decoding, ACME JOSE/JWS parsing, the secret envelope
# decrypt/unwrap path, and OCSP/certificate parsing).
#
# Go's `go test -fuzz` only runs ONE fuzz target per invocation, so this script
# enumerates every target and runs each for a bounded time. It is used both by
# CI (a short smoke run) and by developers (longer local campaigns).
#
# Usage:
#   ./scripts/fuzz.sh                # 30s per target (local default)
#   FUZZTIME=10s ./scripts/fuzz.sh   # short smoke run (CI uses this)
#   FUZZTIME=10m ./scripts/fuzz.sh   # long local campaign
#   ./scripts/fuzz.sh ./internal/secret/ FuzzEnvelopeOpen   # a single target
#
# Environment:
#   FUZZTIME   duration per target (default 30s). Accepts Go duration or an
#              integer count with the "x" suffix (e.g. 100000x).
#   FUZZ_P     value for `go test -p` (default 1: several targets share the
#              SoftHSM token in other suites; kept serial here for parity and
#              stable resource use). Fuzzing itself parallelizes internally.
#
# A crash writes a reproducer under the package's testdata/fuzz/<Target>/ and
# fails the run; commit that file so the input becomes a permanent regression
# seed.
set -euo pipefail

cd "$(dirname "$0")/.."   # server/ module root

FUZZTIME="${FUZZTIME:-30s}"
FUZZ_P="${FUZZ_P:-1}"

# The full inventory of fuzz targets: "package<TAB>FuzzFunc".
# Keep this in sync when adding new Fuzz* functions.
TARGETS=(
	"./internal/pki/	FuzzParseOCSPRequest"
	"./internal/pki/	FuzzParseCertificatePEM"
	"./internal/ca/	FuzzParseAndVerifyCSR"
	"./internal/acme/	FuzzParseJWS"
	"./internal/acme/	FuzzACMEPayloads"
	"./internal/secret/	FuzzEnvelopeUnmarshal"
	"./internal/secret/	FuzzEnvelopeOpen"
)

# run_one fuzzes one target, retrying once if the only failure was the fuzzing
# coordinator's own shutdown deadline.
#
# When -fuzztime elapses, Go's coordinator stops its workers and waits for the
# one still mid-execution. On a shared CI runner that wait can lose the race,
# and the target then fails with a bare "context deadline exceeded" after
# running the full budget — no crash, no reproducer written, nothing to commit.
# That is a property of the harness and the runner, not of the code under test,
# and letting it redden a required gate trains everyone to re-run CI instead of
# reading it.
#
# The retry is deliberately narrow. A genuine finding prints the failing input
# or names the reproducer file, and those strings veto the retry, so a real
# crash still fails on the first attempt. A deadline that recurs on the second
# attempt fails too: a target that cannot finish its own budget twice in a row
# is a finding of a different kind (an input that takes unbounded time), which
# is exactly what a fuzz gate should catch.
run_one() {
	local pkg="$1" fn="$2" attempt log status
	log="$(mktemp)"
	# shellcheck disable=SC2064  # the path is fixed at trap time on purpose
	trap "rm -f '${log}'" RETURN

	for attempt in 1 2; do
		echo "==> fuzzing ${fn} in ${pkg} for ${FUZZTIME}$([[ ${attempt} -gt 1 ]] && echo " (attempt ${attempt})")"
		status=0
		go test -p "${FUZZ_P}" -run '^$' -fuzz="^${fn}\$" -fuzztime="${FUZZTIME}" "${pkg}" 2>&1 | tee "${log}" || status=$?
		if [[ "${status}" -eq 0 ]]; then
			return 0
		fi
		if [[ "${attempt}" -eq 1 ]] &&
			grep -q 'context deadline exceeded' "${log}" &&
			! grep -qE 'Failing input written|failure while testing seed corpus|^\s+Failing input' "${log}"; then
			echo "   the fuzzing coordinator missed its own shutdown deadline (no reproducer written); retrying once" >&2
			continue
		fi
		return "${status}"
	done
}

# Single-target mode: ./scripts/fuzz.sh <pkg> <FuzzFunc>
if [[ $# -eq 2 ]]; then
	run_one "$1" "$2"
	exit 0
fi
if [[ $# -ne 0 ]]; then
	echo "usage: $0 [<package> <FuzzFunc>]" >&2
	exit 2
fi

failed=0
for entry in "${TARGETS[@]}"; do
	pkg="${entry%%$'\t'*}"
	fn="${entry##*$'\t'}"
	if ! run_one "${pkg}" "${fn}"; then
		echo "!! fuzz target ${fn} (${pkg}) FAILED" >&2
		failed=1
	fi
done

if [[ "${failed}" -ne 0 ]]; then
	echo "One or more fuzz targets failed. A reproducer was written under the" >&2
	echo "package's testdata/fuzz/<Target>/ directory; commit it as a regression seed." >&2
	exit 1
fi
echo "All fuzz targets completed cleanly (${FUZZTIME} each)."
