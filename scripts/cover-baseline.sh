#!/usr/bin/env bash
#
# cover-baseline.sh — (re)generate the committed test-coverage baseline that the
# ratcheting coverage gate enforces (coverage/baseline.txt).
#
# Run this intentionally after you ADD covered code (new tests, or new code that
# your tests exercise) so the gate's floor moves up with the improvement. Then
# commit coverage/baseline.txt in the same change:
#
#   scripts/cover-baseline.sh        # or: make cover-baseline
#   git add coverage/baseline.txt
#
# Reproducibility: the CI coverage gate runs HSM-FREE, so the committed baseline
# must be the HSM-free floor. This script clears any SoftHSM / PKCS#11 env before
# measuring, so a token loaded in your shell cannot inflate the baseline (which
# would then make the HSM-free CI gate fail). It reuses `make cover` for the run
# itself — the single source of the `go test -coverprofile` invocation — so the
# baseline and the gate can never measure different things.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

# Prefer whatever Go toolchain is already on PATH (e.g. actions/setup-go's in CI);
# fall back to the conventional local install only if none is found, so this never
# shadows the CI toolchain. GOTOOLCHAIN=auto pins the go.mod-declared version
# regardless of which `go` launches it.
if ! command -v go >/dev/null 2>&1; then
  export PATH="/usr/local/go/bin:$PATH"
fi
export GOTOOLCHAIN=auto

BASELINE="$REPO_ROOT/coverage/baseline.txt"
PROFILE="$REPO_ROOT/dist/coverage.out"
COVER_TAGS="${COVER_TAGS:-sqlite}"
COVER_TOLERANCE="${COVER_TOLERANCE:-1.0}"

# Clear SoftHSM / PKCS#11 env so the baseline is the reproducible HSM-free floor
# regardless of the caller's shell. A DB DSN (SECSY_TEST_PG_DSN) is intentionally
# left alone: the coverage gate matches whatever DB env CI uses (none by default),
# and the tolerance absorbs the small jitter from the timing-sensitive packages.
for v in SECSY_PKCS11_MODULE SECSY_TOKEN_LABEL SECSY_USER_PIN SECSY_SO_PIN \
         SOFTHSM2_CONF SOFTHSM_TOKEN_DIR; do
  unset "$v" || true
done

echo ">> regenerating coverage baseline (HSM-free; SoftHSM/PKCS#11 env cleared)"
echo ">> tags: $COVER_TAGS   tolerance the gate will apply: ${COVER_TOLERANCE}pp"
echo

# Reuse `make cover` for the measurement so the baseline and the gate share one
# invocation. It writes dist/coverage.out (+ HTML + summary artifacts).
make -C "$REPO_ROOT" cover COVER_TAGS="$COVER_TAGS"

mkdir -p "$(dirname "$BASELINE")"
{
  echo "# secsy-pki test-coverage baseline (Task 119)"
  echo "#"
  echo "# Per-package + total Go statement coverage for the HSM-FREE, -tags ${COVER_TAGS}"
  echo "# test subset:  go test -covermode=set -coverprofile ./internal/..."
  echo "#"
  echo "# The coverage gate (make cover-check / scripts/cover-check.sh, and the"
  echo "# coverage-gate CI job) ratchets against this file: total and per-package"
  echo "# coverage may only RISE (within a small tolerance that absorbs jitter). A"
  echo "# real drop fails the build and prints which packages regressed."
  echo "#"
  echo "# Regenerate intentionally after adding covered code, then commit this file:"
  echo "#     scripts/cover-baseline.sh   (or: make cover-baseline)"
  echo "# See TESTING.md#test-coverage-gate and docs/development/coverage.md."
  echo "#"
  echo "# Format: <package-or-total>\\t<percent>.  Generated — do not hand-edit."
} > "$BASELINE"
COVER_TOLERANCE="$COVER_TOLERANCE" "$HERE/cover-check.sh" --summary "$PROFILE" >> "$BASELINE"

TOTAL="$(awk -F'\t' '$1=="total"{print $2}' "$BASELINE")"
NPKG="$(awk -F'\t' '!/^#/ && NF>=2 && $1!="total"{n++} END{print n+0}' "$BASELINE")"

echo
echo ">> wrote $BASELINE"
echo ">>   total coverage: ${TOTAL}%   across ${NPKG} package(s)"
echo ">> review the diff and commit it:  git add coverage/baseline.txt"
