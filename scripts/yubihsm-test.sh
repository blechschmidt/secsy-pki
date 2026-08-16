#!/usr/bin/env bash
#
# Run the YubiHSM 2 hardware test suite against an attached device.
#
# The suite is off by default and enabled by SECSY_YUBIHSM_TESTS=1, which this
# script exports. It is not part of CI: CI has no HSM, and the device this
# validates is by definition local. See docs/hsm/hardware-test-suite.md.
#
#   ./scripts/yubihsm-test.sh                 # the full suite
#   ./scripts/yubihsm-test.sh --quick         # skip the slow RSA-4096 case
#   ./scripts/yubihsm-test.sh --destructive   # also provision a fresh device
#   ./scripts/yubihsm-test.sh --reset         # also the genesis tier (FACTORY RESETS the device)
#   ./scripts/yubihsm-test.sh --legacy        # also the per-package -tags yubihsm tests
#   ./scripts/yubihsm-test.sh -run TestAudit  # anything else is passed to go test
#
# WARNING: this consumes the device's audit-log entries. The 62-slot log cannot
# hold a full run, so the suite drains it as it goes, and drained entries are
# gone. Do not point it at a device whose audit log a deployment is collecting.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Resolved before the cd below: --help reads this file back, and a relative
# BASH_SOURCE stops resolving once the working directory changes.
self="$repo_root/scripts/$(basename "${BASH_SOURCE[0]}")"
cd "$repo_root/server"

quick=0
destructive=0
reset=0
legacy=0
args=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)       quick=1 ;;
        --destructive) destructive=1 ;;
        --reset)       destructive=1; reset=1 ;;
        --legacy)      legacy=1 ;;
        -h|--help)     sed -n '2,18p' "$self" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)             args+=("$1") ;;
    esac
    shift
done

export SECSY_YUBIHSM_TESTS=1
[[ $destructive -eq 1 ]] && export SECSY_YUBIHSM_DESTRUCTIVE=1
# --reset implies --destructive: the genesis tier factory-resets the device
# several times, which erases every key and the whole log and leaves the device
# at factory defaults. It is a separate flag so that "run the destructive tests"
# is never silently consent to a wipe.
[[ $reset -eq 1 ]] && export SECSY_YUBIHSM_RESET=1

# -p 1 is not a preference. The device admits one session at a time over direct
# USB, so two test binaries running concurrently would fight over the interface
# and report "device or resource busy" rather than anything about the code.
go_flags=(-tags sqlite -p 1 -count=1 -timeout 30m)
[[ $quick -eq 1 ]] && go_flags+=(-short)

connector="${SECSY_YUBIHSM_CONNECTOR:-${YUBIHSM_CONNECTOR:-yhusb://}}"

echo "==> YubiHSM hardware suite"
echo "    connector:   $connector"
echo "    destructive: $([[ $destructive -eq 1 ]] && echo 'yes (may irreversibly provision the device)' || echo no)"
echo "    reset:       $([[ $reset -eq 1 ]] && echo 'YES — the genesis tier will factory-reset the device' || echo no)"
echo "    audit log:   entries will be consumed as the suite runs"
echo

status=0
echo "==> internal/yubihsmtest (the suite)"
go test "${go_flags[@]}" ./internal/yubihsmtest/ -v "${args[@]}" || status=$?

if [[ $legacy -eq 1 ]]; then
    # The per-package hardware tests that predate this suite. They stay behind
    # the `yubihsm` build tag because each declares a TestMain that would
    # otherwise take over that package's SoftHSM tests, so they cannot be folded
    # into the run above.
    echo
    echo "==> per-package hardware tests (-tags yubihsm)"
    go test -tags "sqlite yubihsm" -p 1 -count=1 -timeout 30m -v \
        ./internal/yubihsm/ ./internal/hsm/ ./internal/hsmattest/ ./internal/hsmaudit/ ./internal/pki/ \
        || status=$?
fi

echo
if [[ $status -eq 0 ]]; then
    echo "==> PASS"
else
    echo "==> FAIL (exit $status)"
fi
exit $status
