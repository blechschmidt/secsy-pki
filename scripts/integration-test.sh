#!/usr/bin/env bash
#
# integration-test.sh — Run the secsy-pki end-to-end integration suite against
# SoftHSM with a single command.
#
# It initializes (or reuses) a SoftHSM token via setup-softhsm.sh, exports the
# resulting SECSY_* PKCS#11 environment, and runs the Go integration test that
# drives the full product flow on the token:
#
#   initialize token -> generate HSM CA key -> issue root + intermediate + leaf
#   -> verify the chain -> revoke a cert and validate CRL/OCSP
#   -> password encrypt/decrypt round-trips.
#
# Usage:
#   ./scripts/integration-test.sh                 # run the full flow
#   SOFTHSM_REINIT=1 ./scripts/integration-test.sh  # recreate the token first
#   ./scripts/integration-test.sh -run TestFullFlow/IssueLeaf -v  # extra go test args
#
# Any extra arguments are passed through to `go test`.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_DIR="$REPO_ROOT/server"

log() { echo "==> $*"; }

# ----------------------------------------------------------------------------
# 1. Provision the SoftHSM token (idempotent) and load the PKCS#11 environment.
# ----------------------------------------------------------------------------
log "Setting up SoftHSM token..."
"$SCRIPT_DIR/setup-softhsm.sh"

log "Loading PKCS#11 environment..."
eval "$("$SCRIPT_DIR/setup-softhsm.sh" --export-env)"

if [[ -z "${SECSY_PKCS11_MODULE:-}" ]]; then
    echo "ERROR: SoftHSM module not found; cannot run integration tests." >&2
    exit 1
fi

log "Using module : $SECSY_PKCS11_MODULE"
log "Token label  : ${SECSY_TOKEN_LABEL:-}"

# ----------------------------------------------------------------------------
# 2. Ensure the Go toolchain is reachable (system Go bootstraps go.mod's version
#    via GOTOOLCHAIN=auto).
# ----------------------------------------------------------------------------
if [[ -d /usr/local/go/bin ]]; then
    export PATH="/usr/local/go/bin:$PATH"
fi

# ----------------------------------------------------------------------------
# 3. Run the end-to-end suite.
#
# The e2e package and the HSM-backed CA/secret tests need:
#   -tags sqlite   real sqlite driver (in-memory driver otherwise stubs out)
#   -p 1           serialize packages: concurrent access to one SoftHSM token is
#                  flaky ("no token found" mid-write).
# ----------------------------------------------------------------------------
cd "$SERVER_DIR"

# Default target: the dedicated end-to-end flow plus the HSM-backed unit suites.
DEFAULT_PKGS=(./internal/e2e/... ./internal/ca/... ./internal/secret/... ./internal/keyprovider/... ./internal/scep/... ./internal/est/... ./internal/cms/... ./internal/sshca/... ./internal/handlers/... ./internal/doctor/...)

log "Running end-to-end integration tests against SoftHSM..."
set -x
go test -tags sqlite -p 1 -count=1 "${DEFAULT_PKGS[@]}" "$@"
