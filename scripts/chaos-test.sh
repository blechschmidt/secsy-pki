#!/usr/bin/env bash
#
# chaos-test.sh — Run the secsy-pki chaos / fault-injection resilience suite
# (server/internal/chaos) with a single command.
#
# The suite deliberately degrades the PKI's runtime dependencies under
# concurrent load and asserts fail-closed / graceful-degradation invariants:
#
#   1. Mid-load PKCS#11 token failure (Task 44 HA failover) + session-pool
#      saturation and recovery (Task 20).
#   2. PostgreSQL connection drops/timeouts (Task 38): serial/CRL FOR UPDATE
#      contention, audit-chain continuity, and no duplicate serials.
#   3. HSM wrong-PIN login failure and RSA-OAEP hash-mismatch fail-closed paths.
#   4. Rate-limit (429) and HSM concurrency-guard (503) saturation with
#      Retry-After (Task 25).
#
# It provisions (or reuses) a SoftHSM token via setup-softhsm.sh and, when
# possible, an ephemeral PostgreSQL for the connection-drop scenario:
#
#   - If SECSY_TEST_PG_DSN is already set, it is used as-is.
#   - Else, if Docker is available, a throwaway postgres:16-alpine is started on
#     127.0.0.1:5544 and torn down on exit.
#   - Else the Postgres-only scenarios skip cleanly (SoftHSM ones still run).
#
# Usage:
#   ./scripts/chaos-test.sh                 # full suite
#   ./scripts/chaos-test.sh -run TestChaosHSMFailoverUnderLoad -v
#   SECSY_TEST_PG_DSN=postgres://... ./scripts/chaos-test.sh   # bring your own PG
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
eval "$("$SCRIPT_DIR/setup-softhsm.sh" --export-env)"

if [[ -z "${SECSY_PKCS11_MODULE:-}" ]]; then
    echo "ERROR: SoftHSM module not found; cannot run the chaos suite." >&2
    exit 1
fi
log "Using module : $SECSY_PKCS11_MODULE"
log "Token label  : ${SECSY_TOKEN_LABEL:-}"

# ----------------------------------------------------------------------------
# 2. Provision an ephemeral PostgreSQL for the connection-drop scenario.
# ----------------------------------------------------------------------------
PG_CONTAINER=""
cleanup() {
    if [[ -n "$PG_CONTAINER" ]]; then
        log "Removing ephemeral PostgreSQL container..."
        docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

if [[ -n "${SECSY_TEST_PG_DSN:-}" ]]; then
    log "Using provided PostgreSQL: SECSY_TEST_PG_DSN is set."
elif command -v docker >/dev/null 2>&1; then
    PG_CONTAINER="secsy-chaos-pg-$$"
    PG_PORT="${SECSY_CHAOS_PG_PORT:-5544}"
    log "Starting ephemeral PostgreSQL ($PG_CONTAINER) on 127.0.0.1:$PG_PORT..."
    docker run -d --name "$PG_CONTAINER" \
        -e POSTGRES_USER=secsy -e POSTGRES_PASSWORD=secsy -e POSTGRES_DB=secsy_pki \
        -p "127.0.0.1:$PG_PORT:5432" postgres:16-alpine >/dev/null

    export SECSY_TEST_PG_DSN="postgres://secsy:secsy@127.0.0.1:$PG_PORT/secsy_pki?sslmode=disable"

    # A fresh postgres image runs first-boot init on a local-only socket, so
    # pg_isready can be green before TCP accepts connections. Wait on a real
    # host-side query instead.
    log "Waiting for PostgreSQL to accept TCP connections..."
    ready=0
    for _ in $(seq 1 60); do
        if docker exec "$PG_CONTAINER" psql -U secsy -d secsy_pki -h 127.0.0.1 -c 'SELECT 1' >/dev/null 2>&1; then
            ready=1
            break
        fi
        sleep 1
    done
    if [[ "$ready" -ne 1 ]]; then
        echo "ERROR: PostgreSQL did not become ready in time." >&2
        exit 1
    fi
    log "PostgreSQL ready: $SECSY_TEST_PG_DSN"
else
    log "Docker not available and SECSY_TEST_PG_DSN unset; PostgreSQL scenarios will skip."
fi

# ----------------------------------------------------------------------------
# 3. Run the chaos suite. -p 1 serializes packages so the single SoftHSM token
#    and the shared PostgreSQL database are not raced across packages. The
#    sqlite build tag pulls in the embedded SQLite driver used by the CA tests.
# ----------------------------------------------------------------------------
cd "$SERVER_DIR"
log "Running chaos / fault-injection resilience suite..."
set -x
go test -tags sqlite -p 1 -count=1 "$@" ./internal/chaos/...
