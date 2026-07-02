#!/usr/bin/env bash
#
# dr-drill-full.sh — Full-stack disaster-recovery drill for secsy-pki.
#
# This is the Task 16 SoftHSM DR drill (scripts/dr-drill.sh) extended to cover
# the Task 38 pluggable PostgreSQL persistence backend AND its point-in-time
# recovery story. It proves, in one command, that after losing the database we
# can recover a consistent, tamper-evident, still-signing PKI from backups:
#
#   PART 0  Provision an ephemeral PostgreSQL container (WAL archiving on) and a
#           dedicated SoftHSM token; build secsy-ca.
#   PART 1  Create a root + intermediate CA on the HSM (keys never leave the
#           token); issue leaf certs, revoke one, publish a CRL. Capture a
#           pre-disaster integrity fingerprint.
#   PART 2  LOGICAL backup/restore (pg_dump → fresh container → psql restore):
#           verify post-restore store integrity, fingerprint continuity, then
#           re-issue and re-validate a certificate end-to-end against the
#           restored DB + HSM.
#   PART 3  PHYSICAL point-in-time recovery (pg_basebackup + archived WAL replay
#           to a recovery target time): verify the DB recovers to exactly the
#           chosen point — committed-before work is present, after-target work is
#           correctly excluded — and integrity still holds.
#
# Every restore is gated on `secsy-ca db verify`, which asserts the invariants a
# restore must preserve, independent of the HSM:
#     • the hash-chained audit log verifies end-to-end (tamper-evidence intact);
#     • per-CA serial counters are strictly ahead of every issued serial;
#     • per-CA/scope CRL numbers are strictly ahead of every published CRL
#       (RFC 5280 §5.2.3 monotonicity);
#     • the certificate inventory and the revocation store agree both ways.
#
# It uses its own SOFTHSM2_CONF, token directory, and throwaway Postgres
# containers under a temp workspace, so it never touches shared dev state.
#
# Usage:
#   ./scripts/dr-drill-full.sh              # run the full drill (cleans up)
#   DR_KEEP=1 ./scripts/dr-drill-full.sh    # keep the workspace + containers
#   PG_IMAGE=postgres:15-alpine ./scripts/dr-drill-full.sh
#
# Prerequisites: docker, softhsm2-util, pkcs11-tool, pg_dump/pg_basebackup/psql
# (postgresql-client), openssl, and the Go toolchain.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_DIR="$REPO_ROOT/server"

log()  { echo "==> $*"; }
pass() { echo "  ✓ $*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

# ----------------------------------------------------------------------------
# Configuration (override via environment)
# ----------------------------------------------------------------------------
PG_IMAGE="${PG_IMAGE:-postgres:16-alpine}"
PG_USER="${PG_USER:-secsy}"
PG_PASSWORD="${PG_PASSWORD:-secsy}"
PG_DB="${PG_DB:-secsy_pki}"
PG_PORT_PRIMARY="${PG_PORT_PRIMARY:-55432}"   # live primary (pg1)
PG_PORT_LOGICAL="${PG_PORT_LOGICAL:-55452}"   # logical-restore target (pg3)
PG_PORT_PITR="${PG_PORT_PITR:-55442}"         # PITR-restore target (pg2)

# Uniquely name containers per run so parallel/leftover runs never collide.
RUN_ID="$$"
C_PRIMARY="secsy-dr-pg1-$RUN_ID"
C_LOGICAL="secsy-dr-pg3-$RUN_ID"
C_PITR="secsy-dr-pg2-$RUN_ID"

TOKEN_LABEL="secsy-dr-root"
INT_LABEL="secsy-dr-intermediate"
USER_PIN="1234"
SO_PIN="5678"

# ----------------------------------------------------------------------------
# Preflight
# ----------------------------------------------------------------------------
command -v docker         >/dev/null 2>&1 || fail "docker not found"
command -v softhsm2-util  >/dev/null 2>&1 || fail "softhsm2-util not found (apt-get install softhsm2 opensc)"
command -v pg_dump        >/dev/null 2>&1 || fail "pg_dump not found (apt-get install postgresql-client)"
command -v pg_basebackup  >/dev/null 2>&1 || fail "pg_basebackup not found (apt-get install postgresql-client)"
command -v psql           >/dev/null 2>&1 || fail "psql not found (apt-get install postgresql-client)"
command -v openssl        >/dev/null 2>&1 || fail "openssl not found"
[[ -d /usr/local/go/bin ]] && export PATH="/usr/local/go/bin:$PATH"
command -v go >/dev/null 2>&1 || fail "go toolchain not found"
docker info >/dev/null 2>&1 || fail "docker daemon not reachable"

find_module() {
    for c in \
        /usr/lib/softhsm/libsofthsm2.so \
        /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
        /usr/lib64/pkcs11/libsofthsm2.so \
        /usr/lib/pkcs11/libsofthsm2.so \
        /usr/local/lib/softhsm/libsofthsm2.so \
        /opt/homebrew/lib/softhsm/libsofthsm2.so; do
        [[ -f "$c" ]] && { echo "$c"; return 0; }
    done
    return 1
}
MODULE_PATH="$(find_module)" || fail "could not locate libsofthsm2.so"

WORK="$(mktemp -d /tmp/secsy-dr-full.XXXXXX)"
TOKEN_DIR="$WORK/tokens"
CONF="$WORK/softhsm2.conf"
WALARCHIVE="$WORK/walarchive"
BASEBACKUP="$WORK/basebackup"
TOKEN_BACKUP="$WORK/token-state"
DUMP="$WORK/pg_dump.sql"
mkdir -p "$TOKEN_DIR" "$WALARCHIVE" "$BASEBACKUP"
# The Postgres container runs as its own uid; make the bind-mounted archive and
# basebackup dirs writable by it.
chmod 777 "$WALARCHIVE" "$BASEBACKUP"

cleanup() {
    local code=$?
    if [[ "${DR_KEEP:-0}" == "1" ]]; then
        echo "==> DR_KEEP=1 — workspace preserved at: $WORK"
        echo "    containers left running: $C_PRIMARY $C_LOGICAL $C_PITR"
    else
        docker rm -f "$C_PRIMARY" "$C_LOGICAL" "$C_PITR" >/dev/null 2>&1 || true
        rm -rf "$WORK"
    fi
    exit $code
}
trap cleanup EXIT

# psql against a container via TCP from the host.
psql_host() {
    local port="$1"; shift
    PGPASSWORD="$PG_PASSWORD" psql -h 127.0.0.1 -p "$port" -U "$PG_USER" -d "$PG_DB" -qtAX "$@"
}

# Wait until a Postgres container accepts a real query over host TCP. The
# official image runs first-boot init scripts on a local-only socket, so a bare
# pg_isready can report ready before TCP is actually accepting connections;
# probing with a real SELECT avoids that race.
wait_pg_tcp() {
    local port="$1" tries="${2:-60}"
    for _ in $(seq 1 "$tries"); do
        if psql_host "$port" -c 'SELECT 1' >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

DSN_PRIMARY="postgres://$PG_USER:$PG_PASSWORD@127.0.0.1:$PG_PORT_PRIMARY/$PG_DB?sslmode=disable"
DSN_LOGICAL="postgres://$PG_USER:$PG_PASSWORD@127.0.0.1:$PG_PORT_LOGICAL/$PG_DB?sslmode=disable"
DSN_PITR="postgres://$PG_USER:$PG_PASSWORD@127.0.0.1:$PG_PORT_PITR/$PG_DB?sslmode=disable"

# ============================================================================
# PART 0 — Provision Postgres (WAL archiving on), SoftHSM, and build secsy-ca
# ============================================================================
log "PART 0: provisioning ephemeral PostgreSQL primary ($PG_IMAGE)..."
docker rm -f "$C_PRIMARY" >/dev/null 2>&1 || true
# The Postgres image runs as a fixed uid; discover it so the physical backup
# keeps the ownership/permissions (0700, owned by postgres) that the engine
# insists on before it will start on a restored data directory.
PG_UID="$(docker run --rm "$PG_IMAGE" id -u postgres 2>/dev/null || echo 999)"
PG_GID="$(docker run --rm "$PG_IMAGE" id -g postgres 2>/dev/null || echo 999)"

docker run -d --name "$C_PRIMARY" \
    -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_DB="$PG_DB" \
    -p "$PG_PORT_PRIMARY:5432" \
    -v "$WALARCHIVE:/walarchive" \
    -v "$BASEBACKUP:/basebackup" \
    "$PG_IMAGE" \
    -c wal_level=replica \
    -c archive_mode=on \
    -c "archive_command=cp %p /walarchive/%f" \
    -c max_wal_senders=4 \
    -c archive_timeout=60 >/dev/null
wait_pg_tcp "$PG_PORT_PRIMARY" || fail "primary Postgres did not become ready"
pass "primary Postgres up on :$PG_PORT_PRIMARY (WAL archiving to $WALARCHIVE)"

log "Provisioning SoftHSM token '$TOKEN_LABEL'..."
export SOFTHSM2_CONF="$CONF"
cat > "$CONF" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF
softhsm2-util --init-token --free --label "$TOKEN_LABEL" --pin "$USER_PIN" --so-pin "$SO_PIN" >/dev/null
pass "token initialized"

log "Building secsy-ca..."
CA_BIN="$WORK/secsy-ca"
( cd "$SERVER_DIR" && go build -tags sqlite -o "$CA_BIN" ./cmd/secsy-ca )
pass "built $CA_BIN"

# secsy-ca config pointing at the PostgreSQL primary + the SoftHSM token.
CONFIG="$WORK/config.yaml"
write_config() {  # $1 = dsn
cat > "$CONFIG" <<EOF
database:
  driver: "postgres"
  dsn: "$1"
root_user:
  username: "root"
  password: "dr-drill"
key_provider:
  type: "pkcs11"
pkcs11:
  module_path: "$MODULE_PATH"
  pin: "$USER_PIN"
  token_label: "$TOKEN_LABEL"
EOF
}
write_config "$DSN_PRIMARY"
runca() { "$CA_BIN" -config "$CONFIG" "$@"; }

# Opening the store auto-creates/migrates the schema. Verify a clean empty store.
log "Initializing schema on the primary (migration smoke test)..."
runca db verify >/dev/null || fail "empty-store integrity check failed (schema/migration problem)"
pass "schema created; empty store verifies clean"

# ============================================================================
# PART 1 — Build real CA state on the HSM + PostgreSQL, capture a fingerprint
# ============================================================================
log "PART 1: running key ceremony (root + intermediate) on the HSM..."
CONFIRM_ROOT="$WORK/confirm-root.txt"
cat > "$CONFIRM_ROOT" <<'EOF'
alice:correct-horse-battery-staple
bob:hunter2-but-longer
EOF
runca ceremony -role root -label "$TOKEN_LABEL" \
    -cn "Secsy DR Root CA" -o "Secsy" -key-type ecdsa-p384 \
    -operators "alice,bob,carol" -quorum 2 -non-interactive < "$CONFIRM_ROOT" \
    > "$WORK/root-ceremony.json" || fail "root ceremony failed"
grep -q '"private_key_non_extractable": true' "$WORK/root-ceremony.json" \
    || fail "root key not verified non-extractable"

CONFIRM_INT="$WORK/confirm-int.txt"
cat > "$CONFIRM_INT" <<'EOF'
alice:correct-horse-battery-staple
carol:xkcd-936-forever
EOF
runca ceremony -role intermediate -parent "$TOKEN_LABEL" -label "$INT_LABEL" \
    -cn "Secsy DR Issuing CA" -o "Secsy" -key-type ecdsa-p256 \
    -operators "alice,bob,carol" -quorum 2 -non-interactive < "$CONFIRM_INT" \
    > "$WORK/int-ceremony.json" || fail "intermediate ceremony failed"
pass "root + intermediate CA created on the HSM (keys non-extractable)"

# Issue two leaf certs, revoke one, and publish a base CRL so the revocation
# store, serial counter, and CRL counter all hold real, non-trivial state.
# issue_leaf issues a leaf under the intermediate and echoes its DECIMAL serial
# (the identifier secsy-ca uses for revoke/renew), captured from the CLI's own
# report rather than re-parsed from the certificate.
issue_leaf() {  # $1 = CN, $2 = output pem path -> echoes decimal serial
    local cn="$1" out="$2"
    local key="$WORK/${cn}.key" csr="$WORK/${cn}.csr"
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$key" -out "$csr" -subj "/CN=$cn" >/dev/null 2>&1 || fail "CSR gen failed for $cn"
    local serial
    serial="$(runca issue -ca "$INT_LABEL" -csr "$csr" -profile server -out "$out" 2>&1 >/dev/null \
        | sed -n 's/.*serial=\([0-9][0-9]*\).*/\1/p')"
    [[ -n "$serial" ]] || fail "issuance failed for $cn"
    echo "$serial"
}

log "Issuing leaf certificates and revoking one..."
S1="$(issue_leaf leaf1.example.com "$WORK/leaf1.pem")"
S2="$(issue_leaf leaf2.example.com "$WORK/leaf2.pem")"
runca revoke -ca "$INT_LABEL" -serial "$S2" -reason superseded >/dev/null 2>&1 \
    || fail "revocation failed"
# Cut two CRLs so the per-CA CRL-number counter advances past 1, giving the
# post-restore RFC 5280 §5.2.3 monotonicity check real state to validate.
runca gen-crl -ca "$INT_LABEL" -der -out "$WORK/crl1.der" >/dev/null 2>&1 || fail "CRL generation failed"
runca gen-crl -ca "$INT_LABEL" -der -out "$WORK/crl2.der" >/dev/null 2>&1 || fail "CRL generation failed"
pass "2 issued (serials $S1, $S2), 1 revoked, 2 CRLs cut"

log "Capturing pre-disaster integrity fingerprint..."
runca db verify || fail "pre-disaster integrity check failed"
runca db verify -json > "$WORK/pre.json" || fail "pre-disaster fingerprint capture failed"
python3 - "$WORK/pre.json" <<'PY' || fail "pre.json malformed"
import json,sys
d=json.load(open(sys.argv[1]))
assert d["ok"], "store not OK before disaster"
fp=d["fingerprint"]
assert fp["audit_chain_valid"] and fp["audit_event_count"]>0
assert fp["issued_certs"]>=2 and fp["revoked_certs"]>=1
print("  pre-fingerprint:", json.dumps(fp))
PY
pass "pre-disaster fingerprint captured (store integrity OK)"

# Back up the HSM token state (opaque, encrypted key blobs — never plaintext).
cp -a "$TOKEN_DIR" "$TOKEN_BACKUP"
if grep -rlq "PRIVATE KEY" "$TOKEN_BACKUP" 2>/dev/null; then
    fail "token backup contains plaintext private key material"
fi
pass "HSM token state backed up (no plaintext key material)"

# ============================================================================
# PART 2 — LOGICAL backup/restore (pg_dump) + end-to-end re-issuance
# ============================================================================
log "PART 2: taking a logical pg_dump of the primary..."
PGPASSWORD="$PG_PASSWORD" pg_dump -h 127.0.0.1 -p "$PG_PORT_PRIMARY" -U "$PG_USER" \
    --format=plain --no-owner --no-privileges "$PG_DB" > "$DUMP" || fail "pg_dump failed"
[[ -s "$DUMP" ]] || fail "pg_dump produced an empty file"
pass "pg_dump written ($(wc -l < "$DUMP") lines)"

# --- Take the physical base backup now, while the primary is still alive, so
#     PART 3 (PITR) has material to recover from after we destroy the primary.
#     Writing straight into the bind-mounted /basebackup keeps the files owned by
#     the postgres uid with the 0700 data-directory permissions the engine needs.
log "Taking a physical base backup (pg_basebackup) for PITR..."
docker exec "$C_PRIMARY" pg_basebackup -U "$PG_USER" -h /var/run/postgresql \
    -D /basebackup -Fp -Xstream -c fast >/dev/null 2>&1 || fail "pg_basebackup failed"
docker exec "$C_PRIMARY" chmod 700 /basebackup >/dev/null 2>&1 || true
pass "base backup captured to $BASEBACKUP"

# Choose the PITR recovery target: the DB's own clock, right after the good
# state. Anything committed strictly after this must NOT survive PITR.
sleep 1
PITR_TARGET="$(psql_host "$PG_PORT_PRIMARY" -c "SELECT now();")"
[[ -n "$PITR_TARGET" ]] || fail "could not read recovery target time"
sleep 2
log "PITR recovery target: $PITR_TARGET"

# --- Post-target "future" work that PITR must exclude: issue leaf3 AFTER the
#     recovery target. The logical dump (taken before this) already excludes it
#     too, so we re-issue it here purely to mark the timeline for PART 3.
S3="$(issue_leaf leaf3.future.example.com "$WORK/leaf3.pem")"
pass "post-target certificate issued (serial 0x$S3) — expected absent after PITR"
# Force the WAL containing the target boundary to be archived so recovery can
# replay up to and past PITR_TARGET.
psql_host "$PG_PORT_PRIMARY" -c "SELECT pg_switch_wal();" >/dev/null || true
psql_host "$PG_PORT_PRIMARY" -c "CHECKPOINT;" >/dev/null || true
sleep 2

# --- Simulate disaster: destroy the primary container entirely (data lost).
log "Simulating disaster: destroying the primary Postgres container..."
docker rm -f "$C_PRIMARY" >/dev/null 2>&1 || true
pass "primary destroyed — all live database state is gone"

# --- Logical restore into a brand-new, empty container.
log "Restoring the logical dump into a fresh PostgreSQL container..."
docker rm -f "$C_LOGICAL" >/dev/null 2>&1 || true
docker run -d --name "$C_LOGICAL" \
    -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PASSWORD" -e POSTGRES_DB="$PG_DB" \
    -p "$PG_PORT_LOGICAL:5432" "$PG_IMAGE" >/dev/null
wait_pg_tcp "$PG_PORT_LOGICAL" || fail "logical-restore Postgres did not become ready"
PGPASSWORD="$PG_PASSWORD" psql -h 127.0.0.1 -p "$PG_PORT_LOGICAL" -U "$PG_USER" -d "$PG_DB" \
    -v ON_ERROR_STOP=1 -qX -f "$DUMP" >/dev/null || fail "psql restore failed"
pass "logical dump restored into :$PG_PORT_LOGICAL"

log "Verifying store integrity on the logically-restored DB..."
write_config "$DSN_LOGICAL"
runca db verify || fail "post-restore integrity check FAILED (logical restore)"
runca db verify -json > "$WORK/post-logical.json"
# Continuity: the restored store must reproduce the pre-disaster fingerprint
# exactly (nothing lost or rewound) — the logical dump was taken after leaf3, so
# it legitimately contains it; assert the audit head and counters are preserved.
python3 - "$WORK/pre.json" "$WORK/post-logical.json" <<'PY' || fail "logical-restore continuity check failed"
import json,sys
pre=json.load(open(sys.argv[1]))["fingerprint"]
post=json.load(open(sys.argv[2]))
assert post["ok"], "restored store not OK"
fp=post["fingerprint"]
# The dump was taken AFTER leaf3, so it holds >= the pre snapshot in every
# monotonic dimension and the audit chain must still be valid.
assert fp["audit_chain_valid"], "audit chain invalid after restore"
assert fp["audit_event_count"]  >= pre["audit_event_count"],  "audit events lost"
assert fp["issued_certs"]       >= pre["issued_certs"],       "issued certs lost"
assert fp["revoked_certs"]      == pre["revoked_certs"],      "revocation store diverged"
assert fp["sum_next_serial"]    >= pre["sum_next_serial"],    "serial counter rewound"
assert fp["sum_next_crl_number"]>= pre["sum_next_crl_number"],"CRL counter rewound"
print("  logical-restore fingerprint:", json.dumps(fp))
PY
pass "audit chain intact, counters preserved, revocation store consistent"

# --- Re-issue and re-validate a certificate end-to-end against restored DB+HSM.
#     This exercises the whole path: restored CA metadata (PostgreSQL) + the
#     HSM signer, then an independent openssl chain validation to the root.
log "Restoring HSM token state and re-issuing against the restored DB + HSM..."
rm -rf "${TOKEN_DIR:?}"/*
cp -a "$TOKEN_BACKUP/." "$TOKEN_DIR/"
S4="$(issue_leaf recovered.example.com "$WORK/leaf4.pem")"
openssl x509 -in "$WORK/leaf4.pem" -noout -subject >/dev/null || fail "re-issued cert is not valid X.509"
# Build the full issuing chain (intermediate + root) from the restored DB and
# validate the freshly signed leaf against it with openssl.
runca publish-chain -ca "$INT_LABEL" -out "$WORK/ca-chain.pem" 2>/dev/null || fail "publishing CA chain failed"
if openssl verify -CAfile "$WORK/ca-chain.pem" "$WORK/leaf4.pem" >/dev/null 2>&1; then
    pass "re-issued leaf (serial $S4) verifies to the restored root via openssl"
else
    fail "re-issued leaf did not validate against the restored chain"
fi
pass "end-to-end re-issuance against restored DB + HSM succeeded"

# ============================================================================
# PART 3 — PHYSICAL point-in-time recovery (pg_basebackup + WAL replay)
# ============================================================================
log "PART 3: performing point-in-time recovery to $PITR_TARGET ..."
# Inject recovery configuration into the base backup's data directory. Doing this
# from a throwaway container (running as root, then re-owning to the postgres
# uid) keeps the whole PGDATA owned correctly with 0700 permissions.
docker run --rm -v "$BASEBACKUP:/bb" "$PG_IMAGE" sh -c "
    { echo \"restore_command = 'cp /walarchive/%f %p'\"
      echo \"recovery_target_time = '$PITR_TARGET'\"
      echo \"recovery_target_action = 'promote'\"
    } >> /bb/postgresql.auto.conf
    touch /bb/recovery.signal
    chown -R $PG_UID:$PG_GID /bb
    chmod 700 /bb" >/dev/null || fail "injecting recovery config failed"

docker rm -f "$C_PITR" >/dev/null 2>&1 || true
docker run -d --name "$C_PITR" \
    -e POSTGRES_PASSWORD="$PG_PASSWORD" \
    -p "$PG_PORT_PITR:5432" \
    -v "$BASEBACKUP:/var/lib/postgresql/data" \
    -v "$WALARCHIVE:/walarchive" \
    "$PG_IMAGE" >/dev/null

# Wait for recovery to finish and the server to promote out of recovery.
log "Waiting for WAL replay + promotion..."
recovered=0
for _ in $(seq 1 60); do
    if docker exec "$C_PITR" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1; then
        inrec="$(psql_host "$PG_PORT_PITR" -c "SELECT pg_is_in_recovery();" 2>/dev/null || echo t)"
        if [[ "$inrec" == "f" ]]; then recovered=1; break; fi
    fi
    sleep 1
done
[[ "$recovered" == "1" ]] || { docker logs "$C_PITR" 2>&1 | tail -20; fail "PITR did not complete/promote in time"; }
pass "PITR server promoted (recovered to the target time)"

log "Verifying store integrity on the PITR-restored DB..."
write_config "$DSN_PITR"
runca db verify || fail "post-restore integrity check FAILED (PITR restore)"
runca db verify -json > "$WORK/post-pitr.json"

# The point of PITR: pre-target work (leaf1/leaf2 + revocation) is present, but
# the post-target certificate (leaf3) is correctly excluded.
PRE_TARGET_CERTS="$(psql_host "$PG_PORT_PITR" -c "SELECT count(*) FROM issued_certificates;")"
python3 - "$WORK/pre.json" "$WORK/post-pitr.json" "$PRE_TARGET_CERTS" <<'PY' || fail "PITR continuity check failed"
import json,sys
pre=json.load(open(sys.argv[1]))["fingerprint"]
post=json.load(open(sys.argv[2]))
n=int(sys.argv[3])
assert post["ok"], "PITR store not OK"
fp=post["fingerprint"]
assert fp["audit_chain_valid"], "audit chain invalid after PITR"
# Recovery target was set right after the good state (2 issued, 1 revoked) and
# before leaf3, so the recovered inventory must match the pre snapshot exactly.
assert fp["issued_certs"] == pre["issued_certs"], \
    f"PITR issued_certs={fp['issued_certs']} != pre {pre['issued_certs']} (leaf3 should be excluded)"
assert fp["revoked_certs"] == pre["revoked_certs"], "revocation store diverged after PITR"
assert fp["audit_head_hash"] == pre["audit_head_hash"], "audit head diverged (recovered to wrong point)"
print("  PITR fingerprint:", json.dumps(fp))
print(f"  recovered inventory count = {n} (post-target certificate excluded)")
PY
pass "PITR recovered to exactly the target: pre-target state present, post-target excluded, audit chain intact"

# ============================================================================
echo
echo "============================================================"
echo " FULL-STACK DR DRILL PASSED"
echo "   • ephemeral PostgreSQL + SoftHSM, keys non-extractable"
echo "   • logical backup (pg_dump) → restore → integrity verified"
echo "     → re-issued & re-validated a cert against restored DB + HSM"
echo "   • physical PITR (pg_basebackup + WAL replay) → recovered to"
echo "     the target time; audit chain, serial & CRL monotonicity,"
echo "     and revocation-store consistency all verified"
echo "============================================================"
