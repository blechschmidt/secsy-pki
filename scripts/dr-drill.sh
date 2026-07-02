#!/usr/bin/env bash
#
# dr-drill.sh — Disaster-recovery drill for secsy-pki against SoftHSM.
#
# This script exercises the full HSM key lifecycle end-to-end in an isolated
# sandbox, proving the backup/restore procedure actually recovers a working CA:
#
#   1. Provision a fresh, dedicated SoftHSM token.
#   2. Run an M-of-N confirmed key ceremony to create a root + intermediate CA
#      (private keys generated inside the token; never exported).
#   3. Take an inventory of the token's keys.
#   4. Back up CA metadata + a DR manifest (secsy-ca backup) AND the HSM token
#      state (the encrypted, non-extractable key blobs — copied as opaque files).
#   5. Simulate a disaster: wipe the metadata database AND the token directory.
#   6. Restore both from backup material.
#   7. Verify recovery: secsy-ca restore confirms every CA's key resolves on the
#      token with a matching fingerprint and the audit chain is intact.
#
# It uses its own SOFTHSM2_CONF and token directory under a temp workspace, so
# it never touches the shared development token from setup-softhsm.sh.
#
# Usage:
#   ./scripts/dr-drill.sh            # run the drill (cleans up on success)
#   DR_KEEP=1 ./scripts/dr-drill.sh  # keep the workspace for inspection
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_DIR="$REPO_ROOT/server"

log()  { echo "==> $*"; }
pass() { echo "  ✓ $*"; }
fail() { echo "ERROR: $*" >&2; exit 1; }

# ----------------------------------------------------------------------------
# 0. Preflight & isolated workspace
# ----------------------------------------------------------------------------
command -v softhsm2-util >/dev/null 2>&1 || fail "softhsm2-util not found (apt-get install softhsm2 opensc)"
[[ -d /usr/local/go/bin ]] && export PATH="/usr/local/go/bin:$PATH"

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

WORK="$(mktemp -d /tmp/secsy-dr-drill.XXXXXX)"
TOKEN_DIR="$WORK/tokens"
BACKUP_DIR="$WORK/backup"
DB_PATH="$WORK/secsy-pki.db"
CONF="$WORK/softhsm2.conf"
TRANSCRIPTS="$WORK/transcripts"
mkdir -p "$TOKEN_DIR" "$BACKUP_DIR" "$TRANSCRIPTS"

cleanup() {
    if [[ "${DR_KEEP:-0}" == "1" ]]; then
        echo "==> DR_KEEP=1 — workspace preserved at: $WORK"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

TOKEN_LABEL="secsy-dr-root"
USER_PIN="1234"
SO_PIN="5678"

export SOFTHSM2_CONF="$CONF"
cat > "$CONF" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF

# secsy-ca config for this drill. The CLI also honors SECSY_* env overrides, but
# an explicit config keeps the drill self-documenting.
CONFIG="$WORK/config.yaml"
cat > "$CONFIG" <<EOF
database:
  driver: "sqlite"
  dsn: "$DB_PATH"
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

# ----------------------------------------------------------------------------
# 1. Provision a fresh token
# ----------------------------------------------------------------------------
log "Provisioning SoftHSM token '$TOKEN_LABEL'..."
softhsm2-util --init-token --free --label "$TOKEN_LABEL" --pin "$USER_PIN" --so-pin "$SO_PIN" >/dev/null
pass "token initialized"

# ----------------------------------------------------------------------------
# 2. Build the CLI and run the M-of-N key ceremony
# ----------------------------------------------------------------------------
log "Building secsy-ca..."
CA_BIN="$WORK/secsy-ca"
( cd "$SERVER_DIR" && go build -tags sqlite -o "$CA_BIN" ./cmd/secsy-ca )
pass "built $CA_BIN"

runca() { "$CA_BIN" -config "$CONFIG" "$@"; }

# Root ceremony: 2-of-3 operators confirm via a confirmation file.
CONFIRM_ROOT="$WORK/confirm-root.txt"
cat > "$CONFIRM_ROOT" <<'EOF'
# operator:confirmation-phrase  (2-of-3 quorum)
alice:correct-horse-battery-staple
bob:hunter2-but-longer
EOF

log "Running 2-of-3 root key ceremony..."
runca ceremony -role root \
    -label "$TOKEN_LABEL" \
    -cn "Secsy DR Root CA" -o "Secsy" \
    -key-type ecdsa-p384 \
    -operators "alice,bob,carol" -quorum 2 \
    -non-interactive < "$CONFIRM_ROOT" \
    > "$TRANSCRIPTS/root.json" || fail "root ceremony failed"
grep -q '"role": "root"' "$TRANSCRIPTS/root.json" || fail "root transcript missing role"
grep -q '"private_key_non_extractable": true' "$TRANSCRIPTS/root.json" \
    || fail "root key not verified non-extractable"
pass "root ceremony complete; key verified non-extractable"

# Intermediate ceremony under the root.
CONFIRM_INT="$WORK/confirm-int.txt"
cat > "$CONFIRM_INT" <<'EOF'
alice:correct-horse-battery-staple
carol:xkcd-936-forever
EOF

log "Running 2-of-3 intermediate key ceremony..."
runca ceremony -role intermediate \
    -parent "$TOKEN_LABEL" \
    -label "secsy-dr-intermediate" \
    -cn "Secsy DR Issuing CA" -o "Secsy" \
    -key-type ecdsa-p256 \
    -operators "alice,bob,carol" -quorum 2 \
    -non-interactive < "$CONFIRM_INT" \
    > "$TRANSCRIPTS/intermediate.json" || fail "intermediate ceremony failed"
pass "intermediate ceremony complete"

# Negative check: a sub-quorum ceremony must be refused.
log "Verifying quorum enforcement (1 confirmation must fail a 2-of-3 quorum)..."
if echo "alice:only-me" | runca ceremony -role root -label "should-not-exist" \
    -cn "Nope" -operators "alice,bob,carol" -quorum 2 -non-interactive >/dev/null 2>&1; then
    fail "ceremony proceeded without quorum — M-of-N enforcement is broken"
fi
pass "sub-quorum ceremony correctly refused"

# ----------------------------------------------------------------------------
# 3. Inventory
# ----------------------------------------------------------------------------
log "Listing key inventory on the token..."
runca inventory -strict || fail "inventory reported extractable keys"
pass "inventory clean (all keys non-extractable)"

# ----------------------------------------------------------------------------
# 4. Back up CA metadata + manifest, and the HSM token state
# ----------------------------------------------------------------------------
log "Backing up CA metadata + DR manifest..."
runca backup -out "$BACKUP_DIR" || fail "backup failed"
[[ -f "$BACKUP_DIR/manifest.json" ]] || fail "manifest.json not produced"
[[ -f "$BACKUP_DIR/metadata.db" ]]   || fail "metadata.db snapshot not produced"
pass "metadata backup written"

log "Backing up HSM token state (opaque, encrypted key blobs)..."
TOKEN_BACKUP="$BACKUP_DIR/token-state"
cp -a "$TOKEN_DIR" "$TOKEN_BACKUP"
# The token backup must NOT contain any plaintext private key — it is the
# token's own encrypted object store. We assert no PEM private keys leaked.
if grep -rlq "PRIVATE KEY" "$BACKUP_DIR" 2>/dev/null; then
    fail "backup contains plaintext private key material — non-extractability violated"
fi
pass "token state backed up; no plaintext private keys present"

# ----------------------------------------------------------------------------
# 5. Simulate disaster: lose the database AND the token
# ----------------------------------------------------------------------------
log "Simulating disaster: wiping metadata DB and token directory..."
rm -f "$DB_PATH" "$DB_PATH-wal" "$DB_PATH-shm"
rm -rf "${TOKEN_DIR:?}"/*
# Confirm the loss is real: a signer lookup must now fail.
if runca inventory >/dev/null 2>&1 && runca list 2>/dev/null | grep -q "DR Root"; then
    fail "state still present after wipe — disaster simulation ineffective"
fi
pass "state destroyed"

# ----------------------------------------------------------------------------
# 6. Restore from backup material
# ----------------------------------------------------------------------------
log "Restoring HSM token state..."
cp -a "$TOKEN_BACKUP/." "$TOKEN_DIR/"
pass "token state restored"

log "Restoring metadata database..."
cp -a "$BACKUP_DIR/metadata.db" "$DB_PATH"
pass "metadata restored"

# ----------------------------------------------------------------------------
# 7. Verify recovery
# ----------------------------------------------------------------------------
log "Verifying recovery (secsy-ca restore)..."
runca restore -in "$BACKUP_DIR" || fail "restore verification failed"
pass "restore verified: CAs resolve on the token, fingerprints match, audit chain intact"

# Prove the recovered CA can actually sign again: issue a leaf certificate.
log "Proving the recovered intermediate can still sign..."
CSR="$WORK/leaf.csr"
KEY="$WORK/leaf.key"
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$KEY" -out "$CSR" -subj "/CN=recovered.example.com" >/dev/null 2>&1 \
    || fail "could not generate a test CSR"
runca issue -ca "secsy-dr-intermediate" -csr "$CSR" -profile server -out "$WORK/leaf.pem" \
    || fail "recovered CA could not issue a certificate"
openssl x509 -in "$WORK/leaf.pem" -noout -subject >/dev/null || fail "issued cert is not valid X.509"
pass "recovered intermediate signed a fresh leaf certificate"

echo
echo "============================================================"
echo " DR DRILL PASSED"
echo "   • 2-of-3 key ceremony (root + intermediate) on SoftHSM"
echo "   • keys verified non-extractable; no plaintext key leaked"
echo "   • backup → simulated loss → restore → re-issuance verified"
echo "============================================================"
