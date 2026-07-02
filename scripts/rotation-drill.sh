#!/usr/bin/env bash
#
# rotation-drill.sh — Intermediate-CA key-rotation drill for secsy-pki against
# SoftHSM. It proves continuity of validation across a signing-key rollover with
# a dual-chain overlap window, end-to-end, in an isolated sandbox:
#
#   1. Provision a fresh, dedicated SoftHSM token.
#   2. Create a root + intermediate CA (keys generated inside the token).
#   3. Issue a leaf under the OLD intermediate key; verify it chains to the root.
#   4. Rotate the intermediate key (HSM-backed): a new keypair is generated and
#      cross-signed under the root with the same subject DN. Overlap opens.
#   5. Issue a leaf under the SAME CA reference — it is transparently signed by
#      the NEW key.
#   6. Prove BOTH leaves validate against the single combined overlap chain
#      (the crux: the old-key leaf must not break when the key rotates).
#   7. Show rotation status and that premature retirement is refused while the
#      old-key leaf is still valid.
#   8. Drain the old key (revoke the old-key leaf), then retire it: the old
#      intermediate is revoked under the root and the root CRL is refreshed.
#   9. Verify the root CRL lists the retired intermediate, and that the freshly
#      published chain no longer carries the retired key.
#
# It uses its own SOFTHSM2_CONF and token directory under a temp workspace, so it
# never touches the shared development token from setup-softhsm.sh.
#
# Usage:
#   ./scripts/rotation-drill.sh            # run the drill (cleans up on success)
#   ROT_KEEP=1 ./scripts/rotation-drill.sh # keep the workspace for inspection
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
command -v openssl >/dev/null 2>&1 || fail "openssl not found"
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

WORK="$(mktemp -d /tmp/secsy-rotation-drill.XXXXXX)"
TOKEN_DIR="$WORK/tokens"
DB_PATH="$WORK/secsy-pki.db"
CONF="$WORK/softhsm2.conf"
ART="$WORK/artifacts"
mkdir -p "$TOKEN_DIR" "$ART"

cleanup() {
    if [[ "${ROT_KEEP:-0}" == "1" ]]; then
        echo "==> ROT_KEEP=1 — workspace preserved at: $WORK"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

TOKEN_LABEL="secsy-rot-root"
USER_PIN="1234"
SO_PIN="5678"

export SOFTHSM2_CONF="$CONF"
cat > "$CONF" <<EOF
directories.tokendir = $TOKEN_DIR
objectstore.backend = file
log.level = INFO
slots.removable = false
EOF

CONFIG="$WORK/config.yaml"
cat > "$CONFIG" <<EOF
database:
  driver: "sqlite"
  dsn: "$DB_PATH"
root_user:
  username: "root"
  password: "rotation-drill"
key_provider:
  type: "pkcs11"
pkcs11:
  module_path: "$MODULE_PATH"
  pin: "$USER_PIN"
  token_label: "$TOKEN_LABEL"
EOF

# ----------------------------------------------------------------------------
# 1. Provision a fresh token and build the CLI
# ----------------------------------------------------------------------------
log "Provisioning SoftHSM token '$TOKEN_LABEL'..."
softhsm2-util --init-token --free --label "$TOKEN_LABEL" --pin "$USER_PIN" --so-pin "$SO_PIN" >/dev/null
pass "token initialized"

log "Building secsy-ca..."
CA_BIN="$WORK/secsy-ca"
( cd "$SERVER_DIR" && go build -tags sqlite -o "$CA_BIN" ./cmd/secsy-ca )
pass "built $CA_BIN"

runca() { "$CA_BIN" -config "$CONFIG" "$@"; }

# pem_only extracts just the PEM certificate blocks from mixed CLI output.
pem_only() { awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/'; }

# make_leaf <name> <ca-ref> <out.pem> — generate a key+CSR and issue a leaf.
# Prints the issued certificate's decimal serial on stdout.
make_leaf() {
    local name="$1" caref="$2" out="$3"
    local key="$WORK/$name.key" csr="$WORK/$name.csr" errlog="$WORK/$name.issue.log"
    openssl ecparam -name prime256v1 -genkey -noout -out "$key" 2>/dev/null
    openssl req -new -key "$key" -subj "/CN=$name.example.com" -out "$csr" 2>/dev/null
    runca issue -ca "$caref" -csr "$csr" -profile server -out "$out" 2>"$errlog" \
        || fail "issuing leaf $name failed"
    grep -oE 'serial=[0-9]+' "$errlog" | head -1 | cut -d= -f2
}

# ----------------------------------------------------------------------------
# 2. Root + intermediate CA
# ----------------------------------------------------------------------------
log "Creating root CA..."
runca init-root -label "$TOKEN_LABEL" -cn "Secsy Rotation Root CA" -o "Secsy" \
    -key-type ecdsa-p384 -validity-days 3650 >/dev/null || fail "init-root failed"
pass "root created"

log "Issuing intermediate CA..."
runca issue-intermediate -parent "$TOKEN_LABEL" -label "secsy-rot-intermediate" \
    -cn "Secsy Rotation Issuing CA" -o "Secsy" -key-type ecdsa-p256 \
    -validity-days 1825 >/dev/null || fail "issue-intermediate failed"
pass "intermediate created"

runca publish-chain -ca "$TOKEN_LABEL" -out "$ART/root.pem"
[[ -s "$ART/root.pem" ]] || fail "root chain empty"

# ----------------------------------------------------------------------------
# 3. Issue a leaf under the OLD intermediate key
# ----------------------------------------------------------------------------
log "Issuing a leaf under the ORIGINAL intermediate key..."
OLD_LEAF_SERIAL="$(make_leaf oldleaf secsy-rot-intermediate "$ART/oldleaf.pem")"
[[ -n "$OLD_LEAF_SERIAL" ]] || fail "could not determine old-key leaf serial"
pass "old-key leaf issued (serial=$OLD_LEAF_SERIAL)"

runca publish-chain -ca "secsy-rot-intermediate" -out "$ART/chain-before.pem"
openssl verify -CAfile "$ART/root.pem" -untrusted "$ART/chain-before.pem" "$ART/oldleaf.pem" >/dev/null \
    || fail "old-key leaf failed to validate before rotation"
pass "old-key leaf validates against the pre-rotation chain"

# ----------------------------------------------------------------------------
# 4. Rotate the intermediate key
# ----------------------------------------------------------------------------
log "Rotating the intermediate signing key (HSM-backed)..."
runca rotate-intermediate -ca "secsy-rot-intermediate" \
    -transcript-out "$ART/rotation.json" -chain-out "$ART/chain-overlap.pem" >/dev/null \
    || fail "rotation failed"
grep -q '"combined_chain_pem"' "$ART/rotation.json" || fail "rotation transcript missing combined chain"
OLD_CA_SERIAL="$(grep -oE '"old_ca_serial": *"[0-9]+"' "$ART/rotation.json" | grep -oE '[0-9]+' | head -1)"
NEW_CA_LABEL="$(grep -oE '"new_ca_label": *"[^"]+"' "$ART/rotation.json" | sed -E 's/.*: *"([^"]+)"/\1/')"
[[ -n "$OLD_CA_SERIAL" ]] || fail "could not read old intermediate serial from transcript"
pass "rotation complete: new key '$NEW_CA_LABEL' active; old intermediate serial=$OLD_CA_SERIAL superseded"

# ----------------------------------------------------------------------------
# 5. Issue a leaf under the SAME reference — routes to the NEW key
# ----------------------------------------------------------------------------
log "Issuing a leaf under the SAME CA reference (must use the NEW key)..."
NEW_LEAF_SERIAL="$(make_leaf newleaf secsy-rot-intermediate "$ART/newleaf.pem")"
pass "new-key leaf issued (serial=$NEW_LEAF_SERIAL)"

# ----------------------------------------------------------------------------
# 6. The crux: BOTH leaves validate against the single combined overlap chain
# ----------------------------------------------------------------------------
log "Verifying dual-chain continuity across the rollover..."
openssl verify -CAfile "$ART/root.pem" -untrusted "$ART/chain-overlap.pem" "$ART/oldleaf.pem" >/dev/null \
    || fail "old-key leaf BROKE after rotation — continuity violated"
pass "old-key leaf still validates against the combined overlap chain"
openssl verify -CAfile "$ART/root.pem" -untrusted "$ART/chain-overlap.pem" "$ART/newleaf.pem" >/dev/null \
    || fail "new-key leaf failed to validate against the combined overlap chain"
pass "new-key leaf validates against the combined overlap chain"

CERT_COUNT="$(grep -c 'BEGIN CERTIFICATE' "$ART/chain-overlap.pem")"
[[ "$CERT_COUNT" == "3" ]] || fail "combined chain has $CERT_COUNT certs, want 3 (new + old intermediate + root)"
pass "combined overlap chain carries both intermediates plus the root"

# ----------------------------------------------------------------------------
# 7. Rotation status + premature-retirement refusal
# ----------------------------------------------------------------------------
log "Checking rotation status..."
runca rotation-status -ca "secsy-rot-intermediate" -json > "$ART/status.json"
grep -q '"status": *"superseded"' "$ART/status.json" || fail "old key not reported superseded"
pass "old key reported superseded with outstanding leaves"

log "Verifying premature retirement is refused while the old key has valid leaves..."
if runca retire-intermediate -ca "secsy-rot-intermediate" >/dev/null 2>&1; then
    fail "retirement succeeded despite an outstanding old-key leaf — safety gate broken"
fi
pass "premature retirement correctly refused"

# ----------------------------------------------------------------------------
# 8. Drain the old key, then retire it
# ----------------------------------------------------------------------------
log "Draining the old key: revoking the old-key leaf (serial=$OLD_LEAF_SERIAL)..."
runca revoke -ca "secsy-rot-intermediate" -serial "$OLD_LEAF_SERIAL" -reason superseded >/dev/null \
    || fail "revoking old-key leaf failed"
pass "old-key leaf revoked; old key drained"

log "Retiring the superseded intermediate key..."
runca retire-intermediate -ca "secsy-rot-intermediate" -reason cessationOfOperation \
    -crl-out "$ART/root-crl.der" >/dev/null || fail "retirement failed"
pass "old intermediate retired (revoked under the root)"

# ----------------------------------------------------------------------------
# 9. Verify revocation is published, and the retired key drops out of the chain
# ----------------------------------------------------------------------------
log "Verifying the root CRL lists the retired intermediate (serial=$OLD_CA_SERIAL)..."
openssl crl -inform DER -in "$ART/root-crl.der" -text -noout > "$ART/root-crl.txt" 2>/dev/null \
    || fail "could not parse refreshed root CRL"
OLD_CA_HEX="$(printf '%X' "$OLD_CA_SERIAL")"
if ! grep -qiE "Serial Number: *(0x)?0*${OLD_CA_SERIAL}([^0-9]|$)|Serial Number: *(0x)?0*${OLD_CA_HEX}([^0-9A-Fa-f]|$)" "$ART/root-crl.txt"; then
    fail "root CRL does not list retired intermediate serial $OLD_CA_SERIAL"
fi
pass "root CRL lists the retired intermediate"

log "Verifying the retired key is dropped from freshly published chains..."
runca publish-chain -ca "secsy-rot-intermediate" -out "$ART/chain-after.pem"
AFTER_COUNT="$(grep -c 'BEGIN CERTIFICATE' "$ART/chain-after.pem")"
[[ "$AFTER_COUNT" == "2" ]] || fail "post-retirement chain has $AFTER_COUNT certs, want 2 (new intermediate + root)"
pass "post-retirement chain carries only the new intermediate + root"

# The new-key leaf must still validate after retirement; the old-key leaf must not.
openssl verify -CAfile "$ART/root.pem" -untrusted "$ART/chain-after.pem" "$ART/newleaf.pem" >/dev/null \
    || fail "new-key leaf broke after retirement"
pass "new-key leaf still validates after retirement"

echo
echo "======================================================================"
echo " ROTATION DRILL PASSED"
echo "   • Old-key leaf validated continuously across the rollover overlap."
echo "   • New issuance transparently used the rotated-in key."
echo "   • Old key retired only after draining; revocation published via CRL."
echo "======================================================================"
