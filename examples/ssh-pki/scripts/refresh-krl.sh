#!/usr/bin/env bash
# Refresh the OpenSSH KRL a host uses to reject revoked SSH certificates.
#
# The KRL endpoint is public (no credentials, like CRL distribution). Run this
# on a timer on every host that trusts the CA (see ../systemd/) so revocations
# converge within one interval. It writes atomically and only reloads sshd when
# the KRL actually changed.
#
# Usage:
#   refresh-krl.sh <ca-id> [pki-base-url] [krl-path]
# Environment overrides: PKI_BASE_URL, KRL_PATH, SSHD_RELOAD (set to "" to skip).
set -euo pipefail

CA_ID="${1:?usage: refresh-krl.sh <ca-id> [pki-base-url] [krl-path]}"
BASE_URL="${2:-${PKI_BASE_URL:-https://pki.example.com}}"
KRL_PATH="${3:-${KRL_PATH:-/etc/ssh/ops-ssh-ca.krl}}"
SSHD_RELOAD="${SSHD_RELOAD:-systemctl reload sshd}"

url="${BASE_URL%/}/api/ssh/cas/${CA_ID}/krl"
tmp="$(mktemp "${KRL_PATH}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

# --fail: non-2xx is an error; -S: show errors even when quiet.
curl -fsS -o "$tmp" "$url"

# A KRL is a binary blob; a zero-length body means something went wrong.
[ -s "$tmp" ] || { echo "refresh-krl: empty KRL from $url" >&2; exit 1; }

if [ -f "$KRL_PATH" ] && cmp -s "$tmp" "$KRL_PATH"; then
    exit 0    # unchanged — nothing to do
fi

install -m 0644 "$tmp" "$KRL_PATH"
echo "refresh-krl: updated $KRL_PATH from $url"
[ -n "$SSHD_RELOAD" ] && $SSHD_RELOAD || true
