#!/usr/bin/env bash
# Sign a host's OpenSSH host key into a host certificate and (optionally) copy
# it back to the host. Run where secsy-ca can reach the HSM/config.
#
# Usage:
#   enroll-host.sh <ca-label-or-id> <host-ssh-target> <principals> [profile]
#
#   <host-ssh-target>  ssh destination, e.g. root@web1.prod.example.com
#   <principals>       comma-separated host names the cert is valid for,
#                      e.g. web1.prod.example.com,web1
#   [profile]          SSH signing profile (default: prod-host)
#
# Environment: SECSY_CONFIG (default /etc/secsy-pki/config.yaml),
#              HOST_KEY (remote host pubkey path; default ed25519).
set -euo pipefail

CA="${1:?usage: enroll-host.sh <ca> <host-ssh-target> <principals> [profile]}"
TARGET="${2:?missing host ssh target, e.g. root@web1.prod.example.com}"
PRINCIPALS="${3:?missing comma-separated principals}"
PROFILE="${4:-prod-host}"
CONFIG="${SECSY_CONFIG:-/etc/secsy-pki/config.yaml}"
HOST_KEY="${HOST_KEY:-/etc/ssh/ssh_host_ed25519_key.pub}"
CERT="${HOST_KEY%.pub}-cert.pub"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

# 1. Pull the host's public key.
scp -q "${TARGET}:${HOST_KEY}" "$workdir/host_key.pub"

# 2. Sign it into a host certificate.
secsy-ca -config "$CONFIG" ssh sign-host \
    -ca "$CA" -profile "$PROFILE" \
    -pub "$workdir/host_key.pub" \
    -key-id "$(echo "$PRINCIPALS" | cut -d, -f1)" \
    -principals "$PRINCIPALS" \
    -out "$workdir/host_key-cert.pub"

echo "Signed:"
ssh-keygen -L -f "$workdir/host_key-cert.pub"

# 3. Install the certificate beside the host key. sshd presents it once
#    60-secsy-host-cert.conf is in place.
scp -q "$workdir/host_key-cert.pub" "${TARGET}:${CERT}"
echo "Installed $CERT on $TARGET — add sshd_config.d/60-secsy-host-cert.conf and reload sshd."
