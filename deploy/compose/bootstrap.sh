#!/usr/bin/env bash
#
# bootstrap.sh — bring an empty secsy-pki deployment to the point where the
# server can start, using only what the container image already contains.
#
# The server does not create its own CA. It loads one, and fails to start if the
# CA its config names is missing — which is correct (a PKI that invents a trust
# anchor on boot is not one you can reason about) and means a container stack
# needs one step before `up`: initialize the PKCS#11 token, then mint the CA
# hierarchy on it. That is this script, run as a one-shot `bootstrap` service
# that the server waits on.
#
# Every step is guarded, because compose re-runs this on every `up`: the token
# is initialized only if no token carries the label, and each CA only if no CA
# carries its label. A second run is a no-op that prints what it found, so
# `docker compose up` is safe to repeat and restarting the stack never touches
# an existing key. The guards read the real state — the token store and the
# database — rather than a marker file, so a half-finished first run (token
# created, CA not) completes on the next one instead of being skipped.
#
# SoftHSM is the default because it ships in the image and needs no hardware, so
# the stack runs anywhere. It is *not* for production: the "HSM" is a directory
# of files in a Docker volume, and its keys are only as protected as that volume.
# For a real deployment, point SECSY_PKCS11_MODULE at a vendor module (or use the
# -yubihsm image) and skip the token step by setting SECSY_SKIP_TOKEN_INIT=1 —
# provisioning a real HSM is a key ceremony, not a container entrypoint.
# See docs/hsm/key-ceremony.md.

set -euo pipefail

CONFIG=${SECSY_CONFIG:-/etc/secsy/config.yaml}
TOKEN_LABEL=${SECSY_TOKEN_LABEL:-secsy}
ROOT_LABEL=${SECSY_ROOT_CA_LABEL:-root-ca}
ROOT_CN=${SECSY_ROOT_CA_CN:-secsy-pki Demo Root CA}
ROOT_KEY_TYPE=${SECSY_ROOT_CA_KEY_TYPE:-ecdsa-p384}
ICA_LABEL=${SECSY_ISSUING_CA_LABEL:-issuing-ca}
ICA_CN=${SECSY_ISSUING_CA_CN:-secsy-pki Demo Issuing CA}
ICA_KEY_TYPE=${SECSY_ISSUING_CA_KEY_TYPE:-ecdsa-p256}

step() { printf '\n== %s\n' "$*"; }
note() { printf '   %s\n' "$*"; }

: "${SECSY_USER_PIN:?SECSY_USER_PIN must be set (see .env.example)}"
: "${SECSY_ROOT_PASSWORD:?SECSY_ROOT_PASSWORD must be set (see .env.example)}"

# --- the PKCS#11 token -------------------------------------------------------
#
# `--free` takes the first uninitialized slot. Guarded on the label rather than
# on slot 0 being free: SoftHSM reassigns an initialized token to a new slot id,
# so "is slot 0 free" is true again afterwards and would re-initialize forever,
# filling the volume with tokens and leaving the CA keys in an earlier one.
step "PKCS#11 token '${TOKEN_LABEL}'"
if [ "${SECSY_SKIP_TOKEN_INIT:-0}" = "1" ]; then
	note "SECSY_SKIP_TOKEN_INIT=1 — assuming the token is already provisioned"
elif softhsm2-util --show-slots | grep -qE "^[[:space:]]*Label:[[:space:]]+${TOKEN_LABEL}[[:space:]]*$"; then
	note "already initialized"
else
	: "${SECSY_SO_PIN:?SECSY_SO_PIN must be set to initialize a token (see .env.example)}"
	softhsm2-util --init-token --free \
		--label "$TOKEN_LABEL" \
		--pin "$SECSY_USER_PIN" \
		--so-pin "$SECSY_SO_PIN"
	note "initialized"
fi

# --- the CA hierarchy --------------------------------------------------------
#
# `list` is the guard, and its exit status is checked before its output is
# matched: a config error also produces no matching label, and treating that as
# "the CA does not exist yet" would turn a typo in config.yaml into an attempt
# to mint a second root.
ca_labels() {
	local out
	if ! out=$(secsy-ca -config "$CONFIG" list); then
		printf '%s\n' "$out" >&2
		echo "bootstrap: cannot read the CA list — check ${CONFIG} and the PKCS#11 settings" >&2
		return 1
	fi
	# Skip the header; column 2 is LABEL. "No CAs configured." has no second
	# column, so an empty store yields an empty list.
	printf '%s\n' "$out" | awk 'NR > 1 { print $2 }'
}

step "root CA '${ROOT_LABEL}'"
labels=$(ca_labels)
if printf '%s\n' "$labels" | grep -qxF "$ROOT_LABEL"; then
	note "already exists"
else
	secsy-ca -config "$CONFIG" init-root \
		-label "$ROOT_LABEL" -cn "$ROOT_CN" -key-type "$ROOT_KEY_TYPE"
fi

# The root signs the intermediate and nothing else; leaves come from the
# intermediate, so the root's key can later move offline without reissuing
# anything. It is also the CA the server's self-issued serving certificate is
# configured against — see config.yaml.
step "issuing CA '${ICA_LABEL}'"
labels=$(ca_labels)
if printf '%s\n' "$labels" | grep -qxF "$ICA_LABEL"; then
	note "already exists"
else
	secsy-ca -config "$CONFIG" issue-intermediate \
		-parent "$ROOT_LABEL" -label "$ICA_LABEL" -cn "$ICA_CN" -key-type "$ICA_KEY_TYPE"
fi

step "bootstrap complete"
secsy-ca -config "$CONFIG" list
