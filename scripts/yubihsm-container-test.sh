#!/usr/bin/env bash
#
# yubihsm-container-test.sh — prove a published container can put an externally
# generated RSA key onto an attached YubiHSM 2, can be told where the device's
# audit log is permanently written, and can serve both routes to the device from
# a single container with no connector daemon beside it (Tasks 201, 203, 204).
#
# internal/yubihsmtest already settles "the code can import an RSA key" against
# the device. It does so with `go test`, against whatever PKCS#11 module the
# *host* happens to have, and that is precisely the gap this script closes: the
# thing operators run is the container, the module inside it is a different build
# from the host's, and for a while it was a different *version* — bookworm-
# backports' 2.6.0, which stores an RSA key sent with CKA_UNWRAP=FALSE as a
# device wrap-key and so cannot import or generate RSA at all. A suite that
# passes on a developer's host says nothing about that.
#
# "Externally generated" is meant literally: every key below is produced by the
# host's `openssl`, outside the image, in each of the encodings openssl actually
# emits — PKCS#8, traditional PKCS#1, both of their encrypted forms, bare DER
# and PKCS#12. An operator migrating a CA has whichever one their predecessor
# chose, not whichever one a test suite found convenient, and the passphrase for
# the encrypted ones has to reach a container without passing through a command
# line.
#
# So every check below runs inside the image, as the image's own non-root user,
# reaching the device the way docs/deployment/container.md tells operators to.
# Nothing here is compiled from the working tree; the binaries under test are the
# ones in the image.
#
# Requires: docker, an attached YubiHSM 2, and the udev rule from
# deploy/udev/70-yubihsm.rules installed on the host (the script checks, and says
# what to do if not). It is not part of CI — CI has no HSM.
#
#   scripts/yubihsm-container-test.sh
#   scripts/yubihsm-container-test.sh --image secsy-pki:local-yubihsm
#   scripts/yubihsm-container-test.sh --legacy-module /tmp/yubihsm-2.6.0
#   scripts/yubihsm-container-test.sh --keep       # leave the scratch dir behind
#
# --legacy-module DIR repeats the import against a pre-2.7.2 module mounted over
# the image's, which is the shape of a production deployment that mounts the
# host's vendor stack in. DIR must hold yubihsm_pkcs11.so and a lib/ with
# libyubihsm.so.2 and libyubihsm_usb.so.2. To build one:
#
#   docker run --rm -v /tmp/yubihsm-2.6.0:/out debian:bookworm-slim bash -c '
#     echo "deb http://deb.debian.org/debian bookworm-backports main" \
#       >/etc/apt/sources.list.d/backports.list
#     apt-get update -qq
#     apt-get install -y --no-install-recommends -t bookworm-backports \
#       yubihsm-pkcs11 libyubihsm2 libyubihsm-usb2 >/dev/null
#     mkdir -p /out/lib
#     cp -a /usr/lib/*/pkcs11/yubihsm_pkcs11.so /out/
#     cp -a /usr/lib/*/libyubihsm*.so* /out/lib/'
#
# WARNING: this creates and deletes objects on the device, in the reserved id
# range below, and consumes audit-log entries — draining them when the 62-entry
# log runs short, which destroys the device's only copy. Do not point it at a
# device whose audit log a deployment is collecting.
set -uo pipefail

IMAGE="${SECSY_YUBIHSM_IMAGE:-ghcr.io/blechschmidt/secsy-pki:main-yubihsm}"
LEGACY_MODULE=""
KEEP=0

# Object ids this script owns. internal/yubihsmtest owns 0x7f00-0x7f1f and the
# older per-package tests own 0x7e5x, so a separate range lets a run of this
# script and a run of those coexist without either clearing the other's objects.
readonly ID_BASE=0x7d00

# Device credentials. The factory-default authentication key; override for a
# provisioned device.
AUTH_KEY_ID="${SECSY_YUBIHSM_AUTH_KEY_ID:-1}"
PASSWORD="${SECSY_YUBIHSM_PASSWORD:-password}"

# The first Yubico release whose RSA templates read CKA_UNWRAP by value rather
# than by presence, as reported by `yubihsm-shell --version`. Kept in step with
# yubihsmUnwrapFixedIn in server/internal/pki/module_quirks.go.
readonly MIN_MODULE_VERSION="2.7.2"

die() {
	printf '\033[31m!! %s\033[0m\n' "$*" >&2
	exit 1
}
say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

pass=0
fail=0
check() { # check <description> <0-or-1 ok>
	if [[ "$2" == "0" ]]; then
		printf '    \033[32mok\033[0m   %s\n' "$1"
		pass=$((pass + 1))
	else
		printf '    \033[31mFAIL\033[0m %s\n' "$1"
		fail=$((fail + 1))
	fi
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--image)
		IMAGE="${2:?--image needs a value}"
		shift 2
		;;
	--legacy-module)
		LEGACY_MODULE="${2:?--legacy-module needs a directory}"
		shift 2
		;;
	--keep)
		KEEP=1
		shift
		;;
	-h | --help)
		sed -n '2,56p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*) die "unknown argument: $1" ;;
	esac
done

command -v docker >/dev/null || die "docker is required"

# ---------------------------------------------------------------------------
# The device, and the two things the container needs to reach it: the node to
# pass with --device, and the gid that node's group resolves to.
#
# The specific node rather than the whole bus: --device /dev/bus/usb would hand
# the container every USB device on the machine, which is a poor default for a
# script that runs unattended.
say "Locating the device"
usb_path=""
for d in /sys/bus/usb/devices/*/; do
	[[ -r "$d/idVendor" && -r "$d/idProduct" ]] || continue
	[[ "$(cat "$d/idVendor")" == "1050" && "$(cat "$d/idProduct")" == "0030" ]] || continue
	usb_path="$d"
	break
done
[[ -n "$usb_path" ]] || die "no YubiHSM 2 (1050:0030) found on this host"
busnum=$(printf '%03d' "$(cat "$usb_path/busnum")")
devnum=$(printf '%03d' "$(cat "$usb_path/devnum")")
DEV_NODE="/dev/bus/usb/$busnum/$devnum"
[[ -c "$DEV_NODE" ]] || die "expected a character device at $DEV_NODE"

dev_group=$(stat -c '%G' "$DEV_NODE")
dev_gid=$(stat -c '%g' "$DEV_NODE")
dev_mode=$(stat -c '%a' "$DEV_NODE")
echo "    node:  $DEV_NODE (group $dev_group/$dev_gid, mode $dev_mode)"
# libusb needs the node read-write. The container is always given the node's own
# group (--group-add below), so group rw is enough — including the root:root 0660
# default, where the added group is 0. What is not enough is 0600, or a mode that
# only grants read: both leave the image's uid 65532 unable to open it, and the
# failure arrives as LIBUSB_ERROR_ACCESS from inside a container, which is a poor
# place to learn about a host permission.
dev_group_bits=$(((0$dev_mode / 8) % 8))
dev_other_bits=$((0$dev_mode % 8))
if (((dev_group_bits & 6) != 6 && (dev_other_bits & 6) != 6)); then
	die "$DEV_NODE is mode $dev_mode, which grants neither its group nor everyone
   read-write, so the image's non-root user cannot open it. Install the udev rule
   the image ships:
     docker run --rm --entrypoint cat $IMAGE \\
       /usr/share/secsy-pki/udev/70-yubihsm.rules | sudo tee /etc/udev/rules.d/70-yubihsm.rules
     sudo groupadd -r secsy    # or edit GROUP= in the rule
     sudo udevadm control --reload-rules
     sudo udevadm trigger --subsystem-match=usb --attr-match=idVendor=1050"
fi

DOCKER_DEV=(--device "$DEV_NODE" --group-add "$dev_gid")

# ---------------------------------------------------------------------------
say "Scratch directory and config"
WORK=$(mktemp -d /tmp/secsy-yubihsm-container.XXXXXX)
cleanup_work() {
	if [[ $KEEP -eq 1 ]]; then
		echo "    kept: $WORK"
	else
		rm -rf "$WORK"
	fi
}
trap cleanup_work EXIT
mkdir -p "$WORK/keys" "$WORK/data" "$WORK/out"

cat >"$WORK/config.yaml" <<EOF
server:
  host: "127.0.0.1"
  port: 8443
database:
  driver: "sqlite"
  dsn: "/app/data/secsy.db"
root_user:
  username: "root"
  password: "container-test-not-a-deployment"
key_provider:
  type: "pkcs11"
pkcs11:
  module_path: "/usr/lib/pkcs11/yubihsm_pkcs11.so"
  pin: "$(printf '%04d' "$AUTH_KEY_ID")$PASSWORD"
  token_label: "YubiHSM"
  session_pool_size: 1
yubihsm:
  connector_url: "yhusb://"
  auth_key_id: $AUTH_KEY_ID
  password: "$PASSWORD"
EOF
# World-readable/writable because the container runs as uid 65532 and this is a
# throwaway directory holding throwaway keys.
chmod -R a+rwX "$WORK"
echo "    $WORK"

# secsy runs secsy-ca in the image with the device and the scratch dir attached.
# MODULE_OVERLAY is empty except during the legacy-module pass, which mounts a
# different PKCS#11 module over the image's — so the overlay reaches the code
# under test and nothing else. EXTRA_RUN_ARGS is empty except where a single
# call needs more from `docker run` than the rest — an environment variable
# carrying a key passphrase, or the audit volume.
MODULE_OVERLAY=()
EXTRA_RUN_ARGS=()
secsy() { # secsy <binary> <args...>
	local bin="$1"
	shift
	docker run --rm "${DOCKER_DEV[@]}" \
		-v "$WORK/config.yaml:/etc/secsy/config.yaml:ro" \
		-v "$WORK/keys:/keys:ro" \
		-v "$WORK/data:/app/data" \
		-v "$WORK/out:/out" \
		"${MODULE_OVERLAY[@]}" \
		"${EXTRA_RUN_ARGS[@]}" \
		--entrypoint "$bin" "$IMAGE" "$@"
}

# yhs runs the vendor shell in the image, and deliberately *without* the overlay:
# it is the instrument, not the subject, so it keeps the image's own known-good
# libyubihsm even while secsy-ca is being driven through an older one. It claims
# the same USB interface the PKCS#11 module does, so it must not overlap a secsy
# call — every use below is sequential for that reason.
yhs() {
	docker run --rm "${DOCKER_DEV[@]}" \
		--entrypoint yubihsm-shell "$IMAGE" \
		--connector yhusb:// --authkey "$AUTH_KEY_ID" -p "$PASSWORD" "$@"
}

# keep_log_space <entries> drains the device audit log when fewer than <entries>
# slots remain, mirroring keepLogSpace in internal/yubihsmtest.
#
# It is not housekeeping. A YubiHSM with force-audit enabled **stops accepting
# commands** when its 62-entry log fills, so a script that performs forty device
# operations without draining fails partway through with a refusal that looks
# like a bug in whatever it was doing at the time. Draining destroys the device's
# only copy of those entries, which is why the header of this file says not to
# point it at a device whose log a deployment is collecting.
keep_log_space() {
	local want="$1" info used total logs last
	info=$(yhs -a get-device-info 2>&1) || return 0
	used=$(sed -n 's|^Log used:[[:space:]]*\([0-9]*\)/.*|\1|p' <<<"$info")
	total=$(sed -n 's|^Log used:[[:space:]]*[0-9]*/\([0-9]*\).*|\1|p' <<<"$info")
	[[ -n "$used" && -n "$total" ]] || return 0
	((total - used >= want)) && return 0
	logs=$(yhs -a get-logs 2>&1) || return 0
	last=$(sed -n 's/^item:[[:space:]]*\([0-9]*\) --.*/\1/p' <<<"$logs" | tail -1)
	[[ -n "$last" ]] || return 0
	if yhs -a set-log-index --log-index "$last" >/dev/null 2>&1; then
		echo "    drained the device audit log up to entry #$last ($used/$total were used)"
	fi
}

# ---------------------------------------------------------------------------
# 1. The module the image ships.
say "The PKCS#11 module in $IMAGE"
module_info=$(docker run --rm --entrypoint sh "$IMAGE" -c '
	set -e
	printf "path=%s\n" "$(readlink -f /usr/lib/pkcs11/yubihsm_pkcs11.so)"
	printf "shipped=%s\n" "$(cat /usr/share/secsy-pki/yubihsm-shell-version 2>/dev/null || echo unknown)"
	printf "shell=%s\n" "$(yubihsm-shell --version | awk "{print \$2}")"
	printf "unresolved_libs=%s\n" "$(ldd /usr/lib/pkcs11/yubihsm_pkcs11.so | grep -c "not found")"
' 2>&1) || die "the image does not carry a YubiHSM PKCS#11 module — is $IMAGE a -yubihsm tag?"
sed 's/^/    /' <<<"$module_info"

module_version=$(sed -n 's/^shell=//p' <<<"$module_info")
unresolved=$(sed -n 's/^unresolved_libs=//p' <<<"$module_info")
[[ -n "$module_version" ]] || die "could not read the module version out of the image"
check "the module resolves every shared library it needs" \
	"$([[ "$unresolved" == "0" ]] && echo 0 || echo 1)"

# The version gate. Anything older than 2.7.2 cannot import or generate RSA
# through this project's least-privilege template (see module_quirks.go), which
# is the whole reason the image builds the module from Yubico's release instead
# of installing Debian's.
oldest=$(printf '%s\n%s\n' "$MIN_MODULE_VERSION" "$module_version" | sort -V | head -1)
check "the module is $MIN_MODULE_VERSION or newer (found $module_version), so it reads CKA_UNWRAP by value" \
	"$([[ "$oldest" == "$MIN_MODULE_VERSION" ]] && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 2. The device, from inside, as the image's own user.
say "Reaching the device from inside the container"
info=$(yhs -a get-device-info 2>&1) || die "the container cannot reach the device:
$info"
serial=$(sed -n 's/^Serial number:[[:space:]]*//p' <<<"$info")
logused=$(sed -n 's/^Log used:[[:space:]]*//p' <<<"$info")
uid_inside=$(docker run --rm --entrypoint id "$IMAGE" -u)
echo "    serial $serial, audit log $logused, running as uid $uid_inside"
check "the device answers over yhusb:// from inside the image" "$([[ -n "$serial" ]] && echo 0 || echo 1)"
check "the image runs as a non-root user (uid $uid_inside)" "$([[ "$uid_inside" != "0" ]] && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 3-4. Import each RSA size the device supports, then read the object back off
# the device and check it is what it should be.
#
# Reading it back is the point. A module with the pre-2.7.2 bug creates an object
# and returns success; what it creates is a wrap-key, which is not exposed as
# CKO_PRIVATE_KEY, so "the import command exited 0" and "there is an RSA signing
# key on the device" are different claims and only the second one matters.
CREATED_IDS=()

import_one() { # import_one <bits> <id-offset>
	local bits="$1" offset="$2"
	local id label
	id=$(printf '%04x' $((ID_BASE + offset)))
	label="t201-c-rsa$bits"
	# Recorded before the attempt, not after it succeeds: an import that creates
	# the wrong kind of object still leaves one behind, and that is exactly the
	# case this script exists to be able to produce.
	CREATED_IDS+=("$id")

	keep_log_space 12
	openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$bits" \
		-out "$WORK/keys/rsa$bits.pem" 2>/dev/null
	chmod a+r "$WORK/keys/rsa$bits.pem"

	local out rc
	out=$(secsy secsy-ca -config /etc/secsy/config.yaml import-key \
		-label "$label" -id "$id" -key "/keys/rsa$bits.pem" 2>&1)
	rc=$?
	if [[ $rc -ne 0 ]]; then
		check "RSA-$bits imports through secsy-ca import-key" 1
		sed 's/^/         /' <<<"$out"
		return
	fi
	check "RSA-$bits imports through secsy-ca import-key" 0

	# The CLI signs a challenge with the key on the device and verifies it under
	# the public half of the file it read. Its absence would mean the key landed
	# but does not sign.
	check "RSA-$bits is verified by signing on the device after import" \
		"$(grep -q 'Verified:' <<<"$out" && echo 0 || echo 1)"
	check "RSA-$bits is reported as key type rsa-$bits" \
		"$(grep -q "Key type:  rsa-$bits" <<<"$out" && echo 0 || echo 1)"

	# What the device itself says the object is.
	local obj
	obj=$(yhs -a get-object-info -i "0x$id" -t asymmetric-key 2>&1)
	check "0x$id is an asymmetric-key on the device, not a wrap-key" \
		"$([[ "$obj" == *"type: asymmetric-key"* ]] && echo 0 || echo 1)"
	check "0x$id carries algorithm rsa$bits" \
		"$([[ "$obj" == *"algorithm: rsa$bits"* ]] && echo 0 || echo 1)"
	# Least privilege, as the device understands it: it may sign, and it may not
	# leave. exportable-under-wrap is the capability that would let it.
	check "0x$id may sign" \
		"$([[ "$obj" == *sign-pkcs* ]] && echo 0 || echo 1)"
	check "0x$id is not exportable under wrap" \
		"$([[ "$obj" != *exportable-under-wrap* ]] && echo 0 || echo 1)"
	check "0x$id holds no unwrap capability" \
		"$([[ "$obj" != *unwrap-data* ]] && echo 0 || echo 1)"
	sed 's/^/         /' <<<"$obj"
}

delete_created() {
	local id type
	for id in "${CREATED_IDS[@]:-}"; do
		[[ -n "$id" ]] || continue
		# Both types, because the failure mode under test is the object landing as
		# the wrong one — and a wrap-key left at a handle a later run wants is how
		# a cleanup bug turns into a confusing second failure.
		for type in asymmetric-key wrap-key; do
			yhs -a delete-object -i "0x$id" -t "$type" >/dev/null 2>&1
		done
	done
	CREATED_IDS=()
}

say "Importing an existing RSA key into the device, from inside the container"
import_one 2048 1
import_one 3072 2
import_one 4096 3

# ---------------------------------------------------------------------------
# 4b. The same import, once per encoding `openssl` actually produces.
#
# The sweep above generates with `openssl genpkey`, which on OpenSSL 3 writes
# unencrypted PKCS#8 — one of six things an operator may be holding. A CA key
# that predates the migration was written by whichever openssl its generation
# had: `genrsa` before 3.0 wrote traditional PKCS#1, `-aes256` before 3.0 wrote
# a Proc-Type/DEK-Info block that modern openssl will not even produce without
# -traditional, appliances export bare DER, and Windows exports PKCS#12. All of
# them are RSA keys that must land on the device, and the encoding is not the
# operator's choice to make years after the fact.
#
# Each case asserts the *reported* format as well as the import, because
# "pkcs1.pem imported" is satisfied by a parser that quietly treated it as
# something else; the transcript line is what records which decoder ran.
#
# The two encrypted cases also settle how a passphrase reaches a container.
# There is no -pass flag by design — a passphrase on a command line is in the
# process table and in the shell history — so the only routes in are a mounted
# file and an environment variable, and both are checked here.
openssl_form_id=16

import_form() { # import_form <name> <file> <expected-format> [env|passfile]
	local name="$1" file="$2" want="$3" how="${4:-}"
	local id label out rc
	id=$(printf '%04x' $((ID_BASE + openssl_form_id)))
	openssl_form_id=$((openssl_form_id + 1))
	label="t203-c-$name"
	CREATED_IDS+=("$id")

	chmod a+r "$WORK/keys/$(basename "$file")"
	keep_log_space 12

	EXTRA_RUN_ARGS=()
	local pass_args=()
	case "$how" in
	env) EXTRA_RUN_ARGS=(-e "SECSY_KEY_PASSPHRASE=$FORM_PASSPHRASE") ;;
	passfile) pass_args=(-pass-file /keys/passphrase.txt) ;;
	esac
	out=$(secsy secsy-ca -config /etc/secsy/config.yaml import-key \
		-label "$label" -id "$id" -key "$file" "${pass_args[@]}" 2>&1)
	rc=$?
	EXTRA_RUN_ARGS=()

	if [[ $rc -ne 0 ]]; then
		check "$name imports into the device" 1
		sed 's/^/         /' <<<"$out"
		return
	fi
	check "$name imports into the device" 0
	check "$name is read as $want, not silently as something else" \
		"$(grep -q "($want)" <<<"$out" && echo 0 || echo 1)"
	check "$name signs on the device after import" \
		"$(grep -q 'Verified:' <<<"$out" && echo 0 || echo 1)"
	local obj
	obj=$(yhs -a get-object-info -i "0x$id" -t asymmetric-key 2>&1)
	check "$name landed as an asymmetric-key, not a wrap-key" \
		"$([[ "$obj" == *"type: asymmetric-key"* ]] && echo 0 || echo 1)"
	check "$name is not exportable under wrap" \
		"$([[ "$obj" != *exportable-under-wrap* ]] && echo 0 || echo 1)"
}

say "Every encoding an externally generated OpenSSL RSA key arrives in"
FORM_PASSPHRASE="t203-container-passphrase"
printf '%s' "$FORM_PASSPHRASE" >"$WORK/keys/passphrase.txt"

# Generated on the host, by the host's openssl, outside the image — which is
# what "externally generated" has to mean for this to prove anything.
openssl genrsa -out "$WORK/keys/form-pkcs8.pem" 2048 2>/dev/null
openssl genrsa -traditional -out "$WORK/keys/form-pkcs1.pem" 2048 2>/dev/null
openssl genrsa -aes256 -passout "pass:$FORM_PASSPHRASE" \
	-out "$WORK/keys/form-pkcs8enc.pem" 2048 2>/dev/null
openssl genrsa -aes256 -traditional -passout "pass:$FORM_PASSPHRASE" \
	-out "$WORK/keys/form-pemenc.pem" 2048 2>/dev/null
openssl rsa -in "$WORK/keys/form-pkcs8.pem" -outform DER \
	-out "$WORK/keys/form-bare.der" 2>/dev/null
openssl req -x509 -new -key "$WORK/keys/form-pkcs8.pem" -sha256 -days 2 \
	-subj "/CN=t203 container pkcs12" -out "$WORK/keys/form-p12.crt" 2>/dev/null
openssl pkcs12 -export -inkey "$WORK/keys/form-pkcs8.pem" -in "$WORK/keys/form-p12.crt" \
	-passout "pass:$FORM_PASSPHRASE" -out "$WORK/keys/form-bundle.p12" 2>/dev/null
chmod a+r "$WORK/keys"/*

# openssl 3 emits PKCS#8 from `genrsa`; 1.x emitted PKCS#1 from the same
# command, so both appear here deliberately rather than one standing in for the
# other. The header of each generated file says which is which:
for f in form-pkcs8 form-pkcs1 form-pkcs8enc form-pemenc; do
	printf '    %-18s %s\n' "$f.pem" "$(head -1 "$WORK/keys/$f.pem")"
done

import_form pkcs8 /keys/form-pkcs8.pem pkcs8
import_form pkcs1 /keys/form-pkcs1.pem pkcs1
import_form pkcs8-encrypted /keys/form-pkcs8enc.pem pkcs8-encrypted env
import_form pem-encrypted /keys/form-pemenc.pem pem-encrypted passfile
import_form bare-der /keys/form-bare.der der
import_form pkcs12 /keys/form-bundle.p12 pkcs12 env

# An encrypted key with no passphrase must be refused with advice rather than a
# parse error, and must not leave a half-made object behind on the device.
no_pass=$(secsy secsy-ca -config /etc/secsy/config.yaml import-key \
	-label t203-c-nopass -id "$(printf '%04x' $((ID_BASE + 31)))" \
	-key /keys/form-pkcs8enc.pem 2>&1)
check "an encrypted key with no passphrase is refused, naming the way to supply one" \
	"$(grep -qi 'is encrypted: supply the passphrase' <<<"$no_pass" && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
# 5. The lookup the product performs on every restart.
say "The imported keys through secsy-ca inventory"
keep_log_space 12
inv=$(secsy secsy-ca -config /etc/secsy/config.yaml inventory 2>&1)
rc=$?
if [[ $rc -eq 0 ]]; then
	for bits in 2048 3072 4096; do
		local_row=$(grep "t201-c-rsa$bits" <<<"$inv")
		check "inventory lists t201-c-rsa$bits as rsa-$bits" \
			"$([[ "$local_row" == *"rsa-$bits"* ]] && echo 0 || echo 1)"
		# The EXTRACTABLE column, which `inventory -strict` exits non-zero on.
		# An imported key must be no more exposed than a generated one.
		check "inventory reports t201-c-rsa$bits as non-extractable" \
			"$([[ -n "$local_row" && "$local_row" != *YES* ]] && echo 0 || echo 1)"
	done
	sed 's/^/         /' <<<"$inv"
else
	check "secsy-ca inventory runs against the device" 1
	sed 's/^/         /' <<<"$inv"
fi

# ---------------------------------------------------------------------------
# 6. The migration this feature exists for: adopt a CA whose certificate is
# already distributed, and keep issuing from it. The certificate is self-signed
# on the host with the original key, standing in for the published root, and the
# leaf is then signed by the device.
say "Adopting a legacy RSA CA and issuing from it on the device"
keep_log_space 12
openssl req -x509 -new -key "$WORK/keys/rsa2048.pem" -sha256 -days 2 \
	-subj "/CN=t201 container legacy root" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-out "$WORK/keys/legacy-ca.pem" 2>/dev/null
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$WORK/keys/leaf.pem" 2>/dev/null
openssl req -new -key "$WORK/keys/leaf.pem" -subj "/CN=issued-after-migration.example" \
	-addext "subjectAltName=DNS:issued-after-migration.example" \
	-out "$WORK/keys/leaf.csr" 2>/dev/null
chmod a+r "$WORK/keys"/*

adopt=$(secsy secsy-ca -config /etc/secsy/config.yaml ca import \
	-label t201-c-legacy-ca -existing-key t201-c-rsa2048 \
	-cert /keys/legacy-ca.pem 2>&1)
rc=$?
check "ca import adopts the certificate against the already-imported key" "$([[ $rc -eq 0 ]] && echo 0 || echo 1)"
[[ $rc -eq 0 ]] || sed 's/^/         /' <<<"$adopt"

if [[ $rc -eq 0 ]]; then
	issued=$(secsy secsy-ca -config /etc/secsy/config.yaml issue \
		-ca t201-c-legacy-ca -csr /keys/leaf.csr -profile server \
		-validity-days 1 -out /out/leaf.crt 2>&1)
	rc=$?
	check "the adopted CA issues a certificate, signed on the device" "$([[ $rc -eq 0 ]] && echo 0 || echo 1)"
	[[ $rc -eq 0 ]] || sed 's/^/         /' <<<"$issued"

	if [[ -s "$WORK/out/leaf.crt" ]]; then
		# The device-made signature has to verify under the certificate that was
		# published before the migration. If it does not, the key on the device is
		# not the key relying parties trust.
		verify=$(openssl verify -CAfile "$WORK/keys/legacy-ca.pem" "$WORK/out/leaf.crt" 2>&1)
		check "the device-issued leaf verifies under the pre-migration CA certificate" \
			"$([[ "$verify" == *": OK"* ]] && echo 0 || echo 1)"
		[[ "$verify" == *": OK"* ]] || sed 's/^/         /' <<<"$verify"
	else
		check "the issued certificate was written" 1
	fi
fi

# ---------------------------------------------------------------------------
# 7. Generation is the sibling of the import bug — the same mis-read of
# CKA_UNWRAP is on C_GenerateKeyPair — so an image that can import RSA has still
# only proved half of it.
#
# RSA-2048 rather than 4096: the branch is not size-specific — it is reached for
# any CKK_RSA template — and generating 4096 bits on a YubiHSM 2 takes about a
# minute and a half against 2048's few seconds. Nothing is given up by using the
# cheap one, and a script that takes two minutes longer gets run less.
say "Generating an RSA key in the device from inside the container"
keep_log_space 12
gen=$(secsy secsy-ca -config /etc/secsy/config.yaml init-root \
	-label t201-c-gen-rsa -key-type rsa-2048 -validity-days 2 \
	-cn "t201 container generated root" 2>&1)
rc=$?
check "init-root generates an RSA CA key in the device" "$([[ $rc -eq 0 ]] && echo 0 || echo 1)"
if [[ $rc -ne 0 ]]; then
	sed 's/^/         /' <<<"$gen"
else
	gen_obj=$(yhs -a list-objects -l t201-c-gen-rsa 2>&1)
	check "the generated key is an asymmetric-key on the device, not a wrap-key" \
		"$([[ "$gen_obj" == *"type: asymmetric-key"* ]] && echo 0 || echo 1)"
	sed 's/^/         /' <<<"$gen_obj"
	gen_id=$(sed -n 's/.*id: 0x\([0-9a-f]*\).*/\1/p' <<<"$gen_obj" | head -1)
	[[ -n "$gen_id" ]] && CREATED_IDS+=("$gen_id")
fi
unset gen_id

# ---------------------------------------------------------------------------
# 8. The same import against a pre-2.7.2 module mounted over the image's, which
# is how a production deployment that supplies its own vendor stack would look.
# The claim is that the template adapts and the import still works — not that the
# old module is fine.
if [[ -n "$LEGACY_MODULE" ]]; then
	say "Repeating the import against the legacy module in $LEGACY_MODULE"
	[[ -f "$LEGACY_MODULE/yubihsm_pkcs11.so" ]] || die "$LEGACY_MODULE holds no yubihsm_pkcs11.so"
	[[ -d "$LEGACY_MODULE/lib" ]] || die "$LEGACY_MODULE holds no lib/ with libyubihsm.so.2"
	delete_created
	keep_log_space 20
	# Mounted over the symlink's target directory as well as the module itself, so
	# the module's RUNPATH finds the matching libyubihsm rather than the image's.
	MODULE_OVERLAY=(
		-v "$LEGACY_MODULE/yubihsm_pkcs11.so:/usr/local/lib/pkcs11/yubihsm_pkcs11.so:ro"
		-v "$LEGACY_MODULE/lib:/usr/local/lib/legacy-yubihsm:ro"
		-e "LD_LIBRARY_PATH=/usr/local/lib/legacy-yubihsm"
	)
	# Read the version the way the Go code does — out of C_GetInfo, not out of the
	# file — because that is the value the decision is actually made on. The
	# module reports minor as VERSION_MINOR*10 + VERSION_PATCH, so 2.6.0 prints
	# "ver 2.60"; anything below 2.72 is affected.
	legacy_version=$(docker run --rm "${MODULE_OVERLAY[@]}" \
		-e YUBIHSM_PKCS11_CONF=/tmp/legacy-yh.conf \
		--entrypoint sh "$IMAGE" -c '
			printf "connector = yhusb://\n" >/tmp/legacy-yh.conf
			pkcs11-tool --module /usr/local/lib/pkcs11/yubihsm_pkcs11.so --show-info 2>&1 |
				sed -n "s/^Library *//p"' )
	echo "    the mounted module reports: $legacy_version"
	legacy_minor=$(sed -n 's/.*ver 2\.\([0-9]*\)).*/\1/p' <<<"$legacy_version")
	check "the mounted module really is older than $MIN_MODULE_VERSION (so this pass proves something)" \
		"$([[ -n "$legacy_minor" && "$legacy_minor" -lt 72 ]] && echo 0 || echo 1)"
	import_one 2048 1
	import_one 4096 3
	MODULE_OVERLAY=()
fi

# ---------------------------------------------------------------------------
# 9. Where the device audit log is permanently written.
#
# On a force-audited device the log is not diagnostics: the HSM stops accepting
# audited commands once its 62-entry ring fills, and the entries are gone the
# moment they are acknowledged. Whatever the deployment keeps is the only
# record there will ever be — so a container has to be able to say where that
# copy goes, on a volume that outlives the container, without baking a host
# path into the image's config file.
#
# SECSY_YUBIHSM_AUDIT_LOG_FILE is that knob. The checks below are about the
# destination being honoured and the failure being loud, which is what a
# container deployment gets wrong: a path inside the writable layer, a
# read-only mount, or a volume owned by root while the image runs as 65532 —
# all three of which succeed at looking configured.
say "The permanent destination for the device audit log"

mkdir -p "$WORK/audit" "$WORK/audit-ro"
chmod -R a+rwX "$WORK/audit" "$WORK/audit-ro"
AUDIT_DEST=/app/audit/device-log.jsonl

# 9a. The CLI, against the real device. `hsm-audit status` reads the device and
# then reports the configured destination, so this says in one command that the
# override reached the binary in the image and that the device agrees it is the
# one being talked about.
keep_log_space 8
EXTRA_RUN_ARGS=(-v "$WORK/audit:/app/audit" -e "SECSY_YUBIHSM_AUDIT_LOG_FILE=$AUDIT_DEST")
status_out=$(secsy secsy-ca -config /etc/secsy/config.yaml hsm-audit status 2>&1)
EXTRA_RUN_ARGS=()
sed 's/^/         /' <<<"$status_out"
check "hsm-audit status reaches the device from inside the container" \
	"$(grep -q "Device: *$serial" <<<"$status_out" && echo 0 || echo 1)"
check "the destination from SECSY_YUBIHSM_AUDIT_LOG_FILE is the one reported" \
	"$(grep -q "Log file: *$AUDIT_DEST" <<<"$status_out" && echo 0 || echo 1)"

# What the device says about force-audit, recorded rather than asserted: this
# script must run against whatever device is attached, and a commissioned one
# is not something a test may create (provisioning is irreversible and requires
# a factory-reset device).
dev_opts=$(yhs -a get-option --opt-name force-audit 2>&1 | tr -d '\r')
forced=$(sed -n 's/^Option value is: *//p' <<<"$dev_opts" | tail -1)
echo "    device force-audit option: ${forced:-unknown}; collection is gated on provisioning"
provisioned=1
grep -q '^Provisioned: *yes' <<<"$status_out" && provisioned=0

# 9b. The drain itself. On a commissioned device this appends the device's own
# records to the file; on one that was never provisioned it must refuse and say
# why, rather than silently writing nothing — the failure mode that leaves an
# operator believing their audit log is being kept.
keep_log_space 8
EXTRA_RUN_ARGS=(-v "$WORK/audit:/app/audit" -e "SECSY_YUBIHSM_AUDIT_LOG_FILE=$AUDIT_DEST")
collect_out=$(secsy secsy-ca -config /etc/secsy/config.yaml hsm-audit collect 2>&1)
collect_rc=$?
EXTRA_RUN_ARGS=()
sed 's/^/         /' <<<"$collect_out"
if [[ $provisioned -eq 0 ]]; then
	check "hsm-audit collect drains the device into the configured file" \
		"$([[ $collect_rc -eq 0 ]] && echo 0 || echo 1)"
	check "the configured file received device log records" \
		"$(grep -q '"type":"entry"' "$WORK/audit/device-log.jsonl" 2>/dev/null && echo 0 || echo 1)"
else
	check "an uncommissioned device is refused with the reason, not silently skipped" \
		"$([[ $collect_rc -ne 0 ]] && grep -q 'has not been provisioned' <<<"$collect_out" && echo 0 || echo 1)"
fi
# Either way the destination itself must exist and be verifiable: the header
# record is written when the file is opened, which is how an operator finds out
# the path is wrong before there is anything to lose.
check "the configured destination was created on the mounted volume" \
	"$([[ -s "$WORK/audit/device-log.jsonl" ]] && echo 0 || echo 1)"
# verify-file is dispatched before any config or database is opened — it is the
# auditor's command — so it needs the volume and nothing else.
EXTRA_RUN_ARGS=(-v "$WORK/audit:/app/audit")
verify_out=$(secsy secsy-ca hsm-audit verify-file -file "$AUDIT_DEST" 2>&1)
EXTRA_RUN_ARGS=()
check "the file verifies offline, with no database and no device" \
	"$(grep -q 'Verdict: *OK' <<<"$verify_out" && echo 0 || echo 1)"
sed 's/^/         /' <<<"$verify_out"

# 9c. The server, which is what actually runs in a deployment. A software key
# provider and no yubihsm block: this tier is about the destination, and
# pointing a second process at the device while the checks above hold it would
# test the USB interface instead.
cat >"$WORK/config-audit.yaml" <<EOF
server:
  host: "127.0.0.1"
  port: 8443
database:
  driver: "sqlite"
  dsn: "/app/data/audit-dest.db"
root_user:
  username: "root"
  password: "container-test-not-a-deployment"
key_provider:
  type: "software"
software_keystore:
  directory: "/app/data/keystore"
EOF
chmod a+r "$WORK/config-audit.yaml"

docker rm -f secsy-t203-audit >/dev/null 2>&1
server_log=$(docker run --rm \
	-v "$WORK/config-audit.yaml:/etc/secsy/config.yaml:ro" \
	-v "$WORK/data:/app/data" \
	-v "$WORK/audit:/app/audit" \
	-e SECSY_ALLOW_INSECURE_HTTP=1 \
	-e "SECSY_YUBIHSM_AUDIT_LOG_FILE=/app/audit/server-log.jsonl" \
	--name secsy-t203-audit -d "$IMAGE" -config /etc/secsy/config.yaml 2>&1)
if [[ $? -eq 0 ]]; then
	# The destination is opened before anything else in startup, so a second is
	# plenty; the loop is for a slow host rather than for a slow code path.
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		[[ -s "$WORK/audit/server-log.jsonl" ]] && break
		sleep 1
	done
	logs=$(docker logs secsy-t203-audit 2>&1)
	docker rm -f secsy-t203-audit >/dev/null 2>&1
	check "the server creates the destination named by the environment, on the volume" \
		"$([[ -s "$WORK/audit/server-log.jsonl" ]] && echo 0 || echo 1)"
	check "and says where it is, at startup" \
		"$(grep -q 'audit log file /app/audit/server-log.jsonl open for append' <<<"$logs" && echo 0 || echo 1)"
	grep -i 'audit log file' <<<"$logs" | sed 's/^/         /'
else
	check "the server starts with an audit destination configured" 1
	sed 's/^/         /' <<<"$server_log"
fi

# 9d. And the case that matters most, because it is the one that otherwise
# fails silently: a destination that cannot be written. The server must refuse
# to start and name the path, rather than come up looking healthy while the
# record it was told to keep goes nowhere.
ro_out=$(docker run --rm \
	-v "$WORK/config-audit.yaml:/etc/secsy/config.yaml:ro" \
	-v "$WORK/data:/app/data" \
	-v "$WORK/audit-ro:/audit-ro:ro" \
	-e SECSY_ALLOW_INSECURE_HTTP=1 \
	-e "SECSY_YUBIHSM_AUDIT_LOG_FILE=/audit-ro/device-log.jsonl" \
	"$IMAGE" -config /etc/secsy/config.yaml 2>&1)
ro_rc=$?
check "an unwritable destination stops the server instead of being ignored" \
	"$([[ $ro_rc -ne 0 ]] && echo 0 || echo 1)"
check "and the refusal names the path and the setting" \
	"$(grep -q 'audit_log_file is set to /audit-ro/device-log.jsonl' <<<"$ro_out" && echo 0 || echo 1)"
sed 's/^/         /' <<<"$(tail -2 <<<"$ro_out")"

# ---------------------------------------------------------------------------
# 10. One container, both routes to the device (Task 204).
#
# The checks above all run one process at a time, which is the easy case. A
# deployment is not: the server signs through Yubico's PKCS#11 module and the
# same deployment has to read the device audit log through the native driver,
# because PKCS#11 cannot express GET LOG ENTRIES. The kernel grants the
# YubiHSM's USB interface to one claim, the module takes it for the life of its
# session pool, and so that deployment used to need a second container — Yubico's
# yubihsm-connector — with the device node handed to it.
#
# It no longer does: the server claims the device itself and serves the connector
# protocol on loopback inside its own process. These checks are the evidence,
# against the real device, from the published image:
#
#   a. the server starts in that configuration and says it is multiplexing;
#   b. the relay reports the attached device, by serial, over its own endpoint;
#   a-. before any of that, a one-off CLI container with no server to borrow a
#      relay from — the first command this deployment's README asks for;
#   c. the server holds the USB claim for its whole life — Yubico's own shell,
#      pointed straight at the device from the same container, is refused;
#   d. and every other client reaches the device anyway, through the relay: the
#      vendor shell, the vendor PKCS#11 module under pkcs11-tool, and
#      secsy-pki's native driver attesting the device. Three independent
#      clients, one USB claim, one container.
#
# (c) is what makes (d) a property of the relay rather than of a device that
# happened to be free.
say "One container serving both routes to the device"

cat >"$WORK/config-single.yaml" <<EOF
server:
  host: "127.0.0.1"
  port: 8443
database:
  driver: "sqlite"
  dsn: "/app/data/single.db"
root_user:
  username: "root"
  password: "container-test-not-a-deployment"
key_provider:
  type: "pkcs11"
pkcs11:
  module_path: "/usr/lib/pkcs11/yubihsm_pkcs11.so"
  token_label: "YubiHSM"
  pin: "$(printf '%04x' "$AUTH_KEY_ID")$PASSWORD"
  session_pool_size: 1
yubihsm:
  # The address the server serves and every route uses, including the
  # docker-exec calls below. (No backticks in this heredoc: it is unquoted, so
  # the shell would run what they enclose.) The embedded connector is on by
  # default for this configuration; the environment sets it explicitly per
  # deployment.
  connector_url: "http://127.0.0.1:12345"
  auth_key_id: $AUTH_KEY_ID
  password: "$PASSWORD"
EOF
chmod a+r "$WORK/config-single.yaml"
mkdir -p "$WORK/data-single"
chmod -R a+rwX "$WORK/data-single"

# single_server <embedded> starts the server in one container and waits for the
# key provider to be open. It prints the container name, or nothing if
# `docker run` itself failed.
single_server() { # single_server <0|1>
	local embedded="$1" name="secsy-t204-single" i
	docker rm -f "$name" >/dev/null 2>&1
	docker run -d --name "$name" "${DOCKER_DEV[@]}" \
		-v "$WORK/config-single.yaml:/etc/secsy/config.yaml:ro" \
		-v "$WORK/data-single:/app/data" \
		-v "$WORK/audit:/app/audit" \
		-e SECSY_ALLOW_INSECURE_HTTP=1 \
		-e "SECSY_YUBIHSM_EMBEDDED_CONNECTOR=$embedded" \
		-e "SECSY_YUBIHSM_AUDIT_LOG_FILE=/app/audit/single-log.jsonl" \
		"$IMAGE" -config /etc/secsy/config.yaml >/dev/null 2>&1 || return 1
	for i in $(seq 1 40); do
		if docker logs "$name" 2>&1 | grep -q 'Key provider (ca role)'; then
			echo "$name"
			return 0
		fi
		docker ps -q -f "name=$name" | grep -q . || break
		sleep 1
	done
	echo "$name"
	return 0
}

# 10a. Before any server exists: a one-off CLI container.
#
# This is the first command deploy/yubihsm/README.md tells an operator to run,
# and the one case where nothing else has already claimed the device. It reaches
# the hardware through the native driver with no key provider anywhere, so
# nothing will have started a relay on its behalf — and the configured connector
# URL names an address inside *this* container. A CLI that cannot multiplex for
# itself therefore fails against its own loopback while every signing command
# works, which is a poor way to find out on the first command of a deployment.
keep_log_space 10
cli_attest=$(docker run --rm "${DOCKER_DEV[@]}" \
	-v "$WORK/config-single.yaml:/etc/secsy/config.yaml:ro" \
	-v "$WORK/data-single:/app/data" \
	-v "$WORK/audit:/app/audit" \
	-e "SECSY_YUBIHSM_AUDIT_LOG_FILE=/app/audit/single-log.jsonl" \
	--entrypoint secsy-ca "$IMAGE" -config /etc/secsy/config.yaml hsm-attest device 2>&1)
check "a one-off secsy-ca container multiplexes the device for itself, with no server to borrow from" \
	"$(grep -q "verified: this is YubiHSM serial $serial" <<<"$cli_attest" && echo 0 || echo 1)"
check "and says so, so the claim is the CLI's own rather than something it found running" \
	"$(grep -q 'Embedded YubiHSM connector serving' <<<"$cli_attest" && echo 0 || echo 1)"
check "and the drain on the way out reached the device too, rather than reporting entries left behind" \
	"$(grep -q 'device log not collected' <<<"$cli_attest" && echo 1 || echo 0)"
grep -E 'Embedded YubiHSM connector serving|^verified:|not collected' <<<"$cli_attest" |
	cut -c1-160 | sed 's/^/         /'

keep_log_space 12
container=$(single_server 1)
[[ -n "$container" ]] || die "the single-container server did not start"
start_log=$(docker logs "$container" 2>&1)
check "the server starts with the device on direct USB and a PKCS#11 signing path" \
	"$(grep -q 'Key provider (ca role)' <<<"$start_log" && echo 0 || echo 1)"
check "and says it is multiplexing the device in its own process" \
	"$(grep -q 'Embedded YubiHSM connector serving' <<<"$start_log" && echo 0 || echo 1)"
grep -E 'Embedded YubiHSM connector|PKCS#11 module pointed at|Key provider \(ca role\)' <<<"$start_log" |
	sed 's/^/         /'

# 10b. The relay's own endpoint, read from inside the container with bash's
# /dev/tcp — there is no curl or wget in the image. This is the document
# Yubico's module gates on, and the serial in it has to be the attached
# device's: a relay that could not name its device would make the one
# identifying field in its status document worthless.
relay_status=$(docker exec "$container" bash -c '
	exec 3<>/dev/tcp/127.0.0.1/12345 &&
	printf "GET /connector/status HTTP/1.0\r\n\r\n" >&3 &&
	cat <&3' 2>&1)
sed -n 's/^\(status=\|serial=\|implementation=\)/         \1/p' <<<"$relay_status"
check "the relay inside the container reports a device" \
	"$(grep -q 'status=OK' <<<"$relay_status" && echo 0 || echo 1)"
check "and it is the attached device, by serial" \
	"$(grep -q "serial=$serial" <<<"$relay_status" && echo 0 || echo 1)"

# 10c. The control, and the sharpest check here: the server holds the USB claim
# for its whole life, not merely while it is signing. Yubico's own shell, in the
# same container, pointed straight at the device, must be refused.
#
# Without this the checks that follow would pass just as well on a device that
# happened to be free, and the relay would be carrying no weight.
usb_direct=$(docker exec "$container" yubihsm-shell \
	--connector yhusb:// --authkey "$AUTH_KEY_ID" -p "$PASSWORD" -a get-device-info 2>&1)
check "the server holds the USB interface, so nothing else in the container can claim it" \
	"$(grep -qE "Failed connecting|Connector operation failed|Not connected" <<<"$usb_direct" && echo 0 || echo 1)"
sed 's/^/         /' <<<"$(head -2 <<<"$usb_direct")"

# 10d. And through the relay the same device is reachable — by the vendor shell,
# by the vendor PKCS#11 module under a third-party tool, and by secsy-pki's own
# native driver. Three independent clients, one USB claim, one container.
via_relay=$(docker exec "$container" yubihsm-shell \
	--connector http://127.0.0.1:12345 --authkey "$AUTH_KEY_ID" -p "$PASSWORD" -a get-device-info 2>&1)
check "but the vendor shell reaches it through the relay" \
	"$(grep -q "Serial number:[[:space:]]*$serial" <<<"$via_relay" && echo 0 || echo 1)"
sed -n 's/^\(Version number:\|Serial number:\|Log used:\)/         \1/p' <<<"$via_relay"

# The module reads its connector from the file the server wrote at startup,
# which is the same mechanism the server's own signing path uses — so this also
# confirms that file names the relay rather than the USB device.
module_conf=$(docker exec "$container" cat /app/yubihsm_pkcs11.conf 2>&1)
check "the server pointed the PKCS#11 module at the relay, in a file the module reads" \
	"$(grep -q 'connector = http://127.0.0.1:12345' <<<"$module_conf" && echo 0 || echo 1)"
pkcs11_out=$(docker exec -e YUBIHSM_PKCS11_CONF=/app/yubihsm_pkcs11.conf "$container" \
	pkcs11-tool --module /usr/lib/pkcs11/yubihsm_pkcs11.so -p "$(printf '%04x' "$AUTH_KEY_ID")$PASSWORD" \
	--list-objects 2>&1)
check "and Yubico's module opens the token through it, from a second process" \
	"$(grep -q 'present token' <<<"$pkcs11_out" && echo 0 || echo 1)"
sed 's/^/         /' <<<"$(head -2 <<<"$pkcs11_out")"

# secsy-pki's native driver is the route the audit drain and the attestation
# paths take. `hsm-attest device` is the sharpest probe available on an
# uncommissioned device: it generates and deletes a throwaway key in a reserved
# slot and verifies the device's answer against Yubico's published CA, so it
# exercises the signing hardware rather than a status endpoint.
attest_out=$(docker exec "$container" secsy-ca -config /etc/secsy/config.yaml hsm-attest device 2>&1)
check "and secsy-pki's own driver attests the device while the server holds it" \
	"$(grep -q "verified: this is YubiHSM serial $serial" <<<"$attest_out" && echo 0 || echo 1)"
check "with the device answering a fresh challenge from its attestation key" \
	"$(grep -q 'Answered challenge: *yes' <<<"$attest_out" && echo 0 || echo 1)"
grep -E '^(Device serial|Yubico-certified|Answered challenge):|^verified:' <<<"$attest_out" |
	sed 's/^/         /'
docker rm -f "$container" >/dev/null 2>&1

# `docker rm -f` returns as soon as the process is signalled, and the kernel
# releases the USB claim a moment later. Wait for it: the cleanup below talks to
# the device, and a delete that lands in that window fails silently with EBUSY
# and leaves objects behind — which then looks like a cleanup bug rather than a
# race.
wait_for_device() {
	local i
	for i in 1 2 3 4 5 6 7 8 9 10; do
		yhs -a get-device-info >/dev/null 2>&1 && return 0
		sleep 1
	done
	return 1
}
check "the device is free again once the single container is gone" \
	"$(wait_for_device && echo 0 || echo 1)"

# ---------------------------------------------------------------------------
say "Cleaning up the objects this run created"
delete_created
left=$(yhs -a list-objects 2>&1 | grep -c -e 't201-c-' -e 't203-c-' -e 't204-c-' || true)
check "no t201-c-/t203-c-/t204-c- objects remain on the device" "$([[ "$left" == "0" ]] && echo 0 || echo 1)"
yhs -a get-device-info 2>&1 | sed -n 's/^\(Log used:.*\)/    \1/p'

say "Result"
printf '    %d passed, %d failed\n' "$pass" "$fail"
if [[ $fail -eq 0 ]]; then
	printf '\033[32m==> PASS\033[0m — %s imports an externally generated RSA key into YubiHSM %s,\n' "$IMAGE" "$serial"
	printf '            writes the device audit log where it is told to, and serves both routes to\n'
	printf '            the device from one container with no connector daemon beside it.\n'
	exit 0
fi
printf '\033[31m==> FAIL\033[0m\n'
exit 1
