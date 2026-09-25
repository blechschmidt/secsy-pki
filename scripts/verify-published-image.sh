#!/usr/bin/env bash
#
# verify-published-image.sh — check a published image the way a stranger sees it.
#
# The job that pushes an image can prove almost nothing about it. It holds a
# registry credential and a local copy of every layer it just built, so "docker
# pull worked" there says nothing about whether it works anywhere else:
#
#   * GHCR creates a package **private** on its first push, and no workflow flips
#     that. A logged-in runner cannot tell a private package from a public one,
#     so the failure is silent — green pipeline, `denied` on every other machine
#     on earth, and the documented `docker pull ghcr.io/…` quietly false.
#   * The tag. The publishing job verifies `@sha256:…`; a reader types `:1.2.3`.
#   * A cold pull: nothing in the pushing job has to fetch a single layer.
#
# So this runs with no credentials, pulls by tag, and then makes the image do
# the thing it exists for: initialize a SoftHSM token and mint an HSM-backed
# root CA through the PKCS#11 path, as the image's own non-root user. An image
# that starts but cannot reach a PKCS#11 module is an image that cannot issue a
# certificate, and `-version` alone would never notice.
#
# Usage:
#   verify-published-image.sh --image ghcr.io/owner/secsy-pki:1.2.3
#                             [--expect-version 1.2.3] [--allow-login]
#                             [--platforms linux/amd64,linux/arm64] [--local]
#                             [--expect-yubihsm]
#
#   --expect-version  require the binaries to report exactly this version.
#                     Defaults to the tag when the tag looks like a version.
#   --platforms       require the published index to carry these platforms.
#                     Empty to skip (a locally built single-arch image).
#   --allow-login     permit a registry credential to be present. Off by
#                     default: the anonymous pull is the point of this script.
#   --local           the image is already in the daemon and is not in a
#                     registry at all. Skips the credential check, the pull and
#                     the index check; everything the image is actually made to
#                     do — checks 3 to 6 — still runs. This is how the build
#                     job of container.yaml exercises an image it has just
#                     loaded, before any of it is pushed: the same checks that
#                     would otherwise find a break after the publish, run
#                     before it.
#   --expect-yubihsm  this is the `-yubihsm` variant: require Yubico's PKCS#11
#                     module to be present *and to load*. Without the flag the
#                     same check runs inverted — the module must be absent —
#                     because two tags that promise different things and ship
#                     the same bytes is a defect in whichever one is lying.
#
# Runs identically on a laptop and in the verify job of
# .github/workflows/container.yaml.
set -euo pipefail

IMAGE=""
EXPECT_VERSION=""
PLATFORMS="linux/amd64,linux/arm64"
ALLOW_LOGIN=0
LOCAL=0
EXPECT_YUBIHSM=0

# The image's own defaults, asserted rather than assumed: the Dockerfile's
# non-root account and the SoftHSM module Debian installs into the runtime.
EXPECT_UID=65532
SOFTHSM_MODULE=/usr/lib/softhsm/libsofthsm2.so

# Where the `-yubihsm` stage symlinks its source-built module. Checking the
# symlink rather than /usr/local/lib/pkcs11/… behind it is deliberate: this is
# the path the documentation, the example configs and the Helm values all tell
# operators to put in pkcs11.module_path, so it is the one whose breakage they
# would notice.
YUBIHSM_MODULE=/usr/lib/pkcs11/yubihsm_pkcs11.so

# The six commands the Dockerfile installs, each with the cheapest invocation
# that makes it start, and how it reports a version — which is not uniform, so
# it is written down rather than guessed:
#
#   -version   a flag, and the process exits 0 having printed the version
#   version    a subcommand, likewise
#   -          no version interface at all. Three of the six have none, and
#              inventing one here is not this script's job; what it can still
#              prove is that the binary *starts*, which is the failure this
#              check exists for — a cross-compiled cgo binary whose C half did
#              not link resolves nothing and dies in the loader before main().
#              So they are run anyway, and the test is that the usage text they
#              print is their own.
#
# "<binary>|<version-style>|<args…>"
BINARIES=(
	"secsy-pki-server|-version|-version"
	"secsy-ca|version|version"
	"secsy-agent|version|version"
	"secsy-secret|-|"
	"secsy-ssh|-|"
	"secsy-verify|-|"
)

FAILURES=0

note() { printf '  %s\n' "$*"; }
ok() { printf '  ok    %s\n' "$*"; }
bad() {
	FAILURES=$((FAILURES + 1))
	printf '  FAIL  %s\n' "$*"
	[ -n "${GITHUB_ACTIONS:-}" ] && echo "::error::$*" >&2
	return 0
}
die() {
	echo "verify-published-image: error: $*" >&2
	exit 2
}

while [ $# -gt 0 ]; do
	case "$1" in
	--image)
		IMAGE="${2:-}"
		shift 2
		;;
	--expect-version)
		EXPECT_VERSION="${2:-}"
		shift 2
		;;
	--platforms)
		PLATFORMS="${2:-}"
		shift 2
		;;
	--allow-login)
		ALLOW_LOGIN=1
		shift
		;;
	--local)
		LOCAL=1
		shift
		;;
	--expect-yubihsm)
		EXPECT_YUBIHSM=1
		shift
		;;
	-h | --help)
		sed -n '2,49p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*) die "unknown argument: $1" ;;
	esac
done

[ -n "$IMAGE" ] || die "--image is required"
command -v docker >/dev/null 2>&1 || die "docker is required"

# A tag that looks like a version is one, unless told otherwise.
if [ -z "$EXPECT_VERSION" ]; then
	candidate="${IMAGE##*:}"
	[[ "$candidate" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] && EXPECT_VERSION="$candidate"
fi

echo "verifying ${IMAGE}"
[ -n "$EXPECT_VERSION" ] && note "expecting version ${EXPECT_VERSION}"

# --- 1. No credentials ------------------------------------------------------
# --- 2. A cold, anonymous pull ----------------------------------------------
#
# Both are about the registry, and under --local there is no registry: the image
# is in the daemon because this machine built it. Skipping them is not a weaker
# check of the same thing, it is the absence of a thing to check — and running
# check 2 anyway would be actively wrong, because it removes the image before
# pulling it and the pull of a local-only tag cannot succeed.
if [ "$LOCAL" -eq 1 ]; then
	docker image inspect "$IMAGE" >/dev/null 2>&1 ||
		die "--local was given but ${IMAGE} is not in the local daemon; build or load it first"
	ok "using the locally built ${IMAGE} (no registry involved)"
else
	registry="${IMAGE%%/*}"
	config="${DOCKER_CONFIG:-$HOME/.docker}/config.json"
	if [ "$ALLOW_LOGIN" -eq 0 ] && [ -f "$config" ] && grep -qF "\"${registry}\"" "$config"; then
		die "a credential for ${registry} is present in ${config}; run 'docker logout ${registry}' — an authenticated pull cannot prove the package is public"
	fi
	ok "no registry credential in play"

	docker rmi "$IMAGE" >/dev/null 2>&1 || true
	if docker pull --quiet "$IMAGE" >/dev/null; then
		ok "pulled anonymously"
	else
		bad "cannot pull ${IMAGE} without credentials — is the GHCR package still private?"
		echo
		echo "verify-published-image: ${FAILURES} check(s) failed"
		exit 1
	fi
fi

# --- 3. The entrypoint is the server, and it reports the released version ----
reported="$(docker run --rm "$IMAGE" -version 2>&1 | head -n 1)" ||
	bad "the entrypoint does not run: ${reported}"
note "$reported"
case "$reported" in
secsy-pki-server\ *) ok "the entrypoint is the server" ;;
*) bad "expected the entrypoint to be secsy-pki-server, got: ${reported}" ;;
esac
if [ -n "$EXPECT_VERSION" ] && [ "${reported#secsy-pki-server "${EXPECT_VERSION}" }" = "$reported" ]; then
	bad "the image reports '${reported}', expected version ${EXPECT_VERSION}"
fi

# --- 4. Every command the image claims to ship ------------------------------
for entry in "${BINARIES[@]}"; do
	IFS='|' read -r binary style args <<<"$entry"
	read -r -a argv <<<"$args"

	if [ "$style" = "-" ]; then
		# No version interface. Run it bare and require it to have got far
		# enough to print its own usage; the exit status is meaningless here,
		# because "no command given" is a perfectly healthy binary refusing to
		# guess. What must not appear is the loader failing to start it at all.
		out="$(docker run --rm --entrypoint "$binary" "$IMAGE" 2>&1 | head -n 3 || true)"
		case "$out" in
		*"exec format error"* | *"error while loading shared libraries"* | *"cannot execute"*)
			bad "${binary} does not start: ${out}"
			continue
			;;
		esac
		if [[ "$out" == *"$binary"* ]]; then
			ok "${binary}: starts (no version interface)"
		else
			bad "${binary} is missing or printed something else entirely: ${out}"
		fi
		continue
	fi

	if out="$(docker run --rm --entrypoint "$binary" "$IMAGE" "${argv[@]}" 2>&1 | head -n 1)"; then
		if [ -n "$EXPECT_VERSION" ] && [[ "$out" != *"$EXPECT_VERSION"* ]]; then
			bad "${binary} reports '${out}', expected version ${EXPECT_VERSION}"
		else
			ok "${binary}: ${out}"
		fi
	else
		bad "${binary} is missing or does not run: ${out}"
	fi
done

# --- 5. It runs as the non-root account it declares --------------------------
uid="$(docker run --rm --entrypoint id "$IMAGE" -u 2>/dev/null || echo "?")"
if [ "$uid" = "$EXPECT_UID" ]; then
	ok "runs as uid ${uid} (non-root)"
else
	bad "runs as uid ${uid}, expected ${EXPECT_UID}"
fi

# --- 6. It can actually issue from an HSM ------------------------------------
#
# The whole product in one command: provision a PKCS#11 token, generate a CA key
# *on* it and self-sign a root certificate with it. Run as the image's own user,
# with only the paths the image prepares for it — which is also a check that
# those paths are writable by that user, something no `--version` would catch.
echo "  running an HSM-backed root-CA ceremony inside the image"
ceremony=$(
	cat <<'INNER'
set -euo pipefail
softhsm2-util --init-token --free --label verify --pin 1234 --so-pin 0002 >/dev/null
cat >/app/verify-config.yaml <<'YAML'
database:
  driver: "sqlite"
  dsn: "/app/data/verify.db"
root_user:
  username: "root"
  password: "verification-only"
key_provider:
  type: "pkcs11"
pkcs11:
  module_path: "SOFTHSM_MODULE"
  pin: "1234"
  token_label: "verify"
YAML
secsy-ca -config /app/verify-config.yaml init-root \
  -label verify-root -cn "Published Image Verification Root" -key-type ecdsa-p256
secsy-ca -config /app/verify-config.yaml list
INNER
)
ceremony="${ceremony//SOFTHSM_MODULE/$SOFTHSM_MODULE}"
if out="$(docker run --rm --entrypoint bash "$IMAGE" -c "$ceremony" 2>&1)"; then
	printf '%s\n' "$out" | sed 's/^/        /'
	ok "generated an HSM-backed root CA through PKCS#11"
else
	printf '%s\n' "$out" | sed 's/^/        /'
	bad "the image cannot mint a root CA against its bundled PKCS#11 module"
fi

# --- 7. The -yubihsm variant carries what its tag promises --------------------
#
# Present *and loadable*. "The .so is in the image" is the check that passes
# while the image is broken: the module is dynamically linked against
# libyubihsm, which in turn dlopens a per-transport backend, so a transport that
# did not get built or did not get copied leaves a module that loads and can
# reach a yubihsm-connector but not a device on the USB bus — which is how
# nearly everyone attaches one.
#
# So the module is put through pkcs11-tool, which dlopens it, resolves
# C_GetFunctionList and calls C_Initialize/C_GetInfo. No YubiHSM is attached to
# a CI runner, and none is needed: initialization is what loads the backend, and
# the failure this is looking for happens there rather than at the device.
#
# And it is the *right* module: the Dockerfile builds yubihsm-shell from
# upstream's signed release and records the version it built in the image, so
# C_GetInfo's answer can be held against it. That is what distinguishes the
# source build from a silent fall back to Debian's package, which is two minor
# versions behind and would otherwise pass every other check here.
if [ "$EXPECT_YUBIHSM" -eq 1 ]; then
	echo "  checking the bundled YubiHSM PKCS#11 module"
	probe=$(
		cat <<'INNER'
set -euo pipefail

module="$(readlink -f MODULE)"
echo "module:      ${module}"

# The upstream release the image was built from, as recorded by the build stage.
upstream="$(cat /usr/share/secsy-pki/yubihsm-shell-version)"
echo "upstream:    yubihsm-shell ${upstream}"

# The module is built for the architecture of the image it is in. Read off the
# ELF header rather than the path, which no longer encodes the architecture now
# that the module is installed under /usr/local instead of a multiarch
# directory: e_machine is 2 bytes little-endian at offset 18, and the values
# below are the two platforms published. A wrong-arch module would also fail to
# load below, but it fails here with a legible reason.
machine="$(od -An -tx1 -j18 -N2 "$module" | tr -d ' \n')"
case "$(uname -m):${machine}" in
x86_64:3e00 | aarch64:b700) echo "machine:     ${machine} matches $(uname -m)" ;;
*) echo "module e_machine ${machine} is not $(uname -m)" >&2; exit 1 ;;
esac

# Every NEEDED library resolved, for the module and for each library out of the
# same source tree. This is the failure that a cross-built or mismatched-base
# image produces, and it is silent until the first signature: the module is a
# perfectly good file that the loader will not load.
for so in "$module" \
    /usr/local/lib/libyubihsm.so.2 \
    /usr/local/lib/libyubihsm_usb.so.2 \
    /usr/local/lib/libyubihsm_http.so.2 \
    /usr/local/lib/libykhsmauth.so.2; do
    if [ ! -f "$so" ]; then
        echo "missing: $so" >&2
        exit 1
    fi
    echo "linkage:     $(basename "$so") ok"
    if ldd "$so" | grep -F 'not found'; then
        echo "unresolved shared libraries in $so" >&2
        exit 1
    fi
done

# C_Initialize refuses a NULL argument list unless it can read a connector from
# YUBIHSM_PKCS11_CONF, so it is given one — the same file the server writes for
# itself from yubihsm.connector_url. yhusb:// is the deployment this variant
# exists for, and no HSM is needed to exercise it: initializing is what loads
# the transport backend and makes the module state its identity.
conf="$(mktemp)"
printf 'connector = yhusb://\n' >"$conf"
export YUBIHSM_PKCS11_CONF="$conf"

# The exit status is 1 on a machine with no YubiHSM attached — "No slot with a
# token was found", which is the correct answer here and not the thing being
# checked. What is being read is C_GetInfo's reply.
info="$(pkcs11-tool --module "$module" --show-info 2>&1 || true)"
printf '%s\n' "$info"

# C_GetInfo reports CK_VERSION, which has no room for a patch level, so the
# module packs one in: minor becomes minor*10 + patch (2.8.0 -> "2.80"). Both
# numbers are printed on their own lines for the caller to compare, rather than
# grepped for here: an expected-value line and the output it is checked against
# in one blob of text is a comparison that passes against itself.
IFS=. read -r up_major up_minor up_patch <<<"${upstream}"
echo "want-ckver:  ${up_major}.$((up_minor * 10 + up_patch))"
echo "got-ckver:   $(printf '%s\n' "$info" | sed -n 's/^Library  *YubiHSM PKCS#11 Library (ver \(.*\))$/\1/p')"

echo "got-shell:   $(yubihsm-shell --version | sed -n 's/^yubihsm-shell //p')"
echo "yubihsm-connector $(yubihsm-connector version)"
test -f /usr/share/secsy-pki/udev/70-yubihsm.rules
echo "udev rule:   shipped for the host to install"
INNER
	)
	probe="${probe//MODULE/$YUBIHSM_MODULE}"
	if out="$(docker run --rm --entrypoint bash "$IMAGE" -c "$probe" 2>&1)"; then
		printf '%s\n' "$out" | sed 's/^/        /'
		field() { printf '%s\n' "$out" | sed -n "s/^$1: *//p"; }
		# C_GetInfo answers with the module's own identity, so a module that
		# loaded but is the wrong one — SoftHSM reached through a stale symlink,
		# say — cannot pass as this one.
		case "$out" in
		*"YubiHSM PKCS#11 Library"*) ok "Yubico's PKCS#11 module loads and initializes" ;;
		*) bad "${YUBIHSM_MODULE} did not identify itself as the YubiHSM PKCS#11 library" ;;
		esac
		# The Cryptoki version the loaded module reports, against the one the
		# recorded upstream release implies. This is the check that a Debian
		# package or a stale layer has not displaced the source build.
		want_ckver="$(field want-ckver)"
		got_ckver="$(field got-ckver)"
		if [ -z "$want_ckver" ] || [ -z "$got_ckver" ]; then
			bad "the probe did not report both module versions (want='${want_ckver}' got='${got_ckver}')"
		elif [ "$want_ckver" = "$got_ckver" ]; then
			ok "the module is the recorded upstream build (ver ${got_ckver})"
		else
			bad "the module reports ver ${got_ckver}, not the ${want_ckver} the image was built from"
		fi
		# The vendor tools come out of the same source tree as the module, so a
		# version skew between them means one of the two was not replaced.
		upstream="$(field upstream | sed 's/^yubihsm-shell //')"
		if [ -n "$upstream" ] && [ "$(field got-shell)" = "$upstream" ]; then
			ok "yubihsm-shell is the same ${upstream} build as the module"
		else
			bad "yubihsm-shell reports '$(field got-shell)', not the recorded ${upstream:-version}"
		fi
		# Named separately because the module dlopens its transports by SONAME:
		# without the USB one it reaches a yubihsm-connector and never a device
		# on the USB bus.
		case "$out" in
		*libyubihsm_usb*) ok "the direct-USB backend is installed" ;;
		*) bad "libyubihsm_usb is missing — the module could reach a connector but never a device on the USB bus" ;;
		esac
		# The label exists because the image SBOM is catalogued from dpkg and a
		# source build has no dpkg entry, so this is the only place a scanner
		# learns what vendor code is in here. Checked against the build's own
		# record, because a label nobody compares is a label that goes stale.
		label="$(docker image inspect --format \
			'{{index .Config.Labels "io.secsy-pki.yubihsm-shell.version"}}' "$IMAGE" 2>/dev/null || true)"
		if [ -n "$upstream" ] && [ "$label" = "$upstream" ]; then
			ok "the io.secsy-pki.yubihsm-shell.version label says ${label}"
		else
			bad "the io.secsy-pki.yubihsm-shell.version label says '${label}', not ${upstream:-the recorded version}"
		fi
	else
		printf '%s\n' "$out" | sed 's/^/        /'
		bad "the -yubihsm variant cannot load ${YUBIHSM_MODULE}"
	fi
else
	# The inverse, and not a formality. The two tags exist to be different; a
	# default image that quietly grew the vendor module would make the variant
	# pointless and its extra ~4 MB a surprise to everyone pulling the default.
	if docker run --rm --entrypoint test "$IMAGE" -e "$YUBIHSM_MODULE" 2>/dev/null; then
		bad "the default image ships ${YUBIHSM_MODULE}; that belongs only in the -yubihsm variant"
	else
		ok "no vendor PKCS#11 module in the default image"
	fi
fi

# --- 8. The index carries the architectures the tag claims -------------------
#
# An amd64 machine pulls and runs a multi-arch index perfectly happily while the
# arm64 entry is missing, because it never looks at that entry. So the index is
# read directly.
if [ "$LOCAL" -eq 1 ]; then
	note "local image; skipping the published-index check"
elif [ -n "$PLATFORMS" ]; then
	if raw="$(docker buildx imagetools inspect --raw "$IMAGE" 2>/dev/null)"; then
		missing=""
		found="$(printf '%s' "$raw" | python3 -c '
import json, sys

index = json.load(sys.stdin)
names = []
for entry in index.get("manifests", []):
    platform = entry.get("platform") or {}
    # The provenance and SBOM attestations ride in the same index with no real
    # platform of their own. They are not architectures.
    if platform.get("architecture") in (None, "unknown"):
        continue
    names.append(f'"'"'{platform["os"]}/{platform["architecture"]}'"'"')
print(" ".join(sorted(set(names))))
' 2>/dev/null)" || found=""
		if [ -z "$found" ]; then
			note "single-platform image (no index); skipping the platform check"
		else
			note "platforms: ${found}"
			for want in ${PLATFORMS//,/ }; do
				case " ${found} " in
				*" ${want} "*) ok "index carries ${want}" ;;
				*) missing="${missing} ${want}" ;;
				esac
			done
			[ -n "$missing" ] && bad "missing from the published index:${missing}"
		fi
	else
		note "buildx imagetools unavailable; skipping the platform check"
	fi
fi

echo
if [ "$FAILURES" -ne 0 ]; then
	echo "verify-published-image: ${FAILURES} check(s) failed for ${IMAGE}"
	exit 1
fi
echo "verify-published-image: ${IMAGE} verified"
