#!/usr/bin/env bash
#
# build-release-binaries.sh — build, verify and package the released binaries.
#
# The binaries come out of the *image's* Dockerfile (`--target artifacts`),
# not a second build definition of their own. That is deliberate: the released
# `secsy-ca` and the `secsy-ca` inside the published container are then the same
# binary, compiled with the same build tags, the same ldflags and against the
# same glibc, rather than two builds that agree only until someone edits one of
# them. It also fixes the floor: bookworm's glibc 2.36, so the binaries run on
# Debian 12, RHEL 9, Ubuntu 22.04 and anything newer. A binary built on the CI
# runner's own Ubuntu 24.04 would demand glibc 2.39 and fail on all three.
#
# cgo is not optional here — miekg/pkcs11 is a C binding and the SQLite driver
# links libsqlite3 — so "just set GOOS/GOARCH" does not build these. The
# Dockerfile carries the cross toolchain instead, which is why this script talks
# to buildx rather than to `go build`.
#
# Each platform is then *run* before it is packaged: the binaries are executed
# inside debian:bookworm-slim for their own architecture (under QEMU for the
# foreign one) and must report the version being released. A tarball of
# something that does not start is the release-day failure this catches.
#
# Usage:
#   build-release-binaries.sh [--version X.Y.Z] [--platforms linux/amd64,linux/arm64]
#                             [--dest dist/release] [--no-verify]
#
# Requires docker with buildx and, for a foreign platform, binfmt/QEMU
# registered (`docker run --privileged --rm tonistiigi/binfmt --install all`, or
# docker/setup-qemu-action in CI). Run by `make release-binaries` and by the
# build job of .github/workflows/release.yaml.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"

VERSION=""
PLATFORMS="linux/amd64,linux/arm64"
DEST=""
VERIFY=1
# The runtime image's own base, so "it runs here" means "it runs in the image".
RUNTIME_BASE="debian:bookworm-slim"
# The six commands the Dockerfile installs into the image, in the order they are
# listed there. secsy-ca is the one used to check the version stamp.
BINARIES=(secsy-pki-server secsy-ca secsy-secret secsy-ssh secsy-verify secsy-agent)

die() {
	echo "build-release-binaries: error: $*" >&2
	exit 1
}

while [ $# -gt 0 ]; do
	case "$1" in
	--version)
		VERSION="${2:-}"
		shift 2
		;;
	--platforms)
		PLATFORMS="${2:-}"
		shift 2
		;;
	--dest)
		DEST="${2:-}"
		shift 2
		;;
	--no-verify)
		VERIFY=0
		shift
		;;
	-h | --help)
		sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
		exit 0
		;;
	*) die "unknown argument: $1" ;;
	esac
done

command -v docker >/dev/null 2>&1 || die "docker is required (buildx builds these)"
docker buildx version >/dev/null 2>&1 || die "docker buildx is required"

if [ -z "$VERSION" ]; then
	VERSION="$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"
	VERSION="${VERSION#v}"
fi
DEST="${DEST:-${REPO_ROOT}/dist/release}"
mkdir -p "$DEST"
# Absolute from here on. The packaging loop below `cd`s into $DEST to write the
# checksums, and a relative --dest would resolve a second time from in there.
DEST="$(cd "$DEST" && pwd)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Reproducible archives: same input, same bytes, so the checksums below mean
# something when someone rebuilds a tag to compare. SOURCE_DATE_EPOCH is the
# convention for this; the commit date is the natural value when it is unset.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
	SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --pretty=%ct 2>/dev/null || echo 0)"
fi
export SOURCE_DATE_EPOCH

IFS=',' read -r -a PLATFORM_LIST <<<"$PLATFORMS"

# Buildx's default "docker" driver builds one platform per invocation, so a
# two-architecture release needs the container driver. CI already has one
# (docker/setup-buildx-action makes it the default), and there the check below
# finds it and changes nothing; on a laptop, a dedicated builder is created once
# and reused. Said out loud rather than done quietly — it starts a container.
BUILDER_ARGS=()
RELEASE_BUILDER="secsy-pki-release"
if [ "${#PLATFORM_LIST[@]}" -gt 1 ] &&
	[ "$(docker buildx inspect 2>/dev/null | sed -n 's/^Driver:[[:space:]]*//p' | head -n 1)" = "docker" ]; then
	if ! docker buildx inspect "$RELEASE_BUILDER" >/dev/null 2>&1; then
		echo "==> the default buildx driver cannot build ${PLATFORMS}; creating the '${RELEASE_BUILDER}' builder"
		docker buildx create --name "$RELEASE_BUILDER" --driver docker-container >/dev/null
	fi
	BUILDER_ARGS=(--builder "$RELEASE_BUILDER")
fi

echo "==> building ${PLATFORMS} at version ${VERSION}"
docker buildx build \
	"${BUILDER_ARGS[@]}" \
	--target artifacts \
	--platform "$PLATFORMS" \
	--build-arg "VERSION=${VERSION}" \
	--output "type=local,dest=${STAGE}" \
	"$REPO_ROOT"

# A single-platform build writes the binaries straight into the destination; a
# multi-platform one writes <os>_<arch>/ subdirectories. Normalize to the latter
# so the packaging loop below has one shape to handle.
if [ "${#PLATFORM_LIST[@]}" -eq 1 ]; then
	only="${PLATFORM_LIST[0]//\//_}"
	if [ ! -d "${STAGE}/${only}" ]; then
		mkdir -p "${STAGE}/${only}"
		find "$STAGE" -maxdepth 1 -type f -exec mv {} "${STAGE}/${only}/" \;
	fi
fi

CHECKSUMS="${DEST}/SHA256SUMS"
: >"$CHECKSUMS"

for platform in "${PLATFORM_LIST[@]}"; do
	dir="${STAGE}/${platform//\//_}"
	[ -d "$dir" ] || die "buildx produced nothing for ${platform} (looked in ${dir})"

	for binary in "${BINARIES[@]}"; do
		[ -s "${dir}/${binary}" ] || die "${platform}: ${binary} missing from the build output"
	done

	if [ "$VERIFY" -eq 1 ]; then
		# Run them for their own architecture, on the image's base. `secsy-ca
		# version` prints "secsy-ca <version> <go> <fips>", so this checks the
		# ldflags stamp landed as well as that the binary starts at all — a
		# release whose binaries report "dev" is a release nobody can identify.
		echo "==> verifying ${platform} on ${RUNTIME_BASE}"
		reported="$(docker run --rm --platform "$platform" -v "${dir}:/out:ro" \
			"$RUNTIME_BASE" /out/secsy-ca version 2>&1 | head -n 1)" ||
			die "${platform}: secsy-ca does not run on ${RUNTIME_BASE}. Foreign architecture? Register QEMU: docker run --privileged --rm tonistiigi/binfmt --install all"
		echo "    ${reported}"
		[ "${reported#secsy-ca "${VERSION}" }" != "$reported" ] ||
			die "${platform}: secsy-ca reports '${reported}', expected version ${VERSION}"

		# The server is the image's entrypoint; -version is the one flag that
		# needs neither a config file nor an HSM.
		docker run --rm --platform "$platform" -v "${dir}:/out:ro" \
			"$RUNTIME_BASE" /out/secsy-pki-server -version >/dev/null ||
			die "${platform}: secsy-pki-server -version failed"
	fi

	name="secsy-pki_${VERSION}_${platform//\//_}"
	pkg="${STAGE}/pkg/${name}"
	mkdir -p "$pkg"
	for binary in "${BINARIES[@]}"; do
		cp "${dir}/${binary}" "${pkg}/${binary}"
	done
	cp "${REPO_ROOT}/LICENSE" "${pkg}/LICENSE"
	cp "${REPO_ROOT}/README.md" "${pkg}/README.md"
	[ -f "${REPO_ROOT}/CHANGELOG.md" ] && cp "${REPO_ROOT}/CHANGELOG.md" "${pkg}/CHANGELOG.md"

	archive="${DEST}/${name}.tar.gz"
	tar --sort=name --owner=0 --group=0 --numeric-owner \
		--mtime="@${SOURCE_DATE_EPOCH}" \
		-C "${STAGE}/pkg" -czf "$archive" "$name"
	(cd "$DEST" && sha256sum "$(basename "$archive")" >>"$CHECKSUMS")
	echo "==> packaged ${archive} ($(du -h "$archive" | cut -f1))"
done

echo
echo "release binaries for ${VERSION} in ${DEST}:"
cat "$CHECKSUMS"
