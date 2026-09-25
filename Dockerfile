# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# secsy-pki — multi-stage container image
#
# Stage 1 (builder) compiles the server and the CLI tools. The build needs cgo
# because the SQLite driver (mattn/go-sqlite3, selected by the `sqlite` build
# tag) and the PKCS#11 binding (miekg/pkcs11) both link against C. The resulting
# binaries are therefore dynamically linked against glibc, so the runtime image
# is a slim Debian rather than scratch/distroless-static.
#
# Stage 2 (runtime) is a minimal Debian with ca-certificates plus SoftHSM2 and
# OpenSC tooling. SoftHSM lets the same image self-test in kind/CI and gives
# operators pkcs11-tool for debugging; for production the real vendor PKCS#11
# module is bind-mounted over /usr/lib and selected via pkcs11.module_path.
#
# Stage 5 (runtime-yubihsm) is the one exception to that last sentence: the
# runtime with Yubico's PKCS#11 module and the libyubihsm transports already in
# it, published under every tag with `-yubihsm` appended. It is defined after
# the artifacts stage because it derives from the runtime, and a stage can only
# refer to one that came before it. Stage 4 (yubihsm-builder) compiles that
# module from Yubico's own signed release tarball.
#
# Stage 3 (artifacts) is a scratch stage holding nothing but the binaries, so
# that `docker buildx build --target artifacts --output type=local,dest=…`
# exports them for the release archives. The image and the released binaries are
# then the same build, compiled the same way against the same glibc, rather than
# a Dockerfile and a release script that agree only until one of them is edited.
# scripts/build-release-binaries.sh drives it.
#
# Multi-architecture: the builder is pinned to the *build* platform and
# cross-compiles to the target, because the alternative — an emulated arm64
# builder — runs the whole cgo compile under QEMU and takes the better part of
# an hour. Go cross-compiles natively; only the C half needs a cross toolchain,
# which is one apt package per architecture. yubihsm-builder is cross-compiled
# the same way and for the same reason.
# ---------------------------------------------------------------------------

ARG GO_VERSION=1.25

# The upstream yubihsm-shell release the `-yubihsm` variant is built from —
# libyubihsm, its USB and HTTP transports, libykhsmauth, the PKCS#11 module and
# the yubihsm-shell/-wrap/-auth tools all come out of this one source tree, so
# one version pin covers the lot. Overridable for a one-off build:
#
#   docker build --target runtime-yubihsm \
#     --build-arg YUBIHSM_SHELL_VERSION=2.8.1 \
#     --build-arg YUBIHSM_SHELL_SHA256=… .
#
# Bumping it means bumping the digest in the same commit; the signature check in
# the build stage is what stops a wrong digest being pinned by accident.
ARG YUBIHSM_SHELL_VERSION=2.8.0
ARG YUBIHSM_SHELL_SHA256=627a06899096f8bc81a806ef415e00cf7f08a3fc38f4b6b3f39b8129e64dd481
# Primary fingerprint of the Yubico developer key the release tarballs are
# signed with, listed under "developers who are currently releasing code" at
# https://developers.yubico.com/Software_Projects/Software_Signing.html. The
# public key itself is vendored at deploy/yubihsm/yubico-release-signing-key.asc
# and asserted against this fingerprint, so replacing the file does not replace
# the trust anchor.
ARG YUBIHSM_SHELL_SIGNING_KEY=1D7308B0055F5AEF36944A8F27A9C24D9588EA0F
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS builder

# Supplied by BuildKit, not by the caller: the architecture this stage runs on
# and the one it is producing binaries for. Equal for a native build.
ARG BUILDARCH
ARG TARGETARCH

# gcc/libc headers for cgo (sqlite + pkcs11), plus the cross toolchain when the
# target is not what we are running on. `libc6-dev-<arch>-cross` carries the
# target's headers and the crt objects the linker needs.
RUN set -eux; \
    packages="gcc libc6-dev"; \
    if [ "${TARGETARCH}" != "${BUILDARCH}" ]; then \
      case "${TARGETARCH}" in \
        amd64) packages="${packages} gcc-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
        arm64) packages="${packages} gcc-aarch64-linux-gnu libc6-dev-arm64-cross" ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}; add its cross toolchain here" >&2; exit 1 ;; \
      esac; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends ${packages}; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src/server

# Prime the module cache first so dependency downloads are cached independently
# of source changes.
COPY server/go.mod server/go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

# Build the whole server tree.
COPY server/ ./

ENV CGO_ENABLED=1 GOFLAGS=-trimpath
ARG VERSION=dev
# GOFIPS140 selects the Go FIPS 140-3 Cryptographic Module ("off" = ordinary
# build). Build the FIPS variant with `make image-fips`, or directly:
#   docker build --build-arg GOFIPS140=latest -t secsy-pki:fips .
# A GOFIPS140 build defaults GODEBUG=fips140=on, and the step below refuses to
# produce an image whose server does not report FIPS mode at startup.
ARG GOFIPS140=off
ENV GOFIPS140=${GOFIPS140}
# The cache mounts are keyed by target architecture: two platforms of one
# `buildx --platform a,b` run this stage concurrently, and a shared build cache
# would have them contending on the same lock for entries neither can use — the
# compiled objects are per-GOARCH.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build,id=go-build-${TARGETARCH} \
    set -eux; \
    export GOARCH="${TARGETARCH}"; \
    if [ "${TARGETARCH}" != "${BUILDARCH}" ]; then \
      case "${TARGETARCH}" in \
        amd64) export CC=x86_64-linux-gnu-gcc ;; \
        arm64) export CC=aarch64-linux-gnu-gcc ;; \
      esac; \
    fi; \
    ldflags="-s -w -X main.version=${VERSION}"; \
    go build -tags sqlite -ldflags "$ldflags" -o /out/secsy-pki-server ./cmd/server; \
    go build -tags sqlite -ldflags "$ldflags" -o /out/secsy-ca       ./cmd/secsy-ca; \
    go build -tags sqlite -ldflags "$ldflags" -o /out/secsy-secret   ./cmd/secsy-secret; \
    go build           -ldflags "$ldflags" -o /out/secsy-ssh      ./cmd/secsy-ssh; \
    go build           -ldflags "$ldflags" -o /out/secsy-verify   ./cmd/verify; \
    go build           -ldflags "$ldflags" -o /out/secsy-agent    ./cmd/secsy-agent; \
    if [ "${GOFIPS140}" != "off" ]; then \
      if [ "${TARGETARCH}" != "${BUILDARCH}" ]; then \
        echo "!! refusing to cross-build a FIPS image: the fips140=on check below cannot run a ${TARGETARCH} binary here" >&2; \
        exit 1; \
      fi; \
      /out/secsy-pki-server -version; \
      /out/secsy-pki-server -version | grep -q 'fips140=on'; \
    fi

# ---------------------------------------------------------------------------
# The released binaries, and nothing else. Exported rather than run:
#
#   docker buildx build --target artifacts --platform linux/amd64,linux/arm64 \
#     --output type=local,dest=dist/release .
#
# writes dist/release/linux_amd64/… and dist/release/linux_arm64/…, which is
# what scripts/build-release-binaries.sh packages into the release archives.
# Not the last stage in this file: `docker build` with no --target builds the
# last one, and that has to keep meaning the plain runtime image — which is what
# the `default` alias at the bottom is for.
FROM scratch AS artifacts
COPY --from=builder /out/ /

# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        softhsm2 \
        opensc \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user. UID/GID 65532 mirror the distroless "nonroot" account
# so volume ownership lines up with common conventions.
RUN groupadd --gid 65532 secsy \
    && useradd --uid 65532 --gid 65532 --home-dir /app --shell /usr/sbin/nologin secsy

COPY --from=builder /out/secsy-pki-server /usr/local/bin/secsy-pki-server
COPY --from=builder /out/secsy-ca         /usr/local/bin/secsy-ca
COPY --from=builder /out/secsy-secret     /usr/local/bin/secsy-secret
COPY --from=builder /out/secsy-ssh        /usr/local/bin/secsy-ssh
COPY --from=builder /out/secsy-verify     /usr/local/bin/secsy-verify
COPY --from=builder /out/secsy-agent      /usr/local/bin/secsy-agent

# The server serves the SPA from web/static relative to its working directory.
COPY server/web/static /app/web/static

# The Debian softhsm2 package ships only a sample config and leaves /etc/softhsm
# unreadable by non-root users. Provide a world-readable config that points the
# token store at a path we can mount a writable volume onto, and export it via
# SOFTHSM2_CONF so softhsm2-util/the module find it regardless of $HOME. Only the
# SoftHSM module reads this; real-HSM deployments ignore it.
RUN printf 'directories.tokendir = /var/lib/softhsm/tokens\nobjectstore.backend = file\nlog.level = INFO\n' \
        > /etc/softhsm/softhsm2.conf \
    && chmod 0755 /etc/softhsm \
    && chmod 0644 /etc/softhsm/softhsm2.conf
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf

# Writable state (SQLite DB, generated config, SoftHSM tokens for CI) lives under
# /app and /var/lib/softhsm, both owned by the runtime user.
RUN mkdir -p /app/data /var/lib/softhsm/tokens \
    && chown -R 65532:65532 /app /var/lib/softhsm

WORKDIR /app
USER 65532:65532

# HTTPS API / web UI. ACME http-01 validation uses a separate port when enabled.
EXPOSE 8443

ENTRYPOINT ["secsy-pki-server"]
CMD ["-config", "/etc/secsy/config.yaml"]

# ---------------------------------------------------------------------------
# Yubico's PKCS#11 module, compiled from Yubico's own signed release.
#
# The whole `-yubihsm` payload comes out of this one source tree: libyubihsm and
# its two transports (direct USB, and HTTP to a yubihsm-connector), libykhsmauth,
# yubihsm_pkcs11.so, and the yubihsm-shell/-wrap/-auth tools.
#
# Built from source rather than installed from bookworm-backports, which is
# where this used to come from. Backports carries 2.6.0; upstream is on 2.8.0,
# and what is in between is not cosmetic for a CA. From upstream's CHANGELOG:
# 2.7.2 fixes a PKCS#11 bug where generating an RSA key pair "can potentially
# result in the wrong type of object being created" and stops command audit
# being enabled for command 0x05 — which is the audit subsystem this project
# reads and pins; 2.7.3 fixes capabilities on public wrap keys; 2.8.0 adds
# YubiKey-held session authentication and a ykhsmauth buffer-size fix. bookworm
# proper has no yubihsm packages at all, so staying on Debian means staying on
# backports' schedule for the single package the tag exists to provide, and
# leaves the vendor module the oldest thing in the image.
#
# What is given up by leaving Debian is Debian's security tracking of this
# package, and it is replaced rather than dropped: the release is pinned by
# SHA-256 *and* checked against Yubico's detached OpenPGP signature, which is a
# stronger statement about provenance than an unauthenticated apt mirror would
# be, and the weekly rebuild in container.yaml still picks up the base image's
# libcrypto/libcurl/libusb updates underneath it. What is not automatic any more
# is *noticing* a new upstream release: YUBIHSM_SHELL_VERSION is bumped by hand.
#
# Cross-compiled, for the reason the Go builder is: the arm64 half of a
# multi-arch build would otherwise run cmake and gcc under QEMU. Here that costs
# minutes rather than the better part of an hour, but the mechanism is one apt
# transaction either way — a cross toolchain plus the target architecture's -dev
# packages through dpkg multiarch — so it may as well be quick. A mislinked
# cross build cannot pass silently: the linker refuses an object of the wrong
# machine type outright.
FROM --platform=$BUILDPLATFORM debian:bookworm-slim AS yubihsm-builder

ARG BUILDARCH
ARG TARGETARCH
ARG YUBIHSM_SHELL_VERSION
ARG YUBIHSM_SHELL_SHA256
ARG YUBIHSM_SHELL_SIGNING_KEY

# Build dependencies, from upstream's own debian/control. Three groups, because
# only the middle one is architecture-dependent:
#
#   host tools     run on the build machine, so always its own architecture.
#                  gengetopt generates the command-line parsers; g++ is here
#                  only because upstream's `project()` call enables CXX, no C++
#                  is compiled.
#   the compiler   the native one, or a cross toolchain and the target's libc.
#   the libraries  linked into the result, so the *target's* copies. dpkg
#                  multiarch installs them alongside the host's rather than in a
#                  sysroot, which is what lets pkg-config and cmake find them by
#                  multiarch path with no rewriting of either.
#
# help2man is deliberately absent: it generates the manpages by *running* the
# binary it documents, which a cross build cannot do, and a slim Debian excludes
# /usr/share/man from the image anyway. -DWITHOUT_MANPAGES=1 below skips it, so
# both architectures produce the same set of files.
RUN set -eux; \
    host_pkgs="ca-certificates curl gnupg cmake make pkg-config gengetopt"; \
    dev_pkgs="libssl-dev libcurl4-openssl-dev libusb-1.0-0-dev libedit-dev libpcsclite-dev zlib1g-dev"; \
    if [ "${TARGETARCH}" = "${BUILDARCH}" ]; then \
      apt-get update; \
      apt-get install -y --no-install-recommends ${host_pkgs} gcc g++ libc6-dev ${dev_pkgs}; \
    else \
      case "${TARGETARCH}" in \
        amd64) triplet=x86_64-linux-gnu; \
               cross="gcc-x86-64-linux-gnu g++-x86-64-linux-gnu libc6-dev-amd64-cross" ;; \
        arm64) triplet=aarch64-linux-gnu; \
               cross="gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross" ;; \
        *) echo "unsupported TARGETARCH=${TARGETARCH}; add its cross toolchain here" >&2; exit 1 ;; \
      esac; \
      dpkg --add-architecture "${TARGETARCH}"; \
      apt-get update; \
      target_dev=""; for p in ${dev_pkgs}; do target_dev="${target_dev} ${p}:${TARGETARCH}"; done; \
      apt-get install -y --no-install-recommends ${host_pkgs} ${cross} ${target_dev}; \
      echo "${triplet}" > /tmp/target-triplet; \
    fi; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

# The vendored trust anchor. Its fingerprint is not taken from the file — see
# the VALIDSIG assertion below.
COPY deploy/yubihsm/yubico-release-signing-key.asc /tmp/yubico-release-signing-key.asc

# Fetch, then prove it is the release it claims to be, twice over:
#
#   sha256sum   this is the byte sequence the Dockerfile was written against.
#               Pins the build against upstream re-rolling a tarball under the
#               same name, and makes the layer cacheable on something meaningful.
#   gpg         Yubico signed those bytes. Asserted through the VALIDSIG status
#               line rather than gpg's exit status, and against the *primary*
#               key fingerprint in its last field: a good signature by some
#               other key in the keyring would satisfy `gpg --verify`, so
#               swapping the vendored .asc for an attacker's key and re-signing
#               a modified tarball has to fail here, and this is where it does.
#
# Either check alone would be weaker than it looks. The digest says nothing about
# who produced the bytes; the signature says nothing about which release is
# wanted. Together they say: Yubico published this, and this is the one we meant.
RUN set -eux; \
    tarball="yubihsm-shell-${YUBIHSM_SHELL_VERSION}.tar.gz"; \
    base="https://developers.yubico.com/yubihsm-shell/Releases"; \
    curl -fsSL --retry 3 --retry-connrefused -o "${tarball}"     "${base}/${tarball}"; \
    curl -fsSL --retry 3 --retry-connrefused -o "${tarball}.sig" "${base}/${tarball}.sig"; \
    echo "${YUBIHSM_SHELL_SHA256}  ${tarball}" | sha256sum -c -; \
    export GNUPGHOME=/tmp/gnupg; \
    mkdir -m 700 -p "${GNUPGHOME}"; \
    gpg --batch --quiet --import /tmp/yubico-release-signing-key.asc; \
    gpg --batch --status-file /tmp/gpg.status --verify "${tarball}.sig" "${tarball}"; \
    grep -qE "^\[GNUPG:\] VALIDSIG [0-9A-F]+ .* ${YUBIHSM_SHELL_SIGNING_KEY}\$" /tmp/gpg.status \
      || { echo "!! ${tarball} is not signed by ${YUBIHSM_SHELL_SIGNING_KEY}" >&2; \
           cat /tmp/gpg.status >&2; exit 1; }; \
    echo "verified ${tarball}: sha256 ${YUBIHSM_SHELL_SHA256}, signed by ${YUBIHSM_SHELL_SIGNING_KEY}"; \
    tar xzf "${tarball}"; \
    rm -rf "${GNUPGHOME}" /tmp/yubico-release-signing-key.asc "${tarball}" "${tarball}.sig"

# Installed under /usr/local, not over Debian's multiarch directories. That
# removes the reason the old apt-based stage had to glob for the module and
# symlink it: /usr/local/lib/pkcs11/yubihsm_pkcs11.so is the same path on every
# architecture, and cmake writes /usr/local/lib into the module's RUNPATH so it
# finds libyubihsm without anything on LD_LIBRARY_PATH.
#
# CMAKE_LIBRARY_ARCHITECTURE is the load-bearing line of the toolchain file. It
# is what puts /usr/lib/<target-triplet> ahead of /usr/lib in cmake's library
# search, so `find_package(ZLIB)` — the one dependency looked up that way rather
# than through pkg-config — resolves to the target's libz and not to the build
# machine's. PKG_CONFIG_LIBDIR does the same job for everything else, and is set
# rather than prepended so the host's .pc files are out of reach entirely.
RUN set -eux; \
    cd "yubihsm-shell-${YUBIHSM_SHELL_VERSION}"; \
    if [ "${TARGETARCH}" != "${BUILDARCH}" ]; then \
      triplet="$(cat /tmp/target-triplet)"; \
      { echo 'set(CMAKE_SYSTEM_NAME Linux)'; \
        echo "set(CMAKE_SYSTEM_PROCESSOR ${triplet%%-*})"; \
        echo "set(CMAKE_C_COMPILER ${triplet}-gcc)"; \
        echo "set(CMAKE_CXX_COMPILER ${triplet}-g++)"; \
        echo "set(CMAKE_LIBRARY_ARCHITECTURE ${triplet})"; \
        echo 'set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)'; \
      } > /tmp/cross.cmake; \
      export PKG_CONFIG_LIBDIR="/usr/lib/${triplet}/pkgconfig:/usr/share/pkgconfig"; \
      unset PKG_CONFIG_PATH; \
      set -- -DCMAKE_TOOLCHAIN_FILE=/tmp/cross.cmake; \
    else \
      set --; \
    fi; \
    cmake -S . -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DRELEASE_BUILD=1 \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DWITHOUT_MANPAGES=1 \
      "$@"; \
    cmake --build build --parallel "$(nproc)"; \
    DESTDIR=/out cmake --install build --strip; \
    rm -rf /out/usr/local/include /out/usr/local/share; \
    echo "${YUBIHSM_SHELL_VERSION}" > /out/yubihsm-shell-version

# ---------------------------------------------------------------------------
# The `-yubihsm` variant: the runtime above plus everything a YubiHSM 2 needs.
#
# Published as a separate tag rather than folded into the default image, because
# the default is what every deployment pulls and most of them have no YubiHSM;
# and rather than left to the operator, because the usual answer — bind-mount
# the vendor module over /usr/lib — asks whoever runs the container to match a
# glibc, an OpenSSL and a multiarch path against a base image they did not
# build. Getting it wrong yields an image that starts and cannot sign.
#
# Nothing here is needed by the *native* driver (internal/yubihsm speaks SCP03
# over usbfs with no libusb, no cgo and no vendor code — see
# docs/hsm/yubihsm-native-driver.md). It is needed by the other half: live PKI
# signing goes through PKCS#11, and PKCS#11 needs Yubico's module.
FROM runtime AS runtime-yubihsm

ARG YUBIHSM_SHELL_VERSION
ARG YUBIHSM_SHELL_SHA256

# What syft cannot tell you any more. The image SBOM is built by cataloguing
# dpkg's database, and a source build has no dpkg entry — so the one component
# this tag exists to add would be the one component the SBOM does not name.
# These labels put it back where a scanner, a registry UI or `docker inspect`
# will find it, with enough detail to re-fetch the tarball and check it against
# the digest the image was built from. /usr/share/secsy-pki/yubihsm-shell-version
# is the same fact for anything already inside the container.
LABEL io.secsy-pki.yubihsm-shell.version="${YUBIHSM_SHELL_VERSION}" \
      io.secsy-pki.yubihsm-shell.sha256="${YUBIHSM_SHELL_SHA256}" \
      io.secsy-pki.yubihsm-shell.source="https://developers.yubico.com/yubihsm-shell/Releases/yubihsm-shell-${YUBIHSM_SHELL_VERSION}.tar.gz"

USER root

# The shared libraries the source build linked against, as runtime packages from
# bookworm proper. Named explicitly rather than inherited from a vendor package's
# dependency list, because there is no vendor package here any more: this list
# and the -dev list in the build stage are two halves of the same statement, and
# a NEEDED entry that nothing installs is caught by the ldd check below.
#
# yubihsm-connector is the one thing still installed from bookworm-backports. It
# is a separate upstream project — a Go daemon that bridges USB to the HTTP
# transport, useful for deployments that would rather not give the container the
# USB device — and nothing about it has to match the module's version, so there
# is no reason to compile it here.
#
# Deliberately *without* `-t bookworm-backports`: that flag raises every
# backported package to priority 990 for the whole transaction, so a dependency
# resolution could quietly pull a backported libssl3 or libc6 underneath the
# rest of the image. Backports is NotAutomatic (priority 100), which is enough
# to install a package that exists nowhere else and not enough to displace one
# that does — exactly the rule wanted here.
# `--no-upgrade` is what keeps the two published tags of one commit differing by
# exactly the YubiHSM payload. libcrypto and libz are already in the runtime
# stage, and naming them without it makes apt *upgrade* them to whatever the
# archive holds today — which writes a second 7 MB copy of libcrypto into this
# layer and leaves `1.2.3-yubihsm` on a different OpenSSL from `1.2.3`, for a
# reason that has nothing to do with YubiHSMs. Base-image updates are the weekly
# rebuild's job. The flag applies only to packages named on the command line, so
# a genuinely missing dependency is still installed.
RUN set -eux; \
    echo 'deb http://deb.debian.org/debian bookworm-backports main' \
        > /etc/apt/sources.list.d/backports.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends --no-upgrade \
        libssl3 \
        libcurl4 \
        libusb-1.0-0 \
        libedit2 \
        libpcsclite1 \
        zlib1g \
        yubihsm-connector; \
    rm -rf /var/lib/apt/lists/*

COPY --from=yubihsm-builder /out/usr/local/ /usr/local/
COPY --from=yubihsm-builder /out/yubihsm-shell-version /usr/share/secsy-pki/yubihsm-shell-version

# /usr/lib/pkcs11/yubihsm_pkcs11.so is the path every config example, doc page
# and Helm value in this repository names, and it stays that path — now a
# symlink to the source-built module rather than to a multiarch one.
#
# The ldd check is the point of this step. A module whose NEEDED libraries are
# not installed is a perfectly good file that the loader refuses, and nothing
# notices until the first signature; catching it here means a missing runtime
# package above fails the build instead of the deployment. Written as an `if`
# rather than `ldd … | grep …; exit 1`, because under `set -e` a grep that
# matches nothing — the healthy case — would end the script as a failure.
RUN set -eux; \
    ldconfig; \
    mkdir -p /usr/lib/pkcs11; \
    ln -s /usr/local/lib/pkcs11/yubihsm_pkcs11.so /usr/lib/pkcs11/yubihsm_pkcs11.so; \
    for so in /usr/local/lib/pkcs11/yubihsm_pkcs11.so \
              /usr/local/lib/libyubihsm.so.2 \
              /usr/local/lib/libyubihsm_usb.so.2 \
              /usr/local/lib/libyubihsm_http.so.2 \
              /usr/local/lib/libykhsmauth.so.2; do \
      if ldd "$so" | grep -F 'not found'; then \
        echo "!! unresolved shared libraries in $so" >&2; exit 1; \
      fi; \
    done; \
    yubihsm-shell --version | grep -Fqx "yubihsm-shell ${YUBIHSM_SHELL_VERSION}"

# udev does not run in a container, so the device node arrives with whatever
# ownership the host gave it and this file cannot change that. It is shipped to
# be copied *out* — `docker run --rm --entrypoint cat … /usr/share/secsy-pki/udev/70-yubihsm.rules`
# — so the rule the host needs comes from the same place as the software that
# needs it. docs/deployment/container.md has the full recipe.
COPY deploy/udev/70-yubihsm.rules /usr/share/secsy-pki/udev/70-yubihsm.rules

USER 65532:65532

# The image `docker build .` produces when no --target is given: the plain
# runtime, unchanged. BuildKit builds only the stages a target needs, so naming
# this one last leaves runtime-yubihsm out of an ordinary build entirely — and
# an alias stage with no instructions of its own cannot drift from what it
# aliases. The variants are selected explicitly:
#
#   docker build --target runtime         .   (or no --target at all)
#   docker build --target runtime-yubihsm .
#   docker build --target artifacts       .   --output type=local,dest=…
FROM runtime AS default
