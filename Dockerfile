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
# Stage 4 (runtime-yubihsm) is the one exception to that last sentence: the
# runtime with Yubico's PKCS#11 module and the libyubihsm transports already in
# it, published under every tag with `-yubihsm` appended. It is defined after
# the artifacts stage because it derives from the runtime, and a stage can only
# refer to one that came before it.
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
# which is one apt package per architecture.
# ---------------------------------------------------------------------------

ARG GO_VERSION=1.25
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
#
# Debian's own archive, not Yubico's tarball. The tarball is amd64-only, which
# would make this variant single-architecture while the default image is not;
# Debian builds the same source for both, signs it, and tracks it for security
# updates, which is also what makes the weekly rebuild in container.yaml mean
# something here.
#
# The packages live in bookworm-backports; bookworm itself has none of them.
# Deliberately *without* `-t bookworm-backports`: that flag raises every
# backported package to priority 990 for the whole transaction, so a dependency
# resolution could quietly pull a backported libssl3 or libc6 underneath the
# rest of the image. Backports is NotAutomatic (priority 100), which is enough
# to install a package that exists nowhere else and not enough to displace one
# that does — exactly the rule wanted here.
FROM runtime AS runtime-yubihsm

USER root

# libyubihsm-usb2 is named explicitly and must stay that way. libyubihsm2's
# dependency is the *alternative* `libyubihsm-http2 | libyubihsm-usb2`, so apt
# satisfies it with the first and direct USB support is silently absent — an
# image whose PKCS#11 module works against a yubihsm-connector and fails against
# the device plugged into the host, which is the common case.
RUN set -eux; \
    echo 'deb http://deb.debian.org/debian bookworm-backports main' \
        > /etc/apt/sources.list.d/backports.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        yubihsm-pkcs11 \
        libyubihsm-usb2 \
        libyubihsm-http2 \
        yubihsm-shell \
        yubihsm-connector; \
    rm -rf /var/lib/apt/lists/*

# Debian installs the module to the multiarch directory, so its path differs
# between the amd64 and arm64 halves of the same tag — and a config file cannot
# say "whichever". The symlink is the architecture-independent path the
# documentation uses, so one pkcs11.module_path is correct on both.
# Found by glob rather than by naming the triplet: `dpkg-architecture` lives in
# dpkg-dev, which is not in a slim base and is not worth adding for one string.
# The count is asserted, so a second module appearing under a different triplet
# fails the build instead of being resolved by shell-glob ordering.
RUN set -eux; \
    set -- /usr/lib/*/pkcs11/yubihsm_pkcs11.so; \
    [ "$#" -eq 1 ] || { echo "expected exactly one yubihsm_pkcs11.so, found $#: $*" >&2; exit 1; }; \
    mkdir -p /usr/lib/pkcs11; \
    ln -sf "$1" /usr/lib/pkcs11/yubihsm_pkcs11.so

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
