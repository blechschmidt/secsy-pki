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
# Deliberately not the last stage in this file: `docker build` with no --target
# builds the last one, and that has to stay the runtime image.
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
