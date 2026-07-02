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
# ---------------------------------------------------------------------------

ARG GO_VERSION=1.25
FROM golang:${GO_VERSION}-bookworm AS builder

# gcc/libc headers for cgo (sqlite + pkcs11).
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

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
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    set -eux; \
    ldflags="-s -w -X main.version=${VERSION}"; \
    go build -tags sqlite -ldflags "$ldflags" -o /out/secsy-pki-server ./cmd/server; \
    go build -tags sqlite -ldflags "$ldflags" -o /out/secsy-ca       ./cmd/secsy-ca; \
    go build -tags sqlite -ldflags "$ldflags" -o /out/secsy-secret   ./cmd/secsy-secret; \
    go build           -ldflags "$ldflags" -o /out/secsy-ssh      ./cmd/secsy-ssh; \
    go build           -ldflags "$ldflags" -o /out/secsy-verify   ./cmd/verify

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
