# The container image

The published image, what is in it, which tag to pull, and how to check it is
the one this repository built.

- [Where it is published](#where-it-is-published)
- [Which tag to use](#which-tag-to-use)
- [What is in it](#what-is-in-it)
- [Running it](#running-it)
- [Verifying it before you run it](#verifying-it-before-you-run-it)
- [How it is built](#how-it-is-built)

For deploying it on Kubernetes with the Helm chart, see
[Kubernetes deployment](kubernetes.md). For the release process that produces
the version tags, see [releasing](../development/releasing.md).

## Where it is published

```
ghcr.io/blechschmidt/secsy-pki
```

Public, so no `docker login` is needed. Built for **`linux/amd64` and
`linux/arm64`**; the tag resolves to a manifest index and Docker picks the
architecture for you.

## Which tag to use

| Tag | Points at | Use it for |
|-----|-----------|------------|
| `latest` | The newest release that is not a pre-release | Casual use where "current" is what you want |
| `1.2.3` | Exactly that release, forever | **Production.** Pin it |
| `1.2` | The newest patch on that minor line | Picking up patch fixes without re-pinning |
| `edge` | The head of the default branch, rebuilt on every push | Trying unreleased work |
| `<branch>` | The head of that branch | Running a colleague's branch without a Go toolchain |
| `sha-1a2b3c4` | That one commit, immutably | Bisecting, or pinning below release granularity |

A pre-release (`1.3.0-rc.1`) gets its version and minor tags but never `latest`
— that is what the release guard's pre-release detection is for.

Every tag is mutable except `1.2.3` and `sha-…`. For anything that matters, pin
the **digest**, which the release notes carry:

```bash
docker pull ghcr.io/blechschmidt/secsy-pki@sha256:…
```

## What is in it

A two-stage build: the Go tree is compiled with cgo against
`golang:1.25-bookworm`, and the result is copied into `debian:bookworm-slim`.
The runtime layer carries `ca-certificates`, `softhsm2` and `opensc`, and
nothing else.

Six commands, all on `PATH`:

| Command | Purpose |
|---------|---------|
| `secsy-pki-server` | The server. The image's entrypoint |
| `secsy-ca` | CA lifecycle, issuance, audit, diagnostics |
| `secsy-secret` | HSM-backed secret envelopes |
| `secsy-ssh` | SSH certificate client |
| `secsy-verify` | Offline HSM audit-log verifier |
| `secsy-agent` | Host auto-enrollment agent |

| Property | Value |
|----------|-------|
| Entrypoint | `secsy-pki-server -config /etc/secsy/config.yaml` |
| User | `65532:65532`, non-root (matches the distroless `nonroot` account) |
| Working directory | `/app` |
| Exposed port | `8443` |
| Writable paths | `/app/data`, `/var/lib/softhsm/tokens` |

**SoftHSM is in the image on purpose, and it is not for production.** It lets
the image self-test — CI mints a real HSM-backed root CA inside it on every
build — and gives operators `pkcs11-tool` for debugging. For production, mount
the vendor PKCS#11 module over `/usr/lib` and point `pkcs11.module_path` at it;
see [HSM configuration](../hsm/configuration.md) and
[production migration](../hsm/production-migration.md).

## Running it

The entrypoint expects a config at `/etc/secsy/config.yaml`:

```bash
docker run --rm \
  -v "$PWD/config.yaml:/etc/secsy/config.yaml:ro" \
  -v secsy-data:/app/data \
  -p 8443:8443 \
  ghcr.io/blechschmidt/secsy-pki:1.2.3
```

Any of the other commands by overriding the entrypoint:

```bash
docker run --rm --entrypoint secsy-ca \
  -v "$PWD/config.yaml:/etc/secsy/config.yaml:ro" \
  ghcr.io/blechschmidt/secsy-pki:1.2.3 -config /etc/secsy/config.yaml doctor
```

Just to see what a tag is:

```bash
docker run --rm ghcr.io/blechschmidt/secsy-pki:1.2.3 -version
```

A **FIPS 140-3** image is a separate build — `make image-fips` — because the
check that the binary reports `fips140=on` has to run the binary, which a
cross-build cannot do. See [FIPS mode](../security/fips.md).

## Verifying it before you run it

Every push is signed with cosign, keylessly against Fulcio, and carries a
CycloneDX SBOM attestation. Releases additionally carry SLSA Build L3
provenance. None of that is worth anything unless someone checks it:

```bash
# The signature came from a workflow in this repository.
cosign verify \
  --certificate-identity-regexp '^https://github.com/blechschmidt/secsy-pki/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/blechschmidt/secsy-pki@sha256:…

# What it is made of.
cosign verify-attestation --type cyclonedx \
  --certificate-identity-regexp '^https://github.com/blechschmidt/secsy-pki/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/blechschmidt/secsy-pki@sha256:…

# It was built by this repository's release workflow, from this source.
slsa-verifier verify-image ghcr.io/blechschmidt/secsy-pki@sha256:… \
  --source-uri github.com/blechschmidt/secsy-pki
```

The same checks run as `make verify`. See
[supply-chain security](../development/supply-chain.md) for what each
attestation asserts.

To check the image works rather than just that it is authentic:

```bash
scripts/verify-published-image.sh --image ghcr.io/blechschmidt/secsy-pki:1.2.3
```

That pulls anonymously — refusing to run if a registry credential is present,
because an authenticated pull cannot prove the package is public — checks every
command starts, checks it runs as uid 65532, confirms the index really carries
both architectures, and then initializes a SoftHSM token inside the container
and mints an HSM-backed root CA through PKCS#11. CI runs it twice per publish:
once against the local build before pushing, and once from a job with no
registry permission at all.

## How it is built

[`.github/workflows/container.yaml`](../../.github/workflows/container.yaml)
is the only workflow that builds the published image and the only one that
pushes it. It runs on **every commit on every branch**, on pull requests
(build and smoke-test only, never a push), weekly on Mondays, and by
`workflow_call` from the release workflow.

The weekly rebuild is not busywork: the image is `debian:bookworm-slim` plus
Debian's SoftHSM, OpenSC and `ca-certificates`, all of which take security
updates on their own schedule. Without it, `edge` ages into whatever its base
image was on the day it was built — and for a PKI whose trust store is one of
those packages, that ages badly.

Three jobs, in order:

1. **build and smoke-test** — no registry credential at all. Builds `amd64`,
   loads it, and runs the full verification script against it locally. Then
   builds both architectures to prove the arm64 cross-compile works, and runs
   the arm64 image under QEMU: a broken cross-link is a working amd64 image and
   an arm64 one that dies on start, and the index would carry both.
2. **push to ghcr.io** — the only job holding `packages: write`. Tags, pushes,
   signs, attests, then pulls its own push back by digest and runs it.
3. **verify it from outside** — no `packages` permission, an explicit
   `docker logout` first, and the *tag* rather than the digest. GHCR creates a
   package private on first push and no workflow flips it; a logged-in runner
   cannot tell that apart from a public one. This job is what would catch it.

arm64 is **cross-compiled**, not emulated. Go cross-compiles natively and the
Dockerfile carries a cross toolchain for the cgo half, which is one apt package
per architecture; building arm64 under QEMU instead would run the whole cgo
compile emulated and take the better part of an hour.

---

↩ Back to [deployment & scaling](README.md) · [documentation map](../README.md)
