# The container image

The published image, what is in it, which tag to pull, and how to check it is
the one this repository built.

- [Where it is published](#where-it-is-published)
- [Which tag to use](#which-tag-to-use)
- [What is in it](#what-is-in-it)
- [The YubiHSM variant](#the-yubihsm-variant)
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

Every tag above also exists with **`-yubihsm`** appended — `latest-yubihsm`,
`1.2.3-yubihsm`, `edge-yubihsm` and so on. Same commit, same build, plus the
YubiHSM 2 vendor stack; see [the `-yubihsm` variant](#the-yubihsm-variant).

## What is in it

A two-stage build: the Go tree is compiled with cgo against
`golang:1.25-bookworm`, and the result is copied into `debian:bookworm-slim`.
The runtime layer carries `ca-certificates`, `softhsm2` and `opensc`, and
nothing else. (A third stage adds the YubiHSM vendor packages; that is the
`-yubihsm` tag, [below](#the-yubihsm-variant).)

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

For a YubiHSM 2 there is nothing to mount — use the variant below.

## The YubiHSM variant

```
ghcr.io/blechschmidt/secsy-pki:1.2.3-yubihsm
```

The image above with Yubico's YubiHSM 2 stack added, for both architectures.
Every tag has one; they are built from the same commit in the same job, so
`1.2.3-yubihsm` cannot be a different build of `1.2.3` than `1.2.3` is.

| Added | What it is for |
|-------|----------------|
| `yubihsm_pkcs11.so` | Yubico's PKCS#11 module. Live CA signing goes through PKCS#11 |
| `libyubihsm` + the **USB** and **HTTP** transports | What the module loads to reach the device |
| `yubihsm-shell` | Vendor CLI, for diagnosing the device by hand |
| `yubihsm-connector` | The USB-to-HTTP bridge, when the device must be shared |
| `/usr/share/secsy-pki/udev/70-yubihsm.rules` | The host udev rule, shipped to be copied out |

Roughly 17 MB on top of the default image. The packages are Debian's, from
`bookworm-backports` — Yubico's own tarball is amd64-only, which would leave
this variant with one architecture while the default image has two.

**None of it is needed by the native driver.** `internal/yubihsm` speaks the
device's SCP03 protocol over usbfs directly, with no libusb, no cgo and no
vendor code, and that is what reads the audit log and issues attestations
([native YubiHSM 2 driver](../hsm/yubihsm-native-driver.md)). What needs the
vendor module is the other half: **live signing goes through PKCS#11**, and
PKCS#11 needs Yubico's `.so`.

Point the config at the architecture-independent path — the image symlinks it
to whichever multiarch directory Debian used, so one value is right on `amd64`
and `arm64` alike:

```yaml
key_provider:
  type: "pkcs11"
pkcs11:
  module_path: "/usr/lib/pkcs11/yubihsm_pkcs11.so"
  pin_source: "env:SECSY_USER_PIN"
yubihsm:
  connector_url: "yhusb://"          # or http://127.0.0.1:12345 via the connector
```

Then pass the device through, and give the container an identity that may open
it. udev does not run inside a container: the node arrives with the ownership
the *host* gave it, and `--group-add` is how the image's non-root account joins
that group.

```bash
dev=$(readlink -f /dev/yubihsm 2>/dev/null || echo /dev/bus/usb/003/005)

docker run --rm \
  --device "$dev" \
  --group-add "$(stat -c %g "$dev")" \
  -v "$PWD/config.yaml:/etc/secsy/config.yaml:ro" \
  -e SECSY_USER_PIN \
  ghcr.io/blechschmidt/secsy-pki:1.2.3-yubihsm
```

`--device /dev/bus/usb` passes the whole bus instead, which survives the device
being re-enumerated at a new address but hands the container every USB device on
the machine. Prefer the specific node where you can.

For the host side of that — the udev rule the group comes from — take it out of
the image so the rule and the software that needs it stay the same version:

```bash
docker run --rm --entrypoint cat ghcr.io/blechschmidt/secsy-pki:1.2.3-yubihsm \
  /usr/share/secsy-pki/udev/70-yubihsm.rules | sudo tee /etc/udev/rules.d/70-yubihsm.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
```

**Only one process may hold the device's USB interface.** Inside this image both
the PKCS#11 module and the native driver want it, and so does anything else on
the host that has it open. If that bites, run `yubihsm-connector` — it is in the
image — and point `yubihsm.connector_url` and `pkcs11.module_path`'s connector
at `http://…:12345` instead. SCP03 terminates in the process and in the HSM, so
a connector in between can drop or reorder messages but cannot read a signing
request or alter an audit-log reply.

Check the device is reachable from inside the container before trusting a
config to it:

```bash
docker run --rm --device /dev/bus/usb --group-add … --entrypoint yubihsm-shell \
  ghcr.io/blechschmidt/secsy-pki:1.2.3-yubihsm --connector yhusb:// -a get-device-info
```

`--connector` is not optional there: `yubihsm-shell` defaults to a connector on
`http://127.0.0.1:12345`, so leaving it off reports a connection failure rather
than the absence of a device, which is a confusing way to learn that the device
is fine.

Or ask secsy-pki itself, which will also tell you whether the device is genuine:

```bash
docker run --rm --device /dev/bus/usb --group-add … --entrypoint secsy-ca \
  ghcr.io/blechschmidt/secsy-pki:1.2.3-yubihsm -config /etc/secsy/config.yaml \
  hsm-attest device
```

See [device attestation](../hsm/device-attestation.md) for what that proves.

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

For the variant, add `--expect-yubihsm`:

```bash
scripts/verify-published-image.sh --expect-yubihsm \
  --image ghcr.io/blechschmidt/secsy-pki:1.2.3-yubihsm
```

which additionally requires the vendor module to be present, to have every
shared library it needs resolvable, and to initialize far enough to state its
own identity — no HSM attached, because the failure being looked for happens in
the loader rather than at the device. Without the flag the same check runs
inverted: the default image must *not* carry the module, so the two tags cannot
quietly converge into one.

## How it is built

[`.github/workflows/container.yaml`](../../.github/workflows/container.yaml)
is the only workflow that builds the published image and the only one that
pushes it. It runs on **every commit on every branch**, on pull requests
(build and smoke-test only, never a push), weekly on Mondays, and by
`workflow_call` from the release workflow.

The weekly rebuild is not busywork: the image is `debian:bookworm-slim` plus
Debian's SoftHSM, OpenSC and `ca-certificates` — and, in the variant, Debian's
YubiHSM packages — all of which take security updates on their own schedule.
Without it, `edge` ages into whatever its base image was on the day it was built
— and for a PKI whose trust store is one of those packages, that ages badly.

Three jobs, in order:

1. **build and smoke-test** — no registry credential at all. Builds `amd64`,
   loads it, and runs the full verification script against it locally. Then
   builds both architectures to prove the arm64 cross-compile works, and runs
   the arm64 image under QEMU: a broken cross-link is a working amd64 image and
   an arm64 one that dies on start, and the index would carry both. Then all of
   that again for the `-yubihsm` variant, in the same job rather than a parallel
   one — the expensive half is the cgo compile of the whole Go tree, which is a
   stage both variants share and this job has just produced.
2. **push to ghcr.io** — the only job holding `packages: write`. Tags, pushes,
   signs, attests, then pulls its own push back by digest and runs it. Twice
   over, for the two manifests; the variant's tags come from the same rules plus
   a `flavor: suffix`, and a step refuses to push if the suffix ever stops being
   applied — a variant landing on `latest` is not something a later run can
   undo.
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
