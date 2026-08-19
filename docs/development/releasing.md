# Releasing

How a version tag becomes a signed image, a set of binaries and a GitHub
release — and what refuses to let it.

- [Cutting a release](#cutting-a-release)
- [What the tag sets off](#what-the-tag-sets-off)
- [The guard](#the-guard)
- [The release archives](#the-release-archives)
- [Rehearsing without a tag](#rehearsing-without-a-tag)
- [When it goes wrong](#when-it-goes-wrong)

See [the container image](../deployment/container.md) for the image the release
publishes and [supply-chain security](supply-chain.md) for what each signature
and attestation asserts.

## Cutting a release

1. **Write the changelog section.** In [`CHANGELOG.md`](../../CHANGELOG.md), move
   the `## [Unreleased]` entries into a dated section of their own:

   ```markdown
   ## [1.3.0] - 2026-09-01

   ### Added
   - …
   ```

   This is not bookkeeping. That section *is* the body of the GitHub release,
   and the guard refuses a tag that has no dated, non-empty section of its own.

2. **Rehearse it.** `make release-guard` checks the same facts the tag will,
   taking the version from the newest changelog section instead of from a tag.

3. **Tag and push.**

   ```bash
   git tag -a v1.3.0 -m "v1.3.0"
   git push origin v1.3.0
   ```

Versions are [semantic](https://semver.org/), tags are the version prefixed with
`v`, and a pre-release is `v1.3.0-rc.1`. A pre-release gets its version and
minor image tags but never `latest`.

**Before the very first release**, check that the GHCR package is public. GHCR
creates it private on its first push and nothing in CI flips it; the
`verify it from outside` job is what detects that, and on a first release it
would fail *after* the image had been pushed and signed — leaving a published
`1.0.0` with no release attached to it. A branch push publishes `edge` and
creates the package, so make it public there and the tag has nothing to trip
over.

## What the tag sets off

[`.github/workflows/release.yaml`](../../.github/workflows/release.yaml), which
is ordered so that everything cheap and reversible happens before anything
expensive or permanent. A pushed image tag, a GitHub release and a signature in
a public transparency log cannot be taken back.

| Job | What it does | Blocks on |
|-----|--------------|-----------|
| `guard` | The tag, the changelog and `go.mod` agree | — |
| `ci` | The whole SoftHSM suite, at this commit | `guard` |
| `govulncheck` | A called vulnerability stops the release | `guard` |
| `binaries` | The release archives, plus the Go-module SBOM | both gates |
| `verify` | The archives, unpacked and run as a user gets them | `binaries` |
| `image` | Calls `container.yaml`: build, push, sign, attest, verify | `verify` |
| `provenance-image` | SLSA Build L3 on the image | `image` |
| `provenance-archives` | GitHub build provenance on the tarballs | `verify` |
| `github-release` | The release itself, last | everything |

Two points are easy to miss.

**The CI suite is *called*, not assumed.** A `v*` tag does not match
`enterprise-ci.yaml`'s branch filter, so nothing else would run it for a
release. Without that call, a tag would publish on the strength of the branch
having been green at some earlier commit. The four advisory suites stay
skipped — they ask for `schedule` or `workflow_dispatch`, and a called run
reports the caller's event — so a release pays for the nine required gates and
not the nightly-only half.

**The release builds no image of its own.** It calls
[`container.yaml`](../deployment/container.md#how-it-is-built), the same
workflow that builds every branch, passing only what that workflow cannot work
out for itself: whether to push, whether this version may take `latest`, and the
version to stamp. The image *tags* are not passed — they are read off the ref
inside it, so the tag that triggered the release is their single source and
cannot disagree with an argument passed alongside it. This is also what stops
two workflows racing to push `1.2.3` from two separate builds of the same
commit.

## The guard

[`scripts/release-guard.sh`](../../scripts/release-guard.sh) runs first, on a
checkout and nothing else, and checks four things:

1. The tag is a semantic version — `vX.Y.Z`, optionally `-<prerelease>`.
2. `CHANGELOG.md` has a dated, non-empty section for exactly that version, and
   it is the newest one.
3. The released sections descend, which is how a version that goes backwards is
   caught.
4. `server/go.mod`'s module path matches the repository the run is on. Both
   `go install` and the cosign keyless identity key off that path, so a
   repository renamed or forked without updating `go.mod` produces artifacts
   that fail to install and signatures that fail to verify — a fact that
   otherwise surfaces only after the publish, which is the one place it cannot
   be fixed.

Semantic-version comparison is implemented rather than approximated: `sort -V`
orders `1.2.3` before `1.2.3-rc.1`, and semver says a pre-release *precedes* its
release. Getting that backwards would let a release candidate be published as
newer than the release it was a candidate for.

The rules have their own test suite,
[`scripts/release-guard-test.sh`](../../scripts/release-guard-test.sh), which
drives the guard against deliberately broken changelogs — an undated section, a
version that is not the newest, sections that do not descend, `1.10.0` against
`1.9.0`. A guard exercised only by the release it guards is not a guard. Run it
with `make release-guard-test`.

## The release archives

`secsy-pki_<version>_linux_amd64.tar.gz` and `…_linux_arm64.tar.gz`, each
carrying all six commands plus `LICENSE`, `README.md` and `CHANGELOG.md`, with a
`SHA256SUMS` alongside.

They come out of **the image's own Dockerfile** (`--target artifacts`), not a
second build definition of their own. The released `secsy-ca` and the `secsy-ca`
inside the published container are therefore the same binary, compiled with the
same build tags, the same ldflags and against the same glibc — rather than two
builds that agree only until someone edits one of them. It also fixes the
floor at bookworm's **glibc 2.36**, so the binaries run on Debian 12, RHEL 9,
Ubuntu 22.04 and anything newer; a binary built on the CI runner's own Ubuntu
24.04 would demand glibc 2.39 and fail on all three.

cgo is not optional here — `miekg/pkcs11` is a C binding and the SQLite driver
links `libsqlite3` — so "just set `GOOS`/`GOARCH`" does not build these. The
Dockerfile carries the cross toolchain instead, which is why
[`scripts/build-release-binaries.sh`](../../scripts/build-release-binaries.sh)
talks to buildx rather than to `go build`.

Archives are reproducible: `SOURCE_DATE_EPOCH` (the commit date, unless set) and
a sorted, owner-normalized tar, so the same input gives the same bytes and the
checksums mean something when someone rebuilds a tag to compare.

Build them locally with `make release-binaries`. Each platform is *run* before
it is packaged — under QEMU for the foreign one — and must report the version
being released; a tarball of something that does not start is the release-day
failure that catches.

## Rehearsing without a tag

Dispatch *release* from the Actions tab. Everything happens except the pushing:
the guard takes the version from the newest changelog section, the CI suite and
the vulnerability scan run, the archives are built and unpacked and run, and the
image is built and smoke-tested on both architectures but not pushed. The
`provenance-*` and `github-release` jobs are skipped.

So a dry run checks exactly what the next tag will check, without publishing
anything.

## When it goes wrong

**The guard failed.** Nothing was published — that is the point of it running
first. Fix the changelog, delete and re-push the tag.

**A later job failed.** Work out whether anything was published before deciding
what to do. `image` is the first job that makes anything public.

- Before `image` succeeded: nothing is public. Delete the tag, fix, re-tag.
- After it: the image and its signature exist and the transparency-log entry is
  permanent. Do **not** re-use the version — publish the fix as a new patch
  version. Re-running the workflow on the same tag will update the GitHub
  release in place (`gh release edit` / `upload --clobber`), which is the
  intended path for a failure in `github-release` alone.

**The published image is not pullable.** The `verify it from outside` job is
what detects this, and the usual cause is GHCR having created the package
**private** on its first push. No workflow flips that; change it in the
package's settings on GitHub. See
[the container image](../deployment/container.md#verifying-it-before-you-run-it).

---

↩ Back to [development, testing & release](README.md) · [documentation map](../README.md)
