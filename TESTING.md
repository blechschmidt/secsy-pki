# Testing secsy-pki

This document describes how to set up a local/CI test environment for
secsy-pki, in particular the **SoftHSM2** software HSM used to exercise the
PKCS#11 code paths without real hardware.

## Prerequisites

| Tool | Package (Debian/Ubuntu) | Purpose |
|------|-------------------------|---------|
| `softhsm2-util` | `softhsm2` | Software PKCS#11 HSM + token management |
| `pkcs11-tool`   | `opensc`   | Generic PKCS#11 CLI (slots, keys, objects) |
| Go 1.25         | —          | Build & run the server / tests |

Install on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y softhsm2 opensc
```

Other platforms:

- **RHEL/Fedora:** `sudo dnf install -y softhsm opensc`
- **macOS:** `brew install softhsm opensc`

## Quick start: initialize a SoftHSM token

Run the helper script from the repo root. It is **idempotent** — re-running it
reuses an existing token rather than creating a duplicate.

```bash
./scripts/setup-softhsm.sh
```

This will:

1. Locate the `libsofthsm2.so` PKCS#11 module (probes common paths).
2. Write a SoftHSM2 config to `/tmp/softhsm2.conf` pointing at a token store
   under `/tmp/softhsm/tokens`.
3. Initialize a token with a known label, SO PIN, and user PIN.
4. Verify the result with `pkcs11-tool --list-slots`.
5. Print the values you need to configure the server.

### Default token parameters

These defaults match the CI workflow (`.github/workflows/test.yaml`) and the
integration test config so local and CI runs behave identically.

| Setting | Value | Env override |
|---------|-------|--------------|
| Token label | `secsy-pki-root` | `SOFTHSM_TOKEN_LABEL` |
| User PIN | `1234` | `SOFTHSM_USER_PIN` |
| SO PIN | `5678` | `SOFTHSM_SO_PIN` |
| Token store dir | `/tmp/softhsm/tokens` | `SOFTHSM_TOKEN_DIR` |
| SoftHSM2 config | `/tmp/softhsm2.conf` | `SOFTHSM2_CONF` |
| PKCS#11 module | auto-detected | — |

> ⚠️ These PINs are **test-only** credentials. Never reuse them for a real
> HSM or production token.

### Overriding defaults

```bash
SOFTHSM_TOKEN_LABEL=my-token \
SOFTHSM_USER_PIN=9999 \
SOFTHSM_SO_PIN=0000 \
  ./scripts/setup-softhsm.sh
```

### Recreating a token from scratch

```bash
SOFTHSM_REINIT=1 ./scripts/setup-softhsm.sh
```

## Loading the environment into your shell

The server and `pkcs11-tool` need `SOFTHSM2_CONF` set. Export the generated
environment with:

```bash
eval "$(./scripts/setup-softhsm.sh --export-env)"
```

This sets:

- `SOFTHSM2_CONF` — path to the generated SoftHSM2 config
- `SECSY_PKCS11_MODULE` — detected path to `libsofthsm2.so`
- `SECSY_TOKEN_LABEL`, `SECSY_USER_PIN`, `SECSY_SO_PIN`

`--export-env` has no side effects (it does not initialize anything), so it is
safe to call from other scripts.

## Verifying the token manually

```bash
export SOFTHSM2_CONF=/tmp/softhsm2.conf

# List slots — the initialized token should appear with label "secsy-pki-root"
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-slots

# Log in and list objects (empty on a fresh token)
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
  --token-label secsy-pki-root --login --pin 1234 --list-objects
```

Expected `--list-slots` output includes:

```
  token label        : secsy-pki-root
  token manufacturer : SoftHSM project
  token model        : SoftHSM v2
  token flags        : login required, rng, token initialized, PIN initialized ...
```

### Generating a test key pair

To create an EC key pair on the token (as CI does):

```bash
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --login --pin 1234 \
  --keypairgen --key-type EC:prime256v1 --label "secsy-pki-root-ca-priv" --id 01
```

## Wiring SoftHSM into the server config

Point the server's `pkcs11` block at the SoftHSM module and token:

```yaml
pkcs11:
  module_path: "/usr/lib/softhsm/libsofthsm2.so"
  pin: "1234"
  token_label: "secsy-pki-root"
```

Ensure `SOFTHSM2_CONF` is exported in the environment where the server runs.

## Running the test suites

Unit tests:

```bash
cd server
go test -tags sqlite -count=1 ./internal/...
```

Authorization & tenant-isolation regression matrix (no HSM; software provider).
Drives every REST route and gRPC RPC through the real auth middleware and
asserts unauthenticated→401, no-capability→403, cross-tenant→refused, and
capable→success — and **fails if a newly registered route has no declared
RBAC/tenant intent**:

```bash
cd server
go test -tags sqlite -run 'AuthzMatrix|AuthenticateRPC' ./internal/handlers/ ./internal/grpcapi/
```

See [authz-regression-matrix.md](docs/authz-regression-matrix.md) for how to add
a route to the matrix.

Integration tests (spins up KeyCloak via Docker Compose, starts the server,
then runs the tagged tests):

```bash
cd server
./scripts/run-integration-tests.sh
```

Disaster-recovery drill (isolated SoftHSM sandbox; exercises the full key
ceremony → backup → simulated loss → restore → re-issuance lifecycle and asserts
key non-extractability):

```bash
./scripts/dr-drill.sh            # run the drill (cleans up on success)
DR_KEEP=1 ./scripts/dr-drill.sh  # keep the workspace to inspect artifacts
```

See [Key ceremony, backup & DR](docs/key-ceremony.md) for the ceremony checklist
and recovery runbook.

Fuzz tests (native `go test -fuzz` over the untrusted-input parsing surfaces —
CSR/DER decoding, ACME JOSE/JWS parsing, the secret envelope decrypt/unwrap
path, and OCSP/certificate parsing). One target runs per invocation, so a helper
enumerates them all:

```bash
cd server
./scripts/fuzz.sh                 # 30s per target (local default)
FUZZTIME=10m ./scripts/fuzz.sh    # long local campaign
./scripts/fuzz.sh ./internal/secret/ FuzzEnvelopeOpen   # a single target
```

Replaying just the seed corpora (fast, deterministic, reproduces committed
crashers) is a plain test run:

```bash
go test ./internal/pki/ ./internal/ca/ ./internal/acme/ ./internal/secret/
```

See [Fuzz & property testing](docs/fuzzing.md) for the full target inventory and
the workflow for handling a discovered crash.

External-client interop / conformance suite (stands up a live SoftHSM-backed
server and drives it with real third-party clients — acme.sh, `openssl cmp`, a
curl+openssl EST client, `openssl ocsp`, `openssl crl`, and `openssl ts` — to
catch protocol regressions that our own Go test client can miss):

```bash
./scripts/interop-test.sh            # run the whole suite (self-contained)
KEEP=1 ./scripts/interop-test.sh     # keep the work dir + client logs to inspect
```

It provisions everything it needs into a temporary directory (a root + issuing CA
on the token, a TSA key, a self-signed TLS cert, an EAB credential, a throwaway
config) and tears it down on exit; nothing is installed system-wide and no
privileged ports or `/etc/hosts` edits are required. ACME challenge validation is
made hermetic by a bundled authoritative DNS server (`internal/interop/dnsd`) the
server is pointed at via `acme.dns_resolver`. It needs `socat` (for acme.sh's
standalone/alpn responders), an `openssl` with `cmp`/`ts` support, and network
access to fetch a pinned `acme.sh`. Coverage: ACME http-01 / tls-alpn-01 / dns-01
/ EAB / ARI / IP identifiers, EST, CMP, OCSP good→revoked, base+delta CRLs, and
the RFC 3161 TSA. The suite records the client tool versions it used and exits
non-zero on any conformance failure.

## Static analysis (lint & vet)

An **HSM-free static-analysis gate** runs `go vet` and
[`golangci-lint`](https://golangci-lint.run/) over the server module. Run it
locally with the same targets CI uses:

```bash
make vet     # go vet -tags sqlite ./...
make lint    # golangci-lint run  (config: server/.golangci.yml)
make lint-fix  # golangci-lint run --fix — gofmt/goimports + safe autofixes
```

Both build with the `sqlite` tag so the SQLite persistence driver and everything
that depends on it type-check without an HSM present, and neither touches a
token — the gate is pure source analysis. `golangci-lint` is **version-pinned**
(`GOLANGCI_LINT_VERSION` in the root `Makefile`); if it is not already on `PATH`
the pinned version runs via `go run`, so `make lint` and CI can never drift. The
enabled linters and per-rule exclusions live in
[`server/.golangci.yml`](server/.golangci.yml); triaged suppressions carry an
inline `//nolint:<linter> // <reason>` explaining why.

In CI this is the **Static analysis** job in
`.github/workflows/enterprise-ci.yaml` — a required, no-HSM gate that runs
`make vet` then `make lint`. Keep the workflow's `GOLANGCI_LINT_VERSION` in
lockstep with the Makefile.

## Test-coverage gate

An **HSM-free, ratcheting coverage gate** measures Go statement coverage across
the `-tags sqlite` test subset and enforces a committed baseline that can only
**rise** — so coverage never silently regresses as the codebase grows. It is the
coverage analogue of the [benchmark-regression gate](docs/benchmarks.md#benchmark-regression-gate)
and, like it, is driven entirely from the `Makefile`:

```bash
make cover         # run the HSM-free test subset with -coverprofile and emit
                   #   dist/coverage.out, dist/coverage.html (browsable), and
                   #   dist/coverage-summary.txt (per-package + total table)
make cover-check   # run `cover`, then ratchet against coverage/baseline.txt —
                   #   FAILS the build if total or any package dropped, listing
                   #   which packages regressed
make cover-baseline  # regenerate coverage/baseline.txt after you add covered code
```

**How it measures.** `make cover` runs `go test -tags sqlite -covermode=set
-coverprofile ./internal/...` **without a token**, so HSM-backed tests skip
cleanly and each package contributes only its HSM-free reachable coverage — a
deterministic subset. Per-package and total percentages are computed straight
from the profile by `scripts/cover-check.sh` and match Go's own
`coverage: N% of statements` numbers exactly. Running with a SoftHSM token loaded
only *raises* coverage, which never trips the ratchet.

**The ratchet.** `make cover-check` compares the current run against
`coverage/baseline.txt`. A package fails the gate only when its coverage drops
**more than `COVER_TOLERANCE` (default 1.0) percentage points** below its
baseline entry. That small band absorbs the sub-1pp run-to-run jitter of a few
timing/goroutine-sensitive packages — the total itself is stable — exactly as
benchstat's `~` band absorbs benchmark noise, so the gate fails only on a real,
repeatable drop. New packages (absent from the baseline) never fail it; removed
packages are reported but do not fail it.

**Updating the baseline when you add covered code.** When you add tests, or add
code that your tests exercise, coverage goes *up* — refresh the baseline so the
gate's floor moves up with the improvement, and commit it in the **same** change:

```bash
scripts/cover-baseline.sh      # or: make cover-baseline
git add coverage/baseline.txt
```

`scripts/cover-baseline.sh` clears any SoftHSM/PKCS#11 environment before
measuring, so the committed baseline is always the reproducible **HSM-free floor**
regardless of what is loaded in your shell (a token would otherwise inflate it and
make the HSM-free CI gate fail). If `make cover-check` fails on a drop you
*intended* (e.g. you deleted dead code that happened to have tests), the fix is
the same: refresh and commit the baseline — the failure message says so.

In CI this is the required, no-HSM **Test-coverage ratchet gate** job in
`.github/workflows/enterprise-ci.yaml`. It runs `make cover-check` on every push
and PR (no SoftHSM, no Postgres — matching the environment the baseline is
generated in), writes the per-package ratchet table to the GitHub **step
summary**, and uploads the HTML report + summary as build **artifacts** (even on
failure) so a drop can be inspected line-by-line. Because absolute coverage is
largely machine-independent the gate blocks merges; if the runner class ever
diverges from the committed baseline, regenerate it authoritatively on the runner
by dispatching the workflow with **`refresh_coverage_baseline: true`** (it uploads
the fresh `coverage/baseline.txt` as an artifact to download and commit). See
[docs/coverage.md](docs/coverage.md) for the full reference.

## CI

The GitHub Actions workflow (`.github/workflows/test.yaml`) installs
`softhsm2` and `opensc`, initializes the same `secsy-pki-root` token, runs unit
and integration tests, and builds all binaries. Keeping local defaults aligned
with CI means "works on my machine" and "works in CI" stay in sync.

The enterprise workflow (`.github/workflows/enterprise-ci.yaml`) additionally
runs a `fuzz-smoke` job: it replays the fuzz seed corpora as unit tests and then
runs each fuzz target for a bounded `FUZZTIME`. It needs no SoftHSM (all targets
run in software). See [Fuzz & property testing](docs/fuzzing.md).

The same enterprise workflow runs an advisory (`continue-on-error`, not required
for merge) `interop-conformance` job — modeled on the chaos job — that installs
`softhsm2`, `opensc`, and `socat` and runs `scripts/interop-test.sh` against a
live server. It is advisory because it depends on external tooling (a pinned
`acme.sh` checkout from GitHub, `socat`, the host `openssl`'s cmp/ts support), so
a red run is a signal to investigate rather than a merge blocker.

## Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| `pkcs11-tool: not found` | Install the `opensc` package. |
| `ERROR: Could not locate libsofthsm2.so` | Install `softhsm2`; if the module lives elsewhere, add its path to `find_module()` in the script. |
| `CKR_PIN_INCORRECT` on login | Wrong user PIN; default is `1234`. Recreate with `SOFTHSM_REINIT=1`. |
| Token not visible to the server | `SOFTHSM2_CONF` not exported in the server's environment. |
| Stale/corrupt token | `SOFTHSM_REINIT=1 ./scripts/setup-softhsm.sh` to wipe & recreate. |
