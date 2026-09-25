# The container image

The published image: which tag to pull, what is in it, how to run it, and how to
check it is the one this repository built.

- [Where it is published](#where-it-is-published)
- [Which tag to use](#which-tag-to-use)
- [What is in it](#what-is-in-it)
- [First run](#first-run) — from `docker pull` to an issued certificate
- [Configuring it](#configuring-it) — paths, state, environment
- [Running the CLI tools](#running-the-cli-tools)
- [Running a stack with Compose](#running-a-stack-with-compose)
- [Health, readiness and metrics](#health-readiness-and-metrics)
- [Upgrading](#upgrading)
- [The YubiHSM variant](#the-yubihsm-variant)
- [Verifying it before you run it](#verifying-it-before-you-run-it)
- [Troubleshooting](#troubleshooting)
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

## First run

Just to see what a tag is, no config needed:

```bash
docker run --rm ghcr.io/blechschmidt/secsy-pki:1.2.3 -version
# secsy-pki-server 1.2.3 go1.25.13 fips140=off policy=off
```

Anything beyond that needs two things the image cannot invent for you: **a
config** and **a CA**. The server does not create a CA on startup — it loads the
one its config names and fails to start if that CA is missing. That is
deliberate: a PKI that mints a trust anchor by itself on boot is not one you can
reason about afterwards. So a first run is *provision, then serve*.

The fastest honest path is [the Compose stack](#running-a-stack-with-compose),
which does exactly this in two services. What follows is the same thing by hand,
so the pieces are visible.

**1. A config.** Container paths, not host paths — `/app/data` and
`/var/lib/softhsm/tokens` are the two directories the image prepares for its
non-root user:

```yaml
# config.yaml
server:
  host: "0.0.0.0"
  port: 8443
  tls:
    self_issue:                    # HTTPS with no key on disk; see below
      enabled: true
      ca_id: "issuing-ca"
      dnsnames: ["localhost"]
database:
  driver: "sqlite"
  dsn: "/app/data/secsy-pki.db"    # must be inside the volume
root_user:
  username: "root"                 # password comes from SECSY_ROOT_PASSWORD
key_provider:
  type: "pkcs11"
pkcs11:
  module_path: "/usr/lib/softhsm/libsofthsm2.so"
  token_label: "secsy"
  pin_source:
    type: "env"
    env:
      var: "SECSY_USER_PIN"
```

**2. Provision the token and the CAs.** One container, with the volumes the
server will later use, running the CLI instead of the server:

```bash
docker volume create secsy-data && docker volume create secsy-tokens

docker run --rm \
  -v secsy-data:/app/data -v secsy-tokens:/var/lib/softhsm/tokens \
  -v "$PWD/config.yaml:/etc/secsy/config.yaml:ro" \
  -e SECSY_USER_PIN -e SECSY_SO_PIN -e SECSY_ROOT_PASSWORD \
  --entrypoint bash ghcr.io/blechschmidt/secsy-pki:1.2.3 -c '
    softhsm2-util --init-token --free --label secsy \
      --pin "$SECSY_USER_PIN" --so-pin "$SECSY_SO_PIN"
    secsy-ca -config /etc/secsy/config.yaml init-root \
      -label root-ca -cn "Demo Root CA" -key-type ecdsa-p384
    secsy-ca -config /etc/secsy/config.yaml issue-intermediate \
      -parent root-ca -label issuing-ca -cn "Demo Issuing CA"
  '
```

SoftHSM is used here because it ships in the image and needs no hardware. It is
**not** for production: its "HSM" is a directory of files in that volume. On real
hardware the token already exists and provisioning it is a
[key ceremony](../hsm/key-ceremony.md), not a container entrypoint — so only the
two `secsy-ca` steps apply, against a mounted vendor module.

**3. Serve.** The entrypoint already points at `/etc/secsy/config.yaml`, so there
is nothing to pass:

```bash
docker run -d --name secsy-pki \
  -v secsy-data:/app/data -v secsy-tokens:/var/lib/softhsm/tokens \
  -v "$PWD/config.yaml:/etc/secsy/config.yaml:ro" \
  -e SECSY_USER_PIN -e SECSY_ROOT_PASSWORD \
  -p 8443:8443 \
  ghcr.io/blechschmidt/secsy-pki:1.2.3
```

`server.tls.self_issue` above means the listener certificate is issued from
`issuing-ca` at startup, its private key stays inside the token, and it
auto-rotates — so there is no cert/key pair to mount and no key on disk
([self-managed serving certificate](serving-cert.md)). The log says so:

```
serving-tls: issued initial serving certificate serial=… cn="localhost" … (key in provider, label="serving-tls-issuing-ca")
Starting HTTPS server on 0.0.0.0:8443
```

**4. Talk to it.** The serving certificate is signed by *this* PKI, so clients
need its root — which is fetched out of band, from the container, rather than
over the connection you are trying to authenticate:

```bash
docker exec secsy-pki secsy-ca -config /etc/secsy/config.yaml \
  publish-chain -ca root-ca > root.pem

curl --cacert root.pem https://localhost:8443/healthz
# {"build":{…,"version":"1.2.3"},"status":"ok"}
```

Then issue something. `GET /api/keys` lists the CAs, and the issuing CA's **id**
— not its label — goes in the path:

```bash
openssl req -new -newkey ec:<(openssl ecparam -name prime256v1) -nodes \
  -keyout app.key -subj "/CN=app.internal.example" -out app.csr

CA_ID=$(curl -s --cacert root.pem -u root:"$SECSY_ROOT_PASSWORD" \
  https://localhost:8443/api/keys | jq -r '.[] | select(.label=="issuing-ca") | .id')

curl --cacert root.pem -u root:"$SECSY_ROOT_PASSWORD" \
  -H 'Content-Type: application/json' \
  -d "$(jq -Rn --rawfile csr app.csr '{csr:$csr, profile:"server", validity_days:30}')" \
  "https://localhost:8443/api/ca/$CA_ID/issue"
# {"certificate":"-----BEGIN CERTIFICATE-----\n…"}
```

That certificate was signed on the HSM. The rest of the API documents itself
at `/api/docs` (and `/openapi.json`) on the same port, where the web console also
lives at `/`.

A **FIPS 140-3** image is a separate build — `make image-fips` — because the
check that the binary reports `fips140=on` has to run the binary, which a
cross-build cannot do. See [FIPS mode](../security/fips.md).

## Configuring it

### Where the config goes

| Path | Who reads it |
|------|--------------|
| `/etc/secsy/config.yaml` | The server. The entrypoint's `CMD` is `-config /etc/secsy/config.yaml`, so mounting it there needs no arguments |
| `/app/config.yaml` | Nobody by default — but it is where `secsy-ca`/`secsy-secret` look when given no `-config`, because their default is the relative path `config.yaml` and the working directory is `/app` |

The CLIs do **not** inherit the server's config path. `docker run --entrypoint
secsy-ca … list` fails with `open config.yaml: no such file or directory` until
you either pass `-config /etc/secsy/config.yaml` (as every example here does) or
mount the file at `/app/config.yaml` as well.

### What has to persist

| Path | Contents | If you lose it |
|------|----------|----------------|
| `/app/data` | The SQLite database: CA records, every issued certificate, revocations, the hash-chained audit log | The keys survive but the PKI's memory does not — no CRLs, no revocation state, no audit chain |
| `/var/lib/softhsm/tokens` | **SoftHSM only:** the CA private keys | The CAs are gone. Irrelevant on a real HSM, where keys never leave the device |

Anything written elsewhere lands in the container's writable layer and is
discarded when the container is replaced — silently, because the write succeeds.
A relative `database.dsn` is the usual way to get this wrong: it resolves against
`/app`, not `/app/data`.

On PostgreSQL the database volume is not needed at all; see
[persistence backends](persistence.md).

### Settings from the environment

A container is configured by environment, and the config file is often baked
before the deployment knows the values. These variables **override** the file, so
credentials need not be in it. This is the subset that matters in a container;
`applyEnvOverrides` in `server/internal/config/config.go` is the full list:

| Variable | Overrides | Notes |
|----------|-----------|-------|
| `SECSY_USER_PIN` | `pkcs11.pin` | The HSM user PIN. Prefer a `pin_source` block for anything long-lived — [PIN sourcing](../hsm/configuration.md#sourcing-the-user-pin-from-a-credential-store-pin_source) reads it from Vault, a cloud secrets manager or a mode-0600 file |
| `SECSY_ROOT_PASSWORD` | `root_user.password` | Required unless the file sets it: the config refuses to load with neither, so a deployment cannot silently come up without a superuser password |
| `SECSY_DATABASE_DRIVER`, `SECSY_DATABASE_DSN` | `database.driver`, `database.dsn` | The DSN carries PostgreSQL credentials, which is why it belongs here rather than in a mounted file |
| `SECSY_DATABASE_MAX_OPEN_CONNS`, `…_MAX_IDLE_CONNS` | the connection pool | PostgreSQL only |
| `SECSY_KEY_PROVIDER` (`…_CA`, `…_TSA`, `…_SIGNING`) | `key_provider.type` and the per-role providers | |
| `SECSY_PKCS11_MODULE`, `SECSY_TOKEN_LABEL`, `SECSY_TOKEN_SERIAL` | the PKCS#11 module and token selection | Point the image at a mounted vendor module without editing YAML |
| `SECSY_PKCS11_SESSION_POOL_SIZE`, `…_SELECTION_POLICY`, `…_FAILURE_THRESHOLD` | session pool and [HSM failover](../hsm/high-availability.md) | |
| `SECSY_KMS_*`, `VAULT_ADDR`/`VAULT_TOKEN`, `SECSY_VAULT_ROLE_ID`/`…_SECRET_ID` | the [cloud-KMS](../hsm/cloud-kms.md) and [Vault Transit](../hsm/vault-transit.md) backends | Cloud credentials themselves come from the SDK's own chain, never from config |
| `SECSY_ACME_*`, `SECSY_MONITOR_*` | the [ACME server](../protocols/acme.md) and [expiry monitor](../operations/expiry-monitoring.md) | Enable/disable and retarget without a config edit |
| `SECSY_SERVER_UNIX_SOCKET`, `SECSY_GRPC_UNIX_SOCKET` | the listener paths | A runtime often knows the mounted socket path long after the config was written ([Unix sockets](unix-socket.md)) |
| `SECSY_ALLOW_INSECURE_HTTP` | nothing — it is a guard | Set to `1`, `true` or `yes` to serve the API in **cleartext**. Only for a trusted TLS-terminating proxy on the same pod/host; without it the server refuses to start with no `tls_cert`, and with it it logs a warning on every start |
| `SOFTHSM2_CONF` | — | Preset to `/etc/softhsm/softhsm2.conf`. The Debian package's own config is unreadable to non-root, so the image ships a world-readable one pointing at `/var/lib/softhsm/tokens` |

`pin_source` is a **block**, not a string:

```yaml
pkcs11:
  pin_source:
    type: "env"        # or file | vault | aws | azure | gcp
    env:
      var: "SECSY_USER_PIN"
```

A bare `pin_source: "env:SECSY_USER_PIN"` does not parse, and the server exits
with `cannot unmarshal !!str into config.PinSourceConfig`.

## Running the CLI tools

All six commands are on `PATH`, so the entrypoint is what changes. Against a
**running** deployment, use the container that is already configured:

```bash
docker exec secsy-pki secsy-ca -config /etc/secsy/config.yaml doctor
docker exec secsy-pki secsy-ca -config /etc/secsy/config.yaml list
docker compose exec server secsy-ca -config /etc/secsy/config.yaml expiring -days 30
```

That reuses the running container's mounts, PIN and database, so there is no
second copy of the configuration to keep in step.

For a deployment that is **not** running — provisioning, migrations, disaster
recovery — a one-shot container with the same volumes:

```bash
docker run --rm \
  -v secsy-data:/app/data -v secsy-tokens:/var/lib/softhsm/tokens \
  -v "$PWD/config.yaml:/etc/secsy/config.yaml:ro" \
  -e SECSY_USER_PIN -e SECSY_ROOT_PASSWORD \
  --entrypoint secsy-ca ghcr.io/blechschmidt/secsy-pki:1.2.3 \
  -config /etc/secsy/config.yaml list
```

A one-shot container works while the server is running too — SQLite serializes
writers and PostgreSQL has no such constraint — but it needs its own copy of the
config and PIN, which is the part that drifts. Prefer `exec`.

Two things need more than a volume:

- **Piping a CSR in** needs `docker run -i` (or `exec -T`), otherwise `-csr -`
  reads an empty stdin:
  `docker exec -i secsy-pki secsy-ca -config … issue -ca issuing-ca -csr - < app.csr`
- **`secsy-verify` and `hsm-audit verify`** are the auditor's tools and take no
  config, database or HSM at all — mount the bundle and nothing else, which is
  what makes them verifiable by someone who does not run the PKI
  ([remotely verifiable auditing](../hsm/audit-log.md)).

## Running a stack with Compose

[`deploy/compose/`](../../deploy/compose/) is a working stack — the one the
examples above were verified against:

```bash
cd deploy/compose
cp .env.example .env        # then change the PIN and the passwords
docker compose up -d
docker compose logs -f server
```

Two services. `bootstrap` provisions the token and the CA hierarchy and exits;
`server` waits for it with `condition: service_completed_successfully`, so a
failed bootstrap fails the `up` instead of producing a server that crash-loops
looking for a CA that was never created. Every step of the bootstrap is guarded
against the real state — the token store and the database, not a marker file — so
`up` is repeatable and a restart never touches an existing key:

```
== PKCS#11 token 'secsy'
   already initialized
== root CA 'root-ca'
   already exists
```

PostgreSQL instead of SQLite is an overlay, which changes no YAML — the driver
and DSN come from the environment:

```bash
docker compose -f docker-compose.yaml -f docker-compose.postgres.yaml up -d
```

Same file with a managed database: drop the `db` service and set
`SECSY_DATABASE_DSN` in `.env`. PostgreSQL is also what multiple replicas
require, because it carries the advisory-lock leader election that keeps
singleton background jobs singleton — [multi-replica coordination](high-availability.md).

## Health, readiness and metrics

Three unauthenticated endpoints on the main listener. They expose no key material
and monitoring systems scrape them before any user context exists; restrict them
at the network layer if that matters to you.

| Endpoint | Meaning |
|----------|---------|
| `/healthz` | The process is alive. Also reports the build: version, Go runtime, FIPS posture |
| `/readyz` | It can actually serve: database reachable and key provider usable — 503 until both are. Also reports whether this replica holds background-job leadership, which never affects readiness (a follower serves traffic normally) |
| `/metrics` | Prometheus exposition — ~150 series, including `secsy_component_up` per subsystem ([metrics & monitoring](../operations/observability.md)) |

`/readyz` is the one to gate traffic on. The Helm chart wires both as probes
([Kubernetes deployment](kubernetes.md)); for Docker, note that **the image has
no `curl` or `wget`** — it is a PKI, not a toolbox. `openssl` is present, because
the SoftHSM and OpenSC tooling needs it, and it can speak enough HTTP for a
probe:

```yaml
healthcheck:
  test:
    - "CMD-SHELL"
    - |
      printf 'GET /readyz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n' \
        | openssl s_client -quiet -connect 127.0.0.1:8443 2>/dev/null \
        | grep -q '200 OK'
  interval: 10s
  timeout: 5s
  start_period: 30s     # the first serving certificate is issued on the HSM
```

The alternative is `secsy-ca doctor`, which checks far more — config, HSM, keys,
database, audit chain, CRL freshness, clock — and exits 0/1/2. It is the right
thing for a periodic check and too heavy for a 10-second probe.

## Upgrading

The state lives in volumes and the image is stateless, so an upgrade is a
replacement:

```bash
docker compose pull && docker compose up -d
```

Schema migrations run automatically on first connection. Two things follow from
that:

- **Take a backup first** for anything you care about — `secsy-ca backup`, or the
  [scheduled encrypted backups](../operations/backup.md) if they are
  already running. A migration is forward-only; rolling the image back to a tag
  that predates it means restoring.
- **Pin the tag.** `latest` moves under you, and an upgrade you did not choose is
  one you did not back up for. The tag table [above](#which-tag-to-use) says
  which tags are immutable.

For the multi-replica case, and for what happens to in-flight background jobs
when the leader is replaced, see [multi-replica coordination](high-availability.md).

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
| `libykhsmauth` | YubiKey-held authentication keys, which the module links against |
| `yubihsm-shell`, `yubihsm-wrap`, `yubihsm-auth` | Vendor CLIs, for working on the device by hand |
| `yubihsm-connector` | The USB-to-HTTP bridge, when the device must be shared |
| `/usr/share/secsy-pki/udev/70-yubihsm.rules` | The host udev rule, shipped to be copied out |

Roughly 16 MB on top of the default image.

### Built from upstream source, not from Debian

Everything in that table except `yubihsm-connector` is compiled during the image
build from Yubico's own [`yubihsm-shell`](https://developers.yubico.com/yubihsm-shell/)
release tarball, for both architectures. The version built is recorded in the
image:

```console
$ docker run --rm --entrypoint cat ghcr.io/blechschmidt/secsy-pki:1.2.3-yubihsm \
    /usr/share/secsy-pki/yubihsm-shell-version
2.8.0
```

It used to come from `bookworm-backports`, which carries **2.6.0** — two minor
releases behind, and what is in between is not cosmetic for a CA. From upstream's
changelog: 2.7.2 fixes a PKCS#11 bug where generating an RSA key pair "can
potentially result in the wrong type of object being created" and stops command
audit being enabled for command `0x05` — the audit subsystem
[this project reads and pins](../hsm/audit-log.md); 2.7.3 fixes capabilities on
public wrap keys; 2.8.0 adds YubiKey-held session authentication. `bookworm`
proper has no `yubihsm` packages at all, so staying with Debian meant staying on
backports' schedule for the single package this tag exists to provide, and left
the vendor module the oldest thing in the image.

Building from source gives up Debian's security tracking of that package, so the
provenance is replaced rather than dropped. The build:

1. downloads the release tarball named by `YUBIHSM_SHELL_VERSION` in the
   `Dockerfile`, and checks it against the **SHA-256 digest** pinned beside it;
2. verifies Yubico's **detached OpenPGP signature** over those same bytes against
   the key vendored at `deploy/yubihsm/yubico-release-signing-key.asc`, requiring
   the signature to come from the fingerprint pinned in the `Dockerfile` — so
   replacing the key file does not replace the trust anchor;
3. cross-compiles it with cmake for the target architecture and installs it under
   `/usr/local`, stripped.

The digest says nothing about who produced the bytes and the signature says
nothing about which release was wanted, so both are checked. The weekly rebuild
still refreshes the libcrypto, libcurl and libusb it links against, because those
come from the base image; picking up a **new upstream release** is a
`YUBIHSM_SHELL_VERSION` bump in a commit, not something that happens on its own.

The image SBOM is catalogued from `dpkg`, which knows nothing about a source
build, so the same facts are carried as labels for anything reading the image
from outside:

```console
$ docker image inspect ghcr.io/blechschmidt/secsy-pki:1.2.3-yubihsm \
    --format '{{json .Config.Labels}}' | jq 'with_entries(select(.key|startswith("io.secsy-pki")))'
{
  "io.secsy-pki.yubihsm-shell.version": "2.8.0",
  "io.secsy-pki.yubihsm-shell.sha256": "627a06899096f8bc81a806ef415e00cf7f08a3fc38f4b6b3f39b8129e64dd481",
  "io.secsy-pki.yubihsm-shell.source": "https://developers.yubico.com/yubihsm-shell/Releases/yubihsm-shell-2.8.0.tar.gz"
}
```

`scripts/verify-published-image.sh --expect-yubihsm` holds all of it together: it
loads the module, reads the version back out of `C_GetInfo`, and requires it, the
`yubihsm-shell` binary and the label to agree with what the build recorded — which
is what would catch a silent fall back to the distribution package.

To build a one-off image against a different release:

```bash
docker build --target runtime-yubihsm \
  --build-arg YUBIHSM_SHELL_VERSION=2.8.1 \
  --build-arg YUBIHSM_SHELL_SHA256=<sha256 of yubihsm-shell-2.8.1.tar.gz> \
  -t secsy-pki:local-yubihsm .
```

`yubihsm-connector` stays on `bookworm-backports`: it is a separate upstream
project, a small Go daemon whose version does not have to match the module's.

**None of this is needed by the native driver.** `internal/yubihsm` speaks the
device's SCP03 protocol over usbfs directly, with no libusb, no cgo and no
vendor code, and that is what reads the audit log and issues attestations
([native YubiHSM 2 driver](../hsm/yubihsm-native-driver.md)). What needs the
vendor module is the other half: **live signing goes through PKCS#11**, and
PKCS#11 needs Yubico's `.so`.

### Pointing the config at it

The module is installed at `/usr/local/lib/pkcs11/yubihsm_pkcs11.so` and
symlinked to the architecture-independent path below, which is the one to
configure — it is correct on `amd64` and `arm64` alike:

```yaml
key_provider:
  type: "pkcs11"
pkcs11:
  module_path: "/usr/lib/pkcs11/yubihsm_pkcs11.so"
  pin_source:
    type: "env"
    env:
      var: "SECSY_USER_PIN"
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

## Troubleshooting

Every entry here is a failure the container produces on the way to a working
deployment, with the message it actually prints.

**`Failed to load config: … cannot unmarshal !!str into config.PinSourceConfig`**
— `pin_source` was given a string. It is a block with a `type`; see
[settings from the environment](#settings-from-the-environment).

**`error: loading config: root_user.password is required`** — neither
`root_user.password` nor `SECSY_ROOT_PASSWORD` is set. The config fails closed
rather than starting without a superuser password.

**`error: loading config: reading config: open config.yaml: no such file or
directory`** — a CLI invocation with no `-config`. The CLIs default to the
relative path `config.yaml` in `/app`; only the server's entrypoint knows about
`/etc/secsy/config.yaml`. See [where the config goes](#where-the-config-goes).

**`configuring self-issued serving certificate: … CA "…" not found`** — the CA
named by `server.tls.self_issue.ca_id` does not exist yet. The bootstrap has to
run before the server: this is the fail-closed refusal working, not a bug. Check
`secsy-ca … list` and that the CLI and the server are pointed at the *same*
database.

**`failed to bind host port 0.0.0.0:8443: address already in use`** — something
else on the host has the port. Publish a different one; the Compose stack takes
`SECSY_HTTPS_PORT`.

**`curl: (60) SSL certificate problem: self-signed certificate in certificate
chain`** — expected. The listener certificate is issued by your own PKI, so curl
needs its root: `--cacert root.pem`, fetched out of band as in
[first run](#first-run). Reaching for `-k` throws away the property the PKI
exists to provide.

**The container starts, then exits with no message** — look for a `Failed to
load config` line in `docker logs`; a config error happens before anything else
and exits immediately. `secsy-ca … doctor` diagnoses the rest (HSM reachable,
keys present, database writable, clock sane).

**Writes appear to work but vanish on restart** — state was written outside
`/app/data` (or, for SoftHSM, `/var/lib/softhsm/tokens`) and went to the
container's writable layer. A relative `database.dsn` is the usual cause:
[what has to persist](#what-has-to-persist).

**`Permission denied` on a mounted path** — the image runs as uid 65532. A host
directory bind-mounted for state has to be writable by that uid; a named volume
inherits the image's ownership and avoids the question entirely.

**`opening issuer signer: no token found matching label="…"`** — the token name
in the config does not match the one on the device, or the tokens volume is not
mounted. Note that commands which only read the database (`list`, `list-certs`)
succeed anyway; the error appears on the first operation that needs the key. With
SoftHSM, `docker exec … softhsm2-util --show-slots` lists what is really there.

**On a YubiHSM: the module loads but cannot reach the device** — only one process
may hold the device's USB interface, and udev does not run in a container. See
[the YubiHSM variant](#the-yubihsm-variant) for `--device`, `--group-add` and the
connector.

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
those packages, that ages badly. The one thing it does not refresh is the
[yubihsm-shell release](#built-from-upstream-source-not-from-debian) the variant
compiles, which is pinned by version and digest; the libraries that release links
against do come from the base image.

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
