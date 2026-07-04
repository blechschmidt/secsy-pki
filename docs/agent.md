# Host auto-enrollment agent (secsy-agent)

`secsy-agent` is a lightweight client-side daemon that keeps a host's
certificates fresh by enrolling against a secsy-pki server — no server-side
monitor renewal, no configuration management pushing key material around:

- **Keys never leave the host.** The agent generates each private key locally
  and sends only a CSR over EST (RFC 7030) or ACME (RFC 8555), the same
  protocol servers other clients use.
- **ARI-driven renewal timing.** For ACME certificates the agent polls the
  server's [ACME Renewal Information](acme.md) endpoint and renews inside the
  suggested window — so a server-side revocation or CA rotation pulls the
  whole fleet forward automatically. When ARI is unavailable it falls back to
  renewing at a fraction of the certificate lifetime (default 2/3).
- **Deterministic jitter, no renewal storms.** The exact renewal moment is
  derived from the certificate serial, spreading a fleet enrolled in one batch
  across the window while keeping each host's schedule stable across restarts
  — the client-side counterpart of the [expiry monitor](expiry-monitoring.md)'s
  storm prevention.
- **Atomic, verified installs.** New material is written to temp files, the
  chain is verified against a fetched trust bundle, and files are renamed into
  place (`rename(2)` is atomic) *before* the reload hook runs. If the hook
  fails, the previous files are restored.

## Quick start

Build and install the binary (it is pure Go — no PKCS#11/CGO, so it
cross-compiles freely):

```console
$ cd server && go build ./cmd/secsy-agent
$ sudo install -m 0755 secsy-agent /usr/local/bin/
```

Write `/etc/secsy/agent.yaml`:

```yaml
state_dir: /var/lib/secsy-agent

est:
  url: https://pki.example.com/.well-known/est
  username: web-hosts
  password_file: /etc/secsy/est-password   # bootstrap credential

# Trust anchors for verifying issued chains before install. When EST is
# configured this defaults to <est.url>/cacerts; a pre-provisioned file or an
# explicit URL also works:
# trust:
#   bundle_file: /etc/secsy/roots.pem

certificates:
  - name: web
    enroll: est
    dns_names: [web.example.com]
    key_type: ecdsa-p256                    # ecdsa-p256|ecdsa-p384|rsa-2048|rsa-3072|rsa-4096|auto
                                            # "auto" adopts the EST server's /csrattrs key-type hint (RFC 7030 §4.5)
    key_file: /etc/nginx/tls/web.key
    cert_file: /etc/nginx/tls/web.crt
    fullchain_file: /etc/nginx/tls/web-fullchain.crt
    owner: root:www-data
    key_mode: "0640"
    reload:
      command: systemctl reload nginx
```

Run a single pass, then check what the agent tracks:

```console
$ sudo secsy-agent once
renewed  web                  not yet installed
$ sudo secsy-agent status | jq '.certificates[0] | {name, present, not_after, renew_at}'
$ sudo secsy-agent run     # or enable the systemd unit for daemon mode
```

## Enrollment protocols

Each certificate spec selects `enroll: est` or `enroll: acme`; one agent can
mix both.

**EST** uses the operator-provisioned Basic credential from `est.username` /
`est.password` (or `password_file`). Initial issuance goes through
`simpleenroll`; renewals use `simplereenroll`, additionally presenting the
current certificate as a TLS client certificate so servers with
`est.allow_tls_client_reenroll: true` accept renewals even after the bootstrap
credential is retired.

**ACME** registers an account (persisted in `state_dir`) and answers
**http-01** challenges. When the server requires [External Account
Binding](acme.md), provision the credentials:

```yaml
acme:
  directory: https://pki.example.com/acme/directory
  eab_kid: host-web-01
  eab_hmac_key_file: /etc/secsy/eab.key
  http01:
    listen: ":80"                # standalone solver, bound only during a challenge
    # webroot: /var/www/html     # alternative: token files under an existing web server
```

The standalone solver binds `http01.listen` only while challenges are
outstanding and releases the port after each pass, so it coexists with a web
server that is stopped/reloaded around renewals; use `webroot` when something
is permanently listening on port 80. Wildcard names need dns-01, which the
agent does not solve — issue those through the server-side [ACME](acme.md) or
[monitor](expiry-monitoring.md) flows instead.

## Renewal scheduling

For every tracked certificate the agent re-evaluates on each pass (daemon
default: every 5m):

1. **Triggers** force immediate (re-)enrollment: missing/unparsable files, a
   key that does not match the certificate, config drift (SANs, CN, key type),
   or expiry.
2. **ARI** (ACME certificates): the agent polls `renewalInfo` no more often
   than the server's `Retry-After`, picks a moment inside the suggested window
   (uniform, but derived deterministically from the CertID so restarts do not
   re-roll it), and renews once that moment passes. Revoked or
   rotation-superseded certificates get an immediate window from the server,
   so the fleet re-enrolls promptly.
3. **Fraction of lifetime** (EST, or ACME without ARI): renew at
   `renewal.fraction` (default 2/3) of the validity period, plus a
   deterministic jitter of up to `renewal.jitter` (default 4%) of the
   lifetime, capped safely before expiry.

Failed renewals are retried with exponential backoff (capped at 1h) in daemon
mode; `once` always attempts due work.

## Atomic install and reload hooks

Renewal never leaves a half-written or unverified certificate in place:

1. The issued chain must verify against the trust bundle
   (`trust.bundle_file`, `trust.bundle_url`, or EST `/cacerts`), and the leaf
   must match the new key and cover every configured SAN.
2. Key, cert, chain, and fullchain files are staged as temp files in the
   target directory with their final mode/ownership, fsynced, then renamed
   into place.
3. The reload hook runs — either a command (string form runs under `sh -c`;
   list form is exec'd) with `SECSY_CERT_NAME`, `SECSY_KEY_FILE`,
   `SECSY_CERT_FILE`, `SECSY_CHAIN_FILE`, `SECSY_FULLCHAIN_FILE`,
   `SECSY_CERT_SERIAL`, and `SECSY_CERT_NOT_AFTER` in its environment, or a
   signal to a pid-file process:

   ```yaml
   reload:
     signal: HUP
     pid_file: /run/nginx.pid
   ```

4. If the hook fails (non-zero exit, or exceeding `reload.timeout`, default
   30s), the previous files are restored atomically and the pass reports an
   error.

## Commands and exit codes

| Command | Purpose | Exit codes |
|---|---|---|
| `secsy-agent run` | Daemon: evaluate/renew continuously, serve metrics | 0 on clean shutdown |
| `secsy-agent once [-json]` | Single pass (cron/timer-friendly) | 0 nothing to do · 2 renewed something · 1 failure |
| `secsy-agent status` | JSON of tracked certs, next renewal, last outcome | 0 / 1 |

`once` exits 2 after successful renewals so schedulers can distinguish "work
done" from "nothing to do"; the shipped systemd unit declares
`SuccessExitStatus=0 2`.

## Metrics

```yaml
metrics:
  textfile: /var/lib/node_exporter/textfile_collector/secsy-agent.prom
  listen: "127.0.0.1:9930"   # optional exporter in daemon mode
```

The textfile is rewritten atomically after every pass; the exporter serves the
same registry on `/metrics`. Gauges:
`secsy_agent_certificate_not_after_seconds`,
`..._not_before_seconds`, `..._renewal_time_seconds` (planned moment),
`..._present`, `..._last_success`, `..._last_renewal_seconds` (all labelled
`certificate="<name>"`), and `secsy_agent_last_run_seconds`. Alert on expiry
the same way as for [server-side monitoring](observability.md), e.g.
`secsy_agent_certificate_not_after_seconds - time() < 7*86400`.

## systemd deployment

Ready-to-use units live in [`deploy/systemd/`](../deploy/systemd/):
`secsy-agent.service` (daemon) or `secsy-agent-once.service` +
`secsy-agent-once.timer` (hourly single passes — renewal timing still comes
from ARI/fraction scheduling, the timer just bounds detection latency).

```console
$ sudo cp deploy/systemd/secsy-agent.service /etc/systemd/system/
$ sudo systemctl enable --now secsy-agent.service
```

The agent usually runs as root so it can write service key material and chown
it (`owner:`); binding `:80` for http-01 as non-root needs
`AmbientCapabilities=CAP_NET_BIND_SERVICE` (commented in the unit).

## Configuration reference

```yaml
state_dir: /var/lib/secsy-agent   # required: state.json + ACME account key

server:
  tls_ca_file: ""                 # extra roots for the *server's* TLS cert
  insecure_skip_verify: false     # lab use only
  timeout: 30s

trust:                            # anchors for verifying *issued* chains
  bundle_file: ""                 # PEM file, re-read every pass
  bundle_url: ""                  # PEM or EST-style base64 PKCS#7; default <est.url>/cacerts
  refresh_interval: 24h

acme:
  directory: ""                   # enables ACME enrollment
  contact: []
  eab_kid: ""
  eab_hmac_key: ""                # or eab_hmac_key_file
  http01:
    listen: ":80"                 # or webroot: /var/www/html

est:
  url: ""                         # enables EST enrollment
  username: ""
  password: ""                    # or password_file

renewal:
  fraction: 0.6667                # fallback renewal point
  jitter: 0.04                    # deterministic per-cert spread
  check_interval: 5m              # daemon cadence
  disable_ari: false

metrics:
  textfile: ""
  listen: ""

certificates:
  - name: web                     # unique; used in state, logs, metric labels
    enroll: acme                  # acme | est
    common_name: ""               # default: first DNS name
    dns_names: []
    ip_addresses: []
    key_type: ecdsa-p256
    validity: 0s                  # optional requested notAfter (ACME only)
    key_file: ""                  # required
    cert_file: ""                 # required (leaf only)
    chain_file: ""                # issuers only
    fullchain_file: ""            # leaf + issuers
    owner: ""                     # "user:group"
    key_mode: "0600"
    cert_mode: "0644"
    renewal: {fraction: 0, jitter: 0}   # per-cert override
    reload:
      command: ""                 # string (sh -c) or [argv] list
      signal: ""                  # HUP/USR1/USR2/TERM/INT, with pid_file
      pid_file: ""
      timeout: 30s
```

Unknown keys are rejected at load time so a typo cannot silently disable a
renewal.

## Testing

Unit tests run hermetically (`go test ./internal/agent/`). The integration
suite (`go test -tags sqlite -run TestAgent ./internal/e2e/`, SoftHSM
required) spins up the real ACME and EST servers on an HSM-backed CA, runs the
agent (including the compiled CLI) through initial enrollment, asserts the
hook fired only after the files were atomically swapped, then forces renewals
both ways: an ARI-driven immediate renewal after a server-side revocation, and
a fraction-of-lifetime renewal via `simplereenroll` under an advanced clock.
