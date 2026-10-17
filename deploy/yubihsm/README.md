# YubiHSM 2 deployment

A secsy-pki stack backed by a YubiHSM 2 attached to the host over USB, running
from the published `-yubihsm` image — in **one container**.

```bash
cp .env.example .env         # then change the password, PIN and root password
./device-env.sh >> .env      # finds the attached device: its node and its gid
docker compose up -d
docker compose logs -f
```

| File | Role |
|------|------|
| `docker-compose.yaml` | The stack: one `server` container, holding the device and multiplexing it in-process |
| `docker-compose.connector.yaml` | The two-service variant, with Yubico's `yubihsm-connector` owning the device |
| `config.yaml` | The server config, mounted read-only. No secrets, no host-specific paths |
| `.env.example` | Template for the device node, the credentials and the root password. `.env` is gitignored |
| `device-env.sh` | Prints the two device lines for `.env`, and checks the node is openable by a container |
| `../udev/70-yubihsm.rules` | The host udev rule that gives the node a stable group |

## How one container serves one device twice

A YubiHSM 2 speaks over **one USB interface, and the kernel grants that
interface to one claim**. This container has two things that need the device:

* the **PKCS#11 module**, which every signature goes through, and which holds
  the interface for as long as the server has a session — i.e. forever;
* the **native driver**, which reads the device audit log and issues
  attestations, because PKCS#11 cannot express `GET LOG ENTRIES`.

Point both at `yhusb://` with nothing in between and the module wins: every
collection fails with `device or resource busy` while signing carries on, so the
deployment looks healthy right up to the moment its force-audited device fills
its 62-entry log and refuses to sign. secsy-pki detects that configuration from
the config alone and **refuses to start** on a commissioned device rather than
deliver it.

So the server takes the claim itself. At startup it opens the device, serves
Yubico's connector protocol on `127.0.0.1:12345` inside its own process, and
writes the module's `yubihsm_pkcs11.conf` to point there — while the audit
driver uses the same single claim directly, with no HTTP round trip. That is
`SECSY_YUBIHSM_EMBEDDED_CONNECTOR: "1"` in `docker-compose.yaml`, and it is the
default for this configuration; the variable is set explicitly so the deployment
states what it relies on.

Two consequences worth knowing:

* **The drain follows the operations, including the module's.** Every command
  the module sends arrives at the relay as a request, so the device log entry it
  produced is collected by the operation that produced it — not by a timer, and
  not by a log consumer in another process.
* **An operator's CLI joins the relay.** `docker compose exec server secsy-ca …`
  finds the address already served and uses it, rather than competing for a USB
  claim it cannot have. That is why `SECSY_YUBIHSM_CONNECTOR_URL` names the
  loopback address rather than being left unset.

SCP03 terminates in the HSM and in each client, so the relay carries a channel
it cannot read or forge — the same property Yubico's daemon has. It binds
loopback, because a connector has no authentication of its own.

### When to use the two-service variant instead

```bash
docker compose -f docker-compose.connector.yaml up -d
```

`docker-compose.connector.yaml` runs Yubico's `yubihsm-connector` as its own
service, owning the device node, with the server reaching it over HTTP. Use it
when the device must be shared beyond this container: a vendor CLI on the host,
another application, a second deployment — or when the HSM is attached to a
different host than the CA runs on, so the connector has to be where the USB
port is. The embedded relay can only serve the host its device is plugged into,
and says so if a configuration asks otherwise.

## Where the device audit log is written

`SECSY_YUBIHSM_AUDIT_LOG_FILE` in `docker-compose.yaml` names it:
`/app/audit/device-log.jsonl`, on its own volume. The database holds the same
records, and for the running system that copy is the better one — but it is not
append-only, and anybody who can reach the database can shorten it. The file is
the copy that survives that: one self-contained JSON record per line, carrying
the device's own 32-byte log record verbatim, written with `O_APPEND` and
`fsync` and never rewritten, so it keeps working under `chattr +a`, on a WORM
mount, or with a log shipper tailing it.

The server **opens it at startup**, before it knows whether the device has been
commissioned, and refuses to start if it cannot append — a read-only mount, a
volume owned by the wrong uid or a typo is a boot failure naming the path, not a
surprise at the first drain. Verify it any time, offline, with no database and
no device:

```bash
docker compose exec server secsy-ca hsm-audit verify-file -file /app/audit/device-log.jsonl
```

No `-config` there on purpose: `verify-file` is dispatched before any
configuration, database or device is opened, because the file exists precisely
so a copy can be verified by somebody who has none of them.

To put it on something the CA host cannot rewrite, replace the `audit` volume
with a bind mount and make the file append-only on the host:

```yaml
    volumes:
      - /srv/secsy-audit:/app/audit      # in docker-compose.yaml
```

```bash
sudo install -d -o 65532 -g 65532 /srv/secsy-audit
# after the first start, once the file exists:
sudo chattr +a /srv/secsy-audit/device-log.jsonl
```

## Before the first start: the CA

The server does not create a CA for itself, and `config.yaml` asks it to issue
its own listener certificate from one called `issuing-ca`. Create the hierarchy
once, with the stack's own image, before the server is up:

```bash
secsy() {
  docker compose run --rm --entrypoint secsy-ca server \
    -config /etc/secsy/config.yaml "$@"
}

secsy hsm-attest device                       # is this a genuine YubiHSM?
secsy init-root -label root-ca -key-type ecdsa-p384 -cn "Example Root CA" -validity-days 3650
secsy issue-intermediate -label issuing-ca -parent root-ca -cn "Example Issuing CA" -validity-days 1825
docker compose up -d
```

Each of those `docker compose run` invocations is a container of its own, and
each one multiplexes the device for the length of the command: it claims the
USB interface, serves the relay, signs through the module, drains the device
audit log into `/app/audit/device-log.jsonl` and the database, and exits. Once
the server is up it holds the device instead, and `docker compose exec server
secsy-ca …` is the way to run a command alongside it.

To adopt a CA key that already exists outside the HSM instead — an OpenSSL RSA
key in any form `openssl` emits, including PKCS#1, PKCS#8, encrypted and
PKCS#12 — see
[importing an existing key](../../docs/ca/import.md); the key file is
read once, from a local path, and never leaves it afterwards.

## Commissioning the device for audited operation

`secsy-ca hsm-audit provision` turns on **irreversible** forced audit logging
and pins the chain anchor that every later export is verified against. It
requires a **factory-reset** device, because a log that does not begin at the
reset cannot be shown to be complete — so this is a decision to make before the
device holds anything, not after.

```bash
secsy hsm-audit provision     # irreversible: record the printed anchor out of band
secsy hsm-audit status        # device options, collection tail, and the log file
```

Until that is done the device's log is not collected at all, and the file above
stays empty: without a pinned anchor a collected chain cannot be attributed to a
known device history. If the device was force-audited by hand and never
commissioned, the server says so at startup — and means it, because the 62-entry
log then fills and the HSM stops signing.

What the collected log proves, and how a third party checks it without trusting
this deployment, is [docs/hsm/audit-log.md](../../docs/hsm/audit-log.md).

## Troubleshooting

| Symptom | Cause |
|---------|-------|
| `no YubiHSM 2 (1050:0030) is attached` from `device-env.sh` | The device is not plugged in, or not visible to this host (a USB/IP attach may have dropped) |
| `no YubiHSM 2 found on USB` at startup | The node in `.env` is stale — re-run `./device-env.sh >> .env` |
| `the YubiHSM USB interface is held by another process` | Something on the host has the device: a `yubihsm-connector`, a `yubihsm-shell`, or another container with the node passed to it. The relay needs the claim |
| `LIBUSB_ERROR_ACCESS` | The node's mode or gid: install `../udev/70-yubihsm.rules`, then re-run `device-env.sh` |
| Server exits with `yubihsm.audit_log_file … cannot be opened for append` | The audit volume is not writable by uid 65532 |
| Server exits naming `hsmaudit.drain` | The signing path is on `yhusb://` with no connector of either kind: set `SECSY_YUBIHSM_EMBEDDED_CONNECTOR=1`, or use the two-service variant |
| `the embedded YubiHSM connector address is already in use` | Another process already serves `127.0.0.1:12345`. A CLI invocation will use it; a server will not start over it |
