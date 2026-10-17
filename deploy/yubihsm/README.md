# YubiHSM 2 deployment

A secsy-pki stack backed by a YubiHSM 2 attached to the host over USB, running
from the published `-yubihsm` image.

```bash
cp .env.example .env         # then change the password, PIN and root password
./device-env.sh >> .env      # finds the attached device: its node and its gid
docker compose up -d
docker compose logs -f server
```

| File | Role |
|------|------|
| `docker-compose.yaml` | The stack: `yubihsm-connector` holds the device, `server` reaches it over HTTP |
| `config.yaml` | The server config, mounted read-only. No secrets, no host-specific paths |
| `.env.example` | Template for the device node, the credentials and the root password. `.env` is gitignored |
| `device-env.sh` | Prints the two device lines for `.env`, and checks the node is openable by a container |
| `../udev/70-yubihsm.rules` | The host udev rule that gives the node a stable group |

## Why there are two services for one device

A YubiHSM 2 speaks over **one USB interface, and exactly one process may hold
it**. This stack has two things that need the device:

* the **PKCS#11 module**, which every signature goes through, and which holds
  the interface for as long as the server has a session — i.e. forever;
* the **native driver**, which reads the device audit log and issues
  attestations, because PKCS#11 cannot express `GET LOG ENTRIES`.

Point both at `yhusb://` and the module wins: every collection fails with
`device or resource busy` while signing carries on, so the deployment looks
healthy right up to the moment its force-audited device fills its 62-entry log
and refuses to sign. secsy-pki detects that configuration from the config alone
and **refuses to start** on a commissioned device rather than deliver it.

`yubihsm-connector` is Yubico's daemon for exactly this. It is in the image, it
owns the device node, and everything else talks to it over HTTP. The device is
still a direct-USB `yhusb://` device — the connector is what makes it shareable.
SCP03 terminates in the HSM and in each client, so a connector in between can
drop or reorder messages but cannot read a signing request or alter an
audit-log reply.

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
docker compose exec server secsy-ca -config /etc/secsy/config.yaml \
  hsm-audit verify-file -file /app/audit/device-log.jsonl
```

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
once, with the stack's own image and the connector already running:

```bash
docker compose up -d yubihsm-connector

secsy() {
  docker compose run --rm --no-deps --entrypoint secsy-ca server \
    -config /etc/secsy/config.yaml "$@"
}

secsy hsm-attest device                       # is this a genuine YubiHSM?
secsy init-root -label root-ca -key-type ecdsa-p384 -cn "Example Root CA" -validity-days 3650
secsy issue-intermediate -label issuing-ca -parent root-ca -cn "Example Issuing CA" -validity-days 1825
docker compose up -d
```

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
| Connector unhealthy, `status=NO_DEVICE` | The node in `.env` is stale — re-run `./device-env.sh >> .env` — or another process on the host holds the device |
| `LIBUSB_ERROR_ACCESS` | The node's mode or gid: install `../udev/70-yubihsm.rules`, then re-run `device-env.sh` |
| Server exits with `yubihsm.audit_log_file … cannot be opened for append` | The audit volume is not writable by uid 65532 |
| Server exits naming `hsmaudit.drain` | Something is pointing the signing path at `yhusb://` — the two routes to the device cannot share it |
