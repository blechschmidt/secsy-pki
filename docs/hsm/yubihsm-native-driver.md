# Native YubiHSM 2 driver

*Talking to the device, not to a program that talks to the device.*

Everything secsy-pki does with a YubiHSM 2 that PKCS#11 cannot express — reading
the device audit log, provisioning irreversible force-audit, issuing key
attestation certificates, factory reset — goes through
`server/internal/yubihsm`, a native Go driver that speaks the device's own
protocol.

It replaced a layer that ran the `yubihsm-shell` binary as a subprocess and
recovered results by matching regular expressions against its human-readable
output.

## Why this is a correctness matter, not a tidiness one

The audit and attestation subsystems ([audit log](audit-log.md),
[key attestation](key-attestation.md)) exist to let someone who does not trust
the CA operator conclude that a key signed nothing beyond what was published.
That conclusion is only as good as the channel the evidence arrived on.

Four things changed with the driver:

- **Failure is typed.** `yubihsm-shell` exits 0 even when a scripted command is
  rejected: it prints an error line and returns success. The previous code had
  to recognise failure by matching text such as `^Failed`, so a message reworded
  upstream would have made a refused `put option` look like it had been applied
  — precisely the state in which unlogged signing becomes possible. Device
  refusals now arrive as a typed `DeviceError` carrying the device's own error
  code.
- **Values arrive as bytes.** Audit entries, the command-audit option map and
  attestation certificates are decoded from the wire encoding rather than
  scraped from a display format the vendor never promised to keep stable. The
  32-byte log record is parsed field by field; the digest is not re-serialised
  through hex text on the way in.
- **Nothing hits the filesystem.** Signing through the shell required the bytes
  to be signed to exist as a temporary file, and the authentication password to
  be written to a child process's stdin.
- **Deadlines reach the device.** Every call takes a `context.Context`.

It is also faster and quieter in the device log: the shell opened and closed a
session per command, so a signed audit-log export cost four authentications
where it now costs one.

## What it is

A GlobalPlatform **SCP03** secure channel — mutual authentication, per-message
encryption, and a MAC that chains across the session — carried over one of two
transports:

| Connector URL | Transport |
|---------------|-----------|
| `yhusb://` (default) | Direct USB bulk transfers via Linux usbfs |
| `yhusb://serial=0031650425` | The same, selecting a device by serial |
| `http://host:12345` | A `yubihsm-connector` daemon |
| `https://host:12345` | The same, over TLS |

There is no libusb, no cgo and no vendor binary. The USB transport submits
`USBDEVFS_BULK` ioctls on `/dev/bus/usb/<bus>/<device>`, located through sysfs.

Because SCP03 terminates in this process and in the HSM, a `yubihsm-connector`
in between is a relay that can drop or reorder messages but cannot read a signing
request, alter an audit-log response, or forge one.

If more than one YubiHSM is attached and no serial is given, the driver refuses
rather than picking one: every audit and attestation claim is about a *specific*
device, and silently addressing the wrong one would produce evidence that
verifies while describing the wrong hardware.

## Requirements

Direct USB access needs read/write permission on the device node. Running as
root works; for a service account, a udev rule is the usual answer:

```
# /etc/udev/rules.d/70-yubihsm.rules
SUBSYSTEM=="usb", ATTR{idVendor}=="1050", ATTR{idProduct}=="0030", MODE="0660", GROUP="secsy"
```

Only one process may hold the device's USB interface at a time. If
`yubihsm-connector`, `yubihsm-shell` or the PKCS#11 module has it open, the
driver reports that rather than hanging — in a deployment that runs a connector,
point secsy-pki at the connector's URL instead of at USB.

The driver is Linux-only for direct USB. On other platforms, run a
`yubihsm-connector` and use an `http://` URL; the security properties are the
same either way.

## Configuration

```yaml
yubihsm:
  connector_url: "yhusb://"   # or yhusb://serial=..., http://host:12345
  auth_key_id: 1
  password: "..."             # derives the SCP03 static keys (PBKDF2-SHA256)
```

When `connector_url` is empty the driver falls back to the `connector = ...`
line in the file named by `YUBIHSM_PKCS11_CONF`, so a deployment that configured
only the PKCS#11 module keeps addressing the same device — the audit log has to
describe the hardware that holds the CA key, not a different one.

A password-derived authentication key is only as strong as the password.
Production deployments should provision an authentication key from random bytes.

## Scope

The driver implements the commands this codebase issues, not the whole YubiHSM
command set: session management, device info, get/put option, get/set log
entries, list/get object info, get opaque, get public key, generate/import/delete
asymmetric key, sign ECDSA, sign EdDSA, sign attestation certificate, get pseudo
random, and reset. Live PKI signing continues to go through PKCS#11 via
[the key-provider abstraction](configuration.md); the driver is for the vendor
operations PKCS#11 has no notion of.

## Testing

`internal/yubihsm` ships a fake device that terminates SCP03 the same way the
hardware does, so mutual authentication, MAC chaining, tamper rejection and
replay rejection are exercised in CI with no HSM attached. AES-CMAC is pinned to
the RFC 4493 vectors and the key derivation to Yubico's published default keys.
Wire-format parsers are pinned to golden responses captured from a real device.

Hardware tests run behind the `yubihsm` build tag and skip when no device is
reachable:

```bash
go test -tags yubihsm ./internal/yubihsm/ ./internal/hsm/ -v
```

One deliberate deviation from GlobalPlatform SCP03 is worth knowing about: the
YubiHSM decrypts a response under the *same* ICV as the command that asked for
it, rather than under the counter block with its most significant byte set to
`0x80`. This was established against hardware — the `0x80` variant corrupts
exactly the first plaintext block, the signature of a wrong CBC IV — and the
fake device implements the same rule so the two cannot drift apart.

---

↩ Back to [HSM & key management](README.md) · [documentation map](../README.md)
