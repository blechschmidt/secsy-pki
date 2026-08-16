# YubiHSM hardware test suite

*Validating secsy-pki against a real device, not a software token.*

Every other HSM test in this repository runs against SoftHSM. SoftHSM implements
the PKCS#11 API faithfully and shares none of the constraints that make a real
HSM a real HSM: it has no USB transport, no SCP03 secure channel, no 62-slot
append-only audit log, no attestation certificates, and no device options that
cannot be undone. Those are precisely the properties the enterprise claims in
this codebase rest on, so they can only be validated on hardware.

`server/internal/yubihsmtest` is that validation — one suite, six tiers, from
the wire up to the product.

---

## Running it

The suite is off unless you ask for it:

```bash
./scripts/yubihsm-test.sh              # everything
./scripts/yubihsm-test.sh --quick      # skip the slow RSA-4096 case
make test-yubihsm                      # same as the first form
```

or directly:

```bash
SECSY_YUBIHSM_TESTS=1 go test -tags sqlite -p 1 -count=1 ./internal/yubihsmtest/ -v
```

`-p 1` is not a preference. The device admits one session at a time over direct
USB, so two test binaries running at once fight over the interface and report
`device or resource busy` instead of anything about the code.

### Why an environment variable and not a build tag

The suite compiles on every ordinary build and skips at runtime, so it is
type-checked and linted continuously — which is where test rot is actually
caught — while costing CI nothing but a compile. A build tag would hide it from
both.

The per-package hardware tests that predate this suite (`internal/hsm`,
`internal/hsmattest`, `internal/hsmaudit`, `internal/pki`) stay behind the
`yubihsm` build tag, because each declares a `TestMain` that would otherwise
take over that package's SoftHSM tests. Run them alongside the suite with
`./scripts/yubihsm-test.sh --legacy`.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `SECSY_YUBIHSM_TESTS` | *(unset)* | `1` enables the suite. Without it, every test skips. |
| `SECSY_YUBIHSM_DESTRUCTIVE` | *(unset)* | `1` additionally allows irreversible device changes (see below). |
| `SECSY_YUBIHSM_CONNECTOR` | `yhusb://` | Connector URL. Falls back to `YUBIHSM_CONNECTOR`. |
| `SECSY_YUBIHSM_PASSWORD` | `password` | Authentication key password. Falls back to `YUBIHSM_PASSWORD`. |
| `SECSY_YUBIHSM_AUTH_KEY_ID` | `1` | Authentication key object id. |
| `SECSY_YUBIHSM_PKCS11_MODULE` | *(autodetected)* | Path to `yubihsm_pkcs11.so`. Probed across the usual distribution paths. |

With `SECSY_YUBIHSM_TESTS=1` set and no device reachable, the suite **fails**
rather than skipping. That is deliberate: you asked for hardware tests, so an
unplugged or busy device is a result, not a non-event. A suite that reported
PASS while touching no hardware would be worse than no suite.

---

## What it does to a device

**Do not point this at a device a deployment is using.** Specifically:

- It creates and deletes scratch objects in the `0x7f00`–`0x7f1f` handle range,
  and keys labelled `t172-*` at module-assigned handles. It touches nothing
  else, and sweeps both before and after every run.
- **It consumes device audit-log entries.** With forced audit the log is 62
  slots deep and the device refuses every audited operation once it is full. A
  full run produces well over 62 audited operations, so the suite drains the log
  as it goes and says so in the output. Drained entries are gone from the
  device — which is exactly what a deployment's audit collector needs to see.
- It does **not** write device options unless `SECSY_YUBIHSM_DESTRUCTIVE=1`.

The destructive gate covers exactly one thing: provisioning forced audit on a
fresh device. Setting the per-command audit levels to `fixed` survives every
power cycle, and the only way back is a factory reset that destroys every key on
the device. Running the hardware tests is not consent to that.

---

## The tiers

Bottom-up on purpose: a failure in tier 1 explains failures in every tier above
it, so the first failing tier names the layer at fault.

| Tier | File | What it establishes |
|---|---|---|
| 1 | `driver_test.go` | The wire works: device identity is stable, SCP03 survives payloads across every AES-block and USB-packet boundary, the counter chains over 200 exchanges, concurrent callers are serialised without crossing responses, wrong password *and* wrong key id are both rejected, device refusals arrive as typed `DeviceError`s and do not poison the session, cancellation reaches the device, and reading the audit log does not consume it. |
| 2 | `keys_test.go` | Key lifecycle over the full algorithm matrix: generate / read public half / sign / verify with the standard library on P-256, P-384, P-521 and Ed25519; ECDSA nonces differ and Ed25519 is deterministic; imported keys sign as the key that was imported; capabilities are enforced; delete deletes; two keys from one template differ; and `GET PUBLIC KEY` agrees with the attestation certificate. |
| 3 | `attestation_test.go` | Attestation says something true: a device-generated non-exportable key verifies, an **exportable** one fails, an **imported** one fails, an attestation binds to a specific public key and rejects another, a flipped signature bit is caught, label resolution is exact, and chain anchoring is reported honestly (see below). |
| 4 | `audit_test.go` | The audit trail can be complete: the device's forced-audit configuration meets the baseline, a fixed setting cannot be downgraded, signatures are attributed to the handle that made them, collection stays continuous across drain seams spanning more than one 62-entry ring, and a **full log stops the device** rather than dropping records. |
| 5 | `pkcs11_test.go` | The layer the product signs through: generate/find/sign/verify for every offered key type through `keyprovider`, the readiness probe and hardware RNG, concurrent signing through the session pool over a device that cannot parallelise, the secret-envelope round trip, keys created non-exportable, and PKCS#11 labels and native handles resolving to the same object. |
| 6 | `pki_test.go` | The product itself, on the device: a root CA, an intermediate signed by it, a leaf whose chain verifies as a TLS client would build it, revocation and a signature-checked CRL, and an SSH CA whose certificate `ssh.CertChecker` accepts for its principal and rejects for another. Needs `-tags sqlite`. |

---

## Findings this suite pinned down

Written down because each was a surprise, and a surprise that SoftHSM could not
have produced.

**The secret layer was broken on YubiHSM.** The KEK template asked for
`CKA_WRAP`/`CKA_UNWRAP`. Yubico's module maps a template requesting wrapping
onto a device *wrap-key* object, and a wrap-key is not exposed as
`CKO_PRIVATE_KEY` — so `secret.ProvisionKEK` generated a KEK successfully and
the immediately following lookup failed with `private key label not found`.
Every secret in such a deployment would have been unencryptable. The attributes
were never used (the envelope layer unwraps with `C_Decrypt`, not
`C_UnwrapKey`), so the fix was to drop them. SoftHSM draws no distinction
between object types, which is why this survived until the suite ran.

**A full audit log presents as `CKR_DEVICE_MEMORY`.** The module maps the
device's log-full refusal onto a PKCS#11 error that reads like exhausted
storage. Worth knowing before diagnosing a phantom capacity problem.

**Failed operations are logged.** A signature attempt against a nonexistent
handle appears in the audit log with a non-zero result. The suite relies on
this to anchor a freshly drained log without leaving an object behind, and it
strengthens the audit claim: a trail that recorded only successes would hide
every probe of a key an attacker does not have.

**Ed25519 works through this PKCS#11 module.** Older Yubico releases exposed no
EdDSA mechanism, which made "the YubiHSM supports Ed25519" true of the device
and false of the only path the product can reach it through. It is now true of
both, and tier 5's matrix is where a regression would show.

**Attestation chains anchor to Yubico's published roots.** The device
certificate is issued by a `Yubico YubiHSM <n> Sub-CA` which Yubico publishes
individually, named after its own subject key identifier; that sub-CA and the
`Yubico YubiHSM Root CA` above it both ship embedded, so
`hsmattest.Policy.RequireAnchoredChain` is on by default and tier 3 asserts the
chain rather than merely reporting where it terminates. A device whose sub-CA
postdates the binary fails with the URL that fixes it. See
[key attestation](key-attestation.md).

**RSA is slow.** On a YubiHSM 2, RSA-3072 key generation measured 25-45
seconds and RSA-4096 about 1m33s. Any timeout on an issuance or key-ceremony
path has to accommodate that; ECDSA is about a second.

---

## Reference device

The suite was developed and run against:

```
serial 31650425, firmware 2.4.0, part 78CLUFX5000P
audit log 62 slots, force-audit = fixed, 24 commands force-audited
```

---

↩ Back to the [HSM & key management index](README.md) · [documentation map](../README.md)
