# YubiHSM key attestation

Proving that a CA signing key was generated inside the HSM and cannot be
exported from it — as a claim a relying party can check for themselves.

This is the companion to the [remotely verifiable HSM audit
log](audit-log.md). The two answer different questions and neither implies
the other:

| | Question | Mechanism |
|---|---|---|
| Audit log | What did the HSM *do*? | No signature exists beyond the published ones |
| Key attestation | What is the key? | The private material never left the device, so those signatures are the only ones that can ever exist |

A deployment that wants to say "our CA key cannot be misused" needs both. An
audit log without attestation cannot rule out that a copy of the key is signing
elsewhere, off the books entirely. Attestation without an audit log cannot rule
out that the confined key signed something that was never published.

They are wired together rather than merely documented together: an audit-log
export carries an attestation for every key that has signed, verification refuses
a bundle whose signing keys are not attested, and `hsm-audit verify -key` takes a
public key and answers the joined question — *has this key signed anything that
was not published?* See [the audit log](audit-log.md#5-the-signatures-belong-to-a-key-not-to-a-handle).

## What the device asserts

`attest asymmetric` makes the YubiHSM sign an X.509 certificate over the public
key of one of its own asymmetric objects, using a factory-provisioned
attestation key. The Yubico extensions in that certificate (private arc
`1.3.6.1.4.1.41482.4`) carry the device's assertions about the object:

| OID | Assertion |
|---|---|
| `…41482.4.1` | Firmware version |
| `…41482.4.2` | Device serial number |
| `…41482.4.3` | Origin — generated on-device, imported, or imported under wrap |
| `…41482.4.4` | Domains the key belongs to |
| `…41482.4.5` | The key's full 64-bit capability mask |
| `…41482.4.6` | On-device object ID |
| `…41482.4.9` | Label |

The assertions come from the hardware, not from the CA operator. That is the
whole point: it is the difference between a policy statement and a proof.

### How extractability is decided

On a YubiHSM, one capability bit decides it: **`exportable-under-wrap`** (bit
16). A key holding it can be exported wrapped under a wrap key and unwrapped
wherever that wrap key is, so its confinement is only as strong as the wrap
key's. A key without it has no command path off the device at all.

**Origin is a separate question and matters just as much.** A key that was
*imported* existed in software somewhere before it arrived, so non-exportability
only establishes that no copy can leave *now* — not that none was made before.
The verifier reports the two independently and, by default, requires both.

The capability table in `internal/hsmattest/capabilities.go` was extracted
mechanically from Yubico's own `libyubihsm` rather than transcribed from
documentation, because a single wrong bit would silently invert a security
verdict.

## Producing an attestation

```console
$ secsy-ca hsm-attest key my-root-ca
Key label:        my-root-ca
Object ID:        0x2f5d
Device serial:    31650425 (firmware 2.4.0)
Key:              ECDSA P-256
SPKI fingerprint: SHA256:8yLmNpXBaDKLXmNB2Jg2w2jmx/V1CJsPelc+GUWMdtY

Non-exportable:   yes
Generated in HSM: yes  (origin: generated)
Can sign:         yes
Capabilities:     sign-ecdsa
Domains:          [1]

Device-signed:    yes
Chain anchored:   no

verified: key "my-root-ca" (object 0x2f5d) was generated inside YubiHSM 31650425
and cannot be exported from it
```

Exit status is 0 when the attestation satisfies the policy and 1 when it does
not, so this works as a compliance gate in a pipeline.

### Bind it to a CA

An attestation on its own proves that *some* object on the device is
non-exportable. Only comparing the attested public key against the key in the CA
certificate shows that the object in question is the one the CA actually signs
with:

```console
$ secsy-ca hsm-attest ca <ca-id>
...
Matches expected: yes
```

`secsy-ca hsm-attest ca` and `GET /api/ca/{id}/key-attestation` set that
expectation automatically from the stored CA certificate. **Prefer them over the
bare key form** — an unbound attestation is a much weaker statement than it
looks.

The [audit log](audit-log.md) binds it the same way and goes one step further: it
also reads the handle's history out of the device log, so an attested key whose
object ID was deleted and recreated — or exported under a wrap key — is refused
rather than counted.

### Sweep the whole device

The question an operator usually has is not "is this one key safe" but "is
anything on this device exportable". A key mistakenly created with
`exportable-under-wrap` is invisible until something enumerates them:

```console
$ secsy-ca hsm-attest audit
OBJECT  LABEL            EXPORTABLE  ORIGIN     CAPABILITIES                      VERDICT
0x7e57  prod-root-ca     no          generated  sign-ecdsa                        ok
0x7e58  legacy-signer    yes         generated  sign-ecdsa,exportable-under-wrap  FAIL: key holds the exportable-under-wrap capability…
```

## Verifying one remotely

Verification needs nothing but the bytes — no device, no database, no config —
which is what makes it usable by someone who is not the audited party:

```console
$ secsy-ca hsm-attest key my-root-ca -out attestation.json
$ # hand attestation.json to the auditor, who runs:
$ secsy-ca hsm-attest verify -file attestation.json -expect-key ca-cert.pem
```

`-expect-key` accepts a certificate or a public key. Without it, the result only
says that some key on the device has these properties.

Other flags: `-roots` (trust anchors), `-expect-label`, `-expect-serial`,
`-require-anchor`, `-allow-exportable`, `-allow-imported`, `-json`.

## What verification actually checks

1. **Claims decode** — the Yubico extensions parse, and *all seven* are present.
   A YubiHSM emits all of them, so a certificate missing some is one that
   declines to make exactly the assertions being checked — which is what a
   forgery stripped of the inconvenient fields looks like.
2. **Non-exportable** — the key does not hold `exportable-under-wrap`.
3. **Generated on-device** — origin is `generated`, not `imported`.
4. **Device binding** — the attestation certificate's signature verifies against
   the device attestation certificate, i.e. *this device* made these assertions.
5. **Chain anchored** — the device certificate chains to a trusted attestation
   root, i.e. the attesting device is a genuine YubiHSM. See the caveat below.
6. **Expected key / label / serial / object ID** — when supplied.

Unrecognised capability bits are reported as warnings rather than ignored: a
capability introduced by newer firmware cannot be shown *not* to permit export.

### Caveat: chain anchoring is off by default

Yubico's published attestation bundle does not contain the sub-CA certificates
for every device generation. A YubiHSM 2 on firmware 2.4.0 chains through a
per-batch `Yubico YubiHSM <n> Sub-CA` that is **neither stored on the device nor
in the published PEM**, so requiring an anchored chain by default would fail
honest hardware.

The verifier therefore reports anchoring honestly rather than pretending:

```
Chain anchored:   no
Warnings:
  - device attestation certificate "YubiHSM Attestation (31650425)" does not
    chain to a trusted attestation root …; the assertions are self-consistent
    but nothing proves the attesting device is a genuine YubiHSM
```

Until you obtain the right intermediate, an attestation proves the key's
properties *as asserted by a device* — not that the device is a genuine YubiHSM.
Once you have it, point `yubihsm.attestation_root_files` at it and set
`attestation_require_anchored_chain: true`. Yubico's current root
(`Yubico Attestation Root 1`) and published intermediates ship embedded in the
binary, so newer devices anchor with no configuration.

## Configuration

```yaml
yubihsm:
  connector_url: "yhusb://"
  auth_key_id: 1
  password: "…"

  # Trust anchors for key attestation. Empty uses Yubico's published root,
  # embedded in the binary. Self-signed certificates in these files are treated
  # as roots and the rest as intermediates, so one bundle containing a whole
  # chain works without being split by hand.
  attestation_root_files: []
  # Fail an attestation whose device certificate does not chain to one of them.
  # Off by default — see the caveat above.
  attestation_require_anchored_chain: false
  # Capabilities a key must not hold, beyond the exportability check.
  attestation_forbidden_capabilities: []
  # Report rather than fail. Both discard a guarantee; see below.
  attestation_allow_exportable_keys: false
  attestation_allow_imported_keys: false
```

`attestation_allow_exportable_keys` exists for inventory and migration work,
where the point is to *discover* which keys are exportable rather than reject
them. `attestation_allow_imported_keys` is necessary for a CA migrated from a
software key, where the private material demonstrably existed outside the device
and no attestation can claim otherwise. Leaving either on in production discards
the guarantee attestation exists to provide.

Anchor files and capability names are resolved at startup, so a bad value is a
boot failure rather than a surprise the first time someone asks for an
attestation.

## API

| Endpoint | Capability | Notes |
|---|---|---|
| `GET /api/hsm/keys/{label}/attestation` | `hsm:manage` | Attest one key by label |
| `GET /api/ca/{id}/key-attestation` | `hsm:manage` | Attest a CA's key, bound to its certificate |
| `POST /api/hsm/attestation:verify` | `audit:read` | Verify a supplied attestation; touches no device |

Producing an attestation needs the device, so it is `hsm:manage`. Verifying one
needs nothing, so it is `audit:read` — requiring the capability that administers
the device in order to check a claim about that device would defeat the point.

A key that fails policy is reported with **200** and `verification.verified:
false`. The request succeeded; the verdict is the answer. Returning an error
status would make a client's error handling swallow exactly the finding it needs
to see.

Responses carry the certificates, not only the conclusions, so a relying party
can re-derive the verdict instead of taking this server's word for it.

## Audit and metrics

Every attestation appends an `hsm.key_attestation` event carrying the verdict,
so the audit log retains when a CA key was last shown to be non-exportable —
and, more usefully, when that stopped being true.

| Metric | Meaning |
|---|---|
| `secsy_hsm_key_attestations_total{result}` | Attestations checked: `verified` / `failed` / `error` |
| `secsy_hsm_key_attestation_findings_total{finding}` | `exportable`, `not-generated-on-device`, `unauthenticated`, `unanchored-chain` |

Findings are counted whenever the property is absent, not only when policy
required it — a series that goes quiet because someone relaxed the policy would
be the worst possible behaviour for this particular signal.

## Testing

Unit tests run against an attestation certificate captured from real hardware
(`fixtures_test.go`), because the encoding of these extensions is not specified
anywhere the code could be checked against.

Hardware tests are gated behind a build tag and create scratch keys that are
deleted afterwards:

```console
$ go test -tags yubihsm ./internal/hsmattest/ -v
```

They cover the cases a fixture cannot: a key that really is exportable, and one
that really was imported. Everything about the verdict rests on one capability
bit and one origin bit, and both have to be observed on hardware or the test
only proves the parser agrees with itself.
