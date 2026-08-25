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

Both rest on a third claim that neither makes: that the device doing the
asserting is a genuine YubiHSM. Chain anchoring, below, checks that the
*certificate* behind these assertions is Yubico-issued;
[`hsm-attest device`](device-attestation.md) goes the step further of making the
device prove it holds the corresponding private key, and prints the serial number
Yubico certified it under.

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

This is exactly what an imported key looks like from the outside, and it is the
correct outcome: [`ca import` / `import-key`](../ca/import.md) store adopted key
material with the same non-extractable, sensitive, single-purpose template a
generated key gets, but they cannot rewrite where it came from. A CA migrated
off a software key will fail an origin check until it is re-keyed — scope
`-allow-imported` (or `attestation_allow_imported_keys`) to that CA rather than
turning it on for the deployment.

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

It also puts the same device command to a second, less obvious use. The device
log carries no serial number and no signature, so nothing in it says which HSM
wrote it. Attesting a *throwaway* key whose label is a digest of the audit head
turns the host-supplied label extension into a channel for a statement the
factory attestation key signs — which, paired with an RFC 3161 timestamp over the
resulting certificate, is what ties an exported log to real hardware. See [the
log came from the device it names](audit-log.md#7-the-log-came-from-the-device-it-names).

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
   root, i.e. the attesting device is a genuine YubiHSM.
6. **Expected key / label / serial / object ID** — when supplied.

Unrecognised capability bits are reported as warnings rather than ignored: a
capability introduced by newer firmware cannot be shown *not* to permit export.

### Chain anchoring

Anchoring is what separates *"a device asserts this key is non-exportable"* from
*"a YubiHSM asserts it"*. Without it anyone can mint a self-signed certificate
carrying whatever assertions they like, so it is **required by default**, and
stock hardware satisfies it with no configuration:

```
Chain anchored:   yes (Yubico YubiHSM Root CA)
```

Yubico runs two attestation PKIs and secsy-pki embeds both:

| PKI | Root | Published at |
| --- | --- | --- |
| YubiHSM 2 device attestation | `Yubico YubiHSM Root CA` | [`yubihsm2-attest-ca-crt.pem`](https://developers.yubico.com/YubiHSM2/Concepts/yubihsm2-attest-ca-crt.pem) |
| Unified Yubico device attestation | `Yubico Attestation Root 1` | [developers.yubico.com/PKI/](https://developers.yubico.com/PKI/) |

A YubiHSM 2's pre-loaded certificate (opaque object `0`) is issued by a
`Yubico YubiHSM <n> Sub-CA` under the first of these. Yubico publishes those
sub-CAs individually rather than as a bundle, each named after its own subject
key identifier — the [YubiHSM 2 User Guide][ug] lists the current one under
*Core Concepts → Attestation → Pre-Loaded Certificates → Intermediates* as
[`E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem`](https://developers.yubico.com/YubiHSM2/Concepts/E45DA5F361B091B30D8F2C6FA040DB6FEF57918E.pem),
and that certificate ships embedded here.

[ug]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-core-concepts.html

Because that naming is mechanical, a device whose sub-CA Yubico published after
your binary was built is a one-file fix rather than a dead end. A device
certificate names its issuer in its authority key identifier, and that hex value
*is* the filename, so the verifier computes the URL for you:

```
device attestation certificate "YubiHSM Attestation (…)" does not chain to a
trusted attestation root …; if this is genuine hardware its issuing sub-CA
"Yubico YubiHSM <n> Sub-CA" is published at
https://developers.yubico.com/YubiHSM2/Concepts/<AKI>.pem — fetch it and add it
to the configured attestation anchors
```

Fetch that file, point `yubihsm.attestation_root_files` at it, and the chain
anchors. Fetching it over the network is safe: it is signed by an embedded root,
so a hostile server can serve a bad file but not one that verifies.

Set `attestation_require_anchored_chain: false` only for a device whose factory
attestation key has been replaced with an owner-generated one, where no Yubico
chain exists to anchor to by construction. An unanchored attestation proves the
key's properties *as asserted by a device* — not that the device is a genuine
YubiHSM.

## Configuration

```yaml
yubihsm:
  connector_url: "yhusb://"
  auth_key_id: 1
  password: "…"

  # Trust anchors for key attestation. Empty uses Yubico's published roots,
  # embedded in the binary, which cover stock hardware. Self-signed certificates
  # in these files are treated as roots and the rest as intermediates, so one
  # bundle containing a whole chain works without being split by hand.
  attestation_root_files: []
  # Fail an attestation whose device certificate does not chain to one of them.
  # Unset means on — see "Chain anchoring" above before turning it off.
  attestation_require_anchored_chain: true
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
