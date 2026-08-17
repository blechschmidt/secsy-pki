# Remotely Verifiable HSM Audit Log

secsy-pki can turn a YubiHSM 2's on-device audit log into evidence that a third
party can check: **this key has produced no signature beyond the ones the CA
published, that key cannot leave the HSM, this log came from the HSM whose serial
it names, and all of it is still true as of a recent, independently attested
moment.**

That is a stronger claim than "we keep logs", and it is deliberately built so
that it holds even against the operator running the CA — someone who holds the
HSM authentication key, the database credentials and the export tooling.

## What the device log actually is

The whole argument below rests on records the HSM writes about itself, so it is
worth being exact about what one contains — and about what it does not.

### The ring

The log is a **62-entry ring buffer in the device's flash**. Two commands reach
it:

- `GET LOG ENTRIES` (`0x4d`) returns every entry not yet acknowledged, framed as
  a 2-byte unlogged-boot counter, a 2-byte unlogged-authentication counter, a
  1-byte entry count, and that many fixed 32-byte records. Reading acknowledges
  nothing, so a collector that dies while persisting can simply retry.
- `SET LOG INDEX` (`0x67`) acknowledges through an entry number and frees those
  slots. It is irreversible and discards the device's only copy, which is why the
  collector persists first and acknowledges second.

The two counters are the device's own admission that operations happened which it
could not record because the ring was full. Any non-zero value means the log has
holes, so they travel with the entries instead of being dropped.

Only commands whose audit level is *on* or *fixed* produce a record. The rest —
opening a session, reading the log, listing objects — write nothing and, verified
on hardware, **do not consume an entry number either**: 48 entries collected
across several sessions that issued plenty of unaudited commands ran 1365…1412
with no gaps. A gap in the numbering is therefore always a lost record, never an
unaudited command.

### The record

Every entry is exactly 32 bytes; all multi-byte fields are big-endian.

| Offset | Size | Field | What it says |
| --- | --- | --- | --- |
| 0 | 2 | entry number | 1-based `uint16`, monotonic across drains; wraps from `0xffff` to 1, never 0, and a factory reset restarts it at 1 with the sentinel |
| 2 | 1 | command | the command byte, e.g. `0x56` SIGN ECDSA, `0x46` GENERATE ASYMMETRIC KEY |
| 3 | 2 | length | size of the command's **input**, not of whatever was signed |
| 5 | 2 | session key | object id of the authentication key that opened the session — *who*, in the device's terms |
| 7 | 2 | target key | the object the command acted on; `0xffff` when there is none |
| 9 | 2 | second key | a second object id for commands naming two; `0xffff` otherwise |
| 11 | 1 | result | the command byte with its high bit set on success (`0x56` → `0xd6`), the device's error code on failure |
| 12 | 4 | tick | free-running device counter — not a clock |
| 16 | 16 | digest | truncated SHA-256 chaining this entry to its predecessor |

Four of those fields carry more meaning than their names suggest.

**`length` is the size of the request, not of the message.** A SIGN ECDSA entry
is always `0x0022`: a 2-byte key id plus a 32-byte digest, whether the
certificate signed was a kilobyte or a megabyte, because the device only ever
sees the digest. GENERATE ASYMMETRIC KEY is always `0x0035` (id, 40-byte label,
domains, capability mask, algorithm); DELETE OBJECT always `0x0003`. The field
pins down the *shape* of a command and reveals nothing about its content.

**`result` separates an operation from an attempt.** Success is the command byte
with the high bit set — `0x46` → `0xc6`, `0x56` → `0xd6`. A failure carries the
device's error code instead: a delete of a nonexistent object logs `0x0b`
(OBJECT NOT FOUND). Error codes are all below `0x80`, so `result == command|0x80`
is an exact test. Rejected attempts stay in the log and are counted separately —
a refused signature produced nothing to reconcile against a published artifact,
but a burst of them is worth an operator's attention.

**`target key` is not always the object you care about.** For the wrap-transfer
commands the target is the *wrap key* and the second key is the object being
moved. Reading the wrong field would silently miss an export, so verification
matches either.

**`tick` is not a timestamp.** It is a free-running counter, measured at ≈41
ticks per second (≈24 ms) on firmware 2.4.0 — 1248 ticks across a wall-clock
interval of 30.17 s. It has no epoch, carries no unit, and nothing relates it to
UTC. It orders operations and measures their spacing; it can never say when one
happened. That is exactly the gap the RFC 3161 freshness attestation fills
(fact 6 below).

### The chain digest

```text
digest[n] = SHA-256( record[n][0:16] ‖ digest[n-1] )[0:16]
```

The preimage is the record's own first 16 bytes, exactly as they appear on the
wire, followed by the predecessor's 16-byte digest. Each digest therefore commits
to the whole history since the reset — which is what lets a single verified link
bind an entire new segment to everything collected before it. A verifier
re-derives every digest from the fields and never trusts the stored value.

Worked example from device 31650425 (firmware 2.4.0), entry 1375:

| Field | Value |
| --- | --- |
| entry number | 1375 = `055f` |
| command | `56` (SIGN ECDSA) |
| length | `0022` |
| session key | `0001` |
| target key | `fe19` |
| second key | `ffff` |
| result | `d6` (success) |
| tick | 441356 = `0006bc0c` |
| digest of entry 1374 | `132ceaf51f5b099b9893331a9de47d92` |

```console
$ printf '055f5600220001fe19ffffd60006bc0c132ceaf51f5b099b9893331a9de47d92' \
    | xxd -r -p | sha256sum
785eac279ce4bf6febb7a0cca8a30fd5ecf8d7a8ab703e11a0ce610f62ea65ae  -
```

The first 16 bytes are the digest the device reported for entry 1375. The
truncation to 128 bits is the device's choice, and a verifier can only re-derive
what the device commits to — the chain is bounded by the entry numbering and by
reconciliation, not by that digest alone.

### The device-init sentinel

A factory reset writes one record with **every field set to `0xff`**, except the
number, which is 1:

```text
number=1  command=0xff  length=0xffff  session=0xffff
target=0xffff  second=0xffff  result=0xff  tick=0xffffffff
```

Its digest is the one value in the chain that cannot be recomputed: the device
seeds the chain with something that is not a function of the sentinel's fields,
so byte-identical sentinels can carry different digests. That is why the anchor
is *pinned* at provisioning time rather than derived — fact 3 below.

#### Why the anchor cannot verify itself

Pinning a hash by hand is the one manual step in this whole subsystem, and the
obvious way to remove it is to make the anchor *derivable*: publish the sentinel
record — it is famously almost all `0xff` — and let the verifier hash it. Then
nobody has to be told the anchor; they compute it, and in computing it they learn
it really came from a factory reset.

It does not work, for two measured reasons and one that would survive any
firmware change.

**The preimage is a public constant.** The sixteen bytes a sentinel contributes
to the chain are `0001ffffffffffffffffffffffffffff` — `0x0001` and then fourteen
`0xff`. Seven factory resets of device 31650425 (firmware 2.4.0) produced
byte-identical records. A constant is the same on every YubiHSM 2 ever
made, so any hash of it is a universal constant: it identifies no device, no
reset and no history. Pinning it would establish only that the log came from a
YubiHSM, which the bundle already says.

**The digest is not a function of it.** Those same seven resets reported seven
unrelated digests for that one record:

```text
27caf4edc279c4b514bfc61fc6638677
bf22cc13167d6d976defa49648a7f0a3
ef6067b14aae540ed1cf74669abe7b37
fe6bd9680b4df143948cb3e2d3d7230f
9267e0f9f2a2884922bb9b2eedfe58bc
207006239e4d4373e05d876ba9a46647
7ba868938a7a16ef60702d947dc57815
```

So the digest is `SHA-256(0001ff…ff ‖ seed)[0:16]` for a seed the device picks at
reset and never discloses. No candidate an auditor could guess reproduces it —
not an absent seed, not all-zero, not all-ones, not the record itself, not the
serial number. A verifier holding the sentinel simply has nothing to hash.

**And if it could, it would be worthless.** Take any test over a candidate anchor
that a *verifier* can perform from public data. A forger can perform it too: they
pick a value that passes, call it the anchor, and hash a consistent history
forward from it — the chain rule is unkeyed, so a flawless 62-entry log is a few
lines of code. The test rejects nothing. Self-verifiability and evidentiary value
are mutually exclusive here: the anchor is worth something *because* it is
unpredictable and was written down before the history it anchors. It is a
trust-on-first-use pin, not a proof of a property, and making it recomputable
would delete the only thing it does.

The half of the idea that does work is already in place. A bundle carries the
sentinel record in full, verification requires it to have the sentinel's shape,
and it requires the pinned anchor to equal that entry's reported digest. The
preimage is published and checked; what is missing is the seed, and the device
offers neither the seed nor a signature over its log that could stand in for one.

What closes the remaining gap is a witness outside the device — the anchor is
written into the hash-chained event log at provisioning time, so the RFC 3161
audit-chain anchoring that runs over that log places it under a timestamp the CA
cannot backdate (fact 3). Verification also refuses an anchor that *is* derivable
from public data, which is not a live concern but would be the first symptom of a
firmware that started seeding deterministically.

The measurements live in `internal/hsmaudit/genesis.go`; the reset-by-reset
observation is `TestFactoryResetSentinelIsConstantButItsDigestIsNot` in the
[hardware suite](hardware-test-suite.md), gated on `SECSY_YUBIHSM_RESET=1`.

### How it reaches an auditor

An export carries the decoded fields verbatim, so what the auditor checks is what
the device wrote:

```json
{
  "number": 1375, "command": 86, "length": 34, "session_key": 1,
  "target_key": 65049, "second_key": 65535, "result": 214, "tick": 441356,
  "hash": "785eac279ce4bf6febb7a0cca8a30fd5"
}
```

In this codebase `internal/yubihsm` parses the records off the wire (see the
[native driver](yubihsm-native-driver.md)), `hsm.ComputeEntryHash` re-derives the
digest, and `internal/hsmaudit` performs the verification.

## Why the device log alone is not enough

Read that format back and the limit is plain. An entry says object `0x1939`
performed an ECDSA signature over a 34-byte request. It does **not** record what
was signed. So the device log by itself cannot tell 412 legitimate certificate
signatures from 411 legitimate ones plus one forged certificate — the counts, and
every field in every record, are identical.

The proof is therefore assembled from seven independent facts, each of which must
hold or verification fails closed.

### 1. Nothing can be signed unlogged

`secsy-ca hsm-audit provision` sets the device's `force-audit` option and the
per-command audit level of every signing command to **fixed** (`0x02`). Fixed
means the setting cannot be lowered again without a factory reset, and
force-audit means the device *refuses to operate* once its log is full rather
than overwriting entries. A signature that is not in the log therefore cannot
exist.

The forced set covers more than the sign commands: key generation and import,
authentication-key changes, object deletion, and every wrap/export path — any of
which could otherwise be used to obtain signing capability off the books.

It also covers **every command the attached device reports that this build does
not recognise**. That is not defensive padding. Hardware validation against a
YubiHSM 2 running firmware 2.4.0 found it reports audit settings for commands
`0x07` and `0x09`, neither of which appears in Yubico's published command
reference or in the `yh_cmd` enum of their own SDK header. Nothing in this
codebase can show those commands cannot sign or export a key, so they are forced
too — and so is anything a future firmware adds.

### 2. The collected copy is complete

A leader-elected collector drains the ring continuously, and each drained segment
must start exactly where the previous one stopped: the successor entry number,
and a chain digest that hashes forward from the stored one. A dropped, reordered,
or silently re-fetched segment breaks one of the two.

The collector **persists before it acknowledges**. Acknowledgement frees the
device's ring slots and is irreversible, so a failure after it would destroy the
only copy of records nothing else can reconstruct. A verification failure stops
the drain entirely rather than papering over it — on a force-audited device a
stalled drain eventually wedges the HSM, which is a loud, safe failure, whereas
a silently discarded segment is exactly the hole an abuser needs.

### 3. The chain starts somewhere trustworthy

The first collected entry must be the device-init sentinel a factory reset
writes, so the history starts on a device with no prior use. The sentinel's own
digest is the **chain anchor**.

The anchor has to be *pinned*, not recomputed. The device seeds its chain with a
value that is not derived from the sentinel's fields — verified on hardware:
seven factory resets of the same device produced sentinels with byte-identical
all-`0xff` fields but seven different digests. So an unpinned chain proves only
internal consistency: an attacker could invent a sentinel, pick any anchor, and
hash a perfectly consistent forged history forward from it. Publishing the
sentinel does not help, and could not help even if the firmware changed — see
[why the anchor cannot verify itself](#why-the-anchor-cannot-verify-itself).

`hsm-audit provision` prints the anchor once. **Record it outside this system.**
An auditor who only ever learns it from the CA learns nothing.

Provisioning also writes the anchor into the hash-chained `event_log`, and
refuses to run if it cannot. That does not make the anchor self-proving, but it
does date it: the [audit-chain anchoring](../signing/timestamping.md) job puts an
RFC 3161 timestamp over that log, so an operator who fabricates a history later
would have to produce an anchor a third party had already witnessed beforehand.
Recording it out of band remains the part that gives an auditor a copy the CA
cannot revise.

### 4. Every signature is attributed

The device log bounds *how many* signatures exist. The **signature ledger**
records *which ones they were*.

It is written at the key-provider chokepoint every signing operation in the
system passes through — CA issuance, CRL and OCSP signing, the TSA, the SSH CA,
SPIFFE SVIDs, artifact signing, the canary probe, every background job, and code
added later that has never heard of this subsystem. Each row carries the digest
handed to the signer, so an auditor recomputes it from a published artifact.

The ledger is hash-chained like the event log, because an operator who signs a
rogue certificate and then deletes its ledger row would otherwise turn a
detectable surplus into a clean reconciliation.

Recording happens **after** the signature and fails closed: if the row cannot be
written the signature is discarded rather than returned, so an unaccountable
signature is never published.

### 5. The signatures belong to a key, not to a handle

Facts 1–4 bound what *a device* did. They say object `0x1939` performed four
signatures and the CA published four artifacts. That is not yet the question a
relying party has, which is about the public key in the certificate they are
deciding whether to trust:

> has *this key* ever signed anything that was not published?

Two things separate the two questions, and neither is visible in any log:

- **The handle is not the key.** Nothing in the audit log says which public key
  `0x1939` holds. An object can be deleted and recreated under the same number.
- **A copy signs silently.** If the private key was imported from a laptop, or is
  exportable under a wrap key, signatures made with a copy of it appear in no
  device log anywhere, because no device was involved.

The device closes both, on its own authority. `attest asymmetric` makes the
YubiHSM sign a certificate over the public key of one of its objects using its
factory-provisioned [attestation key](key-attestation.md), asserting the
handle, the label, the origin and the full capability mask. An export therefore
carries one attestation per key that has signed, and verification uses it to:

1. join a public key to an on-device handle — so log entries can be attributed
   to *that key*;
2. establish that the key was **generated inside** the HSM, so no copy predates
   it, and holds no **exportable-under-wrap** capability, so no copy can be made;
3. read the handle's own history out of the log — created exactly once, never
   deleted, never exported — so the entries counted against it all belong to the
   attested key.

Only with all three does "the device signed N times" become "this key signed
these N things and nothing else, on or off the device". A key that signed but is
not attested fails verification: the counts may balance perfectly while a copy of
the key signs elsewhere, off the books entirely.

### 6. The evidence is current

Everything above proves the device signed only what was published — *as of some
moment*. Nothing in it pins that moment down. `exported_at` is the exporting
side's clock, and the exporting side is the party being audited. An operator who
abuses a key on Tuesday could hand an auditor Monday's bundle, and every check
would pass.

So a leader-elected job periodically obtains an **RFC 3161 timestamp token** over
the current audit head — the ledger chain hash, the device log tail digest, the
signature count, the device serial and the anchor. The token says, in the TSA's
words and under the TSA's signature: *this exact state existed at this time*.

That gives two things a bundle alone cannot:

- **Staleness detection.** If the newest attestation is three weeks old, the CA
  has not proven its state current for three weeks, and verification says so
  instead of reporting a confident OK over stale data.
- **Interval bounding.** Each attestation pins a prefix of the history to a
  trusted instant, so a signature appearing between two attestations is bounded
  on both sides and cannot be backdated into a period an earlier one closed.

Attestations are a separate sequence from the ledger, not rows in it:
reconciliation depends on the ledger holding exactly one row per HSM signature,
so injecting non-signature rows would break the very check this exists for. Each
attestation instead *references* the ledger and device-log positions it covers.

> **Use an external TSA.** The internal TSA signs with the very HSM under audit,
> so against an adversary holding that HSM its `genTime` is worth no more than
> the CA's own clock. It is enough to stop an outsider passing off an old
> export; it is not enough to hold against your own staff. Set
> `yubihsm.audit_freshness_tsa_url` to an authority they do not control.
> Verification reports which was used, and `-require-external-tsa` refuses the
> internal one outright.

### 7. The log came from the device it names

Facts 1–6 all reason about a log the device cannot sign. Read the [record
layout](#the-record) again: sixteen bytes of fields and a sixteen-byte digest
chained over the predecessor. No serial number. No key. No signature. The chain
proves the entries are *self-consistent*, not that they came from anywhere — a
complete, internally flawless 62-entry log can be fabricated offline in a few
lines of Python.

Yubico's product material states each row is hash-chained *and signed*. There is
no documented command to retrieve such a signature; see
[yubihsm-shell#479](https://github.com/Yubico/yubihsm-shell/issues/479), open and
unanswered since July 2025. Treat the signing claim as unimplemented.

So until this point the sentence "device 31650425 produced this log" had exactly
two sources, and both are weaker than they look. The pinned anchor is
trust-on-first-use — it works, but only for an auditor who was present at
commissioning. The RFC 3161 timestamps say *when* a head existed; the TSA has
never seen a YubiHSM and signs whatever digest it is handed, so a token over a
fabricated head is exactly as genuine as one over a real head.

The device does hold one key whose output a third party can verify without ever
touching it: the factory [attestation key](key-attestation.md) at object `0`,
whose certificate chains to Yubico's published attestation PKI. Certificates it
signs carry device-asserted extensions, two of which matter here — the **device
serial** (`1.3.6.1.4.1.41482.4.2`) and the attested object's 40-byte **label**
(`1.3.6.1.4.1.41482.4.9`), which is supplied by the host at key generation.

A **commitment** exploits exactly that. On a fixed cadence, the CA:

1. computes the current audit head and digests it into a 40-character label —
   `sb1:` plus 27 base64url-encoded bytes, filling the device's label field
   exactly so nothing is NUL-padded on the way in or stripped on the way out;
2. generates a throwaway P-256 key with **no capabilities at all** at a reserved
   handle (`0xfb00`–`0xfbff`), carrying that label;
3. has the device attest it with the factory key;
4. deletes the key and keeps the certificate.

The result is a statement

> YubiHSM serial *N* asserts an object labelled *H*

signed by a key that has never left genuine Yubico hardware, where *H* commits at
once to the device log tail, the ledger head, the signature count and the anchor.

**The timestamp and the commitment are two halves of one statement.** An
attestation certificate carries no date of its own: a clockless YubiHSM copies
the attesting certificate's fixed 2017–2071 validity into everything it
generates, so an undated commitment could have been minted in a batch prepared in
advance. Each commitment therefore also carries an RFC 3161 token whose imprint
is over the certificate's own DER. Together an auditor learns

> device *N* asserted head *H*, and that assertion existed at time *T*.

Alone, the timestamp dates a statement no hardware ever made and the commitment
makes a statement nothing can date. The two are welded rather than adjacent: the
label carries the first 27 bytes of *exactly* the digest the TSA signs, so the
two attestations are demonstrably about the same state.

Steps 2–4 are themselves force-audited commands, so every commitment leaves
entries in the log at the indices right after the head it bound — and the next
commitment's head folds those entries in. Verification insists on finding the
generation entry, which turns a set of detachable snapshots into a **ratchet**: a
commitment cannot be produced out of band, because a certificate filed against a
log that never records its creation is refused.

The converse — a creation entry no commitment accounts for — is *reported*, not
failed, and the asymmetry is deliberate. Device log entries are append-only, so
a commitment that crashes or loses its timestamp authority after the device has
signed leaves a trace nothing can retract. Failing on that would let one network
blip permanently convert every future export into a tampering accusation. It also
buys little: commitments cover cumulative prefixes, so a dropped one removes
evidence *in the CA's favour*, and a drop between two exports is caught by
`-previous` against a bundle the auditor already held. For the same reason an
**undated** binding is skipped with a note rather than failed — it is not
evidence, but it is not a lie either. If *no* binding is dated, verification
fails.

#### What a commitment does not prove

**It is an operator commitment, not device-attested log authenticity.** The label
is whatever the host passed in; the HSM does not know it is attesting its own log
state. A dishonest operator can fabricate a log, digest the fabrication and commit
to that digest exactly as easily as an honest one.

What it establishes, verifiably and transferably:

- A device with serial *N* was physically present when the commitment was made,
  and *N* is Yubico-rooted rather than operator-asserted.
- That device committed to this specific head at a time a third party witnessed.
- Because each commitment is welded into the chain it binds, the sequence cannot
  be produced after the fact or reordered.

What it does not establish: that the digest corresponds to the device's real
command history. Combined with the pinned anchor, which an auditor holds from
commissioning, the remaining gap is one an operator can only exploit by
fabricating a history *and* committing to it live on genuine hardware they hold
— which is a materially different adversary from one editing a JSON file.

SCP03 and SCP11 do not close this gap either. The session MAC authenticates GET
LOG ENTRIES responses *to the device*, but session keys are symmetric and the
operator holds them, so the transcript proves nothing to a third party.
Asymmetric authentication changes how session keys are established, not the fact
that they are symmetric and known to the host.

## Commissioning

Provisioning requires a **factory-reset** device: the log is a bounded ring
starting at the reset, so a device with prior history has already had operations
that cannot be shown to be absent.

```console
$ secsy-ca hsm-audit provision
Device 31650425 (firmware 2.4.0) provisioned for audited operation.
Forced audit logging is enabled for 24 command(s) and cannot be disabled without a factory reset.
Collected 2 initial log entr(ies).

CHAIN ANCHOR: 940ff5892251586f8647e86c24d3811a

Record this anchor outside this system — an auditor who learns it only from
the CA cannot tell a genuine history from a fabricated one, because the device
seeds it randomly at each factory reset and it cannot be recomputed.

It has also been written to the hash-chained event log, so the next RFC 3161
audit-chain anchoring run will place it under a timestamp the CA cannot
backdate (`secsy-ca audit anchor`). That dates the anchor; only recording it
out of band gives an auditor a copy the CA cannot revise.
```

Provisioning is irreversible short of a factory reset, and re-provisioning is
refused: replacing a pinned anchor is exactly how a forged history would be
laundered.

Once provisioned, the server enables collection, ledger recording and freshness
attestation on its own — there is no separate feature flag. Gating on
provisioning rather than a config flag keeps the halves of the proof from
drifting apart: a ledger that reconciles against nothing, or a force-audited
device whose signatures are unattributed, would each produce confident-looking
output backed by half an argument.

## Configuration

```yaml
yubihsm:
  connector_url: yhusb://
  auth_key_id: 1
  password: ${YUBIHSM_PASSWORD}

  # Device-log drain cadence. The ring holds 62 entries and a force-audited
  # device refuses auditable commands once it fills, so this is a liveness
  # setting as much as an audit one.
  audit_collect_interval_seconds: 15

  # Freshness attestation. The interval is also the resolution of the
  # interval-bounding guarantee.
  audit_freshness_interval_seconds: 21600      # 6h
  audit_freshness_tsa_url: https://freetsa.org/tsr
  audit_freshness_timeout_seconds: 30

  # Device serial binding. Each commitment costs at least three device log
  # entries (generate, attest, delete) plus session overhead, and the ring holds
  # 62 — so shortening this without also shortening audit_collect_interval_seconds
  # will fill it.
  audit_commitment_interval_seconds: 21600     # 6h
  audit_commitment_key_id: 0xfb00              # must be in 0xfb00..0xfbff
```

With `audit_freshness_tsa_url` unset both jobs fall back to the TSA configured for
[audit-chain anchoring](../signing/timestamping.md), then to the internal authority.

## Operating

```console
$ secsy-ca hsm-audit status
Device:          31650425 (firmware 2.4.0)
Device log:      3/62 used
Provisioned:     yes
Chain anchor:    940ff5892251586f8647e86c24d3811a
Collected up to: entry 47
Stored entries:  47 (31 signature(s))
Ledger entries:  31
Signing keys:    0x1939
Last attested:   2026-08-16T16:18:40Z (12m3s ago, 4 proof(s))
Device binding:  2026-08-16T16:18:41Z (12m2s ago, 4 commitment(s))
Audit config:    forced (irreversible until factory reset)
```

| Command | Purpose |
| --- | --- |
| `hsm-audit status` | Device audit configuration and collection state |
| `hsm-audit provision` | Commission a factory-reset device; pin the anchor |
| `hsm-audit collect` | Drain the device log once (the server does this continuously) |
| `hsm-audit timestamp` | Obtain one freshness attestation now |
| `hsm-audit commit` | Have the device sign, and the TSA date, a binding of the current head to its serial |
| `hsm-audit export -out FILE` | Write a remotely verifiable bundle, attesting every key that signed |
| `hsm-audit verify -bundle FILE` | Check a bundle — **needs no config, database or HSM** |

`GET /api/hsm/audit-bundle` (capability `audit:read`) serves the same bundle over
HTTP, with its SHA-256 in an `X-Bundle-Fingerprint` header, so an auditor can
pull it and verify offline.

## Verifying as a third party

The verifier is deliberately config-free: requiring the audited party's
`config.yaml` to check their own audit bundle would be absurd. Copy the bundle
anywhere and run:

Pass `-key` with the certificate whose key you want an answer about — that is
what turns a statement about a device into a statement about the key you hold:

```console
$ secsy-ca hsm-audit verify \
    -bundle bundle-2.json \
    -anchor 940ff5892251586f8647e86c24d3811a \
    -serial 31650425 \
    -key issuing-ca.pem \
    -published published.txt \
    -tsa-roots tsa-roots.pem \
    -require-external-tsa
OK: device 31650425, using 1 key(s) it attests are confined to it (0x1939 (issuing-ca))
performed 3 signature(s) since the factory reset, all accounted for by the published
artifacts; no key abuse detected, current as of 2026-08-16T16:18:40Z (8s ago,
attested by a timestamp authority)

  key 0x1939 issuing-ca               device   3  ledger   3  balanced   in-HSM, generated

Key issuing-ca.pem
  Public key:       SHA256:9O5vTL11FNF2/x7rfPNzg6g89xuJad5EKlGC8aaRnjc
  On-device handle: 0x1939 (issuing-ca)
  Non-exportable:   yes
  Generated in HSM: yes
  Device-signed:    yes
  Chain anchored:   no
  Handle history:   generated on-device at log entry 28, never deleted or exported
  Signatures:       device 3, accounted for 3
  Published match:  3 of 3
  OK: public key SHA256:9O5v… was generated inside YubiHSM 31650425 as object
  0x1939 (issuing-ca) and cannot be exported from it; the device performed 3
  signature(s) with it, all accounted for by the published artifacts — so this
  key has signed nothing else, on or off the device

Freshness: last attested 2026-08-16T16:18:40Z (8s ago), 2/2 proof(s) verified.

Device binding: device 31650425 signed for this log at 2026-08-16T16:18:41Z (7s ago),
2/2 commitment(s) verified, anchored to "Yubico YubiHSM Root CA".
```

`-key` accepts a certificate or a bare public key, and is repeatable. Exit status
is 0 only when every check passed, so this works as a compliance gate.

Verification runs ten checks, all of them even after one fails, so an operator
sees the whole picture rather than the first symptom:

1. The device is configured so no signature can escape the log.
2. The bundle's anchor is the one the auditor pinned.
3. The device log chain re-derives from the sentinel, gap-free.
4. The signature ledger chain re-derives.
5. Device signature counts equal ledger counts, per key.
6. Every key that signed is attested by the device as generated inside it and
   non-exportable, and the log shows its handle created once and never exported.
7. Every ledger digest corresponds to an independently obtained artifact.
8. A trusted authority attested to this history recently enough.
9. The device itself signed a commitment to this log, dated by that authority, so
   the serial the bundle names is Yubico-rooted hardware's own assertion.
10. Each `-key` is bound to an attested handle whose signatures are all accounted
    for.

Checks 1–6 and 9 need nothing but the bundle. Check 7 needs the auditor to have
collected the published artifacts themselves — from Certificate Transparency, a
CRL distribution point, or the published inventory — which is the only part of
the argument that cannot be delegated to the party being audited. Checks 8 and 9
need the CA to have been attesting and committing all along, which is why they
are background jobs and not something an export can retrofit.

Checks 5 and 6 are two halves of one claim. Counting operations without
attestation bounds the device; attestation without counting bounds the key's
confinement but not its use. Neither alone answers the question.

Checks 8 and 9 are likewise two halves — see [fact 7](#7-the-log-came-from-the-device-it-names).
Check 9 is also the only one whose subject is the *provenance* of the evidence
rather than its content: every other check reasons about a log that carries no
device identity and no signature, so all of them hold equally well over a
fabrication.

### Flags that change what the result means

| Flag | Without it |
| --- | --- |
| `-anchor` | Only internal consistency is checked; a wholly forged history built on an invented anchor would pass |
| `-key` | The verdict is about the device. It says nothing about whether any key you hold — the one in a CA certificate, say — is among the ones accounted for |
| `-published` | The bundle proves the device signed exactly what the ledger records — not that those records correspond to anything real |
| `-tsa-roots` | Tokens are checked against the certificate they embed, so an authority the CA controls would pass |
| `-max-age` | Defaults to 25h; `0` reports the age without failing on it |
| `-require-external-tsa` | An attestation from the CA's own HSM-backed TSA is accepted, with a note |
| `-attest-roots` / `-require-anchored-attestation` | Attestations must chain to Yubico's embedded roots either way — anchoring is on by default. `-attest-roots` adds anchors for a device whose sub-CA postdates this binary; `-require-anchored-attestation=false` downgrades the requirement to a report — see [key attestation](key-attestation.md#chain-anchoring) |
| `-allow-unattested-keys` | An unattested signing key fails the bundle. **Do not set it in a real audit**: it downgrades the one check that distinguishes a key's history from a device's |
| `-allow-unbound-log` | A log no HSM has signed for fails the bundle. **Do not set it in a real audit**: it downgrades the one check that distinguishes a device's log from a JSON file |

The verifier states these limits in its own output rather than leaving them
implicit.

### Comparing two exports

`-previous` checks that a bundle genuinely extends an earlier one — that
already-exported entries reappear byte-for-byte, that no attestation was
dropped — and reports the window in trusted-clock terms:

```console
$ secsy-ca hsm-audit verify -bundle bundle-2.json -previous bundle-1.json ...
Continuation: OK — 1 new device log entr(ies), 1 new signature(s) since the previous export.
  attested interval 2026-08-16T14:48:40Z .. 2026-08-16T16:18:40Z (1h30m0s)
```

This is what turns "no abuse so far" into "no abuse during this window", and it
is why an auditor should retain each bundle (or at least its fingerprint).

## What failure looks like

A signature the CA cannot account for:

```
VERIFICATION FAILED: cannot conclude that device 31650425 signed only what was published (1 finding(s))

  key 0x1939 issuing-ca               device   4  ledger   3  SURPLUS +1

  - key 0x1939 (issuing-ca): KEY ABUSE — the device performed 4 signature(s)
    but the CA accounts for only 3; 1 signature(s) exist that were never published
```

A signing key that could leave the device — note that the counts balance
perfectly, which is exactly why counting alone is not enough:

```
VERIFICATION FAILED: cannot conclude that device 31650425 signed only what was published (1 finding(s))

  key 0x7e5b legacy-signer            device   1  ledger   1  balanced   ATTESTATION FAILED

  - attestation for object 0x7e5b is not valid: key holds the exportable-under-wrap
    capability: its private material can be exported from the HSM under a wrap key,
    so confinement to hardware is only as strong as that wrap key
```

A key that signed but that the bundle cannot attest at all:

```
  - key 0x1939 signed 3 time(s) but the bundle carries no attestation for it:
    nothing shows that the private key is confined to this HSM, so signatures made
    with a copy of it elsewhere would leave no trace in this log
```

A bundle that is merely out of date:

```
Freshness: STALE — last attested 2026-08-16T14:48:40Z (1h31m ago); this export
cannot show what the HSM has signed since.
```

A log no device has signed for — the state of every deployment that has not run
`hsm-audit commit`, and also what a wholly fabricated history looks like:

```
Device binding: NONE — no HSM has signed for this log, so the serial it names is the CA's claim.

  - the bundle carries no device-signed commitments: nothing but the CA's own word
    connects this log to device 31650425. A YubiHSM audit log carries no serial
    number and no signature, so an internally consistent log can be fabricated
    offline; only a commitment signed by the device's factory attestation key ties
    one to real hardware
```

A commitment filed against a log that has no record of it — the certificate is a
genuine YubiHSM attestation, but it was not produced against *this* history:

```
  - commitment 3: the log contains no creation of the commitment key 0xfb00 after
    device entry 47. Generating it is a force-audited command, so a commitment
    genuinely made against this device would have left that entry — its absence
    means the certificate was produced somewhere this log does not describe
```

A negative surplus — the CA recording more signatures than the device log shows
— is equally fatal: the missing device entries could have been anything.

## Observability

| Metric | Meaning |
| --- | --- |
| `secsy_hsm_audit_entries_total` | Device log entries durably collected |
| `secsy_hsm_audit_signatures_total` | Successful signing operations observed in the device log |
| `secsy_hsm_audit_collection_failures_total` | Drain cycles that failed continuity verification and were not acknowledged |
| `secsy_hsm_audit_attestations_total{result}` | Freshness attestations, by result |
| `secsy_hsm_audit_commitments_total{result}` | Device serial bindings, by result |
| `secsy_hsm_audit_collection_staleness_seconds` | Since the last successful drain — growth precedes an issuance outage as well as an audit gap |
| `secsy_hsm_audit_attestation_age_seconds` | Since the last attestation, **measured on the TSA's clock**; once it exceeds the auditor's threshold, exports stop being able to prove they are current |
| `secsy_hsm_audit_commitment_age_seconds` | Since the HSM last signed for the log, on the TSA's clock; beyond this point the log is connected to the hardware by the CA's word alone |

## Limits

- **YubiHSM 2 only.** The device log, its chain digest and the fixed audit levels
  are YubiHSM features. Other backends get the signature ledger but not the
  independent bound the device log provides.
- **The ledger records digests, not signatures.** An auditor confirms a ledger
  row by recomputing the digest from a published artifact. Publishing the
  signature values themselves would add nothing: the artifact already carries it.
- **A surplus says a signature exists, not what it was.** The device log carries
  no digest of its input. Reconciliation localises abuse to a key and an
  interval; identifying the forged artifact is an investigation, not a lookup.
- **Attestations are gathered at export time.** A key deleted from the device can
  no longer be attested, so a bundle exported afterwards fails closed rather than
  vouching for it retroactively. Retain earlier bundles: they are the record that
  the key was confined while it was signing.
- **Anchoring needs the sub-CA that issued this device.** Yubico publishes it,
  named after its own subject key identifier, and the current one ships embedded
  — but a device whose sub-CA postdates this binary needs that one file before
  its attestation shows more than the key's properties *as asserted by a device*.
  See [key attestation](key-attestation.md#chain-anchoring). This applies to the
  commitments too: without an anchored chain, a serial binding is a serial the
  attesting thing chose to state.
- **A commitment is a host-supplied label.** The device signs the digest it is
  handed; it does not know it is attesting its own log. See [what a commitment
  does not prove](#what-a-commitment-does-not-prove).
- **A factory reset erases the chain and restarts the index**, so no chain and no
  commitment sequence can span one. Export and publish the log, and record the
  final chain digest externally, *before* any reset — the reset is itself an
  audit-erasing event that the resulting log cannot attest to.
- **The internal TSA is circular.** See the note above.

## Related

- [YubiHSM key attestation](key-attestation.md) — the device-signed proof that a
  key lives inside the HSM, which facts 5 and 7 above both depend on
- [Audit logging and SIEM export](../security/audit-siem-export.md) — the hash-chained
  `event_log` this sits alongside
- [Timestamping and audit anchoring](../signing/timestamping.md) — the RFC 3161 authority
  the attestation job reuses
- [HSM configuration](configuration.md) — connector, PIN sourcing, HA
