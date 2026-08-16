# Remotely Verifiable HSM Audit Log

secsy-pki can turn a YubiHSM 2's on-device audit log into evidence that a third
party can check: **this HSM has produced no signature beyond the ones the CA
published, and that is still true as of a recent, independently attested
moment.**

That is a stronger claim than "we keep logs", and it is deliberately built so
that it holds even against the operator running the CA — someone who holds the
HSM authentication key, the database credentials and the export tooling.

## Why the device log alone is not enough

A YubiHSM log entry records that key `0x1939` performed an ECDSA signature. It
does **not** record what was signed. So the device log by itself cannot tell 412
legitimate certificate signatures from 411 legitimate ones plus one forged
certificate — the counts are identical.

The proof is therefore assembled from five independent facts, each of which must
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

The device log is a 62-entry ring buffer. A leader-elected collector drains it
continuously, and each drained segment must start exactly where the previous one
stopped: the successor entry number, and a chain digest that hashes forward from
the stored one. A dropped, reordered, or silently re-fetched segment breaks one
of the two.

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
value that is not derived from the sentinel's fields — verified on hardware: two
factory resets of the same device produced sentinels with byte-identical
all-`0xff` fields but different digests. So an unpinned chain proves only
internal consistency: an attacker could invent a sentinel, pick any anchor, and
hash a perfectly consistent forged history forward from it.

`hsm-audit provision` prints the anchor once. **Record it outside this system.**
An auditor who only ever learns it from the CA learns nothing.

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

### 5. The evidence is current

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
```

With `audit_freshness_tsa_url` unset the job falls back to the TSA configured for
[audit-chain anchoring](timestamping.md), then to the internal authority.

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
Last attested:   2026-08-16T16:18:40Z (12m3s ago, 4 proof(s))
Audit config:    forced (irreversible until factory reset)
```

| Command | Purpose |
| --- | --- |
| `hsm-audit status` | Device audit configuration and collection state |
| `hsm-audit provision` | Commission a factory-reset device; pin the anchor |
| `hsm-audit collect` | Drain the device log once (the server does this continuously) |
| `hsm-audit timestamp` | Obtain one freshness attestation now |
| `hsm-audit export -out FILE` | Write a remotely verifiable bundle |
| `hsm-audit verify -bundle FILE` | Check a bundle — **needs no config, database or HSM** |

`GET /api/hsm/audit-bundle` (capability `audit:read`) serves the same bundle over
HTTP, with its SHA-256 in an `X-Bundle-Fingerprint` header, so an auditor can
pull it and verify offline.

## Verifying as a third party

The verifier is deliberately config-free: requiring the audited party's
`config.yaml` to check their own audit bundle would be absurd. Copy the bundle
anywhere and run:

```console
$ secsy-ca hsm-audit verify \
    -bundle bundle-2.json \
    -anchor 940ff5892251586f8647e86c24d3811a \
    -serial 31650425 \
    -published published.txt \
    -tsa-roots tsa-roots.pem \
    -require-external-tsa
OK: device 31650425 performed 3 signature(s) since the factory reset, all
accounted for by the published artifacts; no key abuse detected, current as of
2026-08-16T16:18:40Z (8s ago, attested by a timestamp authority)

  key 0x1939 issuing-ca               device   3  ledger   3  balanced

Freshness: last attested 2026-08-16T16:18:40Z (8s ago), 2/2 proof(s) verified.
```

Verification runs seven checks, all of them even after one fails, so an operator
sees the whole picture rather than the first symptom:

1. The device is configured so no signature can escape the log.
2. The bundle's anchor is the one the auditor pinned.
3. The device log chain re-derives from the sentinel, gap-free.
4. The signature ledger chain re-derives.
5. Device signature counts equal ledger counts, per key.
6. Every ledger digest corresponds to an independently obtained artifact.
7. A trusted authority attested to this history recently enough.

Checks 1–5 need nothing but the bundle. Check 6 needs the auditor to have
collected the published artifacts themselves — from Certificate Transparency, a
CRL distribution point, or the published inventory — which is the only part of
the argument that cannot be delegated to the party being audited. Check 7 needs
the CA to have been attesting all along, which is why it is a background job and
not something an export can retrofit.

### Flags that change what the result means

| Flag | Without it |
| --- | --- |
| `-anchor` | Only internal consistency is checked; a wholly forged history built on an invented anchor would pass |
| `-published` | The bundle proves the device signed exactly what the ledger records — not that those records correspond to anything real |
| `-tsa-roots` | Tokens are checked against the certificate they embed, so an authority the CA controls would pass |
| `-max-age` | Defaults to 25h; `0` reports the age without failing on it |
| `-require-external-tsa` | An attestation from the CA's own HSM-backed TSA is accepted, with a note |

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

A bundle that is merely out of date:

```
Freshness: STALE — last attested 2026-08-16T14:48:40Z (1h31m ago); this export
cannot show what the HSM has signed since.
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
| `secsy_hsm_audit_collection_staleness_seconds` | Since the last successful drain — growth precedes an issuance outage as well as an audit gap |
| `secsy_hsm_audit_attestation_age_seconds` | Since the last attestation, **measured on the TSA's clock**; once it exceeds the auditor's threshold, exports stop being able to prove they are current |

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
- **The internal TSA is circular.** See the note above.

## Related

- [Audit logging and SIEM export](audit-siem-export.md) — the hash-chained
  `event_log` this sits alongside
- [Timestamping and audit anchoring](timestamping.md) — the RFC 3161 authority
  the attestation job reuses
- [HSM configuration](hsm-configuration.md) — connector, PIN sourcing, HA
