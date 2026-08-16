# Intermediate CA key rotation & rollover

Signing keys don't live forever. An intermediate ("issuing") CA key must be
rotated periodically — as it nears the end of its own validity, to shorten key
lifetimes as a matter of hygiene, or urgently in response to a suspected
compromise. The hard requirement is **continuity**: rotating the key must not
break the certificates already issued under the old key.

secsy-pki performs rotation as an HSM-backed, three-stage rollover with a
**dual-chain overlap window**, so old and new chains both validate until the old
key has drained.

Every signing operation in this workflow happens **inside the key provider**
(the HSM via PKCS#11, or the software keystore in dev/CI). The new private key is
generated on the device and never leaves it, exactly like the original CA keys
(see [HSM configuration](../hsm/configuration.md) and
[Key ceremony](../hsm/key-ceremony.md)).

---

## The rollover model

```
            root CA (unchanged trust anchor)
             │  signs both intermediates
   ┌─────────┴──────────┐
   ▼                    ▼
old intermediate     new intermediate      ← same Subject DN, different key
(superseded)          (active)
   │                    │
   ▼                    ▼
leaves signed by     leaves signed by
the old key          the new key
   └────────┬───────────┘
            ▼
   both validate during the overlap window
   (combined chain / AIA bundle carries both intermediates)
```

Three controlled stages:

1. **Rotate.** A fresh keypair is generated inside the provider. A new
   intermediate certificate is **cross-signed under the same parent (root)**,
   carrying the **same Subject DN** as the old intermediate so it is a drop-in
   issuer — only the key (and its Subject Key Identifier) changes. The old CA is
   marked `superseded`; it keeps validating the leaves it already signed. New
   issuance is automatically directed at the new key.

2. **Overlap.** Both intermediate certificates are published together as a
   **combined chain / bundle**. A leaf signed by the old key chains through the
   old intermediate; a leaf signed by the new key chains through the new one.
   Relying parties pick the correct issuer by Authority Key Identifier, so a
   single bundle validates both.

3. **Retire.** Once no leaves signed by the old key remain valid (they have
   expired or been re-issued onto the new key), the old intermediate is revoked
   under its parent and the parent CRL/OCSP is refreshed, decommissioning the
   retired key. Retirement is **refused while outstanding leaves remain** unless
   explicitly forced (for emergency key-compromise response).

### Why continuity holds

* The new intermediate keeps the **same Subject DN**, so it is a valid issuer for
  the same `Issuer` field that appears in already-issued leaves.
* Each leaf carries an **Authority Key Identifier** matching the Subject Key
  Identifier of the key that signed it. During overlap both intermediates are in
  the bundle, so a verifier deterministically selects the right one.
* The **root is untouched** — the trust anchor never changes, so nothing needs to
  be re-distributed to relying parties beyond the intermediate bundle.

---

## CLI (`secsy-ca`)

Rotation is a ceremony-style operation, mirroring `secsy-ca ceremony`: when you
enroll operators it requires an M-of-N confirmation quorum and writes an
auditable transcript. All events are recorded in the tamper-evident audit log
([RBAC & audit](../security/rbac-and-audit.md)).

| Command | Purpose |
|---------|---------|
| `rotate-intermediate` | Generate a new key, cross-sign a new intermediate under the parent, open the overlap window |
| `rotation-status` | Show a CA's rollover state (superseded/active, predecessor/successor, outstanding leaves, safe-to-retire) |
| `list-rotations` | List all CAs currently in a rollover lineage |
| `publish-chain` | Emit the combined overlap chain (AIA/bundle) for a CA |
| `retire-intermediate` | Retire a drained, superseded key: revoke it under the parent and refresh the parent CRL |

### Rotate

```bash
# Simple rotation (no quorum); writes a transcript and the combined chain.
secsy-ca -config config.yaml rotate-intermediate \
    -ca issuing-ca \
    -transcript-out rotation.json \
    -chain-out combined-chain.pem
```

Flags: `-new-label` (default derives an `-rN` generation suffix), `-key-type`
(default reuses the current key's type), `-validity-days` (default reuses the
old certificate's original span, always clamped to the parent's expiry).

Ceremony-style, 2-of-3 quorum (identical confirmation mechanics to
`secsy-ca ceremony`):

```bash
printf 'alice:phrase-a\nbob:phrase-b\n' | secsy-ca rotate-intermediate \
    -ca issuing-ca -operators alice,bob,carol -quorum 2 -non-interactive
```

### Inspect

```bash
secsy-ca rotation-status -ca issuing-ca        # human-readable
secsy-ca rotation-status -ca issuing-ca -json  # machine-readable
secsy-ca list-rotations                        # all CAs in a rollover lineage
```

### Publish the bundle

```bash
secsy-ca publish-chain -ca issuing-ca -out bundle.pem
```

Serve `bundle.pem` wherever relying parties fetch issuer certificates (AIA, a
static bundle, your ingress). During overlap it contains **both** intermediates
plus the parent chain; after retirement it drops the retired key.

### Retire

```bash
# Refused while old-key leaves are still valid:
secsy-ca retire-intermediate -ca issuing-ca
# error: cannot retire ...: N leaf certificate(s) signed by the old key are
#        still valid; safe to retire after <timestamp> ...

# After the old key has drained (leaves expired or re-issued):
secsy-ca retire-intermediate -ca issuing-ca \
    -reason cessationOfOperation -crl-out root-crl.der
```

`-force` retires despite outstanding leaves — this **intentionally breaks** those
chains and is meant only for key-compromise response, where invalidating the old
key is the goal. `retire-intermediate` accepts the same `-operators`/`-quorum`
confirmation flags as rotation.

After retirement, **publish the refreshed parent CRL** (written to `-crl-out`, or
served live from `/api/ca/{parent}/crl`) so relying parties learn the old
intermediate is revoked.

---

## HTTP API

A public, unauthenticated endpoint serves the combined bundle for relying
parties (like CRL/OCSP):

```
GET /api/ca/{id}/chain      → application/x-pem-file
```

Returns the active intermediate, any overlapping superseded siblings, and the
parent chain up to the root — the same bundle as `secsy-ca publish-chain`.

Rotation and retirement themselves are administrative, ceremony-style operations
and are driven through the `secsy-ca` CLI rather than the API.

---

## Automatic rotation via the expiry monitor

The background [expiry monitor](../operations/expiry-monitoring.md) can trigger rotation
automatically as an intermediate nears expiry, so long-lived issuing keys roll
over ahead of time without manual intervention. Retirement remains a deliberate,
manual step.

```yaml
monitor:
  enabled: true
  interval_hours: 12
  warning_days: 30
  rotate_intermediates: true   # enable auto-rotation of intermediates
  rotate_before_days: 45       # rotate when the intermediate cert has <= 45 days left
                               # (default: warning_days)
```

On each scan the monitor rotates every **active** intermediate whose own
certificate falls within `rotate_before_days`, opening the overlap window and
recording a `ca.rotate` audit event. New issuance immediately uses the fresh key;
old-key leaves keep validating through the published bundle until they drain, at
which point an operator retires the old key.

Environment override: set `SECSY_MONITOR_ROTATE_INTERMEDIATES=true` to enable
auto-rotation without editing the config file (the threshold still comes from
`rotate_before_days`).

---

## Draining strategy

The old key is "drained" when it has no outstanding valid leaves. Two levers:

* **Expiry.** Short-lived leaves drain on their own. `rotation-status` shows the
  recorded `retire_after` deadline (the latest `NotAfter` among the outstanding
  leaves at rotation time) as a hint.
* **Re-issuance.** New issuance is automatically routed to the new key, so any
  workload that re-requests a certificate (ACME renewal, SCEP/EST re-enrollment,
  `secsy-ca issue` against the same CA reference) moves onto the new key.

Retirement is gated on a **live** outstanding-leaf check, not the stored hint —
so it is always safe: the old chain cannot break as long as you retire without
`-force`.

---

## Rotation drill (SoftHSM)

`scripts/rotation-drill.sh` exercises the whole rollover end-to-end in an
isolated SoftHSM sandbox and asserts continuity with `openssl verify`:

```bash
./scripts/rotation-drill.sh            # runs and cleans up
ROT_KEEP=1 ./scripts/rotation-drill.sh # keep the workspace for inspection
```

It provisions a fresh token, creates a root + intermediate, issues a leaf under
the old key, rotates the intermediate, issues a leaf under the new key, and
proves **both** leaves validate against the single combined overlap chain. It
then shows premature retirement being refused, drains the old key, retires it,
and verifies the root CRL lists the retired intermediate and that the freshly
published chain no longer carries it.

---

## Tests

* `server/internal/ca/rotation_test.go` (build tag `sqlite`) — runs against both
  the software provider and SoftHSM (`pkcs11`). Proves an old-key leaf validates
  against the combined chain after rotation, that new issuance routes to the new
  key, controlled/forced retirement, and the monitor-facing `AutoRotateDue`
  trigger (only near-expiry intermediates rotate).
* `server/internal/monitor/runner_rotation_test.go` — the monitor runner triggers
  rotation only when enabled, with the configured threshold, and audits it.

Run them with:

```bash
cd server
eval "$(../scripts/setup-softhsm.sh --export-env)"   # optional: enables the pkcs11 subtests
go test -tags sqlite ./internal/ca/ ./internal/monitor/ -run 'Rotation|Retire|AutoRotate|Runner' -p 1
```
