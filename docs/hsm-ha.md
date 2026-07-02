# HSM high availability: multi-token failover

A single HSM is a single point of failure for a CA. Task 44 makes PKCS#11 key
access resilient by letting the key-provider span **several tokens/slots**, each
holding a replica of the same signing key(s), behind health-tracked failover.
Signing is routed to a healthy token; a token that starts erroring is taken out
of rotation and returned once it recovers. Issuance keeps working as long as one
replica is reachable.

This builds directly on the single-token PKCS#11 backend (see
[HSM / PKCS#11 configuration](hsm-configuration.md)) and the bounded session pool
(see [benchmarks](benchmarks.md)); each token in the set is an ordinary pooled
provider, and the HA layer composes them with failover.

## When to use it

Use a multi-token set when you run more than one HSM (or more than one partition
of a clustered/network HSM) that each hold a copy of the CA key, and you want
signing to survive one of them going away — a device fault, a network partition
to a network HSM, a firmware upgrade, or planned maintenance.

If you have a single token, leave `pkcs11.tokens` empty; nothing changes.

## Configuration

```yaml
key_provider:
  type: "pkcs11"

pkcs11:
  module_path: "/usr/lib/pkcs11/vendor_pkcs11.so"
  pin: "user-pin"                 # shared PIN; each token may override below
  session_pool_size: 8           # per-token session pool size

  selection_policy: "primary-backup"   # or "round-robin"
  failure_threshold: 3                 # consecutive failures before out of rotation
  probe_interval_seconds: 15           # background recovery-probe cadence
  tokens:
    - name: "hsm-a"              # stable identifier used in metrics and logs
      token_label: "secsy-ca-a" # (or token_serial / token_manufacturer)
      # pin: "..."              # optional per-token PIN; falls back to pkcs11.pin
    - name: "hsm-b"
      token_label: "secsy-ca-b"
```

All tokens share `module_path` and `session_pool_size`; each addresses a distinct
token by label/serial/manufacturer and may carry its own PIN. `name` defaults to
`token_label` and is what appears in the per-token metrics.

### Selection policy

| Policy | Behaviour |
|--------|-----------|
| `primary-backup` (default) | Always prefer the first healthy token in configured order. Backups are used only while higher-priority tokens are unhealthy. Predictable: one token carries the load, the rest are hot standbys. |
| `round-robin` | Spread operations across all currently-healthy tokens. Use when every HSM should share the signing load. |

On failover, the next candidate in policy order is tried, so a signature in
flight when a token drops out still completes on another token. A long-lived
signer obtained from `Signer()` re-selects a healthy token on **every** `Sign`,
so it keeps working across a failover without being re-fetched.

### Environment overrides

The token list is file-only (it is a list), but the two knobs are overridable so
you can retune per environment without re-rendering the token block:

| Variable | Setting |
|----------|---------|
| `SECSY_PKCS11_SELECTION_POLICY` | `pkcs11.selection_policy` |
| `SECSY_PKCS11_FAILURE_THRESHOLD` | `pkcs11.failure_threshold` |

## Health tracking

- A token is marked **unhealthy** after `failure_threshold` consecutive
  health-affecting failures — PKCS#11 transport/session errors or failed probes.
  A logical *key-not-found* is a property of the request, not the token, so it
  never counts against health.
- An unhealthy token is taken out of rotation (routed last, as a last resort so a
  fully-degraded set still attempts the operation).
- A background prober re-checks every token on `probe_interval_seconds`, and a
  live operation that succeeds also counts as recovery, so a token returns to
  rotation as soon as it is healthy again.
- Readiness (`/readyz`) reports the HSM up when **at least one** token is
  reachable.

## Replicated keys and the unique-label invariant

Failover for a **CA** only works if the backup token holds the *same* key — a
signature made on the backup must verify against the one CA public key. Because
HSM private keys are non-extractable, you cannot get identical keys by generating
independently on each token; the replica is placed there by an **operator key
ceremony** (import of a shared key, or a vendor clone/backup-restore between
tokens). See [key ceremony & DR](key-ceremony.md).

Across a set, replicas intentionally share one `CKA_LABEL` (that is how failover
finds "the same key" on another token). Within any one token the label must still
be unique: two differently-keyed pairs under one label resolve ambiguously and
produce signatures that fail verification (the
[duplicate-label](hsm-configuration.md#key-labels-must-be-unique) hazard). The HA
provider preserves this: `GenerateKey` refuses a label that already exists on
**any** token in the set, fails closed if a token cannot be checked, and creates
the key on the primary only — replication is the ceremony step above, not
something the provider does by regenerating.

## Metrics

Per-token series (labelled by `token` = the configured `name`):

| Metric | Meaning |
|--------|---------|
| `secsy_hsm_token_up` | 1 = healthy and in rotation, 0 = unhealthy / failed over away from |
| `secsy_hsm_token_failovers_total` | Operations that failed on this token and were retried on another |
| `secsy_hsm_token_errors_total` | Operation errors charged to this token's health (excludes key-not-found) |

Aggregate key-provider latency/outcome (`secsy_hsm_operation_duration_seconds`,
`secsy_hsm_operations_total`) continue to reflect the *post-failover* result, so
a successful failover is recorded as a success.

Suggested alerts:

- `secsy_hsm_token_up == 0` for a token → that HSM is down; the set is running on
  fewer replicas.
- `sum(secsy_hsm_token_up) < 2` → no headroom left for another failure.
- `rate(secsy_hsm_token_failovers_total[5m]) > 0` sustained → a token is flapping.

## Validation

`server/internal/keyprovider/pkcs11_ha_softhsm_test.go` is the end-to-end proof:
it initialises two SoftHSM tokens, imports the same EC CA key into both under one
label, drives a concurrent signing load through the HA provider, pulls the
primary token out **mid-load**, and asserts every signature still verifies (on the
backup), that the per-token health and failover metrics reflect the event, and
that the token returns to rotation once it recovers. Run it with a SoftHSM token
configured:

```bash
eval "$(scripts/setup-softhsm.sh --export-env)"
cd server && go test -p 1 -run TestPKCS11HAFailover ./internal/keyprovider/
```
