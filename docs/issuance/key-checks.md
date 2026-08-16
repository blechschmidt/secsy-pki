# Pre-issuance weak-key & compromised-key gate

secsy-pki runs a **fail-closed key-quality gate** on every certificate issuance,
rejecting weak and known-compromised **subject public keys** before the HSM signs
anything. It implements CA/Browser Forum Baseline Requirements **§6.1.1.3** ("the
CA SHALL reject a certificate request if … the Key is a known weak Key").

The gate runs on **every issuance surface** — REST/gRPC, ACME, EST, SCEP, CMP,
and SPIFFE — because it lives in the shared `ca.buildLeaf` signing path, and on
the Task 113 dry-run **preview** (`POST …/certificates:preview`,
`secsy-ca issue --dry-run`) through the same evaluator, so a preview verdict can
never drift from what real issuance enforces.

> Scope: the gate inspects the **subject** public key a caller asks the CA to
> certify. CA signing keys are generated inside the HSM and are covered by the key
> provider and the FIPS policy, not this gate.

## What it checks

| Check | What it rejects | Applies to |
|-------|-----------------|------------|
| **ROCA / CVE-2017-15361** | RSA moduli carrying the Infineon RSALib fingerprint (private key recoverable via Coppersmith). Detected by a discrete-log fingerprint over small primes — no factoring. | RSA |
| **RSA exponent policy** | Public exponent `e < 65537` or an even `e` (a valid RSA exponent is odd; the BRs require ≥ 65537). | RSA |
| **RSA modulus sanity** | An even modulus, or one below the minimum bit length (2048 by default). | RSA |
| **Debian weak keys (CVE-2008-0166)** | Keys whose fingerprint is in an operator-supplied blocklist (no blob is vendored). | any |
| **Operator compromised-key blocklist** | Keys an operator has explicitly blocked (`secsy-ca blocked-keys`). | any |
| **Duplicate / reused subject key** *(opt-in)* | A subject public key already certified for a **different** subject. | any |

A healthy ECDSA or Ed25519 key passes the RSA-specific checks (they simply do not
apply) and is still subject to the two blocklists and duplicate detection.

## Configuration

Per-profile policy lives in each profile's `key_checks` block. The gate is **on by
default** in enforce mode — a profile that omits the block still enforces it.

```yaml
# Deployment-wide inputs to the gate.
keychecks:
  # Optional Debian OpenSSL / operator weak-key blocklist(s). Files or directories
  # of fingerprints: hex SHA-256/SHA-1 of the DER SubjectPublicKeyInfo, or a
  # "SHA256:<base64>" fingerprint; '#' comments and blank lines are ignored.
  # A configured path that does not exist is a FATAL startup error (fail-closed).
  weak_key_blocklist_paths:
    - /etc/secsy-pki/weak-keys/

profiles:
  - name: server
    # ... key_usages, ext_key_usages, validity ...
    key_checks:
      mode: enforce            # enforce (default) | warn
      # disabled: true         # turn the gate off for this profile (discouraged)
      detect_duplicates: true  # flag a subject key reused across subjects
      # min_rsa_bits: 3072     # override the 2048-bit floor
```

- **`mode: warn`** records findings (audit event + metric) but issues anyway —
  an escape hatch for a migration window, not a steady state.
- **`detect_duplicates`** costs one indexed inventory lookup per issuance and is
  off by default because a key intentionally shared across subjects is
  occasionally legitimate. A renewal (same key, same subject) is never flagged.

## Operator compromised-key blocklist

Blocklist entries are keyed by the **SubjectPublicKeyInfo SHA-256 fingerprint**
(`SHA256:<base64>`, the same textual form as an OpenSSH SHA-256 fingerprint). The
store holds **no key material**.

```console
# Block a leaked/compromised key (from a cert, CSR, public key, or fingerprint):
secsy-ca blocked-keys add -cert leaked.pem   -reason "key compromise, INC-1234"
secsy-ca blocked-keys add -csr  device.csr   -reason "weak vendor key"
secsy-ca blocked-keys add -key  pub.pem       -reason "reported compromised"
secsy-ca blocked-keys add -fingerprint SHA256:abc… -reason "from CT/discovery"

secsy-ca blocked-keys list
secsy-ca blocked-keys remove SHA256:abc…
```

Blocking a key is a natural step in a **key-compromise incident**: after
[mass-revoking](../operations/incident-response.md) the affected certificates, block the key so
it can never be re-certified. Every add/remove is audited (`key.block` /
`key.unblock`).

## Observability

- **Audit:** `cert.keycheck` — one event per issuance that produced findings
  (`ResultError` when it blocked, `ResultSuccess` when warn-mode). The detail
  carries the profile, key fingerprint, and finding codes.
- **Metrics:** `secsy_certificate_key_checks_total{result=pass|warn|fail}` and
  `secsy_certificate_key_check_findings_total{code,mode}` (codes: `roca`,
  `weak_exponent`, `small_modulus`, `even_modulus`, `debian_weak_key`,
  `blocked_key`, `duplicate_key`).
- **Doctor:** `secsy-ca doctor` runs `keychecks.blocklist` (the weak-key file
  loads; the operator blocklist size) and `keychecks.profiles` (any profile that
  has weakened the gate).

## Design notes

- **Fail-closed.** A blocklist/inventory read error, or a configured-but-missing
  weak-key file at startup, refuses issuance / refuses to start — never silently
  disables the check. See [ADR 0003](../adr/0003-fail-closed-security-gates.md).
- **No vendored blob.** The Debian weak-key list (millions of fingerprints) is
  operator-supplied so the binary stays small and the operator controls the trust
  basis.
- **Not a factoring service.** The gate is a *structural* + *blocklist* gate. It
  does not attempt small-factor, Fermat-close-prime, or batch-GCD analysis.
