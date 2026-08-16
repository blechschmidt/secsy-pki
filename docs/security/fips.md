# FIPS 140-3 mode

secsy-pki can run as a FIPS-capable PKI. FIPS mode has **two independent
halves**, and a FIPS deployment needs both:

1. **The FIPS build** — the binaries are compiled against the [Go
   Cryptographic Module](https://go.dev/doc/security/fips140) (`GOFIPS140`),
   so every approved algorithm the Go standard library performs (TLS, X.509
   signing on the software provider, AES-GCM in the secret layer, hashing,
   randomness) runs inside the validated module, in FIPS mode, by default.
2. **The crypto policy** — `security.fips: true` in the configuration turns on
   secsy-pki's own **fail-closed algorithm allowlist**. This is what actually
   refuses non-approved algorithms: Go's `fips140=on` mode activates the
   module but deliberately keeps non-approved algorithms working, so without
   the policy an operator could still issue an Ed25519 leaf or fall back to
   SHA-1 OAEP.

They are decoupled on purpose: the policy also works on a non-FIPS build (a
staging rehearsal for algorithm hygiene), and a FIPS build without the policy
is useful for measuring performance deltas. `secsy-ca doctor` warns when the
policy is enforced on a non-module binary.

> **Scope, honestly stated.** Building with `GOFIPS140` means the Go crypto
> your binary performs happens inside Go's validated module boundary (see the
> [CMVP certificate status](https://go.dev/doc/security/fips140) for the exact
> module version and its validation state). It does **not** make a deployment
> "FIPS certified": overall compliance also depends on your HSM (which carries
> its **own** FIPS 140-2/140-3 validation — key generation and signing on a
> PKCS#11 token happen inside the *HSM's* boundary, not Go's), your platform,
> and your accreditation process. secsy-pki gives you the two technical
> halves — a module-backed binary and a fail-closed algorithm policy — plus
> the diagnostics to prove both are active.

## The approved set

With `security.fips: true`, everything not on this list is rejected:

| Approved | Notes |
|----------|-------|
| RSA ≥ 2048 | signing and OAEP key transport |
| ECDSA P-256 / P-384 / P-521 | |
| SHA-224/256/384/512 | SHA-2 family only |
| AES-256-GCM | the secret envelope cipher (unchanged) |

Explicitly rejected, with the reason:

| Rejected | Why |
|----------|-----|
| Ed25519 (keys and signatures) | Present in the Go module, but EdDSA support across validated HSMs, PKCS#11 mechanisms, and relying parties is inconsistent; the policy takes the conservative interoperable subset |
| ML-DSA (FIPS 204) pure-PQC and hybrid certificates | The implementation is CIRCL — software **outside** the validated module boundary |
| SHA-1, MD5 — anywhere | Including the SoftHSM RSA-OAEP SHA-1 fallback, SCEP/CMS SHA-1 digests, and CMP HMAC-SHA1/PBM-SHA1 protection |
| RSA < 2048 | |

## Where the policy is enforced

Every gate fails **closed** and wraps a common sentinel
(`internal/fips.ErrNotApproved`), so a rejection is always attributable:

- **Configuration load** — a config that names a non-approved algorithm
  (`tsa.accepted_hashes: [sha1]`, `est.server_keygen_key_type: rsa-1024`,
  `server.ocsp.delegated_key_type: ed25519`, …) fails `config.Load` with one
  message listing *every* violation and its config key. The server refuses to
  start; `secsy-ca doctor` shows the same text as a `config.parse` failure.
- **Key generation** — every key-provider backend (software, PKCS#11,
  PKCS#11-HA, cloud KMS) rejects non-approved key types in `GenerateKey`, so
  non-approved key material never comes into existence. This is also what
  blocks the software PQC provider path (`secsy-ca init-root -algorithm pqc`).
- **Certificate issuance** — the `pki` certificate constructors check both the
  issuer key and the subject key on every X.509 signing path (root,
  intermediate, cross-sign, leaf — REST, ACME, SCEP, EST, CMP, SPIFFE alike).
  A CA keyed with Ed25519 *before* the policy was enabled is therefore refused
  at its next issuance, not silently used. PQC/hybrid profiles are rejected at
  their dedicated issuance entry points and when installed as custom profiles.
- **Secret envelope layer** — see the next section.
- **Protocol edges** — SCEP stops advertising `SHA-1`/`DES3` capabilities and
  the CMS layer rejects SHA-1 digests in requests/signatures; CMP rejects
  SHA-1-based PBM/HMAC message protection.

The SKID/AKID derivation in certificates still uses SHA-1 per RFC 5280 §4.2.1.2
method 1 — that is a naming convention over public data, not a cryptographic
protection, and is unchanged.

## The SoftHSM SHA-1 OAEP interaction

SoftHSM 2.6.x supports RSA-OAEP **only with SHA-1** (a SHA-256 OAEP decrypt
fails with `CKR_ARGUMENTS_BAD`). The secret layer normally handles this by
negotiating the wrap algorithm per KEK — SHA-256 first, SHA-1 fallback.

Under `security.fips: true` that fallback is refused:

- Binding the secret service to a KEK whose token cannot unwrap SHA-256 OAEP
  **fails at startup** with:
  `secret: KEK "…" cannot RSA-OAEP unwrap with SHA-256, and security.fips
  refuses the SHA-1 fallback …`
- Envelopes already wrapped with `RSA-OAEP-SHA1` are **refused at decrypt**
  with a pointer to the remediation (below).
- `secsy-ca doctor` runs the same negotiation and reports it as the
  `fips.secret_oaep` check — a FAIL on SoftHSM, PASS (`… negotiates
  RSA-OAEP-SHA256`) on a capable provider.

**Migrate before you flip the flag.** If your deployment has SHA-1-wrapped
envelopes (it does, if the KEK ever lived on SoftHSM):

1. Provision a KEK on a SHA-256-OAEP-capable provider (a real HSM, or the
   software provider).
2. Rotate the KEK and re-wrap the stored envelopes (`secsy-secret rotate-kek`
   / `rewrap`, Task 63 tooling) — re-wrapping rewrites only the envelope
   header, not the ciphertext.
3. Enable `security.fips: true` and re-run `secsy-ca doctor`.

This ordering matters: re-wrapping *reads* the old envelopes, which requires
one last SHA-1 unwrap per envelope — legal before the policy is on, refused
after. Consequently SoftHSM is fine for the FIPS CI smoke tests (X.509 signing
uses no OAEP), but a FIPS deployment's secret layer needs a SHA-256-capable
provider.

## Building and verifying

```console
$ make build-fips                      # binaries -> dist/fips/, then self-verifies
==> verifying the binaries report FIPS mode at startup
    secsy-pki-server v1.2.3+fips go1.25.11 fips140=on (GOFIPS140=latest) policy=off
    secsy-ca v1.2.3+fips go1.25.11 fips140=on (GOFIPS140=latest) policy=off
    FIPS mode verified

$ make image-fips                      # container image tagged <version>-fips
$ docker build --build-arg GOFIPS140=latest -t secsy-pki:fips .   # equivalent
```

`GOFIPS140=latest` follows the toolchain's newest module snapshot; pin a frozen
validated version instead (`make build-fips GOFIPS140=v1.0.0`) for strict
change control — the value is recorded in the binary's build info. A
`GOFIPS140` build defaults `GODEBUG=fips140=on`, so no runtime flag is needed;
both the Makefile target and the Docker build **fail** if the produced server
does not report `fips140=on`.

Runtime verification, in order of convenience:

- **`-version`** — `secsy-pki-server -version` / `secsy-ca version` print
  `… fips140=on (GOFIPS140=latest) policy=enforced`.
- **Startup log** — the server logs `FIPS 140-3: fips140=… policy=…` right
  after loading the config, and a loud `WARNING` if the policy is enforced on
  a non-module binary.
- **`/healthz`** — the liveness payload carries a build block:

  ```json
  {"status":"ok","build":{"version":"v1.2.3+fips","go":"go1.25.11",
   "fips140":"on","fips140_module":"latest","fips140_policy":"enforced"}}
  ```

- **`secsy-ca doctor`** — with `security.fips: true` three checks report the
  posture: `fips.mode` (module active? warns with build guidance if not),
  `fips.store_keys` (every stored CA key/signature satisfies the policy —
  catches pre-FIPS Ed25519 CAs before their next issuance fails), and
  `fips.secret_oaep` (the KEK negotiation described above, per configured
  KEK including tenant overrides).

## Configuration

```yaml
security:
  fips: true
```

That is the whole switch. Review these knobs before enabling it — they are the
config-level surfaces the validator checks:

```yaml
tsa:
  accepted_hashes: [sha256, sha384, sha512]   # "sha1" would fail the load
signing:
  signers:
    - digest: sha256                          # sha256/384/512 only (already enforced)
est:
  server_keygen_key_type: rsa-2048            # no ed25519 / rsa-1024
server:
  ocsp:
    delegated_key_type: ecdsa-p256            # no ed25519
```

## CI

The `fips` job in `.github/workflows/enterprise-ci.yaml`:

1. runs `make build-fips` (which itself verifies `fips140=on`),
2. runs the full non-HSM unit suite with `GOFIPS140=latest` at build time and
   `GODEBUG=fips140=on` at runtime,
3. provisions SoftHSM and runs the e2e flow plus the OAEP-sensitive packages
   (`internal/secret`, `internal/doctor`) under `fips140=on`.

Under `fips140=on` the module handles approved algorithms and non-approved
ones keep working (that is Go's documented behavior — only `fips140=only`
hard-blocks, and it does so by panicking inside libraries), so the suite runs
green without blanket skips: the fail-closed behavior under test is the
`security.fips` policy, which the policy tests enable explicitly. The few
tests that must *generate* non-approved material as probes (e.g. RSA-1024
CSRs) guard that generation with explicit `t.Skip` reasons, so they degrade
cleanly if a stricter runtime mode ever refuses the generation itself.

## Operator checklist

1. Build/pull the FIPS image (`make build-fips` / `make image-fips`); confirm
   `-version` reports `fips140=on`.
2. Use an HSM with its own FIPS validation for CA/TSA/KEK keys; confirm it
   supports SHA-256 RSA-OAEP if you use the secret layer (SoftHSM does not).
3. Migrate SHA-1-wrapped envelopes (KEK rotate + re-wrap) **before** the flag.
4. Set `security.fips: true`; fix any load-time violations it reports.
5. Run `secsy-ca doctor` and get `fips.mode`, `fips.store_keys`, and
   `fips.secret_oaep` green.
6. Watch `/healthz` `build.fips140` / `build.fips140_policy` in monitoring —
   a redeploy with a non-FIPS image flips the field.

Related: [security review](security-review.md) (invariants the policy builds
on), [password/secret encryption](../secrets/password-encryption.md) (the envelope
scheme), [PQC](../certificates/pqc.md) (why ML-DSA is out of scope in FIPS mode),
[HSM configuration](../hsm/configuration.md).
