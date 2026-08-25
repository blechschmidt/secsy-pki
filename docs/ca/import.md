# Importing existing keys and adopting an existing CA

*Moving key material you already have under this PKI, without re-keying.*

Every other path in secsy-pki generates keys: a key is born inside the key
provider and its private half never exists anywhere else. That is the property
the whole design defends, and it is the right default.

It is also unavailable to anyone who already runs a CA. A root whose certificate
sits in laptops, phones, switches, and a build system nobody remembers
configuring cannot be re-keyed on a Tuesday — re-keying means redistributing the
trust anchor to everything that has it. The same is true of an application
signing key whose public half is compiled into clients that have already
shipped.

So secsy-pki supports **import**: taking key material that exists in a file and
placing it in the key provider, where the rest of its life is HSM-held, audited,
monitored, and gated like any other key. What import cannot do is change where
the key came from — and the tooling says so, at every step, rather than letting
a successful command imply otherwise.

| Command | Does |
|---|---|
| `secsy-ca ca import` | Adopt an existing CA: import its private key **and** install its existing certificate, producing an ordinary, issuing CA record |
| `secsy-ca import-key` | Place an existing private key into the key provider under a label (any role: CA, TSA, signing, secret) |
| `secsy-secret signing-key import` | Adopt an existing application signing key into the named-signing-key registry |

All three are **CLI-only by design**. Their input is raw private key material,
and the one thing that must not happen to raw private key material is another
copy of it travelling somewhere — least of all through a browser to a network
API. It is read once, from a local path, on an operator's shell. See
[deliberately CLI-only](../operations/web-console.md#deliberately-cli-only).

---

## Adopting an existing CA

The migration command. It imports the key, validates the certificate against it,
and persists an active CA record that issues, revokes, rotates, and publishes
exactly like a CA created here.

```bash
secsy-ca ca import \
  -label acme-legacy-root \
  -key   /secure/legacy-root.key \
  -pass-file /secure/legacy-root.pass \
  -cert  /secure/legacy-root.crt \
  -chain-out chain.pem
```

```
Adopted existing root CA "acme-legacy-root":
  ID:        5a763454-a640-4be8-90f1-cb270aa50e7a
  Subject:   CN=Acme Legacy Root CA,O=Acme Corp
  Serial:    205680955909635647595802196839725969470470860684
  Validity:  2026-08-25T20:36:04Z — 2036-08-22T20:36:04Z
  Key:       pkcs11:token=secsy-pki-root;object=acme-legacy-root;type=private (ecdsa-sha2-nistp384)
  Imported:  key material read from legacy-root.key (pkcs8-encrypted) and written into the provider
  Verified:  the provider signed a challenge with the key and it matches the certificate
```

From that point the CA is unremarkable:

```bash
secsy-ca issue -ca acme-legacy-root -profile server -csr svc.csr -out svc.crt
openssl verify -CAfile legacy-root.crt svc.crt      # svc.crt: OK
```

The certificate it just issued verifies against the root certificate the world
already trusts. That is the entire point: nothing downstream had to change.

### What is checked, and why

An adoption that binds a CA record to the wrong key produces an authority that
looks healthy and signs certificates nothing can verify — discovered at the
worst possible moment. Every check below is therefore fail-closed:

| Check | Rejected because |
|---|---|
| The private key's public half equals the certificate's public key | Otherwise the CA record points at a key that cannot have issued anything under that certificate. Checked **before** anything is written, so a mismatch never strands key material on the token |
| `basicConstraints` present with `cA=TRUE` | A leaf certificate is not a CA |
| `keyUsage` includes `keyCertSign` (when `keyUsage` is present) | Certificates issued under it would not verify |
| The certificate is currently valid | An expired CA cannot issue; re-certify the key first |
| A self-signed certificate verifies under its own key | Catches a truncated or mispasted root before it becomes a trust anchor no path can be built through |
| The key passes the [key-quality gate](../issuance/key-checks.md) | A ROCA-vulnerable or blocklisted key is not rehabilitated by moving it into an HSM — the HSM cannot un-factor it |
| The provider can actually sign with the key | Proved with a real signature over a random challenge, verified against the expected public key, before the CA record is persisted |

Deviations that do not break issuance are reported as **warnings** and the
import proceeds: a missing `cRLSign` or `digitalSignature` key usage, a
certificate expiring within 90 days, a missing `keyUsage` extension entirely.

### Where the parent goes

For a subordinate CA the issuer is resolved automatically:

- If a CA already in this PKI has the matching subject *and* its certificate
  verifies the signature, the adopted CA is **linked to it** (`parent_id`). Chain
  serving, rotation, and revocation then walk the real tree. Adopt the root
  first and this happens on its own.
- Otherwise the certificates supplied via `-chain` are recorded as **external
  chain material**, exactly as in the
  [externally-signed subordinate CA](external-ca.md) flow, so the served chain
  still reaches the external trust anchor.
- `-parent <id|label>` names the parent explicitly; the certificate must
  genuinely verify under it.

### Input formats

`-key` accepts what operators actually have:

| Format | Typical origin |
|---|---|
| PKCS#8 `PRIVATE KEY` | `openssl genpkey`, `openssl genrsa` (OpenSSL 3) |
| PKCS#8 `ENCRYPTED PRIVATE KEY` (PBES2 + PBKDF2, AES-CBC or 3DES) | `openssl genpkey -aes256`, `openssl pkcs8 -topk8` |
| PKCS#1 `RSA PRIVATE KEY` / SEC1 `EC PRIVATE KEY` | `openssl genrsa` (OpenSSL 1.x), `openssl ecparam -genkey` |
| Legacy `Proc-Type: 4,ENCRYPTED` PEM (DEK-Info) | pre-3.0 `openssl genrsa -aes256` — still guarding plenty of long-lived roots |
| `OPENSSH PRIVATE KEY`, optionally bcrypt-encrypted | `ssh-keygen` |
| PKCS#12 / `.p12` / `.pfx` | Windows CA export, browser export — carries the certificate too |
| Bare DER (PKCS#8 / PKCS#1 / SEC1) | Appliance exports |

A `.p12` supplies key **and** certificate, so `-cert` becomes optional:

```bash
secsy-ca ca import -label acme-from-p12 -key legacy-root.p12 -pass-file p12.pass
```

Passphrases are read from `-pass-file <file>` (`-` reads stdin) or the
`SECSY_KEY_PASSPHRASE` environment variable. There is deliberately no `-pass`
flag: a passphrase on the command line lands in the shell history and the
process table.

### Adopting a key that is already in the provider

When the key was placed on the token out of band — by a vendor migration tool, a
wrapped restore, or an earlier `import-key` — adopt it by label instead. Nothing
is written to the backend; the key is only verified to match the certificate and
to be usable:

```bash
secsy-ca import-key -label legacy-root-key -key legacy-root.key -pass-file pass.txt
secsy-ca ca import  -label acme-legacy-root -existing-key legacy-root-key -cert legacy-root.crt
```

### Four-eyes

Adopting a CA *creates* one, so it passes through the same
[maker-checker gate](../security/approvals.md) as `init-root` and
`issue-intermediate` (`ca.create` class) when `approvals.enabled` is set. An
authority appearing in the tree without a second signature is precisely what
that gate exists to prevent.

---

## Importing a bare key

`secsy-ca import-key` is the building block — a TSA key, an artifact-signing
key, an SSH CA key, or staging a CA key for `ca import -existing-key`:

```bash
secsy-ca import-key -label legacy-tsa -key tsa.key -role tsa
```

`-role` (`ca` | `tsa` | `signing` | `secret`) selects which backend receives the
key, since those roles may resolve to different providers. `-usage decrypt`
imports an RSA key-encryption key for the [envelope layer](../secrets/password-encryption.md)
instead of a signing key.

For a signing key the command proves the provider can sign with it — a real
signature over a random challenge, verified against the key's own public half —
before reporting success. A decrypt-only key cannot sign and is exempt.

## Importing an application signing key

The secret-layer counterpart, for a key whose public half is already embedded in
shipped clients:

```bash
secsy-secret signing-key import -name release-signing -key app-signing.key -out pub.pem
```

The algorithm is derived from the key for ECDSA and Ed25519. **RSA needs an
explicit `-algorithm`**, because the same key can be used with PSS or PKCS#1
v1.5 and the choice must match whatever the existing verifiers already do —
guessing would produce signatures nothing accepts.

Continuity is the whole point, and it holds end to end: after the import, a
signature produced on the HSM verifies with plain `openssl` against the
application's original public key file.

```bash
secsy-secret sign -key release-signing -in payload.txt -out payload.sig
openssl pkeyutl -verify -pubin -inkey app-signing.pub -rawin -in payload.txt -sigfile payload.sig
# Signature Verified Successfully
```

---

## What import does not give you

**Protection: yes.** An imported key is stored with exactly the attributes a
generated key gets — `CKA_SENSITIVE`, `CKA_EXTRACTABLE=false`, `CKA_PRIVATE`,
and a single purpose (sign **or** decrypt, never both). It cannot be wrapped
back off the device. On a high-availability multi-token set it is imported onto
every member, so failover does not turn into an outage; if any member rejects
it, the error names the tokens that already hold the key so the split is
resolved deliberately rather than discovered under load.

**Provenance: no, and it cannot.** The key existed outside the provider before
it arrived. Two consequences that no amount of tooling can undo:

1. **Hardware attestation reports it as imported.** A YubiHSM's own key
   attestation records the origin of every key, and secsy-pki's
   [attestation verifier](../hsm/key-attestation.md) surfaces it. A policy that
   requires generated-on-device keys will fail an imported one — correctly. The
   `-allow-imported` flag (and `attestation_allow_imported_keys`) exists for
   exactly the migrated-CA case, and it should be scoped to that CA rather than
   turned on globally.
2. **Every copy made before the import is still a copy.** Backups, the laptop it
   was generated on, the ticket someone attached it to. The import moves the
   authoritative key; it does not reach the others. Destroying them is an
   operator task, and the CLI ends with that reminder.

A related consequence for the [remotely verifiable audit log](../hsm/audit-log.md):
the argument that a key signed nothing outside the published record rests on the
key never having left the device. For an imported key that argument starts at
the import, not at key generation. The `key.import` audit event is the marker of
where it starts.

**On the software keystore, import protects nothing.** The software provider
stores keys as files; importing into it moves the key, it does not secure it.
The command says so, and adoption onto it emits a warning. Configure a PKCS#11
backend for production CA keys.

## Backends that cannot import

The cloud-KMS backends (AWS KMS, Azure Key Vault, GCP KMS, Vault Transit) do not
implement import: bringing your own key there is a service-specific wrapped-
import ceremony against the provider's own API, not a key-material upload. The
command reports that plainly rather than pretending:

```
error: keyprovider: this backend cannot import an existing key (backend "kms");
       generate the key instead, or use the backend's own bring-your-own-key procedure
```

## Audit trail

| Event | Recorded on |
|---|---|
| `key.import` | Any key placed into a provider — detail carries backend, key type, source file format, usage, and whether the signing self-check passed |
| `ca.import` | A CA adopted — detail carries subject, serial, self-signed, whether key material was written, the key's SPKI fingerprint, and any warnings |
| `secret.signing_key_import` | An application signing key adopted — algorithm, key id, source format |

These are the provenance record. A key with a `key.import` event in its history
is a key that lived outside the provider first — which is exactly what hardware
attestation independently reports.

## Serial numbers after adoption

End-entity serials are random 128-bit values, so nothing the adopted CA issues
from now on can collide with what it issued before. Subordinate-CA serials come
from a per-CA counter that starts fresh, which *can* collide with an
intermediate the legacy deployment issued from a low sequential counter. The
import warns about this; revoke or retire those intermediates before issuing new
ones under the adopted CA.

---

↩ Back to the [CA section](README.md) · [documentation map](../README.md)
