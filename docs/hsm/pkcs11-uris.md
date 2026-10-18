# PKCS#11 URIs in the configuration

[RFC 7512](https://www.rfc-editor.org/rfc/rfc7512) defines a `pkcs11:` URI that
names a PKCS#11 object the way the PKCS#11 world actually identifies one. Every
place secsy-pki's configuration names a token or a key accepts such a URI.

This page is the reference for which fields accept one, what each is allowed to
carry, and why the two kinds are not interchangeable.

## Why a URI rather than a label

A `CKA_LABEL` is not a key identity.

- In a [high-availability set](high-availability.md) the replicas deliberately
  share one label — that is what makes them replicas. The label cannot say
  *which* device signed.
- A token can hold two objects with the same label. Resolving such a label can
  pair the public half of one key with the private half of another, producing
  signatures that fail verification. (secsy-pki refuses to *create* a duplicate
  label for this reason, but it cannot un-create one a vendor tool left behind.)
- A key imported by a migration tool, a wrapped restore, or a vendor utility has
  whatever label that tool chose — sometimes none.

`pkcs11:id=%01%02;serial=0001234` names exactly one object on exactly one
device. It is also the string `p11tool --list-all` and `pkcs11-tool -O` already
print, so it can be copied rather than retyped.

## The two kinds of URI

| | Addresses | Where it goes | Must name an object | May carry the module / PIN |
|---|---|---|---|---|
| **Token URI** | the device | `pkcs11.uri`, `pkcs11.tokens[].uri` | no — it is rejected | yes |
| **Key URI** | one key on a device | `tsa.key_label`, `signing.signers[].key_label`, … | yes (`object=` and/or `id=`) | no — it is rejected |

The split is deliberate. The module and the PIN are properties of the
deployment, not of a key: there is one module and one login per token, and a
`pin-value=` on a key reference could not be honoured even if it were read. A
config that tries is rejected at load, naming the field, rather than being
half-applied.

## Fields that take a key URI

Every one of these accepts three forms — a bare label (the historical form,
still correct), `software:<label>`, or a full `pkcs11:` URI:

| Setting | Key |
|---|---|
| `tsa.key_label` | RFC 3161 TSA signing key |
| `signing.signers[].key_label` | artifact code-signing key |
| `brski.registrar_key_label` | BRSKI registrar voucher-request key |
| `brski.masa.key_label` | built-in MASA voucher-signing key |
| `secret.escrow.agents[].key_label` | an escrow recovery agent's key |
| `server.tls.self_issue.key_label` | the self-issued serving-TLS key |

A key URI may use the object selectors (`object=`, `id=`, `type=`) and the token
selectors (`token=`, `serial=`, `model=`, `manufacturer=`, `slot-id=`,
`slot-description=`, `slot-manufacturer=`). A token selector *pins* the
operation: in an HA set it restricts routing to the matching replica, and on a
single-token deployment it fails closed if the token this process reaches is not
the one named.

```yaml
tsa:
  enabled: true
  # Address the key by CKA_ID on one specific device, whatever its label is.
  key_label: "pkcs11:id=%0a%0b;serial=0001234;type=private"
  certificate_file: /etc/secsy/tsa.pem

signing:
  enabled: true
  signers:
    - name: release
      key_label: "pkcs11:object=release-signing;type=private"
      certificate_file: /etc/secsy/release-signing.pem
```

`type=` may be `private`, `public`, or `secret-key`. A `type=cert` or
`type=data` URI is rejected: these settings name a key, and secsy-pki does not
keep certificates as token objects — a CA certificate lives in the database,
and the TSA/signing/BRSKI certificates are the PEM files their `*_cert*_file`
settings point at. Rejecting the URI says so, rather than resolving it to a
private key that happens to share the label.

### Provisioning matches

The commands and endpoints that *create* these keys take the same forms, so a
key can be provisioned at the exact address the config will later name:

```bash
secsy-ca tsa-key    -label "pkcs11:object=tsa-key;serial=0001234" -ca root
secsy-ca signing-key -label "pkcs11:object=release-signing"       -ca issuing
secsy-ca ca import  -existing-key "pkcs11:id=%01%02;type=private"  …
```

A URI's `object=` becomes the new key's `CKA_LABEL` and its `id=` the `CKA_ID`;
a token selector decides which device in an HA set the key is generated on.

## KEK references are labels, not addresses

`secret.kek_label`, `backup.kek_label` and `tenants[].kek_label` accept a URI
too, but only an object-only one:

```yaml
secret:
  kek_label: "pkcs11:object=prod-kek"      # ok — equivalent to: prod-kek
```

A KEK label is not only an address. It is written into every envelope's wrap
header, it keys the rotation lineage in the database, and it is what
`<label>-v2` is derived from when the KEK rotates. So a URI here is reduced to
its `object=` label at load, and a URI that carries anything else — an `id=`,
which a derived version key could not share, or a token pin, which would not
survive into the wrap header — is **rejected** rather than silently dropped.
Select the token under `pkcs11.uri` / `pkcs11.token_*` instead.

The same rule applies to `secsy-secret -kek`.

## Token and slot addressing

The `pkcs11` block mirrors every RFC 7512 token and slot attribute as a field,
and `pkcs11.uri` backfills any of them left unset:

```yaml
pkcs11:
  module_path: /usr/lib/softhsm/libsofthsm2.so
  token_label: secsy-pki-root
  token_serial: ""
  token_manufacturer: ""
  token_model: ""          # CK_TOKEN_INFO.model          (RFC 7512 model=)
  slot_id:                 # CK_SLOT_ID                   (RFC 7512 slot-id=)
  slot_description: ""     # CK_SLOT_INFO.slotDescription (RFC 7512 slot-description=)
  slot_manufacturer: ""    # CK_SLOT_INFO.manufacturerID  (RFC 7512 slot-manufacturer=)
```

The first slot matching every *set* selector wins; unset selectors do not
constrain the search. `slot_id` is the one that separates two tokens nothing
else can tell apart — two SoftHSM tokens initialised with the same label, or two
identical HSMs in one host.

The same fields exist per token under `pkcs11.tokens[]` for an HA set, where
pinning by `slot_id` or `token_serial` is how a replica is named.

## Naming the module portably

The module may be named in `pkcs11.uri` instead of `pkcs11.module_path`, either
absolutely or symbolically:

```yaml
pkcs11:
  # Absolute, as before:
  uri: "pkcs11:token=secsy-pki-root?module-path=/usr/lib/softhsm/libsofthsm2.so"
```

```yaml
pkcs11:
  # Symbolic: resolved the way p11-kit resolves it.
  uri: "pkcs11:token=YubiHSM?module-name=yubihsm_pkcs11"
```

`module-name=` is resolved at config load, first against the p11-kit module
descriptions (`/etc/pkcs11/modules`, `/usr/share/p11-kit/modules`,
`/usr/local/share/p11-kit/modules`) and then by searching the conventional
module directories for `<name>.so`:

- `/usr/lib/<gnu-triplet>/pkcs11` (Debian/Ubuntu multiarch)
- `/usr/lib64/pkcs11`, `/usr/lib/pkcs11` (RHEL/SUSE)
- the `/usr/local` equivalents (where a module built from source lands)

Set `SECSY_PKCS11_MODULE_DIRS` (a colon-separated list) to override the search
path entirely. A name that resolves to nothing fails the config load with the
list of directories searched — far easier to act on than a `dlopen` failure at
the first signature.

This is what makes one config file correct across distributions: the absolute
path to Yubico's module is
`/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so` on Debian amd64,
`/usr/lib64/pkcs11/yubihsm_pkcs11.so` on RHEL and
`/usr/local/lib/pkcs11/yubihsm_pkcs11.so` in a from-source build; the name is
`yubihsm_pkcs11` everywhere.

## What is checked, and when

Load time (the server refuses to start; `secsy-ca doctor` reports it under
`config.parse`):

- every URI parses as RFC 7512, with no duplicate or unrecognized attributes;
- a token URI names no object;
- a key URI names an object, addresses a key rather than a certificate or data
  object, and carries neither the module nor a PIN;
- a KEK reference carries nothing but `object=`;
- a `module-name=` resolves to a file.

`secsy-ca doctor`, against a live token (`pkcs11.uris` check):

- every configured key URI resolves to a real object on the token it names,
  through the role's own provider;
- every CA's stored key URI resolves, honouring its full object/id/token
  addressing;
- an embedded plaintext `pin-value` is reported as a warning (and never printed
  — it is redacted from the finding, from logs, and from any dumped config).

## Worked example: pinning each role to a different token

```yaml
key_provider:
  type: pkcs11
  roles:
    ca: pkcs11
    tsa: pkcs11

pkcs11:
  uri: "pkcs11:?module-name=yubihsm_pkcs11"
  pin_source:
    type: file
    file:
      path: /etc/secsy/hsm.pin
  selection_policy: primary-backup
  tokens:
    - name: primary
      uri: "pkcs11:serial=0001234"
    - name: backup
      uri: "pkcs11:serial=0005678"

tsa:
  enabled: true
  # The TSA key exists only on the backup device; pin it there so issuance
  # never looks for it on the primary.
  key_label: "pkcs11:object=tsa-key;serial=0005678;type=private"
  certificate_file: /etc/secsy/tsa.pem
```

The module is named once, symbolically. Each token is addressed by its serial.
The TSA key is addressed by label *and* device, so an operation against it is
routed to `0005678` and fails closed — rather than signing on `0001234` — if
that device is unreachable.

## See also

- [HSM / PKCS#11 configuration](configuration.md) — the full `pkcs11` block,
  PIN sourcing, and environment overrides
- [High availability across multiple tokens](high-availability.md)
- [Production HSM migration](production-migration.md)
