# PKCS#11 URI addressing — naming tokens and keys unambiguously

A `CKA_LABEL` is a nickname, not an identity. This example shows the
configuration shape for the point where that starts to matter: two HSMs behind
one deployment, keys that arrived from somewhere else, and roles that must sign
on a *particular* device.

Every string in [`config.yaml`](config.yaml) is an
[RFC 7512](https://www.rfc-editor.org/rfc/rfc7512) `pkcs11:` URI of the kind
`p11tool --list-all` and `pkcs11-tool -O` already print, pasted into the field
that needs it.

Full reference: [`docs/hsm/pkcs11-uris.md`](../../docs/hsm/pkcs11-uris.md).

---

## When a label is not enough

| Situation | Why the label fails | What to write instead |
|---|---|---|
| Two HSMs holding the same key for failover | The replicas *share* the label — that is what makes them replicas | `serial=` or `slot-id=` alongside the label |
| A key imported by a vendor migration tool | The label is whatever that tool chose, sometimes nothing | `id=<CKA_ID>` |
| Two tokens initialised with the same label | Nothing else distinguishes them | `slot_id:` |
| A key that must only ever be used on one device | A label resolves on whichever device answers | `object=…;serial=…` — it fails closed elsewhere |

## The two kinds of URI

The config deliberately separates them, and rejects a config that mixes them up
when it loads:

```yaml
pkcs11:
  # TOKEN URI — the device, the module, the PIN. Must not name an object.
  uri: "pkcs11:?module-path=/usr/lib/softhsm/libsofthsm2.so"

tsa:
  # KEY URI — one key. Must name an object; must not carry the module or PIN.
  key_label: "pkcs11:object=tsa-key;serial=0007654321;type=private"
```

The module and the PIN are properties of the deployment: there is one module
and one login per token. A `pin-value=` on a key reference could not be honoured
even if it were read, so a config that tries is refused at load — naming the
field — rather than being half-applied and discovered at the first signature.

## 1. Find the strings

```console
$ p11tool --list-tokens
Token 0:
  URL: pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM;serial=0001234567;token=secsy-ca
  ...

$ p11tool --login --list-all "pkcs11:serial=0001234567"
Object 0:
  URL: pkcs11:model=SoftHSM%20v2;...;serial=0001234567;token=secsy-ca;id=%0a%1b%2c;object=release-signing;type=private
  Type: Private key
```

Strip what you do not want to pin — a URI constrains only the attributes it
sets — and paste the rest.

## 2. Provision keys at the address the config names

The provisioning commands take the same forms, so the key is created exactly
where the server will look for it:

```console
$ secsy-ca tsa-key -label "pkcs11:object=tsa-key;serial=0007654321" -ca root \
    -out /etc/secsy/tsa.pem
$ secsy-ca signing-key -label "pkcs11:object=release-signing" -ca issuing \
    -out /etc/secsy/release-signing.pem
```

A URI's `object=` becomes the new key's `CKA_LABEL` and its `id=` the `CKA_ID`;
a token selector decides which device in an HA set the key is generated on.

To adopt a key that is already on a token — put there by a migration tool, a
wrapped restore, or `secsy-ca key import` — name it the same way:

```console
$ secsy-ca ca import -label legacy-root \
    -existing-key "pkcs11:id=%0a%1b%2c;type=private" \
    -cert legacy-root.pem
```

## 3. Check it before you need it

```console
$ secsy-ca -config config.yaml doctor
✓ pass  pkcs11.uris   6 pkcs11: URI(s) parsed; 2 CA key(s) resolved on token; 3 configured key URI(s) resolved on token
```

`doctor` resolves every configured key URI against the role's own provider, so
"the config names a key that is not there" or "names a device this process
cannot reach" is a finding rather than an outage.

The load-time checks are stricter still and run before the server starts: a URI
that does not parse, a key URI naming no object or naming a certificate, a
token URI naming an object, a module or PIN inside a key reference, a
`module-name=` that resolves to nothing — each is refused with the YAML path in
the message.

## Portable module naming

```yaml
pkcs11:
  uri: "pkcs11:?module-name=yubihsm_pkcs11"
```

Yubico's module lives at `/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so`
on Debian amd64, `/usr/lib64/pkcs11/yubihsm_pkcs11.so` on RHEL and
`/usr/local/lib/pkcs11/yubihsm_pkcs11.so` in a from-source build. The *name* is
`yubihsm_pkcs11` on all of them. `module-name=` is resolved at config load —
first against the p11-kit module descriptions, then by searching the
conventional module directories — so one config file is correct everywhere.
Override the search path with `SECSY_PKCS11_MODULE_DIRS`.

## What a KEK reference may carry

`secret.kek_label`, `backup.kek_label` and `tenants[].kek_label` take a URI too,
but only an object-only one:

```yaml
secret:
  kek_label: "pkcs11:object=prod-kek"   # ok — same as: prod-kek
```

A KEK label is written into every envelope's wrap header, keys the rotation
lineage in the database, and is what `<label>-v2` is derived from when the KEK
rotates. So it is reduced to its label at load, and a URI carrying an `id=`
(which a derived version key could not share) or a token pin (which would not
survive into the wrap header) is rejected rather than silently dropped. Select
the token under `pkcs11.uri` / `pkcs11.token_*`.

---

↩ Back to the [examples index](../README.md) ·
[PKCS#11 URI reference](../../docs/hsm/pkcs11-uris.md) ·
[HSM configuration](../../docs/hsm/configuration.md)
