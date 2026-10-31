# Raw PKCS#11 inspector

*The token as Cryptoki describes it, rather than as this PKI summarises it.*

Everywhere else, secsy-pki keeps the HSM behind an abstraction that answers the
questions a CA asks: give me a signer for this label, is any key extractable,
is the device reachable. That is the right shape for issuing certificates, and
the wrong shape for the two situations an operator actually ends up in.

**Something is on the token that this PKI did not put there.** A key left behind
by a vendor utility, a certificate object imported by a migration, an object
whose `CKA_LABEL` is empty, or — the one that silently breaks signatures — two
objects sharing a label, so that a label lookup can pair the public half of one
key with the private half of another. An abstraction that enumerates
*private keys with labels* cannot show you any of them.

**The module and the token disagree with the documentation.** A mechanism the
firmware does not actually offer, a `CKA_*` the module answers differently from
the standard, a token whose flags say it is write-protected or whose PIN is one
attempt from locking, a second initialised token in a slot nobody expected.

The inspector answers both by reading out everything Cryptoki can be asked, and
printing it in the standard's own vocabulary:

| Surface | |
|---|---|
| CLI | `secsy-ca pkcs11 module` · `secsy-ca pkcs11 mechanisms` · `secsy-ca pkcs11 objects` |
| Console | the **PKCS#11** view |
| REST | `GET /api/pkcs11/module` · `GET /api/pkcs11/objects` |

It is read-only on every surface. There is no create, modify or destroy path,
and — see [below](#private-key-material-is-never-requested) — it never asks the
token for private key material.

## What it reads

| Cryptoki call | Reported as |
|---|---|
| `C_GetInfo` | the module: Cryptoki version, manufacturer, library description and version, flags |
| `C_GetSlotList` (all slots, not only those with a token) | the slot table |
| `C_GetSlotInfo` | per slot: description, manufacturer, hardware/firmware version, flags |
| `C_GetTokenInfo` | per token: label, model, manufacturer, **serial**, flags, session counts, PIN length bounds, memory, clock |
| `C_GetMechanismList` + `C_GetMechanismInfo` | per slot: every mechanism with its key-size range and operation flags |
| `C_FindObjects` with an **empty template** | every object the session can see, of any class |
| `C_GetAttributeValue` | per object: every attribute the standard defines for its class |
| `C_GetObjectSize` | per object, where the module implements it (many decline) |

Flags are decoded to their `CKF_` names — and per namespace, because Cryptoki
reuses the bit values: `0x2` is `CKF_REMOVABLE_DEVICE` on a slot,
`CKF_WRITE_PROTECTED` on a token and `CKF_DECRYPT` on a mechanism. A bit the
name tables do not know is kept as hex rather than dropped, since a vendor flag
is exactly the thing worth noticing.

The constant → name tables are generated from the PKCS#11 binding this project
links, by `go run scripts/gen-pkcs11-names.go`, which has the Go compiler
evaluate each constant rather than transcribing it. That is what makes the
aliases (`CKA_ECDSA_PARAMS` is `CKA_EC_PARAMS`) and composed values
(`CKA_WRAP_TEMPLATE` is `CKF_ARRAY_ATTRIBUTE | 0x211`) impossible to get wrong.

### Private objects need the login

`C_FindObjects` returns what the *session* can see, and a private object
(`CKA_PRIVATE=true` — every CA private key) is invisible to an unauthenticated
session. The object dump therefore runs on an authenticated session: the
server's own already-logged-in session pool, or a short-lived login for the CLI.

The **module view does not log in at all**, deliberately. `C_GetInfo`, the slot
list and `C_GetTokenInfo` need no session, and an operator reaching for a slot
list is very often one whose login does not work — a PIN that no longer
resolves, a token selector matching nothing, a device that moved slots.
Requiring a login first would make the one view that can diagnose those the one
view that fails with them.

## Private key material is never requested

An attribute whose value **is** private key material is not read. Not read and
redacted — never put in the template:

- `CKA_PRIVATE_EXPONENT`, `CKA_PRIME_1`, `CKA_PRIME_2`, `CKA_EXPONENT_1`,
  `CKA_EXPONENT_2`, `CKA_COEFFICIENT` (the RSA private exponent and CRT
  factors), for every key class;
- `CKA_VALUE` on a private, secret or OTP key — the DSA/EC private scalar, or
  the symmetric key bytes.

They appear in the output with status `withheld` and no bytes. `CKA_VALUE` on a
*certificate* or *data* object is a different attribute of a different object
and is shown: there it is the object itself, not a secret.

A correctly provisioned token refuses these anyway, with
`CKR_ATTRIBUTE_SENSITIVE` — and that refusal is worth showing, which is why
sensitive refusals are reported rather than hidden. But the inspector must not
be the one path in this system that turns a *mis*-provisioned, extractable key
into an HTTP response body. If you need to know whether a key could leave the
device, the answer is the non-extractability verdict in
`secsy-ca inventory` / `GET /api/inventory/keys`, and the device-signed proof is
[key attestation](key-attestation.md).

The `CK_ATTRIBUTE`-array attributes (`CKA_WRAP_TEMPLATE`, `CKA_UNWRAP_TEMPLATE`,
`CKA_DERIVE_TEMPLATE`) are not read either, with status `not-read`: their value
is an array of `CK_ATTRIBUTE` structs whose `pValue` members are pointers the
caller is supposed to have set up, and a module handed a zeroed buffer may write
through them. There is no portable way to read one blind.

## Attribute status vocabulary

PKCS#11 has no "list this object's attributes" call. `C_GetAttributeValue` only
answers questions: you name a `CK_ATTRIBUTE_TYPE` and the token either returns
its value or refuses. So "all attributes" means "every attribute the standard
defines, asked of every object", and each row carries what came back:

| Status | Meaning |
|---|---|
| `present` | the token returned a value. `value` is the decoding, `raw` the hex |
| `unavailable` | the token refused. `reason` is the `CKR_` name — `CKR_ATTRIBUTE_SENSITIVE` (it exists and may not be read: on a CA key, the token asserting the private value cannot leave) or `CKR_ATTRIBUTE_TYPE_INVALID` (this object has no such attribute) |
| `withheld` | the inspector did not ask: the value would be private key material |
| `not-read` | the inspector cannot ask portably (a `CK_ATTRIBUTE` array) |

By default an object is asked only for the attributes the standard defines for
its `CKA_CLASS` — a certificate is not interrogated about `CKA_PIXEL_X` — and
`CKR_ATTRIBUTE_TYPE_INVALID` rows are dropped as noise. `-all` / `?all=1` /
the console's **whole catalogue** checkbox asks every object for every
catalogued attribute and keeps those rows, which is the honest way to discover
what a particular module answers outside the standard. The withholding policy
above is *not* relaxed by it.

Values are decoded by their Cryptoki type, not guessed from the bytes — the same
four bytes are a `CK_ULONG`, a `CK_MECHANISM_TYPE` or the start of a modulus
depending only on which attribute they came from. A `CKA_EC_PARAMS` becomes a
curve name, a `CKA_SUBJECT` a distinguished name, a certificate's `CKA_VALUE` a
subject/issuer/serial/expiry summary, a modulus its bit length. The hex is
always there too, capped (default 2 KiB) with a SHA-256 over the *whole* value,
so a truncated modulus can still be compared between two tokens.

## The CLI

```console
$ secsy-ca pkcs11 module
module path       /usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so
cryptoki version  2.40
manufacturer      Yubico (www.yubico.com)
library           YubiHSM PKCS#11 Library 2.80
flags             0x00000000

slot 0  <- this deployment's token
  description         YubiHSM Connector 127.0.0.1
  manufacturer        Yubico
  hardware/firmware   0.0 / 0.0
  flags               0x00000007 CKF_TOKEN_PRESENT CKF_REMOVABLE_DEVICE CKF_HW_SLOT
  token present       true
  token label         YubiHSM
  token model         YubiHSM
  token serial        31650425
  token flags         0x0000040D CKF_RNG CKF_LOGIN_REQUIRED CKF_USER_PIN_INITIALIZED CKF_TOKEN_INITIALIZED
  pin length          8..64
  token hw/fw         2.40 / 2.40
```

`-mechanisms` adds each slot's mechanism list; `pkcs11 mechanisms` prints it as
a table with the key-size range and flags, and `-filter` narrows it:

```console
$ secsy-ca pkcs11 mechanisms -filter ecdsa
slot 1473751053 (SoftHSM slot ID 0x57d7a80d)
MECHANISM  TYPE        MIN KEY  MAX KEY  FLAGS
CKM_ECDSA  0x00001041  112      521      CKF_SIGN CKF_VERIFY CKF_EC_F_P CKF_EC_NAMEDCURVE CKF_EC_UNCOMPRESS
1 of 70 mechanism(s).
```

A mechanism absent here cannot be used however the configuration is written,
which is the quickest way to tell a firmware limitation from a
misconfiguration.

`pkcs11 objects` prints one attribute table per object:

```console
$ secsy-ca pkcs11 objects
token "YubiHSM" (serial 31650425), slot 0 — 2 object(s)
by class: CKO_PRIVATE_KEY=1 CKO_PUBLIC_KEY=1

--- object 0x31234: CKO_PRIVATE_KEY ca-root
    C_GetObjectSize: 96 bytes
  ATTRIBUTE                TYPE        KIND        LEN  VALUE
  CKA_CLASS                0x00000000  class       8    CKO_PRIVATE_KEY (0x3)
  CKA_TOKEN                0x00000001  bool        1    true
  CKA_PRIVATE              0x00000002  bool        1    true
  CKA_LABEL                0x00000003  string      7    ca-root
  CKA_KEY_TYPE             0x00000100  key-type    8    CKK_EC (0x3)
  CKA_ID                   0x00000102  bytes       2    0x1234
  CKA_ALLOWED_MECHANISMS   0x40000600  mechanisms  48   CKM_ECDSA, CKM_ECDSA_SHA1, CKM_ECDSA_SHA256, …
  CKA_SENSITIVE            0x00000103  bool        1    true
  CKA_SIGN                 0x00000108  bool        1    true
  CKA_EXTRACTABLE          0x00000162  bool        1    false
  CKA_NEVER_EXTRACTABLE    0x00000164  bool        1    true
  CKA_PRIVATE_EXPONENT     0x00000123  biginteger  0    (withheld: not requested: the value is private key material)
  CKA_EC_PARAMS            0x00000180  der         10   P-256 (prime256v1 / secp256r1) [1.2.840.10045.3.1.7]
  CKA_VALUE                0x00000011  bytes       0    (withheld: not requested: the value is private key material)
```

| Flag | |
|---|---|
| `-brief` | one row per object instead of the attribute tables |
| `-all` | the whole attribute catalogue, including unsupported rows |
| `-label` / `-class` | filter (`-class private-key`, or `CKO_PRIVATE_KEY`) |
| `-max-objects` | raise or lower the enumeration cap (default 500) |
| `-max-value-bytes` | raise or lower the per-value hex cap (default 2048) |
| `-raw` | print the hex of every value alongside its decoding |
| `-json` | the machine-readable form, exactly what the REST endpoints return |

## The REST endpoints

Both are gated on the platform-wide `hsm:manage` capability — the same
capability that administers the device elsewhere (key import, backup, audit
provisioning). The object dump names every object on the token, including ones
no CA references; the module view reports the token's serial and PIN-attempt
state. Neither is operator-general information.

| | |
|---|---|
| `GET /api/pkcs11/module` | module/slot/token/mechanism view. `?mechanisms=0` drops the mechanism lists (the bulk of the payload) |
| `GET /api/pkcs11/objects` | object dump. `?all=1`, `?max_objects=N`, `?max_value_bytes=N` |

`tokens` in the response is a **list**: a
[high-availability set](high-availability.md) is several devices behind one
provider, and the point of the view is to tell them apart — replicas
deliberately share key labels, so only the member name and the token serial say
which device an object is on. Inspection is the one operation that never fails
over: a replica that cannot be reached contributes a view carrying its error,
so a degraded set still shows the others *and* which one is down.

A backend with no PKCS#11 view — software, cloud KMS, Vault Transit — answers
**501** naming itself, rather than a 200 carrying an empty view, which would
read as the much more alarming "the token holds nothing".

Each object dump records one `hsm.inspect` audit event whose detail is the
per-token object count, so an access review sees who enumerated the device and
what was on it at the time — and a later reader can tell whether it gained
objects between two inspections. A refused request is recorded too.

## The console view

**PKCS#11** in the console nav carries the same thing in five panels: **Module**
(`C_GetInfo`), **Token** (the resolved `CK_TOKEN_INFO`, or a warning when no
slot matches the configured selectors), **Slots**, **Mechanisms** (filterable,
per slot) and **Objects**. The first four load with the page; objects load on a
click, because they cost device round trips. Each object row expands to its
attribute table, and both halves download as JSON.

In an HA set a token picker appears, naming each member and whether the failover
layer currently has it in rotation.

## Costs and caveats

**On a force-audited YubiHSM, inspecting consumes device audit-log entries.**
`C_FindObjects` is the device's own `ListObjects` command and every attribute
read is a `GetObjectInfo`; on a device provisioned for
[forced audit logging](audit-log.md) those fill its 62-entry ring, and a full
ring is a device that refuses to sign. So an object dump prompts the same
device-log drain a signature does, automatically. It is still worth knowing that
an inspection is not free there.

**Enumeration is capped** (500 objects by default). A truncated result says so
on every surface — an object missing from a truncated list is *not* evidence
that it is absent from the token.

**Object handles are session-scoped.** `CK_OBJECT_HANDLE` values are valid only
within the session that produced them, so the `handle` column changes between
inspections. It is useful for correlating rows within one dump (and, on a
YubiHSM, it encodes the on-device object ID), not as an identifier to store.
`CKA_ID` and `CKA_LABEL` are the identifiers; see
[PKCS#11 URIs](pkcs11-uris.md) for addressing a key by them.

**This is the token's own account of itself, not proof.** `CKA_EXTRACTABLE=false`
read over a session is the *module's* answer; a compromised module or connector
could say anything. The provable version is
[key attestation](key-attestation.md), where the device signs a statement about
the key with a Yubico-rooted key, and
[device attestation](device-attestation.md) for the hardware itself. The
inspector is for seeing what is there; attestation is for proving what it is.

---

↩ Back to [HSM & key management](README.md) · [documentation map](../README.md)
