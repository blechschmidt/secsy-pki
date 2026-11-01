# The CA certificate extension set

Creating a certificate authority is the one issuance decision that cannot be
revised. A leaf is short-lived and reissued constantly; a CA's extensions bind
**every certificate that will ever chain through it**, and changing them means a
new key and a trust-store rollout. So `secsy-pki` accepts the whole common
X.509 v3 extension vocabulary at CA-creation time, validates it before the key
exists, and never offers to edit it afterwards.

This page is the reference for that vocabulary. It is the same set on all three
surfaces — the REST API, the `secsy-ca` CLI and the operator console — because
they all compile the same configuration object.

- [Where it is configured](#where-it-is-configured)
- [What is emitted by default](#what-is-emitted-by-default)
- [Key usage and extended key usage](#key-usage-and-extended-key-usage)
- [Alternative names](#alternative-names)
- [Revocation and discovery pointers](#revocation-and-discovery-pointers)
- [Policy, path and key-period constraints](#policy-path-and-key-period-constraints)
- [Directory attributes, legacy and flags](#directory-attributes-legacy-and-flags)
- [Any extension at all](#any-extension-at-all)
- [The subject distinguished name](#the-subject-distinguished-name)
- [Validation: what is refused, and when](#validation-what-is-refused-and-when)
- [Worked example: a constrained TLS issuing CA](#worked-example-a-constrained-tls-issuing-ca)

---

## Where it is configured

| Surface | How |
|---|---|
| **REST** | the `extensions` object on `POST /api/ca/init-root`, `POST /api/ca/{id}/issue-intermediate` and `POST /api/ca/csr` (schema `CAExtensions` in the OpenAPI spec, served at `GET /openapi.json` and rendered at `/docs`) |
| **CLI** | flags on `secsy-ca init-root`, `issue-intermediate` and `ca csr` — or `-ca-ext-file extensions.json` for the whole object, with the flags layered over it |
| **Console** | the **X.509 extensions…** button on each of the three CA forms on the [Authorities view](../operations/web-console.md), which opens an editor with a live preview of the exact request body |

All three validate identically, because all three hand the same compiled set to
the signer. Name Constraints and the certificate-policy family
(`certificatePolicies` / `policyMappings` / `policyConstraints`) are configured
through their own long-standing request fields and are documented in
[name constraints & certificate policies](../issuance/name-constraints.md); the
set below is everything else.

`-ca-ext-file` is the form worth knowing about for a real root ceremony: the
extension set is the part of the ceremony that deserves review, and a JSON file
in version control reviews better than a 30-flag command line.

```json
{
  "ext_key_usages": ["serverAuth"],
  "crl_distribution_points": ["http://crl.example.com/root.crl"],
  "ocsp_servers": ["http://ocsp.example.com/"],
  "ca_issuers": ["http://pki.example.com/root.cer"],
  "private_key_usage_period": { "fraction": 0.5 }
}
```

An unknown field in that file is an error, not something to ignore — a
misspelled `must_stapel` would otherwise silently produce a CA without the
property the ceremony paperwork claims it has.

---

## What is emitted by default

Omit `extensions` entirely and a CA certificate carries exactly four extensions,
which is what this PKI has always issued:

| Extension | OID | Value |
|---|---|---|
| Key Usage | 2.5.29.15 | critical; `keyCertSign`, `cRLSign`, `digitalSignature` |
| Basic Constraints | 2.5.29.19 | critical; `cA=TRUE`, with the request's `max_path_len` |
| Subject Key Identifier | 2.5.29.14 | derived from the public key |
| Authority Key Identifier | 2.5.29.35 | the issuer's SKI (absent on a self-signed root) |

`digitalSignature` is in the default set because the same CA key signs OCSP
responses in this deployment's default responder arrangement. Everything below
is opt-in: nothing appears because this feature exists.

---

## Key usage and extended key usage

```json
"key_usages": ["keyCertSign", "cRLSign"],
"ext_key_usages": ["serverAuth", "clientAuth"],
"ext_key_usage_critical": false
```

`key_usages` replaces the default set. Both spellings of each RFC 5280 bit are
accepted — `certSign` and `keyCertSign`, `crlSign` and `cRLSign`,
`contentCommitment` and `nonRepudiation` — so a set transcribed from the RFC or
from an OpenSSL config is not rejected for its punctuation. **`certSign` is
mandatory.** A CA certificate without it cannot sign the subordinate
certificates that are the point of having it, and the request is refused rather
than producing an authority that fails path validation much later.

`ext_key_usages` is the single most effective constraint on a delegated
authority. A conforming path validator intersects extended key usages down the
chain, so an issuing CA carrying only `serverAuth` cannot be abused to mint a
code-signing certificate **even if a profile beneath it allows one** — the
constraint lives in the certificate, not in this deployment's policy engine, so
it survives a compromised configuration.

Names come from a catalogue covering the whole IANA `id-kp` arc plus the
Microsoft, Kerberos, Netscape and Adobe purposes that appear in real enterprise
PKIs: `serverAuth`, `clientAuth`, `codeSigning`, `emailProtection`,
`timeStamping`, `ocspSigning`, `ipsecIKE`, `documentSigning`, `bimi`,
`msSmartcardLogon`, `msEnrollmentAgent`, `msDocumentSigning`,
`pkinitClientAuth`, `pkinitKDC`, `adobePDFSigning`, `any`, and some forty
others. **A dotted OID is always accepted**, so the catalogue is a convenience
rather than a limit.

CLI:

```bash
secsy-ca init-root ... \
  -key-usage certSign -key-usage crlSign \
  -eku serverAuth -eku clientAuth -eku 1.3.6.1.4.1.99999.3 -eku-critical
```

---

## Alternative names

`subject_alt_name` (2.5.29.17) and `issuer_alt_name` (2.5.29.18) take a full
RFC 5280 `GeneralNames` set. Uncommon on a CA but legitimate: a directory name
or URI identifying the authority in a form its DN cannot express.

```json
"subject_alt_name": {
  "dns": ["ca.example.com"],
  "ip": ["192.0.2.10"],
  "email": ["pki@example.com"],
  "uri": ["https://ca.example.com/"],
  "upn": ["svc@CORP.EXAMPLE"],
  "dir_names": ["O=Example Org,C=DE"],
  "registered_ids": ["1.3.6.1.4.1.99999.9"],
  "other_names": [{ "oid": "1.3.6.1.4.1.99999.10", "encoding": "ia5", "value": "marker" }]
}
```

Every `GeneralName` alternative a modern relying party consumes is covered:
`otherName` (including Microsoft/Kerberos UPNs and anything else by type-id),
`rfc822Name`, `dNSName`, `directoryName`, `uniformResourceIdentifier`,
`iPAddress` and `registeredID`. The two the RFC defines but nothing reads —
`x400Address` and `ediPartyName` — are deliberately absent; `other_names`
reaches them if a scheme ever needs one.

A `directoryName` is encoded as the **ordered** RDN sequence you wrote it as,
left to right, following the `openssl -subj /O=Acme/C=US` convention rather
than strict RFC 4514's reversed order. The order matters: a directoryName is
compared as an ordered sequence of RDNs, so re-ordering the components produces
a different name.

CLI: `-san-dns`, `-san-ip`, `-san-email`, `-san-uri`, `-san-upn`,
`-san-dirname`, `-san-registered-id`, `-san-othername`, `-san-critical`, and
`-ian-dns` / `-ian-email` / `-ian-uri` for the issuer side. These flags do not
split on commas, so a two-RDN DN stays one subtree.

---

## Revocation and discovery pointers

The first four describe **this** certificate — where its parent publishes
revocation information, and where the parent's own certificate can be fetched
so a relying party can complete the chain. A self-signed root leaves them
empty: nothing revokes a trust anchor.

```json
"crl_distribution_points": ["http://crl.example.com/issuing.crl"],
"freshest_crl":            ["http://crl.example.com/issuing-delta.crl"],
"ocsp_servers":            ["http://ocsp.example.com/"],
"ca_issuers":              ["http://pki.example.com/root.cer"],
"ca_repositories":         ["http://pki.example.com/certs/"],
"timestamp_servers":       ["http://tsa.example.com/"]
```

| Field | Extension | OID |
|---|---|---|
| `crl_distribution_points` | CRL Distribution Points | 2.5.29.31 |
| `freshest_crl` | Freshest CRL (delta) | 2.5.29.46 |
| `ocsp_servers` | Authority Information Access, `id-ad-ocsp` | 1.3.6.1.5.5.7.1.1 |
| `ca_issuers` | Authority Information Access, `id-ad-caIssuers` | 1.3.6.1.5.5.7.1.1 |
| `ca_repositories` | Subject Information Access, `id-ad-caRepository` | 1.3.6.1.5.5.7.1.11 |
| `timestamp_servers` | Subject Information Access, `id-ad-timeStamping` | 1.3.6.1.5.5.7.1.11 |

The last two describe services **this CA** offers: the repository in which it
publishes the certificates it issues, and its [RFC 3161
TSA](../signing/timestamping.md). All six are emitted non-critical, as RFC 5280
requires, so the criticality is not configurable.

These pointers are about the *CA certificate*. The AIA and CRL URLs stamped on
the **leaves** this CA issues come from the issuance configuration — see
[CA setup & certificate lifecycle](overview.md) — and the two are independent.

CLI: `-crl-url`, `-delta-crl-url`, `-ocsp-url`, `-ca-issuer-url`,
`-ca-repository-url`, `-timestamp-url`.

---

## Policy, path and key-period constraints

```json
"inhibit_any_policy": 0,
"private_key_usage_period": { "fraction": 0.5 }
```

**`inhibit_any_policy`** (2.5.29.54) is the `skipCerts` count: how many further
certificates in the path still accept the `anyPolicy` OID as satisfying a
specific policy requirement. `0` stops it immediately below this CA. Always
emitted critical, as RFC 5280 §4.2.1.14 requires.

**`private_key_usage_period`** (2.5.29.16) narrows the window in which this
key may *produce* signatures to less than the certificate's own validity, so the
key can be retired while every certificate it signed stays verifiable. Set
exactly one form:

| Form | Meaning |
|---|---|
| `{"duration": "180d"}` | the key may sign for that long from the certificate's `notBefore` (`d`, `w`, `y` units, or anything Go's `ParseDuration` takes) |
| `{"fraction": 0.5}` | for that fraction of the certificate's lifetime — the "sign for the first half, then only validate" CA policy |
| `{"not_before": "…", "not_after": "…"}` | explicit RFC 3339 instants, either or both |

The resolved window is always clamped to the certificate's own validity: the key
can never be declared usable before the certificate is valid or after it
expires. RFC 5280 deprecates the extension for the Internet PKI, but it is still
expected on some eIDAS and qualified-signing hierarchies.

CLI: `-inhibit-any-policy`, `-key-usage-period 180d`,
`-key-usage-period-fraction 0.5`.

---

## Directory attributes, legacy and flags

```json
"subject_directory_attributes": [
  { "oid": "1.3.6.1.5.5.7.9.4", "encoding": "printable", "values": ["DE"] }
],
"must_staple": true,
"ocsp_no_check": false,
"netscape_comment": "Issued by the Example PKI",
"netscape_cert_type": ["sslCA", "smimeCA"],
"subject_key_id": "de:ad:be:ef:00:11:22:33"
```

| Field | Extension | Notes |
|---|---|---|
| `subject_directory_attributes` | 2.5.29.9 | non-identifying directory attributes of the subject (country of citizenship, date of birth, place of birth); non-critical per RFC 5280 §4.2.1.8 |
| `must_staple` / `tls_features` | RFC 7633 TLS Feature, 1.3.6.1.5.5.7.1.24 | on a CA certificate, declares that certificates issued beneath it are expected to be served with a stapled OCSP response. `must_staple` is shorthand for feature `5` (`status_request`); `tls_features` takes raw numbers for anything else, and the two de-duplicate |
| `ocsp_no_check` | RFC 6960 `id-pkix-ocsp-nocheck` | tells clients not to check this certificate's own revocation status, which would be circular. It belongs on a short-lived **delegated OCSP responder** certificate, not on an issuing CA; it is offered because a CA key that also answers OCSP directly is an arrangement some deployments choose |
| `netscape_comment` | 2.16.840.1.113730.1.13 | an IA5String some old tools display to users |
| `netscape_cert_type` | 2.16.840.1.113730.1.1 | `sslClient`, `sslServer`, `sslCA`, `smime`, `smimeCA`, `objsign`, `objCA`. `keyUsage` and `extKeyUsage` supersede this; it is here for old appliances that still read it |
| `subject_key_id` | 2.5.29.14 | overrides the derived identifier with these exact bytes (hex; colons and spaces ignored). Deriving it from the public key is what a conforming CA does — an explicit value exists for reproducing an identifier a relying party already pins. [Cross-signing](cross-signing.md) sets the SKI for its own reasons and wins over this field |

CLI: `-subject-dir-attr OID:encoding:value`, `-must-staple`, `-ocsp-no-check`,
`-netscape-comment`, `-netscape-cert-type sslCA,smimeCA`, `-subject-key-id`.

---

## Any extension at all

`custom` is why "all common extensions" is not a closed list. An enterprise OID,
a national-scheme extension, or one from an RFC published after this release can
be stamped without a code change:

```json
"custom": [
  { "oid": "1.3.6.1.4.1.99999.100", "critical": true, "encoding": "utf8", "value": "cost-centre 4711" },
  { "oid": "1.3.6.1.4.1.99999.101", "encoding": "der-hex", "value": "3003020101" }
]
```

| Encoding | Produces |
|---|---|
| `utf8` (default) | `UTF8String` |
| `ia5` | `IA5String` |
| `printable` | `PrintableString` |
| `oid` | `OBJECT IDENTIFIER` |
| `int` | `INTEGER` (arbitrary precision) |
| `bool` | `BOOLEAN` |
| `null` | `NULL` |
| `octet-string` | `OCTET STRING` wrapping the supplied hex bytes |
| `bit-string` | `BIT STRING` wrapping the supplied hex bytes |
| `der-hex` | the supplied hex bytes **verbatim** as the extension value |
| `der-base64` | the supplied base64 bytes **verbatim** |

The two `der-*` forms are the real escape hatch: whatever ASN.1 structure an
extension needs, encode it elsewhere and paste the DER. They are also the one
way to produce a certificate nothing can parse, so the server checks that the
bytes are **exactly one complete DER element** — a truncated value or one with a
trailing element is refused before a key is generated. The same encodings apply
to `other_names` values and `subject_directory_attributes` values.

CLI: `-ext 'OID[:critical]:encoding:value'`, repeatable. The value may itself
contain colons (a hex blob with separators, a URI), because only the leading
fields are split off:

```bash
-ext '1.3.6.1.4.1.99999.100:critical:utf8:cost-centre 4711'
-ext '1.3.6.1.4.1.99999.101:der-hex:30:03:02:01:01'
```

---

## The subject distinguished name

Not an extension, but the other half of what a CA certificate asserts, and
subject to the same "you get one chance" rule. Beyond `cn`, `o`, `ou`, `c`,
`st` and `l`:

```json
"subject": {
  "cn": "Example Root CA",
  "o": "Example Org GmbH",
  "c": "DE",
  "serial_number": "HRB 12345",
  "street": "Hafenstrasse 1",
  "postal_code": "20457",
  "dc": ["com", "example"],
  "email": "pki@example.com",
  "extra_names": [
    { "type": "organizationIdentifier", "value": "VATDE-123456789" },
    { "type": "businessCategory", "value": "Private Organization" },
    { "type": "1.3.6.1.4.1.311.60.2.1.3", "value": "DE" }
  ]
}
```

`serial_number` is the X.520 `serialNumber` attribute — a registry or company
number — not the certificate's serial. `dc` entries are `domainComponent`
attributes, most significant first, and `email` is the PKCS#9 `emailAddress`
attribute; both are emitted as `IA5String`, which is how they are defined and
what strict DN-matching relying parties expect. `subjectAltName` is the modern
place for an address — `email` exists for a DN that must match an existing one.

`extra_names` reaches any attribute at all, appended in the order given, and is
also how an attribute that already has a field above gets a **second** value
(RDNs may repeat). `type` accepts a short name — `CN`, `O`, `OU`, `C`, `ST`,
`L`, `STREET`, `postalCode`, `serialNumber`, `DC`, `E`, `title`, `givenName`,
`surname`, `pseudonym`, `businessCategory`, `description`, `initials`,
`organizationIdentifier`, `UID`, `jurisdictionC` / `jurisdictionST` /
`jurisdictionL` — or a dotted OID. An unresolvable type is **refused**, not
dropped: a CA whose DN is not the one that was asked for is worse than a failed
request.

One honest limitation: the attributes with their own named field are emitted in
Go's canonical DN order (street, postalCode, O, OU, CN, serialNumber, …) rather
than the order you listed them, because that is how `crypto/x509` models a
name. `extra_names` entries follow, in order. If a DN must be byte-identical to
an existing one, [cross-signing](cross-signing.md) is the path that reproduces
a subject exactly.

CLI: `-subject-serial-number`, `-street`, `-postal-code`, `-subject-email`,
`-dc` (repeatable), `-dn 'TYPE=VALUE'` (repeatable, not comma-split).

---

## Validation: what is refused, and when

The whole set is compiled and checked **before the key is generated**, so a
rejected configuration costs nothing: no key on the HSM, no CA row, no audit
entry beyond the failed attempt. An operator can iterate on an extension set
without littering the token.

Refused:

- a key-usage set without `certSign`, or naming a bit that does not exist;
- an extended key usage that is neither a catalogued name nor a parseable OID;
- `ext_key_usage_critical` or `subject_alt_name.critical` with nothing to mark
  critical — a half-finished edit that would silently emit nothing;
- two extensions with the same OID, which RFC 5280 §4.2 forbids (usually the
  `custom` hatch duplicating one the request already configures properly);
- a `der-hex` / `der-base64` value that is not exactly one complete DER element;
- more than one `private_key_usage_period` form, a `fraction` outside (0,1], an
  unparseable duration or instant, or a window that resolves to nothing;
- a malformed IP, DN, OID or Netscape type anywhere in the set;
- a negative `inhibit_any_policy`;
- a subject attribute type that cannot be resolved.

Blank entries in a list field are dropped rather than refused, because an empty
textarea in the console posts them and "nothing configured" is the right reading.

---

## Worked example: a constrained TLS issuing CA

The pattern this feature exists for: an intermediate that can only ever produce
server certificates for one domain, carries its parent's revocation pointers,
and whose key is retired halfway through the certificate's life.

```bash
secsy-ca issue-intermediate \
  -parent example-root \
  -label example-issuing-tls \
  -cn "Example TLS Issuing CA G2" -o "Example Org GmbH" -c DE \
  -key-type ecdsa-p256 -validity-days 1825 -path-len 0 \
  -eku serverAuth \
  -permit-dns example.com \
  -policy-oid 1.3.6.1.4.1.99999.1.1 -policy-cps https://cps.example.com/ \
  -crl-url http://crl.example.com/root.crl \
  -ocsp-url http://ocsp.example.com/ \
  -ca-issuer-url http://pki.example.com/root.cer \
  -ca-repository-url http://pki.example.com/certs/ \
  -key-usage-period-fraction 0.5 \
  -must-staple
```

What each line buys:

- **`-path-len 0`** — it may issue end-entity certificates and nothing else, so
  it cannot grow a sub-CA of its own.
- **`-eku serverAuth`** — a path validator will reject a client-auth or
  code-signing leaf under it regardless of what a profile here permits.
- **`-permit-dns example.com`** — a [name
  constraint](../issuance/name-constraints.md); the leaf's names must fall
  inside it, enforced both by this PKI's pre-issuance gate and by any conforming
  validator.
- **`-crl-url` / `-ocsp-url` / `-ca-issuer-url`** — a relying party holding only
  this intermediate can check whether the root revoked it, and fetch the root to
  finish the chain.
- **`-key-usage-period-fraction 0.5`** — the key stops signing after half the
  certificate's life. Pair it with [intermediate key
  rotation](rotation.md), which is what takes over at that point.
- **`-must-staple`** — everything issued beneath is expected to be served with a
  stapled OCSP response.

Verify the result the way a relying party would:

```bash
secsy-ca list
openssl x509 -in issuing.pem -noout -text | sed -n '/X509v3 extensions/,$p'
```

The same CA through the console: fill the **Issue intermediate CA** form,
press **X.509 extensions…**, and the dialog's preview shows the exact request
body before anything is signed — see
[the console walkthrough](../operations/console-walkthrough.md#2-build-the-hierarchy).

---

↩ Back to the [CA section](README.md) · [documentation map](../README.md)
