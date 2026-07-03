# S/MIME e-mail protection certificates

secsy-pki issues **mailbox-validated S/MIME certificates** (EKU
`id-kp-emailProtection`) with first-class handling of e-mail identities:
rfc822Name SANs are validated and normalized before the HSM signs anything,
per-profile and per-tenant domain allowlists scope who may certify which
domains, and a dedicated pre-issuance lint rule set enforces the essentials of
the CA/Browser Forum **S/MIME Baseline Requirements** (SMBRs).

S/MIME certificates ride the existing issuance machinery end to end: the same
HSM-backed signing path, the same REST/CLI/EST/SCEP/CMP/gRPC front ends
(selected purely by profile name), and the same revocation infrastructure —
CRL, delta CRL, and OCSP need no S/MIME-specific configuration.

## Built-in profiles

| Profile | Key usage | Use |
|---------|-----------|-----|
| `smime-sign` | `digitalSignature` | Message signing only |
| `smime-encrypt` | `keyEncipherment` (RSA) | Message encryption only |
| `smime` | `digitalSignature, keyEncipherment` | Single-key dual use |

All three carry exactly the `emailProtection` EKU, default to 365-day validity
(maximum 730 days — inside the SMBR multipurpose 825-day cap), and target the
SMBR **multipurpose** class.

```bash
# Subscriber-side key + CSR with an rfc822Name SAN (key never leaves the client)
openssl req -new -newkey rsa:2048 -nodes -keyout alice.key \
  -subj "/CN=Alice Example" \
  -addext "subjectAltName=email:alice@example.com" -out alice.csr

# Issue the pair
secsy-ca issue -ca my-issuing-ca -csr alice.csr -profile smime-sign    -out alice-sign.crt
secsy-ca issue -ca my-issuing-ca -csr alice.csr -profile smime-encrypt -out alice-enc.crt
```

> **Use RSA subject keys** with the built-in profiles. `keyEncipherment` is an
> RSA operation; the lint gate rejects an EC key under an encryption-capable
> profile (EC S/MIME encryption uses ECDH `keyAgreement` — define a custom
> profile with `key_usages: [keyAgreement]` if you need it).

### Recommended: dual-key (sign/encrypt split) deployment

Prefer issuing **two certificates on two keys** per user over the single-key
`smime` profile:

- **Signing keys must never be escrowed or backed up.** A signature is only
  non-repudiable while exactly one party has ever held the key. Losing a
  signing key costs nothing — revoke and issue a fresh one; old signatures
  remain verifiable.
- **Encryption keys usually must be escrowed.** Encrypted mail is unreadable
  without the private key, so a lost key means lost data. Escrow the
  encryption key at enrollment via the secret layer's M-of-N escrow
  ([HSM-backed secret encryption](password-encryption.md), Task 33): encrypt
  the PKCS#8 key with `secsy-secret encrypt -escrow`, so any quorum of recovery
  agents — and no smaller group — can recover it during a dual-control
  ceremony:

  ```bash
  # At enrollment, escrow the ENCRYPTION key only (never the signing key)
  secsy-secret encrypt -escrow -context user=alice,kind=smime-encryption \
    < alice-enc-key.p8 > alice-enc-key.envelope
  ```

  For central key delivery, [PKCS#12 export](pkcs12.md) does the keygen,
  issuance, bundling **and** escrow in one step — issue the encryption cert with
  `secsy-ca export-p12 -profile smime-encrypt -escrow`, which hands you a
  password-protected `.p12` for the user and the escrow envelope for the vault.

- Renewal differs too: rotate signing keys freely at every renewal; keep (or
  escrow-recover) encryption keys as long as mail encrypted to them must stay
  readable.

## Mailbox validation and normalization

Before any HSM signature, every rfc822Name SAN in an S/MIME request is parsed
as an RFC 5321 `addr-spec` and normalized; the certificate carries the
normalized form:

- the **domain is lowercased and punycoded** (RFC 6531 internationalized
  domains are folded to their A-label form — `post@bücher.example` is issued
  as `post@xn--bcher-kva.example`, as RFC 8398 requires for the IA5String
  rfc822Name);
- the **local part is preserved byte-for-byte** (it is case-sensitive on the
  receiving host; the CA must not rewrite it) — duplicates differing only in
  local-part case are folded;
- display names (`Alice <a@b>`), quoted local parts, address literals
  (`user@[192.0.2.1]`), single-label domains, and non-ASCII **local parts**
  (representable only as an `SmtpUTF8Mailbox` otherName, which secsy-pki does
  not issue) are rejected with a `cert.smime` audit event.

## Domain allowlists and tenant scoping

Two independent allowlists constrain which mailbox domains may be certified;
when both are configured, **both** must admit every address:

```yaml
profiles:
  - name: smime-corp
    key_usages: [digitalSignature, keyEncipherment]
    ext_key_usages: [emailProtection]
    default_validity_days: 365
    max_validity_days: 730
    smime:
      enabled: true
      variant: dual              # sign | encrypt | dual
      br_profile: multipurpose   # legacy | multipurpose | strict
      allowed_domains: ["corp.example", "*.corp.example"]
      subject_email: true        # mirror the mailbox into the subject DN

tenants:
  - id: acme
    name: Acme Corp
    # CAs owned by this tenant may only certify these mail domains,
    # regardless of profile.
    allowed_email_domains: ["acme.example", "*.mail.acme.example"]
```

`example.com` matches exactly; `*.example.com` matches any subdomain but not
the apex (list both to cover a tree). Entries may be internationalized
(U-labels); they are normalized like request addresses. A request outside the
allowlists is refused fail-closed before signing, with a `cert.smime` audit
event and a `secsy_certificate_smime_findings_total{reason="domain"}` metric.

`subject_email: true` additionally carries the first SAN in the subject DN as
a PKCS#9 `emailAddress` attribute (IA5String) for legacy relying parties that
read the address from the subject.

## S/MIME lint rules (CA/B Forum SMBR)

S/MIME profiles automatically extend the [pre-issuance lint
gate](certificate-authority.md) with an SMBR rule set. Like every lint check,
each rule is gated **enforce** (fail-closed, the default) or **warn** per
profile — `lint.mode` or `lint.overrides` by check code:

| Check | Enforces |
|-------|----------|
| `smime_san_present` | ≥ 1 rfc822Name SAN |
| `smime_san_types` | no dNSName / iPAddress / URI SANs in a mailbox-validated cert |
| `smime_email_syntax` | every rfc822Name is a valid, normalized addr-spec |
| `smime_eku` | `emailProtection` present; `serverAuth`, `codeSigning`, `timeStamping`, `ocspSigning`, `anyExtendedKeyUsage` forbidden; **strict** class permits no other EKU at all |
| `smime_key_usage` | KU matches the declared variant (sign/encrypt/dual split), no KU outside the SMBR set, and the KU fits the key algorithm (RSA→`keyEncipherment`, EC→`keyAgreement`) |
| `smime_validity` | ≤ 825 days (multipurpose/strict) or ≤ 1185 days (legacy) |
| `smime_subject_email` | a subject `emailAddress` attribute or mailbox-shaped CN matches an rfc822Name SAN |

So a request mixing `serverAuth` into an S/MIME profile, or arriving without a
mailbox SAN, is rejected before the HSM signs — visible as a `cert.lint` audit
event and `secsy_certificate_lint_findings_total{code="smime_eku",...}`.

The same rules run offline against any existing certificate:

```bash
secsy-ca lint -profile smime some-smime-cert.pem
```

## Enrollment via EST / SCEP

EST and SCEP honor S/MIME profiles like any other — point the endpoint (or a
grant/credential) at one:

```yaml
est:
  enabled: true
  users:
    mailer: { password_hash: "...", profile: "smime" }

scep:
  enabled: true
  grants:
    - { name: mail-fleet, challenge: "...", profile: "smime" }
```

The enrollment CSR carries the mailbox in its subjectAltName extension
request; validation, normalization, allowlists, and the lint gate all apply
identically. SCEP additionally requires an RSA CA (protocol constraint) —
which S/MIME deployments want anyway.

## Verifying interop

A round trip with openssl (also exercised in CI against SoftHSM):

```bash
# Sign and verify (purpose check: emailProtection EKU + digitalSignature KU)
openssl smime -sign -in msg.txt -text -signer alice-sign.crt -inkey alice.key -out msg.p7s
openssl smime -verify -in msg.p7s -CAfile ca-chain.pem

# Encrypt to the encryption certificate and decrypt
openssl smime -encrypt -aes-128-cbc -binary -in secret.txt -out secret.p7m alice-enc.crt
openssl smime -decrypt -binary -in secret.p7m -recip alice-enc.crt -inkey alice-enc.key
```

## Revocation

Nothing S/MIME-specific: `secsy-ca revoke` (or the REST/gRPC equivalents)
revokes by serial, and the certificate appears in the CA's CRL/delta
CRL/OCSP responses as usual. For a compromised **signing** key revoke with
`keyCompromise`; a lost **encryption** key usually calls for escrow recovery
first (mail encrypted to it is otherwise gone), then `superseded`.
