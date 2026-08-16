# Smartcard-logon & Kerberos PKINIT certificates

secsy-pki issues **Microsoft Windows smartcard-logon** and **Kerberos PKINIT
client-authentication** certificates for enterprise Active Directory interop. A
User Principal Name (UPN, `user@REALM`) is carried in a `subjectAltName`
**otherName** with type-id `id-ms-UPN` (`1.3.6.1.4.1.311.20.2.3`, a
`UTF8String`), the leaf carries the smartcard/PKINIT extended key usages
alongside `id-kp-clientAuth`, and the UPN is validated and realm-allowlist-
checked before the HSM signs anything.

Active Directory matches the UPN otherName against a user's `userPrincipalName`
attribute (case-insensitively) to authenticate a smartcard logon; a Kerberos KDC
matches it for PKINIT. The encoding is the exact one Windows expects — verified
against both Go's `crypto/x509` parser and `openssl asn1parse`.

Smartcard/PKINIT certificates ride the existing issuance machinery end to end:
the same HSM-backed signing path, the same REST/CLI/EST/SCEP/gRPC front ends
(selected by profile name), and the same revocation infrastructure.

## Built-in profiles

| Profile | Extended key usage | Use |
|---------|--------------------|-----|
| `smartcard-logon` | `clientAuth`, `msSmartcardLogon` (`1.3.6.1.4.1.311.20.2.2`) | Windows smartcard logon |
| `pkinit-client` | `clientAuth`, `pkinitClientAuth` (`1.3.6.1.5.2.3.4`) | Kerberos PKINIT (MIT/Heimdal) |
| `smartcard-pkinit` | `clientAuth`, `msSmartcardLogon`, `pkinitClientAuth` | One credential for both KDCs |

All three carry key usage `digitalSignature`, default to 365-day validity
(maximum 730 days), and **require a UPN** (`require_upn`) — a smartcard-logon
certificate is useless without one, so an omitted UPN is a hard error.

```bash
# Subscriber-side key + CSR (key never leaves the client / smartcard)
openssl req -new -newkey rsa:2048 -nodes -keyout alice.key \
  -subj "/CN=Alice Example" -out alice.csr

# Issue a smartcard-logon certificate, supplying the UPN out-of-band
secsy-ca issue -ca my-issuing-ca -csr alice.csr \
  -profile smartcard-logon -upn alice@CORP.EXAMPLE.COM -out alice.crt

# Confirm the UPN otherName and EKUs (openssl decodes the OID by name)
openssl x509 -in alice.crt -noout -text | grep -A1 'Subject Alternative Name'
#   X509v3 Subject Alternative Name:
#       othername: UPN::alice@CORP.EXAMPLE.COM
```

The `-upn` flag is repeatable to place more than one UPN otherName in a single
certificate. The UPN is supplied out-of-band (flag / API field), **not** taken
from the CSR subject — except on the EST/SCEP enrollment paths (below), where a
device's CSR SAN is the natural carrier.

## Realm allowlists (tenant + profile scoping)

Who may certify which realms is scoped exactly like the S/MIME e-mail domain
allowlists ([S/MIME](smime.md)). Both the profile-level and tenant-level
allowlist must admit a UPN's realm; matching is case-insensitive, and
`*.example.com` matches strict subdomains.

Per-profile, in a custom profile:

```yaml
profiles:
  - name: corp-smartcard
    key_usages: [digitalSignature]
    ext_key_usages: [clientAuth, msSmartcardLogon]
    upn:
      enabled: true
      require_upn: true
      allowed_realms: ["CORP.EXAMPLE.COM", "*.corp.example.com"]
```

Per-tenant, scoping every UPN profile a tenant's CAs use:

```yaml
tenants:
  - id: acme
    allowed_upn_realms: ["ACME.EXAMPLE"]
```

A UPN whose realm falls outside either allowlist is refused before signing, and
a `cert.upn` audit event (result `error`) is appended. A UPN requested under a
profile that is **not** UPN-enabled is likewise refused — a UPN SAN, which
grants AD logon, must be a deliberate, profile-permitted choice.

## Interfaces

| Surface | How to supply the UPN |
|---------|-----------------------|
| CLI | `secsy-ca issue -upn user@REALM` (repeatable); `-dry-run` previews the UPN gate |
| REST | `POST /api/ca/{id}/issue` body `{"upns": ["user@REALM"], ...}` |
| REST preview | `POST /api/ca/{id}/certificates:preview` body `{"upns": [...]}` — reports the `upn` gate verdict without signing |
| gRPC | `IssueCertificateRequest.upns` / `PreviewCertificateRequest.upns` |
| Console | The **Issue** page shows a *User Principal Name(s)* field for UPN-enabled profiles |
| EST / SCEP | A UPN otherName in the enrollment CSR's SAN is threaded through automatically (validated by the same gate) |

## Observability

- **Metrics** — `secsy_certificate_upn_checks_total{result}` (`pass`/`fail`) and
  `secsy_certificate_upn_findings_total{reason}`
  (`required`/`not_permitted`/`syntax`/`config`/`realm`).
- **Audit** — a blocked UPN issuance appends a tamper-evident `cert.upn` event.
- **Inventory** — the stored record's SANs include `upn:user@REALM`.
- **certlint** — the linter accounts for the UPN otherName (a UPN-only leaf is
  not flagged as lacking a SAN) and validates the smartcard/PKINIT EKUs against
  the key usage, so neither false-positives.

## Notes

- Smartcard/PKINIT is a **classical** (ECDSA/RSA) feature; a UPN requested under
  a post-quantum/hybrid profile is rejected.
- Renewal preserves the UPN otherName (recovered from the prior certificate's
  raw SAN, since `crypto/x509` surfaces `otherName` on no typed field).
- The UPN is preserved byte-for-byte as enrolled (case included) so it matches
  the AD `userPrincipalName` exactly; only the realm is matched case-insensitively
  for the allowlists.
