# eIDAS qualified certificates (ETSI EN 319 412-5 QCStatements)

secsy-pki stamps EU **qualified-certificate semantics** on issued leaves via the
`id-pe-qcStatements` extension (OID `1.3.6.1.5.5.7.1.3`, RFC 3739 / ETSI EN 319
412-5). These statements let a relying party recognize a certificate as issued
under a qualified trust service governed by **Regulation (EU) No 910/2014
(eIDAS)**, and — for payment services — carry the **PSD2** authorization defined
by **ETSI TS 119 495**.

The whole extension is a non-critical `SEQUENCE OF QCStatement`, hand-rolled in
`internal/pki` (the same approach as the smartcard/UPN `otherName` SAN, because
`crypto/x509` cannot encode it). It is appended to the leaf template **before**
the pre-issuance lint gate and **before** any Certificate-Transparency
poison/SCT-list extension, so the linter sees it and the precertificate and final
certificate carry it identically (their TBSCertificates stay aligned for CT).

## Supported statements

| Statement | OID | `qcstatements` field | Meaning |
|-----------|-----|----------------------|---------|
| QcCompliance | `0.4.0.1862.1.1` | `compliance: true` | An EU qualified certificate (eIDAS) |
| QcType | `0.4.0.1862.1.6` | `type: esign\|eseal\|web` | For e-signature / e-seal / website authentication (QWAC) |
| QcSSCD | `0.4.0.1862.1.4` | `sscd: true` | Private key in a qualified signature/seal creation device |
| QcRetentionPeriod | `0.4.0.1862.1.3` | `retention_years: N` | Years the issuer retains material after expiry |
| QcPDS | `0.4.0.1862.1.5` | `pds: [{url, language}]` | PKI Disclosure Statement location(s) + ISO 639-1 language |
| PSD2 QcStatement | `0.4.0.19495.2` | `psd2: {...}` | Payment-service-provider roles + National Competent Authority (ETSI TS 119 495) |

The three `QcType` values encode as `id-etsi-qct-esign` (`…1.6.1`),
`id-etsi-qct-eseal` (`…1.6.2`), and `id-etsi-qct-web` (`…1.6.3`). The four PSD2
roles are `PSP_AS` (account servicing, `0.4.0.19495.1.1`), `PSP_PI` (payment
initiation, `.2`), `PSP_AI` (account information, `.3`), and `PSP_IC` (issuing of
card-based payment instruments, `.4`).

## Built-in profiles

| Profile | Statements | Use |
|---------|-----------|-----|
| `qualified-esign` | QcCompliance, QcType `esign`, QcSSCD; keyUsage `contentCommitment` | Qualified certificate for electronic signature (natural person) |
| `qualified-eseal` | QcCompliance, QcType `eseal`, QcSSCD; keyUsage `contentCommitment` | Qualified certificate for electronic seal (legal person) |
| `qualified-web` | QcCompliance, QcType `web`; serverAuth/clientAuth; **PSD2 override permitted** | Qualified website-authentication certificate (QWAC), incl. PSD2 QWACs |

```bash
# Issue a qualified electronic-seal certificate
secsy-ca issue -ca my-issuing-ca -csr seal.csr -profile qualified-eseal -out seal.crt

# Confirm the QCStatements extension (openssl decodes it by name)
openssl x509 -in seal.crt -noout -text | grep -A6 'Qualified Certificate Statements'
```

## PSD2 QWACs (ETSI TS 119 495)

A PSD2 QWAC carries the payment institution's authorized roles plus the name and
identifier of the National Competent Authority (NCA) that authorized it. Because
those differ per certificate, they are supplied **per request** under a profile
that opts in with `allow_psd2_override: true` (the built-in `qualified-web`
does):

```bash
secsy-ca issue -ca my-issuing-ca -csr bank.csr -profile qualified-web \
  -psd2-role PSP_AS -psd2-role PSP_PI \
  -psd2-nca-name "Financial Conduct Authority" -psd2-nca-id GB-FCA \
  -out bank.crt
```

A PSD2 override supplied against a profile that is not QC-enabled, or a QC profile
that does not set `allow_psd2_override`, is a **hard error** — a request can never
fabricate qualified or PSD2 semantics the profile did not grant.

## Configuring a custom QC profile

```yaml
profiles:
  - name: qwac-psd2
    key_usages: [digitalSignature, keyEncipherment]
    ext_key_usages: [serverAuth, clientAuth]
    qcstatements:
      compliance: true
      type: web
      retention_years: 10
      pds:
        - { url: "https://ca.example/pds/en.pdf", language: en }
        - { url: "https://ca.example/pds/de.pdf", language: de }
      allow_psd2_override: true
      # An optional profile-default PSD2 block (overridden per request if allowed):
      psd2:
        roles: [PSP_AS]
        nca_name: "Bundesanstalt für Finanzdienstleistungsaufsicht"
        nca_id: DE-BAFIN
```

## Interfaces

| Surface | How to select |
|---------|---------------|
| CLI | `secsy-ca issue -profile qualified-*`; per-request PSD2 via `-psd2-role` (repeatable), `-psd2-nca-name`, `-psd2-nca-id`; `-dry-run` previews the `qcstatements` gate |
| REST | `POST /api/ca/{id}/issue` body `{"profile": "qualified-web", "psd2": {"roles": [...], "nca_name": "...", "nca_id": "..."}}` |
| REST preview | `POST /api/ca/{id}/certificates:preview` — reports the `qcstatements` gate verdict without signing |
| gRPC | `IssueCertificateRequest.psd2` / `PreviewCertificateRequest.psd2` (`PSD2QCStatement` message) |
| Config | Per-profile `qcstatements:` block (above) |

The QCStatements themselves are profile-driven (a policy decision), so they apply
uniformly across every issuance front end — REST, gRPC, CLI, and the automated
ACME/EST/SCEP/CMP protocol flows — whenever a QC profile is selected. Only the
per-request PSD2 override is reachable from the REST/gRPC/CLI issue path.

## Notes

- The extension is always **non-critical** (ETSI EN 319 412-5 §4), so a relying
  party that does not understand it still accepts the certificate.
- **certlint** recognizes `id-pe-qcStatements`, so it is never flagged as an
  unknown extension; it also fails-closed on a malformed value or one incorrectly
  marked critical (`qcstatements` check).
- Qc statements are stamped identically on classical, post-quantum, and hybrid
  leaves, and are preserved across the CT precertificate/final split.
- The encoding is verified by a hand-computed known-answer ASN.1 test and an
  `openssl x509 -text` parse check against a real certificate.
