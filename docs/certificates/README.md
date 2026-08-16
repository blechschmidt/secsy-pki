# Certificate types & profiles

*The specialized certificate shapes the CA can issue.*

Beyond ordinary TLS server and client certificates, secsy-pki ships profiles
for identity, e-mail, regulated and post-quantum use cases. Each page covers
the profile, the extensions that define it, the policy controls that scope who
may request it, and the interoperability caveats.

| Guide | Covers |
|-------|--------|
| [**S/MIME e-mail protection**](smime.md) | Mailbox-validated S/MIME certificates: the `smime`/`smime-sign`/`smime-encrypt` profiles, RFC 5321/6531 mailbox validation + punycode normalization of rfc822Name SANs, per-profile & per-tenant e-mail domain allowlists, the CA/B Forum S/MIME Baseline Requirements lint rules (`smime_*` checks, enforce/warn per profile), dual-key sign/encrypt deployment with encryption-key escrow, EST/SCEP enrollment, and `openssl smime` interop |
| [**Smartcard-logon & Kerberos PKINIT**](smartcard-logon.md) | Microsoft Windows smartcard-logon and Kerberos PKINIT client-auth certificates for Active Directory: the `smartcard-logon`/`pkinit-client`/`smartcard-pkinit` profiles, the `id-ms-UPN` (`1.3.6.1.4.1.311.20.2.3`) User Principal Name otherName SAN + `msSmartcardLogon`/`pkinitClientAuth` EKUs, per-profile & per-tenant realm allowlists, `-upn` CLI flag / `upns` REST+gRPC field / console field / EST-SCEP CSR extraction, `cert.upn` audit + metrics, and Go + `openssl asn1parse` known-answer encoding tests |
| [**eIDAS qualified certificates (ETSI EN 319 412-5)**](qualified-certificates.md) | EU qualified-certificate semantics via the non-critical `id-pe-qcStatements` extension (`1.3.6.1.5.5.7.1.3`): QcCompliance, QcType (`esign`/`eseal`/`web`), QcSSCD, QcRetentionPeriod, QcPDS, and the **ETSI TS 119 495 PSD2** QcStatement (PSP roles + NCA name/id); the `qualified-esign`/`qualified-eseal`/`qualified-web` (QWAC) profiles, the per-profile `qcstatements:` config block, per-request PSD2 override (`-psd2-role`/`-psd2-nca-*` CLI, `psd2` REST/gRPC field) gated by `allow_psd2_override`, certlint recognition, CT-safe hand-rolled ASN.1, and a known-answer + `openssl x509 -text` parse test |
| [**SPIFFE SVID workload identity**](spiffe.md) | HSM-backed SPIFFE workload identities, both X.509-SVID and JWT-SVID: the short-lived `spiffe-svid` profile (single `spiffe://` URI SAN, CA:false, digitalSignature), `POST /api/ca/{id}/svid` + `secsy-ca svid`, the trust-domain allowlist (RBAC-layered), fraction-based short-TTL auto-renewal, the JWKS trust-bundle endpoint, and go-spiffe / SPIRE integration |
| [**TLS Delegated Credentials (RFC 9345)**](delegated-credentials.md) | Certificates eligible to authorize short-lived TLS delegated credentials via the non-critical `id-ce-delegationUsage` extension (`1.3.6.1.4.1.44363.44`, `NULL`): the `delegation_usage` per-profile opt-in + built-in `server-delegation` profile, the fail-closed mutual exclusion with OCSP Must-Staple (RFC 9345 §4.2), the operator-holds-the-leaf-key constraint, `secsy-ca delegated-credential mint`/`verify` (offline, operator-held key), `POST /api/ca/{id}/delegated-credential` (recovers an escrowed PKCS#12 leaf key via an M-of-N quorum), the ≤7-day `valid_time` cap, RSASSA-PSS-only RSA signing, `cert.delegated_credential` audit + metrics, and `openssl asn1parse` DER + sign/verify round-trip tests |
| [**Post-quantum & hybrid certificates**](pqc.md) | ML-DSA (FIPS 204) signatures on the CA/issuance paths: pure-PQC and catalyst-hybrid (classical + ML-DSA alternative-signature) certificates, per-profile algorithm selection (`pqc-server`/`hybrid-server`), the software-provider fallback for SoftHSM, `secsy-ca init-root -algorithm pqc\|hybrid`, chain verification, and the interop / trust-store caveats |

---

↩ Back to the [documentation map](../README.md) · [project README](../../README.md)
