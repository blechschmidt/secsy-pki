# Enrollment protocols & integrations

*How clients and devices actually get their certificates.*

These are the machine-facing surfaces: standards-based enrollment protocols for
browsers, devices, MDMs and Windows domains, the host-side renewal agent, and
the gRPC API. All of them terminate in the same HSM-backed issuance path and
the same gate stack as the REST API.

| Guide | Covers |
|-------|--------|
| [**ACME server (RFC 8555)**](acme.md) | Automated certificate issuance for certbot/lego/acme.sh: enabling ACME, ACME-enabled profiles, http-01 & dns-01, and External Account Binding |
| [**ACME Multi-Perspective Issuance Corroboration (SC-067)**](acme-mpic.md) | Corroborating every ACME domain-control check from several independent network perspectives so a *localized* BGP/DNS hijack is outvoted by the honest vantage points: the `Perspective`/`Coordinator`/quorum-policy layer over http-01, dns-01 and tls-alpn-01, the `acme.mpic` config block (per-remote DNS resolver and SOCKS5 proxy), fail-closed quorum evaluation, the `secsy_acme_mpic_*` metrics and the `acme.mpic` audit event. Off by default; phasing in with CA/Browser Forum ballot SC-067. |
| [**SCEP & EST enrollment**](scep-est.md) | Device / MDM / IoT auto-enrollment: SCEP (RFC 8894) with challenge-password grants and an HSM RA key, and EST (RFC 7030) over TLS with Basic / client-cert auth and server-side keygen |
| [**BRSKI zero-touch onboarding (RFC 8995)**](brski.md) | Voucher-based bootstrapping of factory-fresh IoT/network devices with no per-device secret: the registrar validates the pledge's manufacturer IDevID against the (attestation) trust anchors, obtains an RFC 8366 CMS-signed voucher from a pluggable/built-in MASA, pins the provisional domain cert, and hands the pledge off to EST `simpleenroll` for the HSM-backed LDevID; per-profile enable, `cert.brski` audit + metrics |
| [**Windows autoenrollment (MS-XCEP + MS-WSTEP)**](windows-autoenrollment.md) | GPO-driven certificate autoenrollment for AD-joined Windows machines: the MS-XCEP `GetPolicies` policy service (CEP) advertising templates mapped from secsy-pki profiles (template OID/name, key specs, renewal/enrollment flags) and the MS-WSTEP WS-Trust `RequestSecurityToken` enrollment service (CES) issuing an HSM-backed certificate from a PKCS#10 `BinarySecurityToken`; Kerberos-free client auth via native API tokens and mutual TLS, profile↔template mapping from the CSR's Microsoft template extensions, `mswstep:` config with CEP/CES URL advertisement, AD GPO wiring, `mswstep.getpolicies`/`mswstep.enroll` audit + metrics |
| [**Host auto-enrollment agent (secsy-agent)**](agent.md) | Client-side daemon that keeps host/service certificates fresh over EST or ACME http-01 (EAB/bootstrap onboarding, keys never leave the host): declarative YAML cert specs, ARI-driven renewal with fraction-of-lifetime fallback and deterministic jitter, chain-verified atomic installs with reload hooks (command/SIGHUP) and rollback, `run`/`once`/`status` CLI, Prometheus textfile/exporter metrics, and systemd units |
| [**gRPC API**](grpc-api.md) | The core certificate-lifecycle operations (issue/renew/revoke, get certificate/status, list, CRL/OCSP metadata) exposed over gRPC alongside REST: `PKIService` (`proto/pki/v1/pki.proto`), server reflection + health, the same Bearer/Basic/mTLS auth, RBAC, tenant scoping and audit as REST, gRPC status-code mapping, request-ID/trace propagation, and the `secsy-ca grpc` client |

---

↩ Back to the [documentation map](../README.md) · [project README](../../README.md)
