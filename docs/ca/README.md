# Certificate authority

*Standing up CAs and running the certificate lifecycle.*

The CA layer owns root and intermediate certificate authorities and the end-
entity lifecycle built on them — issue, renew, revoke, suspend and release —
together with the CRL and OCSP responders that publish the result. Start with
the overview; the rest of the section covers the less-common CA topologies and
lifecycle operations.

| Guide | Covers |
|-------|--------|
| [**CA setup & certificate lifecycle**](overview.md) | Initializing root & intermediate CAs, profiles, issuing / renewing / revoking certificates, reversible suspend/hold + release, the paged/filtered/searchable issued-cert list endpoints, and serving CRL & OCSP |
| [**Intermediate key rotation**](rotation.md) | Safe, HSM-backed rollover of intermediate CA signing keys: cross-signing under the root, the dual-chain overlap window, combined-chain publication (AIA/bundle), controlled retirement, monitor-triggered auto-rotation, `secsy-ca rotate-intermediate`/`rotation-status`/`retire-intermediate`/`publish-chain`, and the rotation drill |
| [**Cross-signing & bridge CAs**](cross-signing.md) | Certifying one subordinate key under multiple issuers for bridge-CA and root-transition trust: `local-ca`/`certificate`/`csr` subjects, tenant-scoped cross-sign records, alternate-chain selection by Subject Key Identifier, `secsy-ca cross-sign`/`list-cross-signs`, the `/api/ca/{id}/cross-signs` + `/chains` endpoints, and dual-chain `openssl verify` interop |
| [**Externally-signed subordinate CA**](external-ca.md) | The offline/third-party-root topology: `secsy-ca ca csr` (HSM key + PKCS#10 CSR with CA attributes), the out-of-band signing ceremony, `ca import-cert` fail-closed validation (key match against the HSM, cA=TRUE, keyUsage, validity, chain verification) with operator warnings, chain serving through to the external trust anchor, same-key renewal via `-replace`, and the openssl-as-external-root e2e |
| [**Importing existing keys & adopting a CA**](import.md) | Migrating onto this PKI without re-keying: `secsy-ca ca import` adopts a CA that already exists (its key **and** its certificate) so a root already in trust stores keeps issuing; `secsy-ca import-key` places a bare key into any provider role; `secsy-secret signing-key import` adopts an application signing key. Accepted formats (PKCS#8 plain/PBES2-encrypted, PKCS#1, SEC1, legacy DEK-Info PEM, OpenSSH, PKCS#12, bare DER), the fail-closed pairing/validity/key-quality checks and the sign-a-challenge proof before anything is persisted, automatic parent linkage, the least-privilege non-extractable token template, why import is CLI-only, and what it deliberately cannot launder — attestation still reports the key as imported |
| [**SSH certificate authority**](ssh-ca.md) | HSM-backed OpenSSH user/host certificate signing: `secsy-ca ssh` (ca-init, sign-user, sign-host, revoke, krl), per-profile principals/validity/extensions/critical-options policy, store-allocated serials, revocation published as OpenSSH KRLs over HTTP (`sshd` `RevokedKeys`), `/api/ssh/*` with RBAC + tenant scoping, `ssh.sign`/`ssh.revoke` audit, and `ssh-keygen -L`/`-Q` interop |
| [**PKCS#12 (.p12/.pfx) export**](pkcs12.md) | Server-side-keygen key delivery for S/MIME and device enrollment: generate a subject keypair, issue a leaf, and return a password-protected PKCS#12 (key + leaf + full chain) — the CA key never leaves the HSM. `secsy-ca export-p12`, `POST /api/ca/{id}/pkcs12`, and the console PKCS#12 page; `modern`/`legacy` encoders (FIPS refuses legacy), ECDSA/RSA subject keys, optional M-of-N escrow of the subject key, `cert.pkcs12` audit + metrics, and the `openssl pkcs12 -info` round-trip test |
| [**Chain / path validation**](chain-validation.md) | Read-only, HSM-independent validation of a supplied leaf (+ intermediates) against a CA's trust anchors: a tolerant DFS path builder (not `x509.Verify`) reporting chain-built, validity, **live CRL+OCSP revocation** (incl. reversible on-hold), name-constraint/policy conformance, and weak key/signature flags per chain certificate — `secsy-ca validate-cert` (PEM/DER, exits non-zero when invalid), `POST /api/validate`, gRPC `ValidateChain`, and the console Validate page |
| [**Certificate-inventory retention & archival**](retention.md) | The leader-elected background job that ages out `issued_certificates` rows under an explicit, fail-safe policy, so a high-volume ACME/EST/STAR inventory stays bounded without an operator remembering to prune: the `retention:` config block, archive-before-delete, the `retention.freshness` doctor check, and the audit trail every run leaves. |

---

↩ Back to the [documentation map](../README.md) · [project README](../../README.md)
