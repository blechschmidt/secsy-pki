# HSM & key management

*Where private keys live, and the proof they never leave.*

Every signing key in secsy-pki is created inside, and used through, a key
provider — a PKCS#11 HSM, a cloud KMS, Vault Transit, or the software backend
for development. Private key material is never exported. These guides cover
choosing and configuring a backend, running the key ceremony, and proving the
non-extractability guarantee to someone who does not trust you.

| Guide | Covers |
|-------|--------|
| [**HSM / PKCS#11 configuration**](configuration.md) | The key-provider abstraction, configuring a PKCS#11 HSM or the software backend, and SoftHSM for dev/CI |
| [**HSM high availability (multi-token failover)**](high-availability.md) | Spanning several PKCS#11 tokens/slots behind health-tracked failover: `pkcs11.tokens` + `selection_policy` (primary-backup / round-robin), the failure-threshold & background recovery prober, replicated-key ceremony and the cross-token unique-label invariant, per-token health/failover metrics, and the SoftHSM mid-load failover test |
| [**Cloud KMS backend (AWS / Azure / Google)**](cloud-kms.md) | Hosting CA/TSA/OCSP signing keys in AWS KMS, Azure Key Vault or Google Cloud KMS: `key_provider.type: kms` + backend selection, per-role backend routing (`roles.ca`/`roles.tsa`), credentials via the cloud SDK default chain, IAM/RBAC requirements, the non-extractability guarantee, and the in-memory `fake` backend for credential-free tests |
| [**HashiCorp Vault Transit backend**](vault-transit.md) | Hosting CA/TSA/OCSP signing keys and KEKs in a Vault Transit engine (`kms.backend: vault`): trust/non-extractability model, token & AppRole auth with transparent re-login, least-privilege Vault policy, per-role selection, wrap/unwrap (KEK) support, the openssl-verify interop path, and the hermetic httptest fake-Vault test |
| [**Key ceremony, backup & DR**](key-ceremony.md) | M-of-N key ceremony (`secsy-ca ceremony`), key inventory, CA-metadata backup/restore, HSM token backup, and the disaster-recovery runbook & drill |
| [**Production HSM migration**](production-migration.md) | Moving from SoftHSM to a real HSM (YubiHSM / network HSM) for production |
| [**Remotely verifiable HSM audit log**](audit-log.md) | Proving to a third party that the HSM signed nothing beyond what was published, and that the proof is current: irreversible force-audit provisioning (incl. undocumented firmware commands), a pinned factory-reset chain anchor, a fail-closed persist-before-acknowledge device-log collector, the hash-chained signature ledger written at the key-provider chokepoint, device-vs-ledger-vs-published reconciliation, periodic RFC 3161 freshness attestations over the audit head, `secsy-ca hsm-audit provision/collect/timestamp/export/verify` (the verifier needs no config, database or HSM), `GET /api/hsm/audit-bundle`, and the `secsy_hsm_audit_*` metrics |
| [**YubiHSM key attestation**](key-attestation.md) | Proving what a CA key *is*, as a claim a relying party can check: the device-signed attestation certificate and its Yubico extensions (origin, capabilities, domains, on-device handle), the verifier that reports whether the key is non-exportable (`exportable-under-wrap`) and was generated on-device rather than imported, binding the attestation to a CA certificate so it describes the key that CA actually signs with, honest reporting of chain anchoring (Yubico does not publish every per-batch sub-CA), `secsy-ca hsm-attest key/ca/audit/verify` (the verifier needs no config, database or HSM), `GET /api/hsm/keys/{label}/attestation`, `GET /api/ca/{id}/key-attestation`, `POST /api/hsm/attestation:verify`, the `hsm.key_attestation` audit event, and the `secsy_hsm_key_attestation*` metrics |

---

↩ Back to the [documentation map](../README.md) · [project README](../../README.md)
