# Operator web console

The server embeds a dependency-free operator console (vanilla JS, `go:embed`)
at **`/console/`**. There is no separate front-end deployment: the SPA ships
inside the binary, holds no privileges of its own, and drives the same
RBAC-gated, audited REST API as every other client. High-risk operations can
demand a WebAuthn passkey step-up (see [authentication.md](../security/authentication.md));
the console runs the assertion ceremony on demand and retries.

Sign-in supports a server-side password login (session cookie + CSRF), OIDC
SSO, or stateless basic auth/bearer tokens for scripting parity.

For fleet-wide health beyond the console's per-CA operational views (Expiry
Monitor, Compliance, Audit), pair it with the packaged Grafana dashboard and the
[SLO recording rules and multi-window burn-rate alerts](observability.md#slos-and-error-budgets)
(`prometheus-slo-rules.yaml`) — issuance/OCSP/CRL availability and latency SLIs
with fast/slow burn-rate paging.

## Pages

| Page | What it covers | Backing endpoints |
|---|---|---|
| **Certificates** | Browse a CA's issued certificates as a **paged, filtered table** (search over subject/CN/SAN, status and profile filters incl. **held**, server-side keyset pagination with a **Load more** action), revoke (RFC 5280 reason picker), **suspend** (reversible `certificateHold`) and **release** a held certificate, **renew** with a fresh serial, download base/delta CRLs and per-shard partition CRLs, CRL freshness strip, and the **bulk revocation (incident response)** panel — filters (profile / CN-SAN glob / issuance window / serial list), dry-run preview, mandatory typed confirmation of the previewed count, result summary (see [incident-response.md](incident-response.md)) | `/api/ca/{id}/certificates`, `/revoked`, `/renew`, `/revoke`, `/certificates/{serial}:suspend`, `:release`, `/revocations:bulk`, `/crl[...]`, `/crl/status` |
| **Inventory** | Cross-CA certificate inventory with search/status/profile filters, CT and lint verdicts, CSV export, and a **key-compromise search** panel — find every certificate that shares a leaked subject public key by its **SPKI SHA-256 fingerprint** (or a pasted public-key PEM, fingerprinted in your browser), fanned out across every CA you can read, with the ready-to-run `revoke-bulk` command for the matches (see [incident-response.md](incident-response.md#finding-every-certificate-that-shares-a-compromised-key)) | `/api/report/inventory`, `/api/ca/{id}/certificates?public_key_sha256=` |
| **Expiry Monitor** | Certificates ranked by remaining validity; on-demand scan with auto-renewal | `/api/monitor/expiring`, `/api/monitor/scan` |
| **Discovery** | External TLS endpoint scanning; flags expiring/weak/SHA-1/self-signed/mismatched/rogue certificates; **paged, searchable** stored-inventory table with a **Load more** action | `/api/discovery`, `/api/discovery/scan` |
| **CT Inclusion** | Certificate Transparency SCT **inclusion-proof** state recorded by the [inclusion monitor](../issuance/certificate-transparency.md#inclusion-proof-monitoring-post-issuance): status badges (included / pending / failed / unknown-log), log name, tree size and leaf index, filterable by status; `failed` rows flag a log that broke its merge promise | `/api/ct/inclusion` |
| **Issue** | Sign a PKCS#10 CSR under a profile. The profile **policy summary** flags validity, key usage/EKU, CT/CAA/lint, and — new — whether the profile is [**eIDAS-qualified**](../certificates/qualified-certificates.md), carries an [**RFC 5280 private-key usage period**](../ca/overview.md), or is [**RFC 9345 delegated-credential-eligible**](../certificates/delegated-credentials.md). Per-request controls appear only where the selected profile permits an override: a UPN field (smartcard-logon/PKINIT), an **OCSP Must-Staple override** (RFC 7633), an **eIDAS PSD2 authorization** group (ETSI TS 119 495 PSP roles + competent-authority name/ID, for [QWACs](../certificates/qualified-certificates.md#psd2-qwacs-etsi-ts-119-495)), and a **private-key usage period** override (a duration from notBefore). A **Preview (dry run)** button runs the full [pre-issuance gate stack](../issuance/preview.md) — decision + resolved leaf + per-gate verdicts (incl. the `qcstatements` and `private_key_usage_period` gates) — **without signing** (no serial, no audit, no HSM) | `/api/ca/{id}/issue`, `/api/ca/{id}/certificates:preview`, `/api/profiles` |
| **Validate** | [Chain / path validation](../ca/chain-validation.md): build and validate a pasted leaf (+ optional intermediates) against a selected CA's trust anchors and read a structured verdict — chain-built, validity window, **live CRL+OCSP revocation** (incl. reversible on-hold), name-constraint & certificate-policy conformance, and weak key/signature flags per chain certificate; nothing is signed | `/api/validate` |
| **PKCS#12** | Server-side keygen + issue + download a password-protected `.p12` (key + leaf + full chain) for S/MIME / device enrollment; subject/SANs, key type, encoder, and optional M-of-N escrow of the subject key | `/api/ca/{id}/pkcs12`, `/api/profiles` |
| **Authorities** | CA hierarchy table with rollover state; **create root**, **issue intermediate**, **external subordinate CA** (generate HSM key + PKCS#10 CSR for an offline/third-party parent, download/re-download the CSR, import the signed certificate + external chain with validation warnings), **rotate** an intermediate's signing key (dual-chain overlap), **retire** a drained superseded key, **cross-sign** (local CA or external cert/CSR) with alternate-chain downloads, and the **HSM key inventory** (non-extractability verdict, admin-only) | `/api/ca/init-root`, `/api/ca/{id}/issue-intermediate`, `/api/ca/csr`, `/api/ca/{id}/csr`, `/api/ca/{id}/import-cert`, `/api/rotations`, `/api/ca/{id}/rotation`, `/rotate`, `/retire`, `/cross-signs`, `/api/inventory/keys` |
| **HSM** | The device the private keys live inside, when a YubiHSM is configured. **Device** metadata (serial, firmware, log usage, forced-audit state) and the factory attestation certificate; **device authenticity** — a challenge-response that proves the hardware is genuine Yubico silicon and reports its **verified serial** (see [device attestation](../hsm/device-attestation.md)); **key attestation** by CA or by HSM label (non-exportable / generated-on-device, bound to the CA certificate's key); **offline verification** of a pasted device or key bundle, needing no device; and the **device audit log** with the [reconciliation status](../hsm/audit-log.md) (device signatures vs. the CA's own ledger) plus the audit-bundle / signed-log / combined-log downloads and audit provisioning. Producing evidence needs `hsm:manage`; checking it needs only `audit:read` | `/api/hsm/info`, `/attestation`, `/attest-device`, `/attestation:verify`, `/device-attestation:verify`, `/keys/{label}/attestation`, `/api/ca/{id}/key-attestation`, `/api/hsm/audit-status`, `/audit-log`, `/audit-bundle`, `/signed-audit-log`, `/combined-audit-log`, `/provision-audit` |
| **SSH CA** | Create SSH CAs, sign user/host public keys under profiles, browse/revoke signed certificates, download the CA public key and the KRL | `/api/ssh/cas[...]`, `/api/ssh/profiles` |
| **Signing** | Artifact code-signing: configured signer list (with each signer's default **CAdES level**), detached CMS signature over an uploaded file or a digest with a per-signature **CAdES baseline level** selector (**B** signed attrs / **T** + RFC 3161 timestamp / **LT** + embedded revocation), and signature verification against the PKI's anchors with an optional **require-level** gate and require-timestamp check; results report the achieved level and any LTV material (see [artifact-signing.md](../signing/artifact-signing.md#cades-baseline-levels-b--t--lt)) | `/api/sign`, `/api/sign/verify`, `/api/sign/signers` |
| **ACME** | The [ACME server](../protocols/acme.md) at a glance: the offered challenge types (http-01 / dns-01 / tls-alpn-01), and browse of ACME accounts (with **status** and validated **contacts**, per [account & authorization lifecycle](../protocols/acme.md)) and orders | `/api/acme/accounts`, `/api/acme/orders` |
| **Audit** | The tamper-evident event log with action/actor filters and paging, hash-chain verification, SIEM exports (NDJSON, CEF, RFC 5424 syslog), a live SSE tail, and an **RFC 4998 evidence-record** verifier (by stored id or a pasted base64 DER record) reporting the nested timestamp chains and per-object digest results | `/api/events`, `/api/events/verify`, `/api/events/export`, `/api/events/stream`, `/api/ers/verify` |
| **Approvals** | The [four-eyes / maker-checker](../security/approvals.md) queue: pending sensitive operations (CA create/rotate/retire, bulk revoke, KEK rotation, token create) and the per-profile manual **issuance** gate; **approve**/**reject** with a distinct approver, and **fetch the issued certificate** once an issuance approval clears | `/api/approvals`, `/api/approvals/{id}/approve`, `/reject`, `/certificate` |
| **Compliance** | CA/B-Forum conformance evidence (lint split, blocked issuance, audit-chain status) plus an **ad-hoc lint** panel for any pasted certificate | `/api/report/compliance`, `/api/lint` |
| **Trust Bundle** | Issuer chain (AIA bundle, key-rollover aware), **alternate chains** (one per cross-signature plus the native chain, each downloadable — the path a client that trusts only an older root would use), SPIFFE trust bundle (JWKS), and **X.509-SVID / JWT-SVID minting** when SPIFFE issuance is enabled | `/api/ca/{id}/chain`, `/chains`, `/svid/bundle`, `/svid`, `/svid/jwt` |
| **DNS Records** | Generate [DANE TLSA and SSHFP](dns-records.md) pinning records in zone-file format for material this PKI issues: a TLSA panel (CA + host/port, optional leaf serial) and an SSHFP panel (SSH CA + serial, or a pasted host public key) | `/api/ca/{id}/dns-records/tlsa`, `/api/ssh/cas/{id}/dns-records/sshfp` |
| **Secrets** | HSM-backed envelope encryption/decryption (each with an optional **context / AAD** binding), KEK metadata including the [post-quantum hybrid](../secrets/password-encryption.md#post-quantum-hybrid-mode-ml-kem-1024-harvest-now-decrypt-later-resistance) state, and — when configured — M-of-N **escrow on encrypt** with the policy shape displayed. A **Crypto service** panel exposes the stateless [encryption-as-a-service](../secrets/password-encryption.md#stateless-crypto-service-data-key-keyed-hmac-random) endpoints: mint a **data key** (returned in the clear and KEK-wrapped, optional AAD), compute and **verify a keyed HMAC** (versioned MAC key), and draw **CSPRNG random bytes** (HSM RNG when available, hex/base64). A **Digital signatures** panel manages named, HSM-backed [asymmetric signing keys](../secrets/password-encryption.md#digital-signatures-named-signing-keys-sign--verify): create a key, export its public half (SPKI PEM), and **sign / verify** arbitrary data — either against the stored key or against a **supplied public key**, which is what a relying party outside this PKI holds. A **Tokenization** panel drives [format-preserving encryption](../secrets/password-encryption.md#format-preserving-encryption--tokenization-ff1) (FF1) through a named template. A **Stored secrets** panel is the registry: create or update a named secret (every write appends a version), browse **version history**, reveal any version, **roll back** to an older one, and delete — plus a **Lifecycle attention** table of TTL/rotation-due secrets. A **KEK rotation** panel runs the three-step [rotate → re-wrap → retire](../secrets/password-encryption.md#cli--secsy-secret) lifecycle with the per-version secret counts that decide when retirement is safe | `/api/secret/info`, `/encrypt`, `/decrypt`, `/datakey`, `/hmac`, `/hmac/verify`, `/random`, `/signing-keys[...]`, `/verify`, `/transform/encode`, `/decode`, `/store[...]`, `/lifecycle`, `/kek/status`, `/kek/rotate`, `/kek/retire`, `/rewrap` |
| **Tenants** | Tenant lifecycle (create/suspend/reactivate), per-tenant quotas, and usage reports (platform-admin only) | `/api/tenants[...]` |
| **API Tokens** | Native scoped [API tokens / service accounts](../security/authentication.md#4-native-scoped-api-tokens-service-accounts): create a `secsy_pat_` token (name, roles, tenant/platform scope, expiry) with the secret shown **once**, list tokens with status, and revoke | `/api/tokens`, `/api/tokens/{id}` |

## CLI ↔ console parity

Task 62 made every server-side capability the `secsy-ca` / `secsy-secret`
CLIs expose reachable from the console as well, and Task 190 re-audited the
whole CLI surface against it and closed the gaps that had opened since (the
YubiHSM attestation/audit commands, the stored-secret registry, KEK rotation,
tokenization, evidence records, and alternate chains). The mapping:

| CLI | Console |
|---|---|
| `init-root`, `issue-intermediate`, `list` | Authorities page |
| `issue` (incl. `-dry-run` preview, `-psd2-*` eIDAS PSD2, `-pkup` private-key usage period), `renew`, `revoke`, `revoke-bulk`, `gen-crl` (incl. delta/shards) | Issue (incl. **Preview (dry run)**, PSD2 & PKUP override controls) + Certificates pages (bulk revocation panel with dry-run count confirmation) |
| `suspend`, `release` (reversible `certificateHold`) | Certificates page (Suspend / Release actions; **held** status filter) |
| `export-p12` | PKCS#12 page |
| `list-certs` (incl. `-status`/`-profile`/`-q` filters + keyset paging), `expiring`, `monitor-run`, `profiles` | Certificates, Inventory, Expiry Monitor, Issue pages |
| `list-certs --by-public-key <fp\|@file>`, `revoke-bulk --by-public-key` (key-compromise) | Inventory page (**Key-compromise search** panel — SPKI-fingerprint / public-key search across all readable CAs) |
| `approvals list/approve/reject/certificate` | Approvals page (queue, approve/reject, fetch issued cert) |
| `token create/list/revoke` | API Tokens page |
| `ct inclusion-status` (read) / `ct verify-inclusion` (on-demand scan, CLI-only) | CT Inclusion page (status table) |
| `dns-records tlsa`, `dns-records sshfp` | DNS Records page |
| `rotate-intermediate`, `rotation-status`, `list-rotations`, `retire-intermediate`, `publish-chain` | Authorities page (rotate/retire actions, status badges) + Trust Bundle chain download |
| `cross-sign`, `list-cross-signs` | Authorities page (cross-signing panels) |
| `ca csr`, `ca import-cert` | Authorities page (external subordinate CA panel; CSR / Import cert actions on pending rows) |
| `ssh ca-init / sign-user / sign-host / revoke / krl / list / profiles` | SSH CA page |
| `sign` (incl. `-level b\|t\|lt`), `verify-signature` (incl. `-require-level`) | Signing page (CAdES level selector + require-level gate) |
| `svid`, `svid jwt`, `svid-bundle` | Trust Bundle page (X.509-SVID and JWT-SVID mint panels, bundle download) |
| `list-cross-signs -chains` | Trust Bundle page (**Alternate chains** table, per-chain PEM download) |
| `lint` | Compliance page (lint panel) |
| `validate-cert` | Validate page (chain/path validation) |
| `inventory` | Authorities page (HSM key inventory) |
| `audit verify`, `audit export` (json/cef/rfc5424) | Audit page |
| `ers verify` (by id or record) | Audit page (**Evidence record (RFC 4998)** panel) |
| `hsm-attest device` (device authenticity + verified serial), `hsm-attest key`, `hsm-attest ca`, `hsm-attest verify` | HSM page (Device authenticity / Key attestation / Verify an attestation panels) |
| `hsm-audit status`, `hsm-audit provision`, `hsm-audit export` | HSM page (reconciliation strip, Provision audit, Audit bundle / Signed log / Combined log downloads, device log table) |
| `discover` | Discovery page |
| `webhook create/list/enable/disable/test/deliveries/delete` | Webhooks page |
| `tenant list/create/suspend/activate/quota/usage` | Tenants page |
| `secsy-secret encrypt/decrypt/kek-info`, `encrypt -escrow`, `escrow-config` (status), `pqc-info`, `datakey`, `hmac`, `hmac-verify`, `random` | Secrets page (envelope encrypt/decrypt + KEK/PQC/escrow summary + Crypto service panel) |
| `secsy-secret signing-key create/list/public`, `sign`, `verify` (incl. `-public-key`) | Secrets page (**Digital signatures** panel — signing-key management, public-key export, sign/verify against the stored key **or a supplied public key**) |
| `secsy-secret transform encode/decode` | Secrets page (**Tokenization** panel — FF1 template encode/decode) |
| `secsy-secret put/get/list-secrets/versions/rollback`, `lifecycle` | Secrets page (**Stored secrets** panel — create/update, reveal, version history, roll back, delete; **Lifecycle attention** table) |
| `secsy-secret kek-versions`, `rotate-kek`, `rewrap`, `retire-kek` | Secrets page (**KEK rotation** panel — lineage table with per-version secret counts, rotate / re-wrap all / retire) |

### Deliberately CLI-only

Some commands are host-local or dual-control ceremonies and are intentionally
**not** exposed over the network API (and therefore not in the console):

- `ceremony` — interactive M-of-N operator quorum for root/intermediate
  creation (the API's init-root/issue-intermediate are step-up gated instead).
- `backup` / `restore`, `db migrate` / `db verify` — disaster recovery and
  store administration against local files/DSNs.
- `doctor` — local preflight diagnostics (config/HSM/DB/listener); the
  console-visible health signals live in `/healthz`, `/readyz`, and the
  Compliance page.
- `publish` — writes static CRL/OCSP artifacts to a local directory or S3.
- `blocked-keys add/list/remove` — curating the operator-managed
  weak/compromised-key blocklist (SPKI SHA-256 fingerprints) that feeds the
  pre-issuance [key-checks](../issuance/key-checks.md) gate. It is a security-admin store
  with **no network API** by design, so the blocklist is curated only from an
  authenticated host shell, never the console. The gate's effect is visible in
  the key-check verdicts and in the Issue page's dry-run preview.
- `tsa-key`, `signing-key`, `secsy-secret init-kek`, `escrow-init-agent` —
  key provisioning for server-role keys; they require key-provider role
  wiring and a restart to take effect.
- `secsy-secret recover` and escrow recovery — a dual-control quorum ceremony
  requiring recovery-agent key access on the HSM; the console shows escrow
  status and can escrow-on-encrypt, but recovery stays offline by design.
- `secsy-secret pqc-enable` / `pqc-reseal` — provisioning and re-sealing the
  ML-KEM hybrid material, which is key provisioning like `init-kek`. The
  resulting state (`available` / `enabled`) is shown on the Secrets page.
- `secsy-secret exec` — injects decrypted secrets into a child process's
  environment on the machine it runs on; there is no browser equivalent.
- `cmp` / `grpc` — protocol client tools for testing the CMP and gRPC
  endpoints (the endpoints themselves serve machine enrollment, not the
  console).
- `hsm-audit verify` — the auditor's offline verifier. It deliberately reads no
  config, no database and no device, so that a third party can check the CA's
  claims on a machine with access to none of them; running it *inside* the
  audited server would defeat the argument. The console instead serves the
  bundle (`Audit bundle`) for exactly that offline check.
- `hsm-audit collect` / `timestamp` / `commit` — collection now happens
  automatically after every HSM operation, and the RFC 3161 freshness proofs and
  device-signed serial bindings are scheduled attestation ceremonies needing the
  TSA-role key provider. Their results are visible on the HSM page's
  reconciliation strip.
- `hsm-attest audit` — attests *every* asymmetric key on the device in one pass
  for an inventory report; the console attests one key at a time, by CA or by
  label, which is the interactive question.
- `ca import`, `import-key`, `secsy-secret signing-key import` — [importing
  existing key material](../ca/import.md). Their input is a private key file,
  and the point of the operation is to stop that material being copied around;
  uploading it to a browser would do the opposite. It is read once, from a local
  path, on an operator's shell. The *result* is fully visible in the console:
  the adopted CA appears on the Authorities page and issues like any other, the
  key shows in the HSM key inventory, and the HSM page attests it (reporting,
  correctly, that it was imported rather than generated).
- `delegated-credential` (RFC 9345) — minting one requires the *leaf's* private
  key, which the CA never holds and which must not be uploaded to a browser. The
  Issue page reports whether a profile makes a certificate delegation-eligible;
  minting stays where the key is.
- `inventory retention` — ages out long-expired terminal inventory rows; a
  background job with a manual CLI trigger, not an interactive operation.
- `ct verify-inclusion`, `svid jwt-verify` — on-demand scans and client-side
  checks; the recorded results are on the CT Inclusion and Trust Bundle pages.
- `ers generate` / `renew` / `export` / `list` — evidence-record production is a
  scheduled TSA ceremony; the console verifies records (`ers verify`), which is
  the part a relying party performs.

## End-to-end coverage

`server/internal/e2e/console_test.go` drives every console workflow against a
real SoftHSM-backed server (assets, issuance, revocation+CRL, renewal, CA
lifecycle incl. rotation/retirement, cross-signing and alternate chains, SSH CA,
signing endpoints, lint, key inventory, audit list/verify/export, secrets
round-trip incl. the escrow-status shape, the stored-secret registry with
version history and rollback, and the KEK rotate → re-wrap → retire lifecycle
including its refusal to retire a version secrets still depend on). Run it with
the SoftHSM environment exported:

```sh
eval "$(scripts/setup-softhsm.sh --export-env)"
cd server && go test -tags sqlite -p 1 -run TestConsoleFlow ./internal/e2e/
```
