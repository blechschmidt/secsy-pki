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

Tasks 62, 190 and 198 each audited the whole CLI surface against the console by
hand, and the mapping drifted between every audit — this page used to carry its
own copy of it, and that copy went stale (it listed `doctor`, `backup`,
`publish`, `blocked-keys`, `tsa-key`, `ca import` and the evidence-record
commands as CLI-only long after each of them had a console control).

So the mapping now lives in one place, and a test keeps it true:

**→ [CLI ↔ console parity matrix](cli-console-parity.md)** — every top-level
`secsy-ca` / `secsy-secret` command against the console view that offers it, the
sub-commands and routes that have no console control, and the remaining gaps.

`server/internal/console/parity_test.go` enforces it: it parses the route
registrations, this console's bundle and both CLIs' command dispatch, and fails
when any of them is unaccounted for — or when a command is missing from that
page. A new route or command cannot ship without a parity decision.

### Deliberately CLI-only

Some commands are host-local, dual-control ceremonies, or offline by design, and
are intentionally **not** exposed over the network API. The authoritative list,
with the reason for each, is
[in the parity matrix](cli-console-parity.md#deliberately-cli-only) — together
with [the sub-commands](cli-console-parity.md#sub-commands-that-stay-cli-only)
that stay on the command line even though their parent command does not.


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
