# Operator web console

The server embeds a dependency-free operator console (vanilla JS, `go:embed`)
at **`/console/`**. There is no separate front-end deployment: the SPA ships
inside the binary, holds no privileges of its own, and drives the same
RBAC-gated, audited REST API as every other client. High-risk operations can
demand a WebAuthn passkey step-up (see [authentication.md](authentication.md));
the console runs the assertion ceremony on demand and retries.

Sign-in supports a server-side password login (session cookie + CSRF), OIDC
SSO, or stateless basic auth/bearer tokens for scripting parity.

## Pages

| Page | What it covers | Backing endpoints |
|---|---|---|
| **Certificates** | Browse a CA's issued certificates, revoke (RFC 5280 reason picker), **renew** with a fresh serial, download base/delta CRLs and per-shard partition CRLs, CRL freshness strip, and the **bulk revocation (incident response)** panel — filters (profile / CN-SAN glob / issuance window / serial list), dry-run preview, mandatory typed confirmation of the previewed count, result summary (see [incident-response.md](incident-response.md)) | `/api/ca/{id}/certificates`, `/revoked`, `/renew`, `/revoke`, `/revocations:bulk`, `/crl[...]`, `/crl/status` |
| **Inventory** | Cross-CA certificate inventory with search/status/profile filters, CT and lint verdicts, CSV export | `/api/report/inventory` |
| **Expiry Monitor** | Certificates ranked by remaining validity; on-demand scan with auto-renewal | `/api/monitor/expiring`, `/api/monitor/scan` |
| **Discovery** | External TLS endpoint scanning; flags expiring/weak/SHA-1/self-signed/mismatched/rogue certificates | `/api/discovery`, `/api/discovery/scan` |
| **Issue** | Sign a PKCS#10 CSR under a profile (with the selected profile's policy summary) | `/api/ca/{id}/issue`, `/api/profiles` |
| **Authorities** | CA hierarchy table with rollover state; **create root**, **issue intermediate**, **external subordinate CA** (generate HSM key + PKCS#10 CSR for an offline/third-party parent, download/re-download the CSR, import the signed certificate + external chain with validation warnings), **rotate** an intermediate's signing key (dual-chain overlap), **retire** a drained superseded key, **cross-sign** (local CA or external cert/CSR) with alternate-chain downloads, and the **HSM key inventory** (non-extractability verdict, admin-only) | `/api/ca/init-root`, `/api/ca/{id}/issue-intermediate`, `/api/ca/csr`, `/api/ca/{id}/csr`, `/api/ca/{id}/import-cert`, `/api/rotations`, `/api/ca/{id}/rotation`, `/rotate`, `/retire`, `/cross-signs`, `/api/inventory/keys` |
| **SSH CA** | Create SSH CAs, sign user/host public keys under profiles, browse/revoke signed certificates, download the CA public key and the KRL | `/api/ssh/cas[...]`, `/api/ssh/profiles` |
| **Signing** | Artifact code-signing: configured signer list, detached CMS signature over an uploaded file or a digest (optionally RFC 3161 countersigned), and signature verification against the PKI's anchors | `/api/sign`, `/api/sign/verify`, `/api/sign/signers` |
| **Audit** | The tamper-evident event log with action/actor filters and paging, hash-chain verification, and SIEM exports (NDJSON, CEF, RFC 5424 syslog) | `/api/events`, `/api/events/verify`, `/api/events/export` |
| **Compliance** | CA/B-Forum conformance evidence (lint split, blocked issuance, audit-chain status) plus an **ad-hoc lint** panel for any pasted certificate | `/api/report/compliance`, `/api/lint` |
| **Trust Bundle** | Issuer chain (AIA bundle, key-rollover aware), SPIFFE trust bundle (JWKS), and **X.509-SVID minting** when SPIFFE issuance is enabled | `/api/ca/{id}/chain`, `/svid/bundle`, `/svid` |
| **Secrets** | HSM-backed envelope encryption/decryption, KEK metadata, and — when configured — M-of-N **escrow on encrypt** with the policy shape displayed | `/api/secret/info`, `/encrypt`, `/decrypt` |
| **Tenants** | Tenant lifecycle (create/suspend/reactivate), per-tenant quotas, and usage reports (platform-admin only) | `/api/tenants[...]` |

## CLI ↔ console parity

Task 62 made every server-side capability the `secsy-ca` / `secsy-secret`
CLIs expose reachable from the console as well. The mapping:

| CLI | Console |
|---|---|
| `init-root`, `issue-intermediate`, `list` | Authorities page |
| `issue`, `renew`, `revoke`, `revoke-bulk`, `gen-crl` (incl. delta/shards) | Issue + Certificates pages (bulk revocation panel with dry-run count confirmation) |
| `list-certs`, `expiring`, `monitor-run`, `profiles` | Certificates, Inventory, Expiry Monitor, Issue pages |
| `rotate-intermediate`, `rotation-status`, `list-rotations`, `retire-intermediate`, `publish-chain` | Authorities page (rotate/retire actions, status badges) + Trust Bundle chain download |
| `cross-sign`, `list-cross-signs` | Authorities page (cross-signing panels) |
| `ca csr`, `ca import-cert` | Authorities page (external subordinate CA panel; CSR / Import cert actions on pending rows) |
| `ssh ca-init / sign-user / sign-host / revoke / krl / list / profiles` | SSH CA page |
| `sign`, `verify-signature` | Signing page |
| `svid`, `svid-bundle` | Trust Bundle page (SVID mint panel, bundle download) |
| `lint` | Compliance page (lint panel) |
| `inventory` | Authorities page (HSM key inventory) |
| `audit verify`, `audit export` (json/cef/rfc5424) | Audit page |
| `discover` | Discovery page |
| `tenant list/create/suspend/activate/quota/usage` | Tenants page |
| `secsy-secret encrypt/decrypt/kek-info`, `encrypt -escrow`, `escrow-config` (status) | Secrets page |

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
- `tsa-key`, `signing-key`, `secsy-secret init-kek`, `escrow-init-agent` —
  key provisioning for server-role keys; they require key-provider role
  wiring and a restart to take effect.
- `secsy-secret recover` and escrow recovery — a dual-control quorum ceremony
  requiring recovery-agent key access on the HSM; the console shows escrow
  status and can escrow-on-encrypt, but recovery stays offline by design.
- `cmp` / `grpc` — protocol client tools for testing the CMP and gRPC
  endpoints (the endpoints themselves serve machine enrollment, not the
  console).

## End-to-end coverage

`server/internal/e2e/console_test.go` drives every console workflow against a
real SoftHSM-backed server (assets, issuance, revocation+CRL, renewal, CA
lifecycle incl. rotation/retirement, cross-signing, SSH CA, signing endpoints,
lint, key inventory, audit list/verify/export, secrets round-trip incl. the
escrow-status shape). Run it with the SoftHSM environment exported:

```sh
eval "$(scripts/setup-softhsm.sh --export-env)"
cd server && go test -tags sqlite -p 1 -run TestConsoleFlow ./internal/e2e/
```
