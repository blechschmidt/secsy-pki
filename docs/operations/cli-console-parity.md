# CLI ↔ console parity matrix

Everything an operator can do with `secsy-ca` or `secsy-secret` should also be
doable from the embedded [operator web console](web-console.md) — and where it
cannot be, the reason should be a decision rather than an oversight.

This page **is** that matrix: every top-level command of both CLIs, the console
view that offers the same capability, or an explicit reason it stays on the
command line.

!!! info "This page is enforced by a test"

    `server/internal/console/parity_test.go` parses the route registrations in
    `handlers.go`, the console bundle in `server/internal/console/static/`, and
    the command dispatch in `cmd/secsy-ca/main.go` + `cmd/secsy-secret/main.go`,
    and fails if any of them is unaccounted for — including if a command named in
    its table is missing from *this page*. Tasks 62, 190 and 198 each established
    parity by hand and it drifted between each audit; the test exists so a fourth
    hand-audit is never needed. See [keeping it honest](#keeping-it-honest).

Current state: **88** top-level CLI commands — **76** offered by a console view,
**12** deliberately CLI-only. **195** `/api/…` routes — **167** driven by a
console control, **28** with a classified reason none exists.

## Console views

The console's 24 views, with the `data-view` name the test tables use:

| View | `data-view` | View | `data-view` |
|---|---|---|---|
| Certificates | `certs` | Trust Bundle | `bundle` |
| Inventory | `inventory` | DNS Records | `dns` |
| Expiry Monitor | `monitor` | Operations | `ops` |
| Discovery | `discovery` | Secrets | `secrets` |
| CT Inclusion | `ct` | Tenants | `tenants` |
| Issue | `issue` | API Tokens | `tokens` |
| PKCS#12 | `p12` | Access | `access` |
| Authorities | `cas` | Webhooks | `webhooks` |
| HSM | `hsm` | ACME | `acme` |
| SSH CA | `ssh` | Audit | `audit` |
| Signing | `signing` | Approvals | `approvals` |
| Validate | `validate` | Compliance | `compliance` |

## `secsy-ca`

### CA lifecycle

| Command | Console view | Where |
|---|---|---|
| `secsy-ca init-root` | Authorities | **Create root CA** |
| `secsy-ca issue-intermediate` | Authorities | **Issue intermediate CA** |
| `secsy-ca ca` | Authorities | **External subordinate CA (CSR)** for `ca csr` / `ca import-cert`; **Adopt an existing CA** for `ca import` |
| `secsy-ca import-key` | Authorities | **Import a key into the provider** |
| `secsy-ca list` | Authorities | the CA table |
| `secsy-ca inventory` | Authorities | **HSM key inventory** (non-extractability verdict). `inventory retention` is on the Inventory view |
| `secsy-ca rotate-intermediate` | Authorities | **Rotate signing key** (dual-chain overlap) |
| `secsy-ca rotation-status` | Authorities | per-CA rollover badges, from the lineage list |
| `secsy-ca list-rotations` | Authorities | the same lineage list |
| `secsy-ca retire-intermediate` | Authorities | **Retire key**, with the outstanding-leaf drain check |
| `secsy-ca cross-sign` | Authorities | **Cross-signing** (local CA or pasted external cert/CSR) |
| `secsy-ca list-cross-signs` | Authorities | **Cross-signs of a CA**; `-chains` lands on Trust Bundle → **Alternate chains** |
| `secsy-ca publish-chain` | Trust Bundle | the AIA issuer-chain download |

### Issuance & certificate lifecycle

| Command | Console view | Where |
|---|---|---|
| `secsy-ca issue` | Issue | **Issue a leaf certificate**, incl. the profile policy summary, PSD2/PKUP overrides and **Preview (dry run)** |
| `secsy-ca issue-bulk` | Issue | **Bulk issuance — fleet provisioning** |
| `secsy-ca profiles` | Issue | the profile picker + policy summary |
| `secsy-ca export-p12` | PKCS#12 | server-side keygen, issue and download, with optional M-of-N escrow |
| `secsy-ca renew` | Certificates | **Renew** row action |
| `secsy-ca revoke` | Certificates | **Revoke** with the RFC 5280 reason picker |
| `secsy-ca revoke-bulk` | Certificates | **Bulk revocation — incident response** (dry-run + typed count confirmation) |
| `secsy-ca suspend` | Certificates | **Suspend** (reversible `certificateHold`) |
| `secsy-ca release` | Certificates | **Release** a held certificate |
| `secsy-ca gen-crl` | Certificates | base / delta / per-shard CRL downloads and the freshness strip |
| `secsy-ca list-certs` | Certificates | the paged, filtered table; `--by-public-key` is Inventory → **Key-compromise search** |
| `secsy-ca delegated-credential` | Certificates | **Mint a TLS delegated credential (RFC 9345)**. Minting needs the *leaf's* key, so the console recovers it from the M-of-N escrow envelope; `delegated-credential verify` is offline crypto and has no REST counterpart |
| `secsy-ca expiring` | Expiry Monitor | the remaining-validity ranking |
| `secsy-ca monitor-run` | Expiry Monitor | **Scan now** (with auto-renewal) |
| `secsy-ca svid` | Trust Bundle | **Mint an X.509-SVID** / **Mint a JWT-SVID** |
| `secsy-ca svid-bundle` | Trust Bundle | the SPIFFE trust-bundle (JWKS) download |

### Governance, audit & evidence

| Command | Console view | Where |
|---|---|---|
| `secsy-ca tenant` | Tenants | tenant lifecycle, quotas and usage reports |
| `secsy-ca token` | API Tokens | create (secret shown once), list, revoke |
| `secsy-ca grant` | Access | **Grant access**, **Effective access**, **Role catalog**, **User groups** |
| `secsy-ca webhook` | Webhooks | subscriptions, enable/disable, test delivery, delivery history |
| `secsy-ca approvals` | Approvals | the four-eyes queue, approve/reject, fetch the issued certificate |
| `secsy-ca audit` | Audit | the hash-chained event log, `verify`, SIEM exports, the live SSE tail and `audit anchor` |
| `secsy-ca ers` | Compliance | **Evidence records (RFC 4998)** — list, generate, renew, export, verify |
| `secsy-ca lint` | Compliance | **Lint a certificate** (paste any certificate) |
| `secsy-ca blocked-keys` | Compliance | **Compromised-key blocklist** — add, list, remove |
| `secsy-ca validate-cert` | Validate | chain/path validation with live CRL+OCSP revocation |
| `secsy-ca ct` | CT Inclusion | the SCT inclusion-proof table and the on-demand sweep |
| `secsy-ca discover` | Discovery | external TLS endpoint scanning and the stored inventory |
| `secsy-ca dns-records` | DNS Records | **DANE TLSA** and **SSHFP** zone snippets |

### Devices, signing & operations

| Command | Console view | Where |
|---|---|---|
| `secsy-ca hsm-attest` | HSM | **Device authenticity**, **Key attestation** (by CA or by label), **Device-wide attestation audit** for `hsm-attest audit`, **Verify an attestation**. `hsm-attest verify` is also offered offline, by design |
| `secsy-ca hsm-audit` | HSM | **Audit-log reconciliation**, **Device audit log**, provisioning and the bundle / signed-log / combined-log downloads. `hsm-audit verify` and `verify-file` stay offline so a third party can check the claims on a machine with none of the CA's state |
| `secsy-ca ssh` | SSH CA | create CAs, sign user/host keys, browse/revoke, CA public key and KRL downloads |
| `secsy-ca sign` | Signing | detached CMS signature with the CAdES baseline-level selector (B / T / LT) |
| `secsy-ca verify-signature` | Signing | **Verify**, with the require-level and require-timestamp gates |
| `secsy-ca signing-key` | Signing | **Provision a code-signing credential** |
| `secsy-ca tsa-key` | Signing | **Provision the RFC 3161 TSA credential** |
| `secsy-ca doctor` | Operations | **Preflight diagnostics** (config / HSM / KMS / DB / audit chain / expiry / CRL / clock / TLS) |
| `secsy-ca backup` | Operations | **Disaster-recovery manifest**, and **Restore drill** for the verify half |
| `secsy-ca publish` | Operations | **Static-artifact publishing** and publish verification |

## `secsy-secret`

Every command below lands on the single **Secrets** view, whose panels mirror the
CLI's shape — see [password & secret encryption](../secrets/password-encryption.md).

| Command | Console view | Where |
|---|---|---|
| `secsy-secret encrypt` | Secrets | **Encrypt** (with optional context/AAD and escrow-on-encrypt) |
| `secsy-secret decrypt` | Secrets | **Decrypt** |
| `secsy-secret datakey` | Secrets | **Data key** — returned in the clear and KEK-wrapped |
| `secsy-secret hmac` | Secrets | **Keyed HMAC** |
| `secsy-secret hmac-verify` | Secrets | the verify side of the same panel |
| `secsy-secret random` | Secrets | **Random bytes** (HSM RNG when available) |
| `secsy-secret signing-key` | Secrets | **Signing keys** — create, list, export the SPKI public half; **Import an existing signing key** for `signing-key import` |
| `secsy-secret sign` | Secrets | **Sign / verify** |
| `secsy-secret verify` | Secrets | the same panel, incl. verification against a *supplied* public key |
| `secsy-secret transform` | Secrets | **Tokenization** — FF1 format-preserving encode/decode through a named template |
| `secsy-secret put` | Secrets | **Create / update** a stored secret (each write appends a version) |
| `secsy-secret get` | Secrets | reveal any version from the stored-secret table |
| `secsy-secret list-secrets` | Secrets | the **Stored secrets** registry table |
| `secsy-secret versions` | Secrets | **Version history** |
| `secsy-secret rollback` | Secrets | **Roll back** to an older version |
| `secsy-secret lifecycle` | Secrets | **Lifecycle attention** — TTL / rotation-due secrets |
| `secsy-secret kek-info` | Secrets | the KEK summary line (label, family, version, provider, algorithms) |
| `secsy-secret kek-versions` | Secrets | **KEK rotation** — the lineage table with per-version secret counts |
| `secsy-secret rotate-kek` | Secrets | **Rotate** in the same panel |
| `secsy-secret rewrap` | Secrets | **Re-wrap all** |
| `secsy-secret retire-kek` | Secrets | **Retire**, which refuses while secrets still depend on the version |
| `secsy-secret pqc-info` | Secrets | the post-quantum hybrid state in the KEK summary (`provisioned but OFF` vs. `enabled`) |
| `secsy-secret escrow-config` | Secrets | the escrow status in the KEK summary (`escrow N-of-M recovery agents`) |
| `secsy-secret audit` | Audit | the tamper-evident event log and its chain verification |

## Deliberately CLI-only

The 12 commands with no console equivalent, and the reason for each. They fall
into four kinds: **offline store/DR administration** that must work when the
server does not, **dual-control ceremonies** at a physical device, **protocol
clients** that are test tools rather than server features, and **key
provisioning** whose result only reaches the running process through config.

| Command | Why it stays on the command line |
|---|---|
| `secsy-ca version` | Shell plumbing: prints this binary's version, Go runtime and FIPS module state. |
| `secsy-ca db` | Offline store migration and verification. It runs **before** the server starts, takes its own source and destination DSNs, and must work when the deployment it is migrating cannot serve requests. |
| `secsy-ca restore` | The disaster-recovery path, used precisely when the server is **not** running — it writes the store the API would be serving from. The console offers the read halves: the DR manifest and a non-destructive **Restore drill** on the Operations view. |
| `secsy-ca ceremony` | An interactive M-of-N operator quorum at a **physical** HSM: each custodian appears in person and enters a share on that terminal. The API's `init-root` / `issue-intermediate` are WebAuthn step-up gated instead. |
| `secsy-ca cmp` | A CMP protocol **client** for exercising the `/cmp` endpoint; it generates its own key and talks to a running server. Not a server feature. |
| `secsy-ca grpc` | A gRPC **client** for exercising the `PKIService` endpoint. Not a server feature. |
| `secsy-secret init-kek` | Provisions the deployment's key-encryption key. Server-role key provisioning: the label has to reach the running process through config, so it needs a restart to take effect. |
| `secsy-secret pqc-enable` | Provisions the ML-KEM hybrid material — key provisioning like `init-kek`. The resulting state *is* shown on the Secrets view. |
| `secsy-secret pqc-reseal` | Re-seals existing envelopes under the hybrid material: the migration half of `pqc-enable`, offline for the same reason. |
| `secsy-secret escrow-init-agent` | Generates a recovery agent's key pair on the HSM. Key provisioning — and the agent's own custodian runs it, not the CA operator. |
| `secsy-secret recover` | The dual-control escrow recovery quorum: it needs recovery-agent key access and a quorum of custodians. The console shows escrow status and can escrow on encrypt; recovery stays offline by design. |
| `secsy-secret exec` | Injects decrypted secrets into a child process's environment **on the machine it runs on**. There is no browser equivalent of spawning a local process. |

## Sub-commands that stay CLI-only

The tables above map **commands**. A handful of *sub-commands* of an otherwise
console-backed command have no browser equivalent, for reasons of their own:

| Sub-command | Why |
|---|---|
| `secsy-ca hsm-audit verify` | The auditor's offline bundle verifier. It deliberately reads no config, no database and no device, so a third party can check the CA's claims on a machine with access to none of them — running it *inside* the audited server would defeat the argument. The console serves the bundle for exactly that check. |
| `secsy-ca hsm-audit verify-file` | The same argument for the [append-only device-log file](../hsm/audit-log.md): the file exists so a copy can live somewhere the CA operator cannot rewrite it. `hsm-audit status` does report the file's position, and that is on the HSM view. |
| `secsy-ca hsm-audit collect` / `timestamp` / `commit` | Collection now happens automatically after every HSM operation; the RFC 3161 freshness proofs and device-signed serial bindings are scheduled ceremonies needing the TSA-role key provider. Their results are on the HSM view's reconciliation strip. |
| `secsy-ca delegated-credential verify` | Pure offline crypto over a wire credential and a certificate. There is no REST counterpart to expose. |

Two sub-commands that used to be on this list are not any more. `secsy-ca
hsm-attest audit` is the HSM view's **Device-wide attestation audit**
(`GET /api/hsm/attestation-audit`), which walks the key inventory, attests each
key and reports the per-key verdicts with a rollup — one unattestable key is a
row in the table rather than a failed pass, exactly as the CLI's table prints it.
`secsy-secret signing-key import` is the Secrets view's **Import an existing
signing key** (`POST /api/secret/signing-keys/import`), authorized identically to
creation and returning the identical key view, so an adopted key is
indistinguishable from a generated one. Both request bodies that carry private key
material are size-limited before they are decoded, and no part of that material is
echoed, logged or written to an audit detail.

## REST routes with no console control

The other half of the matrix. Of the 195 `/api/…` routes, 28 have no console
control, in four classified kinds:

| Kind | Count | Routes | Why |
|---|---|---|---|
| **Public protocol** | 2 | `POST /api/ca/{id}/ocsp`, `GET /api/ca/{id}/ocsp/{req}` | The RFC 6960 responder. Its callers are TLS clients and stapling daemons speaking DER; an operator checks revocation on the Validate or Certificates view. |
| **Plumbing** | 7 | `/api/health`, `/api/auth/config`, `/api/me`, `/api/parse-csr`, `/api/docs`, `/api/docs/openapi.yaml`, `/api/docs/openapi.json` | Liveness probes, sign-in bootstrap, the Swagger UI and the OpenAPI document. `/api/auth/config` and `/api/me` *are* called by `app.js`, but before any view exists. |
| **Legacy SPA only** | 17 | `/api/audit-log`, `/api/access-log`, `/api/restriction-sets` (+`/{id}`), `/api/keys/{id}/restriction-sets`, `/api/keys/{id}/default-restriction-set`, `/api/keys/{id}/my-restrictions`, `/api/keys/{id}/permissions`, `/api/keys/{id}/sign`, `/api/keys/{id}/sign-x509`, `/api/keys/{id}/public-key`, `/api/hsm/factory-reset` | Reachable only from the **older disk-based SPA** in `server/web/static/`, which predates the embedded console. Real debt, listed as such — see [the gaps](#known-gaps) below. |
| **Reached another way** | 2 | `GET /api/ca/{id}/rotation`, `GET /api/keys/{id}/children` | The capability *is* in the console; it uses a different endpoint. Authorities loads the whole rotation lineage from `GET /api/rotations` and indexes it by CA, and renders the hierarchy from each row's `parent_id`. |

### Known gaps

Parity is not yet total, and the matrix is the place that says so:

- **Restriction sets** (7 routes) have no embedded-console UI at all. Managing
  per-CA issuance restriction sets means the legacy SPA or the CLI.
- **The pre-Task-191 per-CA permission model** (`/api/keys/{id}/permissions`) is
  legacy-only; the console administers access through the newer resource grants
  on the Access view, which is the intended replacement rather than a port.
- **`/api/audit-log` and `/api/access-log`** are the pre-event-log tables. The
  console's Audit view reads the hash-chained event log (`/api/events`), which
  supersedes them but does not contain their historical rows.
- **`/api/keys/{id}/public-key`**, **`/api/keys/{id}/sign`** and
  **`/api/keys/{id}/sign-x509`** are superseded raw-key endpoints; the console
  offers the per-purpose equivalents (`/api/sign`, `/api/ca/{id}/issue`,
  `/api/secret/signing-keys/{name}/sign`).
- **`/api/hsm/factory-reset`** is an irreversible device wipe. The legacy SPA
  offers it; the embedded console deliberately does not.

Every *sub-command* gap is now either offline by design or closed: the two that
were neither — `secsy-secret signing-key import` and `secsy-ca hsm-attest audit` —
are described above.

## Keeping it honest

`server/internal/console/parity_test.go` runs in the HSM-free job — it parses
source, so it needs no device, database or network:

```console
$ cd server
$ go test ./internal/console/
```

It asserts five things:

1. Every `/api/…` route in `RegisterRoutes` has exactly one entry in the route
   table, and no entry is stale. **A new route turns the suite red until its
   author declares which console view surfaces it, or why none does.**
2. Every console view either table names really exists — a `data-view="X"` nav
   button *and* an `id="view-X"` section in `index.html`.
3. A route mapped to a view is actually referenced by `static/app.js`, matched on
   the literal path segments around the `{param}` placeholders. This catches
   "declared in the table but never wired"; it is a one-directional check, and
   the test documents what it cannot catch.
4. Every top-level command both `main.go` files dispatch has exactly one entry in
   the command table, and no entry is stale.
5. Every command in that table is named on **this page**, so the published matrix
   cannot fall behind the code.

When it fails, add or fix the table row — the failure message names the
constructor to use. Do not delete the assertion, and do not classify a route as
`consoleN/A` to silence check 3: that is the exact drift this file exists to
stop.

The behavioural counterpart is `server/internal/e2e/console_test.go`, which drives
the console workflows against a real SoftHSM-backed server. This test proves the
*surface* is complete; that one proves it works.

---

↩ Back to [Day-2 operations](README.md) · [operator web console](web-console.md) ·
[documentation map](../README.md)
