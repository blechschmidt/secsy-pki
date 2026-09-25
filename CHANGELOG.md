# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file is not decorative: `scripts/release-guard.sh` refuses to release a tag
whose version has no dated, non-empty section here, and the section for the
version being released becomes the body of the GitHub release. See
[docs/development/releasing.md](docs/development/releasing.md).

## [Unreleased]

### Added

**A documented way to run the container, and a Compose stack that proves it.**
The container page covered the image — tags, architectures, provenance, the build
— and stopped short of running it, so the path from `docker pull` to an issued
certificate was left to the reader. It now documents a first run end to end
(provision the token and CAs, serve with a self-issued listener certificate,
fetch the root out of band, issue over verified TLS), the two config paths and
why the CLIs do not inherit the server's, which volumes hold state and what a
relative `database.dsn` silently costs, the `SECSY_*` overrides that configure a
deployment without editing YAML, running the CLI tools via `exec` or a one-shot
container, `/healthz`/`/readyz`/`/metrics` — including a healthcheck for an image
that deliberately ships no `curl` — upgrades, and a troubleshooting list quoting
the errors the container actually prints.

[`deploy/compose/`](deploy/compose/) is the stack those examples were verified
against: a one-shot `bootstrap` that provisions the PKCS#11 token and CA
hierarchy, guarded against the real state so `up` is repeatable, and a `server`
gated on it with `service_completed_successfully`. An overlay swaps SQLite for
PostgreSQL without touching the config file.

**Importing existing keys, and adopting a CA that already exists.** An
organization migrating onto secsy-pki generally cannot re-key: its root
certificate is already in trust stores it does not control. `secsy-ca ca import`
takes such a CA's private key *and* its existing certificate and produces an
ordinary, issuing CA record — after which certificates it signs still verify
against the root the world already trusts. `secsy-ca import-key` places a bare
key into any provider role (`ca`/`tsa`/`signing`/`secret`, signing or RSA-KEK
usage), and `secsy-secret signing-key import` adopts an application signing key
whose public half is already embedded in shipped clients.

Key files are accepted in the formats operators actually hold: PKCS#8 (plain and
PBES2/PBKDF2-encrypted), PKCS#1, SEC1, legacy `DEK-Info` PEM, OpenSSH (including
bcrypt-encrypted), PKCS#12 — which supplies the certificate too, so a `.p12` is
a complete adoption — and bare DER. Passphrases come from a file or the
environment, never a flag.

Adoption is fail-closed at every step: the key must match the certificate
(checked *before* anything is written, so a mismatch strands nothing on the
token), the certificate must be a currently valid CA certificate, a self-signed
one must verify under its own key, the key must pass the weak/compromised-key
gate, and the provider must demonstrably sign a random challenge with it before
a CA record is persisted. Subordinates link automatically to a parent already in
the PKI, or record the supplied chain as external chain material. The new
`keyprovider.KeyImporter` capability is implemented by the software and PKCS#11
backends — a high-availability set imports onto every token, and reports which
tokens hold the key if one rejects it — while the cloud-KMS backends report
plainly that they cannot. On a token the imported key gets exactly the
least-privilege template a generated key gets (`CKA_SENSITIVE`,
`CKA_EXTRACTABLE=false`, single-purpose).

What it deliberately does not do is launder provenance: hardware attestation
still reports the key as imported, every copy made before the import is still a
copy, and the CLI says so. The commands are CLI-only by design — their input is
raw private key material. New `key.import`, `ca.import` and
`secret.signing_key_import` audit events; adoption passes the four-eyes
`ca.create` gate. See [docs/ca/import.md](docs/ca/import.md).

**A `-yubihsm` container variant.** Every published image tag now has a
counterpart with `-yubihsm` appended — `latest-yubihsm`, `1.2.3-yubihsm`,
`edge-yubihsm` — built from the same commit in the same job, for `linux/amd64`
and `linux/arm64`. It carries Yubico's PKCS#11 module, `libyubihsm` with both
the USB and HTTP transports, `yubihsm-shell`, `yubihsm-connector` and the host
udev rule, so a YubiHSM 2 needs nothing mounted in from the host. The module is
symlinked to `/usr/lib/pkcs11/yubihsm_pkcs11.so` so one `pkcs11.module_path` is
correct on both architectures. Both images are signed, carry a CycloneDX SBOM
attestation of their own and, on a release, SLSA Build L3 provenance.
`verify-published-image.sh --expect-yubihsm` requires the module to be present
and to load; without the flag it requires the default image *not* to carry it,
so the two tags cannot quietly converge. See
[docs/deployment/container.md](docs/deployment/container.md#the-yubihsm-variant).

**An append-only second copy of the YubiHSM device audit log, and a drain that
follows every operation.** On a force-audited YubiHSM the 62-entry log ring is
not a buffer that overflows into older entries — once full, the device refuses
every audited command, including signing. Collection was already driven by
operations, but only those passing through `internal/keyprovider`; key
attestation, device attestation, audit-head commitments and option changes reach
the hardware directly and left entries nothing drained. A process-wide observer
on the driver's single command path now covers those too, so a deployment that
mostly attests can no longer wedge its own HSM. An explicit
`audit_collect_per_operation: false` is ignored on a force-audited device rather
than allowed to take the CA offline minutes after startup.

Because acknowledging the ring is irreversible and the device keeps no copy,
whatever holds the records afterwards *is* the audit log — and the database is
not append-only: anyone with its credentials can delete the newest rows, which
no digest chain can detect, since a shorter chain is a valid chain. The new
`yubihsm.audit_log_file` writes a second copy as one JSON record per line,
carrying the device's own 32-byte record verbatim, meant for `chattr +a`, a WORM
mount, or a log shipper that moves it off the host. Sinks are written before the
database and long before the acknowledgement, and a sink failure aborts the
cycle. `secsy-ca hsm-audit verify-file` re-derives the chain from the raw
records with no database, device or configuration, and `-anchor` / `-serial` /
`-tail` bind the file to a known commissioning, a device and an independently
obtained collection tail. `hsm-audit status` makes the tail comparison
automatically. See
[docs/hsm/audit-log.md](docs/hsm/audit-log.md#where-the-collected-records-go).

**Everything the CLI can do, the operator console can now do too.** Thirteen
administrative capabilities existed only as `secsy-ca` / `secsy-secret`
subcommands with no REST counterpart at all, so no amount of front-end work could
have surfaced them. They now have one: preflight diagnostics (`GET /api/doctor`),
the disaster-recovery export and restore drill (`GET /api/backup`,
`POST /api/backup/verify-restore`), static-artifact publishing and its offline
integrity audit (`POST /api/publish`, `/api/publish/verify`), certificate-inventory
retention (`GET /api/inventory/retention`, `POST /api/inventory/retention/run`),
the compromised-key blocklist (`/api/blocked-keys`), the rest of the RFC 4998
evidence-record surface (`GET /api/ers`, `/api/ers/export`,
`POST /api/ers/generate`, `/api/ers/renew`), on-demand audit-chain anchoring
(`POST /api/events/anchor`), on-demand CT inclusion verification
(`POST /api/ct/verify-inclusion`), key and CA adoption (`POST /api/keys/import`,
`/api/ca/import`, `/api/secret/signing-keys/import`), TSA and code-signing
credential provisioning (`POST /api/tsa/key`, `/api/sign/signers`), device-wide
key attestation (`GET /api/hsm/attestation-audit`), the resource-role catalog
(`GET /api/grants/roles`), the four-eyes expiry sweep
(`POST /api/approvals/expire`), and JWT-SVID validation
(`POST /api/ca/{id}/svid/jwt/verify`). Each mirrors its command's semantics
rather than approximating them — the verification paths deliberately open no key
provider, so a chain, a published snapshot or a JWT-SVID can still be checked
while the HSM is down, and each answers 503 with a reason when the deployment did
not configure the feature instead of half-working.

The console grew an **Operations** view for the diagnostics/DR/publishing group
and gained controls for all of the above, plus three endpoints that existed but
which nothing had ever called: per-key HSM attestation, delegated-credential
minting, and group management. Adopting a CA, importing a key, provisioning a
signer, un-blocking a key, running retention and publishing join the WebAuthn
step-up set, since each changes what this PKI will sign with or destroys
evidence.

Three previous audits of this same invariant (Tasks 62, 190, 143) each drifted
within a few releases, so it is now enforced rather than asserted:
`internal/console/parity_test.go` parses the route table and both CLIs' command
dispatch and fails when a route or a command has no declared console view or
documented exemption — the same forcing function the authorization matrix uses.
It ships with the matrix it enforces,
[docs/operations/cli-console-parity.md](docs/operations/cli-console-parity.md),
which replaces the hand-maintained lists that had gone stale. Per-CA issuance
restriction sets remain the one feature reachable only from the legacy SPA and
the API.

### Changed

**The `-yubihsm` image builds Yubico's PKCS#11 module from upstream source
instead of installing Debian's package.** `bookworm-backports` carries
yubihsm-shell **2.6.0**; upstream is on **2.8.0**, and `bookworm` proper has no
`yubihsm` packages at all, so the one component the tag exists to provide was
also the only one pinned two minor releases behind — on a project whose YubiHSM
support tracks the current firmware and command set. A new `yubihsm-builder`
stage now compiles the whole upstream tree for both architectures:
`yubihsm_pkcs11.so`, `libyubihsm` with its USB and HTTP transports,
`libykhsmauth`, and the `yubihsm-shell`/`-wrap`/`-auth` tools.

Debian's security tracking of that package is replaced rather than dropped. The
release tarball is pinned by **SHA-256** and checked against Yubico's **detached
OpenPGP signature**, required to come from the fingerprint pinned in the
`Dockerfile` — the public key is vendored at
`deploy/yubihsm/yubico-release-signing-key.asc`, so editing that file does not
change which key is trusted. The digest alone says nothing about who produced the
bytes and the signature alone says nothing about which release was wanted, so
both are checked. The weekly image rebuild still refreshes the libcrypto,
libcurl and libusb it links against; a new upstream release is a
`YUBIHSM_SHELL_VERSION` bump.

The module is installed at `/usr/local/lib/pkcs11/yubihsm_pkcs11.so` and still
symlinked to `/usr/lib/pkcs11/yubihsm_pkcs11.so`, so **no configuration
changes** — and because that path no longer resolves into a multiarch directory,
the glob-and-count the old stage needed is gone. `yubihsm-connector`, a separate
upstream project whose version need not match, stays on backports. The image
records what it built at `/usr/share/secsy-pki/yubihsm-shell-version`, and
`verify-published-image.sh --expect-yubihsm` holds the loaded module's own
`C_GetInfo` version against it — which is what would catch a silent fall back to
the distribution package. Roughly 16 MB on top of the default image, as before.
See [docs/deployment/container.md](docs/deployment/container.md#built-from-upstream-source-not-from-debian).

### Fixed

**`server.tls.self_issue.ca_id` rejected the CA label it documented.** The
config comment and [the guide](docs/deployment/serving-cert.md) both described
`ca_id` as naming the issuing CA "by id or label", and every comparable
subsystem — ACME, SCEP, EST, BRSKI — resolves its configured reference through
`resolveCAID`. This one passed the raw string to an issuer that addresses CAs by
id alone, so a label arrived as an unknown id and the server fail-closed at
startup with `CA "issuing-ca" not found`. The label was also the only form a
deployment could write down in advance, the id being a UUID minted later by
`init-root`. References are now resolved id-first, then by label.

**The documentation gate computed anchors GitHub does not produce.**
`scripts/check-docs.sh` stripped underscores from headings as if they were
emphasis markers, so a heading naming a config key — `pin_source` — got an anchor
that exists neither on GitHub nor on the rendered site. The gate therefore
rejected the correct cross-page link and would have accepted a broken one.

**A `pin_source` example that could not parse.** The container page showed
`pin_source: "env:SECSY_USER_PIN"`; it is a block with a `type`, and a string
there aborts startup with `cannot unmarshal !!str into config.PinSourceConfig`.

**Four timestamps that reported the year 1 instead of being absent.**
`omitempty` does not omit a zero `time.Time` — it is a struct, not a scalar — so
`prune_cutoff` (retention status and run results), `backup_created_at` (the
restore drill) and `tsa_not_after` (per-timestamp evidence-record detail) shipped
`0001-01-01T00:00:00Z` where they meant "not applicable". A consumer reading
`prune_cutoff` as present-means-prune-mode misread every archive-mode response,
and a UI badging TSA expiry marked a timestamp with no embedded certificate as
long expired. All four are now `*time.Time` and genuinely absent, matching what
the OpenAPI spec always said.

**The console silently swallowed a four-eyes hold.** Eight guarded flows —
root-CA creation, intermediate issuance, the external-CA CSR, certificate
import, cross-signing, key rotation, retirement and bulk revocation — ignored the
`202 pending_approval` response and reported success with an `undefined` in it.
They now name the approval request and point at the Approvals view, as the CLI
does. A JWT-SVID or evidence record that fails verification answers 409 with a
reason and no `error` field, which the console's REST helper turned into a bare
`HTTP 409`; the reason is now surfaced.

**A stability pass over the code the test suite had never executed.** Coverage
had grown unevenly: the well-trodden issuance paths were thoroughly tested while
several protocol parsers, background workers and authorization primitives had no
test touching them at all. Those gaps were filled — the HSM-free suite went from
62.9% to 68.0% of statements, and thirteen packages now sit above 90%, among them
the CAA gate (39.5% → 97.5%), the resource-scoped RBAC grant model (46% → 100%),
the webhook worker (59.9% → 98%), the mail transports (31.6% → 99.6%) and the
RFC 3161 token decoder (0% → 100%) — and the new tests found eleven genuine
defects, all fixed. The ones worth knowing about:

*Two remotely reachable crashes.* The hand-rolled IMAP client used to read ACME
`email-reply-00` challenge replies allocated a buffer straight from the byte count
a server announces in a `{n}` literal. A single reply line announcing a literal of
2^50 bytes panicked with `makeslice: len out of range`, and that panic unwound
through the challenge poller goroutine, which has no recover — so a hostile or
merely broken mail server could **terminate the CA process**. A merely enormous
count instead committed the process to reading that many bytes into memory. The
count is now bounded before it reaches an allocation. Separately, `POST
/api/ers/verify` panicked on any Evidence Record submitted without an `objects`
array — a combination the API's own documentation describes as valid — because the
reduction check indexed element zero of the caller's (empty) object list. Any
read-capable caller could crash the handler.

*A hang at server start-up.* `cas.parent_id` is a self-referencing foreign key, so
a CA row can point at itself or two rows at each other. The TSA's chain builder
had no visited set and looped forever, appending a certificate per iteration —
inside `LoadAuthorityConfig`, which runs at server start and in four `secsy-ca`
commands. Two sibling code paths already guarded against exactly this.

*A data race in an authorization gate.* An operator session is handed out by
pointer and read by every request, including the WebAuthn step-up check on the
authorization hot path, while a completed ceremony wrote the step-up deadline with
no synchronization. A `time.Time` is a multi-word struct, so the gate could read a
torn value and reach an unspecified verdict. The deadline is now behind a mutex.

*Three fail-open gates that fail closed now.* An RFC 8555 external-account binding
whose protected header omitted `url` — the only field binding a MAC to one
endpoint — was accepted as "bound to nothing", making a captured binding replayable
at any endpoint sharing the HMAC key; `url` is mandatory per §7.3.4 and is now
required. A zero-value CAA policy evaluated as non-enforcing despite documenting
the opposite, leaving a never-configured gate enabled but toothless. And a TSA
`policy_oid` with a negative arc passed start-up validation and then made the
authority emit tokens carrying a zero-length OBJECT IDENTIFIER that no verifier can
decode, while an out-of-range arc turned every `/tsa` request into a 500.

*Webhook delivery could spin, silently drop events, or lose them to a redirect.*
The delivery loop re-ran immediately whenever a sweep reported a full batch, but
the count was rows *listed* rather than rows whose state actually advanced — so a
batch of rows stuck behind a store error made the worker re-POST to the customer
endpoint continuously with no backoff. A redirecting endpoint was followed, and
since `net/http` rewrites a 302 into a bodyless GET, the receiver never saw the
signed payload while the final 2xx marked the delivery succeeded; a 307 instead
replayed the body *and* its signature header to the redirect target. Redirects are
now surfaced as the ordinary non-2xx failures they are. And a transient failure
reading the fan-out cursor at start-up — which happens on every leadership
handover — was treated as "never initialized" and re-seeded the cursor to the
current log head, permanently discarding every event since the last sweep; the
sweep is now skipped and retried instead.

*Three smaller ones.* The IMAP client put the mailbox password into the error it
returned when a server echoed the rejected `LOGIN` command, and the poll loop logs
those errors verbatim; UIDs were interpolated into `UID STORE` unvalidated, so a
non-numeric UID could inject a second command into the authenticated session.
`secsy-secret exec` emitted an `EnvTemplate` name verbatim as `NAME=value`, so a
name containing `=` spliced an extra assignment into the child's environment and
could shadow its `PATH`. An NTS handshake was abandoned when a peer's final read
returned its data together with `io.EOF` — permitted by `io.Reader` — which would
have made the TSA refuse to sign for no reason. Evidence-record verification also
reported objects as "covered" by a chain that had failed structurally.

Also fixed: a DNS TTL of 0 was read as "unset" rather than as the minimum when
computing a CAA answer's cache lifetime; an IMAP/NTS host given as a bracketed
IPv6 literal without a port was re-bracketed into something undialable; an
oversized NTS cookie silently produced a corrupt packet instead of an error;
`SortGrants` was not a total order, so a grant list containing one rule at two
scopes printed in a different order run to run; a time-stamp token's optional
`statusString` was decoded as `ANY` and swallowed the `failInfo` of every
conforming third-party TSA that omits it; and `crypto/sha1|sha256|sha512` were
blank-imported in the wrong package, so a caller importing the token decoder on
its own could reach a `Hash.New()` on an unlinked hash.

**Importing RSA keys onto a YubiHSM now fails on the host, with a reason.** The
import path worked against SoftHSM and against a YubiHSM for the ordinary cases
— RSA-2048, 3072 and 4096 all land on the device and sign, in about a second
each — but the device is far stricter than a software token and terse about it:
it implements exactly those three modulus sizes and the single public exponent
65537, and refuses everything else with one undifferentiated
`CKR_ATTRIBUTE_VALUE_INVALID` covering "wrong size", "wrong exponent" and
"unsupported algorithm" alike, arriving after a round trip over USB. An
operator migrating a legacy CA met that code holding a key file that looked
perfectly valid.

Both constraints are now checked before the device is touched. RSA sizes are
matched exactly instead of being rounded up to the next name — a 2560-bit key
was previously accepted and recorded as `rsa-3072`, a mislabel that would have
propagated into the CA record and every inventory and compliance report derived
from it, while the token rejected the key anyway. And the weak-key gate that
subject public keys have always passed before being certified (ROCA, exponent
policy, modulus sanity) now runs on imported key material too: it guarded `ca
import` from the start but not `import-key` or the secret layer's signing-key
import, so the one command whose purpose is to give a key a *better* home could
write a known-broken one onto a token.

A new hardware tier (`internal/yubihsmtest/import_test.go`) holds this to the
device: the three sizes round-tripped through PKCS#11 and signed with both
PKCS#1 v1.5 and PSS, a decrypt-only RSA KEK unwrapping, a requested `CKA_ID`
honoured, the imported key attesting as imported *and* non-exportable, a legacy
RSA CA issuing a leaf that verifies under the root published before the
migration, and each rejection arriving as a sentence. See
[docs/ca/import.md](docs/ca/import.md#importing-rsa-onto-a-yubihsm).

## [1.0.0] - 2026-08-19

The first tagged release of the enterprise edition: an HSM-backed X.509 and SSH
certificate authority with envelope-based secret encryption, governed by RBAC
and recorded in a tamper-evident audit log.

### Added

**Keys and HSMs.** A backend-agnostic key provider (`internal/keyprovider`)
routes every key operation to a PKCS#11 HSM, a cloud KMS (AWS KMS, Azure Key
Vault, Google Cloud KMS), HashiCorp Vault Transit, or a software keystore for
development. Keys are generated on the device and never exported. Multi-token
high availability with health-tracked failover, a bounded session pool, RFC 7512
PKCS#11 URI addressing, external PIN sourcing (file, environment, Vault, AWS,
Azure, GCP), and a native YubiHSM driver speaking SCP03 over usbfs.

**Certificate authority.** Root and intermediate CA bootstrap, end-entity
issue/renew/revoke from CSRs against named profiles, reversible suspend/hold,
bulk issuance and bulk revocation, intermediate key rotation with a dual-chain
overlap window, cross-signing and bridge CAs, externally-signed subordinate CAs,
PKCS#12 export, and chain/path validation. Revocation through signed CRLs
— including delta CRLs and sharding — and an OCSP responder with nonces, a
delegated responder certificate, pre-signing and static artifact publishing.

**Enrollment protocols.** ACME (RFC 8555) with http-01, dns-01, tls-alpn-01,
device-attest-01 and email-reply-00 challenges, plus ARI, Profiles, alternate
chains, pre-authorization, STAR short-term certificates, EAB and multi-perspective
validation. SCEP, EST (including `/csrattrs`), CMP (RFC 9483), BRSKI (RFC 8995)
zero-touch onboarding, Microsoft Windows autoenrollment (MS-XCEP/MS-WSTEP), and a
host auto-enrollment agent.

**Issuance gates.** A fail-closed pre-issuance stack: CA/Browser Forum Baseline
Requirements linting (hand-rolled, with an optional zlint backend), CAA checking
per RFC 8659 and 8657, RFC 5280 name constraints and certificate policies,
weak-key and compromised-key blocklists, hardware key attestation, Certificate
Transparency SCT embedding with inclusion-proof monitoring and log-operator
diversity, policy-as-code expressions, and per-profile manual approval.

**Certificate types.** TLS server and client, S/MIME, smartcard logon and PKINIT,
eIDAS qualified certificates with QCStatements, SPIFFE X.509 and JWT SVIDs, TLS
delegated credentials, OCSP Must-Staple, and post-quantum ML-DSA and hybrid
certificates.

**SSH.** An HSM-backed OpenSSH user and host certificate authority with KRL
revocation, and DANE TLSA / SSHFP pinning-record generation.

**Signing and timestamping.** Detached CMS artifact and code signing with CAdES
B/T/LT levels, an RFC 3161 timestamping authority, a trusted external time source
(NTS/Roughtime) with fail-closed drift detection, and RFC 4998 evidence records.

**Secrets.** HSM-backed envelope encryption for passwords and small secrets, with
KEK rotation and DEK re-wrap, M-of-N escrow and recovery, FF1 format-preserving
tokenization, asymmetric signing, a stateless crypto service (data keys, HMAC,
CSPRNG), and optional post-quantum hybrid KEK wrapping.

**Security and governance.** Role-based access control, operator authentication
through OIDC SSO, LDAP/Active Directory, mTLS and WebAuthn step-up, scoped API
tokens and service accounts, four-eyes maker-checker approvals, multi-tenant
isolation with per-tenant quotas, tiered rate limiting, and a FIPS 140-3 build
mode.

**Audit.** An append-only hash-chained event log with RFC 3161 anchoring, SIEM
export (syslog/CEF/webhook), a live SSE and gRPC event stream, and a remotely
verifiable HSM audit log proving a named public key signed nothing beyond what
was published.

**Interfaces.** A REST API with an OpenAPI 3.1 specification and generated Go
client, a gRPC service with reflection and server streaming, the `secsy-ca`,
`secsy-secret`, `secsy-ssh`, `secsy-verify` and `secsy-agent` command-line tools,
and an operator web console embedded in the server binary.

**Operations.** Prometheus metrics with Grafana dashboards, alert rules and
multi-window SLO burn-rate alerts; OpenTelemetry tracing; expiry monitoring with
automated renewal; a synthetic issuance canary; external certificate discovery;
scheduled encrypted backups with automated restore verification; leader-elected
background jobs for multi-replica deployments; a self-issued serving-TLS
certificate; Unix-domain-socket listeners; and the `secsy-ca doctor` preflight
diagnostics.

**Deployment.** A multi-stage container image for `linux/amd64` and
`linux/arm64`, a Helm chart, a cert-manager external issuer, and SQLite and
PostgreSQL persistence backends.

**Supply chain.** CycloneDX SBOMs for the Go modules and the image, cosign
signatures and SBOM attestations, SLSA Build L3 provenance, a gating
`govulncheck` scan, and reproducible release archives built from the same
Dockerfile as the image.

[Unreleased]: https://github.com/blechschmidt/secsy-pki/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/blechschmidt/secsy-pki/releases/tag/v1.0.0
