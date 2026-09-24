package console

// Task 198: CLI ↔ console parity, made a forcing function.
//
// The embedded operator console at /console/ is supposed to expose everything
// the `secsy-ca` / `secsy-secret` CLIs can do. Three separate tasks (62, 190 and
// 198) established that by HAND-AUDITING the whole surface, and between each
// audit it drifted again: routes were added with no console control, console
// controls were added and the docs never caught up, and the parity table in
// docs/operations/web-console.md accumulated claims that stopped being true
// ("doctor is CLI-only" was in that list while /api/doctor already had an
// Operations-page panel). A fourth hand-audit would rot the same way.
//
// So this file is the audit, expressed as code. It parses the three sources of
// truth — the route registrations in handlers.go, the console bundle in static/,
// and the command dispatch in cmd/secsy-{ca,secret}/main.go — and fails unless
// every one of them is accounted for in the two tables below. It is the
// console-facing sibling of internal/handlers/authz_matrix_test.go, which does
// the same thing for authorization, and it borrows that file's go/ast approach.
// It parses source only: no HSM, no database, no network, so it runs in the
// HSM-free CI job with no build tag.
//
// Five checks:
//
//  1. TestConsoleParityCoversRegisteredRoutes — every /api/... route registered
//     in handlers.go has exactly one parityRoutes() entry, and no entry is
//     stale. This is the linchpin: a new route breaks the build until its author
//     says which console view surfaces it, or why none does.
//  2. TestConsoleParityViewsExist — every view named in either table really is a
//     view: a data-view="X" nav button AND an id="view-X" section in index.html.
//     Catches a typo'd or renamed view name.
//  3. TestConsoleParityRoutesAreWired — a route mapped to a view is actually
//     referenced by static/app.js. Catches "declared in the table but never
//     wired" (see the heuristic's documented limits at jsProbes).
//  4. TestConsoleParityCoversCLICommands — every top-level CLI command of both
//     binaries has exactly one parityCommands() entry, and no entry is stale.
//  5. TestConsoleParityMatrixIsDocumented — every command in parityCommands()
//     is named on docs/operations/cli-console-parity.md, so the published
//     parity matrix cannot silently fall behind this table.
//
// ---------------------------------------------------------------------------
// WHEN THIS TEST FAILS, DO THIS
//
//   * "route ... has NO console-parity entry": you added a route. Add one
//     parityRoutes() row. If a console control drives it, use
//     onView(route, "<data-view>") — and make sure app.js really calls it.
//     If nothing in the console should, use the consoleN/A constructor that
//     states WHY: naPublic (a relying party consumes it, not an operator),
//     naPlumbing (machine/bootstrap endpoint, no operator control),
//     naLegacy (only the legacy disk-based SPA in server/web/static/ uses it),
//     naIndirect (the capability IS on a console view, reached through a
//     different endpoint). Do NOT reach for a consoleN/A row to silence check
//     3 — that is exactly the drift this file exists to stop.
//   * "entry ... matches no registered route": you removed or renamed a route.
//     Delete or fix the row.
//   * "mapped to view ... but app.js never references it": either wire the
//     control, or — if the console reaches the capability another way — say so
//     with naIndirect, or supply an onViewRef override when the console builds
//     the path with a template literal that hides the distinguishing segment.
//   * "command ... has NO console-parity entry": you added a CLI command. Add a
//     parityCommands() row: cmdOn(bin, cmd, "<data-view>") or
//     cliOnly(bin, cmd, "<why it cannot/should not be a browser control>").
//   * "command ... is not named in docs/operations/cli-console-parity.md": add
//     the row to that page's table. The page IS the published matrix; keep it
//     and this file saying the same thing.
// ---------------------------------------------------------------------------

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// parityDoc is the published parity matrix this file keeps honest.
const parityDoc = "../../../docs/operations/cli-console-parity.md"

// --- route entries ---------------------------------------------------------

// naClass names why a route has no console control. Every consoleN/A row must
// pick one, so the exemptions stay a short, reviewable list of kinds rather
// than a free-text dumping ground.
type naClass int

const (
	naNone      naClass = iota // not exempt: a console view surfaces it
	naPublicAPI                // public protocol / relying-party endpoint
	naMachine                  // machine or bootstrap plumbing
	naLegacySPA                // only the legacy disk-based SPA (server/web/static/) uses it
	naViaOther                 // the capability is on a console view, via a different route
)

// routeEntry is one REST route's console-parity declaration. Read the table
// below as the parity matrix: route -> the console view that surfaces it, or a
// classified reason why nothing does.
type routeEntry struct {
	route string  // "METHOD /pattern", exactly as registered in handlers.go
	view  string  // console data-view that surfaces it ("" for consoleN/A rows except naViaOther)
	na    naClass // naNone, or why there is no console control
	why   string  // required on every consoleN/A row
	ref   string  // optional literal app.js must contain, overriding jsProbes
}

// onView: a control on the named console view drives this route.
func onView(route, view string) routeEntry {
	return routeEntry{route: route, view: view}
}

// onViewRef: same, but the console builds the path with a template literal that
// interpolates the segment which DISTINGUISHES this route from its siblings
// (`/api/secret/transform/${direction}` covers both encode and decode), so the
// derived probe cannot see it. The override is the literal app.js must contain.
func onViewRef(route, view, ref string) routeEntry {
	return routeEntry{route: route, view: view, ref: ref}
}

// naPublic: consoleN/A — a relying party or protocol client consumes this, not
// an operator at a browser.
func naPublic(route, why string) routeEntry {
	return routeEntry{route: route, na: naPublicAPI, why: why}
}

// naPlumbing: consoleN/A — machine/bootstrap endpoint with no operator control
// of its own.
func naPlumbing(route, why string) routeEntry {
	return routeEntry{route: route, na: naMachine, why: why}
}

// naLegacy: consoleN/A — served by the LEGACY disk-based SPA in
// server/web/static/, which predates the embedded console and was never ported.
// These are the honest debt rows: each one is a capability an operator can only
// reach from the old UI or the CLI.
func naLegacy(route, why string) routeEntry {
	return routeEntry{route: route, na: naLegacySPA, why: why}
}

// naIndirect: consoleN/A for THIS route, but the capability is on the named
// view — the console reaches it through a different endpoint. Not a parity gap
// in the operator's sense; a redundant endpoint in the API's.
func naIndirect(route, view, why string) routeEntry {
	return routeEntry{route: route, view: view, na: naViaOther, why: why}
}

// parityRoutes is the declared route -> console-view matrix. Every /api/...
// route in RegisterRoutes must appear here exactly once (enforced by
// TestConsoleParityCoversRegisteredRoutes). Ordered as in handlers.go.
func parityRoutes() []routeEntry {
	return []routeEntry{
		// Health / login bootstrap. app.js does call /api/auth/config and
		// /api/me, but not from any view — they run before the first view is
		// shown, which is why they are plumbing rather than mapped.
		naPlumbing("GET /api/health", "liveness probe for orchestrators; the console's health signals are /healthz, /readyz and the Compliance page"),
		naPlumbing("GET /api/auth/config", "login bootstrap: tells the SPA which auth modes exist, before any view exists"),

		// CA inventory + creation.
		onView("GET /api/keys", "cas"),
		onView("POST /api/keys", "cas"),

		// Multi-tenant administration.
		onView("GET /api/tenants", "tenants"),
		onView("POST /api/tenants", "tenants"),
		onView("GET /api/tenants/{id}", "tenants"),
		onView("PUT /api/tenants/{id}", "tenants"),
		onView("PUT /api/tenants/{id}/status", "tenants"),
		onView("GET /api/tenants/{id}/usage", "tenants"),
		onView("DELETE /api/tenants/{id}", "tenants"),

		// Native scoped API tokens.
		onView("GET /api/tokens", "tokens"),
		onView("POST /api/tokens", "tokens"),
		onView("DELETE /api/tokens/{id}", "tokens"),

		// Outbound webhook subscriptions.
		onView("GET /api/webhooks", "webhooks"),
		onView("POST /api/webhooks", "webhooks"),
		onView("GET /api/webhooks/{id}", "webhooks"),
		onView("DELETE /api/webhooks/{id}", "webhooks"),
		// One handler drives both buttons: `/api/webhooks/${id}/${act}`.
		onViewRef("POST /api/webhooks/{id}/enable", "webhooks", "/api/webhooks/${encodeURIComponent(w.id)}/${act}"),
		onViewRef("POST /api/webhooks/{id}/disable", "webhooks", "/api/webhooks/${encodeURIComponent(w.id)}/${act}"),
		onView("POST /api/webhooks/{id}/test", "webhooks"),
		onView("GET /api/webhooks/{id}/deliveries", "webhooks"),

		// X.509 CA setup + the externally-signed subordinate flow.
		onView("POST /api/ca/init-root", "cas"),
		onView("POST /api/ca/{id}/issue-intermediate", "cas"),
		onView("POST /api/ca/csr", "cas"),
		onView("GET /api/ca/{id}/csr", "cas"),
		onView("POST /api/ca/{id}/import-cert", "cas"),

		// Key/CA adoption (Task 198).
		onView("POST /api/keys/import", "cas"),
		onView("POST /api/ca/import", "cas"),

		// Cross-signing; the alternate chains it produces are served on the
		// Trust Bundle view, where a relying party's operator looks for them.
		onView("POST /api/ca/{id}/cross-signs", "cas"),
		onView("GET /api/ca/{id}/cross-signs", "cas"),
		onView("GET /api/ca/{id}/chains", "bundle"),
		onView("GET /api/ca/{id}/cross-signs/{csid}/chain", "bundle"),

		// Intermediate rotation lifecycle.
		onView("GET /api/rotations", "cas"),
		naIndirect("GET /api/ca/{id}/rotation", "cas",
			"the Authorities view loads the whole lineage from GET /api/rotations once and indexes it by CA "+
				"(rotationByCA in app.js), so it never issues the single-CA read; rotate/retire and the status "+
				"badges are all there"),
		onView("POST /api/ca/{id}/rotate", "cas"),
		onView("POST /api/ca/{id}/retire", "cas"),

		// Issuance / renewal / revocation / suspension.
		onView("GET /api/profiles", "issue"),
		onView("POST /api/ca/{id}/issue", "issue"),
		onView("POST /api/ca/{id}/pkcs12", "p12"),
		onView("POST /api/ca/{id}/delegated-credential", "certs"),
		onView("POST /api/ca/{id}/renew", "certs"),
		onView("POST /api/ca/{id}/revoke", "certs"),
		onView("POST /api/ca/{id}/revocations:bulk", "certs"),
		onView("POST /api/ca/{id}/certificates:bulk", "issue"),
		onView("POST /api/ca/{id}/certificates:preview", "issue"),
		onView("GET /api/ca/{id}/certificates", "certs"),
		onView("GET /api/ca/{id}/revoked", "certs"),
		onView("POST /api/ca/{id}/certificates/{action}", "certs"),

		// SPIFFE X.509-SVID + JWT-SVID.
		onView("POST /api/ca/{id}/svid", "bundle"),
		onView("POST /api/ca/{id}/svid/jwt", "bundle"),
		onView("POST /api/ca/{id}/svid/jwt/verify", "bundle"),
		onView("GET /api/ca/{id}/svid/bundle", "bundle"),

		// Expiry monitoring + reporting.
		onView("GET /api/monitor/expiring", "monitor"),
		onView("POST /api/monitor/scan", "monitor"),
		onView("GET /api/report/inventory", "inventory"),
		onView("GET /api/report/compliance", "compliance"),

		// External certificate discovery.
		onView("GET /api/discovery", "discovery"),
		onView("POST /api/discovery/scan", "discovery"),

		// CT inclusion state.
		onView("GET /api/ct/inclusion", "ct"),
		onView("POST /api/ct/verify-inclusion", "ct"),

		// SSH certificate authority. The SSHFP generator lives with the TLSA one
		// on the DNS Records view rather than on the SSH CA view.
		onView("POST /api/ssh/cas", "ssh"),
		onView("GET /api/ssh/cas", "ssh"),
		onView("GET /api/ssh/profiles", "ssh"),
		onView("POST /api/ssh/cas/{id}/sign", "ssh"),
		onView("POST /api/ssh/cas/{id}/revoke", "ssh"),
		onView("GET /api/ssh/cas/{id}/certificates", "ssh"),
		onView("GET /api/ssh/cas/{id}/revocations", "ssh"),
		onView("GET /api/ssh/cas/{id}/public", "ssh"),
		onView("GET /api/ssh/cas/{id}/krl", "ssh"),
		onView("POST /api/ssh/cas/{id}/dns-records/sshfp", "dns"),

		// Artifact code-signing + credential provisioning (Task 198).
		onView("POST /api/sign", "signing"),
		onView("POST /api/sign/verify", "signing"),
		onView("GET /api/sign/signers", "signing"),
		onView("POST /api/sign/signers", "signing"),
		onView("POST /api/tsa/key", "signing"),

		// Revocation material. The CRLs are public artifacts, but the console
		// downloads every form of them from the Certificates view, so they are
		// mapped rather than exempt.
		onView("GET /api/ca/{id}/crl", "certs"),
		onView("GET /api/ca/{id}/crl/delta", "certs"),
		onView("GET /api/ca/{id}/crl/status", "certs"),
		onView("GET /api/ca/{id}/crl/partition/{shard}", "certs"),
		onView("GET /api/ca/{id}/crl/partition/{shard}/delta", "certs"),
		onView("GET /api/ca/{id}/dns-records/tlsa", "dns"),
		onView("GET /api/ca/{id}/chain", "bundle"),

		// OCSP. The only genuinely console-less public protocol surface here:
		// its callers are TLS clients and stapling daemons speaking RFC 6960
		// DER, and an operator checking revocation uses the Validate view (which
		// runs the OCSP check server-side) or the Certificates view.
		naPublic("POST /api/ca/{id}/ocsp", "RFC 6960 responder consumed by relying parties; operators check revocation on the Validate view"),
		naPublic("GET /api/ca/{id}/ocsp/{req}", "same responder, GET form (base64 request in the path)"),

		// Per-CA read + delete.
		onView("GET /api/keys/{id}", "cas"),
		onView("DELETE /api/keys/{id}", "cas"),
		naIndirect("GET /api/keys/{id}/children", "cas",
			"the Authorities view renders the hierarchy from the parent_id on each row of GET /api/keys, so it "+
				"never asks for one CA's children; only pkg/client and the OpenAPI spec reference this route"),

		// Legacy surface, still registered, only reachable from the OLD
		// disk-based SPA in server/web/static/. Each of these is real debt: the
		// embedded console has no equivalent control.
		naLegacy("GET /api/keys/{id}/public-key", "public-key export exists only in the legacy SPA; the console exports public keys per-purpose (SVID bundle, signing-key SPKI)"),
		naLegacy("POST /api/keys/{id}/sign", "legacy raw-signing endpoint, superseded by /api/sign and /api/secret/signing-keys/{name}/sign"),
		naLegacy("POST /api/keys/{id}/sign-x509", "legacy raw X.509 signing endpoint, superseded by /api/ca/{id}/issue"),
		naPlumbing("POST /api/parse-csr", "stateless CSR-decoding helper; the console's Issue view gets the parsed leaf back from certificates:preview instead (the legacy SPA still calls it)"),
		naLegacy("GET /api/keys/{id}/my-restrictions", "self-service restriction lookup, part of the legacy SPA's restriction-set UI"),

		// Groups (ported into the console by Task 198).
		onView("GET /api/groups", "access"),
		onView("POST /api/groups", "access"),
		onView("DELETE /api/groups/{id}", "access"),
		onView("GET /api/groups/{id}/members", "access"),
		onView("POST /api/groups/{id}/members", "access"),
		onView("DELETE /api/groups/{id}/members/{sub}", "access"),

		// Per-CA permission grants: the pre-Task-191 model. The console
		// administers access through the resource-grant routes below instead.
		naLegacy("GET /api/keys/{id}/permissions", "pre-Task-191 per-CA permission model; the console's Access view uses /api/grants"),
		naLegacy("POST /api/keys/{id}/permissions", "pre-Task-191 per-CA permission model; the console's Access view uses /api/grants"),
		naLegacy("DELETE /api/keys/{id}/permissions", "pre-Task-191 per-CA permission model; the console's Access view uses /api/grants"),

		// Resource-scoped grants (Task 191).
		onView("GET /api/grants", "access"),
		onView("POST /api/grants", "access"),
		onView("DELETE /api/grants", "access"),
		onView("GET /api/grants/effective", "access"),
		onView("GET /api/grants/roles", "access"),

		// Restriction sets: an entire feature the embedded console never got.
		naLegacy("GET /api/restriction-sets", "restriction-set administration exists only in the legacy SPA and the CLI"),
		naLegacy("POST /api/restriction-sets", "restriction-set administration exists only in the legacy SPA and the CLI"),
		naLegacy("GET /api/keys/{id}/restriction-sets", "restriction-set administration exists only in the legacy SPA and the CLI"),
		naLegacy("POST /api/keys/{id}/restriction-sets", "restriction-set administration exists only in the legacy SPA and the CLI"),
		naLegacy("PUT /api/restriction-sets/{id}", "restriction-set administration exists only in the legacy SPA and the CLI"),
		naLegacy("DELETE /api/restriction-sets/{id}", "restriction-set administration exists only in the legacy SPA and the CLI"),
		naLegacy("PUT /api/keys/{id}/default-restriction-set", "restriction-set administration exists only in the legacy SPA and the CLI"),

		// The two pre-event-log audit tables. The console's Audit view shows the
		// hash-chained event log (/api/events) instead, which supersedes both but
		// does not contain their rows.
		naLegacy("GET /api/audit-log", "pre-event-log audit table, browsable only in the legacy SPA; the console's Audit view reads /api/events"),
		naLegacy("GET /api/access-log", "HTTP access log, browsable only in the legacy SPA"),

		// Tamper-evident event log.
		onView("GET /api/events", "audit"),
		onView("GET /api/events/verify", "audit"),
		onView("GET /api/events/export", "audit"),
		onView("GET /api/events/stream", "audit"),
		onView("POST /api/events/anchor", "audit"),

		// Four-eyes approvals.
		onView("GET /api/approvals", "approvals"),
		onView("GET /api/approvals/{id}", "approvals"),
		onView("POST /api/approvals/{id}/approve", "approvals"),
		onView("POST /api/approvals/{id}/reject", "approvals"),
		onView("GET /api/approvals/{id}/certificate", "approvals"),
		onView("POST /api/approvals/expire", "approvals"),

		// Lint, key inventory, blocklist, retention.
		onView("POST /api/lint", "compliance"),
		onView("GET /api/inventory/keys", "cas"),
		onView("GET /api/blocked-keys", "compliance"),
		onView("POST /api/blocked-keys", "compliance"),
		onView("DELETE /api/blocked-keys/{fingerprint}", "compliance"),
		onView("GET /api/inventory/retention", "inventory"),
		onView("POST /api/inventory/retention/run", "inventory"),

		// Operator operations (Task 198): diagnostics, DR, publishing.
		onView("GET /api/doctor", "ops"),
		onView("GET /api/backup", "ops"),
		onView("POST /api/backup/verify-restore", "ops"),
		onView("POST /api/publish", "ops"),
		onView("POST /api/publish/verify", "ops"),

		// Chain validation + Evidence Records. The whole ERS panel (list,
		// generate, renew, export, verify) sits on the Compliance view.
		onView("POST /api/validate", "validate"),
		onView("POST /api/ers/verify", "compliance"),
		onView("GET /api/ers", "compliance"),
		onView("GET /api/ers/export", "compliance"),
		onView("POST /api/ers/generate", "compliance"),
		onView("POST /api/ers/renew", "compliance"),

		// ACME operator visibility.
		onView("GET /api/acme/accounts", "acme"),
		onView("GET /api/acme/orders", "acme"),

		// Secret envelope layer, stateless crypto service, named signing keys,
		// tokenization, the stored-secret registry and the KEK lifecycle — all
		// panels on the one Secrets view.
		onView("GET /api/secret/info", "secrets"),
		onView("POST /api/secret/encrypt", "secrets"),
		onView("POST /api/secret/decrypt", "secrets"),
		onView("GET /api/secret/kek/status", "secrets"),
		onView("POST /api/secret/kek/rotate", "secrets"),
		onView("POST /api/secret/kek/retire", "secrets"),
		onView("POST /api/secret/rewrap", "secrets"),
		onView("POST /api/secret/datakey", "secrets"),
		onView("POST /api/secret/hmac", "secrets"),
		onView("POST /api/secret/hmac/verify", "secrets"),
		onView("POST /api/secret/random", "secrets"),
		onView("POST /api/secret/signing-keys", "secrets"),
		onView("POST /api/secret/signing-keys/import", "secrets"),
		onView("GET /api/secret/signing-keys", "secrets"),
		onView("GET /api/secret/signing-keys/{name}", "secrets"),
		onView("POST /api/secret/signing-keys/{name}/sign", "secrets"),
		onView("POST /api/secret/signing-keys/{name}/verify", "secrets"),
		onView("POST /api/secret/verify", "secrets"),
		// One handler drives both directions: `/api/secret/transform/${direction}`.
		onViewRef("POST /api/secret/transform/encode", "secrets", "/api/secret/transform/${direction}"),
		onViewRef("POST /api/secret/transform/decode", "secrets", "/api/secret/transform/${direction}"),
		onView("POST /api/secret/store", "secrets"),
		onView("GET /api/secret/store", "secrets"),
		onView("GET /api/secret/store/{id}", "secrets"),
		onView("DELETE /api/secret/store/{id}", "secrets"),
		onView("PUT /api/secret/store/{id}", "secrets"),
		onView("GET /api/secret/store/{id}/versions", "secrets"),
		onView("GET /api/secret/store/{id}/versions/{version}", "secrets"),
		onView("POST /api/secret/store/{id}/rollback", "secrets"),
		onView("GET /api/secret/lifecycle", "secrets"),

		// HSM administration. Key attestation by CA lives on the HSM view too,
		// next to attestation by label, because it answers the same question.
		onView("GET /api/hsm/info", "hsm"),
		onView("GET /api/hsm/attestation", "hsm"),
		onView("GET /api/hsm/audit-log", "hsm"),
		onView("POST /api/hsm/provision-audit", "hsm"),
		naLegacy("POST /api/hsm/factory-reset", "irreversible device wipe; offered only by the legacy SPA and deliberately not by the embedded console"),
		onView("GET /api/hsm/combined-audit-log", "hsm"),
		onView("GET /api/hsm/signed-audit-log", "hsm"),
		onView("GET /api/hsm/audit-bundle", "hsm"),
		onView("GET /api/hsm/keys/{label}/attestation", "hsm"),
		onView("GET /api/ca/{id}/key-attestation", "hsm"),
		onView("GET /api/hsm/attestation-audit", "hsm"),
		onView("POST /api/hsm/attestation:verify", "hsm"),
		onView("POST /api/hsm/attest-device", "hsm"),
		onView("POST /api/hsm/device-attestation:verify", "hsm"),
		onView("GET /api/hsm/audit-status", "hsm"),

		// API documentation + self identity. (The non-/api/ spec routes —
		// /openapi.json, /openapi.yaml, /docs — are outside this table's scope.)
		naPlumbing("GET /api/docs", "Swagger UI for the REST API, a sibling of the console rather than a part of it"),
		naPlumbing("GET /api/docs/openapi.yaml", "OpenAPI document served for tooling"),
		naPlumbing("GET /api/docs/openapi.json", "OpenAPI document served for tooling"),
		naPlumbing("GET /api/me", "identity bootstrap: app.js reads it at sign-in to decide what to show, before any view exists"),
	}
}

// --- CLI command entries ---------------------------------------------------

// cmdEntry is one top-level CLI command's console-parity declaration.
type cmdEntry struct {
	bin, cmd string // "secsy-ca", "doctor"
	view     string // console data-view offering the same capability ("" when CLI-only)
	why      string // required when CLI-only
}

func (c cmdEntry) key() string { return c.bin + " " + c.cmd }

// cmdOn: the named console view offers this command's capability.
func cmdOn(bin, cmd, view string) cmdEntry {
	return cmdEntry{bin: bin, cmd: cmd, view: view}
}

// cliOnly: deliberately has no console equivalent, for the stated reason.
func cliOnly(bin, cmd, why string) cmdEntry {
	return cmdEntry{bin: bin, cmd: cmd, why: why}
}

// parityCommands is the declared CLI command -> console-view matrix. Every
// top-level command dispatched by cmd/secsy-ca/main.go and
// cmd/secsy-secret/main.go must appear here exactly once (enforced by
// TestConsoleParityCoversCLICommands).
//
// A row maps the COMMAND, not every flag and sub-command of it: `secsy-ca
// hsm-audit` is on the HSM view even though `hsm-audit verify` is deliberately
// offline-only, and the reasons below say so where it matters. Sub-command-level
// detail belongs on the documentation page.
func parityCommands() []cmdEntry {
	const ca = "secsy-ca"
	const sec = "secsy-secret"
	return []cmdEntry{
		// --- secsy-ca: CA lifecycle -------------------------------------
		cmdOn(ca, "init-root", "cas"),
		cmdOn(ca, "issue-intermediate", "cas"),
		cmdOn(ca, "ca", "cas"),         // csr / import-cert / import
		cmdOn(ca, "import-key", "cas"), // Authorities > "Import a key into the provider"
		cmdOn(ca, "list", "cas"),
		cmdOn(ca, "inventory", "cas"), // HSM key inventory; `inventory retention` is on the Inventory view
		cmdOn(ca, "rotate-intermediate", "cas"),
		cmdOn(ca, "rotation-status", "cas"),
		cmdOn(ca, "list-rotations", "cas"),
		cmdOn(ca, "retire-intermediate", "cas"),
		cmdOn(ca, "cross-sign", "cas"),
		cmdOn(ca, "list-cross-signs", "cas"), // -chains lands on the Trust Bundle view
		cmdOn(ca, "publish-chain", "bundle"),

		// --- secsy-ca: issuance + certificate lifecycle -----------------
		cmdOn(ca, "issue", "issue"),
		cmdOn(ca, "issue-bulk", "issue"),
		cmdOn(ca, "profiles", "issue"),
		cmdOn(ca, "export-p12", "p12"),
		cmdOn(ca, "renew", "certs"),
		cmdOn(ca, "revoke", "certs"),
		cmdOn(ca, "revoke-bulk", "certs"),
		cmdOn(ca, "suspend", "certs"),
		cmdOn(ca, "release", "certs"),
		cmdOn(ca, "gen-crl", "certs"),
		cmdOn(ca, "list-certs", "certs"),
		cmdOn(ca, "delegated-credential", "certs"),
		cmdOn(ca, "expiring", "monitor"),
		cmdOn(ca, "monitor-run", "monitor"),
		cmdOn(ca, "svid", "bundle"),
		cmdOn(ca, "svid-bundle", "bundle"),

		// --- secsy-ca: governance + evidence ----------------------------
		cmdOn(ca, "tenant", "tenants"),
		cmdOn(ca, "token", "tokens"),
		cmdOn(ca, "grant", "access"),
		cmdOn(ca, "webhook", "webhooks"),
		cmdOn(ca, "approvals", "approvals"),
		cmdOn(ca, "audit", "audit"),
		cmdOn(ca, "ers", "compliance"),
		cmdOn(ca, "lint", "compliance"),
		cmdOn(ca, "blocked-keys", "compliance"),
		cmdOn(ca, "validate-cert", "validate"),
		cmdOn(ca, "ct", "ct"),
		cmdOn(ca, "discover", "discovery"),
		cmdOn(ca, "dns-records", "dns"),

		// --- secsy-ca: devices, signing, operations ---------------------
		// Every device-touching sub-command is on the HSM view: key, ca, and — since
		// Task 198 — audit, the whole-device pass, next to the single-key controls.
		// Only `hsm-attest verify` stays offline, deliberately.
		cmdOn(ca, "hsm-attest", "hsm"),
		cmdOn(ca, "hsm-audit", "hsm"),
		cmdOn(ca, "ssh", "ssh"),
		cmdOn(ca, "sign", "signing"),
		cmdOn(ca, "verify-signature", "signing"),
		cmdOn(ca, "signing-key", "signing"), // Signing > "Provision a code-signing credential"
		cmdOn(ca, "tsa-key", "signing"),     // Signing > "Provision the RFC 3161 TSA credential"
		cmdOn(ca, "doctor", "ops"),
		cmdOn(ca, "backup", "ops"),
		cmdOn(ca, "publish", "ops"),

		// --- secsy-ca: genuinely CLI-only -------------------------------
		cliOnly(ca, "version", "shell plumbing: prints this binary's version, Go runtime and FIPS module state"),
		cliOnly(ca, "db", "offline store migration/verification. It runs BEFORE the server starts, takes its own source and destination DSNs, and must work when the deployment it is migrating cannot serve requests"),
		cliOnly(ca, "restore", "the disaster-recovery path, used precisely when the server is not running. The console offers the read halves — the DR manifest and the restore DRILL (POST /api/backup/verify-restore) — on the Operations view; the restore itself writes the store the API would be serving from"),
		cliOnly(ca, "ceremony", "interactive M-of-N operator quorum at a physical HSM: each custodian appears in person and enters a share on that terminal. The API's init-root / issue-intermediate are WebAuthn step-up gated instead"),
		cliOnly(ca, "cmp", "a CMP protocol CLIENT for testing the /cmp endpoint; it generates its own key and talks to a running server. Not a server feature"),
		cliOnly(ca, "grpc", "a gRPC CLIENT for testing the PKIService endpoint. Not a server feature"),

		// --- secsy-secret: on the Secrets view --------------------------
		cmdOn(sec, "encrypt", "secrets"),
		cmdOn(sec, "decrypt", "secrets"),
		cmdOn(sec, "datakey", "secrets"),
		cmdOn(sec, "hmac", "secrets"),
		cmdOn(sec, "hmac-verify", "secrets"),
		cmdOn(sec, "random", "secrets"),
		cmdOn(sec, "signing-key", "secrets"), // create / list / public, and import since Task 198
		cmdOn(sec, "sign", "secrets"),
		cmdOn(sec, "verify", "secrets"),
		cmdOn(sec, "transform", "secrets"),
		cmdOn(sec, "put", "secrets"),
		cmdOn(sec, "get", "secrets"),
		cmdOn(sec, "list-secrets", "secrets"),
		cmdOn(sec, "versions", "secrets"),
		cmdOn(sec, "rollback", "secrets"),
		cmdOn(sec, "lifecycle", "secrets"),
		cmdOn(sec, "kek-info", "secrets"),
		cmdOn(sec, "kek-versions", "secrets"),
		cmdOn(sec, "rotate-kek", "secrets"),
		cmdOn(sec, "rewrap", "secrets"),
		cmdOn(sec, "retire-kek", "secrets"),
		cmdOn(sec, "pqc-info", "secrets"),      // reported in the Secrets view's KEK summary line
		cmdOn(sec, "escrow-config", "secrets"), // ditto: "escrow N-of-M recovery agents"
		cmdOn(sec, "audit", "audit"),

		// --- secsy-secret: genuinely CLI-only ---------------------------
		cliOnly(sec, "init-kek", "provisions the deployment's key-encryption key. It is server-role key provisioning: the label has to reach the running process through config, so it needs a restart to take effect"),
		cliOnly(sec, "pqc-enable", "provisions the ML-KEM hybrid material, key provisioning like init-kek. The resulting state (provisioned / enabled) IS shown on the Secrets view"),
		cliOnly(sec, "pqc-reseal", "re-seals existing envelopes under the hybrid material — the migration half of pqc-enable, and offline for the same reason"),
		cliOnly(sec, "escrow-init-agent", "generates a recovery agent's key pair on the HSM. Key provisioning, and the agent's own custodian runs it"),
		cliOnly(sec, "recover", "the dual-control escrow recovery quorum: it needs recovery-agent key access and a quorum of custodians. The console shows escrow status and can escrow on encrypt; recovery stays offline by design"),
		cliOnly(sec, "exec", "injects decrypted secrets into a child process's environment on the machine it runs on. There is no browser equivalent of spawning a local process"),
	}
}

// --- (1) route coverage ----------------------------------------------------

// TestConsoleParityCoversRegisteredRoutes is the forcing function: every
// /api/... route registered in handlers.go must have exactly one parityRoutes()
// entry, and no entry may be stale.
func TestConsoleParityCoversRegisteredRoutes(t *testing.T) {
	registered := parseAPIRoutes(t)
	declared := map[string]routeEntry{}
	mapped, exempt := 0, 0
	for _, e := range parityRoutes() {
		if _, dup := declared[e.route]; dup {
			t.Errorf("duplicate console-parity entry %q", e.route)
		}
		if e.na == naNone && e.view == "" {
			t.Errorf("entry %q declares neither a console view nor a consoleN/A reason", e.route)
		}
		if e.na != naNone && strings.TrimSpace(e.why) == "" {
			t.Errorf("consoleN/A entry %q has no reason — say why the console does not surface it", e.route)
		}
		if e.na == naNone {
			mapped++
		} else {
			exempt++
		}
		declared[e.route] = e
	}
	for r := range registered {
		if _, ok := declared[r]; !ok {
			t.Errorf("route %q is registered in handlers.go but has NO console-parity entry.\n"+
				"    Declare the console view that surfaces it with onView(route, \"<data-view>\"),\n"+
				"    or say why none does with naPublic/naPlumbing/naLegacy/naIndirect.", r)
		}
	}
	for r := range declared {
		if !registered[r] {
			t.Errorf("console-parity entry %q matches no /api route registered in handlers.go "+
				"(stale — remove or fix it)", r)
		}
	}
	t.Logf("%d /api routes registered; %d entries declared: %d mapped to a console view, %d consoleN/A",
		len(registered), len(declared), mapped, exempt)
}

// --- (2) declared views exist ---------------------------------------------

// TestConsoleParityViewsExist checks that every view named in either table is a
// real console view: index.html must carry both a data-view="X" nav button and
// an id="view-X" section for it. Without this, a renamed view would silently
// turn both tables into fiction.
func TestConsoleParityViewsExist(t *testing.T) {
	html := readAsset(t, "static/index.html")
	seen := map[string]bool{}
	check := func(what, view string) {
		if view == "" || seen[view] {
			return
		}
		seen[view] = true
		if !strings.Contains(html, `data-view="`+view+`"`) {
			t.Errorf("%s names console view %q, but index.html has no data-view=%q nav button", what, view, view)
		}
		if !strings.Contains(html, `id="view-`+view+`"`) {
			t.Errorf("%s names console view %q, but index.html has no id=\"view-%s\" section", what, view, view)
		}
	}
	for _, e := range parityRoutes() {
		check("route "+e.route, e.view)
	}
	for _, c := range parityCommands() {
		check("command "+c.key(), c.view)
	}
	if len(seen) == 0 {
		t.Fatal("no views declared in either table — the tables are empty or the walk is broken")
	}
	t.Logf("%d distinct console views referenced by the parity tables", len(seen))
}

// --- (3) a view-mapped route is really wired ------------------------------

// jsProbes returns the literal substrings static/app.js must contain for
// pattern to count as referenced.
//
// The console builds paths with template literals — `/api/ca/${id}/certificates`
// — so the registered pattern never appears verbatim. What survives
// interpolation is the literal text around the parameters, so the probes are:
//
//	the literal PREFIX before the first {param}, and
//	the literal TAIL after the last {param}, when the pattern does not end in one.
//
// For "GET /api/ca/{id}/crl/status" that is "/api/ca/" plus "/crl/status"; for a
// pattern with no parameters it is the whole path.
//
// What this catches: a route declared onView() in the table that nothing in the
// bundle ever calls — a stale claim of parity. That is its whole purpose, and it
// found two such routes when it was written (see the naIndirect rows).
//
// What it CANNOT catch, honestly:
//   - A weak tail. "POST /api/keys/{id}/sign" probes "/api/keys/" and "/sign",
//     both of which occur in app.js for unrelated reasons, so the check would
//     pass on coincidence. Every such route in this table is a consoleN/A row
//     whose classification was made by reading the bundle, not by this probe.
//   - A parameter at the END with nothing after it ("GET /api/webhooks/{id}")
//     leaves only the prefix, which its siblings satisfy.
//   - A longer path that merely CONTAINS a probe. This is a substring test, so a
//     typo'd "/api/doctorr" in the bundle still satisfies "/api/doctor".
//     Demanding a path boundary after the probe would reject the legitimate
//     "/api/ca/" prefix form, so the looser test is deliberate: it is aimed at
//     "nothing calls this at all", not at spelling.
//   - Reachability. A literal present in a dead code path, behind a control
//     nothing renders, or in a comment still counts as referenced. Only the
//     end-to-end suite (internal/e2e/console_test.go) can speak to that.
//   - Method. The probe is path-only, so GET and DELETE on the same pattern are
//     indistinguishable.
//
// It is a cheap, strictly one-directional check: a pass means "plausibly wired",
// a failure means "definitely not wired as declared".
func jsProbes(pattern string) []string {
	parts := strings.Split(pattern, "{")
	prefix := parts[0]
	probes := []string{prefix}
	if len(parts) > 1 {
		last := parts[len(parts)-1]
		if _, tail, ok := strings.Cut(last, "}"); ok && tail != "" {
			probes = append(probes, tail)
		}
	}
	return probes
}

// TestConsoleParityRoutesAreWired asserts that every route the table maps to a
// console view is actually referenced by the console bundle. See jsProbes for
// exactly what the match does and does not prove.
func TestConsoleParityRoutesAreWired(t *testing.T) {
	app := readAsset(t, "static/app.js")
	checked := 0
	for _, e := range parityRoutes() {
		if e.na != naNone {
			continue // consoleN/A: no wiring is expected, by declaration
		}
		checked++
		_, pattern, ok := strings.Cut(e.route, " ")
		if !ok {
			t.Errorf("malformed route %q (want \"METHOD /pattern\")", e.route)
			continue
		}
		if e.ref != "" {
			// An explicit override: the console interpolates the segment that
			// distinguishes this route from its siblings, so the derived probes
			// cannot see it. The override is itself a declaration — if app.js is
			// refactored, update it rather than dropping the row.
			if !strings.Contains(app, e.ref) {
				t.Errorf("route %q is mapped to console view %q with reference override %q, "+
					"but app.js does not contain that literal.\n"+
					"    Either the control was removed (fix the table) or the call was rewritten (fix the override).",
					e.route, e.view, e.ref)
			}
			continue
		}
		for _, p := range jsProbes(pattern) {
			if !strings.Contains(app, p) {
				t.Errorf("route %q is mapped to console view %q, but static/app.js never references it "+
					"(missing literal %q).\n"+
					"    Wire the control, or — if the console reaches the capability through a different "+
					"endpoint — declare that with naIndirect.", e.route, e.view, p)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no view-mapped routes checked — the table is empty or the walk is broken")
	}
	t.Logf("%d view-mapped routes are referenced by static/app.js", checked)
}

// --- (4) CLI command coverage ---------------------------------------------

// TestConsoleParityCoversCLICommands is the CLI-side forcing function: every
// top-level command either binary dispatches must have exactly one
// parityCommands() entry, and no entry may be stale.
func TestConsoleParityCoversCLICommands(t *testing.T) {
	dispatched := map[string]bool{}
	for bin, path := range map[string]string{
		"secsy-ca":     "../../cmd/secsy-ca/main.go",
		"secsy-secret": "../../cmd/secsy-secret/main.go",
	} {
		cmds := parseCLICommands(t, path)
		if len(cmds) == 0 {
			t.Fatalf("no commands extracted from %s — the AST walk is broken", path)
		}
		for c := range cmds {
			dispatched[bin+" "+c] = true
		}
	}
	declared := map[string]cmdEntry{}
	onConsole, cliOnlyCount := 0, 0
	for _, c := range parityCommands() {
		if _, dup := declared[c.key()]; dup {
			t.Errorf("duplicate console-parity entry for command %q", c.key())
		}
		if c.view == "" {
			cliOnlyCount++
			if strings.TrimSpace(c.why) == "" {
				t.Errorf("command %q is declared CLI-only with no reason", c.key())
			}
		} else {
			onConsole++
		}
		declared[c.key()] = c
	}
	for c := range dispatched {
		if _, ok := declared[c]; !ok {
			t.Errorf("command %q is dispatched by main.go but has NO console-parity entry.\n"+
				"    Declare the console view offering it with cmdOn(bin, cmd, \"<data-view>\"),\n"+
				"    or say why it cannot be one with cliOnly(bin, cmd, \"<reason>\").", c)
		}
	}
	for c := range declared {
		if !dispatched[c] {
			t.Errorf("console-parity entry for command %q matches nothing dispatched by main.go "+
				"(stale — remove or fix it)", c)
		}
	}
	t.Logf("%d CLI commands dispatched; %d entries declared: %d offered by a console view, %d CLI-only",
		len(dispatched), len(declared), onConsole, cliOnlyCount)
}

// --- (5) the published matrix cannot drift -------------------------------

// TestConsoleParityMatrixIsDocumented ties the table above to the operator-
// facing page that publishes it: every command must be NAMED there, in a code
// span, so a command cannot be added to this file (or to the CLI) without
// appearing in the documentation operators actually read.
//
// What it guarantees: the page mentions every command, spelled `<bin> <cmd>`.
// What it does NOT: that the page's stated view matches this table's, or that
// the surrounding prose is true. Those stay a review question — the point here
// is only that a NEW command cannot ship undocumented, which is the specific
// way the three previous hand-audits rotted.
func TestConsoleParityMatrixIsDocumented(t *testing.T) {
	raw, err := os.ReadFile(parityDoc)
	if err != nil {
		t.Fatalf("read the parity matrix page: %v\n"+
			"    This page IS the published matrix; it must exist at %s.", err, parityDoc)
	}
	doc := string(raw)
	for _, c := range parityCommands() {
		span := "`" + c.key() + "`"
		if !strings.Contains(doc, span) {
			t.Errorf("command %q is in parityCommands() but %s does not name it as %s.\n"+
				"    Add its row to the page's table (first column: the command in a code span).",
				c.key(), parityDoc, span)
		}
	}
}

// --- parsing helpers ------------------------------------------------------

// readAsset reads one of the embedded console assets from disk. The test reads
// the source files rather than the embed.FS so that a failure names a file a
// developer can open.
func readAsset(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read console asset %s: %v", path, err)
	}
	return string(b)
}

// parseAPIRoutes extracts every "METHOD /api/..." pattern passed to mux.Handle /
// mux.HandleFunc inside RegisterRoutes, by parsing handlers.go with go/ast — the
// same walk internal/handlers/authz_matrix_test.go uses. Conditionally-
// registered routes (secret / hsm / svid) are included regardless of their
// runtime guard, because the table declares intent, not runtime state. Non-/api
// patterns (/openapi.json, /openapi.yaml, /docs) are outside this table's scope.
func parseAPIRoutes(t *testing.T) map[string]bool {
	t.Helper()
	const path = "../handlers/handlers.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var reg *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "RegisterRoutes" {
			reg = fd
			break
		}
	}
	if reg == nil {
		t.Fatalf("RegisterRoutes not found in %s", path)
	}
	out := map[string]bool{}
	ast.Inspect(reg, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok || x.Name != "mux" {
			return true
		}
		if sel.Sel.Name != "Handle" && sel.Sel.Name != "HandleFunc" {
			return true
		}
		if len(call.Args) == 0 {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		pattern, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if _, p, ok := strings.Cut(pattern, " "); ok && strings.HasPrefix(p, "/api/") {
			out[pattern] = true
		}
		return true
	})
	if len(out) == 0 {
		t.Fatalf("no /api routes extracted from RegisterRoutes in %s — the AST walk is broken", path)
	}
	return out
}

// parseCLICommands extracts the top-level command names a CLI's main.go
// dispatches. Both binaries dispatch in two stages and this walk covers both:
//
//	if command == "doctor" { ... }        -> a BinaryExpr comparing `command`
//	switch command { case "issue": ... }  -> a SwitchStmt whose tag is `command`
//
// Restricting the switch half to a tag literally named `command` is what keeps
// unrelated string switches in the same file (algorithm names, key kinds) out of
// the result. Compound guards like
//
//	if command == "hsm-audit" && cmdArgs[0] == "verify"
//
// contribute the top-level name only: the second comparison's operand is not the
// `command` identifier, so it is ignored — sub-commands are deliberately out of
// scope (see parityCommands). The usage aliases (help, -h, --help) are dropped.
func parseCLICommands(t *testing.T, path string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := map[string]bool{}
	add := func(e ast.Expr) {
		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return
		}
		name, err := strconv.Unquote(lit.Value)
		if err != nil {
			return
		}
		switch name {
		case "", "help", "-h", "--help":
			return
		}
		out[name] = true
	}
	isCommandIdent := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "command"
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.BinaryExpr:
			if node.Op != token.EQL {
				return true
			}
			if isCommandIdent(node.X) {
				add(node.Y)
			} else if isCommandIdent(node.Y) {
				add(node.X)
			}
		case *ast.SwitchStmt:
			if !isCommandIdent(node.Tag) {
				return true
			}
			for _, stmt := range node.Body.List {
				cc, ok := stmt.(*ast.CaseClause)
				if !ok {
					continue
				}
				for _, e := range cc.List {
					add(e)
				}
			}
		}
		return true
	})
	return out
}
