//go:build sqlite

package handlers

// Task 106: comprehensive authorization + tenant-isolation regression matrix.
//
// This suite is the systematic guard over every REST route registered in
// handlers.go. It exists because the codebase grew ~116 routes with only ad-hoc
// per-feature authz tests and no forcing function to make a NEW route declare
// its access-control intent.
//
// It has two halves:
//
//  1. TestAuthzMatrixCoversRegisteredRoutes parses RegisterRoutes in handlers.go
//     with go/ast and fails if any registered route has no entry in authzMatrix()
//     (and if any matrix entry is stale). Adding a route therefore breaks this
//     test until the author declares the route's capability + tenant scope here
//     (or adds it to the public allowlist). This is the linchpin.
//
//  2. TestAuthzMatrix drives every matrix entry through the REAL mux + auth
//     middleware and asserts the four contract points from the task:
//       (a) unauthenticated            -> 401           (protected routes)
//       (b) authenticated, no capability -> denied (403/404, never 2xx)
//       (c) tenant-scoped principal on another tenant's resource -> denied
//       (d) a correctly-capable principal -> NOT denied (not 401/403)
//     Public routes assert only that an unauthenticated caller is not 401.
//     "Authed-only" routes (no capability gate by design — /api/me, profiles,
//     device/KEK info) assert 401 for anonymous and reachability for an
//     authenticated caller.
//
// Principals are minted through the real middleware via a mock OIDC verifier +
// role resolvers: the bearer token IS the subject, and the resolvers decode
// roles from the subject string ("plat:<role>" = platform-wide role;
// "tn:<tenant>:<role>" = a role within one tenant; "none" = authenticated but
// roleless). admin is allow-all, so a tenant-a admin is the universal "capable"
// witness for tenant-scoped routes and a roleless principal is the universal
// "denied" witness. The gRPC PKIService mirror lives in
// internal/grpcapi/authz_matrix_test.go.
//
// To keep this green as routes are added: give every new mux.Handle/HandleFunc
// in RegisterRoutes a matrix row using the constructor that matches its gate
// (caRd/iss/caMg/secret/... ), or pub()/authed() for the two allowlists.

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/signing"
	"github.com/blechschmidt/secsy-pki/server/internal/spiffe"
)

// --- principals (bearer token == subject; resolvers decode roles from it) ---

const (
	subjUnauth      = ""           // no credentials
	subjRoot        = "root"       // built-in basic-auth superuser
	subjNobody      = "none"       // authenticated, zero roles/tenants
	subjPlatAdmin   = "plat:admin" // platform-wide admin
	subjPlatAuditor = "plat:auditor"
	subjAdminA      = "tn:a:admin"   // admin within tenant "a" (allow-all in a)
	subjAdminB      = "tn:b:admin"   // admin within tenant "b"
	subjAuditorA    = "tn:a:auditor" // read within tenant "a"
	subjAuditorB    = "tn:b:auditor"
)

// matrixVerifier authenticates any bearer token as subject == token; the role
// resolvers below turn that subject into platform/tenant roles.
type matrixVerifier struct{}

func (matrixVerifier) VerifyToken(_ context.Context, raw string) (*auth.Claims, error) {
	return &auth.Claims{Subject: raw, EmailVerified: true}, nil
}

func matrixRoleResolver(u *models.UserInfo) []string {
	if r, ok := strings.CutPrefix(u.Subject, "plat:"); ok {
		return []string{r}
	}
	return nil
}

func matrixTenantRoleResolver(u *models.UserInfo) map[string][]string {
	if rest, ok := strings.CutPrefix(u.Subject, "tn:"); ok {
		if tenant, role, ok := strings.Cut(rest, ":"); ok {
			return map[string][]string{tenant: {role}}
		}
	}
	return nil
}

// --- acceptable "denied" status sets ---

var (
	den403 = []int{http.StatusForbidden}
	den404 = []int{http.StatusNotFound}
)

// rc is one route's authorization contract.
type rc struct {
	method, pattern, path, body string
	headers                     map[string]string
	public                      bool // unauthenticated access is intentional
	authedOnly                  bool // any authenticated principal; no capability gate
	skipReach                   bool // authed-only: don't invoke the handler for the reachability probe
	capable                     string
	denied                      []int
	tenantScoped                bool
	cross                       string
	crossDenied                 []int
	extra                       map[string][]int // subject -> acceptable denied statuses (extra witnesses)
}

func (c rc) key() string { return c.method + " " + c.pattern }

// --- constructors, one per authorization class ---

func pub(m, pat, path string) rc { return rc{method: m, pattern: pat, path: path, public: true} }
func authed(m, pat, path, b string) rc {
	return rc{method: m, pattern: pat, path: path, body: b, authedOnly: true}
}
func authedSkip(m, pat, path string) rc {
	return rc{method: m, pattern: pat, path: path, authedOnly: true, skipReach: true}
}

// rdG: global read (canRead) — any assigned role; roleless -> 403.
func rdG(m, pat, path, b string) rc {
	return rc{method: m, pattern: pat, path: path, body: b, capable: subjAuditorA, denied: den403}
}

// rdGStream: global read (canRead) for a STREAMING endpoint (Server-Sent Events).
// Same gate as rdG, but the (d) reachability probe is skipped: a streaming
// handler never returns from ServeHTTP synchronously (it blocks until the client
// disconnects), so driving it with a capable principal would hang the harness.
// The unauthenticated-401 and roleless-403 checks still run and prove the gate.
func rdGStream(m, pat, path string) rc {
	c := rdG(m, pat, path, "")
	c.skipReach = true
	return c
}

// caRd: per-CA read (authorizeCARead) — roleless -> 403, cross member -> 404.
func caRd(m, pat, path string) rc {
	return rc{method: m, pattern: pat, path: path, capable: subjAuditorA, denied: den403,
		tenantScoped: true, cross: subjAuditorB, crossDenied: den404}
}

// caRdBody: per-CA read taking a request body (POST that is read-gated).
func caRdBody(m, pat, path, b string) rc {
	c := caRd(m, pat, path)
	c.body = b
	return c
}

// platRd: platform read (a.can(audit:read)) — a tenant-scoped auditor is denied too.
func platRd(m, pat, path string) rc {
	return rc{method: m, pattern: pat, path: path, capable: subjPlatAuditor, denied: den403,
		extra: map[string][]int{subjAuditorA: den403}}
}

// iss: per-CA issue (canIssueOn) — tenant issuer/admin; cross-tenant -> 403.
func iss(m, pat, path, b string) rc {
	return rc{method: m, pattern: pat, path: path, body: b, capable: subjAdminA, denied: den403,
		tenantScoped: true, cross: subjAdminB, crossDenied: den403}
}

// platIss: platform issue (a.can(cert:issue)) — a tenant issuer is denied.
func platIss(m, pat, path, b string) rc {
	return rc{method: m, pattern: pat, path: path, body: b, capable: subjRoot, denied: den403,
		extra: map[string][]int{subjAuditorA: den403}}
}

// caMg: tenant ca:manage on an existing CA path.
func caMg(m, pat, path, b string) rc {
	return rc{method: m, pattern: pat, path: path, body: b, capable: subjAdminA, denied: den403,
		tenantScoped: true, cross: subjAdminB, crossDenied: den403}
}

// caMgBody: ca:manage where the target tenant comes from the body (create flows).
// The cross principal replays the SAME tenant-a body as a tenant-b admin -> 403.
func caMgBody(m, pat, path, b string) rc { return caMg(m, pat, path, b) }

// platAdm: platform-admin / root-only (tenant CRUD, global restriction sets).
func platAdm(m, pat, path, b string) rc {
	return rc{method: m, pattern: pat, path: path, body: b, capable: subjRoot, denied: den403,
		extra: map[string][]int{subjAdminA: den403}}
}

// memRd: tenant-member read — non-members get 404 (non-disclosure).
func memRd(m, pat, path string) rc {
	return rc{method: m, pattern: pat, path: path, capable: subjAdminA, denied: den404,
		tenantScoped: true, cross: subjAdminB, crossDenied: den404}
}

// tokMg: token:manage list/create scoped to tenant a (admin in a).
func tokMg(m, pat, path, b string) rc {
	return rc{method: m, pattern: pat, path: path, body: b, capable: subjAdminA, denied: den403}
}

// tokMgScoped: token:manage on a specific token owned by tenant a.
func tokMgScoped(m, pat, path string) rc {
	return rc{method: m, pattern: pat, path: path, capable: subjAdminA, denied: den403,
		tenantScoped: true, cross: subjAdminB, crossDenied: den403}
}

// secret: tenant secret capability, tenant chosen via the X-Secsy-Tenant header.
func secretR(m, pat, path, b string) rc {
	return rc{method: m, pattern: pat, path: path, body: b, headers: map[string]string{TenantHeader: "a"},
		capable: subjAdminA, denied: den403, tenantScoped: true, cross: subjAdminB, crossDenied: den403}
}

// signR: artifact:sign on the signer's tenant (a).
func signR(m, pat, path, b string) rc {
	return rc{method: m, pattern: pat, path: path, body: b, capable: subjAdminA, denied: den403,
		tenantScoped: true, cross: subjAdminB, crossDenied: den403}
}

// aprRd: approval:read list.
func aprRd(m, pat, path string) rc {
	return rc{method: m, pattern: pat, path: path, capable: subjAuditorA, denied: den403}
}

// aprGet: approval:read on one request scoped to its tenant (a).
func aprGet(m, pat, path string) rc {
	return rc{method: m, pattern: pat, path: path, capable: subjAuditorA, denied: den403,
		tenantScoped: true, cross: subjAuditorB, crossDenied: den403}
}

// aprDec: approval:approve on one request scoped to its tenant (a).
func aprDec(m, pat, path, b string) rc {
	return rc{method: m, pattern: pat, path: path, body: b, capable: subjAdminA, denied: den403,
		tenantScoped: true, cross: subjAdminB, crossDenied: den403}
}

// rbacMg: platform rbac:manage (groups / per-CA permission grants). A tenant
// admin does NOT hold the platform capability, so it is a denied witness.
func rbacMg(m, pat, path, b string) rc {
	return rc{method: m, pattern: pat, path: path, body: b, capable: subjPlatAdmin, denied: den403,
		extra: map[string][]int{subjAdminA: den403}}
}

// cfgCA: root or a per-CA CONFIGURE_CA grant (restriction-set management).
func cfgCA(m, pat, path, b string) rc {
	return rc{method: m, pattern: pat, path: path, body: b, capable: subjRoot, denied: den403,
		extra: map[string][]int{subjAdminA: den403}}
}

// hsmMg: platform hsm:manage.
func hsmMg(m, pat, path, b string) rc {
	return rc{method: m, pattern: pat, path: path, body: b, capable: subjRoot, denied: den403,
		extra: map[string][]int{subjAdminA: den403}}
}

// authzMatrix is the declared route -> capability -> tenant-scope matrix. Every
// route in RegisterRoutes must appear here exactly once (enforced by
// TestAuthzMatrixCoversRegisteredRoutes). Ordered as in handlers.go.
func authzMatrix() []rc {
	const bogusKey = `"key_type":"bogus"` // a non-empty key type that fails key generation post-authz
	return []rc{
		// Public health / auth-config.
		pub("GET", "/api/health", "/api/health"),
		pub("GET", "/api/auth/config", "/api/auth/config"),

		// CA inventory + creation.
		rdG("GET", "/api/keys", "/api/keys", ""),
		caMgBody("POST", "/api/keys", "/api/keys", `{"label":"authz-new",`+bogusKey+`,"tenant_id":"a"}`),

		// Multi-tenant administration.
		platAdm("GET", "/api/tenants", "/api/tenants", ""),
		platAdm("POST", "/api/tenants", "/api/tenants", `{"slug":"authz-t","name":"t"}`),
		memRd("GET", "/api/tenants/{id}", "/api/tenants/a"),
		platAdm("PUT", "/api/tenants/{id}", "/api/tenants/a", `{"name":"a"}`),
		platAdm("PUT", "/api/tenants/{id}/status", "/api/tenants/a/status", `{"status":"active"}`),
		memRd("GET", "/api/tenants/{id}/usage", "/api/tenants/a/usage"),
		platAdm("DELETE", "/api/tenants/{id}", "/api/tenants/a", ""),

		// Native scoped API tokens.
		tokMg("GET", "/api/tokens", "/api/tokens", ""),
		tokMg("POST", "/api/tokens", "/api/tokens", `{"name":"x","tenant_id":"a","scope":"tenant","roles":["auditor"]}`),
		tokMgScoped("DELETE", "/api/tokens/{id}", "/api/tokens/tok-a"),

		// X.509 CA setup.
		caMgBody("POST", "/api/ca/init-root", "/api/ca/init-root", `{"tenant_id":"a","label":"authz-root",`+bogusKey+`,"subject":{"common_name":"x"}}`),
		caMg("POST", "/api/ca/{id}/issue-intermediate", "/api/ca/ca-a/issue-intermediate", `{"label":"i",`+bogusKey+`}`),

		// Externally-signed subordinate CA flow.
		caMgBody("POST", "/api/ca/csr", "/api/ca/csr", `{"tenant_id":"a","label":"ext",`+bogusKey+`}`),
		caRd("GET", "/api/ca/{id}/csr", "/api/ca/ca-a/csr"),
		caMg("POST", "/api/ca/{id}/import-cert", "/api/ca/ca-a/import-cert", `{}`),

		// Cross-signing.
		caMg("POST", "/api/ca/{id}/cross-signs", "/api/ca/ca-a/cross-signs", `{}`),
		caMg("GET", "/api/ca/{id}/cross-signs", "/api/ca/ca-a/cross-signs", ""),
		pub("GET", "/api/ca/{id}/chains", "/api/ca/ca-a/chains"),
		pub("GET", "/api/ca/{id}/cross-signs/{csid}/chain", "/api/ca/ca-a/cross-signs/x/chain"),

		// Intermediate rotation lifecycle.
		rdG("GET", "/api/rotations", "/api/rotations", ""),
		caRd("GET", "/api/ca/{id}/rotation", "/api/ca/ca-a/rotation"),
		caMg("POST", "/api/ca/{id}/rotate", "/api/ca/ca-a/rotate", `{}`),
		caMg("POST", "/api/ca/{id}/retire", "/api/ca/ca-a/retire", `{}`),

		// Issuance / renewal / revocation.
		authed("GET", "/api/profiles", "/api/profiles", ""),
		iss("POST", "/api/ca/{id}/issue", "/api/ca/ca-a/issue", `{"csr":"bogus"}`),
		iss("POST", "/api/ca/{id}/pkcs12", "/api/ca/ca-a/pkcs12", `{}`),
		iss("POST", "/api/ca/{id}/renew", "/api/ca/ca-a/renew", `{}`),
		iss("POST", "/api/ca/{id}/revoke", "/api/ca/ca-a/revoke", `{"serial":"01"}`),
		caMg("POST", "/api/ca/{id}/revocations:bulk", "/api/ca/ca-a/revocations:bulk", `{}`),
		iss("POST", "/api/ca/{id}/certificates:bulk", "/api/ca/ca-a/certificates:bulk", `{}`),
		caRd("GET", "/api/ca/{id}/certificates", "/api/ca/ca-a/certificates"),
		caRd("GET", "/api/ca/{id}/revoked", "/api/ca/ca-a/revoked"),
		iss("POST", "/api/ca/{id}/certificates/{action}", "/api/ca/ca-a/certificates/01:suspend", `{}`),

		// SPIFFE X.509-SVID + JWT-SVID (registered because SPIFFE is enabled in the
		// harness). Both mint an identity, so both are gated by canIssueOn + the
		// trust-domain allowlist and are tenant-scoped.
		iss("POST", "/api/ca/{id}/svid", "/api/ca/ca-a/svid", `{}`),
		iss("POST", "/api/ca/{id}/svid/jwt", "/api/ca/ca-a/svid/jwt", `{}`),
		pub("GET", "/api/ca/{id}/svid/bundle", "/api/ca/ca-a/svid/bundle"),

		// Expiry monitoring.
		rdG("GET", "/api/monitor/expiring", "/api/monitor/expiring", ""),
		rdG("POST", "/api/monitor/scan", "/api/monitor/scan", `{}`),

		// Compliance / inventory reporting.
		rdG("GET", "/api/report/inventory", "/api/report/inventory", ""),
		rdG("GET", "/api/report/compliance", "/api/report/compliance", ""),

		// External certificate discovery.
		rdG("GET", "/api/discovery", "/api/discovery", ""),
		platIss("POST", "/api/discovery/scan", "/api/discovery/scan", `{}`),

		// CT inclusion state.
		rdG("GET", "/api/ct/inclusion", "/api/ct/inclusion", ""),

		// SSH certificate authority.
		caMgBody("POST", "/api/ssh/cas", "/api/ssh/cas", `{"label":"authz-ssh","tenant_id":"a",`+bogusKey+`}`),
		rdG("GET", "/api/ssh/cas", "/api/ssh/cas", ""),
		rdG("GET", "/api/ssh/profiles", "/api/ssh/profiles", ""),
		iss("POST", "/api/ssh/cas/{id}/sign", "/api/ssh/cas/ca-a/sign", `{}`),
		iss("POST", "/api/ssh/cas/{id}/revoke", "/api/ssh/cas/ca-a/revoke", `{}`),
		caRd("GET", "/api/ssh/cas/{id}/certificates", "/api/ssh/cas/ca-a/certificates"),
		caRd("GET", "/api/ssh/cas/{id}/revocations", "/api/ssh/cas/ca-a/revocations"),
		pub("GET", "/api/ssh/cas/{id}/public", "/api/ssh/cas/ca-a/public"),
		pub("GET", "/api/ssh/cas/{id}/krl", "/api/ssh/cas/ca-a/krl"),
		caRdBody("POST", "/api/ssh/cas/{id}/dns-records/sshfp", "/api/ssh/cas/ca-a/dns-records/sshfp", `{}`),

		// Artifact code-signing.
		signR("POST", "/api/sign", "/api/sign", `{"signer":"release","artifact":"eA=="}`),
		rdG("POST", "/api/sign/verify", "/api/sign/verify", `{}`),
		rdG("GET", "/api/sign/signers", "/api/sign/signers", ""),

		// Public revocation material + CRL freshness.
		pub("GET", "/api/ca/{id}/crl", "/api/ca/ca-a/crl"),
		pub("GET", "/api/ca/{id}/crl/delta", "/api/ca/ca-a/crl/delta"),
		caRd("GET", "/api/ca/{id}/crl/status", "/api/ca/ca-a/crl/status"),
		pub("GET", "/api/ca/{id}/crl/partition/{shard}", "/api/ca/ca-a/crl/partition/0"),
		pub("GET", "/api/ca/{id}/crl/partition/{shard}/delta", "/api/ca/ca-a/crl/partition/0/delta"),
		caRd("GET", "/api/ca/{id}/dns-records/tlsa", "/api/ca/ca-a/dns-records/tlsa"),

		// Public chain / OCSP.
		pub("GET", "/api/ca/{id}/chain", "/api/ca/ca-a/chain"),
		pub("POST", "/api/ca/{id}/ocsp", "/api/ca/ca-a/ocsp"),
		pub("GET", "/api/ca/{id}/ocsp/{req}", "/api/ca/ca-a/ocsp/AAAA"),

		// Per-CA read + delete.
		caRd("GET", "/api/keys/{id}", "/api/keys/ca-a"),
		caMg("DELETE", "/api/keys/{id}", "/api/keys/ca-del", ""), // ca-del is a throwaway CA so the delete side-effect is isolated
		caRd("GET", "/api/keys/{id}/children", "/api/keys/ca-a/children"),
		caRd("GET", "/api/keys/{id}/public-key", "/api/keys/ca-a/public-key"),

		// Legacy sign endpoints.
		iss("POST", "/api/keys/{id}/sign", "/api/keys/ca-a/sign", `{}`),
		iss("POST", "/api/keys/{id}/sign-x509", "/api/keys/ca-a/sign-x509", `{}`),
		rdG("POST", "/api/parse-csr", "/api/parse-csr", `{}`),
		authed("GET", "/api/keys/{id}/my-restrictions", "/api/keys/ca-a/my-restrictions", ""),

		// Groups (platform rbac:manage; members read-gated).
		rdG("GET", "/api/groups", "/api/groups", ""),
		rbacMg("POST", "/api/groups", "/api/groups", `{"name":"g"}`),
		rbacMg("DELETE", "/api/groups/{id}", "/api/groups/g-1", ""),
		rdG("GET", "/api/groups/{id}/members", "/api/groups/g-1/members", ""),
		rbacMg("POST", "/api/groups/{id}/members", "/api/groups/g-1/members", `{"user_sub":"x"}`),
		rbacMg("DELETE", "/api/groups/{id}/members/{sub}", "/api/groups/g-1/members/x", ""),

		// Per-CA permission grants (platform rbac:manage or per-CA MANAGE_PERMISSIONS).
		rbacMg("GET", "/api/keys/{id}/permissions", "/api/keys/ca-a/permissions", ""),
		rbacMg("POST", "/api/keys/{id}/permissions", "/api/keys/ca-a/permissions", `{"entity_type":"user","entity_id":"x","permission":"SIGN_CERTIFICATE"}`),
		rbacMg("DELETE", "/api/keys/{id}/permissions", "/api/keys/ca-a/permissions", `{"entity_type":"user","entity_id":"x","permission":"SIGN_CERTIFICATE"}`),

		// Restriction sets.
		rdG("GET", "/api/restriction-sets", "/api/restriction-sets", ""),
		cfgCA("POST", "/api/restriction-sets", "/api/restriction-sets", `{"name":"rs"}`), // root-only (CreateRestrictionSetGlobal)
		rdG("GET", "/api/keys/{id}/restriction-sets", "/api/keys/ca-a/restriction-sets", ""),
		cfgCA("POST", "/api/keys/{id}/restriction-sets", "/api/keys/ca-a/restriction-sets", `{"name":"rs"}`),
		cfgCA("PUT", "/api/restriction-sets/{id}", "/api/restriction-sets/rs-a", `{"name":"rs"}`),
		cfgCA("DELETE", "/api/restriction-sets/{id}", "/api/restriction-sets/rs-a", ""),
		cfgCA("PUT", "/api/keys/{id}/default-restriction-set", "/api/keys/ca-a/default-restriction-set", `{"type":"ssh"}`),

		// Audit / access logs (platform audit:read).
		platRd("GET", "/api/audit-log", "/api/audit-log"),
		platRd("GET", "/api/access-log", "/api/access-log"),

		// Tamper-evident event log.
		rdG("GET", "/api/events", "/api/events", ""),
		platRd("GET", "/api/events/verify", "/api/events/verify"),
		platRd("GET", "/api/events/export", "/api/events/export"),
		// Live audit-event feed (SSE): read-gated like /api/events; streaming, so
		// the reachability probe is skipped (see rdGStream).
		rdGStream("GET", "/api/events/stream", "/api/events/stream"),

		// Four-eyes approval workflow (engine enabled in the harness).
		aprRd("GET", "/api/approvals", "/api/approvals"),
		aprGet("GET", "/api/approvals/{id}", "/api/approvals/apr-get"),
		aprDec("POST", "/api/approvals/{id}/approve", "/api/approvals/apr-approve/approve", `{}`),
		aprDec("POST", "/api/approvals/{id}/reject", "/api/approvals/apr-reject/reject", `{}`),
		iss("GET", "/api/approvals/{id}/certificate", "/api/approvals/apr-cert/certificate", ""),

		// Ad-hoc lint + provider key inventory.
		rdG("POST", "/api/lint", "/api/lint", `{}`),
		hsmMg("GET", "/api/inventory/keys", "/api/inventory/keys", ""),

		// ACME operator visibility.
		rdG("GET", "/api/acme/accounts", "/api/acme/accounts", ""),
		rdG("GET", "/api/acme/orders", "/api/acme/orders", ""),

		// Secret envelope layer (enabled in the harness).
		authed("GET", "/api/secret/info", "/api/secret/info", ""),
		secretR("POST", "/api/secret/encrypt", "/api/secret/encrypt", `{}`),
		secretR("POST", "/api/secret/decrypt", "/api/secret/decrypt", `{}`),
		secretR("GET", "/api/secret/kek/status", "/api/secret/kek/status", ""),
		secretR("POST", "/api/secret/kek/rotate", "/api/secret/kek/rotate", `{}`),
		secretR("POST", "/api/secret/kek/retire", "/api/secret/kek/retire", `{}`),
		secretR("POST", "/api/secret/rewrap", "/api/secret/rewrap", `{}`),
		secretR("POST", "/api/secret/store", "/api/secret/store", `{}`),
		secretR("GET", "/api/secret/store", "/api/secret/store", ""),
		secretR("GET", "/api/secret/store/{id}", "/api/secret/store/s-a", ""),
		secretR("DELETE", "/api/secret/store/{id}", "/api/secret/store/s-a", ""),
		secretR("PUT", "/api/secret/store/{id}", "/api/secret/store/s-a", `{}`),
		secretR("GET", "/api/secret/store/{id}/versions", "/api/secret/store/s-a/versions", ""),
		secretR("GET", "/api/secret/store/{id}/versions/{version}", "/api/secret/store/s-a/versions/1", ""),
		secretR("POST", "/api/secret/store/{id}/rollback", "/api/secret/store/s-a/rollback", `{}`),
		secretR("GET", "/api/secret/lifecycle", "/api/secret/lifecycle", ""),

		// HSM administration (enabled in the harness).
		authedSkip("GET", "/api/hsm/info", "/api/hsm/info"), // device metadata; touches HSM, so probe only 401
		hsmMg("GET", "/api/hsm/attestation", "/api/hsm/attestation", ""),
		platRd("GET", "/api/hsm/audit-log", "/api/hsm/audit-log"),
		hsmMg("POST", "/api/hsm/provision-audit", "/api/hsm/provision-audit", `{}`),
		hsmMg("POST", "/api/hsm/factory-reset", "/api/hsm/factory-reset", `{}`),
		platRd("GET", "/api/hsm/combined-audit-log", "/api/hsm/combined-audit-log"),
		platRd("GET", "/api/hsm/signed-audit-log", "/api/hsm/signed-audit-log"),

		// OpenAPI spec + docs UI (public).
		pub("GET", "/openapi.json", "/openapi.json"),
		pub("GET", "/openapi.yaml", "/openapi.yaml"),
		pub("GET", "/docs", "/docs"),
		pub("GET", "/api/docs", "/api/docs"),
		pub("GET", "/api/docs/openapi.yaml", "/api/docs/openapi.yaml"),
		pub("GET", "/api/docs/openapi.json", "/api/docs/openapi.json"),

		// Self identity.
		authed("GET", "/api/me", "/api/me", ""),
	}
}

// --- harness ---

type authzHarness struct {
	mux *http.ServeMux
	db  *database.DB
}

func newAuthzHarness(t *testing.T) *authzHarness {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}

	// A bogus HSM connector so the hsm.* routes are registered; the gated ones
	// deny before touching the device, and a connection-refused address fails
	// fast for the few that reach it.
	api := NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{ConnectorURL: "http://127.0.0.1:1"}, true, "authz-kek")
	api.SetSPIFFE(spiffe.NewPolicy(spiffe.PolicyConfig{TrustDomains: []string{"example.org"}, DefaultCAID: "ca-a"}), "spiffe-svid")
	api.SetApprovals(approval.NewEngine(db, db, approval.Policy{Enabled: true, DefaultThreshold: 2, TTL: 72 * time.Hour}))
	installMatrixSigning(t, api, prov)

	// Fixtures: two tenants, an X.509 CA in each, a throwaway CA for the delete
	// case, a token, a restriction set, and four approval requests in tenant "a".
	mkTenant(t, db, "a")
	mkTenant(t, db, "b")
	mkTenantCA(t, db, "a", "ca-a")
	mkTenantCA(t, db, "b", "ca-b")
	mkTenantCA(t, db, "a", "ca-del")
	if err := db.CreateAPIToken(&models.APIToken{
		ID: "tok-a", TenantID: "a", Name: "t", Prefix: "secsy_pat_aaaa",
		TokenHash: strings.Repeat("a", 64), Roles: []string{"auditor"}, Scope: "tenant",
		CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if err := db.CreateRestrictionSet(&models.RestrictionSet{ID: "rs-a", CAID: "ca-a", Name: "rs"}); err != nil {
		t.Fatalf("CreateRestrictionSet: %v", err)
	}
	for _, id := range []string{"apr-get", "apr-approve", "apr-reject"} {
		seedApproval(t, db, id, approval.ClassCARotate, "ca:ca-a")
	}
	seedApproval(t, db, "apr-cert", approval.ClassCertIssue, "ca:ca-a")

	authMw := middleware.NewAuthMiddleware(matrixVerifier{}, "root", "rootpw")
	authMw.SetRoleResolver(matrixRoleResolver)
	authMw.SetTenantRoleResolver(matrixTenantRoleResolver)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux, authMw)
	return &authzHarness{mux: mux, db: db}
}

func seedApproval(t *testing.T, db *database.DB, id, class, resourceKey string) {
	t.Helper()
	pa := &models.PendingApproval{
		ID: id, TenantID: "a", OperationClass: class, ResourceKey: resourceKey,
		Fingerprint: "fp-" + id, RequestedBy: "seed-requester", RequiredApprovals: 2,
		Status: approval.StatusPending, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := db.CreatePendingApproval(pa); err != nil {
		t.Fatalf("CreatePendingApproval(%s): %v", id, err)
	}
}

func installMatrixSigning(t *testing.T, api *API, prov keyprovider.Provider) {
	t.Helper()
	ctx := context.Background()
	caInfo, err := prov.GenerateKey(ctx, keyprovider.KeySpec{Label: "authz-sign-ca", KeyType: keyprovider.KeyTypeECDSAP256})
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caSigner, err := prov.Signer(ctx, keyprovider.KeyRef{Label: "authz-sign-ca"})
	if err != nil {
		t.Fatalf("CA signer: %v", err)
	}
	defer caSigner.Close()
	caDER, err := pki.CreateCACertificate(caSigner, nil, pki.CACertRequest{
		Subject: pkix.Name{CommonName: "authz sign CA"}, PublicKey: caInfo.PublicKey,
		Serial: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafInfo, err := prov.GenerateKey(ctx, keyprovider.KeySpec{Label: "authz-signer", KeyType: keyprovider.KeyTypeECDSAP256})
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	leafDER, err := pki.CreateLeafCertificate(caSigner, caCert, pki.LeafCertRequest{
		Subject: pkix.Name{CommonName: "authz release-signer"}, PublicKey: leafInfo.PublicKey,
		Serial: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		t.Fatalf("CreateLeafCertificate: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := signing.NewService(prov, nil, []signing.SignerConfig{{
		Name: "release", KeyLabel: "authz-signer", Certificate: leafCert,
		Chain: []*x509.Certificate{leafCert, caCert}, TenantID: "a",
	}})
	if err != nil {
		t.Fatalf("signing.NewService: %v", err)
	}
	api.SetSigningService(svc)
}

func (h *authzHarness) do(c rc, subj string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
	if c.body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for k, v := range c.headers {
		r.Header.Set(k, v)
	}
	switch subj {
	case subjUnauth:
		// no credentials
	case subjRoot:
		r.SetBasicAuth("root", "rootpw")
	default:
		r.Header.Set("Authorization", "Bearer "+subj)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, r)
	return rec
}

func snippet(rec *httptest.ResponseRecorder) string {
	s := strings.TrimSpace(rec.Body.String())
	if len(s) > 180 {
		return s[:180]
	}
	return s
}

func assertDenied(t *testing.T, label string, rec *httptest.ResponseRecorder, want []int) {
	t.Helper()
	if rec.Code >= 200 && rec.Code < 300 {
		t.Errorf("%s: got 2xx (%d) — access was NOT denied; body=%s", label, rec.Code, snippet(rec))
		return
	}
	for _, w := range want {
		if rec.Code == w {
			return
		}
	}
	t.Errorf("%s: status=%d, want one of %v (authz gate not reached or wrong code); body=%s",
		label, rec.Code, want, snippet(rec))
}

// TestAuthzMatrix drives every declared route through the real mux + middleware
// and asserts the four authorization/tenant-isolation contract points.
func TestAuthzMatrix(t *testing.T) {
	h := newAuthzHarness(t)
	for _, c := range authzMatrix() {
		c := c
		t.Run(c.method+"_"+c.path, func(t *testing.T) {
			if c.public {
				if rec := h.do(c, subjUnauth); rec.Code == http.StatusUnauthorized {
					t.Errorf("public route answered 401 to an anonymous caller; body=%s", snippet(rec))
				}
				return
			}
			// (a) unauthenticated -> 401.
			if rec := h.do(c, subjUnauth); rec.Code != http.StatusUnauthorized {
				t.Errorf("(a) unauthenticated: status=%d, want 401; body=%s", rec.Code, snippet(rec))
			}
			if c.authedOnly {
				if c.skipReach {
					return
				}
				if rec := h.do(c, subjNobody); rec.Code == http.StatusUnauthorized {
					t.Errorf("(authed-only) an authenticated principal was rejected 401; body=%s", snippet(rec))
				}
				return
			}
			// (b) authenticated but lacking the capability -> denied.
			assertDenied(t, "(b) roleless", h.do(c, subjNobody), c.denied)
			for subj, want := range c.extra {
				assertDenied(t, "(b) "+subj, h.do(c, subj), want)
			}
			// (c) tenant-scoped principal on another tenant's resource -> denied, no leak.
			if c.tenantScoped {
				cd := c.crossDenied
				if cd == nil {
					cd = c.denied
				}
				rec := h.do(c, c.cross)
				assertDenied(t, "(c) cross-tenant "+c.cross, rec, cd)
				// A denied response must not carry the foreign tenant's resource payload.
				if b := rec.Body.String(); strings.Contains(b, `"pkcs11:object=ca-a"`) || strings.Contains(b, `"tenant_id":"a"`) {
					t.Errorf("(c) cross-tenant response leaked tenant-a data; body=%s", snippet(rec))
				}
			}
			if c.skipReach {
				// A streaming endpoint (the SSE audit feed) never returns from
				// ServeHTTP synchronously — once past the gate it blocks until the
				// client disconnects — so the reachability probe below would hang.
				// (a) unauthenticated and (b) roleless above already prove the gate.
				return
			}
			// (d) a correctly-capable principal -> authorized (not 401/403).
			if rec := h.do(c, c.capable); rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Errorf("(d) capable %q: status=%d (denied), want authorized; body=%s",
					c.capable, rec.Code, snippet(rec))
			}
		})
	}
}

// TestAuthzMatrixCoversRegisteredRoutes is the forcing function: every route
// registered in handlers.go must have exactly one authzMatrix() entry, and no
// entry may be stale. A new mux.Handle/HandleFunc breaks this test until its
// RBAC/tenant intent is declared above.
func TestAuthzMatrixCoversRegisteredRoutes(t *testing.T) {
	registered := parseRegisteredRoutes(t)
	declared := map[string]bool{}
	for _, c := range authzMatrix() {
		if declared[c.key()] {
			t.Errorf("duplicate authorization-matrix entry %q", c.key())
		}
		declared[c.key()] = true
	}
	for r := range registered {
		if !declared[r] {
			t.Errorf("route %q is registered in handlers.go but has NO authorization-matrix entry.\n"+
				"    Declare its RBAC/tenant intent in authzMatrix() (or add it to the public/authed allowlist).", r)
		}
	}
	for d := range declared {
		if !registered[d] {
			t.Errorf("authorization-matrix entry %q matches no route registered in handlers.go "+
				"(stale — remove or fix it)", d)
		}
	}
}

// parseRegisteredRoutes extracts every "METHOD /pattern" passed to mux.Handle /
// mux.HandleFunc inside RegisterRoutes, by parsing handlers.go with go/ast.
// Conditionally-registered routes (secret/hsm/svid) are included regardless of
// their runtime guard, because the matrix declares intent, not runtime state.
func parseRegisteredRoutes(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "handlers.go", nil, 0)
	if err != nil {
		t.Fatalf("parse handlers.go: %v", err)
	}
	var reg *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == "RegisterRoutes" {
			reg = fd
			break
		}
	}
	if reg == nil {
		t.Fatal("RegisterRoutes not found in handlers.go")
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
		if pattern, err := strconv.Unquote(lit.Value); err == nil {
			out[pattern] = true
		}
		return true
	})
	if len(out) == 0 {
		t.Fatal("no routes extracted from RegisterRoutes — the AST walk is broken")
	}
	return out
}
