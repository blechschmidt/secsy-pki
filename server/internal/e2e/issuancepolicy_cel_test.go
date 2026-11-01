//go:build sqlite

// End-to-end verification of the CEL issuance-restriction engine (Task 223)
// through the real HTTP stack.
//
// The unit tests prove the engine decides correctly given a fact set. What only
// an end-to-end test can prove is that the fact set is actually assembled from
// the live request: that a claim in a token the OIDC verifier accepted, the URL
// the request arrived on, and a parameter in its JSON body all reach a rule
// evaluated deep inside the signing path — and that a refusal comes back to the
// requester as a 422 naming the rule and its reason rather than as an opaque
// error.
package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

const (
	policyAudience = "secsy-policy-test"
	policySubject  = "machine@example.com"
)

// policyEnv is the wired app server plus the stub IdP whose tokens it accepts.
type policyEnv struct {
	srv  *httptest.Server
	idp  *stubIDP
	db   *database.DB
	root *models.CA
}

// setupPolicyEnv wires the server the way cmd/server does for the machine axis:
// a Bearer OIDC verifier, a claim->role mapping that makes the token's holder an
// issuer, and the full route table (so the request passes through
// celpolicy.Capture and the authentication middleware exactly as in production).
func setupPolicyEnv(t *testing.T) *policyEnv {
	t.Helper()

	idp := newStubIDP(t, policyAudience, policySubject)
	idp.groups = []string{"pki-issuers"}

	db, err := database.New("sqlite", t.TempDir()+"/policy.db")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	provider, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("software provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	bearer, provErrs := auth.NewMultiProvider(context.Background(), []auth.ProviderSpec{
		{Name: "idp", IssuerURL: idp.srv.URL, Audiences: []string{policyAudience}},
	})
	if len(provErrs) != 0 {
		t.Fatalf("NewMultiProvider: %v", provErrs)
	}

	api := handlers.NewAPI(db, provider, bearer.Primary(), hsm.Config{}, true, "")
	authMw := middleware.NewAuthMiddleware(bearer, "root", "root-pass")
	// Anyone the IdP vouches for with the pki-issuers group may issue. The policy
	// engine is what constrains WHAT they may issue — which is the separation the
	// whole feature exists to express.
	authMw.SetBearerClaimResolver(func(info *models.UserInfo, claims *auth.Claims) {
		if groups, ok := claims.Raw["groups"].([]interface{}); ok {
			for _, g := range groups {
				if s, _ := g.(string); s == "pki-issuers" {
					info.Roles = append(info.Roles, string(rbac.RoleIssuer))
					info.Groups = append(info.Groups, s)
				}
			}
		}
	})

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, authMw)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mgr := ca.NewManager(db, provider)
	root, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		Label:    "policy-e2e-root",
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Policy E2E Root", Organization: "Acme"}),
		Validity: 3 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	return &policyEnv{srv: srv, idp: idp, db: db, root: root}
}

// mintToken signs a token for this environment's IdP carrying arbitrary extra
// claims, so a test can model the entitlement vocabulary an enterprise uses.
func (e *policyEnv) mintToken(t *testing.T, extra map[string]interface{}) string {
	t.Helper()
	claims := map[string]interface{}{
		"iss":            e.idp.issuer,
		"aud":            policyAudience,
		"sub":            policySubject,
		"exp":            time.Now().Add(time.Hour).Unix(),
		"iat":            time.Now().Unix(),
		"email":          policySubject,
		"email_verified": true,
		"groups":         []string{"pki-issuers"},
	}
	for k, v := range extra {
		claims[k] = v
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := e.idp.signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize token: %v", err)
	}
	return compact
}

// do performs an authenticated request and returns the status and raw body.
func (e *policyEnv) do(t *testing.T, method, path, authorization, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}

// rootAuth is the built-in root operator's Basic credential, used to administer
// the rules (ca:configure) in tests whose subject is the token holder.
const rootAuth = "Basic cm9vdDpyb290LXBhc3M=" // root:root-pass

// addPolicy stores a rule through the REST API, as the console does.
func (e *policyEnv) addPolicy(t *testing.T, body string) celpolicy.Rule {
	t.Helper()
	code, raw := e.do(t, http.MethodPost, "/api/issuance-policies", rootAuth, body)
	if code != http.StatusCreated {
		t.Fatalf("storing the rule = %d: %s", code, raw)
	}
	var rule celpolicy.Rule
	if err := json.Unmarshal(raw, &rule); err != nil {
		t.Fatalf("decoding the stored rule: %v", err)
	}
	return rule
}

// csrFor builds a PEM CSR with the given CN and DNS names.
func csrFor(t *testing.T, cn string, dns []string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dns,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// issue asks for a certificate as the Bearer caller, returning the status and
// the decoded refusal (when there was one).
func (e *policyEnv) issue(t *testing.T, token, body string) (int, models.PolicyDeniedResponse, []byte) {
	t.Helper()
	code, raw := e.do(t, http.MethodPost, "/api/ca/"+e.root.ID+"/issue", "Bearer "+token, body)
	var denied models.PolicyDeniedResponse
	if code == http.StatusUnprocessableEntity {
		if err := json.Unmarshal(raw, &denied); err != nil {
			t.Fatalf("decoding the refusal: %v (%s)", err, raw)
		}
	}
	return code, denied, raw
}

// TestPolicyDeniesWithAReasonTheRequesterCanAct0n is the headline end-to-end
// case: a rule refuses an over-long lifetime, and the requester is told the
// number they exceeded and the rule that said so.
func TestPolicyDeniesWithAReasonTheRequesterCanActOn(t *testing.T) {
	env := setupPolicyEnv(t)
	env.addPolicy(t, `{
		"name": "max-lifetime",
		"description": "operator-set lifetime ceiling",
		"expression": "request.validity_days <= 30 ? \"\" : \"requested %d days of validity; this profile allows at most 30\".format([request.validity_days])"
	}`)
	token := env.mintToken(t, nil)
	csr := csrFor(t, "www.example.com", []string{"www.example.com"})

	body, err := json.Marshal(map[string]interface{}{"csr": csr, "profile": "server", "validity_days": 365})
	if err != nil {
		t.Fatal(err)
	}
	code, denied, raw := env.issue(t, token, string(body))
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("issue = %d, want 422: %s", code, raw)
	}
	if denied.Code != "policy_denied" {
		t.Errorf("code = %q", denied.Code)
	}
	if len(denied.Violations) != 1 {
		t.Fatalf("violations = %+v", denied.Violations)
	}
	v := denied.Violations[0]
	if v.Rule != "max-lifetime" {
		t.Errorf("rule = %q", v.Rule)
	}
	if !strings.Contains(v.Message, "requested 365 days") || !strings.Contains(v.Message, "at most 30") {
		t.Errorf("the refusal does not tell the requester what to change: %q", v.Message)
	}
	// Nothing was issued.
	if certs, err := env.db.ListIssuedCertificates(env.root.ID); err != nil || len(certs) != 0 {
		t.Fatalf("a refused request left %d certificates behind (%v)", len(certs), err)
	}

	// Asking for a permitted lifetime succeeds through the very same path.
	body, _ = json.Marshal(map[string]interface{}{"csr": csr, "profile": "server", "validity_days": 7})
	code, _, raw = env.issue(t, token, string(body))
	if code != http.StatusCreated {
		t.Fatalf("a permitted request = %d: %s", code, raw)
	}
}

// TestPolicyReadsTheVerifiedToken proves a claim from the token the OIDC
// verifier accepted reaches the rule — the authorization fact an enterprise
// actually wants to gate a wildcard on.
func TestPolicyReadsTheVerifiedToken(t *testing.T) {
	env := setupPolicyEnv(t)
	env.addPolicy(t, `{
		"name": "wildcard-entitlement",
		"expression": "!request.wildcard || (has(jwt.entitlements) && \"pki.wildcard\" in jwt.entitlements)",
		"message": "a wildcard certificate requires the pki.wildcard entitlement in your token"
	}`)
	wildcardCSR := csrFor(t, "*.example.com", []string{"*.example.com"})
	plainCSR := csrFor(t, "www.example.com", []string{"www.example.com"})

	// A token without the entitlement: the plain name issues, the wildcard does not.
	plain := env.mintToken(t, nil)
	body, _ := json.Marshal(map[string]string{"csr": plainCSR, "profile": "server"})
	if code, _, raw := env.issue(t, plain, string(body)); code != http.StatusCreated {
		t.Fatalf("a plain name = %d: %s", code, raw)
	}
	body, _ = json.Marshal(map[string]string{"csr": wildcardCSR, "profile": "server"})
	code, denied, raw := env.issue(t, plain, string(body))
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("an unentitled wildcard = %d, want 422: %s", code, raw)
	}
	if !strings.Contains(denied.Error, "pki.wildcard entitlement") {
		t.Errorf("refusal = %q", denied.Error)
	}

	// The same request with the entitlement in the token succeeds. The only thing
	// that changed is a claim inside a signed token — which is the point.
	entitled := env.mintToken(t, map[string]interface{}{"entitlements": []string{"pki.issue", "pki.wildcard"}})
	if code, _, raw := env.issue(t, entitled, string(body)); code != http.StatusCreated {
		t.Fatalf("an entitled wildcard = %d: %s", code, raw)
	}

	// A claim the requester cannot forge: the rule reads the VERIFIED claim set,
	// so stuffing the entitlement into the request body changes nothing.
	forged, _ := json.Marshal(map[string]interface{}{
		"csr": wildcardCSR, "profile": "server", "entitlements": []string{"pki.wildcard"},
	})
	if code, _, _ := env.issue(t, plain, string(forged)); code != http.StatusUnprocessableEntity {
		t.Errorf("a body-supplied entitlement satisfied a jwt rule: %d", code)
	}
}

// TestPolicyReadsTheRequestURLAndBody proves the two HTTP fact sets captured at
// the edge reach the gate: the path the request arrived on, and a parameter the
// certificate itself does not carry.
func TestPolicyReadsTheRequestURLAndBody(t *testing.T) {
	env := setupPolicyEnv(t)
	env.addPolicy(t, `{
		"name": "change-ticket",
		"expression": "has(body.reason) && string(body.reason).matches(\"^(CHG|INC)-[0-9]{4,}$\")",
		"message": "the \"reason\" parameter must name a change or incident ticket, e.g. CHG-10482",
		"priority": 10
	}`)
	env.addPolicy(t, `{
		"name": "api-path-only",
		"expression": "url.method == \"POST\" && path.matches(\"^/api/ca/[^/]+/issue$\") && url.segments.size() == 4",
		"message": "this CA only certifies requests made through the issuance endpoint",
		"priority": 20
	}`)
	token := env.mintToken(t, nil)
	csr := csrFor(t, "www.example.com", []string{"www.example.com"})

	// Without the ticket parameter: refused by the body rule, while the URL rule
	// is satisfied — so exactly one reason comes back.
	body, _ := json.Marshal(map[string]string{"csr": csr, "profile": "server"})
	code, denied, raw := env.issue(t, token, string(body))
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("a request with no ticket = %d, want 422: %s", code, raw)
	}
	if len(denied.Violations) != 1 || denied.Violations[0].Rule != "change-ticket" {
		t.Fatalf("violations = %+v; the URL rule should have been satisfied", denied.Violations)
	}

	// A malformed ticket is refused too.
	body, _ = json.Marshal(map[string]string{"csr": csr, "profile": "server", "reason": "because"})
	if code, _, _ := env.issue(t, token, string(body)); code != http.StatusUnprocessableEntity {
		t.Errorf("a malformed ticket = %d, want 422", code)
	}

	// With a well-formed ticket both rules hold and the certificate is issued —
	// proving the body parameter was read from the very request that was served,
	// and that the handler still decoded the same bytes.
	body, _ = json.Marshal(map[string]string{"csr": csr, "profile": "server", "reason": "CHG-10482"})
	code, _, raw = env.issue(t, token, string(body))
	if code != http.StatusCreated {
		t.Fatalf("a request with a valid ticket = %d: %s", code, raw)
	}
	var issued models.IssueCertResponse
	if err := json.Unmarshal(raw, &issued); err != nil {
		t.Fatalf("decoding the issuance: %v", err)
	}
	if issued.Certificate == "" || issued.Serial == "" {
		t.Error("the issuance response is incomplete, so the body capture broke the handler's decode")
	}
}

// TestPolicyReportsEveryReasonAtOnce: a requester who got three things wrong
// learns three things, rather than discovering them one retry at a time.
func TestPolicyReportsEveryReasonAtOnce(t *testing.T) {
	env := setupPolicyEnv(t)
	env.addPolicy(t, `{
		"name": "dns-suffix", "priority": 10,
		"expression": "request.dns_names.filter(d, !d.endsWith(\".example.com\")).map(d, \"DNS name \" + d + \" is outside example.com\")"
	}`)
	env.addPolicy(t, `{
		"name": "max-lifetime", "priority": 20,
		"expression": "request.validity_days <= 30", "message": "this profile allows at most 30 days"
	}`)
	env.addPolicy(t, `{
		"name": "no-wildcards", "priority": 30, "effect": "deny",
		"expression": "request.wildcard", "message": "wildcard certificates are not issued by this CA"
	}`)

	token := env.mintToken(t, nil)
	csr := csrFor(t, "*.evil.test", []string{"*.evil.test"})
	body, _ := json.Marshal(map[string]interface{}{"csr": csr, "profile": "server", "validity_days": 365})
	code, denied, raw := env.issue(t, token, string(body))
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("issue = %d, want 422: %s", code, raw)
	}
	if len(denied.Violations) != 3 {
		t.Fatalf("got %d violations, want 3: %+v", len(denied.Violations), denied.Violations)
	}
	// Priority fixes the order the requester reads them in.
	want := []string{"dns-suffix", "max-lifetime", "no-wildcards"}
	for i, name := range want {
		if denied.Violations[i].Rule != name {
			t.Fatalf("order = %+v, want %v", denied.Violations, want)
		}
	}
}

// TestPolicyMonitorModeIssuesThroughTheAPI: the rollout path, seen from the
// client — the certificate is issued and the finding is recorded.
func TestPolicyMonitorModeIssuesThroughTheAPI(t *testing.T) {
	env := setupPolicyEnv(t)
	env.addPolicy(t, `{
		"name": "future-ban", "mode": "monitor", "effect": "deny",
		"expression": "request.dns_names.exists(d, d.endsWith(\".test\"))",
		"message": "would be refused once this rule is enforced"
	}`)
	token := env.mintToken(t, nil)
	csr := csrFor(t, "www.evil.test", []string{"www.evil.test"})
	body, _ := json.Marshal(map[string]string{"csr": csr, "profile": "server"})
	if code, _, raw := env.issue(t, token, string(body)); code != http.StatusCreated {
		t.Fatalf("a monitor-mode rule blocked issuance: %d %s", code, raw)
	}
	// Switch it to enforce through the API and the next request is refused —
	// no restart, no reload.
	code, raw := env.do(t, http.MethodPut, "/api/issuance-policies/future-ban", rootAuth,
		`{"name":"future-ban","mode":"enforce","effect":"deny","expression":"request.dns_names.exists(d, d.endsWith(\".test\"))","message":"would be refused once this rule is enforced","enabled":true}`)
	if code != http.StatusOK {
		t.Fatalf("switching the rule to enforce = %d: %s", code, raw)
	}
	if code, _, _ := env.issue(t, token, string(body)); code != http.StatusUnprocessableEntity {
		t.Errorf("after switching to enforce, issue = %d, want 422", code)
	}
}

// TestPolicyPreviewAgreesWithIssuance: the dry-run endpoint must not promise an
// issuance the gate then refuses.
func TestPolicyPreviewAgreesWithIssuance(t *testing.T) {
	env := setupPolicyEnv(t)
	env.addPolicy(t, `{
		"name": "dns-suffix",
		"expression": "request.dns_names.filter(d, !d.endsWith(\".example.com\")).map(d, \"DNS name \" + d + \" is outside example.com\")"
	}`)
	token := env.mintToken(t, nil)

	for _, c := range []struct {
		cn         string
		wouldIssue bool
	}{
		{"www.example.com", true},
		{"www.evil.test", false},
	} {
		csr := csrFor(t, c.cn, []string{c.cn})
		body, _ := json.Marshal(map[string]string{"csr": csr, "profile": "server"})
		code, raw := env.do(t, http.MethodPost, "/api/ca/"+env.root.ID+"/certificates:preview", "Bearer "+token, string(body))
		if code != http.StatusOK {
			t.Fatalf("%s: preview = %d: %s", c.cn, code, raw)
		}
		var preview struct {
			WouldIssue bool `json:"would_issue"`
			Decision   string
			Gates      []struct {
				Name     string   `json:"name"`
				Status   string   `json:"status"`
				Findings []string `json:"findings"`
			} `json:"gates"`
		}
		if err := json.Unmarshal(raw, &preview); err != nil {
			t.Fatalf("decoding the preview: %v (%s)", err, raw)
		}
		if preview.WouldIssue != c.wouldIssue {
			t.Errorf("%s: preview would_issue = %v, want %v", c.cn, preview.WouldIssue, c.wouldIssue)
		}
		var gate *struct {
			Name     string   `json:"name"`
			Status   string   `json:"status"`
			Findings []string `json:"findings"`
		}
		for i := range preview.Gates {
			if preview.Gates[i].Name == "cel_policy" {
				gate = &preview.Gates[i]
			}
		}
		if gate == nil {
			t.Fatalf("%s: the preview carries no cel_policy gate", c.cn)
		}
		if c.wouldIssue && gate.Status != "pass" {
			t.Errorf("%s: gate status = %q, want pass", c.cn, gate.Status)
		}
		if !c.wouldIssue {
			if gate.Status != "fail" {
				t.Errorf("%s: gate status = %q, want fail", c.cn, gate.Status)
			}
			if len(gate.Findings) != 1 || !strings.Contains(gate.Findings[0], c.cn) {
				t.Errorf("%s: findings = %v", c.cn, gate.Findings)
			}
		}

		// And the real issuance agrees with the preview.
		code, _, _ = env.issue(t, token, string(body))
		issued := code == http.StatusCreated
		if issued != c.wouldIssue {
			t.Errorf("%s: preview said would_issue=%v but issuance returned %d", c.cn, c.wouldIssue, code)
		}
	}
}

// TestPolicyDryRunFromARealCSR covers the console's rule tester in its most
// faithful mode: the facts are derived from a real CSR under a real CA by the
// same code the gate uses.
func TestPolicyDryRunFromARealCSR(t *testing.T) {
	env := setupPolicyEnv(t)
	csr := csrFor(t, "www.example.com", []string{"www.example.com", "*.example.com"})
	body, err := json.Marshal(map[string]interface{}{
		"expression":    "!request.wildcard",
		"message":       "no wildcards",
		"csr":           csr,
		"ca_id":         env.root.ID,
		"profile":       "server",
		"validity_days": 45,
	})
	if err != nil {
		t.Fatal(err)
	}
	code, raw := env.do(t, http.MethodPost, "/api/issuance-policies/test", rootAuth, string(body))
	if code != http.StatusOK {
		t.Fatalf("dry-run = %d: %s", code, raw)
	}
	var out struct {
		Decision celpolicy.Decision `json:"decision"`
		Rules    []string           `json:"rules"`
		Input    celpolicy.Input    `json:"input"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decoding the dry-run: %v (%s)", err, raw)
	}
	if out.Decision.Allowed {
		t.Fatalf("the dry-run allowed a wildcard: %+v", out.Decision)
	}
	if out.Decision.Violations[0].Message != "no wildcards" {
		t.Errorf("violation = %+v", out.Decision.Violations[0])
	}
	// The echoed facts must be the ones the gate would see, derived from the CSR
	// and the CA rather than from the request JSON.
	if out.Input.Request.CA.ID != env.root.ID || out.Input.Request.CA.Label != env.root.Label {
		t.Errorf("the echoed CA facts are wrong: %+v", out.Input.Request.CA)
	}
	if len(out.Input.Request.DNSNames) != 2 || !out.Input.Request.Wildcard {
		t.Errorf("the echoed SAN facts are wrong: %+v", out.Input.Request)
	}
	if out.Input.Request.ValidityDays != 45 {
		t.Errorf("validity_days = %d, want 45", out.Input.Request.ValidityDays)
	}
	if out.Input.Request.Key.Algorithm != "ECDSA" || out.Input.Request.Key.Fingerprint == "" {
		t.Errorf("the echoed key facts are wrong: %+v", out.Input.Request.Key)
	}
}

// TestPolicyReferenceIsServedToTheConsole: the console renders the vocabulary
// from the server, so the reference an operator reads cannot drift from the
// environment their rule is compiled in.
func TestPolicyReferenceIsServedToTheConsole(t *testing.T) {
	env := setupPolicyEnv(t)
	code, raw := env.do(t, http.MethodGet, "/api/issuance-policies/reference", rootAuth, "")
	if code != http.StatusOK {
		t.Fatalf("reference = %d: %s", code, raw)
	}
	var ref celpolicy.Reference
	if err := json.Unmarshal(raw, &ref); err != nil {
		t.Fatalf("decoding the reference: %v", err)
	}
	seen := map[string]bool{}
	for _, v := range ref.Variables {
		seen[v.Name] = true
	}
	for _, want := range []string{"request", "jwt", "url", "path", "body", "principal", "now"} {
		if !seen[want] {
			t.Errorf("the reference omits the %q variable", want)
		}
	}
	if len(ref.Examples) < 5 {
		t.Errorf("the reference offers only %d examples", len(ref.Examples))
	}
	// Every example must be storable and immediately usable.
	for i, ex := range ref.Examples {
		body, err := json.Marshal(map[string]interface{}{
			"name":       fmt.Sprintf("ref-example-%d", i),
			"expression": ex.Expression,
			"effect":     ex.Effect,
			"message":    ex.Message,
			"enabled":    false,
		})
		if err != nil {
			t.Fatal(err)
		}
		if code, raw := env.do(t, http.MethodPost, "/api/issuance-policies", rootAuth, string(body)); code != http.StatusCreated {
			t.Errorf("example %q could not be stored: %d %s", ex.Title, code, raw)
		}
	}
}

// TestPolicyEditingIsRestrictedToConfigurators: an issuer may read the rules
// that constrain them but not rewrite them.
func TestPolicyEditingIsRestrictedToConfigurators(t *testing.T) {
	env := setupPolicyEnv(t)
	env.addPolicy(t, `{"name":"existing","expression":"true"}`)
	token := "Bearer " + env.mintToken(t, nil)

	if code, _ := env.do(t, http.MethodGet, "/api/issuance-policies", token, ""); code != http.StatusOK {
		t.Errorf("an issuer may not read the rules: %d", code)
	}
	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/issuance-policies", `{"name":"x","expression":"true"}`},
		{http.MethodPut, "/api/issuance-policies/existing", `{"name":"existing","expression":"false"}`},
		{http.MethodPut, "/api/issuance-policies/existing/enabled", `{"enabled":false}`},
		{http.MethodDelete, "/api/issuance-policies/existing", ""},
	} {
		if code, raw := env.do(t, c.method, c.path, token, c.body); code != http.StatusForbidden {
			t.Errorf("%s %s as an issuer = %d, want 403: %s", c.method, c.path, code, raw)
		}
	}
	// The rule is untouched.
	rule, err := env.db.GetCELPolicyRuleByName("existing")
	if err != nil || rule == nil || rule.Expression != "true" || !rule.Enabled {
		t.Errorf("a denied write took effect: %+v (%v)", rule, err)
	}
}
