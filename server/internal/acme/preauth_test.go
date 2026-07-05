//go:build sqlite

package acme

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"testing"
)

// These tests cover ACME pre-authorization (Task 134, RFC 8555 §7.4.1). The
// golang.org/x/crypto/acme client used by the other ACME tests has no notion of a
// newAuthz resource, so they drive the minimal raw-JWS client from profile_test.go
// — the same shape a pre-authorization-aware client uses.

// withPreAuth enables the optional pre-authorization flow on the test server.
func withPreAuth(cfg *Config) { cfg.PreAuthorization = true }

// newAuthz sends a pre-authorization request for a single identifier to the given
// newAuthz URL and returns the response, body, and the authorization URL from the
// Location header.
func (rc *rawClient) newAuthz(url, idType, value string) (*http.Response, []byte, string) {
	rc.t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"identifier": map[string]string{"type": idType, "value": value},
	})
	resp, body := rc.post(url, payload, false)
	return resp, body, resp.Header.Get("Location")
}

// solveHTTP01 POST-as-GETs an authorization, satisfies its http-01 challenge
// against the in-process responder, accepts it, and waits for the authorization to
// become valid.
func (rc *rawClient) solveHTTP01(env *testEnv, authzURL string) {
	rc.t.Helper()
	tp := rc.thumbprint()
	_, ab := rc.post(authzURL, nil, false) // POST-as-GET
	var az rawAuthz
	if err := json.Unmarshal(ab, &az); err != nil {
		rc.t.Fatalf("decode authz: %v (%s)", err, ab)
	}
	var chURL, token string
	for _, ch := range az.Challenges {
		if ch.Type == "http-01" {
			chURL, token = ch.URL, ch.Token
		}
	}
	if chURL == "" {
		rc.t.Fatalf("no http-01 challenge offered: %s", ab)
	}
	env.httpMu.Lock()
	env.httpResp[token] = keyAuthorization(token, tp)
	env.httpMu.Unlock()
	if r, b := rc.post(chURL, []byte(`{}`), false); r.StatusCode != http.StatusOK {
		rc.t.Fatalf("accept challenge: status %d: %s", r.StatusCode, b)
	}
	rc.waitStatus(authzURL, "valid")
}

// TestACME_PreAuthorization_ReuseInOrder drives the full pre-authorization flow
// (RFC 8555 §7.4.1): pre-authorize an identifier via newAuthz, validate it to
// "valid", then place a newOrder for the same identifier and confirm the server
// reuses the existing authorization — the order is immediately "ready" (no new
// challenge to solve) and finalize issues a certificate.
func TestACME_PreAuthorization_ReuseInOrder(t *testing.T) {
	env := newTestEnv(t, withPreAuth)
	rc := newRawClient(t, env.dirURL)
	rc.register()

	// The directory must advertise the newAuthz resource when enabled.
	if rc.dir.NewAuthz == "" {
		t.Fatal("directory does not advertise newAuthz with pre-authorization enabled")
	}

	domain := "preauth.example.test"

	// 1. Pre-authorize the identifier.
	resp, body, authzURL := rc.newAuthz(rc.dir.NewAuthz, "dns", domain)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newAuthz status = %d, want 201: %s", resp.StatusCode, body)
	}
	if authzURL == "" {
		t.Fatal("newAuthz did not return a Location (authorization URL)")
	}
	var preAuthz rawAuthz
	if err := json.Unmarshal(body, &preAuthz); err != nil {
		t.Fatalf("decode pre-authorization: %v (%s)", err, body)
	}
	if preAuthz.Status != "pending" {
		t.Fatalf("pre-authorization status = %q, want pending", preAuthz.Status)
	}
	// It must be standalone: created with no owning order until claimed.
	authzID := authzURL[strings.LastIndex(authzURL, "/")+1:]
	stored, err := env.db.GetACMEAuthorization(authzID)
	if err != nil || stored == nil {
		t.Fatalf("GetACMEAuthorization(%q): %v", authzID, err)
	}
	if stored.OrderID != "" {
		t.Fatalf("pre-authorization is bound to order %q, want standalone", stored.OrderID)
	}

	// 2. Validate the pre-authorization to "valid".
	rc.solveHTTP01(env, authzURL)

	// 3. newOrder for the same identifier must reuse the pre-authorization: the
	//    order is ready immediately, and its single authorization URL is the very
	//    one we pre-authorized (proving no fresh authorization was created).
	oresp, obody, ord, orderURL := rc.newOrder("", domain)
	if oresp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder status = %d, want 201: %s", oresp.StatusCode, obody)
	}
	if ord.Status != "ready" {
		t.Fatalf("order status = %q, want ready (pre-authorization not reused): %s", ord.Status, obody)
	}
	if len(ord.Authorizations) != 1 || ord.Authorizations[0] != authzURL {
		t.Fatalf("order authorizations = %v, want the reused [%s]", ord.Authorizations, authzURL)
	}

	// The claimed authorization must now belong to the order.
	if claimed, _ := env.db.GetACMEAuthorization(authzID); claimed == nil || claimed.OrderID == "" {
		t.Fatalf("reused authorization was not claimed by the order: %+v", claimed)
	}
	// And no duplicate authorization was created for the order.
	authzs, err := env.db.ListACMEAuthorizationsByOrder(orderURL[strings.LastIndex(orderURL, "/")+1:])
	if err != nil {
		t.Fatalf("ListACMEAuthorizationsByOrder: %v", err)
	}
	if len(authzs) != 1 || authzs[0].ID != authzID {
		t.Fatalf("order has authorizations %+v, want exactly the reused %s", authzs, authzID)
	}

	// 4. Finalize succeeds without any further validation.
	csr := base64.RawURLEncoding.EncodeToString(csrFor(t, domain))
	fresp, fbody := rc.post(ord.Finalize, []byte(`{"csr":"`+csr+`"}`), false)
	if fresp.StatusCode != http.StatusOK {
		t.Fatalf("finalize status = %d, want 200: %s", fresp.StatusCode, fbody)
	}
	var finalized rawOrder
	if err := json.Unmarshal(fbody, &finalized); err != nil {
		t.Fatalf("decode finalized order: %v", err)
	}
	if finalized.Status != "valid" || finalized.Certificate == "" {
		t.Fatalf("finalized order = %+v, want valid with a certificate URL", finalized)
	}

	// The issued leaf must chain to the test roots.
	_, chain := rc.post(finalized.Certificate, nil, false)
	block, _ := pem.Decode(chain)
	if block == nil {
		t.Fatalf("certificate response is not PEM: %s", chain)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: env.roots, Intermediates: env.inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
	if leaf.DNSNames[0] != domain {
		t.Fatalf("leaf DNS name = %v, want %q", leaf.DNSNames, domain)
	}
}

// TestACME_PreAuthorization_Disabled confirms that when pre-authorization is not
// enabled the newAuthz resource is absent from the directory and a direct POST is
// rejected with a 404 carrying an ACME (urn:ietf:params:acme:error) problem
// document — not the framework's plain-text 404.
func TestACME_PreAuthorization_Disabled(t *testing.T) {
	env := newTestEnv(t) // pre-authorization off
	rc := newRawClient(t, env.dirURL)
	rc.register()

	if rc.dir.NewAuthz != "" {
		t.Fatalf("directory advertises newAuthz while disabled: %q", rc.dir.NewAuthz)
	}

	// The route is still mounted, so a direct POST answers with an ACME problem.
	url := env.baseURL + "/acme/new-authz"
	resp, body, _ := rc.newAuthz(url, "dns", "nope.example.test")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("disabled newAuthz status = %d, want 404: %s", resp.StatusCode, body)
	}
	var prob Problem
	if err := json.Unmarshal(body, &prob); err != nil {
		t.Fatalf("disabled newAuthz did not return a JSON problem: %v (%s)", err, body)
	}
	if !strings.HasPrefix(prob.Type, "urn:ietf:params:acme:error:") {
		t.Errorf("problem type = %q, want a urn:ietf:params:acme:error:* type", prob.Type)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}
}

// TestACME_PreAuthorization_UnsupportedIdentifier confirms newAuthz rejects an
// identifier type the server does not support with the unsupportedIdentifier
// problem, and rejects a wildcard identifier (which cannot be pre-authorized).
func TestACME_PreAuthorization_UnsupportedIdentifier(t *testing.T) {
	env := newTestEnv(t, withPreAuth)
	rc := newRawClient(t, env.dirURL)
	rc.register()

	// An unknown identifier type is unsupported.
	resp, body, _ := rc.newAuthz(rc.dir.NewAuthz, "carrier-pigeon", "roost.example.test")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("newAuthz(unsupported type) status = %d, want 400: %s", resp.StatusCode, body)
	}
	var prob Problem
	_ = json.Unmarshal(body, &prob)
	if prob.Type != probUnsupportedID {
		t.Errorf("problem type = %q, want %q", prob.Type, probUnsupportedID)
	}

	// IP identifiers are unsupported unless explicitly enabled.
	if resp, body, _ := rc.newAuthz(rc.dir.NewAuthz, "ip", "192.0.2.10"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("newAuthz(ip, disabled) status = %d, want 400: %s", resp.StatusCode, body)
	}

	// A wildcard cannot be pre-authorized (the wildcard is not part of the
	// identifier, RFC 8555 §7.4.1).
	wresp, wbody, _ := rc.newAuthz(rc.dir.NewAuthz, "dns", "*.example.test")
	if wresp.StatusCode != http.StatusBadRequest {
		t.Fatalf("newAuthz(wildcard) status = %d, want 400: %s", wresp.StatusCode, wbody)
	}
	var wprob Problem
	_ = json.Unmarshal(wbody, &wprob)
	if wprob.Type != probRejectedID {
		t.Errorf("wildcard problem type = %q, want %q", wprob.Type, probRejectedID)
	}
}
