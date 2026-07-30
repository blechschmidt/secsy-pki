//go:build sqlite

package acme

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// These tests cover two ACME account/authorization lifecycle operations added in
// Task 152: authorization deactivation (RFC 8555 §7.5.2) and account "contact"
// validation (§7.3). The golang.org/x/crypto/acme client used by the other ACME
// tests exposes neither an authorization-deactivation call nor arbitrary contact
// values, so they drive the minimal raw-JWS client from profile_test.go — the
// same shape a real client uses. The pre-authorization helpers (newAuthz,
// solveHTTP01, withPreAuth) live in preauth_test.go.

// deactivateAuthz posts an RFC 8555 §7.5.2 deactivation to an authorization URL.
func (rc *rawClient) deactivateAuthz(authzURL string) (*http.Response, []byte) {
	rc.t.Helper()
	return rc.post(authzURL, []byte(`{"status":"deactivated"}`), false)
}

// registerContacts posts a newAccount (agreeing to any ToS) with the given
// contacts, returning the response and body. On success it records the account
// URL as the client's kid; on rejection kid is left unset. A nil slice omits the
// "contact" field entirely.
func (rc *rawClient) registerContacts(contacts []string) (*http.Response, []byte) {
	rc.t.Helper()
	req := map[string]any{"termsOfServiceAgreed": true}
	if contacts != nil {
		req["contact"] = contacts
	}
	payload, _ := json.Marshal(req)
	resp, body := rc.post(rc.dir.NewAccount, payload, true)
	if loc := resp.Header.Get("Location"); loc != "" {
		rc.kid = loc
	}
	return resp, body
}

// updateAccount posts an account-update payload to the client's account URL.
func (rc *rawClient) updateAccount(payload []byte) (*http.Response, []byte) {
	rc.t.Helper()
	return rc.post(rc.kid, payload, false)
}

// idFromURL returns the last path segment of a resource URL (its id).
func idFromURL(u string) string { return u[strings.LastIndex(u, "/")+1:] }

// TestACME_Authz_Deactivate drives the RFC 8555 §7.5.2 deactivation of a pending
// order authorization: the authorization moves to "deactivated", its challenges
// are closed out (invalid), the dependent order can no longer be fulfilled (it
// becomes invalid), and a second deactivation is idempotent.
func TestACME_Authz_Deactivate(t *testing.T) {
	env := newTestEnv(t)
	rc := newRawClient(t, env.dirURL)
	rc.register()

	domain := "deactivate.example.test"
	oresp, obody, ord, orderURL := rc.newOrder("", domain)
	if oresp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder status = %d, want 201: %s", oresp.StatusCode, obody)
	}
	if len(ord.Authorizations) != 1 {
		t.Fatalf("order has %d authorizations, want 1: %s", len(ord.Authorizations), obody)
	}
	authzURL := ord.Authorizations[0]

	// Deactivate the pending authorization.
	resp, body := rc.deactivateAuthz(authzURL)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("deactivate status = %d, want 200: %s", resp.StatusCode, body)
	}
	var az rawAuthz
	if err := json.Unmarshal(body, &az); err != nil {
		t.Fatalf("decode deactivated authz: %v (%s)", err, body)
	}
	if az.Status != "deactivated" {
		t.Fatalf("authz status = %q, want deactivated: %s", az.Status, body)
	}

	// Persisted as deactivated, with all its challenges moved to the terminal
	// "invalid" state (a deactivated authorization can no longer be validated).
	authzID := idFromURL(authzURL)
	stored, err := env.db.GetACMEAuthorization(authzID)
	if err != nil || stored == nil {
		t.Fatalf("GetACMEAuthorization(%q): %v", authzID, err)
	}
	if stored.Status != "deactivated" {
		t.Errorf("stored authz status = %q, want deactivated", stored.Status)
	}
	challs, err := env.db.ListACMEChallengesByAuthz(authzID)
	if err != nil {
		t.Fatalf("ListACMEChallengesByAuthz: %v", err)
	}
	if len(challs) == 0 {
		t.Fatal("authorization has no challenges to check")
	}
	for _, ch := range challs {
		if ch.Status != "invalid" {
			t.Errorf("challenge %s status = %q, want invalid after deactivation", ch.Type, ch.Status)
		}
	}

	// The dependent order can never become ready now — it is invalid.
	orderID := idFromURL(orderURL)
	order, err := env.db.GetACMEOrder(orderID)
	if err != nil || order == nil {
		t.Fatalf("GetACMEOrder(%q): %v", orderID, err)
	}
	if order.Status != "invalid" {
		t.Errorf("order status = %q, want invalid after its authorization was deactivated", order.Status)
	}
	// And that is visible over the wire when the client fetches the order.
	_, ob := rc.post(orderURL, nil, false)
	var fetched rawOrder
	_ = json.Unmarshal(ob, &fetched)
	if fetched.Status != "invalid" {
		t.Errorf("fetched order status = %q, want invalid: %s", fetched.Status, ob)
	}

	// Idempotent: deactivating an already-deactivated authorization returns 200.
	resp2, body2 := rc.deactivateAuthz(authzURL)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("second deactivate status = %d, want 200: %s", resp2.StatusCode, body2)
	}
	var az2 rawAuthz
	_ = json.Unmarshal(body2, &az2)
	if az2.Status != "deactivated" {
		t.Errorf("second deactivate status = %q, want deactivated", az2.Status)
	}
}

// TestACME_Authz_Deactivate_PreventsReuse confirms a deactivated authorization
// cannot be reused: after pre-authorizing an identifier to "valid" and then
// deactivating it, a new order for the same identifier must validate afresh
// (pending, with a brand-new authorization) rather than claim the deactivated one.
func TestACME_Authz_Deactivate_PreventsReuse(t *testing.T) {
	env := newTestEnv(t, withPreAuth)
	rc := newRawClient(t, env.dirURL)
	rc.register()

	domain := "reuse-after-deactivate.example.test"

	// Pre-authorize and validate the identifier to "valid".
	resp, body, authzURL := rc.newAuthz(rc.dir.NewAuthz, "dns", domain)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newAuthz status = %d, want 201: %s", resp.StatusCode, body)
	}
	rc.solveHTTP01(env, authzURL)

	// Deactivate the now-valid authorization.
	dresp, dbody := rc.deactivateAuthz(authzURL)
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("deactivate status = %d, want 200: %s", dresp.StatusCode, dbody)
	}
	var az rawAuthz
	_ = json.Unmarshal(dbody, &az)
	if az.Status != "deactivated" {
		t.Fatalf("authz status = %q, want deactivated: %s", az.Status, dbody)
	}

	// A new order for the same identifier must NOT reuse the deactivated
	// authorization: it needs fresh validation (pending) and a new authorization.
	oresp, obody, ord, _ := rc.newOrder("", domain)
	if oresp.StatusCode != http.StatusCreated {
		t.Fatalf("newOrder status = %d, want 201: %s", oresp.StatusCode, obody)
	}
	if ord.Status != "pending" {
		t.Fatalf("order status = %q, want pending (deactivated authz must not be reused): %s", ord.Status, obody)
	}
	if len(ord.Authorizations) != 1 || ord.Authorizations[0] == authzURL {
		t.Fatalf("order reused the deactivated authorization %s: %v", authzURL, ord.Authorizations)
	}
}

// TestACME_Authz_Deactivate_InvalidState confirms an authorization that has
// already resolved terminally (here, "invalid" after a failed challenge) cannot
// be deactivated: the request is rejected as malformed.
func TestACME_Authz_Deactivate_InvalidState(t *testing.T) {
	env := newTestEnv(t)
	rc := newRawClient(t, env.dirURL)
	rc.register()

	// Fail the http-01 challenge: no key authorization is published, so the
	// in-process responder 404s and validation drives the authorization to invalid.
	_, _, ord, _ := rc.newOrder("", "fail.example.test")
	authzURL := ord.Authorizations[0]
	_, ab := rc.post(authzURL, nil, false)
	var az rawAuthz
	_ = json.Unmarshal(ab, &az)
	var chURL string
	for _, ch := range az.Challenges {
		if ch.Type == "http-01" {
			chURL = ch.URL
		}
	}
	if chURL == "" {
		t.Fatalf("no http-01 challenge offered: %s", ab)
	}
	if r, b := rc.post(chURL, []byte(`{}`), false); r.StatusCode != http.StatusOK {
		t.Fatalf("accept challenge: status %d: %s", r.StatusCode, b)
	}
	rc.waitStatus(authzURL, "invalid")

	// Deactivating a terminally-invalid authorization is a malformed request.
	resp, body := rc.deactivateAuthz(authzURL)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("deactivate(invalid) status = %d, want 400: %s", resp.StatusCode, body)
	}
	var prob Problem
	_ = json.Unmarshal(body, &prob)
	if prob.Type != probMalformed {
		t.Errorf("problem type = %q, want %q: %s", prob.Type, probMalformed, body)
	}
}

// TestACME_Authz_Deactivate_MalformedUpdate confirms only status="deactivated" is
// an accepted authorization update; any other status is rejected as malformed and
// leaves the authorization untouched.
func TestACME_Authz_Deactivate_MalformedUpdate(t *testing.T) {
	env := newTestEnv(t)
	rc := newRawClient(t, env.dirURL)
	rc.register()
	_, _, ord, _ := rc.newOrder("", "malformed.example.test")
	authzURL := ord.Authorizations[0]

	resp, body := rc.post(authzURL, []byte(`{"status":"valid"}`), false)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=valid update = %d, want 400: %s", resp.StatusCode, body)
	}
	var prob Problem
	_ = json.Unmarshal(body, &prob)
	if prob.Type != probMalformed {
		t.Errorf("problem type = %q, want %q", prob.Type, probMalformed)
	}

	// The authorization is untouched — still pending.
	_, ab := rc.post(authzURL, nil, false)
	var az rawAuthz
	_ = json.Unmarshal(ab, &az)
	if az.Status != "pending" {
		t.Errorf("authz status = %q, want still pending after a rejected update", az.Status)
	}
}

// TestACME_Authz_Deactivate_WrongAccount confirms one account cannot deactivate
// another account's authorization: the request is unauthorized and the
// authorization is untouched.
func TestACME_Authz_Deactivate_WrongAccount(t *testing.T) {
	env := newTestEnv(t)
	owner := newRawClient(t, env.dirURL)
	owner.register()
	_, _, ord, _ := owner.newOrder("", "owned.example.test")
	authzURL := ord.Authorizations[0]

	other := newRawClient(t, env.dirURL)
	other.register()
	resp, body := other.deactivateAuthz(authzURL)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-account deactivate = %d, want 401: %s", resp.StatusCode, body)
	}

	// The owner's authorization is untouched.
	_, ab := owner.post(authzURL, nil, false)
	var az rawAuthz
	_ = json.Unmarshal(ab, &az)
	if az.Status != "pending" {
		t.Errorf("authz status = %q, want still pending after a cross-account attempt", az.Status)
	}
}

// TestACME_Account_ContactValidation covers newAccount "contact" validation
// (RFC 8555 §7.3): only single, header-free mailto: addresses are accepted; an
// unsupported scheme yields unsupportedContact and a malformed mailto value yields
// invalidContact.
func TestACME_Account_ContactValidation(t *testing.T) {
	env := newTestEnv(t)

	cases := []struct {
		name     string
		contacts []string
		wantType string // "" means the account should be accepted (201)
	}{
		{"valid-single", []string{"mailto:admin@example.org"}, ""},
		{"valid-two-mailboxes", []string{"mailto:a@example.org", "mailto:b@example.org"}, ""},
		{"no-contacts", []string{}, ""},
		{"unsupported-scheme-tel", []string{"tel:+1-555-1234"}, probUnsupportedContact},
		{"unsupported-scheme-https", []string{"https://example.org/hook"}, probUnsupportedContact},
		{"hfields", []string{"mailto:admin@example.org?subject=hi"}, probInvalidContact},
		{"multiple-addresses", []string{"mailto:a@example.org,b@example.org"}, probInvalidContact},
		{"not-an-email", []string{"mailto:not-an-email"}, probInvalidContact},
		{"empty-entry", []string{""}, probInvalidContact},
		{"good-then-bad", []string{"mailto:ok@example.org", "tel:123"}, probUnsupportedContact},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc := newRawClient(t, env.dirURL)
			resp, body := rc.registerContacts(tc.contacts)
			if tc.wantType == "" {
				if resp.StatusCode != http.StatusCreated {
					t.Fatalf("newAccount(%v) = %d, want 201: %s", tc.contacts, resp.StatusCode, body)
				}
				return
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("newAccount(%v) = %d, want 400: %s", tc.contacts, resp.StatusCode, body)
			}
			var prob Problem
			if err := json.Unmarshal(body, &prob); err != nil {
				t.Fatalf("decode problem: %v (%s)", err, body)
			}
			if prob.Type != tc.wantType {
				t.Errorf("problem type = %q, want %q: %s", prob.Type, tc.wantType, body)
			}
		})
	}
}

// TestACME_Account_ContactUpdate confirms a valid contact is stored on
// registration, an account-update with a bad contact is rejected without changing
// the stored set, and a good update replaces it.
func TestACME_Account_ContactUpdate(t *testing.T) {
	env := newTestEnv(t)
	rc := newRawClient(t, env.dirURL)
	resp, body := rc.registerContacts([]string{"mailto:initial@example.org"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("newAccount = %d: %s", resp.StatusCode, body)
	}
	acctID := idFromURL(rc.kid)
	if acct, err := env.db.GetACMEAccount(acctID); err != nil || acct == nil {
		t.Fatalf("GetACMEAccount: %v", err)
	} else if len(acct.Contacts) != 1 || acct.Contacts[0] != "mailto:initial@example.org" {
		t.Fatalf("stored contacts = %v, want [mailto:initial@example.org]", acct.Contacts)
	}

	// A bad contact update is rejected and does not change the stored contacts.
	bad, bbody := rc.updateAccount([]byte(`{"contact":["tel:+1-555"]}`))
	if bad.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad contact update = %d, want 400: %s", bad.StatusCode, bbody)
	}
	var prob Problem
	_ = json.Unmarshal(bbody, &prob)
	if prob.Type != probUnsupportedContact {
		t.Errorf("problem type = %q, want %q", prob.Type, probUnsupportedContact)
	}
	if again, _ := env.db.GetACMEAccount(acctID); again == nil || len(again.Contacts) != 1 || again.Contacts[0] != "mailto:initial@example.org" {
		t.Errorf("contacts changed after a rejected update: %v", again.Contacts)
	}

	// A good contact update replaces the set.
	good, gbody := rc.updateAccount([]byte(`{"contact":["mailto:updated@example.org"]}`))
	if good.StatusCode != http.StatusOK {
		t.Fatalf("good contact update = %d, want 200: %s", good.StatusCode, gbody)
	}
	if again, _ := env.db.GetACMEAccount(acctID); again == nil || len(again.Contacts) != 1 || again.Contacts[0] != "mailto:updated@example.org" {
		t.Errorf("contacts not updated: %v", again.Contacts)
	}
}
