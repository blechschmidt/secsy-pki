//go:build sqlite

package handlers

// Tests for POST /api/ca/{id}/svid/jwt/verify (Task 198).
//
// The contract under test is a round trip: a token minted by the existing
// POST /api/ca/{id}/svid/jwt must validate here, and every way a token can be
// wrong — tampered signature, wrong audience, a different CA's key, an unlisted
// trust domain — must come back as a clear, non-2xx verdict rather than a pass. It
// also asserts the response never carries key material, which matters because the
// handler holds the CA's JWKS bundle in memory to do its work.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// mintJWTSVID issues a JWT-SVID through the existing endpoint and returns the
// decoded response, so the verify tests always test against a real token.
func mintJWTSVID(t *testing.T, api *API, caID, spiffeID, audience string) models.IssueJWTSVIDResponse {
	t.Helper()
	body, err := json.Marshal(models.IssueJWTSVIDRequest{SpiffeID: spiffeID, Audience: []string{audience}})
	if err != nil {
		t.Fatalf("marshal mint request: %v", err)
	}
	rec := postJWTSVID(t, api, caID, string(body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint: status = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var resp models.IssueJWTSVIDResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	return resp
}

// postJWTSVIDVerify drives the verify handler against one CA as the given
// principal (the CA id travels as the {id} path value, as the mux supplies it).
func postJWTSVIDVerify(api *API, user *models.UserInfo, caID, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	api.VerifyJWTSVID(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/svid/jwt/verify", user, caID, body))
	return rec
}

// decodeJWTVerify decodes the verdict body.
func decodeJWTVerify(t *testing.T, rec *httptest.ResponseRecorder) VerifyJWTSVIDResponse {
	t.Helper()
	var resp VerifyJWTSVIDResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode verdict: %v (body=%s)", err, rec.Body.String())
	}
	return resp
}

// TestSVIDJWTVerifyRoundTrip is the headline proof: mint, verify, then tamper.
func TestSVIDJWTVerifyRoundTrip(t *testing.T) {
	api, caID := jwtSVIDAPI(t, nil)
	const id = "spiffe://example.org/ns/prod/sa/web"
	const aud = "spiffe://example.org/ns/prod/sa/db"
	minted := mintJWTSVID(t, api, caID, id, aud)

	rec := postJWTSVIDVerify(api, rootUser(), caID,
		`{"token":"`+minted.Token+`","audience":"`+aud+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	resp := decodeJWTVerify(t, rec)
	if !resp.Valid || resp.Reason != "" {
		t.Fatalf("verdict = %+v, want valid with no reason", resp)
	}
	if resp.SpiffeID != id || resp.TrustDomain != "example.org" || resp.Path != "/ns/prod/sa/web" {
		t.Errorf("identity = %q / %q / %q, want %q / example.org / /ns/prod/sa/web",
			resp.SpiffeID, resp.TrustDomain, resp.Path, id)
	}
	if len(resp.Audience) != 1 || resp.Audience[0] != aud {
		t.Errorf("audience = %v, want [%s]", resp.Audience, aud)
	}
	if resp.KeyID != minted.KeyID || resp.Algorithm != minted.Algorithm {
		t.Errorf("kid/alg = %q/%q, want the minted %q/%q", resp.KeyID, resp.Algorithm, minted.KeyID, minted.Algorithm)
	}
	if resp.ExpiresAt == "" {
		t.Error("expires_at must be reported: it is the claim a relying party most often needs")
	}
	if _, err := time.Parse(time.RFC3339, resp.ExpiresAt); err != nil {
		t.Errorf("expires_at %q is not RFC 3339: %v", resp.ExpiresAt, err)
	}

	// No key material, public or private, beyond the kid the token itself carries.
	if body := rec.Body.String(); strings.Contains(body, "PRIVATE") || strings.Contains(body, "\"keys\"") ||
		strings.Contains(body, "BEGIN") {
		t.Errorf("verdict must not carry key material: %s", body)
	}

	// Tampered signature: flip the last character of the JWS signature segment.
	parts := strings.Split(minted.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("minted token is not a 3-part JWS: %q", minted.Token)
	}
	// The LAST base64url character of an ES256 signature carries only the two
	// leading bits of the final byte, so several characters decode identically —
	// flip the first one instead, where all six bits are significant.
	sig := parts[2]
	flipped := byte('A')
	if sig[0] == 'A' {
		flipped = 'B'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(flipped) + sig[1:]
	bad := postJWTSVIDVerify(api, rootUser(), caID, `{"token":"`+tampered+`","audience":"`+aud+`"}`)
	if bad.Code != http.StatusConflict {
		t.Fatalf("tampered token: status = %d, want 409: %s", bad.Code, bad.Body.String())
	}
	verdict := decodeJWTVerify(t, bad)
	if verdict.Valid || verdict.Reason == "" {
		t.Fatalf("tampered verdict = %+v, want invalid with a reason", verdict)
	}
	if verdict.SpiffeID != "" {
		t.Errorf("a rejected token must not report claims as validated, got %q", verdict.SpiffeID)
	}

	// A tampered PAYLOAD (a different subject spliced in) is equally rejected.
	other := mintJWTSVID(t, api, caID, "spiffe://example.org/ns/prod/sa/other", aud)
	otherParts := strings.Split(other.Token, ".")
	spliced := parts[0] + "." + otherParts[1] + "." + parts[2]
	if rec := postJWTSVIDVerify(api, rootUser(), caID, `{"token":"`+spliced+`","audience":"`+aud+`"}`); rec.Code != http.StatusConflict {
		t.Fatalf("spliced payload: status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
}

// TestSVIDJWTVerifyAuthz: validation is a per-CA READ — it mints nothing and opens
// no key provider — so any assigned role in the CA's tenant may run it, a roleless
// principal is refused, and a principal from another tenant gets 404 (the CA's
// existence is not disclosed), exactly like every other per-CA read.
func TestSVIDJWTVerifyAuthz(t *testing.T) {
	api, caID := jwtSVIDAPI(t, nil)
	const aud = "spiffe://example.org/aud"
	minted := mintJWTSVID(t, api, caID, "spiffe://example.org/w", aud)
	body := `{"token":"` + minted.Token + `","audience":"` + aud + `"}`

	for _, tc := range []struct {
		name string
		user *models.UserInfo
		want int
	}{
		{"unauthenticated", nil, http.StatusForbidden},
		{"roleless", &models.UserInfo{Subject: "nobody"}, http.StatusForbidden},
		{"tenant auditor", tenantUser("bob", models.DefaultTenantID, "auditor"), http.StatusOK},
		{"tenant issuer", tenantUser("alice", models.DefaultTenantID, "issuer"), http.StatusOK},
		{"other tenant admin", tenantUser("eve", "other-tenant", "admin"), http.StatusNotFound},
		{"platform admin", platAdminUser(), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postJWTSVIDVerify(api, tc.user, caID, body)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}

	// An unknown CA is 404, not a 500 from a failed bundle build.
	if rec := postJWTSVIDVerify(api, rootUser(), "no-such-ca", body); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown CA: status = %d, want 404: %s", rec.Code, rec.Body.String())
	}
}

// TestSVIDJWTVerifyBadInput: the two mandatory fields are enforced with 400 —
// notably the audience, because a JWT-SVID must be rejected unless it is addressed
// to its validator, and defaulting that would quietly turn the rule off.
func TestSVIDJWTVerifyBadInput(t *testing.T) {
	api, caID := jwtSVIDAPI(t, nil)
	for _, tc := range []struct{ name, body string }{
		{"malformed JSON", `{`},
		{"no token", `{"audience":"x"}`},
		{"no audience", `{"token":"a.b.c"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := postJWTSVIDVerify(api, rootUser(), caID, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rec.Code, rec.Body.String())
			}
		})
	}
	// A syntactically impossible token is a verdict, not a request error.
	if rec := postJWTSVIDVerify(api, rootUser(), caID, `{"token":"not-a-jwt","audience":"x"}`); rec.Code != http.StatusConflict {
		t.Fatalf("garbage token: status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
}

// TestSVIDJWTVerifyWrongAudience: a token addressed elsewhere does not validate for
// this relying party, even though its signature is perfectly good.
func TestSVIDJWTVerifyWrongAudience(t *testing.T) {
	api, caID := jwtSVIDAPI(t, nil)
	minted := mintJWTSVID(t, api, caID, "spiffe://example.org/w", "spiffe://example.org/intended")

	rec := postJWTSVIDVerify(api, rootUser(), caID,
		`{"token":"`+minted.Token+`","audience":"spiffe://example.org/someone-else"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if verdict := decodeJWTVerify(t, rec); verdict.Valid {
		t.Fatal("a token not addressed to the validator must not validate")
	}
}

// TestSVIDJWTVerifyForeignCA: a token minted under one CA does not validate against
// another's trust bundle — the bundle really is the trust anchor set, not decoration.
func TestSVIDJWTVerifyForeignCA(t *testing.T) {
	api, caID := jwtSVIDAPI(t, nil)
	const aud = "spiffe://example.org/aud"
	minted := mintJWTSVID(t, api, caID, "spiffe://example.org/w", aud)

	other, err := ca.NewManager(api.db, api.keyProvider).InitRoot(context.Background(), ca.RootSpec{
		Label:    "jwt-svid-other-root",
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Other JWT SVID Root", Organization: "Secsy"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot(other): %v", err)
	}

	rec := postJWTSVIDVerify(api, rootUser(), other.ID, `{"token":"`+minted.Token+`","audience":"`+aud+`"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	verdict := decodeJWTVerify(t, rec)
	if verdict.Valid || !strings.Contains(verdict.Reason, "unknown key") {
		t.Fatalf("verdict = %+v, want invalid because the kid is not in this CA's bundle", verdict)
	}
}

// TestSVIDJWTVerifyTrustDomainNarrowing: the request's trust_domains can only
// NARROW the accepted set. Naming a different domain rejects a token this
// deployment would otherwise accept, and naming a domain the deployment's own SVID
// policy does not permit cannot make a token acceptable.
func TestSVIDJWTVerifyTrustDomainNarrowing(t *testing.T) {
	api, caID := jwtSVIDAPI(t, nil)
	const aud = "spiffe://example.org/aud"
	minted := mintJWTSVID(t, api, caID, "spiffe://example.org/w", aud)

	// Narrowing to the token's own domain still validates.
	ok := postJWTSVIDVerify(api, rootUser(), caID,
		`{"token":"`+minted.Token+`","audience":"`+aud+`","trust_domains":["example.org"]}`)
	if ok.Code != http.StatusOK {
		t.Fatalf("narrowing to the token's domain: status = %d, want 200: %s", ok.Code, ok.Body.String())
	}

	// Narrowing to a different domain rejects it.
	no := postJWTSVIDVerify(api, rootUser(), caID,
		`{"token":"`+minted.Token+`","audience":"`+aud+`","trust_domains":["other.example"]}`)
	if no.Code != http.StatusConflict {
		t.Fatalf("narrowing away the token's domain: status = %d, want 409: %s", no.Code, no.Body.String())
	}
	if verdict := decodeJWTVerify(t, no); verdict.Valid {
		t.Fatal("a trust domain outside the requested set must not validate")
	}
}
