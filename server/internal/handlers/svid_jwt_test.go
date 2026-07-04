//go:build sqlite

package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/spiffe"
)

// jwtSVIDAPI builds a software-backed API with a CA and SPIFFE JWT-SVID issuance
// enabled for the example.org trust domain, returning the API and the CA id.
func jwtSVIDAPI(t *testing.T, defaultAudience []string) (*API, string) {
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
	api := NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, "")
	api.SetSPIFFE(spiffe.NewPolicy(spiffe.PolicyConfig{TrustDomains: []string{"example.org"}}), "spiffe-svid")
	api.SetSPIFFEJWT(defaultAudience, time.Hour, 24*time.Hour)

	root, err := ca.NewManager(db, prov).InitRoot(context.Background(), ca.RootSpec{
		Label:    "jwt-svid-root",
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "JWT SVID Root", Organization: "Secsy"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	return api, root.ID
}

func postJWTSVID(t *testing.T, api *API, caID, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	api.IssueJWTSVID(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/svid/jwt", rootUser(), caID, body))
	return rec
}

// TestJWTSVIDIssueAndValidate: the endpoint mints a token that validates against
// the trust bundle it returns, with the expected subject, audience, and alg.
func TestJWTSVIDIssueAndValidate(t *testing.T) {
	api, caID := jwtSVIDAPI(t, nil)

	body, _ := json.Marshal(models.IssueJWTSVIDRequest{
		SpiffeID: "spiffe://example.org/ns/prod/sa/web",
		Audience: []string{"spiffe://example.org/ns/prod/sa/db"},
	})
	rec := postJWTSVID(t, api, caID, string(body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp models.IssueJWTSVIDResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Token == "" || resp.Bundle == "" {
		t.Fatal("response must carry both a token and the trust bundle")
	}
	if resp.SpiffeID != "spiffe://example.org/ns/prod/sa/web" || resp.TrustDomain != "example.org" {
		t.Errorf("identity = %q/%q, want spiffe://example.org/ns/prod/sa/web/example.org", resp.SpiffeID, resp.TrustDomain)
	}
	if resp.Algorithm != "ES256" {
		t.Errorf("alg = %q, want ES256", resp.Algorithm)
	}

	// The returned token validates against the returned bundle.
	res, err := spiffe.ValidateJWTSVID(resp.Token, []byte(resp.Bundle), spiffe.JWTValidationOptions{
		Audience:     "spiffe://example.org/ns/prod/sa/db",
		TrustDomains: []string{"example.org"},
	})
	if err != nil {
		t.Fatalf("returned token failed validation: %v", err)
	}
	if res.KeyID != resp.KeyID {
		t.Errorf("validated kid %q != response kid %q", res.KeyID, resp.KeyID)
	}
}

// TestJWTSVIDAudienceRequired: with no request audience and no server default,
// the endpoint refuses (a JWT-SVID must always carry an aud).
func TestJWTSVIDAudienceRequired(t *testing.T) {
	api, caID := jwtSVIDAPI(t, nil)
	body, _ := json.Marshal(models.IssueJWTSVIDRequest{SpiffeID: "spiffe://example.org/w"})
	rec := postJWTSVID(t, api, caID, string(body))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for a missing audience (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestJWTSVIDDefaultAudience: when the server configures a default audience, a
// request that omits one succeeds and the token carries the default.
func TestJWTSVIDDefaultAudience(t *testing.T) {
	api, caID := jwtSVIDAPI(t, []string{"https://api.example.org"})
	body, _ := json.Marshal(models.IssueJWTSVIDRequest{SpiffeID: "spiffe://example.org/w"})
	rec := postJWTSVID(t, api, caID, string(body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp models.IssueJWTSVIDResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Audience) != 1 || resp.Audience[0] != "https://api.example.org" {
		t.Errorf("audience = %v, want [https://api.example.org]", resp.Audience)
	}
	if _, err := spiffe.ValidateJWTSVID(resp.Token, []byte(resp.Bundle), spiffe.JWTValidationOptions{
		Audience: "https://api.example.org", TrustDomains: []string{"example.org"},
	}); err != nil {
		t.Fatalf("token with default audience failed validation: %v", err)
	}
}

// TestJWTSVIDForeignTrustDomainDenied: a trust domain outside the allowlist is
// refused (403), matching X.509-SVID behavior, and is not minted.
func TestJWTSVIDForeignTrustDomainDenied(t *testing.T) {
	api, caID := jwtSVIDAPI(t, nil)
	body, _ := json.Marshal(models.IssueJWTSVIDRequest{
		SpiffeID: "spiffe://evil.example.net/w",
		Audience: []string{"aud"},
	})
	rec := postJWTSVID(t, api, caID, string(body))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a foreign trust domain (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestJWTSVIDSuspendedTenantDenied: a suspended tenant is frozen for JWT-SVID
// issuance (403 tenant_suspended), matching the X.509-SVID tenant gate.
func TestJWTSVIDSuspendedTenantDenied(t *testing.T) {
	api, caID := jwtSVIDAPI(t, nil)
	if err := api.db.SetTenantStatus(models.DefaultTenantID, models.TenantStatusSuspended); err != nil {
		t.Fatalf("SetTenantStatus: %v", err)
	}
	body, _ := json.Marshal(models.IssueJWTSVIDRequest{
		SpiffeID: "spiffe://example.org/w",
		Audience: []string{"aud"},
	})
	rec := postJWTSVID(t, api, caID, string(body))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a suspended tenant (body=%s)", rec.Code, rec.Body.String())
	}
}
