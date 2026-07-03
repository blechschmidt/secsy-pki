package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// fakeTokenLookup is an in-memory authn.TokenLookup for middleware tests.
type fakeTokenLookup struct {
	byHash map[string]*models.APIToken
}

func (f *fakeTokenLookup) GetAPITokenByHash(hash string) (*models.APIToken, error) {
	return f.byHash[hash], nil
}
func (f *fakeTokenLookup) TouchAPIToken(id string, at time.Time, ip string) error { return nil }

func tokenMiddleware(tok *models.APIToken) (*AuthMiddleware, string) {
	secret, hash, prefix := authn.GenerateToken()
	if tok != nil {
		tok.TokenHash = hash
		tok.Prefix = prefix
	}
	store := &fakeTokenLookup{byHash: map[string]*models.APIToken{}}
	if tok != nil {
		store.byHash[hash] = tok
	}
	mw := NewAuthMiddleware(nil, "root", "secret")
	mw.SetTokenAuthenticator(authn.NewTokenAuthenticator(store))
	return mw, secret
}

func TestTokenAuthHTTPSuccess(t *testing.T) {
	tok := &models.APIToken{
		ID: "svc-1", TenantID: "acme", Name: "ci",
		Roles: []string{"issuer"}, Scope: models.TokenScopeTenant,
		CreatedAt: time.Now().Add(-time.Hour),
	}
	mw, secret := tokenMiddleware(tok)

	var got *models.UserInfo
	h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = GetUserInfo(r.Context())
		w.WriteHeader(200)
	}))

	// Canonical distinct scheme.
	req := httptest.NewRequest("GET", "/api/keys", nil)
	req.Header.Set("Authorization", "Token "+secret)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("Token scheme: status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if got == nil || got.Subject != "token:svc-1" {
		t.Fatalf("principal = %+v", got)
	}
	if len(got.TenantRoles["acme"]) != 1 || got.TenantRoles["acme"][0] != "issuer" {
		t.Fatalf("tenant roles = %v", got.TenantRoles)
	}

	// Bearer convenience form (prefix disambiguates).
	req = httptest.NewRequest("GET", "/api/keys", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("Bearer secsy_pat_: status = %d, want 200", w.Code)
	}
}

func TestTokenAuthHTTPFailClosed(t *testing.T) {
	now := time.Now()
	expired := now.Add(-time.Minute)
	revoked := now.Add(-time.Minute)

	cases := []struct {
		name string
		tok  *models.APIToken
	}{
		{"expired", &models.APIToken{ID: "e", Scope: models.TokenScopeTenant, Roles: []string{"issuer"}, ExpiresAt: &expired}},
		{"revoked", &models.APIToken{ID: "r", Scope: models.TokenScopeTenant, Roles: []string{"issuer"}, RevokedAt: &revoked}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mw, secret := tokenMiddleware(tc.tok)
			h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Fatal("handler must not run for an invalid token")
			}))
			req := httptest.NewRequest("GET", "/api/keys", nil)
			req.Header.Set("Authorization", "Token "+secret)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != 401 {
				t.Fatalf("%s: status = %d, want 401", tc.name, w.Code)
			}
			var resp map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if resp["error"] != "invalid api token" {
				t.Fatalf("%s: error = %q", tc.name, resp["error"])
			}
		})
	}
}

func TestTokenAuthHTTPUnknown(t *testing.T) {
	mw, _ := tokenMiddleware(nil) // authenticator installed, but no matching token
	h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run")
	}))
	req := httptest.NewRequest("GET", "/api/keys", nil)
	req.Header.Set("Authorization", "Token "+authn.TokenSecretPrefix+"bogus")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestTokenSchemeIgnoredWhenDisabled(t *testing.T) {
	// With no token authenticator installed, a Token-scheme header is just an
	// unrecognized credential (401), never a 503 — preserving prior behavior.
	mw := NewAuthMiddleware(nil, "root", "secret")
	h := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run")
	}))
	req := httptest.NewRequest("GET", "/api/keys", nil)
	req.Header.Set("Authorization", "Token "+authn.TokenSecretPrefix+"whatever")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestTokenAuthRPC(t *testing.T) {
	tok := &models.APIToken{
		ID: "svc-2", Scope: models.TokenScopePlatform, Name: "platform-bot",
		Roles: []string{"admin"}, CreatedAt: time.Now().Add(-time.Hour),
	}
	mw, secret := tokenMiddleware(tok)

	info, err := mw.AuthenticateRPC(context.Background(), "Token "+secret, nil)
	if err != nil {
		t.Fatalf("AuthenticateRPC: %v", err)
	}
	if info.Subject != "token:svc-2" || len(info.Roles) != 1 || info.Roles[0] != "admin" {
		t.Fatalf("platform token principal = %+v", info)
	}

	// A bogus token fails closed with ErrInvalidCredentials.
	if _, err := mw.AuthenticateRPC(context.Background(), "Token "+authn.TokenSecretPrefix+"bad", nil); err != ErrInvalidCredentials {
		t.Fatalf("bad RPC token: err = %v, want ErrInvalidCredentials", err)
	}
}
