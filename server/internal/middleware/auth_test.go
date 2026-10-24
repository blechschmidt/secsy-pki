package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// mockTokenVerifier implements TokenVerifier for testing.
type mockTokenVerifier struct {
	claims *auth.Claims
	err    error
}

func (m *mockTokenVerifier) VerifyToken(_ context.Context, _ string) (*auth.Claims, error) {
	return m.claims, m.err
}

func TestBasicAuthRoot(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserInfo(r.Context())
		if user == nil {
			t.Fatal("user is nil")
		}
		if !user.IsRoot || user.Subject != "root" {
			t.Errorf("user = %+v", user)
		}
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("root", "secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestBasicAuthWrongPassword(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("root", "wrong")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestNoAuth(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "authorization required" {
		t.Errorf("error = %q", resp["error"])
	}
}

func TestBearerNoOIDC(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer sometoken")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 503 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestInvalidAuthHeader(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Token xyz")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestGetUserInfoNil(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	user := GetUserInfo(req.Context())
	if user != nil {
		t.Error("should be nil without context")
	}
}

func TestGetUserInfoFromContext(t *testing.T) {
	mw := NewAuthMiddleware(nil, "admin", "pass")
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserInfo(r.Context())
		json.NewEncoder(w).Encode(user)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("admin", "pass")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var user models.UserInfo
	json.Unmarshal(w.Body.Bytes(), &user)
	if user.Subject != "root" {
		t.Errorf("subject = %q", user.Subject)
	}
}

func TestBearerTokenSuccess(t *testing.T) {
	verifier := &mockTokenVerifier{
		claims: &auth.Claims{
			Subject: "oidc-user-123",
			Email:   "alice@example.com",
			Name:    "Alice",
		},
	}
	mw := NewAuthMiddleware(verifier, "root", "secret")

	var capturedUser *models.UserInfo
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUser = GetUserInfo(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/cas", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if capturedUser == nil {
		t.Fatal("user is nil after successful OIDC auth")
	}
	if capturedUser.Subject != "oidc-user-123" {
		t.Errorf("Subject = %q, want %q", capturedUser.Subject, "oidc-user-123")
	}
	if capturedUser.Email != "alice@example.com" {
		t.Errorf("Email = %q, want %q", capturedUser.Email, "alice@example.com")
	}
	if capturedUser.Name != "Alice" {
		t.Errorf("Name = %q, want %q", capturedUser.Name, "Alice")
	}
	if capturedUser.IsRoot {
		t.Error("OIDC user should not be root")
	}
}

func TestBearerTokenVerificationFailure(t *testing.T) {
	verifier := &mockTokenVerifier{
		err: fmt.Errorf("token expired"),
	}
	mw := NewAuthMiddleware(verifier, "root", "secret")

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called on verification failure")
	}))

	req := httptest.NewRequest("GET", "/api/cas", nil)
	req.Header.Set("Authorization", "Bearer expired-token")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d, want 401", w.Code)
	}
	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "invalid token" {
		t.Errorf("error = %q, want %q", resp["error"], "invalid token")
	}
}

func TestBasicAuthWrongUsername(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("notroot", "secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != 401 {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// TestBearerClaimResolverIsApplied asserts the per-provider claim -> role hook
// (Task 212) runs on the Bearer path, after the central role resolvers, and that
// the verifying provider's name is carried onto the principal. Without this wiring
// a federated deployment's provider-scoped role mappings would simply never be
// consulted.
func TestBearerClaimResolverIsApplied(t *testing.T) {
	claims := &auth.Claims{
		Subject:  "repo:example-org/app:environment:release",
		Provider: "github",
		Raw:      map[string]interface{}{"sub": "repo:example-org/app:environment:release"},
	}
	mw := NewAuthMiddleware(&mockTokenVerifier{claims: claims}, "root", "secret")
	// A central resolver runs first and grants nothing...
	mw.SetRoleResolver(func(*models.UserInfo) []string { return nil })
	// ...then the provider-scoped hook unions in what that issuer's mapping grants.
	var sawProvider string
	mw.SetBearerClaimResolver(func(info *models.UserInfo, c *auth.Claims) {
		sawProvider = c.Provider
		info.Roles = append(info.Roles, "signer")
		info.Groups = []string{"workflow"}
	})

	var got *models.UserInfo
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = GetUserInfo(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer some.jwt.token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if sawProvider != "github" {
		t.Errorf("hook saw provider %q, want github", sawProvider)
	}
	if got == nil || len(got.Roles) != 1 || got.Roles[0] != "signer" {
		t.Errorf("principal = %+v, want the provider-scoped signer role", got)
	}
	if got.AuthProvider != "github" {
		t.Errorf("AuthProvider = %q, want github recorded on the principal", got.AuthProvider)
	}
	if len(got.Groups) != 1 || got.Groups[0] != "workflow" {
		t.Errorf("Groups = %v, want the IdP groups the hook resolved", got.Groups)
	}

	// The gRPC path must resolve identically — the two credential paths are meant
	// to accept the same credentials with the same authorization.
	rpcInfo, err := mw.AuthenticateRPC(context.Background(), "Bearer some.jwt.token", nil)
	if err != nil {
		t.Fatalf("AuthenticateRPC: %v", err)
	}
	if rpcInfo.AuthProvider != "github" || len(rpcInfo.Roles) != 1 || rpcInfo.Roles[0] != "signer" {
		t.Errorf("gRPC principal = %+v, want the same provider and roles as HTTP", rpcInfo)
	}
}
