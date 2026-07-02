package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func TestRoleResolverPopulatesRoles(t *testing.T) {
	verifier := &mockTokenVerifier{claims: &auth.Claims{Subject: "sub-1", Email: "a@x.io", Name: "A"}}
	mw := NewAuthMiddleware(verifier, "root", "secret")
	mw.SetRoleResolver(func(u *models.UserInfo) []string {
		if u.Subject == "sub-1" {
			return []string{"issuer", "auditor"}
		}
		return nil
	})

	var captured *models.UserInfo
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = GetUserInfo(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer tok")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if captured == nil {
		t.Fatal("no user captured")
	}
	if len(captured.Roles) != 2 || captured.Roles[0] != "issuer" {
		t.Errorf("roles = %v, want [issuer auditor]", captured.Roles)
	}
}

func TestRootLoginDisabled(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")
	mw.SetRootEnabled(false)

	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not run when root login is disabled")
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("root", "secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

func TestRootLoginEnabledByDefault(t *testing.T) {
	mw := NewAuthMiddleware(nil, "root", "secret")
	// No SetRootEnabled call — default must remain enabled (backward compatible).
	handler := mw.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.SetBasicAuth("root", "secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
