//go:build sqlite

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/profiling"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// pprofVerifier is a minimal TokenVerifier that resolves any bearer token to a
// fixed subject, so the role resolver can assign it test roles.
type pprofVerifier struct{ subject string }

func (v *pprofVerifier) VerifyToken(_ context.Context, _ string) (*auth.Claims, error) {
	return &auth.Claims{Subject: v.subject}, nil
}

// buildPProfGate constructs the exact gate wiring cmd/server uses for the
// "authenticated" pprof mode — authMw.Authenticate over
// profiling.AccessControlled(handler, api.Can(server:profile)) — with a real API
// so the RBAC decision under test is the production one, not a stub.
func buildPProfGate(t *testing.T, subjectRoles map[string][]string) http.Handler {
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

	authMw := middleware.NewAuthMiddleware(&pprofVerifier{subject: "op"}, "root", "s3cret")
	authMw.SetRoleResolver(func(u *models.UserInfo) []string { return subjectRoles[u.Subject] })

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PROFILE-DATA"))
	})
	return authMw.Authenticate(profiling.AccessControlled(inner, func(r *http.Request) bool {
		return api.Can(middleware.GetUserInfo(r.Context()), rbac.ActionProfile)
	}))
}

// TestPProfGateEndToEnd exercises the full authenticated-mode gate: an
// unauthenticated caller is rejected before any RBAC check, a principal without
// the admin-only server:profile capability gets 403, and only root/admin reach
// the profiler. This is the trust boundary the task requires be verified — a heap
// profile can contain in-flight secrets, so a non-admin must never reach it.
func TestPProfGateEndToEnd(t *testing.T) {
	cases := []struct {
		name      string
		roles     []string // roles assigned to subject "op"
		auth      func(*http.Request)
		wantCode  int
		wantReach bool
	}{
		{
			name:     "anonymous is 401 (never reaches RBAC or profiler)",
			auth:     func(*http.Request) {},
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "issuer lacks server:profile -> 403",
			roles:    []string{string(rbac.RoleIssuer)},
			auth:     func(r *http.Request) { r.Header.Set("Authorization", "Bearer t") },
			wantCode: http.StatusForbidden,
		},
		{
			name:     "auditor lacks server:profile -> 403",
			roles:    []string{string(rbac.RoleAuditor)},
			auth:     func(r *http.Request) { r.Header.Set("Authorization", "Bearer t") },
			wantCode: http.StatusForbidden,
		},
		{
			name:      "admin holds server:profile -> 200",
			roles:     []string{string(rbac.RoleAdmin)},
			auth:      func(r *http.Request) { r.Header.Set("Authorization", "Bearer t") },
			wantCode:  http.StatusOK,
			wantReach: true,
		},
		{
			name:      "root superuser -> 200",
			auth:      func(r *http.Request) { r.SetBasicAuth("root", "s3cret") },
			wantCode:  http.StatusOK,
			wantReach: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gate := buildPProfGate(t, map[string][]string{"op": tc.roles})
			req := httptest.NewRequest(http.MethodGet, "/debug/pprof/heap", nil)
			tc.auth(req)
			rec := httptest.NewRecorder()
			gate.ServeHTTP(rec, req)

			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tc.wantCode, rec.Body.String())
			}
			reached := rec.Body.String() == "PROFILE-DATA"
			if reached != tc.wantReach {
				t.Errorf("profiler reached = %v, want %v", reached, tc.wantReach)
			}
		})
	}
}
