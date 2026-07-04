//go:build sqlite

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
)

// TestSetupPProfAuthenticatedMountNoConflict is a regression test for the Go 1.22+
// ServeMux pattern conflict: a method-agnostic "/debug/pprof/" collides with the
// app's "GET /" static catch-all (neither is more specific) and panics at startup.
// setupPProf must register method-specific patterns so it composes with "GET /".
// The test also confirms the real gate is wired: anonymous is 401, root reaches
// the profiler (200), and the catch-all still serves other paths.
func TestSetupPProfAuthenticatedMountNoConflict(t *testing.T) {
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	api := handlers.NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, "")
	authMw := middleware.NewAuthMiddleware(nil, "root", "pw")

	mux := http.NewServeMux()
	// The "GET /" static catch-all that the dev tree registers (web/static present).
	mux.Handle("GET /", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("SITE"))
	}))

	cfg := &config.Config{}
	cfg.Server.PProf = config.PProfConfig{Enabled: true, Mode: config.PProfModeAuthenticated}

	// Before the fix this panicked with a pattern conflict.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("setupPProf panicked mounting on a mux with GET /: %v", r)
		}
	}()
	setupPProf(cfg, authMw, api, mux)

	// Anonymous → 401 (auth runs before the capability check).
	if code := doGet(mux, "/debug/pprof/heap", ""); code != http.StatusUnauthorized {
		t.Errorf("anonymous /debug/pprof/heap = %d, want 401", code)
	}
	// Root superuser holds server:profile → 200.
	if code := doGet(mux, "/debug/pprof/heap", "root:pw"); code != http.StatusOK {
		t.Errorf("root /debug/pprof/heap = %d, want 200", code)
	}
	// The static catch-all still works — profiling did not shadow it.
	if code := doGet(mux, "/", ""); code != http.StatusOK {
		t.Errorf("GET / (catch-all) = %d, want 200", code)
	}
}

// doGet issues a GET against the mux, optionally with basic-auth creds
// ("user:pass"), and returns the status code.
func doGet(h http.Handler, path, basicAuth string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if basicAuth != "" {
		for i := 0; i < len(basicAuth); i++ {
			if basicAuth[i] == ':' {
				req.SetBasicAuth(basicAuth[:i], basicAuth[i+1:])
				break
			}
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}
