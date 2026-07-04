package profiling

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAccessControlledDeniesUnauthorized proves the gate fails closed: a request
// the authorizer rejects gets 403 and the wrapped profiler is never reached.
func TestAccessControlledDeniesUnauthorized(t *testing.T) {
	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	gated := AccessControlled(inner, func(*http.Request) bool { return false })

	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/heap", nil))

	if reached {
		t.Fatal("profiler handler must NOT run for an unauthorized request")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "server:profile") {
		t.Errorf("403 body should name the required capability, got %q", rec.Body.String())
	}
}

// TestAccessControlledNilAuthorizerDenies proves a missing authorizer denies
// everything (fail-closed default), so a wiring mistake never exposes profiling.
func TestAccessControlledNilAuthorizerDenies(t *testing.T) {
	gated := AccessControlled(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler must not run with a nil authorizer")
	}), nil)

	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// TestAccessControlledAllowsAuthorized proves an authorized request reaches the
// profiler and the authorizer sees the real request (so it can inspect context).
func TestAccessControlledAllowsAuthorized(t *testing.T) {
	var sawPath string
	gated := AccessControlled(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }),
		func(r *http.Request) bool { sawPath = r.URL.Path; return true },
	)

	rec := httptest.NewRecorder()
	gated.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/debug/pprof/goroutine", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if sawPath != "/debug/pprof/goroutine" {
		t.Errorf("authorizer saw path %q, want /debug/pprof/goroutine", sawPath)
	}
}

// TestHandlerServesProfiles proves Handler() serves the pprof index and the named
// profiles an operator needs (heap, goroutine) without touching
// http.DefaultServeMux.
func TestHandlerServesProfiles(t *testing.T) {
	h := Handler()
	for _, path := range []string{"/debug/pprof/", "/debug/pprof/heap?debug=1", "/debug/pprof/goroutine?debug=1"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status = %d, want 200", path, rec.Code)
		}
		if rec.Body.Len() == 0 {
			t.Errorf("GET %s: empty body", path)
		}
	}
}

// TestHandlerIsDedicatedMux proves Handler() returns its OWN mux, distinct from
// http.DefaultServeMux. The stdlib net/http/pprof init unavoidably registers on
// DefaultServeMux when imported, so the safety property is not "DefaultServeMux is
// clean" but "our profiling handler is a separate mux we mount only where gated",
// which is what lets the server never serve DefaultServeMux.
func TestHandlerIsDedicatedMux(t *testing.T) {
	h := Handler()
	if _, isMux := h.(*http.ServeMux); !isMux {
		t.Fatalf("Handler() returned %T, want a dedicated *http.ServeMux", h)
	}
	if h == http.Handler(http.DefaultServeMux) {
		t.Fatal("Handler() must not be http.DefaultServeMux")
	}
}
