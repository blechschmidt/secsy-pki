package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Task 61 middleware-level tenant handling: suspension walls off enrollment
// protocol surfaces (never OCSP/CRL), and the per-tenant tier meters with
// per-tenant overrides that are isolated between tenants and applied live.

func ok200() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// staticTenants resolves every enrollment endpoint to a fixed tenant state.
func staticTenants(states map[string]*TenantState) func(*http.Request, string) *TenantState {
	return func(r *http.Request, endpoint string) *TenantState {
		proto := endpoint
		switch {
		case len(endpoint) >= 4 && endpoint[:4] == "acme":
			proto = "acme"
		case len(endpoint) >= 3 && endpoint[:3] == "est":
			proto = "est"
		case len(endpoint) >= 4 && endpoint[:4] == "scep":
			proto = "scep"
		}
		return states[proto]
	}
}

func TestMiddlewareSuspendedTenantBlocksEnrollmentNotOCSPCRL(t *testing.T) {
	suspended := &TenantState{ID: "t-susp", Suspended: true}
	mw := New(Options{
		Prefixes:    Prefixes{ACME: "/acme", EST: "/.well-known/est", SCEP: "/scep", CMP: "/cmp"},
		TenantState: staticTenants(map[string]*TenantState{"acme": suspended, "est": suspended, "scep": suspended, "cmp": suspended}),
	})
	if !mw.Active() {
		t.Fatal("middleware with a tenant resolver must report Active")
	}
	h := mw.Handler(ok200())

	do := func(method, path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec
	}

	// Every enrollment protocol surface answers 403.
	for _, path := range []string{"/acme/new-order", "/acme/new-account", "/.well-known/est/simpleenroll", "/scep?operation=GetCACert", "/cmp"} {
		if rec := do(http.MethodPost, path); rec.Code != http.StatusForbidden {
			t.Errorf("%s under suspension = %d, want 403", path, rec.Code)
		}
	}
	// ACME rejections speak problem+json.
	if rec := do(http.MethodPost, "/acme/new-order"); rec.Header().Get("Content-Type") != "application/problem+json" {
		t.Errorf("ACME suspension Content-Type = %q, want application/problem+json", rec.Header().Get("Content-Type"))
	}

	// OCSP and CRL requests pass straight through (never tenant-blocked).
	for _, path := range []string{"/api/ca/some-ca/crl", "/api/ca/some-ca/ocsp"} {
		if rec := do(http.MethodGet, path); rec.Code != http.StatusOK {
			t.Errorf("%s under suspension = %d, want 200 (revocation status must keep flowing)", path, rec.Code)
		}
	}
}

func TestPerTenantTierWithOverrides(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := NewTieredLimiter(LimiterConfig{
		PerTenant: Rate{Rate: 1, Burst: 2}, // deployment default: burst of 2
		Now:       func() time.Time { return now },
	})

	// Tenant A inherits the default: two admits, then throttled on its tier.
	keysA := Keys{IP: "192.0.2.1", Tenant: "tenant-a"}
	for i := 0; i < 2; i++ {
		if d := limiter.Allow(keysA); !d.Allowed {
			t.Fatalf("tenant A admit %d refused: %+v", i+1, d)
		}
	}
	d := limiter.Allow(keysA)
	if d.Allowed || d.Tier != TierPerTenant {
		t.Fatalf("tenant A third request: %+v, want per_tenant throttle", d)
	}
	if d.RetryAfter <= 0 {
		t.Errorf("throttle RetryAfter = %v, want > 0", d.RetryAfter)
	}

	// Tenant B has its own bucket — unaffected by A's exhaustion.
	if d := limiter.Allow(Keys{IP: "192.0.2.1", Tenant: "tenant-b"}); !d.Allowed {
		t.Errorf("tenant B refused after A exhausted: %+v", d)
	}

	// Tenant C carries a larger override and gets its own capacity.
	keysC := Keys{IP: "192.0.2.1", Tenant: "tenant-c", TenantLimit: &Rate{Rate: 1, Burst: 4}}
	for i := 0; i < 4; i++ {
		if d := limiter.Allow(keysC); !d.Allowed {
			t.Fatalf("tenant C admit %d refused under override: %+v", i+1, d)
		}
	}
	if d := limiter.Allow(keysC); d.Allowed {
		t.Error("tenant C exceeded its override burst without a throttle")
	}

	// A zero-valued override exempts the tenant from the tier entirely.
	exempt := Keys{Tenant: "tenant-x", TenantLimit: &Rate{}}
	for i := 0; i < 10; i++ {
		if d := limiter.Allow(exempt); !d.Allowed {
			t.Fatalf("exempt tenant throttled on attempt %d: %+v", i+1, d)
		}
	}

	// Requests with no tenant skip the tier.
	for i := 0; i < 10; i++ {
		if d := limiter.Allow(Keys{IP: "198.51.100.7"}); !d.Allowed {
			t.Fatalf("tenantless request throttled by the per-tenant tier: %+v", d)
		}
	}
}

// TestPerTenantOverrideRetunesLiveBucket: changing a tenant's override applies
// to its existing bucket without a restart (the operator edits quotas live).
func TestPerTenantOverrideRetunesLiveBucket(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	limiter := NewTieredLimiter(LimiterConfig{
		PerTenant: Rate{Rate: 1, Burst: 1},
		Now:       func() time.Time { return now },
	})

	keys := Keys{Tenant: "tenant-r"}
	if d := limiter.Allow(keys); !d.Allowed {
		t.Fatalf("first admit refused: %+v", d)
	}
	if d := limiter.Allow(keys); d.Allowed {
		t.Fatal("second admit passed a burst-1 bucket")
	}

	// The operator raises the tenant's burst; the live bucket adapts. The new
	// capacity minus the token already spent admits one more immediately.
	keys.TenantLimit = &Rate{Rate: 1, Burst: 3}
	if d := limiter.Allow(keys); !d.Allowed {
		t.Fatalf("admit after raising the override refused: %+v", d)
	}
}

// TestMiddlewarePerTenantThrottleMetersEnrollment: end-to-end through the
// middleware, a tenant override throttles its enrollment surface with 429 +
// Retry-After.
func TestMiddlewarePerTenantThrottle(t *testing.T) {
	limiter := NewTieredLimiter(LimiterConfig{}) // no static tiers at all
	tenant := &TenantState{ID: "t-metered", Limit: &Rate{Rate: 0.001, Burst: 1}}
	mw := New(Options{
		Limiter:     limiter,
		Prefixes:    Prefixes{EST: "/.well-known/est"},
		TenantState: staticTenants(map[string]*TenantState{"est": tenant}),
	})
	h := mw.Handler(ok200())

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("first request = %d, want 200", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/.well-known/est/simpleenroll", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429 (override must engage without static tiers)", rec.Code)
	}
	if ra := rec.Header().Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("429 missing positive Retry-After (got %q)", ra)
	}
}
