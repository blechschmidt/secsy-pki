package ratelimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Task 70: the bulk-revocation endpoint is an authenticated internal path and
// must never be throttled or tenant-blocked — mass revocation races the CA/B
// Forum 24-hour key-compromise clock, and the public rate limiter exists to
// protect the HSM from anonymous traffic, not to slow incident response.
func TestBulkRevocationPathIsExemptFromRateLimiting(t *testing.T) {
	// The tightest possible limiter: one request total, everything else 429s…
	limiter := NewTieredLimiter(LimiterConfig{
		Global: Rate{Rate: 0.0001, Burst: 1},
		PerIP:  Rate{Rate: 0.0001, Burst: 1},
	})
	suspended := &TenantState{ID: "t-susp", Suspended: true}
	mw := New(Options{
		Limiter:  limiter,
		Prefixes: Prefixes{ACME: "/acme", EST: "/.well-known/est", SCEP: "/scep", TSA: "/tsa", CMP: "/cmp", Sign: "/api/sign"},
		TenantState: func(r *http.Request, endpoint string) *TenantState {
			return suspended
		},
	})
	h := mw.Handler(ok200())

	// …and it engages: a public endpoint is exhausted after one admit.
	first := httptest.NewRecorder()
	h.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/api/ca/x/crl", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first public request = %d, want 200", first.Code)
	}
	second := httptest.NewRecorder()
	h.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/api/ca/x/crl", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second public request = %d, want 429 (limiter must be engaged for this test to mean anything)", second.Code)
	}

	// The bulk-revocation path passes through untouched every time, even with
	// the limiter exhausted and the resolver claiming a suspended tenant.
	for i := 0; i < 20; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/ca/x/revocations:bulk", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("bulk revocation attempt %d = %d, want 200 (path must not be classified)", i+1, rec.Code)
		}
	}

	// The single-revoke admin path is equally unclassified.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/ca/x/revoke", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("single revoke = %d, want 200", rec.Code)
	}
}
