package ratelimit

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// okHandler records how many requests reached it and echoes any body so body
// restoration can be verified.
type okHandler struct {
	mu   sync.Mutex
	hits int
	body string
}

func (h *okHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.hits++
	h.body = string(b)
	h.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "ok")
}

func (h *okHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits
}

func testPrefixes() Prefixes {
	return Prefixes{ACME: "/acme", EST: "/.well-known/est", SCEP: "/scep"}
}

func TestMiddlewarePassesThroughUnmatched(t *testing.T) {
	clk := newFakeClock()
	// A limiter tight enough to reject everything if it applied.
	l := NewTieredLimiter(LimiterConfig{Global: Rate{Rate: 0.0001, Burst: 1}, Now: clk.now})
	m := New(Options{Limiter: l, Prefixes: testPrefixes()})
	next := &okHandler{}
	h := m.Handler(next)

	// Admin API and console paths are not public endpoints and must never be
	// rate limited, even though the global bucket is essentially empty.
	for _, path := range []string{"/api/ca/abc/issue", "/console/", "/api/health", "/metrics"} {
		for i := 0; i < 5; i++ {
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("path %s: status %d, want 200 (should not be limited)", path, rr.Code)
			}
		}
	}
}

func TestMiddlewareThrottlesOCSPPerIP(t *testing.T) {
	clk := newFakeClock()
	l := NewTieredLimiter(LimiterConfig{PerIP: Rate{Rate: 1, Burst: 2}, Now: clk.now})
	m := New(Options{Limiter: l, Prefixes: testPrefixes()})
	next := &okHandler{}
	h := m.Handler(next)

	req := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/ca/root/ocsp/abc", nil)
		r.RemoteAddr = "9.9.9.9:5555"
		h.ServeHTTP(rr, r)
		return rr
	}

	if rr := req(); rr.Code != 200 {
		t.Fatalf("req1 = %d", rr.Code)
	}
	if rr := req(); rr.Code != 200 {
		t.Fatalf("req2 (burst) = %d", rr.Code)
	}
	rr := req()
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("req3 = %d, want 429", rr.Code)
	}
	if ra := rr.Header().Get("Retry-After"); ra == "" {
		t.Fatal("429 response missing Retry-After header")
	} else if n, err := strconv.Atoi(ra); err != nil || n < 1 {
		t.Fatalf("Retry-After = %q, want a positive integer", ra)
	}
}

func TestMiddlewareACMEProblemJSON(t *testing.T) {
	clk := newFakeClock()
	l := NewTieredLimiter(LimiterConfig{PerIP: Rate{Rate: 1, Burst: 1}, Now: clk.now})
	m := New(Options{Limiter: l, Prefixes: testPrefixes()})
	h := m.Handler(&okHandler{})

	do := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/acme/new-order", strings.NewReader("{}"))
		r.RemoteAddr = "8.8.8.8:1"
		h.ServeHTTP(rr, r)
		return rr
	}
	do() // consume burst
	rr := do()
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q, want application/problem+json", ct)
	}
	var prob struct {
		Type   string `json:"type"`
		Status int    `json:"status"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &prob); err != nil {
		t.Fatalf("decoding problem doc: %v", err)
	}
	if prob.Type != "urn:ietf:params:acme:error:rateLimited" {
		t.Fatalf("problem type = %q", prob.Type)
	}
}

// TestMiddlewareACMEAccountExtraction verifies that two different ACME accounts
// on the same IP are metered independently (per-account tier), and that the JWS
// body is restored intact for the downstream handler.
func TestMiddlewareACMEAccountExtraction(t *testing.T) {
	clk := newFakeClock()
	l := NewTieredLimiter(LimiterConfig{
		Global:     Rate{Rate: 1000, Burst: 1000},
		PerIP:      Rate{Rate: 1000, Burst: 1000},
		PerAccount: Rate{Rate: 1, Burst: 1},
		Now:        clk.now,
	})
	m := New(Options{Limiter: l, Prefixes: testPrefixes()})
	next := &okHandler{}
	h := m.Handler(next)

	body := func(acct string) string {
		protected := base64.RawURLEncoding.EncodeToString(
			[]byte(fmt.Sprintf(`{"alg":"ES256","kid":"https://ca.example/acme/acct/%s","nonce":"n"}`, acct)))
		return fmt.Sprintf(`{"protected":%q,"payload":"cGF5","signature":"c2ln"}`, protected)
	}

	post := func(acct string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/acme/new-order", strings.NewReader(body(acct)))
		r.RemoteAddr = "7.7.7.7:9" // same IP for both accounts
		h.ServeHTTP(rr, r)
		return rr
	}

	// Account A: first passes, second throttled (per-account burst 1).
	if rr := post("AAAA"); rr.Code != 200 {
		t.Fatalf("A first = %d", rr.Code)
	}
	if rr := post("AAAA"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("A second = %d, want 429", rr.Code)
	}
	// Account B on the same IP is independent and still admitted.
	if rr := post("BBBB"); rr.Code != 200 {
		t.Fatalf("B first = %d, want 200 (per-account isolation)", rr.Code)
	}

	// The downstream handler must have seen the full, intact JWS body.
	if !strings.Contains(next.body, `"signature":"c2ln"`) {
		t.Fatalf("downstream body was not restored intact: %q", next.body)
	}
}

func TestMiddlewareESTAccountFromBasicAuth(t *testing.T) {
	clk := newFakeClock()
	l := NewTieredLimiter(LimiterConfig{PerAccount: Rate{Rate: 1, Burst: 1}, Now: clk.now})
	m := New(Options{Limiter: l, Prefixes: testPrefixes()})
	h := m.Handler(&okHandler{})

	enroll := func(user string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/.well-known/est/simpleenroll", strings.NewReader("csr"))
		r.SetBasicAuth(user, "pw")
		r.RemoteAddr = "6.6.6.6:2"
		h.ServeHTTP(rr, r)
		return rr
	}
	if rr := enroll("device1"); rr.Code != 200 {
		t.Fatalf("device1 first = %d", rr.Code)
	}
	if rr := enroll("device1"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("device1 second = %d, want 429", rr.Code)
	}
	if rr := enroll("device2"); rr.Code != 200 {
		t.Fatalf("device2 = %d, want 200 (independent EST account)", rr.Code)
	}
}

// TestMiddlewareGuardShedsEnrollment verifies HSM-bound enrollment endpoints are
// gated by the concurrency guard: when the guard is saturated with no queue,
// further enrollments are shed with 503 + Retry-After while the slot is held.
func TestMiddlewareGuardShedsEnrollment(t *testing.T) {
	guard := NewGuard(GuardConfig{MaxInFlight: 1, MaxQueue: 0})
	m := New(Options{Guard: guard, Prefixes: testPrefixes()})

	block := make(chan struct{})
	reached := make(chan struct{})
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(reached)
		<-block // hold the single slot until released
		w.WriteHeader(200)
	})
	h := m.Handler(slow)

	// First enrollment grabs the only slot and blocks inside the handler.
	go func() {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/.well-known/est/simpleenroll", strings.NewReader("csr"))
		r.RemoteAddr = "5.5.5.5:1"
		h.ServeHTTP(rr, r)
	}()
	<-reached

	// A concurrent enrollment cannot get a slot and is shed immediately.
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/.well-known/est/simpleenroll", strings.NewReader("csr"))
	r.RemoteAddr = "5.5.5.6:1"
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("shed enrollment status = %d, want 503", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("503 response missing Retry-After")
	}
	close(block)
}

// TestMiddlewareGracefulDegradation models a legitimate ACME client under
// load: when throttled it honors Retry-After, waits, and retries, ultimately
// completing every request without a permanent failure.
func TestMiddlewareGracefulDegradation(t *testing.T) {
	clk := newFakeClock()
	l := NewTieredLimiter(LimiterConfig{
		PerIP: Rate{Rate: 5, Burst: 2}, // 5/sec sustained, small burst
		Now:   clk.now,
	})
	m := New(Options{Limiter: l, Prefixes: testPrefixes()})
	next := &okHandler{}
	h := m.Handler(next)

	send := func() (int, time.Duration) {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/ca/root/crl", nil)
		r.RemoteAddr = "4.4.4.4:1"
		h.ServeHTTP(rr, r)
		ra := time.Duration(0)
		if v := rr.Header().Get("Retry-After"); v != "" {
			n, _ := strconv.Atoi(v)
			ra = time.Duration(n) * time.Second
		}
		return rr.Code, ra
	}

	const wanted = 20
	completed := 0
	// A well-behaved client: on 429, advance the (fake) clock by Retry-After
	// and retry. It must eventually complete all requests.
	for iter := 0; completed < wanted && iter < 1000; iter++ {
		code, ra := send()
		if code == http.StatusOK {
			completed++
			continue
		}
		if code != http.StatusTooManyRequests {
			t.Fatalf("unexpected status %d", code)
		}
		// Back off exactly as instructed.
		if ra <= 0 {
			t.Fatal("throttled without a usable Retry-After")
		}
		clk.advance(ra)
	}
	if completed != wanted {
		t.Fatalf("client completed %d/%d requests; did not degrade gracefully", completed, wanted)
	}
	if next.count() != wanted {
		t.Fatalf("handler saw %d requests, want %d", next.count(), wanted)
	}
}
