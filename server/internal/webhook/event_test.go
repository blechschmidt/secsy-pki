package webhook

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Store-free unit tests for the event catalog, the payload builders, the config
// contract, the retry-delay schedule, the audit-hook nudge and the synchronous
// CLI test send. Everything here is hermetic: the only network is an
// httptest.Server bound to loopback, and nothing waits on wall-clock time.

// --- shared test doubles (also used by delivery_test.go) -------------------------

// capturedReq is one request exactly as the endpoint saw it. The body is kept as
// raw bytes so assertions can compare the signed bytes byte-for-byte.
type capturedReq struct {
	method string
	header http.Header
	body   []byte
}

func (c capturedReq) sig() string { return c.header.Get(SignatureHeader) }

// testEndpoint is an httptest receiver whose reply is chosen per request by a
// hook, so one type covers 2xx / 4xx / 5xx / redirect / oversize / never-answers
// endpoints without sleeps or external network.
type testEndpoint struct {
	srv     *httptest.Server
	mu      sync.Mutex
	reqs    []capturedReq
	respond func(n int, w http.ResponseWriter, r *http.Request)
}

// newEndpoint starts an endpoint that answers via respond (nil = 200 OK) and
// shuts it down when the test ends. n is the 0-based request ordinal, so a hook
// can fail the first attempt and accept the retry.
func newEndpoint(t *testing.T, respond func(n int, w http.ResponseWriter, r *http.Request)) *testEndpoint {
	t.Helper()
	ep := &testEndpoint{respond: respond}
	ep.srv = httptest.NewServer(ep)
	t.Cleanup(ep.srv.Close)
	return ep
}

// newStatusEndpoint starts an endpoint that always answers with code.
func newStatusEndpoint(t *testing.T, code int) *testEndpoint {
	t.Helper()
	return newEndpoint(t, func(_ int, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(code) })
}

// deadEndpointURL returns the URL of an endpoint that has already been shut
// down, so a connection to it is refused (a transport error, no HTTP status).
func deadEndpointURL(t *testing.T) string {
	t.Helper()
	ep := newEndpoint(t, nil)
	url := ep.url()
	ep.srv.Close() // httptest.Server.Close is idempotent; the cleanup Close is a no-op
	return url
}

func (ep *testEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	ep.mu.Lock()
	n := len(ep.reqs)
	ep.reqs = append(ep.reqs, capturedReq{method: r.Method, header: r.Header.Clone(), body: body})
	respond := ep.respond
	ep.mu.Unlock()
	if respond == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	respond(n, w, r)
}

func (ep *testEndpoint) url() string { return ep.srv.URL }

func (ep *testEndpoint) count() int {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return len(ep.reqs)
}

// at returns the i-th received request, failing the test when it is missing.
func (ep *testEndpoint) at(t *testing.T, i int) capturedReq {
	t.Helper()
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if i >= len(ep.reqs) {
		t.Fatalf("endpoint received %d requests, want at least %d", len(ep.reqs), i+1)
	}
	return ep.reqs[i]
}

// syncBuffer is a mutex-guarded log sink: the engine logs from its own
// goroutines, so a test must not read an unsynchronized buffer under -race.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func testLogger(buf *syncBuffer) *log.Logger { return log.New(buf, "", 0) }

// assertNoSecret proves the shared HMAC key never travels with a delivery: it is
// the signing key, so leaking it in a header or the body would let any receiver
// (or anything on the path that sees a mirrored request) forge deliveries.
func assertNoSecret(t *testing.T, req capturedReq, secret string) {
	t.Helper()
	if secret == "" {
		t.Fatalf("assertNoSecret needs a non-empty secret")
	}
	if strings.Contains(string(req.body), secret) {
		t.Errorf("the signing secret appears in the request body")
	}
	for k, vals := range req.header {
		for _, v := range vals {
			if strings.Contains(v, secret) {
				t.Errorf("the signing secret appears in header %s", k)
			}
		}
	}
}

// --- event catalog --------------------------------------------------------------

// TestEventCatalogSelfConsistency is the drift guard between the operator-facing
// catalog (SupportedEventTypes, used by the CLI/console and subscription
// validation) and the predicates the fan-out gates on (IsSupportedEventType,
// IsLifecycleEvent). If a new event type reaches one and not the other, the
// system either advertises a subscription that never fires or delivers an event
// nobody could subscribe to.
func TestEventCatalogSelfConsistency(t *testing.T) {
	types := SupportedEventTypes()

	want := []string{
		audit.ActionCertIssue,
		audit.ActionCertRelease,
		audit.ActionCertRenew,
		audit.ActionCertRevoke,
		audit.ActionCertSuspend,
	}
	sort.Strings(want)
	if !reflect.DeepEqual(types, want) {
		t.Errorf("SupportedEventTypes() = %v, want %v", types, want)
	}
	if !sort.StringsAreSorted(types) {
		t.Errorf("SupportedEventTypes() is not sorted: %v", types)
	}

	seen := map[string]bool{}
	for _, ty := range types {
		if seen[ty] {
			t.Errorf("SupportedEventTypes() repeats %q", ty)
		}
		seen[ty] = true
		if !IsSupportedEventType(ty) {
			t.Errorf("IsSupportedEventType(%q) = false for an advertised event type", ty)
		}
		if !IsLifecycleEvent(ty) {
			t.Errorf("IsLifecycleEvent(%q) = false: the fan-out would drop an advertised event type", ty)
		}
	}

	// The reverse direction, straight off the catalog map: a key mapped to false
	// would be listed by SupportedEventTypes (it ranges over keys) yet rejected by
	// IsSupportedEventType — exactly the drift this guards.
	for action, ok := range lifecycleEvents {
		if !ok {
			t.Errorf("lifecycleEvents[%q] = false: advertised by SupportedEventTypes but rejected by IsSupportedEventType", action)
		}
		if !seen[action] {
			t.Errorf("catalog entry %q is missing from SupportedEventTypes()", action)
		}
	}

	// Unknown, near-miss and deliberately excluded actions must be rejected by
	// both predicates. The bulk summaries are excluded by design: they already
	// emit a per-item event each, so delivering the summary too would double-fire.
	for _, unknown := range []string{
		"", " ", "cert.issue ", " cert.issue", "CERT.ISSUE", "cert.issued",
		audit.ActionCertIssueBulk, audit.ActionCertRevokeBulk,
		audit.ActionCACreate, audit.ActionWebhookDeliver, "webhook.test",
	} {
		if IsSupportedEventType(unknown) {
			t.Errorf("IsSupportedEventType(%q) = true, want false", unknown)
		}
		if IsLifecycleEvent(unknown) {
			t.Errorf("IsLifecycleEvent(%q) = true, want false", unknown)
		}
	}
}

// TestSupportedEventTypesReturnsIndependentSlice proves a caller cannot corrupt
// the catalog through the returned slice (the CLI sorts/filters it in place).
func TestSupportedEventTypesReturnsIndependentSlice(t *testing.T) {
	first := SupportedEventTypes()
	if len(first) == 0 {
		t.Fatal("SupportedEventTypes() is empty")
	}
	original := first[0]
	first[0] = "mutated"

	second := SupportedEventTypes()
	if second[0] != original {
		t.Errorf("mutating the returned slice changed the catalog: now %q, want %q", second[0], original)
	}
	if !IsSupportedEventType(original) {
		t.Errorf("mutating the returned slice broke IsSupportedEventType(%q)", original)
	}
}

// --- payload builders -----------------------------------------------------------

// TestBuildTestPayload covers the synthetic body the `webhook test` CLI and the
// REST test endpoint send: a stable, signable envelope that identifies itself as
// a test, normalizes the tenant, emits UTC, and carries no secret.
func TestBuildTestPayload(t *testing.T) {
	// A non-UTC zone proves the builder normalizes rather than passes through.
	ts := time.Date(2026, 3, 4, 5, 6, 7, 0, time.FixedZone("UTC+1", 3600))
	sub := &models.WebhookSubscription{ID: "sub-7", TenantID: "", Secret: "hmac-key-do-not-leak"}

	body, err := BuildTestPayload("del-7", sub, ts)
	if err != nil {
		t.Fatalf("BuildTestPayload: %v", err)
	}

	var p EventPayload
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("payload is not valid JSON: %v (%s)", err, body)
	}
	if p.SpecVersion != "1.0" {
		t.Errorf("specversion = %q, want 1.0", p.SpecVersion)
	}
	if p.Type != "webhook.test" || p.Data.Action != "webhook.test" {
		t.Errorf("type/action = %q/%q, want webhook.test", p.Type, p.Data.Action)
	}
	if p.Data.Result != audit.ResultSuccess {
		t.Errorf("data.result = %q, want %q", p.Data.Result, audit.ResultSuccess)
	}
	if p.ID != "del-7" || p.EventID != "del-7" {
		t.Errorf("id/event_id = %q/%q, want del-7 for both", p.ID, p.EventID)
	}
	if p.SubscriptionID != sub.ID {
		t.Errorf("subscription_id = %q, want %q", p.SubscriptionID, sub.ID)
	}
	if p.Sequence != 0 {
		t.Errorf("sequence = %d, want 0 (a test delivery has no source event)", p.Sequence)
	}
	// An empty subscription tenant is normalized to the default tenant so
	// single-tenant receivers see a stable value.
	if p.Tenant != models.DefaultTenantID {
		t.Errorf("tenant = %q, want %q", p.Tenant, models.DefaultTenantID)
	}
	if !p.Time.Equal(ts) {
		t.Errorf("time = %s, want %s", p.Time, ts)
	}
	if got := `"time":"2026-03-04T04:06:07Z"`; !strings.Contains(string(body), got) {
		t.Errorf("time is not serialized as UTC RFC 3339: %s", body)
	}
	if strings.Contains(string(body), sub.Secret) {
		t.Errorf("BuildTestPayload leaked the signing secret into the body")
	}

	// A tenant-scoped subscription keeps its own tenant.
	body2, err := BuildTestPayload("del-8", &models.WebhookSubscription{ID: "s", TenantID: "acme"}, ts)
	if err != nil {
		t.Fatalf("BuildTestPayload: %v", err)
	}
	var p2 EventPayload
	if err := json.Unmarshal(body2, &p2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p2.Tenant != "acme" {
		t.Errorf("tenant = %q, want acme", p2.Tenant)
	}

	// The body is what gets signed, so it must round-trip through the signature.
	hdr := Sign(sub.Secret, ts, body)
	if err := Verify(sub.Secret, hdr, body, time.Minute, ts); err != nil {
		t.Errorf("a test payload does not verify under its own signature: %v", err)
	}
}

// TestNewTestDeliveryRow covers the durable row the REST test endpoint enqueues
// for the worker: due immediately, budgeted, and carrying a negative sentinel
// sequence so it can never collide with a real event under
// UNIQUE(subscription_id, event_seq).
func TestNewTestDeliveryRow(t *testing.T) {
	sub := &models.WebhookSubscription{ID: "s1", TenantID: "acme", URL: "https://hook.example/x", Secret: "hmac-key-do-not-leak"}

	d, err := NewTestDelivery(sub, 0)
	if err != nil {
		t.Fatalf("NewTestDelivery: %v", err)
	}
	if d.Status != models.WebhookDeliveryPending {
		t.Errorf("status = %q, want %q", d.Status, models.WebhookDeliveryPending)
	}
	if d.EventType != "webhook.test" {
		t.Errorf("event_type = %q, want webhook.test", d.EventType)
	}
	if d.SubscriptionID != sub.ID || d.TenantID != sub.TenantID {
		t.Errorf("subscription/tenant = %q/%q, want %q/%q", d.SubscriptionID, d.TenantID, sub.ID, sub.TenantID)
	}
	if d.MaxAttempts != 8 {
		t.Errorf("max_attempts = %d, want the 8 default for a non-positive budget", d.MaxAttempts)
	}
	if d.Attempts != 0 {
		t.Errorf("attempts = %d, want 0 on a fresh row", d.Attempts)
	}
	if d.EventSeq >= 0 {
		t.Errorf("event_seq = %d, want a negative sentinel clear of real (positive) event sequences", d.EventSeq)
	}
	if !d.NextAttemptAt.Equal(d.CreatedAt) {
		t.Errorf("next_attempt_at = %s, want created_at %s (due immediately)", d.NextAttemptAt, d.CreatedAt)
	}
	if d.CreatedAt.Location() != time.UTC {
		t.Errorf("created_at is not UTC: %s", d.CreatedAt)
	}
	if d.EventID != d.ID {
		t.Errorf("event_id = %q, want the delivery id %q", d.EventID, d.ID)
	}
	var p EventPayload
	if err := json.Unmarshal([]byte(d.Payload), &p); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if p.ID != d.ID {
		t.Errorf("payload id = %q, want the row id %q (the signed body must name its own delivery)", p.ID, d.ID)
	}
	if strings.Contains(d.Payload, sub.Secret) {
		t.Errorf("NewTestDelivery leaked the signing secret into the stored payload")
	}

	// An explicit budget is honored, and every row gets its own identity.
	d2, err := NewTestDelivery(sub, 3)
	if err != nil {
		t.Fatalf("NewTestDelivery: %v", err)
	}
	if d2.MaxAttempts != 3 {
		t.Errorf("max_attempts = %d, want the requested 3", d2.MaxAttempts)
	}
	if d2.ID == d.ID {
		t.Errorf("two test deliveries share the id %q", d.ID)
	}
}

// --- config contract ------------------------------------------------------------

// TestConfigDefaults pins the documented production defaults. A silent change
// here (e.g. a 100x larger poll interval or a shorter retry budget) changes the
// runtime behavior of every deployment that does not override the knob.
func TestConfigDefaults(t *testing.T) {
	// A nil store is deliberate: New must not touch it.
	c := New(nil, Config{}).cfg

	if c.PollInterval != 5*time.Second {
		t.Errorf("PollInterval default = %s, want 5s", c.PollInterval)
	}
	if c.BatchSize != 100 {
		t.Errorf("BatchSize default = %d, want 100", c.BatchSize)
	}
	if c.MaxAttempts != 8 {
		t.Errorf("MaxAttempts default = %d, want 8", c.MaxAttempts)
	}
	if c.Timeout != 10*time.Second {
		t.Errorf("Timeout default = %s, want 10s", c.Timeout)
	}
	if c.BackoffBase != 30*time.Second {
		t.Errorf("BackoffBase default = %s, want 30s", c.BackoffBase)
	}
	if c.BackoffMax != time.Hour {
		t.Errorf("BackoffMax default = %s, want 1h", c.BackoffMax)
	}
	if c.Logger == nil || c.Client == nil || c.Clock == nil {
		t.Fatalf("withDefaults left a nil Logger/Client/Clock: %v/%v/%v", c.Logger == nil, c.Client == nil, c.Clock == nil)
	}
	// The default clock must be the real one, not a zero time.
	if d := time.Since(c.Clock()); d > time.Minute || d < -time.Minute {
		t.Errorf("default Clock() is %s away from now, want time.Now", d)
	}
	// The default client must have no global timeout: each attempt is bounded by
	// its own context deadline, and a global one would also cap the (streamed)
	// response drain.
	if c.Client.Timeout != 0 {
		t.Errorf("default Client.Timeout = %s, want 0 (per-attempt context deadline instead)", c.Client.Timeout)
	}
	// NOTE: AuditDeliveries documents "Default true" but a plain bool cannot
	// distinguish unset from explicitly-false, so withDefaults leaves it false.
	// The production wiring always passes config.WebhookConfig.AuditDeliveriesEnabled()
	// explicitly; this pins the engine's actual behavior.
	if c.AuditDeliveries {
		t.Errorf("AuditDeliveries = true for a zero Config, want false (withDefaults cannot default a bool)")
	}

	// Non-positive durations/sizes fall back too, and explicit values survive.
	neg := New(nil, Config{PollInterval: -1, BatchSize: -1, MaxAttempts: -1, Timeout: -1, BackoffBase: -1, BackoffMax: -1}).cfg
	if neg.PollInterval != 5*time.Second || neg.BatchSize != 100 || neg.MaxAttempts != 8 ||
		neg.Timeout != 10*time.Second || neg.BackoffBase != 30*time.Second || neg.BackoffMax != time.Hour {
		t.Errorf("negative knobs did not fall back to defaults: %+v", neg)
	}

	clock := func() time.Time { return time.Unix(42, 0) }
	client := &http.Client{}
	logger := log.New(io.Discard, "", 0)
	set := New(nil, Config{
		PollInterval: time.Second, BatchSize: 7, MaxAttempts: 2, Timeout: 3 * time.Second,
		BackoffBase: 4 * time.Second, BackoffMax: 5 * time.Second, AuditDeliveries: true,
		Clock: clock, Client: client, Logger: logger,
	}).cfg
	if set.PollInterval != time.Second || set.BatchSize != 7 || set.MaxAttempts != 2 ||
		set.Timeout != 3*time.Second || set.BackoffBase != 4*time.Second || set.BackoffMax != 5*time.Second ||
		!set.AuditDeliveries || set.Client != client || set.Logger != logger || !set.Clock().Equal(time.Unix(42, 0)) {
		t.Errorf("withDefaults overwrote explicitly-set values: %+v", set)
	}
}

// TestBackoffSchedule pins the retry-delay curve: BackoffBase * 2^(attempt-1),
// clamped to BackoffMax. Both the growth and the clamp matter — no growth is a
// retry storm against a struggling endpoint, no clamp is an unbounded delay (and
// an overflow risk) on a long-dead one.
func TestBackoffSchedule(t *testing.T) {
	e := New(nil, Config{BackoffBase: time.Second, BackoffMax: 10 * time.Second})
	for attempt, want := range map[int]time.Duration{
		1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 4: 8 * time.Second,
		5: 10 * time.Second, 6: 10 * time.Second, 64: 10 * time.Second, 1000: 10 * time.Second,
	} {
		if got := e.backoff(attempt); got != want {
			t.Errorf("backoff(%d) = %s, want %s", attempt, got, want)
		}
	}

	// The production default curve: 30s doubling to the 1h clamp at attempt 8.
	def := New(nil, Config{})
	for attempt, want := range map[int]time.Duration{
		1: 30 * time.Second, 2: time.Minute, 3: 2 * time.Minute, 4: 4 * time.Minute,
		5: 8 * time.Minute, 6: 16 * time.Minute, 7: 32 * time.Minute, 8: time.Hour,
	} {
		if got := def.backoff(attempt); got != want {
			t.Errorf("default backoff(%d) = %s, want %s", attempt, got, want)
		}
	}

	// A misconfigured base above the clamp must still be clamped, never returned raw.
	odd := New(nil, Config{BackoffBase: time.Minute, BackoffMax: 5 * time.Second})
	for _, attempt := range []int{0, 1, 2, 9} {
		if got := odd.backoff(attempt); got != 5*time.Second {
			t.Errorf("backoff(%d) with base > max = %s, want the 5s clamp", attempt, got)
		}
	}
}

// --- audit-append hook ----------------------------------------------------------

// TestNotifyGatesAndNeverTouchesTheStore proves the audit-append hook contract:
// Notify only nudges on a deliverable event, never blocks, coalesces repeats into
// the single-slot wake, and never re-enters the store (it runs inside the append
// critical section, so a store call there would deadlock the log). The nil store
// makes any store access panic.
func TestNotifyGatesAndNeverTouchesTheStore(t *testing.T) {
	e := New(nil, Config{})

	woke := func() bool {
		select {
		case <-e.wake:
			return true
		default:
			return false
		}
	}

	for _, tc := range []struct {
		name string
		ev   audit.Event
		want bool
	}{
		{"lifecycle success wakes", audit.Event{Action: audit.ActionCertIssue, Result: audit.ResultSuccess}, true},
		{"revoke success wakes", audit.Event{Action: audit.ActionCertRevoke, Result: audit.ResultSuccess}, true},
		{"denied lifecycle event is not delivered", audit.Event{Action: audit.ActionCertIssue, Result: audit.ResultDenied}, false},
		{"errored lifecycle event is not delivered", audit.Event{Action: audit.ActionCertIssue, Result: audit.ResultError}, false},
		{"non-lifecycle event is ignored", audit.Event{Action: audit.ActionCACreate, Result: audit.ResultSuccess}, false},
		{"bulk summary is ignored (per-item events already fire)", audit.Event{Action: audit.ActionCertIssueBulk, Result: audit.ResultSuccess}, false},
		{"our own delivery audit never feeds back", audit.Event{Action: audit.ActionWebhookDeliver, Result: audit.ResultSuccess}, false},
		{"empty event is ignored", audit.Event{}, false},
	} {
		e.Notify(tc.ev) // must not panic: the store is nil
		if got := woke(); got != tc.want {
			t.Errorf("%s: woke = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestNotifyCoalescesUnderConcurrency proves the nudge is non-blocking and
// bounded: many concurrent appends collapse into the single buffered slot instead
// of blocking the audit-append critical section.
func TestNotifyCoalescesUnderConcurrency(t *testing.T) {
	e := New(nil, Config{})
	ev := audit.Event{Action: audit.ActionCertIssue, Result: audit.ResultSuccess}

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 200; j++ {
					e.Notify(ev)
				}
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Notify blocked: 1600 nudges did not complete, the audit-append hook would stall the log")
	}
	if n := len(e.wake); n != 1 {
		t.Errorf("wake holds %d nudges, want exactly 1 (coalesced)", n)
	}
}

// --- synchronous CLI test send --------------------------------------------------

// TestSendTestSignsLikeARealDelivery proves `secsy-ca webhook test` is a faithful
// rehearsal: same signature, same headers, same body shape as a queued delivery,
// so a receiver that passes the test also passes production traffic.
func TestSendTestSignsLikeARealDelivery(t *testing.T) {
	ep := newStatusEndpoint(t, http.StatusOK)
	sub := &models.WebhookSubscription{ID: "sub-1", TenantID: "acme", URL: ep.url(), Secret: "hmac-key-do-not-leak"}

	code, err := SendTest(context.Background(), sub, 5*time.Second)
	if err != nil {
		t.Fatalf("SendTest: %v", err)
	}
	if code != http.StatusOK {
		t.Errorf("SendTest status = %d, want 200", code)
	}
	if ep.count() != 1 {
		t.Fatalf("endpoint got %d requests, want 1", ep.count())
	}

	req := ep.at(t, 0)
	if req.method != http.MethodPost {
		t.Errorf("method = %s, want POST", req.method)
	}
	for header, want := range map[string]string{
		"Content-Type":       "application/json",
		"User-Agent":         "secsy-pki-webhook/1",
		"X-Secsy-Event":      "webhook.test",
		"X-Secsy-Webhook-Id": sub.ID,
		"X-Secsy-Attempt":    "1",
	} {
		if got := req.header.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	// The signature must authenticate the exact bytes sent, and be fresh.
	if err := Verify(sub.Secret, req.sig(), req.body, time.Minute, time.Now()); err != nil {
		t.Errorf("test delivery signature did not verify: %v", err)
	}
	// One byte of tampering must break it.
	tampered := append([]byte(nil), req.body...)
	tampered[len(tampered)-1] = '!'
	if err := Verify(sub.Secret, req.sig(), tampered, 0, time.Now()); err == nil {
		t.Errorf("signature verified over a tampered body")
	}
	var p EventPayload
	if err := json.Unmarshal(req.body, &p); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}
	if p.ID != req.header.Get("X-Secsy-Delivery") {
		t.Errorf("body id %q != X-Secsy-Delivery %q: the header and the signed body disagree", p.ID, req.header.Get("X-Secsy-Delivery"))
	}
	if p.SubscriptionID != sub.ID || p.Tenant != "acme" {
		t.Errorf("body subscription/tenant = %q/%q, want %q/acme", p.SubscriptionID, p.Tenant, sub.ID)
	}
	assertNoSecret(t, req, sub.Secret)
}

// TestSendTestReportsFailuresWithoutRetrying proves the synchronous path reports
// what happened and makes exactly one attempt: a non-2xx comes back as a status
// code (the CLI decides), while an unreachable endpoint or a canceled context
// comes back as an error with status 0.
func TestSendTestReportsFailuresWithoutRetrying(t *testing.T) {
	t.Run("non-2xx is reported, not retried", func(t *testing.T) {
		ep := newStatusEndpoint(t, http.StatusServiceUnavailable)
		sub := &models.WebhookSubscription{ID: "s", URL: ep.url(), Secret: "k"}
		code, err := SendTest(context.Background(), sub, 5*time.Second)
		if err != nil {
			t.Errorf("SendTest returned an error for an HTTP 503 response: %v", err)
		}
		if code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", code)
		}
		if ep.count() != 1 {
			t.Errorf("endpoint got %d requests, want exactly 1 (SendTest must not retry)", ep.count())
		}
	})

	t.Run("connection refused", func(t *testing.T) {
		sub := &models.WebhookSubscription{ID: "s", URL: deadEndpointURL(t), Secret: "k"}
		code, err := SendTest(context.Background(), sub, 5*time.Second)
		if err == nil {
			t.Errorf("SendTest to a closed endpoint returned no error (status %d)", code)
		}
		if code != 0 {
			t.Errorf("status = %d, want 0 on a transport error", code)
		}
	})

	t.Run("canceled context", func(t *testing.T) {
		ep := newStatusEndpoint(t, http.StatusOK)
		sub := &models.WebhookSubscription{ID: "s", URL: ep.url(), Secret: "k"}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		code, err := SendTest(ctx, sub, 5*time.Second)
		if err == nil {
			t.Errorf("SendTest with a canceled context returned no error (status %d)", code)
		}
		if code != 0 {
			t.Errorf("status = %d, want 0", code)
		}
		if ep.count() != 0 {
			t.Errorf("endpoint got %d requests, want 0 for a canceled context", ep.count())
		}
	})

	t.Run("unusable URL", func(t *testing.T) {
		// A stored subscription URL that cannot be POSTed must surface as an error
		// rather than panic the caller.
		for _, raw := range []string{"", "ftp://example.invalid/hook", "http://[::1", "http://exa mple/hook"} {
			sub := &models.WebhookSubscription{ID: "s", URL: raw, Secret: "k"}
			if code, err := SendTest(context.Background(), sub, time.Second); err == nil {
				t.Errorf("SendTest(%q) returned no error (status %d)", raw, code)
			}
		}
	})
}

// TestVerifyRejectsFutureTimestamps proves the freshness window is two-sided: a
// delivery stamped far in the FUTURE (a badly skewed or malicious sender) must be
// rejected just like a stale replay, or an attacker could mint a signature that
// stays "fresh" indefinitely.
func TestVerifyRejectsFutureTimestamps(t *testing.T) {
	secret, body := "k", []byte("payload")
	now := time.Unix(1_700_000_000, 0)

	future := Sign(secret, now.Add(10*time.Minute), body)
	if err := Verify(secret, future, body, 5*time.Minute, now); err == nil {
		t.Errorf("Verify accepted a signature stamped 10 minutes in the future within a 5m tolerance")
	}
	// Just inside the window is fine (clock skew between sender and receiver).
	near := Sign(secret, now.Add(time.Minute), body)
	if err := Verify(secret, near, body, 5*time.Minute, now); err != nil {
		t.Errorf("Verify rejected a 1m clock skew inside a 5m tolerance: %v", err)
	}
}

// --- small helpers --------------------------------------------------------------

// TestHostOfRedactsCredentialsAndPath proves the audit/log rendering of an
// endpoint keeps only scheme+host: a subscription URL may carry a bearer token in
// its path or query, or credentials in its userinfo, and those must never reach
// the tamper-evident log (which auditors read).
func TestHostOfRedactsCredentialsAndPath(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://hook.example.com/path?token=SECRET", "https://hook.example.com"},
		{"https://user:PASSWORD@hook.example.com:8443/p", "https://hook.example.com:8443"},
		{"http://[::1]:9000/x", "http://[::1]:9000"},
		{"http://127.0.0.1:1/hook", "http://127.0.0.1:1"},
		{"not a url", "not a url"}, // no host to extract: returned verbatim
		{"", ""},
	} {
		if got := hostOf(tc.in); got != tc.want {
			t.Errorf("hostOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestDeliveryErrorMessage pins the stored failure reason: a transport error is
// labeled as such, an HTTP failure records its status, and a transport error wins
// when both are present (the status is meaningless then).
func TestDeliveryErrorMessage(t *testing.T) {
	if got, want := deliveryErrorMessage(500, nil), "endpoint returned HTTP 500"; got != want {
		t.Errorf("deliveryErrorMessage(500, nil) = %q, want %q", got, want)
	}
	if got := deliveryErrorMessage(0, io.EOF); got != "transport error: EOF" {
		t.Errorf("deliveryErrorMessage(0, EOF) = %q, want %q", got, "transport error: EOF")
	}
	if got := deliveryErrorMessage(502, io.EOF); got != "transport error: EOF" {
		t.Errorf("deliveryErrorMessage(502, EOF) = %q, want the transport error to win", got)
	}
}
