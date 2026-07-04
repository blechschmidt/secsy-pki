//go:build sqlite

package webhook

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// --- test doubles ---------------------------------------------------------------

// recordedReq captures one received delivery for assertions.
type recordedReq struct {
	webhookID string
	event     string
	delivery  string
	validSig  bool
	body      []byte
}

// receiver is an httptest endpoint that verifies each delivery's HMAC signature
// against a known secret and returns a configurable status code, so tests can
// exercise success, retry (5xx), and dead-lettering paths.
type receiver struct {
	mu     sync.Mutex
	reqs   []recordedReq
	secret string
	status int
}

func newReceiver(secret string, status int) *receiver {
	return &receiver{secret: secret, status: status}
}

func (rr *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	sig := r.Header.Get(SignatureHeader)
	// tolerance 0: authenticate the HMAC only (the engine signs with its injected
	// clock, so a wall-clock freshness check would be meaningless here; the replay
	// window is covered by the pure signature tests).
	valid := Verify(rr.secret, sig, body, 0, time.Now()) == nil
	rr.mu.Lock()
	rr.reqs = append(rr.reqs, recordedReq{
		webhookID: r.Header.Get("X-Secsy-Webhook-Id"),
		event:     r.Header.Get("X-Secsy-Event"),
		delivery:  r.Header.Get("X-Secsy-Delivery"),
		validSig:  valid,
		body:      body,
	})
	status := rr.status
	rr.mu.Unlock()
	w.WriteHeader(status)
}

func (rr *receiver) count() int {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	return len(rr.reqs)
}

func (rr *receiver) snapshot() []recordedReq {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	out := make([]recordedReq, len(rr.reqs))
	copy(out, rr.reqs)
	return out
}

func (rr *receiver) setStatus(s int) {
	rr.mu.Lock()
	rr.status = s
	rr.mu.Unlock()
}

// fakeClock is a manually-advanced clock so retry/backoff timing is deterministic
// (no sleeps, no wall-clock flakiness).
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// --- helpers --------------------------------------------------------------------

func newStore(t *testing.T) *database.DB {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func mkTenant(t *testing.T, db *database.DB, id string) {
	t.Helper()
	if err := db.CreateTenant(&models.Tenant{ID: id, Slug: id, Name: id, Status: models.TenantStatusActive}); err != nil {
		t.Fatalf("CreateTenant(%s): %v", id, err)
	}
}

func mkSub(t *testing.T, db *database.DB, id, tenant, scope, url string, events []string) *models.WebhookSubscription {
	t.Helper()
	s := &models.WebhookSubscription{
		ID: id, TenantID: tenant, Scope: scope, URL: url, Secret: "sec-" + id,
		EventTypes: events, Enabled: true, CreatedAt: time.Now().UTC(),
	}
	if err := db.CreateWebhookSubscription(s); err != nil {
		t.Fatalf("CreateWebhookSubscription(%s): %v", id, err)
	}
	return s
}

// appendLifecycle appends a successful certificate lifecycle audit event and
// returns it (with its assigned Seq).
func appendLifecycle(t *testing.T, db *database.DB, action, tenant, caID, serial string) audit.Event {
	t.Helper()
	e := &audit.Event{
		ID: uuid.New().String(), Actor: "tester", Action: action, Tenant: tenant,
		Target: caID, TargetName: serial, Result: audit.ResultSuccess, Detail: "test",
	}
	if err := db.AppendEvent(e); err != nil {
		t.Fatalf("AppendEvent(%s): %v", action, err)
	}
	return *e
}

func newEngine(store Store, clock *fakeClock) *Engine {
	return New(store, Config{
		PollInterval:    time.Hour, // loops are driven directly in tests
		BatchSize:       100,
		MaxAttempts:     3,
		Timeout:         2 * time.Second,
		BackoffBase:     time.Second,
		BackoffMax:      10 * time.Second,
		AuditDeliveries: true,
		Clock:           clock.now,
		Client:          &http.Client{},
	})
}

// --- tests ----------------------------------------------------------------------

// TestFanOutDeliverAndSignature is the happy path: a matching lifecycle event is
// fanned out to a subscription and delivered, and the receiver validates the HMAC
// signature and the X-Secsy-* headers.
func TestFanOutDeliverAndSignature(t *testing.T) {
	db := newStore(t)
	rr := newReceiver("sec-w1", http.StatusOK)
	srv := httptest.NewServer(rr)
	defer srv.Close()

	sub := mkSub(t, db, "w1", models.DefaultTenantID, "tenant", srv.URL, nil)
	ev := appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "0A")

	clock := newFakeClock()
	e := newEngine(db, clock)
	cursor := e.initCursor() // seeds to current head; event above predates it
	// Re-run against a cursor positioned BEFORE the event so it is delivered.
	cursor = ev.Seq - 1
	ctx := context.Background()
	e.fanOutOnce(ctx, &cursor)

	deliveries, err := db.ListWebhookDeliveries(sub.ID, "", 0)
	if err != nil {
		t.Fatalf("ListWebhookDeliveries: %v", err)
	}
	if len(deliveries) != 1 {
		t.Fatalf("fan-out produced %d deliveries, want 1", len(deliveries))
	}

	e.deliverDueOnce(ctx)
	if rr.count() != 1 {
		t.Fatalf("receiver got %d requests, want 1", rr.count())
	}
	got := rr.snapshot()[0]
	if !got.validSig {
		t.Errorf("receiver rejected the HMAC signature")
	}
	if got.webhookID != sub.ID {
		t.Errorf("X-Secsy-Webhook-Id = %q, want %q", got.webhookID, sub.ID)
	}
	if got.event != audit.ActionCertIssue {
		t.Errorf("X-Secsy-Event = %q, want %q", got.event, audit.ActionCertIssue)
	}

	d, err := db.GetWebhookDelivery(deliveries[0].ID)
	if err != nil {
		t.Fatalf("GetWebhookDelivery: %v", err)
	}
	if d.Status != models.WebhookDeliveryDelivered {
		t.Errorf("delivery status = %q, want delivered", d.Status)
	}
	if d.DeliveredAt == nil {
		t.Errorf("delivered_at not set on a delivered delivery")
	}

	// A webhook.deliver audit event should have been recorded (AuditDeliveries).
	events, _, err := db.ListEvents(audit.ActionWebhookDeliver, "", "", 10, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	if len(events) != 1 || events[0].Result != audit.ResultSuccess {
		t.Errorf("want one successful webhook.deliver audit event, got %d", len(events))
	}
}

// TestRetryOnServerErrorThenDeadLetter proves 5xx responses are retried with
// backoff and the delivery is dead-lettered once the retry budget is exhausted.
func TestRetryOnServerErrorThenDeadLetter(t *testing.T) {
	db := newStore(t)
	rr := newReceiver("sec-w1", http.StatusInternalServerError)
	srv := httptest.NewServer(rr)
	defer srv.Close()

	sub := mkSub(t, db, "w1", models.DefaultTenantID, "tenant", srv.URL, nil)
	ev := appendLifecycle(t, db, audit.ActionCertRevoke, models.DefaultTenantID, "ca-1", "0B")

	clock := newFakeClock()
	e := newEngine(db, clock) // MaxAttempts=3, BackoffBase=1s
	ctx := context.Background()
	cursor := ev.Seq - 1
	e.fanOutOnce(ctx, &cursor)

	// Attempt 1 (due now) -> fail, retry scheduled +1s.
	e.deliverDueOnce(ctx)
	if rr.count() != 1 {
		t.Fatalf("after attempt 1: receiver hits = %d, want 1", rr.count())
	}
	assertDeliveryStatus(t, db, sub.ID, models.WebhookDeliveryPending, 1)

	// Not yet due -> no attempt.
	e.deliverDueOnce(ctx)
	if rr.count() != 1 {
		t.Fatalf("premature retry: receiver hits = %d, want 1", rr.count())
	}

	// Advance past the first backoff -> attempt 2 fails, retry +2s.
	clock.advance(2 * time.Second)
	e.deliverDueOnce(ctx)
	if rr.count() != 2 {
		t.Fatalf("after attempt 2: receiver hits = %d, want 2", rr.count())
	}
	assertDeliveryStatus(t, db, sub.ID, models.WebhookDeliveryPending, 2)

	// Advance past the second backoff -> attempt 3 exhausts the budget -> dead.
	clock.advance(4 * time.Second)
	e.deliverDueOnce(ctx)
	if rr.count() != 3 {
		t.Fatalf("after attempt 3: receiver hits = %d, want 3", rr.count())
	}
	assertDeliveryStatus(t, db, sub.ID, models.WebhookDeliveryDead, 3)

	// A dead delivery is terminal: no further attempts however far time advances.
	clock.advance(time.Hour)
	e.deliverDueOnce(ctx)
	if rr.count() != 3 {
		t.Fatalf("dead delivery was retried: receiver hits = %d, want 3", rr.count())
	}

	// The dead-letter is auditable and surfaced by the store query the doctor uses.
	oldest, err := db.OldestDeadWebhookDelivery()
	if err != nil || oldest == nil {
		t.Fatalf("OldestDeadWebhookDelivery = %v, %v", oldest, err)
	}
	events, _, _ := db.ListEvents(audit.ActionWebhookDeliver, "", "", 10, 0)
	var sawDeadAudit bool
	for _, e := range events {
		if e.Result == audit.ResultError {
			sawDeadAudit = true
		}
	}
	if !sawDeadAudit {
		t.Errorf("no error-result webhook.deliver audit event for the dead-letter")
	}
}

// TestEventTypeFiltering proves a subscription with an event-type filter only
// receives the matching events.
func TestEventTypeFiltering(t *testing.T) {
	db := newStore(t)
	sub := mkSub(t, db, "w1", models.DefaultTenantID, "tenant", "http://127.0.0.1:1/hook", []string{audit.ActionCertIssue})

	start, _ := db.MaxEventSeq()
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")   // matches
	appendLifecycle(t, db, audit.ActionCertRevoke, models.DefaultTenantID, "ca-1", "02")  // filtered out
	appendLifecycle(t, db, audit.ActionCertRenew, models.DefaultTenantID, "ca-1", "03")   // filtered out
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "04")   // matches

	e := newEngine(db, newFakeClock())
	cursor := start
	e.fanOutOnce(context.Background(), &cursor)

	deliveries, _ := db.ListWebhookDeliveries(sub.ID, "", 0)
	if len(deliveries) != 2 {
		t.Fatalf("event-type filter produced %d deliveries, want 2 (only cert.issue)", len(deliveries))
	}
	for _, d := range deliveries {
		if d.EventType != audit.ActionCertIssue {
			t.Errorf("delivered a filtered-out event %q", d.EventType)
		}
	}
}

// TestCrossTenantIsolation proves a tenant-scoped subscription only receives its
// own tenant's events, while a platform-scoped subscription receives all.
func TestCrossTenantIsolation(t *testing.T) {
	db := newStore(t)
	mkTenant(t, db, "a")
	mkTenant(t, db, "b")
	subA := mkSub(t, db, "wa", "a", "tenant", "http://127.0.0.1:1/a", nil)
	subB := mkSub(t, db, "wb", "b", "tenant", "http://127.0.0.1:1/b", nil)
	subP := mkSub(t, db, "wp", models.DefaultTenantID, "platform", "http://127.0.0.1:1/p", nil)

	start, _ := db.MaxEventSeq()
	appendLifecycle(t, db, audit.ActionCertIssue, "a", "ca-a", "01") // tenant a's event

	e := newEngine(db, newFakeClock())
	cursor := start
	e.fanOutOnce(context.Background(), &cursor)

	if n := deliveryCount(t, db, subA.ID); n != 1 {
		t.Errorf("tenant-a subscription got %d deliveries, want 1", n)
	}
	if n := deliveryCount(t, db, subB.ID); n != 0 {
		t.Errorf("tenant-b subscription got %d deliveries for tenant-a's event — CROSS-TENANT LEAK", n)
	}
	if n := deliveryCount(t, db, subP.ID); n != 1 {
		t.Errorf("platform subscription got %d deliveries, want 1", n)
	}
}

// TestFanOutIsIdempotent proves re-scanning a range (as happens after a crash
// between enqueue and cursor advance) does not double-enqueue deliveries.
func TestFanOutIsIdempotent(t *testing.T) {
	db := newStore(t)
	sub := mkSub(t, db, "w1", models.DefaultTenantID, "tenant", "http://127.0.0.1:1/hook", nil)
	start, _ := db.MaxEventSeq()
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")

	e := newEngine(db, newFakeClock())
	ctx := context.Background()

	cursor := start
	e.fanOutOnce(ctx, &cursor)
	if n := deliveryCount(t, db, sub.ID); n != 1 {
		t.Fatalf("first fan-out produced %d deliveries, want 1", n)
	}

	// Re-scan the same range with a rewound cursor (simulating a lost cursor write).
	rewound := start
	e.fanOutOnce(ctx, &rewound)
	if n := deliveryCount(t, db, sub.ID); n != 1 {
		t.Fatalf("re-scan double-enqueued: %d deliveries, want 1 (idempotency broken)", n)
	}
}

// TestCursorInitializesToHead proves that enabling the feature does not replay the
// entire certificate history: the fan-out cursor seeds to the current log head,
// so only events committed after enablement are delivered.
func TestCursorInitializesToHead(t *testing.T) {
	db := newStore(t)
	// Pre-existing history, before any subscription or cursor exists.
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "02")

	sub := mkSub(t, db, "w1", models.DefaultTenantID, "tenant", "http://127.0.0.1:1/hook", nil)

	e := newEngine(db, newFakeClock())
	cursor := e.initCursor() // must seed to head (2), not genesis

	// A new event after enablement is the only one that should be delivered.
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "03")
	e.fanOutOnce(context.Background(), &cursor)

	deliveries, _ := db.ListWebhookDeliveries(sub.ID, "", 0)
	if len(deliveries) != 1 {
		t.Fatalf("cursor replayed history: %d deliveries, want 1 (only the post-enablement event)", len(deliveries))
	}
	if deliveries[0].EventSeq <= 2 {
		t.Errorf("delivered a pre-enablement event (seq %d)", deliveries[0].EventSeq)
	}
}

// TestDisabledSubscriptionCancelsPending proves disabling a subscription cancels
// its still-pending deliveries so the worker stops attempting them.
func TestDisabledSubscriptionCancelsPending(t *testing.T) {
	db := newStore(t)
	rr := newReceiver("sec-w1", http.StatusInternalServerError)
	srv := httptest.NewServer(rr)
	defer srv.Close()

	sub := mkSub(t, db, "w1", models.DefaultTenantID, "tenant", srv.URL, nil)
	ev := appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")

	e := newEngine(db, newFakeClock())
	ctx := context.Background()
	cursor := ev.Seq - 1
	e.fanOutOnce(ctx, &cursor)

	// Disable the subscription; the worker must cancel the pending delivery rather
	// than keep hammering the (paused) endpoint.
	if _, err := db.SetWebhookSubscriptionEnabled(sub.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	e.deliverDueOnce(ctx)
	if rr.count() != 0 {
		t.Errorf("disabled subscription was still delivered to (%d hits)", rr.count())
	}
	assertDeliveryStatus(t, db, sub.ID, models.WebhookDeliveryCanceled, 0)
}

// --- assertion helpers ----------------------------------------------------------

func deliveryCount(t *testing.T, db *database.DB, subID string) int {
	t.Helper()
	d, err := db.ListWebhookDeliveries(subID, "", 0)
	if err != nil {
		t.Fatalf("ListWebhookDeliveries(%s): %v", subID, err)
	}
	return len(d)
}

func assertDeliveryStatus(t *testing.T, db *database.DB, subID, wantStatus string, wantAttempts int) {
	t.Helper()
	d, err := db.ListWebhookDeliveries(subID, "", 0)
	if err != nil {
		t.Fatalf("ListWebhookDeliveries: %v", err)
	}
	if len(d) != 1 {
		t.Fatalf("want exactly 1 delivery for %s, got %d", subID, len(d))
	}
	if d[0].Status != wantStatus {
		t.Errorf("delivery status = %q, want %q", d[0].Status, wantStatus)
	}
	if d[0].Attempts != wantAttempts {
		t.Errorf("delivery attempts = %d, want %d", d[0].Attempts, wantAttempts)
	}
}
