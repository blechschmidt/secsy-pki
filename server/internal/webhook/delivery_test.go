//go:build sqlite

package webhook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Delivery-engine tests: the HTTP failure matrix, the retry/backoff bookkeeping,
// the fan-out routing matrix, and the two background loops' shutdown behavior.
// Everything is driven off a fake clock and an httptest endpoint, so no test
// waits on real time or leaves a goroutine behind.

// --- helpers --------------------------------------------------------------------

// engineFor builds an engine over store with tweak applied to a deterministic
// base config: a poll interval long enough that the loops never tick on their own
// (tests drive the sweeps, or rely on the wake channel), and small backoffs the
// fake clock can step over.
func engineFor(store Store, clock *fakeClock, tweak func(*Config)) *Engine {
	cfg := Config{
		PollInterval:    time.Hour,
		BatchSize:       100,
		MaxAttempts:     3,
		Timeout:         2 * time.Second,
		BackoffBase:     time.Second,
		BackoffMax:      10 * time.Second,
		AuditDeliveries: true,
		Client:          newHTTPClient(), // the production client: redirects are not followed
	}
	if clock != nil {
		cfg.Clock = clock.now
	}
	if tweak != nil {
		tweak(&cfg)
	}
	return New(store, cfg)
}

// seedCursorAtHead persists the fan-out cursor at the current log head, as an
// already-running worker would have left it. A fresh engine instead seeds past
// everything (the anti-replay rule), so a test that wants an event fanned out
// must pin the cursor before appending it.
func seedCursorAtHead(t *testing.T, db *database.DB) int64 {
	t.Helper()
	head, err := db.MaxEventSeq()
	if err != nil {
		t.Fatalf("MaxEventSeq: %v", err)
	}
	if err := db.SetWebhookCursor(head); err != nil {
		t.Fatalf("SetWebhookCursor: %v", err)
	}
	return head
}

// onlyDelivery returns the single delivery row of a subscription.
func onlyDelivery(t *testing.T, db *database.DB, subID string) models.WebhookDelivery {
	t.Helper()
	rows, err := db.ListWebhookDeliveries(subID, "", 0)
	if err != nil {
		t.Fatalf("ListWebhookDeliveries(%s): %v", subID, err)
	}
	if len(rows) != 1 {
		t.Fatalf("subscription %s has %d deliveries, want exactly 1", subID, len(rows))
	}
	return rows[0]
}

// mustDeliveries returns a subscription's delivery rows.
func mustDeliveries(t *testing.T, db *database.DB, subID string) []models.WebhookDelivery {
	t.Helper()
	rows, err := db.ListWebhookDeliveries(subID, "", 0)
	if err != nil {
		t.Fatalf("ListWebhookDeliveries(%s): %v", subID, err)
	}
	return rows
}

// waitFor polls cond until it holds or the deadline expires. Tests never sleep
// for a fixed duration hoping something happened; they poll with a hard deadline
// so a regression fails fast instead of hanging.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// waitReturn asserts a loop goroutine finished within d — the shutdown-latency
// property a leader-elected job needs (a handover must not block on it).
func waitReturn(t *testing.T, what string, done <-chan struct{}, d time.Duration) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %s after the context was canceled", what, d)
	}
}

// auditDeliverEvents returns the webhook.deliver audit events recorded so far.
func auditDeliverEvents(t *testing.T, db *database.DB) []audit.Event {
	t.Helper()
	events, _, err := db.ListEvents(audit.ActionWebhookDeliver, "", "", 50, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	return events
}

// --- HTTP outcome matrix --------------------------------------------------------

// TestDeliveryStatusCodeClassification is the response-code contract: only a 2xx
// acknowledges a delivery. Everything else is a failure that keeps its retry
// budget — including 4xx, which the engine deliberately does NOT treat as
// permanent (there is no give-up-early classification; a misconfigured receiver
// returning 404 is retried and eventually dead-lettered, never silently dropped).
func TestDeliveryStatusCodeClassification(t *testing.T) {
	for _, tc := range []struct {
		code      int
		delivered bool
	}{
		{http.StatusOK, true},
		{http.StatusCreated, true},
		{http.StatusAccepted, true},
		{http.StatusNoContent, true},
		{299, true},
		{http.StatusBadRequest, false},
		{http.StatusUnauthorized, false},
		{http.StatusForbidden, false},
		{http.StatusNotFound, false},
		{http.StatusGone, false},
		{http.StatusTooManyRequests, false},
		{http.StatusInternalServerError, false},
		{http.StatusBadGateway, false},
		{http.StatusServiceUnavailable, false},
	} {
		name := http.StatusText(tc.code)
		if name == "" {
			name = "custom"
		}
		t.Run(name, func(t *testing.T) {
			db := newStore(t)
			ep := newStatusEndpoint(t, tc.code)
			sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)

			clock := newFakeClock()
			t0 := clock.now()
			e := engineFor(db, clock, nil)
			ctx := context.Background()

			cursor := seedCursorAtHead(t, db)
			appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
			e.fanOutOnce(ctx, &cursor)
			e.deliverDueOnce(ctx)

			if ep.count() != 1 {
				t.Fatalf("endpoint got %d requests, want exactly 1", ep.count())
			}
			d := onlyDelivery(t, db, sub.ID)
			if d.Attempts != 1 {
				t.Errorf("attempts = %d, want 1 after a single sweep", d.Attempts)
			}
			if d.LastStatusCode != tc.code {
				t.Errorf("last_status_code = %d, want %d", d.LastStatusCode, tc.code)
			}
			if d.LastAttemptAt == nil || !d.LastAttemptAt.Equal(t0) {
				t.Errorf("last_attempt_at = %v, want the attempt time %s", d.LastAttemptAt, t0)
			}

			if tc.delivered {
				if d.Status != models.WebhookDeliveryDelivered {
					t.Fatalf("HTTP %d: status = %q, want delivered", tc.code, d.Status)
				}
				if d.DeliveredAt == nil {
					t.Errorf("delivered_at not stamped on a delivered row")
				}
				if d.LastError != "" {
					t.Errorf("last_error = %q on a delivered row, want empty", d.LastError)
				}
				if evs := auditDeliverEvents(t, db); len(evs) != 1 || evs[0].Result != audit.ResultSuccess {
					t.Errorf("want exactly one successful webhook.deliver audit event, got %+v", evs)
				}
			} else {
				if d.Status != models.WebhookDeliveryPending {
					t.Fatalf("HTTP %d: status = %q, want pending (retry budget not yet spent)", tc.code, d.Status)
				}
				if d.DeliveredAt != nil {
					t.Errorf("delivered_at stamped on a failed row")
				}
				if want := "endpoint returned HTTP " + strconv.Itoa(tc.code); d.LastError != want {
					t.Errorf("last_error = %q, want %q", d.LastError, want)
				}
				if want := t0.Add(time.Second); !d.NextAttemptAt.Equal(want) {
					t.Errorf("next_attempt_at = %s, want %s (one BackoffBase out)", d.NextAttemptAt, want)
				}
				// A retryable failure must not flood the hash-chained audit log; only
				// terminal outcomes are audited.
				if evs := auditDeliverEvents(t, db); len(evs) != 0 {
					t.Errorf("a retryable failure recorded %d audit events, want 0", len(evs))
				}
			}

			// A terminal row is never re-listed; a pending one is not yet due.
			e.deliverDueOnce(ctx)
			if ep.count() != 1 {
				t.Errorf("second sweep re-POSTed: endpoint got %d requests, want 1", ep.count())
			}
		})
	}
}

// TestRetryBackoffAdvancesAndStopsAtTheBudget walks a failing endpoint through
// its whole retry budget, asserting the two pieces of bookkeeping the queue
// depends on: the attempt counter advances by exactly one per POST, and
// next_attempt_at advances by the doubling-then-clamped backoff so a struggling
// endpoint is not hammered. Once the budget is spent the delivery is
// dead-lettered and never attempted again, however far the clock moves.
func TestRetryBackoffAdvancesAndStopsAtTheBudget(t *testing.T) {
	db := newStore(t)
	ep := newStatusEndpoint(t, http.StatusInternalServerError)
	// A credential-bearing endpoint URL: the audit trail and the logs must record
	// only scheme+host, never the token in the query or the path.
	url := ep.url() + "/hooks/in?token=urlquerysecret"
	sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, url, nil)

	clock := newFakeClock()
	var logs syncBuffer
	e := engineFor(db, clock, func(c *Config) {
		c.MaxAttempts = 4
		c.BackoffBase = time.Second
		c.BackoffMax = 4 * time.Second
		c.Logger = testLogger(&logs)
	})
	ctx := context.Background()

	cursor := seedCursorAtHead(t, db)
	appendLifecycle(t, db, audit.ActionCertRevoke, models.DefaultTenantID, "ca-1", "0B")
	e.fanOutOnce(ctx, &cursor)
	if d := onlyDelivery(t, db, sub.ID); d.MaxAttempts != 4 {
		t.Fatalf("max_attempts = %d, want the configured 4 snapshotted at enqueue time", d.MaxAttempts)
	}

	// 1s, 2s, then the 4s clamp (8s would exceed BackoffMax).
	for i, wantBackoff := range []time.Duration{time.Second, 2 * time.Second, 4 * time.Second} {
		attempt := i + 1
		e.deliverDueOnce(ctx)
		if ep.count() != attempt {
			t.Fatalf("after attempt %d: endpoint got %d requests, want %d", attempt, ep.count(), attempt)
		}
		d := onlyDelivery(t, db, sub.ID)
		if d.Status != models.WebhookDeliveryPending {
			t.Fatalf("attempt %d: status = %q, want pending (budget 4)", attempt, d.Status)
		}
		if d.Attempts != attempt {
			t.Fatalf("attempt %d: attempts = %d, want %d", attempt, d.Attempts, attempt)
		}
		if want := clock.now().Add(wantBackoff); !d.NextAttemptAt.Equal(want) {
			t.Fatalf("attempt %d: next_attempt_at = %s, want %s (+%s)", attempt, d.NextAttemptAt, want, wantBackoff)
		}
		// One tick short of due: nothing may be attempted.
		clock.advance(wantBackoff - time.Millisecond)
		e.deliverDueOnce(ctx)
		if ep.count() != attempt {
			t.Fatalf("attempt %d: retried %s early (endpoint got %d requests)", attempt, time.Millisecond, ep.count())
		}
		clock.advance(time.Millisecond)
	}

	// The fourth attempt exhausts the budget -> dead-lettered.
	e.deliverDueOnce(ctx)
	if ep.count() != 4 {
		t.Fatalf("after the final attempt: endpoint got %d requests, want 4", ep.count())
	}
	d := onlyDelivery(t, db, sub.ID)
	if d.Status != models.WebhookDeliveryDead {
		t.Fatalf("status = %q, want dead after 4 of 4 attempts", d.Status)
	}
	if d.Attempts != 4 {
		t.Errorf("attempts = %d, want exactly the 4-attempt budget", d.Attempts)
	}

	// Terminal: no further attempt, ever.
	clock.advance(365 * 24 * time.Hour)
	e.deliverDueOnce(ctx)
	if ep.count() != 4 {
		t.Errorf("a dead-lettered delivery was retried a year later: endpoint got %d requests", ep.count())
	}

	// The dead-letter is auditable, names the attempt count, and leaks neither the
	// endpoint path nor its query token into the tamper-evident log.
	evs := auditDeliverEvents(t, db)
	if len(evs) != 1 || evs[0].Result != audit.ResultError {
		t.Fatalf("want exactly one error-result webhook.deliver audit event, got %+v", evs)
	}
	if !strings.Contains(evs[0].Detail, "dead-lettered after 4 attempts") {
		t.Errorf("audit detail = %q, want it to name the attempt count", evs[0].Detail)
	}
	for _, leak := range []string{"urlquerysecret", "/hooks/in", sub.Secret} {
		if strings.Contains(evs[0].Detail, leak) {
			t.Errorf("audit detail leaked %q: %s", leak, evs[0].Detail)
		}
		if strings.Contains(evs[0].TargetName, leak) {
			t.Errorf("audit target_name leaked %q: %s", leak, evs[0].TargetName)
		}
		if strings.Contains(logs.String(), leak) {
			t.Errorf("the operational log leaked %q: %s", leak, logs.String())
		}
	}
	res, err := db.VerifyEventChain()
	if err != nil || !res.Valid {
		t.Errorf("the audit chain broke after webhook delivery auditing: %+v (%v)", res, err)
	}
}

// TestTransportFailureRetriesAndDoesNotBlockTheBatch proves a connection refused
// is recorded as a transport error (no HTTP status) and retried, and — the
// stability property — that one unreachable endpoint in a batch does not stop the
// healthy endpoints in the same sweep from being delivered.
func TestTransportFailureRetriesAndDoesNotBlockTheBatch(t *testing.T) {
	db := newStore(t)
	ok := newStatusEndpoint(t, http.StatusOK)
	broken := mkSub(t, db, "w-broken", models.DefaultTenantID, models.WebhookScopeTenant, deadEndpointURL(t), nil)
	healthy := mkSub(t, db, "w-ok", models.DefaultTenantID, models.WebhookScopeTenant, ok.url(), nil)

	clock := newFakeClock()
	t0 := clock.now()
	e := engineFor(db, clock, nil)
	ctx := context.Background()

	cursor := seedCursorAtHead(t, db)
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
	e.fanOutOnce(ctx, &cursor)
	e.deliverDueOnce(ctx)

	if d := onlyDelivery(t, db, healthy.ID); d.Status != models.WebhookDeliveryDelivered {
		t.Errorf("a healthy endpoint's delivery is %q: an unreachable peer in the same batch blocked it", d.Status)
	}
	if ok.count() != 1 {
		t.Errorf("healthy endpoint got %d requests, want 1", ok.count())
	}

	d := onlyDelivery(t, db, broken.ID)
	if d.Status != models.WebhookDeliveryPending || d.Attempts != 1 {
		t.Errorf("refused delivery: status/attempts = %q/%d, want pending/1", d.Status, d.Attempts)
	}
	if d.LastStatusCode != 0 {
		t.Errorf("last_status_code = %d, want 0 when no HTTP response was received", d.LastStatusCode)
	}
	if !strings.HasPrefix(d.LastError, "transport error: ") {
		t.Errorf("last_error = %q, want a transport-error reason", d.LastError)
	}
	if want := t0.Add(time.Second); !d.NextAttemptAt.Equal(want) {
		t.Errorf("next_attempt_at = %s, want %s", d.NextAttemptAt, want)
	}
}

// TestDeliveryTimeoutIsBoundedAndRetried proves a receiver that accepts the
// connection and never answers cannot wedge the worker: the per-attempt context
// deadline fires, the sweep returns, and the delivery is retried.
func TestDeliveryTimeoutIsBoundedAndRetried(t *testing.T) {
	db := newStore(t)
	block := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(block) }) }
	ep := newEndpoint(t, func(_ int, _ http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	})
	// Registered after the endpoint, so it runs BEFORE the server shutdown that
	// httptest waits on (cleanups run last-registered-first).
	t.Cleanup(unblock)
	defer unblock()

	sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
	clock := newFakeClock()
	e := engineFor(db, clock, func(c *Config) { c.Timeout = 150 * time.Millisecond })
	ctx := context.Background()

	cursor := seedCursorAtHead(t, db)
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
	e.fanOutOnce(ctx, &cursor)

	swept := make(chan struct{})
	go func() { defer close(swept); e.deliverDueOnce(ctx) }()
	waitReturn(t, "a delivery sweep against a never-answering endpoint", swept, 10*time.Second)

	if ep.count() != 1 {
		t.Fatalf("endpoint got %d requests, want 1 (the timeout must be client-side)", ep.count())
	}
	d := onlyDelivery(t, db, sub.ID)
	if d.Status != models.WebhookDeliveryPending || d.Attempts != 1 {
		t.Errorf("status/attempts = %q/%d, want pending/1", d.Status, d.Attempts)
	}
	if d.LastStatusCode != 0 {
		t.Errorf("last_status_code = %d, want 0 on a timeout", d.LastStatusCode)
	}
	if !strings.Contains(d.LastError, "context deadline exceeded") {
		t.Errorf("last_error = %q, want the per-attempt deadline as the reason", d.LastError)
	}
	if want := clock.now().Add(time.Second); !d.NextAttemptAt.Equal(want) {
		t.Errorf("next_attempt_at = %s, want %s (a timeout is retryable)", d.NextAttemptAt, want)
	}
}

// TestOversizeResponseBody proves a hostile or chatty receiver cannot hurt the
// worker: a multi-megabyte response body is neither buffered into the delivery
// row nor able to stall the sweep, on both the success and the failure path.
func TestOversizeResponseBody(t *testing.T) {
	huge := strings.Repeat("A", 1<<20) // 1 MiB, far past the 4 KiB drain bound

	for _, tc := range []struct {
		name       string
		code       int
		wantStatus string
		wantErr    string
	}{
		{"2xx with a huge body is still delivered", http.StatusOK, models.WebhookDeliveryDelivered, ""},
		{"5xx with a huge body records only the status", http.StatusInternalServerError, models.WebhookDeliveryPending, "endpoint returned HTTP 500"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newStore(t)
			ep := newEndpoint(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.code)
				for i := 0; i < 4; i++ { // 4 MiB in chunks
					if _, err := w.Write([]byte(huge)); err != nil {
						return // the sender closed the body after its bounded drain
					}
				}
			})
			sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)

			clock := newFakeClock()
			e := engineFor(db, clock, nil)
			ctx := context.Background()
			cursor := seedCursorAtHead(t, db)
			appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
			e.fanOutOnce(ctx, &cursor)

			swept := make(chan struct{})
			go func() { defer close(swept); e.deliverDueOnce(ctx) }()
			waitReturn(t, "a delivery sweep against a 4 MiB response", swept, 20*time.Second)

			d := onlyDelivery(t, db, sub.ID)
			if d.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", d.Status, tc.wantStatus)
			}
			if d.LastError != tc.wantErr {
				t.Errorf("last_error = %q, want %q (the response body must never be stored)", d.LastError, tc.wantErr)
			}
			if strings.Contains(d.LastError, "AAAA") {
				t.Errorf("the response body leaked into the delivery row")
			}
		})
	}
}

// TestRedirectHandling pins that a redirecting subscription endpoint is treated as
// a plain failure: the engine's client returns the 3xx as the response rather than
// following it (newHTTPClient sets CheckRedirect to http.ErrUseLastResponse).
//
// Following redirects was silently lossy in two different ways, and both are
// asserted here as NOT happening:
//
//   - A 302/303 is rewritten by net/http into a bodyless GET, so the final
//     receiver never sees the signed payload — yet its 2xx marked the delivery
//     delivered. Events vanished with no retry and no dead-letter.
//   - A 307/308 preserves the body, which means the payload AND the
//     X-Secsy-Signature header were replayed to the redirect target, including a
//     cross-host one (net/http only strips Authorization/Cookie).
//
// Surfacing the 3xx makes it an ordinary non-2xx: retried, then dead-lettered, so
// the operator sees the misconfiguration instead of losing events to it.
func TestRedirectHandling(t *testing.T) {
	// deliverOnce wires one subscription pointed at url and runs a single sweep.
	deliverOnce := func(t *testing.T, url string) (*database.DB, models.WebhookDelivery) {
		t.Helper()
		db := newStore(t)
		sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, url, nil)
		clock := newFakeClock()
		e := engineFor(db, clock, nil)
		ctx := context.Background()
		cursor := seedCursorAtHead(t, db)
		appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
		e.fanOutOnce(ctx, &cursor)
		e.deliverDueOnce(ctx)
		return db, onlyDelivery(t, db, sub.ID)
	}

	// Every redirect status is a retryable non-2xx recorded verbatim, and the
	// redirect target is never contacted — so neither the payload nor its signature
	// can be replayed to another host.
	for _, code := range []int{
		http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
	} {
		t.Run(fmt.Sprintf("%d is not followed", code), func(t *testing.T) {
			final := newStatusEndpoint(t, http.StatusOK)
			front := newEndpoint(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
				http.Redirect(w, &http.Request{}, final.url(), code)
			})
			_, d := deliverOnce(t, front.url())

			if final.count() != 0 {
				t.Errorf("the redirect target got %d requests, want 0: the signed body and "+
					"X-Secsy-Signature must never be forwarded", final.count())
			}
			if d.Status != models.WebhookDeliveryPending || d.Attempts != 1 {
				t.Errorf("status/attempts = %q/%d, want pending/1 (a 3xx is a retryable failure)", d.Status, d.Attempts)
			}
			if d.LastStatusCode != code {
				t.Errorf("last_status_code = %d, want the %d recorded verbatim so the "+
					"misconfiguration is visible to the operator", d.LastStatusCode, code)
			}
			if d.DeliveredAt != nil {
				t.Errorf("delivered_at was set on a delivery the endpoint never accepted")
			}
		})
	}

	// A redirect loop cannot become a POST storm if the first hop is never followed.
	t.Run("a redirect loop is not followed at all", func(t *testing.T) {
		var loop *testEndpoint
		loop = newEndpoint(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, &http.Request{}, loop.url(), http.StatusTemporaryRedirect)
		})
		_, d := deliverOnce(t, loop.url())

		if loop.count() != 1 {
			t.Errorf("the self-redirecting endpoint saw %d requests, want exactly 1", loop.count())
		}
		if d.Status != models.WebhookDeliveryPending || d.Attempts != 1 {
			t.Errorf("status/attempts = %q/%d, want pending/1", d.Status, d.Attempts)
		}
		if d.LastStatusCode != http.StatusTemporaryRedirect {
			t.Errorf("last_status_code = %d, want 307", d.LastStatusCode)
		}
	})

	// SendTest (the `secsy-ca webhook test` path) builds its own client and must
	// make the same choice, or the CLI would report a redirecting endpoint healthy.
	t.Run("SendTest does not follow redirects either", func(t *testing.T) {
		final := newStatusEndpoint(t, http.StatusOK)
		front := newEndpoint(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, &http.Request{}, final.url(), http.StatusFound)
		})
		sub := &models.WebhookSubscription{ID: "w1", URL: front.url(), Secret: "sec-w1"}
		status, err := SendTest(context.Background(), sub, 2*time.Second)
		if err != nil {
			t.Fatalf("SendTest: %v", err)
		}
		if status != http.StatusFound {
			t.Errorf("SendTest reported status %d, want the 302 surfaced", status)
		}
		if final.count() != 0 {
			t.Errorf("SendTest forwarded the signed test payload to the redirect target")
		}
	})
}

// TestStuckRowsDoNotSpinTheDeliveryLoop proves the delivery loop cannot busy-spin
// against a customer endpoint. runDelivery fast-drains whenever a sweep reports a
// full batch, so that count must reflect rows whose durable state ADVANCED, not
// rows merely listed: every store-error path in attemptDelivery leaves the row
// pending-and-due, so counting those would re-POST continuously with no backoff.
func TestStuckRowsDoNotSpinTheDeliveryLoop(t *testing.T) {
	db := newStore(t)
	ep := newStatusEndpoint(t, http.StatusInternalServerError)

	const batch = 3
	for i := 0; i < batch; i++ {
		mkSub(t, db, "w"+strconv.Itoa(i), models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
	}
	store := newHookStore(db)
	e := engineFor(store, newFakeClock(), func(c *Config) { c.BatchSize = batch })
	cursor := seedCursorAtHead(t, db)
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
	e.fanOutOnce(context.Background(), &cursor)

	// The retry bookkeeping write fails, so all `batch` rows stay pending and due —
	// a full batch's worth of rows that made no progress whatsoever.
	store.fail("MarkWebhookDeliveryRetry", errors.New("bookkeeping write failed"))

	n := e.deliverDueOnce(context.Background())
	if n != 0 {
		t.Errorf("deliverDueOnce reported %d rows advanced, want 0: every row is still "+
			"pending-and-due, so reporting progress would make runDelivery spin", n)
	}
	if n >= e.cfg.BatchSize {
		t.Errorf("a sweep that advanced nothing reported a full batch (%d >= %d): "+
			"runDelivery would loop immediately and re-POST with no backoff", n, e.cfg.BatchSize)
	}
	counts, err := db.CountWebhookDeliveriesByStatus()
	if err != nil {
		t.Fatalf("CountWebhookDeliveriesByStatus: %v", err)
	}
	if counts[models.WebhookDeliveryPending] != batch {
		t.Fatalf("pending = %d, want all %d rows still stuck (precondition)", counts[models.WebhookDeliveryPending], batch)
	}

	// Sanity check the other direction: once the write succeeds, a full batch of
	// real progress *is* reported, so genuine backlog still drains without waiting
	// a whole poll interval.
	store.fail("MarkWebhookDeliveryRetry", nil)
	if n := e.deliverDueOnce(context.Background()); n != batch {
		t.Errorf("deliverDueOnce advanced %d rows once the store healed, want %d", n, batch)
	}
}

// --- fan-out routing ------------------------------------------------------------

// TestRunFanOutRoutingMatrix drives the real fan-out loop with N subscriptions
// and two events and asserts the routing table exactly: every matching
// subscription gets exactly one delivery row per matching event and every
// non-matching one gets none. Both filter dimensions are exercised at once —
// event type and tenant scope — plus the enabled gate, because a leak here
// delivers one tenant's certificate events to another tenant's endpoint.
func TestRunFanOutRoutingMatrix(t *testing.T) {
	db := newStore(t)
	mkTenant(t, db, "b")

	all := mkSub(t, db, "w-all", models.DefaultTenantID, models.WebhookScopeTenant, "http://127.0.0.1:1/all", nil)
	issue := mkSub(t, db, "w-issue", models.DefaultTenantID, models.WebhookScopeTenant, "http://127.0.0.1:1/i", []string{audit.ActionCertIssue})
	revoke := mkSub(t, db, "w-revoke", models.DefaultTenantID, models.WebhookScopeTenant, "http://127.0.0.1:1/r", []string{audit.ActionCertRevoke})
	platform := mkSub(t, db, "w-platform", models.DefaultTenantID, models.WebhookScopePlatform, "http://127.0.0.1:1/p", nil)
	tenantB := mkSub(t, db, "w-b", "b", models.WebhookScopeTenant, "http://127.0.0.1:1/b", nil)
	disabled := mkSub(t, db, "w-off", models.DefaultTenantID, models.WebhookScopeTenant, "http://127.0.0.1:1/off", nil)
	if _, err := db.SetWebhookSubscriptionEnabled(disabled.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}

	seedCursorAtHead(t, db)
	ev1 := appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
	ev2 := appendLifecycle(t, db, audit.ActionCertRevoke, "b", "ca-b", "02")
	// Neither of these is deliverable: a denied attempt is not a lifecycle
	// transition, and the bulk summary would double-deliver.
	appendDenied(t, db, audit.ActionCertIssue, models.DefaultTenantID)
	appendLifecycle(t, db, audit.ActionCertIssueBulk, models.DefaultTenantID, "ca-1", "bulk")

	e := engineFor(db, newFakeClock(), nil) // PollInterval 1h: the initial sweep does the work
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.runFanOut(ctx) }()

	// The platform subscription is the last to be satisfied (it takes both events),
	// so waiting for it waits for the whole sweep.
	waitFor(t, "the fan-out to enqueue both events for the platform subscription", func() bool {
		return deliveryCount(t, db, platform.ID) == 2
	})
	cancel()
	waitReturn(t, "runFanOut", done, 5*time.Second)

	// Re-sweeping the same range (a crash between enqueue and cursor advance) must
	// not double-enqueue: UNIQUE(subscription_id, event_seq) makes it idempotent.
	rewound := ev1.Seq - 1
	e.fanOutOnce(context.Background(), &rewound)

	for _, tc := range []struct {
		sub  *models.WebhookSubscription
		want int
		why  string
	}{
		{all, 1, "an unfiltered tenant-scoped subscription takes only its own tenant's event"},
		{issue, 1, "a cert.issue filter takes the issue event only"},
		{revoke, 0, "a cert.revoke filter must not take another tenant's revoke event"},
		{platform, 2, "a platform-scoped subscription takes every tenant's events"},
		{tenantB, 1, "tenant b takes its own revoke event only"},
		{disabled, 0, "a disabled subscription produces no deliveries"},
	} {
		if n := deliveryCount(t, db, tc.sub.ID); n != tc.want {
			t.Errorf("%s: %s has %d deliveries, want %d", tc.why, tc.sub.ID, n, tc.want)
		}
	}

	// The rows themselves must be correctly attributed: the row is scoped to the
	// subscription's tenant (for scoped reads) while the payload carries the
	// event's tenant (for the receiver).
	rows, err := db.ListWebhookDeliveries(platform.ID, "", 0)
	if err != nil {
		t.Fatalf("ListWebhookDeliveries: %v", err)
	}
	seq := map[int64]models.WebhookDelivery{}
	for _, r := range rows {
		seq[r.EventSeq] = r
	}
	for _, ev := range []audit.Event{ev1, ev2} {
		r, ok := seq[ev.Seq]
		if !ok {
			t.Fatalf("platform subscription has no delivery for event seq %d", ev.Seq)
		}
		if r.EventType != ev.Action || r.EventID != ev.ID {
			t.Errorf("row for seq %d = %q/%q, want %q/%q", ev.Seq, r.EventType, r.EventID, ev.Action, ev.ID)
		}
		if r.TenantID != platform.TenantID {
			t.Errorf("row tenant = %q, want the subscription's %q", r.TenantID, platform.TenantID)
		}
		if r.Status != models.WebhookDeliveryPending || r.MaxAttempts != 3 {
			t.Errorf("row status/budget = %q/%d, want pending/3", r.Status, r.MaxAttempts)
		}
		assertPayloadTenant(t, r, ev)
	}
}

// appendDenied appends a lifecycle action that was REFUSED, which must never be
// delivered (it is not a lifecycle transition).
func appendDenied(t *testing.T, db *database.DB, action, tenant string) {
	t.Helper()
	if err := db.AppendEvent(&audit.Event{
		ID: "denied-" + action + "-" + tenant, Actor: "tester", Action: action,
		Tenant: tenant, Result: audit.ResultDenied, Detail: "quota exhausted",
	}); err != nil {
		t.Fatalf("AppendEvent(denied): %v", err)
	}
}

// assertPayloadTenant proves the signed body carries the source event's tenant
// (normalized), not the subscription's.
func assertPayloadTenant(t *testing.T, d models.WebhookDelivery, ev audit.Event) {
	t.Helper()
	want := ev.Tenant
	if want == "" {
		want = models.DefaultTenantID
	}
	if !strings.Contains(d.Payload, `"tenant":"`+want+`"`) {
		t.Errorf("payload for seq %d does not carry tenant %q: %s", ev.Seq, want, d.Payload)
	}
	if !strings.Contains(d.Payload, `"sequence":`+strconv.FormatInt(ev.Seq, 10)) {
		t.Errorf("payload does not carry sequence %d: %s", ev.Seq, d.Payload)
	}
}

// TestRunFanOutWakesOnNotify proves the audit-append nudge actually shortens
// delivery latency: with the poll interval set to an hour, the only thing that can
// make the fan-out notice a freshly committed event is the wake channel.
func TestRunFanOutWakesOnNotify(t *testing.T) {
	db := newStore(t)
	sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, "http://127.0.0.1:1/hook", nil)
	seedCursorAtHead(t, db)

	store := newHookStore(db)
	e := engineFor(store, newFakeClock(), nil) // PollInterval 1h
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.runFanOut(ctx) }()

	// The first sweep ends by refreshing the queue gauges, so once that has
	// happened the loop is parked in its select and any later delivery can only be
	// explained by the wake.
	waitFor(t, "the initial fan-out sweep to finish", func() bool { return store.callCount("CountWebhookDeliveriesByStatus") >= 1 })
	if n := deliveryCount(t, db, sub.ID); n != 0 {
		t.Fatalf("the initial sweep enqueued %d deliveries, want 0 (the cursor was at head)", n)
	}

	ev := appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
	e.Notify(ev)
	waitFor(t, "the nudged fan-out to enqueue the new event", func() bool { return deliveryCount(t, db, sub.ID) == 1 })

	cancel()
	waitReturn(t, "runFanOut", done, 5*time.Second)
}

// --- store fault injection ------------------------------------------------------

// hookStore wraps a Store so a test can count the engine's store calls and inject
// a failure at one exact seam. Embedding the interface keeps it a drop-in for
// *database.DB: only the overridden methods change behavior.
type hookStore struct {
	Store
	mu     sync.Mutex
	calls  map[string]int
	errs   map[string]error
	subNil bool
	// emptyEvents makes the log read return nothing while the head still reports
	// unscanned events — the shape that would spin the fan-out forever.
	emptyEvents bool
}

func newHookStore(inner Store) *hookStore {
	return &hookStore{Store: inner, calls: map[string]int{}, errs: map[string]error{}}
}

// record counts a call and returns the injected error for it, if any.
func (s *hookStore) record(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls[name]++
	return s.errs[name]
}

func (s *hookStore) callCount(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[name]
}

// fail makes the named store method return err (pass nil to heal it).
func (s *hookStore) fail(name string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		delete(s.errs, name)
		return
	}
	s.errs[name] = err
}

// starveEvents makes the log read come back empty even though the head is ahead.
func (s *hookStore) starveEvents() {
	s.mu.Lock()
	s.emptyEvents = true
	s.mu.Unlock()
}

// vanish makes the subscription lookup report "no such subscription".
func (s *hookStore) vanish() {
	s.mu.Lock()
	s.subNil = true
	s.mu.Unlock()
}

func (s *hookStore) MaxEventSeq() (int64, error) {
	if err := s.record("MaxEventSeq"); err != nil {
		return 0, err
	}
	return s.Store.MaxEventSeq()
}

func (s *hookStore) ListEventsSince(afterSeq int64, limit int) ([]audit.Event, error) {
	if err := s.record("ListEventsSince"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	empty := s.emptyEvents
	s.mu.Unlock()
	if empty {
		return nil, nil
	}
	return s.Store.ListEventsSince(afterSeq, limit)
}

func (s *hookStore) ListEnabledWebhookSubscriptions() ([]models.WebhookSubscription, error) {
	if err := s.record("ListEnabledWebhookSubscriptions"); err != nil {
		return nil, err
	}
	return s.Store.ListEnabledWebhookSubscriptions()
}

func (s *hookStore) GetWebhookSubscription(id string) (*models.WebhookSubscription, error) {
	if err := s.record("GetWebhookSubscription"); err != nil {
		return nil, err
	}
	s.mu.Lock()
	gone := s.subNil
	s.mu.Unlock()
	if gone {
		return nil, nil
	}
	return s.Store.GetWebhookSubscription(id)
}

func (s *hookStore) EnqueueWebhookDelivery(d *models.WebhookDelivery) error {
	if err := s.record("EnqueueWebhookDelivery"); err != nil {
		return err
	}
	return s.Store.EnqueueWebhookDelivery(d)
}

func (s *hookStore) WebhookCursorInitialized() (bool, error) {
	if err := s.record("WebhookCursorInitialized"); err != nil {
		return false, err
	}
	return s.Store.WebhookCursorInitialized()
}

func (s *hookStore) GetWebhookCursor() (int64, error) {
	if err := s.record("GetWebhookCursor"); err != nil {
		return 0, err
	}
	return s.Store.GetWebhookCursor()
}

func (s *hookStore) SetWebhookCursor(seq int64) error {
	if err := s.record("SetWebhookCursor"); err != nil {
		return err
	}
	return s.Store.SetWebhookCursor(seq)
}

func (s *hookStore) ListDueWebhookDeliveries(now time.Time, limit int) ([]models.WebhookDelivery, error) {
	if err := s.record("ListDueWebhookDeliveries"); err != nil {
		return nil, err
	}
	return s.Store.ListDueWebhookDeliveries(now, limit)
}

func (s *hookStore) MarkWebhookDeliverySucceeded(id string, at time.Time, statusCode int) error {
	if err := s.record("MarkWebhookDeliverySucceeded"); err != nil {
		return err
	}
	return s.Store.MarkWebhookDeliverySucceeded(id, at, statusCode)
}

func (s *hookStore) MarkWebhookDeliveryRetry(id string, at, next time.Time, statusCode int, errMsg string) error {
	if err := s.record("MarkWebhookDeliveryRetry"); err != nil {
		return err
	}
	return s.Store.MarkWebhookDeliveryRetry(id, at, next, statusCode, errMsg)
}

func (s *hookStore) MarkWebhookDeliveryDead(id string, at time.Time, statusCode int, errMsg string) error {
	if err := s.record("MarkWebhookDeliveryDead"); err != nil {
		return err
	}
	return s.Store.MarkWebhookDeliveryDead(id, at, statusCode, errMsg)
}

func (s *hookStore) CancelPendingWebhookDeliveries(subscriptionID string) (int64, error) {
	if err := s.record("CancelPendingWebhookDeliveries"); err != nil {
		return 0, err
	}
	return s.Store.CancelPendingWebhookDeliveries(subscriptionID)
}

func (s *hookStore) CountWebhookDeliveriesByStatus() (map[string]int, error) {
	if err := s.record("CountWebhookDeliveriesByStatus"); err != nil {
		return nil, err
	}
	return s.Store.CountWebhookDeliveriesByStatus()
}

func (s *hookStore) AppendEvent(e *audit.Event) error {
	if err := s.record("AppendEvent"); err != nil {
		return err
	}
	return s.Store.AppendEvent(e)
}

// --- background loops -----------------------------------------------------------

// engineLoopGoroutines counts live delivery-engine loop goroutines by frame name,
// so the leak check is immune to unrelated (http, test harness) goroutines.
func engineLoopGoroutines() int {
	buf := make([]byte, 1<<20)
	dump := string(buf[:runtime.Stack(buf, true)])
	return strings.Count(dump, "webhook.(*Engine).runFanOut") + strings.Count(dump, "webhook.(*Engine).runDelivery")
}

// TestRunDeliveryDrainsBacklogAndStopsPromptly proves the delivery loop drains a
// backlog deeper than one batch without waiting a poll interval between batches
// (the poll interval here is an hour, so only the full-batch fast path can
// explain the drain) and that it returns as soon as the context is canceled.
func TestRunDeliveryDrainsBacklogAndStopsPromptly(t *testing.T) {
	db := newStore(t)
	ep := newStatusEndpoint(t, http.StatusOK)

	const subs = 5
	var ids []string
	for i := 0; i < subs; i++ {
		id := "w" + strconv.Itoa(i)
		mkSub(t, db, id, models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
		ids = append(ids, id)
	}

	clock := newFakeClock()
	e := engineFor(db, clock, func(c *Config) { c.BatchSize = 2 }) // 5 rows = 2 + 2 + 1
	cursor := seedCursorAtHead(t, db)
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
	e.fanOutOnce(context.Background(), &cursor)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); e.runDelivery(ctx) }()

	waitFor(t, "the whole backlog to drain across several batches", func() bool {
		counts, err := db.CountWebhookDeliveriesByStatus()
		if err != nil {
			t.Fatalf("CountWebhookDeliveriesByStatus: %v", err)
		}
		return counts[models.WebhookDeliveryDelivered] == subs
	})
	cancel()
	waitReturn(t, "runDelivery", done, 5*time.Second)

	for _, id := range ids {
		if d := onlyDelivery(t, db, id); d.Status != models.WebhookDeliveryDelivered || d.Attempts != 1 {
			t.Errorf("%s: status/attempts = %q/%d, want delivered/1", id, d.Status, d.Attempts)
		}
	}
	if ep.count() != subs {
		t.Errorf("endpoint got %d requests, want exactly %d (no duplicate POSTs)", ep.count(), subs)
	}
}

// TestRunStopsOnContextCancel is the background-job contract: Run must return
// promptly when its context is canceled and must leave no goroutine behind, or a
// leadership handover leaks a worker per handover and two replicas end up
// delivering at once.
func TestRunStopsOnContextCancel(t *testing.T) {
	t.Run("already-canceled context", func(t *testing.T) {
		db := newStore(t)
		var logs syncBuffer
		e := engineFor(db, newFakeClock(), func(c *Config) { c.Logger = testLogger(&logs) })

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		done := make(chan struct{})
		go func() { defer close(done); e.Run(ctx) }()
		waitReturn(t, "Run with an already-canceled context", done, 5*time.Second)

		if !strings.Contains(logs.String(), "worker stopped") {
			t.Errorf("Run did not log its shutdown: %q", logs.String())
		}
		waitFor(t, "both loop goroutines to exit", func() bool { return engineLoopGoroutines() == 0 })
	})

	t.Run("running worker", func(t *testing.T) {
		db := newStore(t)
		ep := newStatusEndpoint(t, http.StatusOK)
		sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
		seedCursorAtHead(t, db)

		var logs syncBuffer
		clock := newFakeClock()
		e := engineFor(db, clock, func(c *Config) {
			c.PollInterval = 10 * time.Millisecond // the delivery loop is tick-driven
			c.Logger = testLogger(&logs)
		})

		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); e.Run(ctx) }()

		ev := appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
		e.Notify(ev)
		waitFor(t, "the worker to deliver the event end to end", func() bool {
			rows, err := db.ListWebhookDeliveries(sub.ID, models.WebhookDeliveryDelivered, 0)
			if err != nil {
				t.Fatalf("ListWebhookDeliveries: %v", err)
			}
			return len(rows) == 1
		})

		cancel()
		waitReturn(t, "Run", done, 5*time.Second)
		waitFor(t, "both loop goroutines to exit", func() bool { return engineLoopGoroutines() == 0 })

		if !strings.Contains(logs.String(), "worker started") || !strings.Contains(logs.String(), "worker stopped") {
			t.Errorf("Run did not log its lifecycle: %q", logs.String())
		}
		if strings.Contains(logs.String(), sub.Secret) {
			t.Errorf("the worker logged the subscription secret: %q", logs.String())
		}
	})
}

// TestRunOnceSeedsThenResumes covers the deterministic one-shot driver: the first
// call seeds the cursor at the log head so enabling the feature does not replay
// history, later calls resume from the persisted cursor and carry an event all the
// way to the endpoint, and a call with nothing new redelivers nothing.
func TestRunOnceSeedsThenResumes(t *testing.T) {
	db := newStore(t)
	ep := newStatusEndpoint(t, http.StatusOK)
	sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)

	// Pre-existing history, committed before the worker ever ran.
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
	head, err := db.MaxEventSeq()
	if err != nil {
		t.Fatalf("MaxEventSeq: %v", err)
	}

	e := engineFor(db, newFakeClock(), nil)
	ctx := context.Background()

	e.RunOnce(ctx)
	if n := deliveryCount(t, db, sub.ID); n != 0 {
		t.Fatalf("the first RunOnce replayed %d historical events, want 0", n)
	}
	if ep.count() != 0 {
		t.Fatalf("endpoint got %d requests on the seeding run, want 0", ep.count())
	}
	if cur, err := db.GetWebhookCursor(); err != nil || cur != head {
		t.Fatalf("cursor = %d (%v), want the log head %d", cur, err, head)
	}

	ev := appendLifecycle(t, db, audit.ActionCertRenew, models.DefaultTenantID, "ca-1", "02")
	e.RunOnce(ctx)

	d := onlyDelivery(t, db, sub.ID)
	if d.Status != models.WebhookDeliveryDelivered {
		t.Fatalf("status = %q, want delivered after a resumed RunOnce", d.Status)
	}
	if d.EventSeq != ev.Seq {
		t.Errorf("event_seq = %d, want the post-enablement event %d", d.EventSeq, ev.Seq)
	}
	if ep.count() != 1 {
		t.Fatalf("endpoint got %d requests, want 1", ep.count())
	}
	if cur, _ := db.GetWebhookCursor(); cur != ev.Seq {
		t.Errorf("cursor = %d, want %d after the sweep", cur, ev.Seq)
	}

	// Nothing new: no fan-out, no redelivery of a terminal row.
	e.RunOnce(ctx)
	if n := deliveryCount(t, db, sub.ID); n != 1 {
		t.Errorf("an idle RunOnce created deliveries: %d rows, want 1", n)
	}
	if ep.count() != 1 {
		t.Errorf("an idle RunOnce re-POSTed: endpoint got %d requests, want 1", ep.count())
	}
}

// --- store faults and mid-flight subscription changes ---------------------------

// TestSubscriptionVanishesMidFlight proves a queued delivery whose subscription
// disappeared between enqueue and attempt is canceled instead of POSTed: without
// this the worker would keep hammering an endpoint whose registration is gone.
func TestSubscriptionVanishesMidFlight(t *testing.T) {
	db := newStore(t)
	ep := newStatusEndpoint(t, http.StatusOK)
	sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)

	store := newHookStore(db)
	e := engineFor(store, newFakeClock(), nil)
	ctx := context.Background()
	cursor := seedCursorAtHead(t, db)
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
	e.fanOutOnce(ctx, &cursor)

	store.vanish()
	e.deliverDueOnce(ctx)

	if ep.count() != 0 {
		t.Errorf("endpoint got %d requests for a vanished subscription, want 0", ep.count())
	}
	if d := onlyDelivery(t, db, sub.ID); d.Status != models.WebhookDeliveryCanceled {
		t.Errorf("status = %q, want canceled", d.Status)
	}
	if n := store.callCount("CancelPendingWebhookDeliveries"); n != 1 {
		t.Errorf("CancelPendingWebhookDeliveries called %d times, want 1", n)
	}

	// Even when the cancel write itself fails, the vanished subscription's endpoint
	// is never POSTed to; the row simply stays claimable for the next sweep.
	store.fail("CancelPendingWebhookDeliveries", errors.New("store unavailable"))
	second := mkSub(t, db, "w2", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
	cursor2 := seedCursorAtHead(t, db)
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "02")
	e.fanOutOnce(ctx, &cursor2)
	e.deliverDueOnce(ctx)
	if ep.count() != 0 {
		t.Errorf("endpoint got %d requests after a failed cancel, want 0", ep.count())
	}
	for _, d := range mustDeliveries(t, db, second.ID) {
		if d.Status != models.WebhookDeliveryPending {
			t.Errorf("status = %q, want pending when the cancel write failed", d.Status)
		}
	}

	// Terminal: the canceled row is not re-listed on the next sweep.
	e.deliverDueOnce(ctx)
	if ep.count() != 0 {
		t.Errorf("a canceled delivery was attempted: endpoint got %d requests", ep.count())
	}
}

// TestFanOutStoreFaultsPreserveWork proves a store hiccup never loses an event:
// on any error the fan-out returns WITHOUT advancing the cursor, so the batch is
// re-scanned, and because enqueue is idempotent the re-scan cannot double-deliver.
func TestFanOutStoreFaultsPreserveWork(t *testing.T) {
	boom := errors.New("store unavailable")

	for _, seam := range []string{"MaxEventSeq", "ListEventsSince", "ListEnabledWebhookSubscriptions", "EnqueueWebhookDelivery", "SetWebhookCursor"} {
		t.Run(seam, func(t *testing.T) {
			db := newStore(t)
			sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, "http://127.0.0.1:1/hook", nil)
			start := seedCursorAtHead(t, db)
			appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")

			store := newHookStore(db)
			var logs syncBuffer
			e := engineFor(store, newFakeClock(), func(c *Config) { c.Logger = testLogger(&logs) })
			store.fail(seam, boom)

			cursor := start
			e.fanOutOnce(context.Background(), &cursor) // must not panic
			if cur, err := db.GetWebhookCursor(); err != nil || cur != start {
				t.Errorf("persisted cursor = %d (%v), want %d: a failed sweep must not advance it", cur, err, start)
			}
			if cursor != start {
				t.Errorf("in-memory cursor = %d, want %d", cursor, start)
			}
			if logs.String() == "" {
				t.Errorf("a store failure at %s was swallowed silently", seam)
			}

			// Heal the store: the retried sweep must land the delivery exactly once.
			store.fail(seam, nil)
			e.fanOutOnce(context.Background(), &cursor)
			if n := deliveryCount(t, db, sub.ID); n != 1 {
				t.Fatalf("after recovery: %d deliveries, want exactly 1", n)
			}
			// And a third sweep from the rewound cursor still yields one row.
			rewound := start
			e.fanOutOnce(context.Background(), &rewound)
			if n := deliveryCount(t, db, sub.ID); n != 1 {
				t.Errorf("a re-scan double-enqueued: %d deliveries, want 1", n)
			}
		})
	}
}

// TestDeliveryStoreFaultsKeepTheRowClaimable covers the delivery-side seams:
//
//   - a failing subscription lookup is transient, so the row is left untouched
//     (no POST, no attempt spent);
//   - a POST that succeeded but whose bookkeeping write failed leaves the row
//     pending, which is exactly the at-least-once redelivery window receivers must
//     deduplicate on (EventID) — the row must never be lost or stuck.
func TestDeliveryStoreFaultsKeepTheRowClaimable(t *testing.T) {
	boom := errors.New("store unavailable")

	t.Run("subscription lookup fails", func(t *testing.T) {
		db := newStore(t)
		ep := newStatusEndpoint(t, http.StatusOK)
		sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
		store := newHookStore(db)
		e := engineFor(store, newFakeClock(), nil)
		ctx := context.Background()
		cursor := seedCursorAtHead(t, db)
		appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
		e.fanOutOnce(ctx, &cursor)

		store.fail("GetWebhookSubscription", boom)
		e.deliverDueOnce(ctx)
		if ep.count() != 0 {
			t.Errorf("endpoint got %d requests despite an unreadable subscription", ep.count())
		}
		d := onlyDelivery(t, db, sub.ID)
		if d.Status != models.WebhookDeliveryPending || d.Attempts != 0 {
			t.Errorf("status/attempts = %q/%d, want pending/0 (a transient store error must not spend the budget)", d.Status, d.Attempts)
		}

		store.fail("GetWebhookSubscription", nil)
		e.deliverDueOnce(ctx)
		if d := onlyDelivery(t, db, sub.ID); d.Status != models.WebhookDeliveryDelivered {
			t.Errorf("status = %q after recovery, want delivered", d.Status)
		}
	})

	t.Run("success bookkeeping fails", func(t *testing.T) {
		db := newStore(t)
		ep := newStatusEndpoint(t, http.StatusOK)
		sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
		store := newHookStore(db)
		var logs syncBuffer
		e := engineFor(store, newFakeClock(), func(c *Config) { c.Logger = testLogger(&logs) })
		ctx := context.Background()
		cursor := seedCursorAtHead(t, db)
		appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
		e.fanOutOnce(ctx, &cursor)

		store.fail("MarkWebhookDeliverySucceeded", boom)
		e.deliverDueOnce(ctx)
		if ep.count() != 1 {
			t.Fatalf("endpoint got %d requests, want 1", ep.count())
		}
		d := onlyDelivery(t, db, sub.ID)
		if d.Status != models.WebhookDeliveryPending {
			t.Errorf("status = %q, want pending: a lost acknowledgement must leave the row claimable", d.Status)
		}
		if !strings.Contains(logs.String(), "marking") {
			t.Errorf("the failed bookkeeping write was not logged: %q", logs.String())
		}
		// No audit event for an outcome that was not persisted.
		if evs := auditDeliverEvents(t, db); len(evs) != 0 {
			t.Errorf("recorded %d audit events for an unpersisted outcome, want 0", len(evs))
		}

		// The next sweep redelivers (at-least-once) and converges once the store heals.
		store.fail("MarkWebhookDeliverySucceeded", nil)
		e.deliverDueOnce(ctx)
		if ep.count() != 2 {
			t.Errorf("endpoint got %d requests, want 2 (the redelivery)", ep.count())
		}
		if d := onlyDelivery(t, db, sub.ID); d.Status != models.WebhookDeliveryDelivered {
			t.Errorf("status = %q, want delivered after recovery", d.Status)
		}
	})
}

// --- signing on the wire --------------------------------------------------------

// TestSignatureIsPerAttemptOverTheExactBody proves the authentication contract on
// the wire: each attempt signs the exact bytes it sends under a freshly stamped
// timestamp (so a receiver's freshness window actually bounds replay), the body
// itself is byte-identical across retries and carries a stable idempotency key,
// and the shared secret never leaves the process.
func TestSignatureIsPerAttemptOverTheExactBody(t *testing.T) {
	db := newStore(t)
	// Fail the first attempt, accept the retry.
	ep := newEndpoint(t, func(n int, w http.ResponseWriter, _ *http.Request) {
		if n == 0 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)

	clock := newFakeClock()
	t0 := clock.now()
	var logs syncBuffer
	e := engineFor(db, clock, func(c *Config) { c.Logger = testLogger(&logs) })
	ctx := context.Background()
	cursor := seedCursorAtHead(t, db)
	ev := appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "0A")
	e.fanOutOnce(ctx, &cursor)
	row := onlyDelivery(t, db, sub.ID)

	e.deliverDueOnce(ctx) // attempt 1: 500 -> retry in 1s
	clock.advance(5 * time.Second)
	e.deliverDueOnce(ctx) // attempt 2: 200 -> delivered

	if ep.count() != 2 {
		t.Fatalf("endpoint got %d requests, want 2", ep.count())
	}
	if d := onlyDelivery(t, db, sub.ID); d.Status != models.WebhookDeliveryDelivered {
		t.Fatalf("status = %q, want delivered", d.Status)
	}

	first, second := ep.at(t, 0), ep.at(t, 1)
	for i, req := range []capturedReq{first, second} {
		attempt := i + 1
		if string(req.body) != row.Payload {
			t.Errorf("attempt %d body != the stored payload:\n got %q\nwant %q", attempt, req.body, row.Payload)
		}
		signedAt := t0.Add(time.Duration(i) * 5 * time.Second)
		if err := Verify(sub.Secret, req.sig(), req.body, time.Minute, signedAt); err != nil {
			t.Errorf("attempt %d signature did not verify: %v", attempt, err)
		}
		unix, _, err := parseSignatureHeader(req.sig())
		if err != nil {
			t.Fatalf("attempt %d: unparsable signature header %q: %v", attempt, req.sig(), err)
		}
		if unix != signedAt.Unix() {
			t.Errorf("attempt %d signed at t=%d, want %d (the engine must sign with its injected clock)", attempt, unix, signedAt.Unix())
		}
		if got, want := req.header.Get("X-Secsy-Attempt"), strconv.Itoa(attempt); got != want {
			t.Errorf("X-Secsy-Attempt = %q on attempt %d, want %q", got, attempt, want)
		}
		if got := req.header.Get("X-Secsy-Delivery"); got != row.ID {
			t.Errorf("X-Secsy-Delivery = %q on attempt %d, want the stable delivery id %q", got, attempt, row.ID)
		}
		if got := req.header.Get("X-Secsy-Event"); got != audit.ActionCertIssue {
			t.Errorf("X-Secsy-Event = %q, want %q", got, audit.ActionCertIssue)
		}
		if !strings.Contains(string(req.body), `"event_id":"`+ev.ID+`"`) {
			t.Errorf("attempt %d body lost the idempotency key %q: %s", attempt, ev.ID, req.body)
		}
		assertNoSecret(t, req, sub.Secret)
	}

	// Same bytes, different timestamp => a different tag. A retry must not be a
	// byte-identical replay of the first attempt.
	if first.sig() == second.sig() {
		t.Errorf("both attempts carried the identical signature %q: the timestamp is not refreshed per attempt", first.sig())
	}
	// Both attempts carry the same bytes, so only the signed timestamp separates a
	// legitimate redelivery from a replay of the captured first attempt: the older
	// tag must fall outside a tight receiver tolerance.
	if err := Verify(sub.Secret, first.sig(), second.body, time.Second, t0.Add(5*time.Second)); err == nil {
		t.Errorf("a 5s-old signature verified inside a 1s freshness window: replay is not bounded")
	}
	if strings.Contains(logs.String(), sub.Secret) {
		t.Errorf("the signing secret reached the operational log: %q", logs.String())
	}
}

// TestTestDeliveryThroughTheWorker covers the REST test-delivery path end to end:
// NewTestDelivery's row is due immediately, the worker signs and POSTs it like any
// other delivery, and its negative sentinel sequence keeps repeated test sends
// clear of each other and of the real event space under
// UNIQUE(subscription_id, event_seq).
func TestTestDeliveryThroughTheWorker(t *testing.T) {
	db := newStore(t)
	ep := newStatusEndpoint(t, http.StatusOK)
	sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
	// A real event occupies the positive sequence space.
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")

	first, err := NewTestDelivery(sub, 2)
	if err != nil {
		t.Fatalf("NewTestDelivery: %v", err)
	}
	if err := db.EnqueueWebhookDelivery(first); err != nil {
		t.Fatalf("EnqueueWebhookDelivery: %v", err)
	}
	second, err := NewTestDelivery(sub, 2)
	if err != nil {
		t.Fatalf("NewTestDelivery: %v", err)
	}
	if err := db.EnqueueWebhookDelivery(second); err != nil {
		t.Fatalf("EnqueueWebhookDelivery: %v", err)
	}
	if second.EventSeq == first.EventSeq {
		t.Fatalf("two test deliveries share event_seq %d: the second would be silently dropped", first.EventSeq)
	}

	rows, err := db.ListWebhookDeliveries(sub.ID, "", 0)
	if err != nil {
		t.Fatalf("ListWebhookDeliveries: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("stored %d test deliveries, want 2 (the sentinel sequences must not collide)", len(rows))
	}

	// A real clock: the row is stamped with time.Now, not the test's fake clock.
	e := engineFor(db, nil, nil)
	e.deliverDueOnce(context.Background())

	if ep.count() != 2 {
		t.Fatalf("endpoint got %d requests, want 2", ep.count())
	}
	for i := 0; i < 2; i++ {
		req := ep.at(t, i)
		if got := req.header.Get("X-Secsy-Event"); got != "webhook.test" {
			t.Errorf("X-Secsy-Event = %q, want webhook.test", got)
		}
		if err := Verify(sub.Secret, req.sig(), req.body, time.Minute, time.Now()); err != nil {
			t.Errorf("test delivery %d did not verify: %v", i, err)
		}
		assertNoSecret(t, req, sub.Secret)
	}
	for _, r := range rows {
		d, err := db.GetWebhookDelivery(r.ID)
		if err != nil {
			t.Fatalf("GetWebhookDelivery: %v", err)
		}
		if d.Status != models.WebhookDeliveryDelivered {
			t.Errorf("test delivery %s status = %q, want delivered", d.ID, d.Status)
		}
	}
}

// --- concurrency ----------------------------------------------------------------

// TestConcurrentNotifyAndRunOnce hammers the engine the way production does — many
// audit appends nudging the fan-out while sweeps run — to give -race something to
// find and to prove the durable invariant holds under concurrency: exactly one
// delivery row per (subscription, event), never a lost event, never a duplicate
// row. Concurrent sweeps MAY re-POST the same row (that is the documented
// at-least-once window, and why the worker is leader-elected), so only the row
// bookkeeping is asserted exactly.
func TestConcurrentNotifyAndRunOnce(t *testing.T) {
	db := newStore(t)
	ep := newStatusEndpoint(t, http.StatusOK)
	sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
	seedCursorAtHead(t, db)

	clock := newFakeClock()
	e := engineFor(db, clock, nil)
	ctx := context.Background()

	const appenders, perAppender, sweepers = 2, 5, 3
	var (
		wg      sync.WaitGroup
		errMu   sync.Mutex
		errs    []error
		appends = appenders * perAppender
	)
	record := func(err error) {
		if err == nil {
			return
		}
		errMu.Lock()
		errs = append(errs, err)
		errMu.Unlock()
	}

	for a := 0; a < appenders; a++ {
		wg.Add(1)
		go func(a int) {
			defer wg.Done()
			for i := 0; i < perAppender; i++ {
				ev := &audit.Event{
					ID:     "conc-" + strconv.Itoa(a) + "-" + strconv.Itoa(i),
					Actor:  "tester",
					Action: audit.ActionCertIssue,
					Tenant: models.DefaultTenantID,
					Target: "ca-1", TargetName: strconv.Itoa(i),
					Result: audit.ResultSuccess,
				}
				record(db.AppendEvent(ev))
				e.Notify(*ev) // the audit-append hook, exactly as the server wires it
			}
		}(a)
	}
	for s := 0; s < sweepers; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				e.RunOnce(ctx)
			}
		}()
	}
	wg.Wait()

	errMu.Lock()
	for _, err := range errs {
		t.Errorf("concurrent append failed: %v", err)
	}
	errMu.Unlock()

	// Quiescent sweeps drain whatever the racing sweepers left behind, stepping the
	// clock past any backoff a raced attempt may have scheduled. Bounded, so a
	// genuinely stuck row still fails the assertions below rather than hanging.
	for i := 0; i < 1+3; i++ {
		e.RunOnce(ctx)
		counts, err := db.CountWebhookDeliveriesByStatus()
		if err != nil {
			t.Fatalf("CountWebhookDeliveriesByStatus: %v", err)
		}
		if counts[models.WebhookDeliveryPending] == 0 {
			break
		}
		clock.advance(time.Minute)
	}

	rows, err := db.ListWebhookDeliveries(sub.ID, "", 0)
	if err != nil {
		t.Fatalf("ListWebhookDeliveries: %v", err)
	}
	if len(rows) != appends {
		t.Fatalf("%d delivery rows for %d events: the fan-out lost or duplicated work", len(rows), appends)
	}
	seqs := map[int64]bool{}
	for _, d := range rows {
		if seqs[d.EventSeq] {
			t.Errorf("event_seq %d has more than one delivery row", d.EventSeq)
		}
		seqs[d.EventSeq] = true
		if d.Status != models.WebhookDeliveryDelivered {
			t.Errorf("delivery %s (seq %d) status = %q, want delivered", d.ID, d.EventSeq, d.Status)
		}
		if d.Attempts < 1 {
			t.Errorf("delivery %s attempts = %d, want at least 1", d.ID, d.Attempts)
		}
	}
	if ep.count() < appends {
		t.Errorf("endpoint got %d requests for %d events, want at least one each", ep.count(), appends)
	}
	if cur, err := db.GetWebhookCursor(); err != nil || cur < 1 {
		t.Errorf("cursor = %d (%v), want it advanced past the appended events", cur, err)
	}
}

// TestCursorReadFaultsAtStartup pins the fail-safe behavior of cursor
// initialization. initCursor runs on every worker start — and therefore on every
// leadership handover — so a transient store hiccup there must never be allowed to
// guess at the cursor. Both reachable read failures must leave the persisted
// cursor untouched and report "not ready" so the caller skips the sweep and
// retries:
//
//   - WebhookCursorInitialized fails: treating that as "never initialized" would
//     RE-SEED the cursor to the current log head, silently and permanently dropping
//     every event committed since the last sweep (no retry, no dead-letter).
//   - GetWebhookCursor fails: falling back to the genesis would re-scan the whole
//     log and replay the entire certificate history to every subscriber endpoint.
//
// Each subtest then heals the store and asserts the backlog is delivered exactly
// once — proving the skip deferred the work rather than losing or duplicating it.
func TestCursorReadFaultsAtStartup(t *testing.T) {
	boom := errors.New("cursor read failed")

	for _, tc := range []struct {
		name   string
		method string
	}{
		{"initialized-check failure preserves the cursor", "WebhookCursorInitialized"},
		{"cursor load failure preserves the cursor", "GetWebhookCursor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newStore(t)
			sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, "http://127.0.0.1:1/hook", nil)
			before := seedCursorAtHead(t, db)
			appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
			appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "02")

			store := newHookStore(db)
			store.fail(tc.method, boom)
			var logs syncBuffer
			e := engineFor(store, newFakeClock(), func(c *Config) { c.Logger = testLogger(&logs) })

			cursor, ok := e.initCursor()
			if ok {
				t.Errorf("initCursor reported ready despite a %s failure", tc.method)
			}
			if cursor != 0 {
				t.Errorf("initCursor = %d, want 0 alongside ok=false", cursor)
			}
			// The decisive assertion: the good cursor is still on disk, so the two
			// appended events remain pending rather than being skipped or replayed.
			if persisted, err := db.GetWebhookCursor(); err != nil || persisted != before {
				t.Errorf("persisted cursor = %d (%v), want it preserved at %d", persisted, err, before)
			}
			if !strings.Contains(logs.String(), "skipping this sweep") {
				t.Errorf("the skipped sweep was not logged: %q", logs.String())
			}

			// RunOnce must not fan out with an unusable cursor.
			e.RunOnce(context.Background())
			if n := deliveryCount(t, db, sub.ID); n != 0 {
				t.Errorf("%d deliveries while the cursor was unreadable, want 0", n)
			}

			// Heal the store: the deferred backlog is delivered, exactly once.
			store.fail(tc.method, nil)
			healed, ok := e.initCursor()
			if !ok {
				t.Fatalf("initCursor still not ready after the store healed")
			}
			if healed != before {
				t.Errorf("initCursor = %d after healing, want the preserved %d", healed, before)
			}
			e.fanOutOnce(context.Background(), &healed)
			if n := deliveryCount(t, db, sub.ID); n != 2 {
				t.Errorf("%d deliveries after recovery, want 2 (neither event was lost)", n)
			}
			// A second sweep must not double-enqueue.
			again, _ := e.initCursor()
			e.fanOutOnce(context.Background(), &again)
			if n := deliveryCount(t, db, sub.ID); n != 2 {
				t.Errorf("a second sweep produced %d deliveries, want 2", n)
			}
		})
	}
}

// --- sweep robustness -----------------------------------------------------------

// TestDeliverySweepStopsMidBatchOnCancel proves a shutdown (or leadership loss)
// mid-sweep abandons the rest of the batch instead of POSTing through it: the
// untouched rows keep their full retry budget for the next leader.
func TestDeliverySweepStopsMidBatchOnCancel(t *testing.T) {
	db := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The first delivery attempt cancels the worker's context, exactly as a
	// SIGTERM or a lost lease would mid-batch.
	ep := newEndpoint(t, func(_ int, w http.ResponseWriter, _ *http.Request) {
		cancel()
		w.WriteHeader(http.StatusOK)
	})

	const subs = 3
	for i := 0; i < subs; i++ {
		mkSub(t, db, "w"+strconv.Itoa(i), models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
	}
	e := engineFor(db, newFakeClock(), nil)
	cursor := seedCursorAtHead(t, db)
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
	e.fanOutOnce(context.Background(), &cursor)

	// deliverDueOnce counts rows it durably ADVANCED, not rows it listed. Exactly
	// one attempt got far enough to transition (to a backed-off retry, since the
	// cancel aborted its in-flight POST); the other two were abandoned untouched.
	// Reporting 3 here would tell runDelivery it had drained a full batch and send
	// it straight round again with no backoff.
	if n := e.deliverDueOnce(ctx); n != 1 {
		t.Errorf("deliverDueOnce advanced %d rows, want 1 (the other %d were abandoned on cancel)", n, subs-1)
	}
	if ep.count() != 1 {
		t.Fatalf("endpoint got %d requests, want 1: the canceled sweep kept POSTing", ep.count())
	}

	counts, err := db.CountWebhookDeliveriesByStatus()
	if err != nil {
		t.Fatalf("CountWebhookDeliveriesByStatus: %v", err)
	}
	if counts[models.WebhookDeliveryPending] != subs {
		t.Errorf("pending = %d, want all %d rows still claimable after the cancel", counts[models.WebhookDeliveryPending], subs)
	}
	untouched := 0
	for i := 0; i < subs; i++ {
		if d := onlyDelivery(t, db, "w"+strconv.Itoa(i)); d.Attempts == 0 {
			untouched++
		}
	}
	if untouched != subs-1 {
		t.Errorf("%d rows kept their full budget, want %d (one attempt was in flight)", untouched, subs-1)
	}
}

// TestDueListFailureIsSkippedNotFatal proves an unreadable queue is a logged
// no-op: the worker neither panics nor spins its attempt counters, and recovers on
// the next sweep.
func TestDueListFailureIsSkippedNotFatal(t *testing.T) {
	db := newStore(t)
	ep := newStatusEndpoint(t, http.StatusOK)
	sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)

	store := newHookStore(db)
	var logs syncBuffer
	e := engineFor(store, newFakeClock(), func(c *Config) { c.Logger = testLogger(&logs) })
	ctx := context.Background()
	cursor := seedCursorAtHead(t, db)
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
	e.fanOutOnce(ctx, &cursor)

	store.fail("ListDueWebhookDeliveries", errors.New("queue unreadable"))
	if n := e.deliverDueOnce(ctx); n != 0 {
		t.Errorf("deliverDueOnce = %d on an unreadable queue, want 0", n)
	}
	if ep.count() != 0 {
		t.Errorf("endpoint got %d requests, want 0", ep.count())
	}
	if !strings.Contains(logs.String(), "listing due deliveries") {
		t.Errorf("the queue read failure was not logged: %q", logs.String())
	}

	store.fail("ListDueWebhookDeliveries", nil)
	e.deliverDueOnce(ctx)
	if d := onlyDelivery(t, db, sub.ID); d.Status != models.WebhookDeliveryDelivered || d.Attempts != 1 {
		t.Errorf("status/attempts = %q/%d after recovery, want delivered/1", d.Status, d.Attempts)
	}
}

// TestAuditAndGaugeFailuresDoNotWedgeTheQueue proves the observability side-paths
// are best-effort: auditing can be switched off, an audit-append failure still
// leaves the delivery marked delivered (the queue must not stall because the
// hash-chained log is unavailable), and an advisory gauge read failure is ignored.
func TestAuditAndGaugeFailuresDoNotWedgeTheQueue(t *testing.T) {
	t.Run("auditing disabled", func(t *testing.T) {
		db := newStore(t)
		ep := newStatusEndpoint(t, http.StatusOK)
		sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
		e := engineFor(db, newFakeClock(), func(c *Config) { c.AuditDeliveries = false })
		ctx := context.Background()
		cursor := seedCursorAtHead(t, db)
		appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
		e.fanOutOnce(ctx, &cursor)
		e.deliverDueOnce(ctx)

		if d := onlyDelivery(t, db, sub.ID); d.Status != models.WebhookDeliveryDelivered {
			t.Errorf("status = %q, want delivered", d.Status)
		}
		if evs := auditDeliverEvents(t, db); len(evs) != 0 {
			t.Errorf("recorded %d webhook.deliver events with auditing off, want 0", len(evs))
		}
	})

	t.Run("audit append and gauge reads fail", func(t *testing.T) {
		db := newStore(t)
		ep := newStatusEndpoint(t, http.StatusOK)
		sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
		store := newHookStore(db)
		var logs syncBuffer
		e := engineFor(store, newFakeClock(), func(c *Config) { c.Logger = testLogger(&logs) })
		ctx := context.Background()
		cursor := seedCursorAtHead(t, db)
		appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
		e.fanOutOnce(ctx, &cursor)

		store.fail("AppendEvent", errors.New("log unavailable"))
		store.fail("CountWebhookDeliveriesByStatus", errors.New("gauge read failed"))
		e.deliverDueOnce(ctx)

		if d := onlyDelivery(t, db, sub.ID); d.Status != models.WebhookDeliveryDelivered {
			t.Errorf("status = %q, want delivered: a failed audit must not undo a delivered row", d.Status)
		}
		if !strings.Contains(logs.String(), "recording audit event") {
			t.Errorf("the audit failure was not logged: %q", logs.String())
		}
	})
}

// TestTerminalWriteFailuresKeepTheRowClaimable covers the two remaining
// bookkeeping seams. A failed retry write leaves the row due, so the next sweep
// re-attempts it — at-least-once, never lost. A failed dead-letter write is the
// sharper case: the row stays pending with its budget already spent, so every
// sweep re-POSTs a delivery that should have been retired (see the report).
func TestTerminalWriteFailuresKeepTheRowClaimable(t *testing.T) {
	boom := errors.New("store unavailable")

	t.Run("retry write fails", func(t *testing.T) {
		db := newStore(t)
		ep := newStatusEndpoint(t, http.StatusInternalServerError)
		sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
		store := newHookStore(db)
		var logs syncBuffer
		e := engineFor(store, newFakeClock(), func(c *Config) { c.Logger = testLogger(&logs) })
		ctx := context.Background()
		cursor := seedCursorAtHead(t, db)
		appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
		e.fanOutOnce(ctx, &cursor)

		store.fail("MarkWebhookDeliveryRetry", boom)
		e.deliverDueOnce(ctx)
		d := onlyDelivery(t, db, sub.ID)
		if d.Status != models.WebhookDeliveryPending || d.Attempts != 0 {
			t.Errorf("status/attempts = %q/%d, want pending/0 (the attempt was never recorded)", d.Status, d.Attempts)
		}
		if !strings.Contains(logs.String(), "scheduling retry") {
			t.Errorf("the failed retry write was not logged: %q", logs.String())
		}

		store.fail("MarkWebhookDeliveryRetry", nil)
		e.deliverDueOnce(ctx)
		if d := onlyDelivery(t, db, sub.ID); d.Attempts != 1 {
			t.Errorf("attempts = %d after recovery, want 1", d.Attempts)
		}
		if ep.count() != 2 {
			t.Errorf("endpoint got %d requests, want 2", ep.count())
		}
	})

	t.Run("dead-letter write fails", func(t *testing.T) {
		db := newStore(t)
		ep := newStatusEndpoint(t, http.StatusInternalServerError)
		sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, ep.url(), nil)
		store := newHookStore(db)
		var logs syncBuffer
		clock := newFakeClock()
		e := engineFor(store, clock, func(c *Config) {
			c.MaxAttempts = 1 // the very first failure exhausts the budget
			c.Logger = testLogger(&logs)
		})
		ctx := context.Background()
		cursor := seedCursorAtHead(t, db)
		appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
		e.fanOutOnce(ctx, &cursor)

		store.fail("MarkWebhookDeliveryDead", boom)
		e.deliverDueOnce(ctx)
		if d := onlyDelivery(t, db, sub.ID); d.Status != models.WebhookDeliveryPending {
			t.Errorf("status = %q, want pending (the dead-letter was never written)", d.Status)
		}
		if !strings.Contains(logs.String(), "dead-lettering") {
			t.Errorf("the failed dead-letter write was not logged: %q", logs.String())
		}
		// The row is still due, so the worker re-POSTs it even though its budget is
		// spent: the endpoint sees a second attempt.
		e.deliverDueOnce(ctx)
		if ep.count() != 2 {
			t.Errorf("endpoint got %d requests, want 2 (an unretired row is re-POSTed)", ep.count())
		}

		// Once the store recovers the row retires and stays retired.
		store.fail("MarkWebhookDeliveryDead", nil)
		e.deliverDueOnce(ctx)
		if d := onlyDelivery(t, db, sub.ID); d.Status != models.WebhookDeliveryDead {
			t.Errorf("status = %q, want dead after recovery", d.Status)
		}
		clock.advance(time.Hour)
		e.deliverDueOnce(ctx)
		if ep.count() != 3 {
			t.Errorf("endpoint got %d requests, want 3 (the retired row is terminal)", ep.count())
		}
	})
}

// TestSeedWriteFailureAndCanceledSweep covers the last two early-outs on the
// fan-out path: a cursor seed that cannot be persisted (the worker proceeds from
// head in memory, so it does not replay history, but the next start re-seeds) and
// a sweep entered with an already-canceled context (it must do nothing).
func TestSeedWriteFailureAndCanceledSweep(t *testing.T) {
	db := newStore(t)
	sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, "http://127.0.0.1:1/hook", nil)
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")
	head, err := db.MaxEventSeq()
	if err != nil {
		t.Fatalf("MaxEventSeq: %v", err)
	}

	store := newHookStore(db)
	store.fail("SetWebhookCursor", errors.New("cursor write failed"))
	var logs syncBuffer
	e := engineFor(store, newFakeClock(), func(c *Config) { c.Logger = testLogger(&logs) })

	// No cursor row exists yet, so this is the first-enablement seed. A seed that
	// could not be persisted must report "not ready": proceeding on an in-memory
	// head would fan out from a position the next start cannot recover.
	if got, ok := e.initCursor(); ok || got != 0 {
		t.Errorf("initCursor = (%d, %v), want (0, false) when the seed write fails (head was %d)", got, ok, head)
	}
	if inited, err := db.WebhookCursorInitialized(); err != nil || inited {
		t.Errorf("cursor initialized = %v (%v), want false: the seed write failed", inited, err)
	}
	if !strings.Contains(logs.String(), "seeding fan-out cursor") {
		t.Errorf("the failed seed write was not logged: %q", logs.String())
	}

	// A sweep whose context is already canceled must not enqueue anything.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cursor := int64(0)
	e.fanOutOnce(ctx, &cursor)
	if n := deliveryCount(t, db, sub.ID); n != 0 {
		t.Errorf("a canceled fan-out enqueued %d deliveries, want 0", n)
	}
	if cursor != 0 {
		t.Errorf("a canceled fan-out advanced the cursor to %d", cursor)
	}
}

// TestFanOutTerminatesOnAnEmptyBatch is the anti-spin guard: if the log read comes
// back empty while the head still claims unscanned events (a truncated or
// mid-migration log), the sweep must break out instead of looping forever holding
// the worker.
func TestFanOutTerminatesOnAnEmptyBatch(t *testing.T) {
	db := newStore(t)
	sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, "http://127.0.0.1:1/hook", nil)
	start := seedCursorAtHead(t, db)
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")

	store := newHookStore(db)
	store.starveEvents()
	e := engineFor(store, newFakeClock(), nil)

	cursor := start
	done := make(chan struct{})
	go func() { defer close(done); e.fanOutOnce(context.Background(), &cursor) }()
	waitReturn(t, "a fan-out sweep whose log read came back empty", done, 10*time.Second)

	if cursor != start {
		t.Errorf("cursor = %d, want %d: nothing was scanned", cursor, start)
	}
	if n := deliveryCount(t, db, sub.ID); n != 0 {
		t.Errorf("%d deliveries from an empty batch, want 0", n)
	}
	if store.callCount("ListEventsSince") != 1 {
		t.Errorf("ListEventsSince called %d times, want 1 (the sweep must not spin)", store.callCount("ListEventsSince"))
	}
}

// TestSeedHeadReadFailureDefersEnablement covers the other first-enablement
// fault: if the log head cannot be read, the cursor must NOT be seeded at all.
// Seeding at the genesis instead would make the first sweep after a transient
// store error replay the entire certificate history to every subscriber's
// endpoint. Deferring to the next tick costs nothing — nothing is subscribed to
// the past — so the safe choice is to write no cursor and retry.
func TestSeedHeadReadFailureDefersEnablement(t *testing.T) {
	db := newStore(t)
	sub := mkSub(t, db, "w1", models.DefaultTenantID, models.WebhookScopeTenant, "http://127.0.0.1:1/hook", nil)
	appendLifecycle(t, db, audit.ActionCertIssue, models.DefaultTenantID, "ca-1", "01")

	store := newHookStore(db)
	store.fail("MaxEventSeq", errors.New("head unreadable"))
	var logs syncBuffer
	e := engineFor(store, newFakeClock(), func(c *Config) { c.Logger = testLogger(&logs) })

	if got, ok := e.initCursor(); ok || got != 0 {
		t.Errorf("initCursor = (%d, %v), want (0, false) when the head cannot be read", got, ok)
	}
	if !strings.Contains(logs.String(), "reading log head") {
		t.Errorf("the failed head read was not logged: %q", logs.String())
	}
	// No cursor was written, so enablement has not happened yet.
	if inited, err := db.WebhookCursorInitialized(); err != nil || inited {
		t.Errorf("cursor initialized = %v (%v), want false: the head read failed", inited, err)
	}
	// And crucially, the pre-existing event was not replayed.
	e.RunOnce(context.Background())
	if n := deliveryCount(t, db, sub.ID); n != 0 {
		t.Errorf("%d deliveries, want 0: history must not be replayed", n)
	}

	// Once the head is readable, enablement completes and still only covers the
	// future — the pre-enablement event stays unshipped.
	store.fail("MaxEventSeq", nil)
	head, ok := e.initCursor()
	if !ok {
		t.Fatalf("initCursor still not ready after the store healed")
	}
	if want, err := db.MaxEventSeq(); err != nil || head != want {
		t.Errorf("initCursor = %d (%v), want the head %d", head, err, want)
	}
	e.fanOutOnce(context.Background(), &head)
	if n := deliveryCount(t, db, sub.ID); n != 0 {
		t.Errorf("%d deliveries after enablement, want 0 (future events only)", n)
	}
}
