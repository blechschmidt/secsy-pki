package webhook

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Store is the persistence surface the delivery engine needs. *database.DB
// satisfies it; the interface keeps the engine decoupled and documents the exact
// operations the durable pipeline depends on.
type Store interface {
	// Event source (fan-out reads the durable, hash-chained audit log forward).
	MaxEventSeq() (int64, error)
	ListEventsSince(afterSeq int64, limit int) ([]audit.Event, error)

	// Fan-out high-water mark.
	GetWebhookCursor() (int64, error)
	WebhookCursorInitialized() (bool, error)
	SetWebhookCursor(seq int64) error

	// Subscriptions.
	ListEnabledWebhookSubscriptions() ([]models.WebhookSubscription, error)
	GetWebhookSubscription(id string) (*models.WebhookSubscription, error)

	// Delivery queue.
	EnqueueWebhookDelivery(d *models.WebhookDelivery) error
	ListDueWebhookDeliveries(now time.Time, limit int) ([]models.WebhookDelivery, error)
	MarkWebhookDeliverySucceeded(id string, at time.Time, statusCode int) error
	MarkWebhookDeliveryRetry(id string, at, nextAttempt time.Time, statusCode int, errMsg string) error
	MarkWebhookDeliveryDead(id string, at time.Time, statusCode int, errMsg string) error
	CancelPendingWebhookDeliveries(subscriptionID string) (int64, error)
	CountWebhookDeliveriesByStatus() (map[string]int, error)

	// Audit (terminal delivery outcomes).
	AppendEvent(e *audit.Event) error
}

// Config tunes the delivery engine. Zero values fall back to production defaults
// (see withDefaults); the wiring translates config.WebhookConfig into this.
type Config struct {
	// PollInterval is the fan-out and delivery poll cadence. The fan-out is also
	// woken immediately by the audit-append hook (see Engine.Notify), so this is
	// the safety-net tick, not the primary latency bound. Default 5s.
	PollInterval time.Duration
	// BatchSize bounds how many events the fan-out scans and how many due
	// deliveries the worker claims per iteration — the backpressure knob. Default
	// 100.
	BatchSize int
	// MaxAttempts is the retry budget: a delivery is dead-lettered once it has
	// been attempted this many times without a 2xx. Default 8.
	MaxAttempts int
	// Timeout bounds a single POST. Default 10s.
	Timeout time.Duration
	// BackoffBase is the first retry delay; it doubles per attempt up to
	// BackoffMax. Default 30s.
	BackoffBase time.Duration
	// BackoffMax caps the retry delay. Default 1h.
	BackoffMax time.Duration
	// AuditDeliveries records a webhook.deliver audit event on each terminal
	// outcome (delivered / dead-lettered). Default true.
	AuditDeliveries bool
	// Logger receives operational messages. Defaults to the standard logger.
	Logger *log.Logger
	// Clock is a test seam for "now". Defaults to time.Now.
	Clock func() time.Time
	// Client is the HTTP client used for deliveries. Defaults to a client with no
	// global timeout (each request is bounded by a per-attempt context timeout).
	Client *http.Client
}

func (c Config) withDefaults() Config {
	if c.PollInterval <= 0 {
		c.PollInterval = 5 * time.Second
	}
	if c.BatchSize <= 0 {
		c.BatchSize = 100
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 8
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
	if c.BackoffBase <= 0 {
		c.BackoffBase = 30 * time.Second
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = time.Hour
	}
	if c.Logger == nil {
		c.Logger = log.Default()
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.Client == nil {
		c.Client = newHTTPClient()
	}
	return c
}

// newHTTPClient builds the delivery client. Redirects are deliberately NOT
// followed: net/http rewrites a 302/303 into a bodyless GET, so the endpoint
// would never receive the signed payload while the final 200 marked the delivery
// succeeded — silent event loss with no retry and no dead-letter. On a 307/308 it
// would instead replay the body *and* the signature header to the redirect
// target, including a cross-host one. Surfacing the 3xx as the response makes it
// an ordinary non-2xx failure, which retries and eventually dead-letters.
func newHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Engine is the leader-elected outbound webhook delivery worker. It runs two
// cooperating loops: a fan-out that scans the durable audit log forward from a
// persistent cursor and enqueues a delivery per matching subscription, and a
// delivery loop that POSTs due deliveries with signed bodies, retrying with
// exponential backoff and dead-lettering after the retry budget is exhausted.
type Engine struct {
	store Store
	cfg   Config
	// wake is a coalesced, non-blocking signal from the audit-append hook that a
	// new lifecycle event was committed, so the fan-out runs promptly rather than
	// waiting for the next poll tick.
	wake chan struct{}
}

// New builds an Engine over store with cfg.
func New(store Store, cfg Config) *Engine {
	return &Engine{store: store, cfg: cfg.withDefaults(), wake: make(chan struct{}, 1)}
}

// Notify is the audit-append hook: it nudges the fan-out when a deliverable
// lifecycle event is committed. It is non-blocking and never touches the store,
// so it is safe to call from inside the audit-append critical section (the hook
// contract). A dropped nudge (buffer full) is harmless — the poll tick catches
// up. It ignores non-lifecycle and non-success events.
func (e *Engine) Notify(ev audit.Event) {
	if !IsLifecycleEvent(ev.Action) || ev.Result != audit.ResultSuccess {
		return
	}
	select {
	case e.wake <- struct{}{}:
	default:
	}
}

// Run drives both loops until ctx is cancelled, then returns. It is intended to
// be registered as a leader-elected background job so exactly one replica
// delivers, avoiding duplicate POSTs across a multi-replica deployment.
func (e *Engine) Run(ctx context.Context) {
	e.cfg.Logger.Printf("webhook delivery worker started (poll=%s, batch=%d, max_attempts=%d, backoff=%s..%s, timeout=%s)",
		e.cfg.PollInterval, e.cfg.BatchSize, e.cfg.MaxAttempts, e.cfg.BackoffBase, e.cfg.BackoffMax, e.cfg.Timeout)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); e.runFanOut(ctx) }()
	go func() { defer wg.Done(); e.runDelivery(ctx) }()
	wg.Wait()
	e.cfg.Logger.Printf("webhook delivery worker stopped")
}

func (e *Engine) now() time.Time { return e.cfg.Clock() }

// RunOnce performs a single fan-out sweep (durable log -> delivery queue)
// followed by a single delivery sweep (queue -> endpoints), then returns. The
// leader-elected Run loop is the production driver; RunOnce backs deterministic
// tests and could back a manual "flush now" trigger. Because the fan-out cursor
// is persisted, successive RunOnce calls resume where the previous left off.
func (e *Engine) RunOnce(ctx context.Context) {
	if cursor, ok := e.initCursor(); ok {
		e.fanOutOnce(ctx, &cursor)
	}
	e.deliverDueOnce(ctx)
}

// --- fan-out: audit log -> delivery queue ---

func (e *Engine) runFanOut(ctx context.Context) {
	cursor, ready := e.initCursor()
	ticker := time.NewTicker(e.cfg.PollInterval)
	defer ticker.Stop()
	for {
		// A cursor that could not be read leaves the sweep skipped rather than
		// guessed at; retry the load on each tick until the store answers.
		if !ready {
			cursor, ready = e.initCursor()
		}
		if ready {
			e.fanOutOnce(ctx, &cursor)
		}
		select {
		case <-ctx.Done():
			return
		case <-e.wake:
		case <-ticker.C:
		}
	}
}

// initCursor loads the fan-out cursor, seeding it to the current log head on the
// very first run so enabling the feature does not replay the entire certificate
// history — subscriptions receive only events committed from enablement forward.
// It reports whether the cursor is usable. A read failure must NOT be treated as
// "never initialized": that seeds the cursor at the current head, overwriting a
// good persisted value and silently dropping every event committed since the last
// sweep, with no retry and no dead-letter. Since initCursor runs on every start
// and every leadership handover, a transient store error would lose a window of
// events permanently. On failure the caller skips the sweep and retries.
func (e *Engine) initCursor() (int64, bool) {
	inited, err := e.store.WebhookCursorInitialized()
	if err != nil {
		e.cfg.Logger.Printf("webhook: reading fan-out cursor state: %v; skipping this sweep (will retry)", err)
		return 0, false
	}
	if !inited {
		head, err := e.store.MaxEventSeq()
		if err != nil {
			// Seeding at genesis here would replay the entire certificate history
			// to every subscriber's endpoint on the first sweep after a transient
			// store error. Retry instead.
			e.cfg.Logger.Printf("webhook: reading log head: %v; skipping this sweep (will retry)", err)
			return 0, false
		}
		if err := e.store.SetWebhookCursor(head); err != nil {
			e.cfg.Logger.Printf("webhook: seeding fan-out cursor: %v", err)
			return 0, false
		}
		e.cfg.Logger.Printf("webhook fan-out initialized at seq=%d (future events only)", head)
		return head, true
	}
	cursor, err := e.store.GetWebhookCursor()
	if err != nil {
		// Never fall back to genesis: that would replay the entire certificate
		// history to every subscriber's endpoint.
		e.cfg.Logger.Printf("webhook: loading fan-out cursor: %v; skipping this sweep (will retry)", err)
		return 0, false
	}
	return cursor, true
}

// fanOutOnce drains new events into the delivery queue. On any error it returns
// without advancing the cursor, so the batch is retried; because enqueue is
// idempotent (UNIQUE(subscription_id, event_seq)), re-processing never
// double-delivers.
func (e *Engine) fanOutOnce(ctx context.Context, cursor *int64) {
	for {
		if ctx.Err() != nil {
			return
		}
		head, err := e.store.MaxEventSeq()
		if err != nil {
			e.cfg.Logger.Printf("webhook fan-out: reading head: %v", err)
			return
		}
		if *cursor >= head {
			break
		}
		batch, err := e.store.ListEventsSince(*cursor, e.cfg.BatchSize)
		if err != nil {
			e.cfg.Logger.Printf("webhook fan-out: reading events: %v", err)
			return
		}
		if len(batch) == 0 {
			break
		}
		subs, err := e.store.ListEnabledWebhookSubscriptions()
		if err != nil {
			e.cfg.Logger.Printf("webhook fan-out: listing subscriptions: %v", err)
			return
		}
		for i := range batch {
			ev := batch[i]
			if IsLifecycleEvent(ev.Action) && ev.Result == audit.ResultSuccess {
				for j := range subs {
					if SubscriptionMatches(&subs[j], &ev) {
						if err := e.enqueue(&subs[j], &ev); err != nil {
							e.cfg.Logger.Printf("webhook fan-out: enqueue sub=%s event=%d: %v", subs[j].ID, ev.Seq, err)
							return // don't advance the cursor; retry the batch (idempotent)
						}
					}
				}
			}
		}
		last := batch[len(batch)-1].Seq
		if err := e.store.SetWebhookCursor(last); err != nil {
			e.cfg.Logger.Printf("webhook fan-out: advancing cursor to %d: %v", last, err)
			return
		}
		*cursor = last
	}
	e.refreshGauges()
}

// enqueue builds a signed-body delivery for one (subscription, event) pair.
func (e *Engine) enqueue(sub *models.WebhookSubscription, ev *audit.Event) error {
	id := uuid.New().String()
	payload, err := BuildEventPayload(id, sub, ev)
	if err != nil {
		return fmt.Errorf("building payload: %w", err)
	}
	now := e.now()
	return e.store.EnqueueWebhookDelivery(&models.WebhookDelivery{
		ID:             id,
		SubscriptionID: sub.ID,
		TenantID:       sub.TenantID,
		EventID:        ev.ID,
		EventSeq:       ev.Seq,
		EventType:      ev.Action,
		Payload:        string(payload),
		Status:         models.WebhookDeliveryPending,
		MaxAttempts:    e.cfg.MaxAttempts,
		NextAttemptAt:  now,
		CreatedAt:      now,
	})
}

// --- delivery: queue -> external endpoint ---

func (e *Engine) runDelivery(ctx context.Context) {
	ticker := time.NewTicker(e.cfg.PollInterval)
	defer ticker.Stop()
	for {
		n := e.deliverDueOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		// A full batch of *progress* means there may be more backlog; loop
		// immediately to drain it rather than waiting a whole poll interval. The
		// count deliberately excludes rows that stayed pending-and-due (a store
		// error left them unclaimed): counting those would fast-drain forever,
		// re-POSTing to the endpoint with no backoff at all.
		if n >= e.cfg.BatchSize {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// deliverDueOnce runs one delivery sweep and returns the number of rows whose
// durable state it actually advanced — not the number it listed. A row left
// pending-and-due by a store error is still claimable next sweep, so counting it
// as drained would make runDelivery spin (see the comment there).
func (e *Engine) deliverDueOnce(ctx context.Context) int {
	due, err := e.store.ListDueWebhookDeliveries(e.now(), e.cfg.BatchSize)
	if err != nil {
		e.cfg.Logger.Printf("webhook delivery: listing due deliveries: %v", err)
		return 0
	}
	progressed := 0
	for i := range due {
		if ctx.Err() != nil {
			break
		}
		if e.attemptDelivery(ctx, &due[i]) {
			progressed++
		}
	}
	e.refreshGauges()
	return progressed
}

// attemptDelivery makes one POST and transitions the delivery: success ->
// delivered, failure with budget remaining -> retry (backed off), budget
// exhausted -> dead-letter. A delivery whose subscription vanished or was
// disabled is canceled rather than retried against a paused endpoint.
//
// It reports whether the row's durable state advanced. false means the row is
// still pending and due — the caller must not treat it as drained.
func (e *Engine) attemptDelivery(ctx context.Context, d *models.WebhookDelivery) bool {
	sub, err := e.store.GetWebhookSubscription(d.SubscriptionID)
	if err != nil {
		e.cfg.Logger.Printf("webhook delivery: loading subscription %s: %v", d.SubscriptionID, err)
		return false // transient; leave pending for the next poll
	}
	if sub == nil || !sub.Enabled {
		n, cerr := e.store.CancelPendingWebhookDeliveries(d.SubscriptionID)
		if cerr != nil {
			e.cfg.Logger.Printf("webhook delivery: canceling deliveries for %s: %v", d.SubscriptionID, cerr)
			return false
		}
		metrics.RecordWebhookCanceled(int(n))
		return true
	}

	start := e.now()
	statusCode, postErr := post(ctx, e.cfg.Client, e.cfg.Timeout, e.now, sub, d)
	dur := e.now().Sub(start)
	now := e.now()

	if postErr == nil && statusCode >= 200 && statusCode < 300 {
		if err := e.store.MarkWebhookDeliverySucceeded(d.ID, now, statusCode); err != nil {
			e.cfg.Logger.Printf("webhook delivery: marking %s delivered: %v", d.ID, err)
			return false
		}
		metrics.RecordWebhookDelivered(dur)
		e.auditDeliver(sub, d, audit.ResultSuccess, fmt.Sprintf("status=%d", statusCode))
		return true
	}

	errMsg := deliveryErrorMessage(statusCode, postErr)
	attemptsAfter := d.Attempts + 1
	if attemptsAfter >= d.MaxAttempts {
		if err := e.store.MarkWebhookDeliveryDead(d.ID, now, statusCode, errMsg); err != nil {
			e.cfg.Logger.Printf("webhook delivery: dead-lettering %s: %v", d.ID, err)
			return false
		}
		metrics.RecordWebhookDead(dur)
		e.cfg.Logger.Printf("webhook delivery %s to sub %s dead-lettered after %d attempts: %s",
			d.ID, sub.ID, attemptsAfter, errMsg)
		e.auditDeliver(sub, d, audit.ResultError, fmt.Sprintf("dead-lettered after %d attempts: %s", attemptsAfter, errMsg))
		return true
	}

	next := now.Add(e.backoff(attemptsAfter))
	if err := e.store.MarkWebhookDeliveryRetry(d.ID, now, next, statusCode, errMsg); err != nil {
		e.cfg.Logger.Printf("webhook delivery: scheduling retry for %s: %v", d.ID, err)
		return false
	}
	metrics.RecordWebhookRetry(dur)
	return true
}

// backoff returns the delay before the next attempt after a delivery has failed
// `attempt` times (1-based): BackoffBase * 2^(attempt-1), capped at BackoffMax.
func (e *Engine) backoff(attempt int) time.Duration {
	d := e.cfg.BackoffBase
	for i := 1; i < attempt; i++ {
		d *= 2
		if d >= e.cfg.BackoffMax {
			return e.cfg.BackoffMax
		}
	}
	if d > e.cfg.BackoffMax {
		return e.cfg.BackoffMax
	}
	return d
}

// auditDeliver records a terminal delivery outcome in the tamper-evident audit
// log (best-effort: an audit failure must not wedge the queue). Transient
// retryable failures are intentionally not audited — metrics cover them — so the
// hash-chained log is not flooded.
func (e *Engine) auditDeliver(sub *models.WebhookSubscription, d *models.WebhookDelivery, result, detail string) {
	if !e.cfg.AuditDeliveries {
		return
	}
	full := fmt.Sprintf("event=%s delivery=%s url=%s %s", d.EventType, d.ID, hostOf(sub.URL), detail)
	if err := e.store.AppendEvent(&audit.Event{
		ID:         uuid.New().String(),
		Actor:      "system:webhook",
		Action:     audit.ActionWebhookDeliver,
		Tenant:     sub.TenantID,
		Target:     sub.ID,
		TargetName: hostOf(sub.URL),
		Result:     result,
		Detail:     full,
	}); err != nil {
		e.cfg.Logger.Printf("webhook delivery: recording audit event for %s: %v", d.ID, err)
	}
}

// refreshGauges republishes the durable-queue backlog gauges from the store. A
// read error is non-fatal — the gauges are advisory.
func (e *Engine) refreshGauges() {
	counts, err := e.store.CountWebhookDeliveriesByStatus()
	if err != nil {
		return
	}
	metrics.SetWebhookQueueGauges(counts[models.WebhookDeliveryPending], counts[models.WebhookDeliveryDead])
	if subs, err := e.store.ListEnabledWebhookSubscriptions(); err == nil {
		metrics.SetWebhookSubscriptionsActive(len(subs))
	}
}

// --- shared HTTP send (used by the engine and the CLI test command) ---

// post signs and POSTs a delivery's body to its subscription URL, returning the
// HTTP status code (0 on a transport error). The signature timestamp is taken at
// send time so the receiver's freshness window bounds replay. now is the clock
// (the engine's test seam; the CLI passes time.Now).
func post(ctx context.Context, client *http.Client, timeout time.Duration, now func() time.Time, sub *models.WebhookSubscription, d *models.WebhookDelivery) (int, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	body := []byte(d.Payload)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, sub.URL, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "secsy-pki-webhook/1")
	req.Header.Set(SignatureHeader, Sign(sub.Secret, now(), body))
	req.Header.Set("X-Secsy-Event", d.EventType)
	req.Header.Set("X-Secsy-Delivery", d.ID)
	req.Header.Set("X-Secsy-Webhook-Id", sub.ID)
	req.Header.Set("X-Secsy-Attempt", strconv.Itoa(d.Attempts+1))
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the connection can be reused (keep-alive).
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<12))
	return resp.StatusCode, nil
}

// SendTest performs one synchronous, signed test POST to a subscription and
// returns the HTTP status code. It shares the exact signing/headers of a real
// delivery, so it is a faithful reachability + signature check. It is used by the
// `secsy-ca webhook test` CLI, which runs standalone (no delivery worker).
func SendTest(ctx context.Context, sub *models.WebhookSubscription, timeout time.Duration) (int, error) {
	id := uuid.New().String()
	body, err := BuildTestPayload(id, sub, time.Now())
	if err != nil {
		return 0, err
	}
	d := &models.WebhookDelivery{ID: id, EventType: "webhook.test", Payload: string(body)}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return post(ctx, newHTTPClient(), timeout, time.Now, sub, d)
}

// NewTestDelivery builds a durable test-delivery row for a subscription, for the
// REST test endpoint (which enqueues it for the worker to deliver). A negative,
// time-derived event_seq keeps it unique and clear of real events under the
// UNIQUE(subscription_id, event_seq) constraint.
func NewTestDelivery(sub *models.WebhookSubscription, maxAttempts int) (*models.WebhookDelivery, error) {
	id := uuid.New().String()
	now := time.Now().UTC()
	body, err := BuildTestPayload(id, sub, now)
	if err != nil {
		return nil, err
	}
	if maxAttempts <= 0 {
		maxAttempts = 8
	}
	return &models.WebhookDelivery{
		ID:             id,
		SubscriptionID: sub.ID,
		TenantID:       sub.TenantID,
		EventID:        id,
		EventSeq:       -now.UnixNano(),
		EventType:      "webhook.test",
		Payload:        string(body),
		Status:         models.WebhookDeliveryPending,
		MaxAttempts:    maxAttempts,
		NextAttemptAt:  now,
		CreatedAt:      now,
	}, nil
}

// deliveryErrorMessage renders a compact failure reason for the delivery row.
func deliveryErrorMessage(statusCode int, err error) string {
	if err != nil {
		return "transport error: " + err.Error()
	}
	return "endpoint returned HTTP " + strconv.Itoa(statusCode)
}

// hostOf extracts the host of a URL for audit/logging without leaking the full
// (possibly credential-bearing) path/query.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}
