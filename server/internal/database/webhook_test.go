//go:build sqlite

package database

import (
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func newWebhookTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestWebhookSubscriptionCRUD covers create/get/list, the enabled filter and
// toggle (a boolean column that must round-trip across engines), and delete.
func TestWebhookSubscriptionCRUD(t *testing.T) {
	db := newWebhookTestDB(t)

	sub := &models.WebhookSubscription{
		ID: "w1", TenantID: models.DefaultTenantID, Scope: "tenant",
		URL: "https://example.com/hook", Secret: "shhh",
		EventTypes: []string{"cert.issue", "cert.revoke"}, Enabled: true,
		Description: "primary", CreatedBy: "op",
	}
	if err := db.CreateWebhookSubscription(sub); err != nil {
		t.Fatalf("CreateWebhookSubscription: %v", err)
	}

	got, err := db.GetWebhookSubscription("w1")
	if err != nil || got == nil {
		t.Fatalf("GetWebhookSubscription: %v, %v", got, err)
	}
	if got.Secret != "shhh" || got.URL != sub.URL || !got.Enabled {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if len(got.EventTypes) != 2 || got.EventTypes[0] != "cert.issue" {
		t.Errorf("event types did not round-trip: %v", got.EventTypes)
	}

	// A disabled subscription must be excluded from the enabled list.
	if changed, err := db.SetWebhookSubscriptionEnabled("w1", false); err != nil || !changed {
		t.Fatalf("SetWebhookSubscriptionEnabled: changed=%v err=%v", changed, err)
	}
	enabled, err := db.ListEnabledWebhookSubscriptions()
	if err != nil {
		t.Fatalf("ListEnabledWebhookSubscriptions: %v", err)
	}
	if len(enabled) != 0 {
		t.Errorf("disabled subscription still listed as enabled: %d", len(enabled))
	}
	// Toggling to the same value is a no-op (idempotent).
	if changed, _ := db.SetWebhookSubscriptionEnabled("w1", false); changed {
		t.Errorf("re-disabling reported a change")
	}
	if changed, _ := db.SetWebhookSubscriptionEnabled("w1", true); !changed {
		t.Errorf("re-enabling reported no change")
	}

	// List across all tenants sees it.
	all, err := db.ListWebhookSubscriptions("")
	if err != nil || len(all) != 1 {
		t.Fatalf("ListWebhookSubscriptions(all) = %d, %v", len(all), err)
	}

	// Delete removes it (and reports the change idempotently).
	if changed, err := db.DeleteWebhookSubscription("w1"); err != nil || !changed {
		t.Fatalf("DeleteWebhookSubscription: changed=%v err=%v", changed, err)
	}
	if changed, _ := db.DeleteWebhookSubscription("w1"); changed {
		t.Errorf("second delete reported a change")
	}
}

// TestWebhookDeliveryQueue covers enqueue idempotency, the due/claim read, the
// terminal/retry transitions, status counts, and the dead-letter probe.
func TestWebhookDeliveryQueue(t *testing.T) {
	db := newWebhookTestDB(t)
	if err := db.CreateWebhookSubscription(&models.WebhookSubscription{
		ID: "w1", TenantID: models.DefaultTenantID, Scope: "tenant",
		URL: "https://example.com/hook", Enabled: true,
	}); err != nil {
		t.Fatalf("CreateWebhookSubscription: %v", err)
	}

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	d := &models.WebhookDelivery{
		ID: "d1", SubscriptionID: "w1", TenantID: models.DefaultTenantID,
		EventID: "e1", EventSeq: 5, EventType: "cert.issue", Payload: `{"x":1}`,
		Status: models.WebhookDeliveryPending, MaxAttempts: 3,
		NextAttemptAt: base, CreatedAt: base,
	}
	if err := db.EnqueueWebhookDelivery(d); err != nil {
		t.Fatalf("EnqueueWebhookDelivery: %v", err)
	}
	// Idempotent enqueue: a second row with the same (subscription, event_seq) is
	// ignored, not inserted (the fan-out crash-safety guarantee).
	dup := *d
	dup.ID = "d1-dup"
	if err := db.EnqueueWebhookDelivery(&dup); err != nil {
		t.Fatalf("EnqueueWebhookDelivery(dup): %v", err)
	}
	all, _ := db.ListWebhookDeliveries("w1", "", 0)
	if len(all) != 1 {
		t.Fatalf("duplicate (subscription,event_seq) was inserted: %d rows", len(all))
	}

	// Not yet due before base.
	if due, _ := db.ListDueWebhookDeliveries(base.Add(-time.Second), 10); len(due) != 0 {
		t.Errorf("delivery due before its next_attempt_at: %d", len(due))
	}
	// Due at base.
	due, err := db.ListDueWebhookDeliveries(base, 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("ListDueWebhookDeliveries = %d, %v", len(due), err)
	}

	// Retry transition: bumps attempts, records the error, reschedules.
	if err := db.MarkWebhookDeliveryRetry("d1", base, base.Add(time.Minute), 500, "boom"); err != nil {
		t.Fatalf("MarkWebhookDeliveryRetry: %v", err)
	}
	got, _ := db.GetWebhookDelivery("d1")
	if got.Attempts != 1 || got.LastStatusCode != 500 || got.LastError != "boom" {
		t.Errorf("retry state = attempts %d code %d err %q", got.Attempts, got.LastStatusCode, got.LastError)
	}
	if due, _ := db.ListDueWebhookDeliveries(base, 10); len(due) != 0 {
		t.Errorf("delivery still due after being rescheduled forward")
	}

	// Dead-letter transition + counts + oldest probe.
	if err := db.MarkWebhookDeliveryDead("d1", base.Add(time.Minute), 500, "boom"); err != nil {
		t.Fatalf("MarkWebhookDeliveryDead: %v", err)
	}
	counts, _ := db.CountWebhookDeliveriesByStatus()
	if counts[models.WebhookDeliveryDead] != 1 {
		t.Errorf("dead count = %d, want 1", counts[models.WebhookDeliveryDead])
	}
	oldest, err := db.OldestDeadWebhookDelivery()
	if err != nil || oldest == nil || oldest.ID != "d1" {
		t.Fatalf("OldestDeadWebhookDelivery = %v, %v", oldest, err)
	}

	// Deleting the subscription also removes its deliveries.
	if _, err := db.DeleteWebhookSubscription("w1"); err != nil {
		t.Fatalf("DeleteWebhookSubscription: %v", err)
	}
	if remaining, _ := db.ListWebhookDeliveries("w1", "", 0); len(remaining) != 0 {
		t.Errorf("deliveries orphaned after subscription delete: %d", len(remaining))
	}
}

// TestWebhookCursor covers the fan-out high-water mark's init/round-trip.
func TestWebhookCursor(t *testing.T) {
	db := newWebhookTestDB(t)
	if inited, err := db.WebhookCursorInitialized(); err != nil || inited {
		t.Fatalf("fresh cursor reported initialized=%v err=%v", inited, err)
	}
	if seq, err := db.GetWebhookCursor(); err != nil || seq != 0 {
		t.Fatalf("GetWebhookCursor on empty = %d, %v", seq, err)
	}
	if err := db.SetWebhookCursor(42); err != nil {
		t.Fatalf("SetWebhookCursor: %v", err)
	}
	if inited, _ := db.WebhookCursorInitialized(); !inited {
		t.Errorf("cursor not reported initialized after set")
	}
	if seq, _ := db.GetWebhookCursor(); seq != 42 {
		t.Errorf("cursor round-trip = %d, want 42", seq)
	}
	// Upsert advances in place.
	if err := db.SetWebhookCursor(99); err != nil {
		t.Fatalf("SetWebhookCursor(99): %v", err)
	}
	if seq, _ := db.GetWebhookCursor(); seq != 99 {
		t.Errorf("cursor advance = %d, want 99", seq)
	}
}
