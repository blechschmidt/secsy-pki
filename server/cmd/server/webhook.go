package main

import (
	"log"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/leader"
	"github.com/blechschmidt/secsy-pki/server/internal/webhook"
)

// setupWebhook wires the durable outbound webhook / eventing system (Task 116).
//
// The subscription-management API/CLI work regardless of configuration; this
// wires only the DELIVERY side, and only when webhook.enabled is set:
//
//   - It composes the audit-append event hook so, in addition to fanning every
//     hash-chained event out to the operator SSE feed (Task 104), it also nudges
//     the webhook engine's fan-out whenever a certificate lifecycle event is
//     committed. The nudge is non-blocking and never re-enters the store, honoring
//     the hook contract; durability does not depend on it (the fan-out sweeps the
//     durable event log from a persistent cursor and also polls), it only lowers
//     delivery latency below the poll interval.
//
//   - It registers the delivery worker as a leader-elected job (Task 68) so, in a
//     multi-replica deployment, exactly one replica delivers — no duplicate POSTs.
//     A handover at worst redelivers the last unacknowledged attempt, which the
//     at-least-once, HMAC-signed, EventID-keyed payload lets receivers deduplicate.
//
// The API is always told the worker's state (SetWebhookDelivery) so the
// create/test responses can report whether queued deliveries will actually be
// sent.
func setupWebhook(cfg *config.Config, db *database.DB, api *handlers.API, elector *leader.Elector) {
	wc := cfg.Webhook
	// Inform the API of the delivery-worker state and retry budget for test
	// deliveries — regardless of whether the worker runs here.
	api.SetWebhookDelivery(wc.Enabled, wc.Attempts())
	if !wc.Enabled {
		return
	}

	engine := webhook.New(db, webhook.Config{
		PollInterval:    wc.PollInterval(),
		BatchSize:       wc.Batch(),
		MaxAttempts:     wc.Attempts(),
		Timeout:         wc.Timeout(),
		BackoffBase:     wc.BackoffBase(),
		BackoffMax:      wc.BackoffMax(),
		AuditDeliveries: wc.AuditDeliveriesEnabled(),
		Logger:          log.Default(),
	})

	// Compose the audit-append hook: keep the SSE publisher fan-out AND wake the
	// webhook fan-out. The publisher was installed as the sole hook at startup;
	// re-installing the composed hook here (before serving begins) is safe because
	// SetEventHook serializes with the append critical section.
	publisher := api.EventPublisher()
	db.SetEventHook(func(e audit.Event) {
		publisher.Publish(e)
		engine.Notify(e)
	})

	elector.Register("webhook-deliver", engine.Run)
	log.Printf("Durable outbound webhooks enabled (poll=%s, batch=%d, max_attempts=%d, backoff=%s..%s, timeout=%s)",
		wc.PollInterval(), wc.Batch(), wc.Attempts(), wc.BackoffBase(), wc.BackoffMax(), wc.Timeout())
}
