package webhook

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// lifecycleEvents is the catalog of certificate lifecycle audit actions a
// subscription may receive. Using the audit action strings verbatim as the
// webhook event types keeps the event-type filter a direct match against
// audit.Event.Action with no translation table to drift. Only successful events
// are delivered — a denied or errored attempt is not a lifecycle transition.
//
// Bulk operations (cert.issue_bulk / cert.revoke_bulk) are deliberately NOT in
// the catalog: they already emit a per-item cert.issue / cert.revoke event each,
// so including the summary too would double-deliver.
var lifecycleEvents = map[string]bool{
	audit.ActionCertIssue:   true,
	audit.ActionCertRenew:   true,
	audit.ActionCertRevoke:  true,
	audit.ActionCertSuspend: true,
	audit.ActionCertRelease: true,
}

// SupportedEventTypes returns the sorted catalog of subscribable event types,
// for the CLI/console/validation surfaces.
func SupportedEventTypes() []string {
	out := make([]string, 0, len(lifecycleEvents))
	for e := range lifecycleEvents {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// IsSupportedEventType reports whether e is a subscribable lifecycle event.
func IsSupportedEventType(e string) bool { return lifecycleEvents[e] }

// IsLifecycleEvent reports whether an audit action is a deliverable lifecycle
// event (the fan-out gate).
func IsLifecycleEvent(action string) bool { return lifecycleEvents[action] }

// SubscriptionMatches reports whether a subscription should receive an event,
// combining the event-type filter with the tenant scope. It is the sole
// authority for cross-tenant isolation on the delivery path: a tenant-scoped
// subscription only ever matches its own tenant's events.
func SubscriptionMatches(sub *models.WebhookSubscription, ev *audit.Event) bool {
	// Event-type filter: an empty list subscribes to every supported lifecycle
	// event; a non-empty list must contain the event's action.
	if len(sub.EventTypes) > 0 {
		found := false
		for _, t := range sub.EventTypes {
			if t == ev.Action {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// Tenant scope. A platform-scoped subscription receives every tenant's
	// events; a tenant-scoped one receives only its own tenant's. Empty tenants
	// on either side are normalized to the default tenant so a single-tenant
	// deployment matches regardless of whether the event carried "default" or "".
	if sub.Scope == models.WebhookScopePlatform {
		return true
	}
	return normalizeTenant(ev.Tenant) == normalizeTenant(sub.TenantID)
}

func normalizeTenant(t string) string {
	if t == "" {
		return models.DefaultTenantID
	}
	return t
}

// EventPayload is the JSON body POSTed to a subscribed endpoint. It is a stable
// envelope over the source audit event: top-level routing/identity fields plus a
// data object carrying the audit fields (and, for certificate events, the CA id
// and serial split out from the generic target fields).
type EventPayload struct {
	// SpecVersion lets receivers evolve their parsing as the schema changes.
	SpecVersion string `json:"specversion"`
	// Type is the lifecycle event type (audit action), e.g. "cert.issue".
	Type string `json:"type"`
	// ID is the delivery id (also the X-Secsy-Delivery header) — unique per
	// delivery attempt-set, so retries of the same event share it.
	ID string `json:"id"`
	// EventID is the source audit event's id: the idempotency key a receiver
	// should deduplicate on across at-least-once redeliveries.
	EventID string `json:"event_id"`
	// Sequence is the source audit event's monotonic sequence number.
	Sequence int64 `json:"sequence"`
	// Time is when the source event occurred (RFC 3339, UTC).
	Time time.Time `json:"time"`
	// Tenant is the owning tenant of the event.
	Tenant string `json:"tenant"`
	// SubscriptionID identifies the subscription this delivery targets.
	SubscriptionID string `json:"subscription_id"`
	// Data carries the event details.
	Data EventData `json:"data"`
}

// EventData is the per-event detail block.
type EventData struct {
	Action     string `json:"action"`
	Result     string `json:"result"`
	Actor      string `json:"actor,omitempty"`
	ActorName  string `json:"actor_name,omitempty"`
	CAID       string `json:"ca_id,omitempty"`
	Serial     string `json:"serial,omitempty"`
	Target     string `json:"target,omitempty"`
	TargetName string `json:"target_name,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// BuildEventPayload renders the JSON body for a delivery. deliveryID is the
// pre-allocated delivery id so it can be embedded in the signed body.
func BuildEventPayload(deliveryID string, sub *models.WebhookSubscription, ev *audit.Event) ([]byte, error) {
	p := EventPayload{
		SpecVersion:    "1.0",
		Type:           ev.Action,
		ID:             deliveryID,
		EventID:        ev.ID,
		Sequence:       ev.Seq,
		Time:           ev.Timestamp.UTC(),
		Tenant:         normalizeTenant(ev.Tenant),
		SubscriptionID: sub.ID,
		Data: EventData{
			Action:     ev.Action,
			Result:     ev.Result,
			Actor:      ev.Actor,
			ActorName:  ev.ActorName,
			// For certificate lifecycle events the audit Target is the issuing CA id
			// and TargetName is the certificate serial; surface both raw and split.
			CAID:       ev.Target,
			Serial:     ev.TargetName,
			Target:     ev.Target,
			TargetName: ev.TargetName,
			Detail:     ev.Detail,
		},
	}
	return json.Marshal(p)
}

// BuildTestPayload renders a synthetic "webhook.test" delivery body so an
// operator can verify an endpoint (URL reachability + signature handling)
// without waiting for a real lifecycle event.
func BuildTestPayload(deliveryID string, sub *models.WebhookSubscription, now time.Time) ([]byte, error) {
	p := EventPayload{
		SpecVersion:    "1.0",
		Type:           "webhook.test",
		ID:             deliveryID,
		EventID:        deliveryID,
		Sequence:       0,
		Time:           now.UTC(),
		Tenant:         normalizeTenant(sub.TenantID),
		SubscriptionID: sub.ID,
		Data: EventData{
			Action: "webhook.test",
			Result: "success",
			Detail: "test delivery from secsy-pki — your endpoint is reachable and the signature verified",
		},
	}
	return json.Marshal(p)
}
