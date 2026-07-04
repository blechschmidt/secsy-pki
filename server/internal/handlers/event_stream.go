package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/eventstream"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
)

// eventStreamHeartbeat is how often the SSE feed emits a comment line when no
// events are flowing. It keeps the connection (and any intermediary proxy) from
// idling out, and lets a client detect a dead connection promptly.
const eventStreamHeartbeat = 15 * time.Second

// StreamEventLog serves the tamper-evident audit event log as a live Server-Sent
// Events feed (Task 90/104): every hash-chained event appended anywhere in the
// system (HTTP handlers, background jobs, protocol servers) is fanned out to
// connected operators in real time. It is the live-tail companion to
// ListEventLog — that endpoint pages the historical log; this one streams new
// entries as they are sealed.
//
// Authorization and tenant scoping are identical to ListEventLog: audit:read is
// required, a platform operator sees every tenant (optionally narrowed with
// ?tenant=), and a tenant-scoped principal is confined to its own tenant's
// events — the same isolation guarantee, enforced here by the subscriber filter
// rather than a SQL WHERE clause. An optional ?action= narrows the stream to a
// single audit action, mirroring the listing endpoint's filter.
//
// The feed favors liveness over completeness: a subscriber that cannot keep up
// drops its oldest undelivered events (and is told, via a "lag" event) rather
// than ever blocking the audit-append hot path.
func (a *API) StreamEventLog(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.canRead(user) {
		writeError(w, http.StatusForbidden, "audit:read capability required (admin or auditor role)")
		return
	}

	action := r.URL.Query().Get("action")
	// Tenant scoping mirrors ListEventLog exactly: a platform operator (root or a
	// platform-wide role) streams across tenants, optionally narrowing with
	// ?tenant=; a tenant-scoped principal is pinned to the single tenant it belongs
	// to and cannot widen the view.
	tenantFilter := r.URL.Query().Get("tenant")
	if !user.IsRoot && len(user.Roles) == 0 {
		member := user.TenantsWithRoles()
		switch len(member) {
		case 0:
			writeError(w, http.StatusForbidden, "no tenant membership")
			return
		case 1:
			tenantFilter = member[0]
		default:
			if tenantFilter == "" {
				writeError(w, http.StatusBadRequest, "tenant query parameter is required")
				return
			}
			if len(user.TenantRoles[tenantFilter]) == 0 {
				writeError(w, http.StatusForbidden, "not a member of tenant %q", tenantFilter)
				return
			}
		}
	}

	// The feed streams incrementally, so the ResponseWriter must support flushing.
	// Every wrapper in the middleware chain (observability recorder, access-log
	// status writer) delegates Flush, so this succeeds in production; it only fails
	// for a non-streaming test recorder.
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming unsupported by this connection")
		return
	}

	// Translate the resolved scope into a subscriber filter. An empty tenantFilter
	// means the platform-wide view (all tenants, including platform-level events
	// with no owning tenant); a specific tenant matches only that tenant's events —
	// exactly the confinement ListEvents applies with its tenant WHERE clause.
	filter := eventstream.Filter{Action: action}
	if tenantFilter == "" {
		filter.AllTenants = true
	} else {
		filter.Tenants = map[string]bool{tenantFilter: true}
	}

	sub := a.events.Subscribe(filter)
	defer a.events.Unsubscribe(sub)

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	// Defeat response buffering in reverse proxies (nginx honors this header), so
	// events reach the browser as soon as they are flushed rather than in blocks.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// Prime the stream: hint a reconnection delay and open the event stream with a
	// comment so the client's connection is established immediately, before the
	// first audit event (which may be a long time coming on a quiet system).
	if _, err := io.WriteString(w, "retry: 3000\n: connected\n\n"); err != nil {
		return
	}
	flusher.Flush()

	ctx := r.Context()
	notify := sub.Notify()
	heartbeat := time.NewTicker(eventStreamHeartbeat)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			// The client disconnected (or the server is shutting down): unsubscribe
			// (deferred) and stop. AppendEvent no longer fans out to this subscriber.
			return
		case <-notify:
			events, dropped := sub.Drain()
			// Report lag first: the dropped events were older than the retained
			// batch, so telling the client "you missed N events" before delivering
			// the newer ones preserves chronological sense.
			if dropped > 0 {
				if !writeLagNotice(w, dropped) {
					return
				}
			}
			for i := range events {
				if !writeAuditEvent(w, &events[i]) {
					return
				}
			}
			flusher.Flush()
		case <-heartbeat.C:
			if _, err := io.WriteString(w, ": heartbeat\n\n"); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

// writeAuditEvent renders one event as an SSE frame. The sequence number becomes
// the SSE id (so a reconnecting client's Last-Event-ID names the last event it
// saw), the event type is "audit", and the data payload is the event's canonical
// JSON. It reports whether the write succeeded; a failure means the client is
// gone and the caller should stop.
func writeAuditEvent(w io.Writer, e *audit.Event) bool {
	payload, err := json.Marshal(e)
	if err != nil {
		// A well-formed audit.Event always marshals; treat the impossible case as a
		// non-fatal skip rather than tearing the stream down.
		return true
	}
	// json.Marshal escapes any control characters (including newlines) inside
	// string fields, so payload is a single line and needs no multi-line SSE
	// data-field splitting.
	_, err = fmt.Fprintf(w, "id: %d\nevent: audit\ndata: %s\n\n", e.Seq, payload)
	return err == nil
}

// writeLagNotice emits an SSE "lag" event telling the client its buffer
// overflowed and dropped the given number of oldest undelivered events, so a
// live viewer knows the feed is not complete and can refresh the paged log for
// the gap. It reports whether the write succeeded.
func writeLagNotice(w io.Writer, dropped uint64) bool {
	payload, _ := json.Marshal(map[string]interface{}{
		"dropped": dropped,
		"message": fmt.Sprintf("subscriber lagged: %d event(s) dropped; refresh the audit log to see the gap", dropped),
	})
	_, err := fmt.Fprintf(w, "event: lag\ndata: %s\n\n", payload)
	return err == nil
}
