//go:build sqlite

package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// sseWithUser wraps h so each request carries the given authenticated user in its
// context, exactly as the auth middleware would, letting the SSE handler be
// exercised over a real streaming httptest server without the full auth stack.
func sseWithUser(user *models.UserInfo, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), middleware.UserInfoKey, user)
		ctx = middleware.WithTenantHolder(ctx)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sseAuditEvents parses the SSE body and delivers each "audit" frame's decoded
// event on the returned channel until the body closes. Comments (heartbeats) and
// the priming frame are ignored.
func sseAuditEvents(body io.Reader) <-chan audit.Event {
	ch := make(chan audit.Event, 16)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(body)
		event, data := "", ""
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if event == "audit" && data != "" {
					var e audit.Event
					if err := json.Unmarshal([]byte(data), &e); err == nil {
						ch <- e
					}
				}
				event, data = "", ""
			case strings.HasPrefix(line, ":"):
				// comment / heartbeat — ignore
			case strings.HasPrefix(line, "event:"):
				event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				data += strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			}
		}
	}()
	return ch
}

// waitForSubscribers blocks until the publisher reports n subscribers, so a test
// only appends an event once the streaming handler has registered — making the
// fan-out deterministic rather than racing the subscription.
func waitForSubscribers(t *testing.T, api *API, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if api.EventPublisher().SubscriberCount() == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("subscriber count did not reach %d (have %d)", n, api.EventPublisher().SubscriberCount())
}

// openSSE starts a streaming httptest server for api.StreamEventLog authenticated
// as user, opens a cancelable streaming GET, and returns the parsed-event channel.
// The returned cancel tears the stream (and server) down.
func openSSE(t *testing.T, api *API, user *models.UserInfo, query string) (<-chan audit.Event, func()) {
	t.Helper()
	srv := httptest.NewServer(sseWithUser(user, http.HandlerFunc(api.StreamEventLog)))
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/events/stream"+query, nil)
	if err != nil {
		srv.Close()
		cancel()
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		srv.Close()
		cancel()
		t.Fatalf("GET stream: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		srv.Close()
		cancel()
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		resp.Body.Close()
		srv.Close()
		cancel()
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}
	teardown := func() {
		cancel()
		resp.Body.Close()
		srv.Close()
	}
	return sseAuditEvents(resp.Body), teardown
}

// TestStreamEventLogReceivesAppendedEvent is the end-to-end proof: an operator
// subscribing to the SSE feed receives an event appended through the ordinary
// audit-append chokepoint (database.DB.AppendEvent), via the wired publisher hook.
func TestStreamEventLogReceivesAppendedEvent(t *testing.T) {
	api, db := tenantAPI(t)
	db.SetEventHook(api.EventPublisher().Publish)
	mkTenant(t, db, "a")

	root := &models.UserInfo{Subject: "root", IsRoot: true}
	events, teardown := openSSE(t, api, root, "")
	defer teardown()

	waitForSubscribers(t, api, 1)

	if err := db.AppendEvent(&audit.Event{
		ID: "x1", Actor: "alice", Action: audit.ActionCertIssue, Tenant: "a", Result: audit.ResultSuccess,
	}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}

	select {
	case e := <-events:
		if e.Actor != "alice" || e.Action != audit.ActionCertIssue || e.Tenant != "a" {
			t.Fatalf("received event = %+v, want alice/cert.issue/tenant a", e)
		}
		if e.Seq == 0 || e.Hash == "" {
			t.Fatalf("streamed event is not sealed: seq=%d hash=%q", e.Seq, e.Hash)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the streamed event")
	}
}

// TestStreamEventLogTenantIsolation proves the SSE feed enforces the same
// tenant confinement as the paged listing: a tenant-a auditor never receives a
// tenant-b event. A tenant-b event is appended first (and must be dropped at the
// filter), immediately followed by a tenant-a event; the auditor sees only the
// tenant-a one, and nothing else follows.
func TestStreamEventLogTenantIsolation(t *testing.T) {
	api, db := tenantAPI(t)
	db.SetEventHook(api.EventPublisher().Publish)
	mkTenant(t, db, "a")
	mkTenant(t, db, "b")

	auditorA := tenantUser("alice", "a", "auditor")
	events, teardown := openSSE(t, api, auditorA, "")
	defer teardown()

	waitForSubscribers(t, api, 1)

	if err := db.AppendEvent(&audit.Event{ID: "b1", Actor: "bob", Action: audit.ActionCertIssue, Tenant: "b", Result: audit.ResultSuccess}); err != nil {
		t.Fatalf("AppendEvent(b): %v", err)
	}
	if err := db.AppendEvent(&audit.Event{ID: "a1", Actor: "alice", Action: audit.ActionCertRevoke, Tenant: "a", Result: audit.ResultSuccess}); err != nil {
		t.Fatalf("AppendEvent(a): %v", err)
	}

	select {
	case e := <-events:
		if e.Tenant != "a" || e.Actor != "alice" {
			t.Fatalf("tenant-a auditor received a cross-tenant event: %+v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the tenant-a event")
	}

	// No further event may arrive — the tenant-b event must have been filtered out.
	select {
	case e := <-events:
		t.Fatalf("tenant-a auditor received an unexpected extra event (isolation leak?): %+v", e)
	case <-time.After(250 * time.Millisecond):
		// good: the tenant-b event was never delivered
	}
}

// TestStreamEventLogActionFilter proves the ?action= narrowing reaches the
// subscriber filter: only events of the requested action are streamed.
func TestStreamEventLogActionFilter(t *testing.T) {
	api, db := tenantAPI(t)
	db.SetEventHook(api.EventPublisher().Publish)
	mkTenant(t, db, "a")

	root := &models.UserInfo{Subject: "root", IsRoot: true}
	events, teardown := openSSE(t, api, root, "?action="+audit.ActionCertRevoke)
	defer teardown()

	waitForSubscribers(t, api, 1)

	// An issue event (filtered out) followed by a revoke event (delivered).
	if err := db.AppendEvent(&audit.Event{ID: "i1", Actor: "alice", Action: audit.ActionCertIssue, Tenant: "a", Result: audit.ResultSuccess}); err != nil {
		t.Fatalf("AppendEvent(issue): %v", err)
	}
	if err := db.AppendEvent(&audit.Event{ID: "r1", Actor: "alice", Action: audit.ActionCertRevoke, Tenant: "a", Result: audit.ResultSuccess}); err != nil {
		t.Fatalf("AppendEvent(revoke): %v", err)
	}

	select {
	case e := <-events:
		if e.Action != audit.ActionCertRevoke {
			t.Fatalf("action filter leaked a %q event", e.Action)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the revoke event")
	}
}

// TestStreamEventLogForbidden proves an authenticated principal with no read
// capability is refused before any streaming begins (403, not a hung stream).
func TestStreamEventLogForbidden(t *testing.T) {
	api, _ := tenantAPI(t)
	rec := httptest.NewRecorder()
	noRole := &models.UserInfo{Subject: "nobody"}
	api.StreamEventLog(rec, reqAs(http.MethodGet, "/api/events/stream", noRole, "", ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", rec.Code, rec.Body.String())
	}
}

// TestStreamEventLogUnsubscribesOnDisconnect proves the handler releases its
// subscriber when the client goes away, so subscriptions do not leak.
func TestStreamEventLogUnsubscribesOnDisconnect(t *testing.T) {
	api, db := tenantAPI(t)
	db.SetEventHook(api.EventPublisher().Publish)

	root := &models.UserInfo{Subject: "root", IsRoot: true}
	_, teardown := openSSE(t, api, root, "")
	waitForSubscribers(t, api, 1)

	teardown() // disconnect the client

	// The handler's ctx.Done fires and it unsubscribes; the count drops back to 0.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if api.EventPublisher().SubscriberCount() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("subscriber was not released on disconnect (count=%d)", api.EventPublisher().SubscriberCount())
}
