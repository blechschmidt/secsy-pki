//go:build sqlite

package grpcapi

// Streaming integration test for the StreamEvents server-streaming RPC (Task 130).
// It stands up the real grpcapi.Server — so the stream recovery/context/auth
// interceptors run end-to-end — over an in-process loopback listener, wires the
// event publisher to the audit-append chokepoint exactly as the server does, and
// drives a real gRPC client. It proves live delivery, durable resume-from-seq
// replay, tenant isolation, heartbeats, and the authorization contract, mirroring
// the REST SSE feed's guarantees (internal/handlers/event_stream_test.go) over
// gRPC.

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

const (
	streamRootUser = "root"
	streamRootPass = "stream-e2e-pw"
)

// newStreamServer stands up an in-process gRPC server (plaintext loopback) with
// the event publisher wired to the audit-append hook, plus tenants a and b. A
// bearer token resolves to its subject; the tenant-role resolver grants
// "auditor-a" the auditor role in tenant a (and nothing to anyone else), so the
// test can exercise the tenant-scoped path.
func newStreamServer(t *testing.T) (addr string, api *handlers.API, db *database.DB) {
	t.Helper()
	var err error
	db, err = database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	api = handlers.NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, "")
	// Wire the fan-out to the single audit-append chokepoint, exactly as the server
	// does at startup, so every appended event reaches live subscribers.
	db.SetEventHook(api.EventPublisher().Publish)

	for _, id := range []string{"a", "b"} {
		if err := db.CreateTenant(&models.Tenant{ID: id, Slug: id, Name: id, Status: models.TenantStatusActive}); err != nil {
			t.Fatalf("CreateTenant(%s): %v", id, err)
		}
	}

	authMw := middleware.NewAuthMiddleware(grpcTestVerifier{}, streamRootUser, streamRootPass)
	authMw.SetTenantRoleResolver(func(u *models.UserInfo) map[string][]string {
		if u.Subject == "auditor-a" {
			return map[string][]string{"a": {"auditor"}}
		}
		return nil
	})

	srv, err := New(Config{Address: "127.0.0.1:0", Insecure: true}, api, authMw)
	if err != nil {
		t.Fatalf("grpcapi.New: %v", err)
	}
	go func() { _ = srv.Serve() }()
	t.Cleanup(srv.Stop)
	return srv.Addr(), api, db
}

func streamClient(t *testing.T, addr string) pkiv1.PKIServiceClient {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dialing %s: %v", addr, err)
	}
	t.Cleanup(func() { conn.Close() })
	return pkiv1.NewPKIServiceClient(conn)
}

// basicCtx / bearerCtx build a cancelable client context carrying the credential.
func basicCtx(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	enc := base64.StdEncoding.EncodeToString([]byte(streamRootUser + ":" + streamRootPass))
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Basic "+enc), cancel
}

func bearerCtx(token string) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token), cancel
}

// waitForStreamSubscribers blocks until the publisher reports n subscribers, so a
// test appends an event only once the server-side handler has registered — making
// the fan-out deterministic rather than racing the subscription.
func waitForStreamSubscribers(t *testing.T, api *handlers.API, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if api.EventPublisher().SubscriberCount() == n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("subscriber count did not reach %d (have %d)", n, api.EventPublisher().SubscriberCount())
}

// nextFrame reads the next stream frame, bounding the blocking Recv with timeout.
// A Recv still parked after the timeout unblocks when the stream context is
// cancelled at test teardown.
func nextFrame(t *testing.T, stream pkiv1.PKIService_StreamEventsClient, timeout time.Duration) (*pkiv1.StreamEventsResponse, bool) {
	t.Helper()
	type res struct {
		msg *pkiv1.StreamEventsResponse
		err error
	}
	ch := make(chan res, 1)
	go func() {
		m, e := stream.Recv()
		ch <- res{m, e}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("stream.Recv: %v", r.err)
		}
		return r.msg, true
	case <-time.After(timeout):
		return nil, false
	}
}

// nextAuditEvent returns the next audit-event frame, skipping heartbeats/lag.
func nextAuditEvent(t *testing.T, stream pkiv1.PKIService_StreamEventsClient, timeout time.Duration) *pkiv1.AuditEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatal("timed out waiting for an audit event")
		}
		msg, ok := nextFrame(t, stream, remaining)
		if !ok {
			t.Fatal("timed out waiting for an audit event")
		}
		if e := msg.GetEvent(); e != nil {
			return e
		}
	}
}

func appendEvent(t *testing.T, db *database.DB, id, actor, action, tenant string) {
	t.Helper()
	if err := db.AppendEvent(&audit.Event{ID: id, Actor: actor, Action: action, Tenant: tenant, Result: audit.ResultSuccess}); err != nil {
		t.Fatalf("AppendEvent(%s): %v", id, err)
	}
}

// TestStreamEventsLiveDelivery proves an authenticated operator receives an event
// appended through the ordinary audit-append chokepoint, over the live gRPC feed.
func TestStreamEventsLiveDelivery(t *testing.T) {
	addr, api, db := newStreamServer(t)
	client := streamClient(t, addr)

	ctx, cancel := basicCtx(t)
	defer cancel()
	stream, err := client.StreamEvents(ctx, &pkiv1.StreamEventsRequest{})
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	waitForStreamSubscribers(t, api, 1)

	appendEvent(t, db, "x1", "alice", audit.ActionCertIssue, "a")

	e := nextAuditEvent(t, stream, 3*time.Second)
	if e.GetActor() != "alice" || e.GetAction() != audit.ActionCertIssue || e.GetTenant() != "a" {
		t.Fatalf("received event = %+v, want alice/cert.issue/tenant a", e)
	}
	if e.GetSeq() == 0 || e.GetHash() == "" {
		t.Fatalf("streamed event is not sealed: seq=%d hash=%q", e.GetSeq(), e.GetHash())
	}
}

// TestStreamEventsHeartbeat proves an idle stream still emits heartbeat frames so
// half-open connections are detectable.
func TestStreamEventsHeartbeat(t *testing.T) {
	addr, api, _ := newStreamServer(t)
	client := streamClient(t, addr)

	ctx, cancel := basicCtx(t)
	defer cancel()
	stream, err := client.StreamEvents(ctx, &pkiv1.StreamEventsRequest{HeartbeatSeconds: 1})
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	waitForStreamSubscribers(t, api, 1)

	// No events are appended, so the first frame must be a heartbeat carrying the
	// (zero) resume cursor.
	msg, ok := nextFrame(t, stream, 3*time.Second)
	if !ok {
		t.Fatal("no heartbeat within the interval")
	}
	if msg.GetHeartbeat() == nil {
		t.Fatalf("first idle frame = %T, want a heartbeat", msg.GetPayload())
	}
}

// TestStreamEventsResumeFromSeq proves the durable replay: with resume_from_seq
// set, the stream first replays matching events past that cursor from the event
// log, then continues live — with no gap and no duplicate across the seam.
func TestStreamEventsResumeFromSeq(t *testing.T) {
	addr, api, db := newStreamServer(t)
	client := streamClient(t, addr)

	// Three events land BEFORE any subscription; they exist only in the durable log.
	appendEvent(t, db, "e1", "alice", audit.ActionCertIssue, "a")  // seq 1
	appendEvent(t, db, "e2", "alice", audit.ActionCertRenew, "a")  // seq 2
	appendEvent(t, db, "e3", "alice", audit.ActionCertRevoke, "a") // seq 3

	ctx, cancel := basicCtx(t)
	defer cancel()
	// Resume past seq 1: expect the replay to deliver seq 2 then 3.
	stream, err := client.StreamEvents(ctx, &pkiv1.StreamEventsRequest{ResumeFromSeq: 1})
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}

	if e := nextAuditEvent(t, stream, 3*time.Second); e.GetSeq() != 2 {
		t.Fatalf("first replayed event seq = %d, want 2", e.GetSeq())
	}
	if e := nextAuditEvent(t, stream, 3*time.Second); e.GetSeq() != 3 {
		t.Fatalf("second replayed event seq = %d, want 3", e.GetSeq())
	}

	// Having drained the replay, the handler is now in its live loop with the
	// subscription active. A newly appended event (seq 4) arrives live, exactly once
	// — proving the replay→live seam neither gaps nor repeats.
	waitForStreamSubscribers(t, api, 1)
	appendEvent(t, db, "e4", "bob", audit.ActionCertIssue, "a") // seq 4
	if e := nextAuditEvent(t, stream, 3*time.Second); e.GetSeq() != 4 || e.GetActor() != "bob" {
		t.Fatalf("live event after replay = seq %d actor %q, want seq 4 actor bob", e.GetSeq(), e.GetActor())
	}
}

// TestStreamEventsTenantIsolation proves the gRPC feed enforces the same tenant
// confinement as the REST SSE feed: a tenant-a auditor never receives a tenant-b
// event. A tenant-b event is appended first (must be filtered out), immediately
// followed by a tenant-a event; the auditor sees only the tenant-a one.
func TestStreamEventsTenantIsolation(t *testing.T) {
	addr, api, db := newStreamServer(t)
	client := streamClient(t, addr)

	ctx, cancel := bearerCtx("auditor-a")
	defer cancel()
	stream, err := client.StreamEvents(ctx, &pkiv1.StreamEventsRequest{})
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	waitForStreamSubscribers(t, api, 1)

	appendEvent(t, db, "b1", "bob", audit.ActionCertIssue, "b")
	appendEvent(t, db, "a1", "alice", audit.ActionCertRevoke, "a")

	e := nextAuditEvent(t, stream, 3*time.Second)
	if e.GetTenant() != "a" || e.GetActor() != "alice" {
		t.Fatalf("tenant-a auditor received a cross-tenant event: %+v", e)
	}

	// No further frame carrying an event may arrive — the tenant-b event was filtered.
	if msg, ok := nextFrame(t, stream, 400*time.Millisecond); ok && msg.GetEvent() != nil {
		t.Fatalf("tenant-a auditor received an unexpected extra event (isolation leak?): %+v", msg.GetEvent())
	}
}

// TestStreamEventsAuthz proves the authorization contract at the stream boundary:
// an unauthenticated call is Unauthenticated and a roleless principal is
// PermissionDenied, both surfaced on the first Recv.
func TestStreamEventsAuthz(t *testing.T) {
	addr, _, _ := newStreamServer(t)
	client := streamClient(t, addr)

	code := func(ctx context.Context) codes.Code {
		stream, err := client.StreamEvents(ctx, &pkiv1.StreamEventsRequest{})
		if err != nil {
			return status.Code(err)
		}
		_, err = stream.Recv()
		return status.Code(err)
	}

	// Unauthenticated: no credential metadata.
	noCredCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if got := code(noCredCtx); got != codes.Unauthenticated {
		t.Errorf("no credentials: code = %s, want Unauthenticated", got)
	}

	// Authenticated but roleless -> PermissionDenied (audit:read required).
	roleless, cancel2 := bearerCtx("nobody")
	defer cancel2()
	if got := code(roleless); got != codes.PermissionDenied {
		t.Errorf("roleless principal: code = %s, want PermissionDenied", got)
	}
}
