//go:build sqlite

package anchor

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// ---- fakes -----------------------------------------------------------------

// errTSA is what a TSA outage looks like to the anchor service.
var errTSA = errors.New("tsa unreachable")

// fakeTimestamper records every call so the tests can prove a token was (or was
// not) requested, and can force a failure.
type fakeTimestamper struct {
	mu      sync.Mutex
	digests [][]byte
	source  string
	err     error
	inner   Timestamper
	once    sync.Once
	called  chan struct{}
}

func newFakeTimestamper(inner Timestamper) *fakeTimestamper {
	return &fakeTimestamper{inner: inner, called: make(chan struct{})}
}

func (f *fakeTimestamper) Timestamp(ctx context.Context, digest []byte) ([]byte, time.Time, error) {
	f.mu.Lock()
	f.digests = append(f.digests, append([]byte(nil), digest...))
	f.mu.Unlock()
	f.once.Do(func() { close(f.called) })
	if f.err != nil {
		return nil, time.Time{}, f.err
	}
	return f.inner.Timestamp(ctx, digest)
}

func (f *fakeTimestamper) Source() string { return f.source }

func (f *fakeTimestamper) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.digests)
}

// fakeClock is a Clock that can be made to fail, standing in for a
// timesource.Checker whose drift check refuses to vouch for the host clock.
type fakeClock struct {
	now time.Time
	err error
}

func (c fakeClock) Now(context.Context) (time.Time, error) {
	if c.err != nil {
		return time.Time{}, c.err
	}
	return c.now, nil
}

// memAnchorStore is an in-memory Store: no SQLite needed for the pure
// error-propagation paths, and every method can be made to fail independently.
type memAnchorStore struct {
	mu      sync.Mutex
	headSeq int64
	headHsh string
	headAct string
	anchors   []audit.Anchor
	events    []audit.Event
	headReads int

	errHead, errLatest, errInsert, errAppend error
}

func (m *memAnchorStore) EventLogHead() (int64, string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.headReads++
	if m.errHead != nil {
		return 0, "", "", m.errHead
	}
	return m.headSeq, m.headHsh, m.headAct, nil
}

func (m *memAnchorStore) headReadCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.headReads
}

func (m *memAnchorStore) LatestAuditAnchor() (*audit.Anchor, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.errLatest != nil {
		return nil, m.errLatest
	}
	if len(m.anchors) == 0 {
		return nil, nil
	}
	cp := m.anchors[len(m.anchors)-1]
	return &cp, nil
}

func (m *memAnchorStore) InsertAuditAnchor(a *audit.Anchor) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.errInsert != nil {
		return m.errInsert
	}
	m.anchors = append(m.anchors, *a)
	return nil
}

func (m *memAnchorStore) AppendEvent(e *audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.errAppend != nil {
		return m.errAppend
	}
	cp := *e
	cp.Seq = int64(len(m.events)) + 1
	m.events = append(m.events, cp)
	m.headSeq, m.headHsh, m.headAct = cp.Seq, "deadbeef", cp.Action
	return nil
}

func (m *memAnchorStore) lastEvent(t *testing.T) audit.Event {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) == 0 {
		t.Fatal("no audit event was appended")
	}
	return m.events[len(m.events)-1]
}

func (m *memAnchorStore) anchorCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.anchors)
}

// ---- actor and clock seams -------------------------------------------------

// TestAnchorActorAndDeterministicCreatedAt covers the two seams the CLI and the
// tests rely on: WithActor renames the anchoring principal in the audit trail, and
// SetClock makes the persisted CreatedAt exactly reproducible.
func TestAnchorActorAndDeterministicCreatedAt(t *testing.T) {
	h := newTSAHarness(t)
	db, _ := anchorTestDB(t)
	appendEvents(t, db, 3)

	fixed := time.Date(2029, 11, 12, 13, 14, 15, 0, time.FixedZone("UTC+3", 3*3600))
	svc := NewService(db, NewAuthorityTimestamper(h.authority)).WithActor("secsy-ca-cli")
	svc.SetClock(func() time.Time { return fixed })

	res, err := svc.AnchorOnce(context.Background(), false)
	if err != nil {
		t.Fatalf("AnchorOnce: %v", err)
	}
	if res.Skipped || res.Anchor == nil {
		t.Fatalf("expected an anchor, got %+v", res)
	}
	if !res.Anchor.CreatedAt.Equal(fixed) {
		t.Fatalf("CreatedAt = %s, want the injected clock instant %s", res.Anchor.CreatedAt, fixed)
	}
	if res.Anchor.CreatedAt.Location() != time.UTC {
		t.Fatalf("CreatedAt must be stored in UTC, got %s", res.Anchor.CreatedAt.Location())
	}
	// The head hash is canonicalised to lowercase so a later case-insensitive
	// comparison and the token imprint agree.
	if res.Anchor.HeadHash != strings.ToLower(res.Anchor.HeadHash) {
		t.Fatalf("head hash must be stored lowercase, got %q", res.Anchor.HeadHash)
	}

	events, err := db.ListAllEventsAsc()
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	if last.Action != audit.ActionAuditAnchor {
		t.Fatalf("the newest event is %s, want audit.anchor", last.Action)
	}
	if last.Actor != "secsy-ca-cli" {
		t.Fatalf("audit actor = %q, want secsy-ca-cli", last.Actor)
	}
	if last.Target != res.Anchor.ID {
		t.Fatalf("audit target = %q, want the anchor id %q", last.Target, res.Anchor.ID)
	}
	if !strings.Contains(last.Detail, "tsa=internal") {
		t.Fatalf("audit detail should label the internal TSA: %q", last.Detail)
	}

	// The default actor is the background job.
	plain := NewService(db, NewAuthorityTimestamper(h.authority))
	if _, err := plain.AnchorOnce(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	events, _ = db.ListAllEventsAsc()
	if got := events[len(events)-1].Actor; got != "anchor" {
		t.Fatalf("default actor = %q, want anchor", got)
	}
}

// TestTrustedClockFailsClosed: when the trusted-time check cannot vouch for the
// host clock, AnchorOnce must refuse BEFORE requesting a token — otherwise a
// drifted or hostile host clock could mint an anchor dated at will — and must
// persist nothing while still leaving an audit trail of the refusal.
func TestTrustedClockFailsClosed(t *testing.T) {
	h := newTSAHarness(t)
	store := &memAnchorStore{headSeq: 7, headHsh: "abc123", headAct: audit.ActionCertIssue}
	ts := newFakeTimestamper(NewAuthorityTimestamper(h.authority))
	svc := NewService(store, ts)

	driftErr := errors.New("host clock drifted 90s from the trusted source")
	svc.SetTrustedClock(fakeClock{err: driftErr})
	_, err := svc.AnchorOnce(context.Background(), false)
	if err == nil {
		t.Fatal("AnchorOnce must fail closed when the clock cannot be trusted")
	}
	if !errors.Is(err, driftErr) {
		t.Fatalf("error %v does not wrap the clock failure", err)
	}
	if !strings.Contains(err.Error(), "trusted-time") {
		t.Fatalf("error should name the trusted-time check: %v", err)
	}
	if ts.calls() != 0 {
		t.Fatalf("no token may be requested when the clock is untrusted (got %d requests)", ts.calls())
	}
	if store.anchorCount() != 0 {
		t.Fatal("a fail-closed anchor must persist nothing")
	}
	ev := store.lastEvent(t)
	if ev.Action != audit.ActionAuditAnchor || ev.Result != audit.ResultError {
		t.Fatalf("the refusal must be audited as an error, got %s/%s", ev.Action, ev.Result)
	}
	if !strings.Contains(ev.Detail, "trusted-time") {
		t.Fatalf("audit detail should name the trusted-time failure: %q", ev.Detail)
	}

	// A passing trusted clock supplies CreatedAt.
	trusted := time.Date(2030, 2, 2, 2, 2, 2, 0, time.UTC)
	svc.SetTrustedClock(fakeClock{now: trusted})
	res, err := svc.AnchorOnce(context.Background(), true)
	if err != nil {
		t.Fatalf("AnchorOnce with a trusted clock: %v", err)
	}
	if !res.Anchor.CreatedAt.Equal(trusted) {
		t.Fatalf("CreatedAt = %s, want the trusted clock's %s", res.Anchor.CreatedAt, trusted)
	}

	// SetTrustedClock(nil) must be a no-op rather than installing a nil Clock that
	// would panic on the next anchor.
	svc.SetTrustedClock(nil)
	res2, err := svc.AnchorOnce(context.Background(), true)
	if err != nil {
		t.Fatalf("AnchorOnce after SetTrustedClock(nil): %v", err)
	}
	if !res2.Anchor.CreatedAt.Equal(trusted) {
		t.Fatalf("SetTrustedClock(nil) replaced the installed clock: CreatedAt = %s", res2.Anchor.CreatedAt)
	}
}

// TestAnchorDigestIsOverTheLiveHead: the token must be requested over exactly the
// canonical digest of the head the store reported, not over anything else.
func TestAnchorDigestIsOverTheLiveHead(t *testing.T) {
	h := newTSAHarness(t)
	store := &memAnchorStore{headSeq: 42, headHsh: "AABBCC", headAct: audit.ActionCertIssue}
	ts := newFakeTimestamper(NewAuthorityTimestamper(h.authority))
	svc := NewService(store, ts)

	res, err := svc.AnchorOnce(context.Background(), false)
	if err != nil {
		t.Fatalf("AnchorOnce: %v", err)
	}
	if ts.calls() != 1 {
		t.Fatalf("expected exactly one token request, got %d", ts.calls())
	}
	want := audit.AnchorDigest(42, "AABBCC")
	if got := ts.digests[0]; string(got) != string(want) {
		t.Fatalf("submitted digest %x, want the canonical anchor digest %x", got, want)
	}
	// The uppercase store value must be canonicalised in the persisted row, and the
	// token must still verify against it.
	if res.Anchor.HeadHash != "aabbcc" {
		t.Fatalf("stored head hash = %q, want the lowercased form", res.Anchor.HeadHash)
	}
	if err := VerifyAnchorToken(*res.Anchor, nil, time.Now()); err != nil {
		t.Fatalf("the freshly minted anchor must verify: %v", err)
	}
}

// ---- error propagation ------------------------------------------------------

// TestStoreAndTSAFailuresSurface: every failure along the anchoring path must come
// back as an error. A swallowed failure would leave the log unattested while the
// operator (and the metrics) believed it was anchored.
func TestStoreAndTSAFailuresSurface(t *testing.T) {
	h := newTSAHarness(t)
	boom := errors.New("store exploded")
	ctx := context.Background()

	tests := []struct {
		name        string
		configure   func(*memAnchorStore)
		tsErr       error
		wantAudited bool
		wantTokens  int
	}{
		{name: "event-log head read fails", configure: func(s *memAnchorStore) { s.errHead = boom }},
		{name: "latest-anchor read fails", configure: func(s *memAnchorStore) { s.errLatest = boom }},
		{name: "TSA fails", tsErr: errTSA, wantAudited: true, wantTokens: 1},
		{name: "anchor insert fails", configure: func(s *memAnchorStore) { s.errInsert = boom }, wantAudited: true, wantTokens: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &memAnchorStore{headSeq: 5, headHsh: "aa", headAct: audit.ActionCertIssue}
			if tc.configure != nil {
				tc.configure(store)
			}
			ts := newFakeTimestamper(NewAuthorityTimestamper(h.authority))
			ts.err = tc.tsErr
			res, err := NewService(store, ts).AnchorOnce(ctx, false)
			if err == nil {
				t.Fatalf("expected an error, got %+v", res)
			}
			if res != nil {
				t.Fatal("a failure must not also return a Result")
			}
			if ts.calls() != tc.wantTokens {
				t.Fatalf("token requests = %d, want %d", ts.calls(), tc.wantTokens)
			}
			if store.anchorCount() != 0 {
				t.Fatal("a failed anchoring must persist nothing")
			}
			if tc.wantAudited {
				ev := store.lastEvent(t)
				if ev.Action != audit.ActionAuditAnchor || ev.Result != audit.ResultError {
					t.Fatalf("expected an audit.anchor error event, got %s/%s", ev.Action, ev.Result)
				}
			}
		})
	}

	// A failing audit-event append must NOT undo or fail an anchor that is already
	// durable: the anchor row is the evidence, the event is the SIEM copy.
	store := &memAnchorStore{headSeq: 5, headHsh: "aa", headAct: audit.ActionCertIssue, errAppend: boom}
	res, err := NewService(store, NewAuthorityTimestamper(h.authority)).AnchorOnce(ctx, false)
	if err != nil {
		t.Fatalf("a failing audit sink must not fail the anchor: %v", err)
	}
	if res.Anchor == nil || store.anchorCount() != 1 {
		t.Fatalf("the anchor must still be persisted: %+v", res)
	}
}

// TestSeedMetricsFromPersistedAnchors covers the restart path: an empty store is
// not an error, a populated one seeds without error, and a store failure surfaces
// so the caller can log it.
func TestSeedMetricsFromPersistedAnchors(t *testing.T) {
	h := newTSAHarness(t)
	db, _ := anchorTestDB(t)
	svc := NewService(db, NewAuthorityTimestamper(h.authority))

	if err := svc.SeedMetrics(); err != nil {
		t.Fatalf("SeedMetrics with no anchors must be a no-op: %v", err)
	}
	appendEvents(t, db, 2)
	if _, err := svc.AnchorOnce(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if err := svc.SeedMetrics(); err != nil {
		t.Fatalf("SeedMetrics: %v", err)
	}

	boom := errors.New("cannot read anchors")
	failing := NewService(&memAnchorStore{errLatest: boom}, NewAuthorityTimestamper(h.authority))
	if err := failing.SeedMetrics(); !errors.Is(err, boom) {
		t.Fatalf("SeedMetrics must surface a store failure, got %v", err)
	}
}

// TestSourceLabelling: the anchor row records the raw TSA source ("" for the
// in-process authority) while logs and audit details use the readable label.
func TestSourceLabelling(t *testing.T) {
	h := newTSAHarness(t)
	internal := NewService(&memAnchorStore{}, NewAuthorityTimestamper(h.authority))
	if got := internal.sourceLabel(); got != "internal" {
		t.Fatalf("internal source label = %q, want \"internal\"", got)
	}
	external := NewService(&memAnchorStore{}, &fakeTimestamper{source: "https://tsa.example/tsa"})
	if got := external.sourceLabel(); got != "https://tsa.example/tsa" {
		t.Fatalf("external source label = %q", got)
	}
}

// ---- runner -----------------------------------------------------------------

// TestRunnerDefaultsAndLifecycle: NewRunner fills in the interval and logger, Run
// anchors immediately (not only on the first tick) and returns when its context is
// cancelled.
func TestRunnerDefaultsAndLifecycle(t *testing.T) {
	h := newTSAHarness(t)
	db, _ := anchorTestDB(t)
	appendEvents(t, db, 3)
	ts := newFakeTimestamper(NewAuthorityTimestamper(h.authority))
	svc := NewService(db, ts)

	if r := NewRunner(svc, 0, nil); r.interval != DefaultInterval || r.logger == nil {
		t.Fatalf("NewRunner defaults: interval=%s logger=%v", r.interval, r.logger)
	}
	if r := NewRunner(svc, -time.Minute, nil); r.interval != DefaultInterval {
		t.Fatalf("a negative interval must fall back to the default, got %s", r.interval)
	}
	if r := NewRunner(svc, 15*time.Minute, nil); r.interval != 15*time.Minute {
		t.Fatalf("NewRunner discarded its interval: %s", r.interval)
	}

	var logbuf strings.Builder
	runner := NewRunner(svc, time.Hour, log.New(&logbuf, "", 0))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runner.Run(ctx); close(done) }()

	select {
	case <-ts.called:
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatal("Run did not anchor before its first tick")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}

	anchors, err := db.ListAuditAnchorsAsc()
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != 1 {
		t.Fatalf("the immediate run should have produced one anchor, got %d", len(anchors))
	}
	if anchors[0].Seq != 3 {
		t.Fatalf("anchored seq = %d, want the head 3", anchors[0].Seq)
	}
	out := logbuf.String()
	for _, want := range []string{"anchoring started", "anchored head seq=3", "anchoring stopped"} {
		if !strings.Contains(out, want) {
			t.Fatalf("runner log %q is missing %q", out, want)
		}
	}
}

// TestRunnerAbsorbsFailuresAndSkips: a failing TSA must be logged and survived (the
// head is retried next tick), and a skipped run must stay quiet rather than
// reporting an anchor that was not made.
func TestRunnerAbsorbsFailuresAndSkips(t *testing.T) {
	h := newTSAHarness(t)
	store := &memAnchorStore{headSeq: 4, headHsh: "aa", headAct: audit.ActionCertIssue}
	ts := newFakeTimestamper(NewAuthorityTimestamper(h.authority))
	ts.err = errTSA
	var logbuf strings.Builder
	runner := NewRunner(NewService(store, ts), time.Hour, log.New(&logbuf, "", 0))

	runner.runOnce(context.Background()) // must not panic and must not block
	if !strings.Contains(logbuf.String(), errTSA.Error()) {
		t.Fatalf("a failing TSA must be logged: %q", logbuf.String())
	}
	if store.anchorCount() != 0 {
		t.Fatal("a failed run must persist no anchor")
	}

	// An empty log is a skip: nothing logged, nothing persisted, no error.
	logbuf.Reset()
	emptyRunner := NewRunner(NewService(&memAnchorStore{}, ts), time.Hour, log.New(&logbuf, "", 0))
	emptyRunner.runOnce(context.Background())
	if logbuf.Len() != 0 {
		t.Fatalf("a skipped run must stay quiet, logged: %q", logbuf.String())
	}

	// And a runner built with a nil logger must still be usable.
	quiet := NewRunner(NewService(&memAnchorStore{}, ts), time.Hour, nil)
	quiet.logger = log.New(io.Discard, "", 0)
	quiet.runOnce(context.Background())
}

// TestRunnerKeepsAnchoringOnEveryTick exercises the ticker branch of Run: after the
// immediate first attempt the loop must keep going, so a long-lived server does not
// silently stop anchoring after boot.
func TestRunnerKeepsAnchoringOnEveryTick(t *testing.T) {
	h := newTSAHarness(t)
	store := &memAnchorStore{headSeq: 3, headHsh: "aa", headAct: audit.ActionCertIssue}
	runner := NewRunner(NewService(store, NewAuthorityTimestamper(h.authority)), 2*time.Millisecond,
		log.New(io.Discard, "", 0))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runner.Run(ctx); close(done) }()

	deadline := time.Now().Add(30 * time.Second)
	for store.headReadCount() < 3 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("Run stopped attempting after %d head reads", store.headReadCount())
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

// TestAuthorityRejectionSurfaces: when the in-process TSA refuses to stamp — here
// because its own trusted-clock check fails, the fail-closed timeNotAvailable path —
// the anchor job must report an error and persist nothing, not fall back to an
// unsigned anchor.
func TestAuthorityRejectionSurfaces(t *testing.T) {
	h := newTSAHarness(t)
	h.authority.SetTrustedClock(failingAuthorityClock{})
	store := &memAnchorStore{headSeq: 8, headHsh: "aa", headAct: audit.ActionCertIssue}
	svc := NewService(store, NewAuthorityTimestamper(h.authority))

	res, err := svc.AnchorOnce(context.Background(), false)
	if err == nil {
		t.Fatalf("a TSA rejection must surface as an error, got %+v", res)
	}
	if !strings.Contains(err.Error(), "rejected the timestamp request") {
		t.Fatalf("error = %v, want it to name the protocol rejection", err)
	}
	if store.anchorCount() != 0 {
		t.Fatal("a rejected request must persist no anchor")
	}
	ev := store.lastEvent(t)
	if ev.Action != audit.ActionAuditAnchor || ev.Result != audit.ResultError {
		t.Fatalf("the rejection must be audited as an error, got %s/%s", ev.Action, ev.Result)
	}
}

// failingAuthorityClock makes the TSA's own trusted-time check fail, which the
// authority turns into a timeNotAvailable rejection rather than a signed token.
type failingAuthorityClock struct{}

func (failingAuthorityClock) Now(context.Context) (time.Time, error) {
	return time.Time{}, errors.New("authority clock untrusted")
}

// TestTimestamperRejectsUnusableResponses drives the shared request/validate half of
// the Timestamper against a loopback TSA that answers wrongly in each way that
// matters. Every one must be refused: an anchor is only worth something if the token
// provably covers the digest that was submitted.
func TestTimestamperRejectsUnusableResponses(t *testing.T) {
	h := newTSAHarness(t)
	ctx := context.Background()
	digest := audit.AnchorDigest(12, "abcdef")

	var mode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch mode {
		case "ok":
			res, err := h.authority.Stamp(r.Context(), body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(res.Response)
		case "status":
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		case "garbage":
			w.Write([]byte("not a TimeStampResp"))
		case "oversize":
			w.Write(bytes.Repeat([]byte{0x41}, maxTSAResponseBytes+16))
		case "otherdigest":
			other := audit.AnchorDigest(999, "ffffff")
			req, err := tsa.MakeRequest(crypto.SHA256, other, &tsa.RequestOptions{Nonce: big.NewInt(5), CertReq: true})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			res, _ := h.authority.Stamp(r.Context(), req)
			w.Write(res.Response)
		case "othernonce":
			parsed, err := tsa.ParseRequest(body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			req, err := tsa.MakeRequest(parsed.Hash, parsed.Digest, &tsa.RequestOptions{Nonce: big.NewInt(4242), CertReq: true})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			res, _ := h.authority.Stamp(r.Context(), req)
			w.Write(res.Response)
		case "nononce":
			parsed, err := tsa.ParseRequest(body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			req, err := tsa.MakeRequest(parsed.Hash, parsed.Digest, &tsa.RequestOptions{CertReq: true})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			res, _ := h.authority.Stamp(r.Context(), req)
			w.Write(res.Response)
		default:
			http.Error(w, "unknown mode", http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	ts := NewHTTPTimestamper(srv.URL, 10*time.Second)
	mode = "ok"
	token, genTime, err := ts.Timestamp(ctx, digest)
	if err != nil {
		t.Fatalf("happy path: %v", err)
	}
	if len(token) == 0 || genTime.IsZero() {
		t.Fatalf("happy path returned token=%d genTime=%s", len(token), genTime)
	}

	bad := []struct{ mode, want string }{
		{"status", "HTTP 503"},
		{"garbage", "anchor:"},
		{"oversize", "exceeds"},
		{"otherdigest", "does not cover the submitted digest"},
		{"othernonce", "does not echo the request nonce"},
		{"nononce", "does not echo the request nonce"},
	}
	for _, bm := range bad {
		t.Run(bm.mode, func(t *testing.T) {
			mode = bm.mode
			tok, _, err := ts.Timestamp(ctx, digest)
			if err == nil {
				t.Fatalf("mode %q must be refused, got %d token bytes", bm.mode, len(tok))
			}
			if !strings.Contains(err.Error(), bm.want) {
				t.Fatalf("mode %q error = %v, want it to mention %q", bm.mode, err, bm.want)
			}
			if tok != nil {
				t.Fatal("a refused response must not yield a token")
			}
		})
	}

	// A digest that is not SHA-256-sized cannot be turned into a request at all, and
	// must be refused before any transport happens.
	mode = "ok"
	for _, size := range []int{0, 20, 31, 33, 64} {
		if _, _, err := ts.Timestamp(ctx, make([]byte, size)); err == nil {
			t.Fatalf("a %d-byte anchor digest must be refused", size)
		}
	}
	// A cancelled context must fail rather than hang.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := ts.Timestamp(cancelled, digest); err == nil {
		t.Fatal("a cancelled context must fail the request")
	}
	// An unreachable TSA must surface with its URL, and timeout <= 0 must default.
	dead := NewHTTPTimestamper("http://127.0.0.1:1/tsa", 0)
	if _, _, err := dead.Timestamp(ctx, digest); err == nil || !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("an unreachable TSA must surface with its URL: %v", err)
	}
	if dead.Source() != "http://127.0.0.1:1/tsa" {
		t.Fatalf("Source() = %q", dead.Source())
	}
}

// TestAnchorSkipReasonsAreDistinguished pins the two idle-log skip rules: the head
// is already anchored, and the only new entry is the previous anchor's own audit
// record. Both must skip without an error and without requesting a token.
func TestAnchorSkipReasonsAreDistinguished(t *testing.T) {
	h := newTSAHarness(t)
	ctx := context.Background()

	// 1. Empty log.
	empty := &memAnchorStore{}
	ts := newFakeTimestamper(NewAuthorityTimestamper(h.authority))
	res, err := NewService(empty, ts).AnchorOnce(ctx, false)
	if err != nil || !res.Skipped || !strings.Contains(res.Reason, "empty") {
		t.Fatalf("empty log: %+v %v", res, err)
	}
	if ts.calls() != 0 {
		t.Fatal("an empty log must not consume a TSA signature")
	}

	// 2. Head already anchored (same seq, same hash, differing case).
	already := &memAnchorStore{
		headSeq: 9, headHsh: "ABCD", headAct: audit.ActionCertIssue,
		anchors: []audit.Anchor{{ID: "a1", Seq: 9, HeadHash: "abcd"}},
	}
	ts2 := newFakeTimestamper(NewAuthorityTimestamper(h.authority))
	res, err = NewService(already, ts2).AnchorOnce(ctx, false)
	if err != nil || !res.Skipped || !strings.Contains(res.Reason, "already anchored") {
		t.Fatalf("already-anchored head: %+v %v", res, err)
	}
	if ts2.calls() != 0 {
		t.Fatal("an already-anchored head must not consume a TSA signature")
	}
	// …but -force overrides it.
	if res, err = NewService(already, ts2).AnchorOnce(ctx, true); err != nil || res.Skipped {
		t.Fatalf("force must override the skip: %+v %v", res, err)
	}

	// 3. The only new entry is the previous anchor's own audit record.
	ownRecord := &memAnchorStore{
		headSeq: 10, headHsh: "ef01", headAct: audit.ActionAuditAnchor,
		anchors: []audit.Anchor{{ID: "a1", Seq: 9, HeadHash: "abcd"}},
	}
	ts3 := newFakeTimestamper(NewAuthorityTimestamper(h.authority))
	res, err = NewService(ownRecord, ts3).AnchorOnce(ctx, false)
	if err != nil || !res.Skipped || !strings.Contains(res.Reason, "no new events") {
		t.Fatalf("own-anchor-record head: %+v %v", res, err)
	}
	if ts3.calls() != 0 {
		t.Fatal("an idle log must not consume a TSA signature")
	}

	// 4. A head that moved past the anchor record IS new activity.
	moved := &memAnchorStore{
		headSeq: 11, headHsh: "ef02", headAct: audit.ActionCertIssue,
		anchors: []audit.Anchor{{ID: "a1", Seq: 9, HeadHash: "abcd"}},
	}
	ts4 := newFakeTimestamper(NewAuthorityTimestamper(h.authority))
	res, err = NewService(moved, ts4).AnchorOnce(ctx, false)
	if err != nil {
		t.Fatalf("new activity must be anchored: %v", err)
	}
	if res.Skipped {
		t.Fatalf("new activity must not be skipped: %s", res.Reason)
	}

	// 5. A head whose hash changed at the SAME seq is a rewrite, not an idle log:
	//    it must be anchored so the divergence is itself attested.
	rewritten := &memAnchorStore{
		headSeq: 9, headHsh: "9999", headAct: audit.ActionCertIssue,
		anchors: []audit.Anchor{{ID: "a1", Seq: 9, HeadHash: "abcd"}},
	}
	res, err = NewService(rewritten, newFakeTimestamper(NewAuthorityTimestamper(h.authority))).AnchorOnce(ctx, false)
	if err != nil {
		t.Fatalf("a changed head hash must be anchored: %v", err)
	}
	if res.Skipped {
		t.Fatalf("a changed head hash at the same seq must not be treated as idle: %s", res.Reason)
	}
}
