package ers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
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
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/tsa"
)

// ---- fakes -----------------------------------------------------------------

// errTSA is the failure a TSA outage surfaces as.
var errTSA = errors.New("tsa is down")

// failingTimestamper always fails. A preservation cycle that swallowed this would
// leave audit events silently unpreserved while advancing its cursor past them.
type failingTimestamper struct{ calls int }

func (f *failingTimestamper) Timestamp(context.Context, crypto.Hash, []byte) ([]byte, time.Time, error) {
	f.calls++
	return nil, time.Time{}, errTSA
}
func (f *failingTimestamper) Source() string { return "failing" }

// countingTimestamper wraps a real Timestamper, counting calls and signalling the
// first one so a background runner can be observed without sleeping.
type countingTimestamper struct {
	Timestamper
	mu     sync.Mutex
	calls  int
	once   sync.Once
	called chan struct{}
}

func newCountingTimestamper(inner Timestamper) *countingTimestamper {
	return &countingTimestamper{Timestamper: inner, called: make(chan struct{})}
}

func (c *countingTimestamper) Timestamp(ctx context.Context, h crypto.Hash, digest []byte) ([]byte, time.Time, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	c.once.Do(func() { close(c.called) })
	return c.Timestamper.Timestamp(ctx, h, digest)
}

func (c *countingTimestamper) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// flakyStore injects a failure into any single Store method, so every persistence
// error path can be shown to surface rather than to be swallowed.
type flakyStore struct {
	*memStore
	maxSeq, cursorInit, getCursor, setCursor error
	listEvents, insert, update               error
	listAll, listPage, appendEvent           error

	headMu    sync.Mutex
	headReads int
}

func (f *flakyStore) MaxEventSeq() (int64, error) {
	f.headMu.Lock()
	f.headReads++
	f.headMu.Unlock()
	if f.maxSeq != nil {
		return 0, f.maxSeq
	}
	return f.memStore.MaxEventSeq()
}

func (f *flakyStore) headReadCount() int {
	f.headMu.Lock()
	defer f.headMu.Unlock()
	return f.headReads
}

func (f *flakyStore) ErsCursorInitialized() (bool, error) {
	if f.cursorInit != nil {
		return false, f.cursorInit
	}
	return f.memStore.ErsCursorInitialized()
}

func (f *flakyStore) GetErsCursor() (int64, error) {
	if f.getCursor != nil {
		return 0, f.getCursor
	}
	return f.memStore.GetErsCursor()
}

func (f *flakyStore) SetErsCursor(seq int64) error {
	if f.setCursor != nil {
		return f.setCursor
	}
	return f.memStore.SetErsCursor(seq)
}

func (f *flakyStore) ListEventsSince(after int64, limit int) ([]audit.Event, error) {
	if f.listEvents != nil {
		return nil, f.listEvents
	}
	return f.memStore.ListEventsSince(after, limit)
}

func (f *flakyStore) InsertEvidenceRecord(r *models.EvidenceRecord) error {
	if f.insert != nil {
		return f.insert
	}
	return f.memStore.InsertEvidenceRecord(r)
}

func (f *flakyStore) UpdateEvidenceRecord(r *models.EvidenceRecord) error {
	if f.update != nil {
		return f.update
	}
	return f.memStore.UpdateEvidenceRecord(r)
}

func (f *flakyStore) ListAllEvidenceRecords() ([]models.EvidenceRecord, error) {
	if f.listAll != nil {
		return nil, f.listAll
	}
	return f.memStore.ListAllEvidenceRecords()
}

func (f *flakyStore) ListEvidenceRecords(limit, offset int) ([]models.EvidenceRecord, int, error) {
	if f.listPage != nil {
		return nil, 0, f.listPage
	}
	return f.memStore.ListEvidenceRecords(limit, offset)
}

func (f *flakyStore) AppendEvent(e *audit.Event) error {
	if f.appendEvent != nil {
		return f.appendEvent
	}
	return f.memStore.AppendEvent(e)
}

// lastEvent returns the newest appended audit event.
func (m *memStore) lastEvent(t *testing.T) audit.Event {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) == 0 {
		t.Fatal("no audit events were appended")
	}
	return m.events[len(m.events)-1]
}

// ---- generation error propagation ------------------------------------------

// TestTSAFailureNeverLosesEvents is the central stability property of the
// preservation loop: when the TSA is unavailable nothing may be recorded as
// preserved. In particular the durable cursor must not advance, or the events in
// the failed batch would never be preserved by any later cycle.
func TestTSAFailureNeverLosesEvents(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	store.appendN(5)
	if err := store.SetErsCursor(0); err != nil { // mark preservation as already enabled
		t.Fatal(err)
	}
	ts := &failingTimestamper{}
	svc := NewService(store, ts, Options{Batch: 2})

	created, err := svc.GenerateAudit(ctx)
	if err == nil {
		t.Fatal("GenerateAudit must surface a TSA failure")
	}
	if !errors.Is(err, errTSA) {
		t.Fatalf("error %v does not wrap the TSA failure", err)
	}
	if created != 0 {
		t.Fatalf("created = %d, want 0", created)
	}
	if ts.calls == 0 {
		t.Fatal("the TSA should have been asked at least once")
	}
	if cursor, _ := store.GetErsCursor(); cursor != 0 {
		t.Fatalf("cursor advanced to %d despite a TSA failure: the batch would never be preserved", cursor)
	}
	if all, _ := store.ListAllEvidenceRecords(); len(all) != 0 {
		t.Fatalf("a failed generation persisted %d records", len(all))
	}

	// The same failure must surface from every other generation entry point.
	if _, err := svc.GenerateArtifact(ctx, "artifact", objects("a")); !errors.Is(err, errTSA) {
		t.Fatalf("GenerateArtifact error = %v, want the TSA failure", err)
	}
	if _, err := svc.GenerateAuditRange(ctx, 1, 3); !errors.Is(err, errTSA) {
		t.Fatalf("GenerateAuditRange error = %v, want the TSA failure", err)
	}
	if all, _ := store.ListAllEvidenceRecords(); len(all) != 0 {
		t.Fatalf("failed generations persisted %d records", len(all))
	}

	// …and from the record-level renewal paths.
	h := newTSAHarness(t)
	er, err := Generate(ctx, h.ts(), GenerateOptions{Objects: objects("a", "b")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := er.RenewTimestamp(ctx, ts); !errors.Is(err, errTSA) {
		t.Fatalf("RenewTimestamp error = %v, want the TSA failure", err)
	}
	if _, err := er.RenewHashTree(ctx, ts, objects("a", "b"), crypto.SHA512); !errors.Is(err, errTSA) {
		t.Fatalf("RenewHashTree error = %v, want the TSA failure", err)
	}
}

// TestStoreFailuresSurface walks each persistence failure the generation loop can
// hit and asserts it becomes a caller-visible error with the cursor left where a
// retry can still pick the batch up.
func TestStoreFailuresSurface(t *testing.T) {
	ctx := context.Background()
	boom := errors.New("store exploded")

	newFlaky := func(t *testing.T, configure func(*flakyStore)) (*flakyStore, *Service) {
		t.Helper()
		h := newTSAHarness(t)
		mem := newMemStore()
		mem.appendN(4)
		if err := mem.SetErsCursor(0); err != nil {
			t.Fatal(err)
		}
		fs := &flakyStore{memStore: mem}
		configure(fs)
		return fs, NewService(fs, h.ts(), Options{Batch: 2})
	}

	tests := []struct {
		name      string
		configure func(*flakyStore)
	}{
		{"cursor-state read fails", func(f *flakyStore) { f.cursorInit = boom }},
		{"event-log head read fails", func(f *flakyStore) { f.maxSeq = boom }},
		{"cursor read fails", func(f *flakyStore) { f.getCursor = boom }},
		{"event listing fails", func(f *flakyStore) { f.listEvents = boom }},
		{"record insert fails", func(f *flakyStore) { f.insert = boom }},
		{"cursor advance fails", func(f *flakyStore) { f.setCursor = boom }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs, svc := newFlaky(t, tc.configure)
			_, err := svc.GenerateAudit(ctx)
			if err == nil {
				t.Fatal("GenerateAudit must surface the store failure")
			}
			if !errors.Is(err, boom) {
				t.Fatalf("error %v does not wrap the store failure", err)
			}
			if cursor, cerr := fs.memStore.GetErsCursor(); cerr == nil && cursor > 2 {
				t.Fatalf("cursor advanced to %d past the failed batch", cursor)
			}
		})
	}

	// A listing failure in RenewAll is fatal to the pass (nothing can be renewed).
	_, svc := newFlaky(t, func(f *flakyStore) { f.listAll = boom })
	if _, _, err := svc.RenewAll(ctx); !errors.Is(err, boom) {
		t.Fatalf("RenewAll error = %v, want the store failure", err)
	}

	// A per-record failure is counted as pending, not fatal, and is logged.
	var logged strings.Builder
	fs2, _ := newFlaky(t, func(f *flakyStore) {})
	svc2 := NewService(fs2, &failingTimestamper{}, Options{
		Hash:  crypto.SHA512,
		Logf:  func(f string, a ...any) { fmt.Fprintf(&logged, f, a...) },
		Batch: 2,
	})
	// A stored row whose DER cannot be parsed must not abort the pass.
	if err := fs2.InsertEvidenceRecord(&models.EvidenceRecord{
		ID: "corrupt", Scope: ScopeAudit, Record: []byte{0x30, 0x00}, FirstSeq: 1, LastSeq: 2,
	}); err != nil {
		t.Fatal(err)
	}
	renewed, pending, err := svc2.RenewAll(ctx)
	if err != nil {
		t.Fatalf("RenewAll must tolerate a corrupt row: %v", err)
	}
	if renewed != 0 || pending != 1 {
		t.Fatalf("renewed=%d pending=%d, want 0/1", renewed, pending)
	}
	if !strings.Contains(logged.String(), "corrupt") {
		t.Fatalf("the corrupt record should have been logged: %q", logged.String())
	}
	if ev := fs2.memStore.lastEvent(t); ev.Action != audit.ActionERSRenew || ev.Result != audit.ResultError {
		t.Fatalf("a failed renewal must append an error audit event, got %s/%s", ev.Action, ev.Result)
	}
}

// TestAppendEventFailureDoesNotHideTheRecord: the audit event is best-effort, so a
// failure to append it must be logged but must not undo (or fail) the record that
// was already persisted.
func TestAppendEventFailureDoesNotHideTheRecord(t *testing.T) {
	h := newTSAHarness(t)
	fs := &flakyStore{memStore: newMemStore(), appendEvent: errors.New("no audit sink")}
	var logged strings.Builder
	svc := NewService(fs, h.ts(), Options{Logf: func(f string, a ...any) { fmt.Fprintf(&logged, f, a...) }})
	rec, err := svc.GenerateArtifact(context.Background(), "doc", objects("a"))
	if err != nil {
		t.Fatalf("GenerateArtifact: %v", err)
	}
	if rec == nil {
		t.Fatal("no record returned")
	}
	if all, _ := fs.ListAllEvidenceRecords(); len(all) != 1 {
		t.Fatalf("the record must still be persisted, got %d rows", len(all))
	}
	if !strings.Contains(logged.String(), "audit event") {
		t.Fatalf("the audit-append failure should be logged: %q", logged.String())
	}
}

// ---- artifact and range generation -----------------------------------------

// TestGenerateArtifactRoundTrip covers the CLI `ers generate -file` path: the
// record is persisted with artifact scope, its metadata columns are derived from
// the record itself, and it verifies against the supplied bytes.
func TestGenerateArtifactRoundTrip(t *testing.T) {
	h := newTSAHarness(t)
	gen := time.Date(2029, 7, 8, 9, 10, 11, 0, time.UTC)
	h.setNow(gen)
	store := newMemStore()
	svc := NewService(store, h.ts(), Options{Hash: crypto.SHA384}).WithActor("secsy-ca-cli")
	created := time.Date(2029, 7, 8, 9, 30, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return created })

	objs := []DataObject{{ID: "report.pdf", Bytes: []byte("pdf-bytes")}, {ID: "sig.p7s", Bytes: []byte("cms-bytes")}}
	rec, err := svc.GenerateArtifact(context.Background(), "quarterly report", objs)
	if err != nil {
		t.Fatalf("GenerateArtifact: %v", err)
	}
	if rec.Scope != ScopeArtifact {
		t.Fatalf("scope = %q, want %q", rec.Scope, ScopeArtifact)
	}
	if rec.Description != "quarterly report" {
		t.Fatalf("description = %q", rec.Description)
	}
	if rec.DigestAlg != "sha384" {
		t.Fatalf("digest alg = %q, want sha384", rec.DigestAlg)
	}
	if rec.Chains != 1 {
		t.Fatalf("chains = %d, want 1", rec.Chains)
	}
	if !rec.CreatedAt.Equal(created) {
		t.Fatalf("created at = %s, want the injected clock %s", rec.CreatedAt, created)
	}
	if !rec.LastGenTime.Equal(gen) {
		t.Fatalf("last gen time = %s, want the token genTime %s", rec.LastGenTime, gen)
	}
	if rec.TSANotAfter == nil {
		t.Fatal("the TSA certificate expiry must be recorded for renewal scheduling")
	}
	if got, want := rec.ObjectIDs, []string{"report.pdf", "sig.p7s"}; len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("object ids = %v, want %v", got, want)
	}
	if rec.FirstSeq != 0 || rec.LastSeq != 0 {
		t.Fatalf("an artifact record must not claim an event-log range: %d-%d", rec.FirstSeq, rec.LastSeq)
	}

	// The actor override must show up in the audit trail.
	if ev := store.lastEvent(t); ev.Actor != "secsy-ca-cli" || ev.Action != audit.ActionERSGenerate {
		t.Fatalf("audit event = %s by %s, want ers.generate by secsy-ca-cli", ev.Action, ev.Actor)
	}

	// It verifies against the exact bytes, and not against altered bytes.
	er := mustParse(t, rec.Record)
	res, err := Verify(er, VerifyOptions{Objects: objs, Roots: []*x509.Certificate{h.caCert}, Now: gen.Add(time.Hour)})
	if err != nil || !res.Valid {
		t.Fatalf("artifact record must verify: err=%v reason=%s", err, res.Reason)
	}
	altered := []DataObject{{ID: "report.pdf", Bytes: []byte("pdf-bytez")}, objs[1]}
	if res, _ := Verify(er, VerifyOptions{Objects: altered, Now: gen.Add(time.Hour)}); res.Valid {
		t.Fatal("an altered artifact must not verify")
	}

	// Artifact records cannot be reconstructed server-side, so the background
	// renewal must report them pending rather than guess at their bytes.
	if _, err := svc.ResolveObjects(*rec); err == nil {
		t.Fatal("ResolveObjects must refuse an artifact-scope record")
	}
	if _, err := svc.GenerateArtifact(context.Background(), "empty", nil); !errors.Is(err, ErrEmpty) {
		t.Fatalf("GenerateArtifact(nil) = %v, want ErrEmpty", err)
	}
}

// TestGenerateAuditRange covers the historical-preservation path and its input
// validation. The cursor must be left untouched: the range command is explicitly
// independent of the background loop's position.
func TestGenerateAuditRange(t *testing.T) {
	h := newTSAHarness(t)
	store := newMemStore()
	store.appendN(10)
	if err := store.SetErsCursor(7); err != nil {
		t.Fatal(err)
	}
	svc := NewService(store, h.ts(), Options{})
	ctx := context.Background()

	rec, err := svc.GenerateAuditRange(ctx, 3, 6)
	if err != nil {
		t.Fatalf("GenerateAuditRange: %v", err)
	}
	if rec.Scope != ScopeAudit || rec.FirstSeq != 3 || rec.LastSeq != 6 {
		t.Fatalf("record covers %s %d-%d, want audit 3-6", rec.Scope, rec.FirstSeq, rec.LastSeq)
	}
	if len(rec.ObjectIDs) != 4 {
		t.Fatalf("expected 4 covered objects, got %d: %v", len(rec.ObjectIDs), rec.ObjectIDs)
	}
	if rec.ObjectIDs[0] != "event:3" || rec.ObjectIDs[3] != "event:6" {
		t.Fatalf("object ids = %v", rec.ObjectIDs)
	}
	if cursor, _ := store.GetErsCursor(); cursor != 7 {
		t.Fatalf("GenerateAuditRange moved the cursor to %d", cursor)
	}
	// It must verify against the objects re-derived from the log.
	if res := store.verifyRecord(t, *rec, []*x509.Certificate{h.caCert}, time.Now()); !res.Valid {
		t.Fatalf("range record must verify: %s", res.Reason)
	}
	// A single-event range is the boundary case.
	if one, err := svc.GenerateAuditRange(ctx, 10, 10); err != nil || one.FirstSeq != 10 || one.LastSeq != 10 {
		t.Fatalf("single-event range: %+v %v", one, err)
	}

	for _, bad := range [][2]int64{{0, 5}, {-1, 5}, {6, 3}, {0, 0}} {
		if _, err := svc.GenerateAuditRange(ctx, bad[0], bad[1]); err == nil {
			t.Fatalf("range %d-%d must be rejected", bad[0], bad[1])
		}
	}
	// A range past the end of the log has nothing to preserve.
	if _, err := svc.GenerateAuditRange(ctx, 100, 200); err == nil {
		t.Fatal("an empty range must be an error, not an empty record")
	}
}

// TestResolveObjectsReproducesTheLeafBytes: hash-tree renewal and verification both
// re-derive an audit record's protected objects, so the reconstruction must be
// byte-identical to what generation hashed — and must refuse to guess when the log
// no longer holds the full range.
func TestResolveObjectsReproducesTheLeafBytes(t *testing.T) {
	h := newTSAHarness(t)
	store := newMemStore()
	store.appendN(6)
	svc := NewService(store, h.ts(), Options{Batch: 3})
	ctx := context.Background()
	if err := store.SetErsCursor(0); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GenerateAudit(ctx); err != nil {
		t.Fatalf("GenerateAudit: %v", err)
	}
	all, _ := store.ListAllEvidenceRecords()
	if len(all) == 0 {
		t.Fatal("no records generated")
	}
	rec := all[0]

	objs, err := svc.ResolveObjects(rec)
	if err != nil {
		t.Fatalf("ResolveObjects: %v", err)
	}
	if len(objs) != int(rec.LastSeq-rec.FirstSeq+1) {
		t.Fatalf("resolved %d objects for range %d-%d", len(objs), rec.FirstSeq, rec.LastSeq)
	}
	// The re-derived objects must satisfy the record's own proof.
	res, err := Verify(mustParse(t, rec.Record), VerifyOptions{Objects: objs, Roots: []*x509.Certificate{h.caCert}})
	if err != nil || !res.Valid {
		t.Fatalf("re-derived objects must verify: err=%v reason=%s", err, res.Reason)
	}
	// Resolution must be repeatable byte-for-byte.
	again, _ := svc.ResolveObjects(rec)
	for i := range objs {
		if objs[i].ID != again[i].ID || !bytes.Equal(objs[i].Bytes, again[i].Bytes) {
			t.Fatalf("object %d differs between resolutions", i)
		}
	}

	// A truncated log must be an error, never a short object list that would be
	// "verified" against a subset of what the record actually covers.
	wide := rec
	wide.LastSeq = 99
	if _, err := svc.ResolveObjects(wide); err == nil {
		t.Fatal("ResolveObjects must refuse a range the log no longer covers")
	}
	inverted := rec
	inverted.FirstSeq, inverted.LastSeq = 5, 2
	if _, err := svc.ResolveObjects(inverted); err == nil {
		t.Fatal("ResolveObjects must refuse an inverted seq range")
	}
	// A store failure must surface.
	fs := &flakyStore{memStore: store, listEvents: errors.New("read failed")}
	if _, err := NewService(fs, h.ts(), Options{}).ResolveObjects(rec); err == nil {
		t.Fatal("ResolveObjects must surface a store failure")
	}
}

// ---- cycle, metrics, runner -------------------------------------------------

// TestRunOnceAbsorbsFailures: the background cycle must never propagate an error
// (a transient outage would otherwise tear down the leader job), but it must also
// not report progress it did not make.
func TestRunOnceAbsorbsFailures(t *testing.T) {
	ctx := context.Background()
	store := newMemStore()
	store.appendN(3)
	if err := store.SetErsCursor(0); err != nil {
		t.Fatal(err)
	}
	var logged strings.Builder
	svc := NewService(store, &failingTimestamper{}, Options{
		Logf: func(f string, a ...any) { fmt.Fprintf(&logged, f+"\n", a...) },
	})
	svc.RunOnce(ctx, true) // must not panic and must not block
	if !strings.Contains(logged.String(), "FAILED") {
		t.Fatalf("a failed cycle must be logged: %q", logged.String())
	}
	if all, _ := store.ListAllEvidenceRecords(); len(all) != 0 {
		t.Fatalf("a failed cycle persisted %d records", len(all))
	}
	if cursor, _ := store.GetErsCursor(); cursor != 0 {
		t.Fatalf("a failed cycle advanced the cursor to %d", cursor)
	}

	// With a working TSA the same cycle succeeds and logs progress.
	h := newTSAHarness(t)
	logged.Reset()
	ok := NewService(store, h.ts(), Options{
		Logf: func(f string, a ...any) { fmt.Fprintf(&logged, f+"\n", a...) },
	})
	ok.RunOnce(ctx, true)
	if all, _ := store.ListAllEvidenceRecords(); len(all) != 1 {
		t.Fatalf("expected one record from the cycle, got %d", len(all))
	}
	if !strings.Contains(logged.String(), "cycle ok") {
		t.Fatalf("a successful cycle must be logged: %q", logged.String())
	}

	// preserveAudit=false must not generate, only renew.
	before, _ := store.ListAllEvidenceRecords()
	store.appendN(2)
	ok.RunOnce(ctx, false)
	after, _ := store.ListAllEvidenceRecords()
	if len(after) != len(before) {
		t.Fatalf("preserveAudit=false generated %d new records", len(after)-len(before))
	}
}

// TestSeedMetricsFromStore covers the restart path: the gauges are seeded from the
// persisted rows, an empty store is not an error, and a store failure surfaces so
// the caller can log it.
func TestSeedMetricsFromStore(t *testing.T) {
	h := newTSAHarness(t)
	store := newMemStore()
	svc := NewService(store, h.ts(), Options{})
	if err := svc.SeedMetrics(); err != nil {
		t.Fatalf("SeedMetrics on an empty store: %v", err)
	}

	store.appendN(2)
	if err := store.SetErsCursor(0); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GenerateAudit(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A renewed row must seed off its RenewedAt, which is newer than CreatedAt.
	all, _ := store.ListAllEvidenceRecords()
	renewedAt := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	all[0].RenewedAt = &renewedAt
	if err := store.UpdateEvidenceRecord(&all[0]); err != nil {
		t.Fatal(err)
	}
	if err := svc.SeedMetrics(); err != nil {
		t.Fatalf("SeedMetrics: %v", err)
	}

	boom := errors.New("cannot list")
	if err := NewService(&flakyStore{memStore: store, listPage: boom}, h.ts(), Options{}).SeedMetrics(); !errors.Is(err, boom) {
		t.Fatalf("SeedMetrics must surface a store failure, got %v", err)
	}
}

// TestRunnerDefaultsAndLifecycle: NewRunner fills in the interval and logger, Run
// performs one cycle immediately (not only on the first tick) and returns when the
// context is cancelled.
func TestRunnerDefaultsAndLifecycle(t *testing.T) {
	h := newTSAHarness(t)
	store := newMemStore()
	store.appendN(4)
	if err := store.SetErsCursor(0); err != nil {
		t.Fatal(err)
	}
	ts := newCountingTimestamper(h.ts())
	svc := NewService(store, ts, Options{Batch: 4})

	if r := NewRunner(svc, 0, true, nil); r.interval != DefaultInterval || r.logger == nil {
		t.Fatalf("NewRunner defaults: interval=%s logger=%v", r.interval, r.logger)
	}
	if r := NewRunner(svc, -time.Second, false, nil); r.interval != DefaultInterval {
		t.Fatalf("a negative interval must fall back to the default, got %s", r.interval)
	}
	if r := NewRunner(svc, 90*time.Minute, true, nil); r.interval != 90*time.Minute || !r.preserveAudit {
		t.Fatalf("NewRunner did not keep its arguments: %+v", r)
	}

	runner := NewRunner(svc, time.Hour, true, log.New(io.Discard, "", 0))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runner.Run(ctx); close(done) }()

	select {
	case <-ts.called:
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatal("Run did not perform a cycle before its first tick")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}

	if all, _ := store.ListAllEvidenceRecords(); len(all) == 0 {
		t.Fatal("the immediate cycle should have preserved the pending events")
	}
	if ts.count() == 0 {
		t.Fatal("the immediate cycle should have requested a timestamp")
	}
}

// TestRunnerKeepsCyclingOnEveryTick exercises the ticker branch of Run: the
// leader-elected preservation job must keep cycling after its immediate first pass,
// so a long-lived server does not silently stop preserving after boot.
func TestRunnerKeepsCyclingOnEveryTick(t *testing.T) {
	h := newTSAHarness(t)
	fs := &flakyStore{memStore: newMemStore()}
	runner := NewRunner(NewService(fs, h.ts(), Options{}), 2*time.Millisecond, true, log.New(io.Discard, "", 0))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { runner.Run(ctx); close(done) }()

	deadline := time.Now().Add(30 * time.Second)
	for fs.headReadCount() < 3 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("Run stopped cycling after %d passes", fs.headReadCount())
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

// ---- renewal decisioning ---------------------------------------------------

// TestRenewalDecisioning drives renewOne's two triggers independently: the
// deprecation predicate (hash-tree renewal) and the TSA-certificate lookahead
// (time-stamp renewal), plus the case where neither fires.
func TestRenewalDecisioning(t *testing.T) {
	h := newTSAHarness(t)
	ctx := context.Background()
	store := newMemStore()
	store.appendN(2)
	if err := store.SetErsCursor(0); err != nil {
		t.Fatal(err)
	}
	base := NewService(store, h.ts(), Options{Hash: crypto.SHA256})
	if _, err := base.GenerateAudit(ctx); err != nil {
		t.Fatal(err)
	}
	all, _ := store.ListAllEvidenceRecords()
	if len(all) != 1 {
		t.Fatalf("expected one record, got %d", len(all))
	}
	notAfter := *all[0].TSANotAfter

	// Nothing is due: the algorithm matches and the certificate is far from expiry.
	early := notAfter.AddDate(-5, 0, 0)
	quiet := NewService(store, h.ts(), Options{Hash: crypto.SHA256, RenewalLookahead: 24 * time.Hour})
	quiet.SetClock(func() time.Time { return early })
	h.setNow(early)
	renewed, pending, err := quiet.RenewAll(ctx)
	if err != nil || renewed != 0 || pending != 0 {
		t.Fatalf("no renewal should be due: renewed=%d pending=%d err=%v", renewed, pending, err)
	}
	if got, _ := store.ListAllEvidenceRecords(); got[0].RenewedAt != nil {
		t.Fatal("a record that was not due must not be marked renewed")
	}

	// A custom Deprecated predicate must drive hash-tree renewal even when the
	// service hash equals the record's current algorithm.
	deprecating := NewService(store, h.ts(), Options{
		Hash:       crypto.SHA256,
		Deprecated: func(hash crypto.Hash) bool { return hash == crypto.SHA256 },
	})
	deprecating.SetClock(func() time.Time { return early })
	renewed, pending, err = deprecating.RenewAll(ctx)
	if err != nil {
		t.Fatalf("RenewAll: %v", err)
	}
	if renewed != 1 || pending != 0 {
		t.Fatalf("the deprecation predicate should have renewed 1 record: renewed=%d pending=%d", renewed, pending)
	}
	got, _ := store.ListAllEvidenceRecords()
	if got[0].Chains != 2 {
		t.Fatalf("hash-tree renewal must add a chain, got %d", got[0].Chains)
	}
	if got[0].DigestAlg != "sha256" {
		t.Fatalf("a same-algorithm hash-tree renewal must stay on sha256, got %q", got[0].DigestAlg)
	}
	if got[0].RenewedAt == nil || !got[0].RenewedAt.Equal(early.UTC()) {
		t.Fatalf("RenewedAt = %v, want the injected clock %s", got[0].RenewedAt, early.UTC())
	}
	// It must still verify, and still cover every object, after the migration.
	if res := store.verifyRecord(t, got[0], []*x509.Certificate{h.caCert}, early); !res.Valid {
		t.Fatalf("record must verify after the same-algorithm renewal: %s", res.Reason)
	}

	// An artifact record cannot be reconstructed here, so it is reported pending
	// rather than renewed or failed.
	art, err := base.GenerateArtifact(ctx, "doc", objects("x"))
	if err != nil {
		t.Fatal(err)
	}
	onlyArtifact := newMemStore()
	if err := onlyArtifact.InsertEvidenceRecord(art); err != nil {
		t.Fatal(err)
	}
	pendingSvc := NewService(onlyArtifact, h.ts(), Options{
		Hash:       crypto.SHA256,
		Deprecated: func(crypto.Hash) bool { return true },
	})
	renewed, pending, err = pendingSvc.RenewAll(ctx)
	if err != nil {
		t.Fatalf("RenewAll: %v", err)
	}
	if renewed != 0 || pending != 1 {
		t.Fatalf("an artifact record due for hash-tree renewal must be pending: renewed=%d pending=%d", renewed, pending)
	}
	if rows, _ := onlyArtifact.ListAllEvidenceRecords(); rows[0].RenewedAt != nil {
		t.Fatal("a pending record must not be marked renewed")
	}
}

// TestRefreshRowKeepsCoverageMetadata: the renewal writeback must refresh the
// derived columns and must never rewrite the covered-object range, which is what
// resolveObjects keys off.
func TestRefreshRowKeepsCoverageMetadata(t *testing.T) {
	h := newTSAHarness(t)
	ctx := context.Background()
	gen := time.Date(2030, 4, 1, 0, 0, 0, 0, time.UTC)
	h.setNow(gen)
	er, err := Generate(ctx, h.ts(), GenerateOptions{Objects: objects("a", "b")})
	if err != nil {
		t.Fatal(err)
	}
	rec := &models.EvidenceRecord{
		ID: "r1", Scope: ScopeAudit, FirstSeq: 11, LastSeq: 20,
		ObjectIDs: []string{"event:11"}, DigestAlg: "sha256", Chains: 1,
		CreatedAt: gen,
	}
	later := gen.AddDate(1, 0, 0)
	h.setNow(later)
	renewed, err := er.RenewHashTree(ctx, h.ts(), objects("a", "b"), crypto.SHA512)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2031, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := RefreshRow(rec, renewed, at); err != nil {
		t.Fatalf("RefreshRow: %v", err)
	}
	if rec.FirstSeq != 11 || rec.LastSeq != 20 {
		t.Fatalf("RefreshRow rewrote the covered range to %d-%d", rec.FirstSeq, rec.LastSeq)
	}
	if len(rec.ObjectIDs) != 1 || rec.ObjectIDs[0] != "event:11" {
		t.Fatalf("RefreshRow rewrote the object ids: %v", rec.ObjectIDs)
	}
	if rec.Chains != 2 || rec.DigestAlg != "sha512" {
		t.Fatalf("chains=%d alg=%s, want 2/sha512", rec.Chains, rec.DigestAlg)
	}
	if !rec.LastGenTime.Equal(later) {
		t.Fatalf("last gen time = %s, want %s", rec.LastGenTime, later)
	}
	if rec.RenewedAt == nil || !rec.RenewedAt.Equal(at.UTC()) {
		t.Fatalf("renewed at = %v, want %s", rec.RenewedAt, at.UTC())
	}
	if rec.TSANotAfter == nil {
		t.Fatal("the TSA expiry must be refreshed")
	}
	// The written DER must be the renewed record, byte for byte.
	want, _ := renewed.Marshal()
	if !bytes.Equal(rec.Record, want) {
		t.Fatal("RefreshRow did not store the renewed DER")
	}
	if !rec.CreatedAt.Equal(gen) {
		t.Fatal("RefreshRow must not move CreatedAt")
	}
}

// TestGenerationAndRenewalInputValidation: every entry point must refuse an
// impossible request outright. Accepting one would mint a record that can never
// be verified, or lose the linkage a renewal is supposed to extend.
func TestGenerationAndRenewalInputValidation(t *testing.T) {
	h := newTSAHarness(t)
	ctx := context.Background()
	er, err := Generate(ctx, h.ts(), GenerateOptions{Objects: objects("a")})
	if err != nil {
		t.Fatal(err)
	}
	var unsupported *UnsupportedHashError

	if _, err := Generate(ctx, h.ts(), GenerateOptions{}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("Generate with no objects = %v, want ErrEmpty", err)
	}
	if _, err := Generate(ctx, h.ts(), GenerateOptions{Objects: objects("a"), Hash: crypto.Hash(200)}); !errors.As(err, &unsupported) {
		t.Fatalf("Generate with an unavailable hash = %v, want UnsupportedHashError", err)
	}
	if _, err := er.RenewHashTree(ctx, h.ts(), nil, crypto.SHA512); !errors.Is(err, ErrEmpty) {
		t.Fatalf("RenewHashTree with no objects = %v, want ErrEmpty", err)
	}
	for _, bad := range []crypto.Hash{0, crypto.Hash(200)} {
		if _, err := er.RenewHashTree(ctx, h.ts(), objects("a"), bad); !errors.As(err, &unsupported) {
			t.Fatalf("RenewHashTree to %v = %v, want UnsupportedHashError", bad, err)
		}
	}

	empty := &EvidenceRecord{wire: evidenceRecord{Version: Version}}
	if _, err := empty.RenewHashTree(ctx, h.ts(), objects("a"), crypto.SHA512); !errors.Is(err, ErrNoTimestamp) {
		t.Fatalf("RenewHashTree on an empty record = %v, want ErrNoTimestamp", err)
	}
	emptyChain := &EvidenceRecord{wire: evidenceRecord{
		Version: Version, ArchiveTimeStampSequence: []archiveTimeStampChain{{}},
	}}
	if _, err := emptyChain.RenewTimestamp(ctx, h.ts()); !errors.Is(err, ErrNoTimestamp) {
		t.Fatalf("RenewTimestamp on an empty chain = %v, want ErrNoTimestamp", err)
	}
	noToken := &EvidenceRecord{wire: evidenceRecord{
		Version:                  Version,
		ArchiveTimeStampSequence: []archiveTimeStampChain{{{DigestAlgorithm: pkixAlg(oidSHA256)}}},
	}}
	if _, err := noToken.RenewTimestamp(ctx, h.ts()); !errors.Is(err, ErrNoTimestamp) {
		t.Fatalf("RenewTimestamp with no embedded token = %v, want ErrNoTimestamp", err)
	}
	badAlgChain := &EvidenceRecord{wire: evidenceRecord{
		Version: Version,
		ArchiveTimeStampSequence: []archiveTimeStampChain{{{
			DigestAlgorithm: pkixAlg(oidSHA1),
			TimeStamp:       asn1RawGarbage(),
		}}},
	}}
	if _, err := badAlgChain.RenewTimestamp(ctx, h.ts()); err == nil {
		t.Fatal("RenewTimestamp must refuse a chain whose algorithm it cannot recompute")
	}
}

// TestRenewalWritebackFailureSurfaces: a renewal that cannot be persisted must be
// reported as a failure, never as a completed renewal — otherwise the in-memory
// (renewed) and stored (stale) records diverge silently.
func TestRenewalWritebackFailureSurfaces(t *testing.T) {
	h := newTSAHarness(t)
	ctx := context.Background()
	mem := newMemStore()
	mem.appendN(2)
	if err := mem.SetErsCursor(0); err != nil {
		t.Fatal(err)
	}
	if _, err := NewService(mem, h.ts(), Options{}).GenerateAudit(ctx); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("write failed")
	fs := &flakyStore{memStore: mem, update: boom}
	var logged strings.Builder
	svc := NewService(fs, h.ts(), Options{
		Deprecated: func(crypto.Hash) bool { return true },
		Logf:       func(f string, a ...any) { fmt.Fprintf(&logged, f+"\n", a...) },
	})
	renewed, pending, err := svc.RenewAll(ctx)
	if err != nil {
		t.Fatalf("RenewAll must absorb a per-record failure: %v", err)
	}
	if renewed != 0 || pending != 1 {
		t.Fatalf("renewed=%d pending=%d, want 0/1", renewed, pending)
	}
	if !strings.Contains(logged.String(), "write failed") {
		t.Fatalf("the writeback failure must be logged: %q", logged.String())
	}
	if rows, _ := mem.ListAllEvidenceRecords(); rows[0].RenewedAt != nil || rows[0].Chains != 1 {
		t.Fatalf("the stored row must be untouched: chains=%d renewedAt=%v", rows[0].Chains, rows[0].RenewedAt)
	}
}

// TestTimestampRenewalNotScheduledWithoutATSACertificate: the lookahead trigger
// keys off the embedded TSA certificate's expiry. When it cannot be read the
// renewal must NOT fire (there is no expiry to race), rather than fire every cycle.
func TestTimestampRenewalNotScheduledWithoutATSACertificate(t *testing.T) {
	h := newTSAHarness(t)
	er, err := Generate(context.Background(), h.ts(), GenerateOptions{Objects: objects("a")})
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(newMemStore(), h.ts(), Options{RenewalLookahead: time.Hour})
	if !svc.needsTimestampRenewal(er, time.Now().AddDate(100, 0, 0)) {
		t.Fatal("a long-past expiry must schedule a time-stamp renewal")
	}
	if svc.needsTimestampRenewal(er, time.Now().AddDate(-100, 0, 0)) {
		t.Fatal("an expiry a century away must not schedule a renewal")
	}
	unreadable := rebuild(er, func(seq []archiveTimeStampChain) {
		seq[0][0].TimeStamp = asn1RawGarbage()
	})
	if _, ok := unreadable.LatestSignerNotAfter(); ok {
		t.Fatal("an unparseable token must not yield a TSA expiry")
	}
	if svc.needsTimestampRenewal(unreadable, time.Now().AddDate(100, 0, 0)) {
		t.Fatal("a record with no readable TSA certificate must not be scheduled for renewal")
	}
}

// ---- Info ------------------------------------------------------------------

// TestInfoSummary covers the inspection surface used by `secsy-ca ers show`.
func TestInfoSummary(t *testing.T) {
	h := newTSAHarness(t)
	ctx := context.Background()
	t0 := time.Date(2030, 8, 1, 0, 0, 0, 0, time.UTC)
	h.setNow(t0)
	er, err := Generate(ctx, h.ts(), GenerateOptions{Objects: objects("a", "b")})
	if err != nil {
		t.Fatal(err)
	}
	t1 := t0.AddDate(0, 1, 0)
	h.setNow(t1)
	er, err = er.RenewTimestamp(ctx, h.ts())
	if err != nil {
		t.Fatal(err)
	}
	t2 := t0.AddDate(0, 2, 0)
	h.setNow(t2)
	er, err = er.RenewHashTree(ctx, h.ts(), objects("a", "b"), crypto.SHA512)
	if err != nil {
		t.Fatal(err)
	}

	info := er.Info()
	if info.Version != Version || info.Chains != 2 {
		t.Fatalf("version=%d chains=%d, want 1/2", info.Version, info.Chains)
	}
	if len(info.Timestamps) != 3 {
		t.Fatalf("expected 3 timestamps (2 in chain 0, 1 in chain 1), got %d", len(info.Timestamps))
	}
	if info.CurrentHash != "sha512" {
		t.Fatalf("current hash = %q, want sha512", info.CurrentHash)
	}
	wantAlgs := map[string]bool{"sha256": true, "sha512": true}
	if len(info.DigestAlgorithms) != 2 {
		t.Fatalf("digest algorithms = %v", info.DigestAlgorithms)
	}
	for _, a := range info.DigestAlgorithms {
		if !wantAlgs[a] {
			t.Fatalf("unexpected digest algorithm %q in %v", a, info.DigestAlgorithms)
		}
	}
	if !info.FirstGenTime.Equal(t0) || !info.LatestGenTime.Equal(t2) {
		t.Fatalf("gen-time span = %s..%s, want %s..%s", info.FirstGenTime, info.LatestGenTime, t0, t2)
	}
	want := []struct {
		chain, index int
		hash         string
		gen          time.Time
	}{{0, 0, "sha256", t0}, {0, 1, "sha256", t1}, {1, 0, "sha512", t2}}
	for i, w := range want {
		ti := info.Timestamps[i]
		if ti.Chain != w.chain || ti.Index != w.index || ti.Hash != w.hash || !ti.GenTime.Equal(w.gen) {
			t.Fatalf("timestamp %d = %+v, want chain %d index %d %s %s", i, ti, w.chain, w.index, w.hash, w.gen)
		}
		if !strings.Contains(ti.TSASubject, "ERS Test TSA") {
			t.Fatalf("timestamp %d TSA subject = %q", i, ti.TSASubject)
		}
		if ti.TSANotAfter.IsZero() {
			t.Fatalf("timestamp %d has no TSA expiry", i)
		}
	}

	// Info is best-effort per token: an unparseable token still appears, with the
	// fields that could be read, instead of aborting the whole summary.
	broken := rebuild(er, func(seq []archiveTimeStampChain) {
		seq[1][0].TimeStamp = asn1RawGarbage()
	})
	bi := broken.Info()
	if len(bi.Timestamps) != 3 {
		t.Fatalf("a broken token must not drop entries: %d", len(bi.Timestamps))
	}
	if !bi.Timestamps[2].GenTime.IsZero() || bi.Timestamps[2].TSASubject != "" {
		t.Fatalf("the unparseable token should report no genTime/subject: %+v", bi.Timestamps[2])
	}
	if bi.Timestamps[2].Hash != "sha512" {
		t.Fatalf("the chain algorithm is still known: %q", bi.Timestamps[2].Hash)
	}

	// An unknown digest-algorithm OID is rendered as the dotted OID, not dropped.
	odd := rebuild(er, func(seq []archiveTimeStampChain) {})
	odd.wire.DigestAlgorithms = append(odd.wire.DigestAlgorithms, pkixAlg(oidSHA1))
	if got := odd.Info().DigestAlgorithms; len(got) != 3 || got[2] != oidSHA1.String() {
		t.Fatalf("unknown algorithm rendering = %v", got)
	}
}

// ---- Timestampers ----------------------------------------------------------

// fakeAuthority stands in for *tsa.Authority so the two failure modes of the
// in-process path — an internal error and a protocol rejection — can be forced.
type fakeAuthority struct {
	res *tsa.Result
	err error
}

func (f fakeAuthority) Stamp(context.Context, []byte) (*tsa.Result, error) { return f.res, f.err }

func TestAuthorityTimestamperFailureModes(t *testing.T) {
	ctx := context.Background()
	digest := sha256.Sum256([]byte("root"))

	internal := NewAuthorityTimestamper(fakeAuthority{err: errors.New("signer unavailable")})
	if _, _, err := internal.Timestamp(ctx, crypto.SHA256, digest[:]); err == nil ||
		!strings.Contains(err.Error(), "internal TSA") {
		t.Fatalf("an internal TSA error must surface: %v", err)
	}
	if internal.Source() != "" {
		t.Fatalf("the in-process source label must be empty, got %q", internal.Source())
	}

	rejected := NewAuthorityTimestamper(fakeAuthority{res: &tsa.Result{Granted: false, Detail: "badAlg"}})
	_, _, err := rejected.Timestamp(ctx, crypto.SHA256, digest[:])
	if err == nil || !strings.Contains(err.Error(), "rejected") || !strings.Contains(err.Error(), "badAlg") {
		t.Fatalf("a protocol rejection must surface with its detail: %v", err)
	}

	// A granted response carrying garbage must not be handed back as a token.
	garbage := NewAuthorityTimestamper(fakeAuthority{res: &tsa.Result{Granted: true, Response: []byte{0x30, 0x00}}})
	if tok, _, err := garbage.Timestamp(ctx, crypto.SHA256, digest[:]); err == nil {
		t.Fatalf("a malformed response must be refused, got %d token bytes", len(tok))
	}
}

// TestTimestamperValidatesItsRequest: the shared fetcher must reject an impossible
// request before any transport happens, so a caller bug cannot end up stored as a
// token over the wrong digest.
func TestTimestamperValidatesItsRequest(t *testing.T) {
	ctx := context.Background()
	reached := false
	f := &tokenFetcher{source: "unit", roundTrip: func(context.Context, []byte) ([]byte, error) {
		reached = true
		return nil, errors.New("should not be reached")
	}}

	var unsupported *UnsupportedHashError
	if _, _, err := f.Timestamp(ctx, crypto.Hash(200), make([]byte, 32)); !errors.As(err, &unsupported) {
		t.Fatalf("an unavailable hash must give UnsupportedHashError, got %v", err)
	}
	for _, size := range []int{0, 31, 33, 64} {
		if _, _, err := f.Timestamp(ctx, crypto.SHA256, make([]byte, size)); err == nil {
			t.Fatalf("a %d-byte SHA-256 root must be refused", size)
		}
	}
	if reached {
		t.Fatal("a rejected request must not reach the transport")
	}
	if f.Source() != "unit" {
		t.Fatalf("Source() = %q", f.Source())
	}
}

// TestHTTPTimestamper drives the external-TSA transport against a loopback server:
// the happy path, then each way a hostile or broken TSA can answer. Every one must
// be refused rather than stored as evidence.
func TestHTTPTimestamper(t *testing.T) {
	h := newTSAHarness(t)
	gen := time.Date(2030, 9, 9, 9, 0, 0, 0, time.UTC)
	h.setNow(gen)
	ctx := context.Background()

	// mode switches the handler's behaviour per subtest.
	var mode string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch mode {
		case "ok":
			if ct := r.Header.Get("Content-Type"); ct != "application/timestamp-query" {
				http.Error(w, "content type "+ct, http.StatusUnsupportedMediaType)
				return
			}
			res, err := h.authority.Stamp(r.Context(), body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(res.Response)
		case "status":
			http.Error(w, "nope", http.StatusServiceUnavailable)
		case "garbage":
			w.Write([]byte("not a TimeStampResp"))
		case "oversize":
			w.Write(bytes.Repeat([]byte{0x41}, maxTSAResponseBytes+16))
		case "otherdigest":
			// A token over a digest the client never submitted.
			other := sha256.Sum256([]byte("some other data"))
			req, err := tsa.MakeRequest(crypto.SHA256, other[:], &tsa.RequestOptions{Nonce: big.NewInt(99), CertReq: true})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			res, _ := h.authority.Stamp(r.Context(), req)
			w.Write(res.Response)
		case "othernonce":
			// The right digest, but a nonce the client never sent: a replayed or
			// substituted response.
			parsed, err := tsa.ParseRequest(body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			req, err := tsa.MakeRequest(parsed.Hash, parsed.Digest, &tsa.RequestOptions{Nonce: big.NewInt(1234567), CertReq: true})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			res, _ := h.authority.Stamp(r.Context(), req)
			w.Write(res.Response)
		case "wronghash":
			// A SHA-256 token where SHA-512 was requested.
			parsed, err := tsa.ParseRequest(body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			short := sha256.Sum256(parsed.Digest)
			req, err := tsa.MakeRequest(crypto.SHA256, short[:], &tsa.RequestOptions{Nonce: big.NewInt(7), CertReq: true})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			res, _ := h.authority.Stamp(r.Context(), req)
			w.Write(res.Response)
		default:
			http.Error(w, "unknown mode "+mode, http.StatusInternalServerError)
		}
	}))
	defer srv.Close()

	ts := NewHTTPTimestamper(srv.URL, 10*time.Second)
	if ts.Source() != srv.URL {
		t.Fatalf("Source() = %q, want the TSA URL", ts.Source())
	}

	// Happy path, at each supported imprint hash. An Evidence Record's imprint hash
	// tracks the chain algorithm, so SHA-384/512 must work too.
	mode = "ok"
	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		root := leafHash(hash, []byte("group root"))
		token, genTime, err := ts.Timestamp(ctx, hash, root)
		if err != nil {
			t.Fatalf("%v: Timestamp over HTTP: %v", hash, err)
		}
		info, err := tsa.ParseTokenInfo(token)
		if err != nil {
			t.Fatalf("%v: ParseTokenInfo: %v", hash, err)
		}
		if info.Hash != hash {
			t.Fatalf("token imprint hash = %v, want %v", info.Hash, hash)
		}
		if !bytes.Equal(info.HashedMessage, root) {
			t.Fatalf("%v: token does not cover the submitted root", hash)
		}
		if !genTime.Equal(gen) {
			t.Fatalf("%v: genTime = %s, want %s", hash, genTime, gen)
		}
	}

	root := leafHash(crypto.SHA256, []byte("group root"))
	badModes := []struct {
		mode string
		hash crypto.Hash
		want string
	}{
		{"status", crypto.SHA256, "HTTP 503"},
		{"garbage", crypto.SHA256, "ers:"},
		{"oversize", crypto.SHA256, "exceeds"},
		{"otherdigest", crypto.SHA256, "does not cover the submitted root"},
		{"othernonce", crypto.SHA256, "does not echo the request nonce"},
		{"wronghash", crypto.SHA512, "does not match the requested"},
	}
	for _, bm := range badModes {
		t.Run(bm.mode, func(t *testing.T) {
			mode = bm.mode
			digest := root
			if bm.hash != crypto.SHA256 {
				digest = leafHash(bm.hash, []byte("group root"))
			}
			token, _, err := ts.Timestamp(ctx, bm.hash, digest)
			if err == nil {
				t.Fatalf("mode %q must be refused, got %d token bytes", bm.mode, len(token))
			}
			if !strings.Contains(err.Error(), bm.want) {
				t.Fatalf("mode %q error = %v, want it to mention %q", bm.mode, err, bm.want)
			}
			if token != nil {
				t.Fatal("a refused request must not return a token")
			}
		})
	}

	// A cancelled context must fail, not hang.
	mode = "ok"
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := ts.Timestamp(cancelled, crypto.SHA256, root); err == nil {
		t.Fatal("a cancelled context must fail the request")
	}

	// An unreachable TSA must surface as an error naming the URL.
	dead := NewHTTPTimestamper("http://127.0.0.1:1/tsa", 0) // timeout <= 0 takes the default
	if _, _, err := dead.Timestamp(ctx, crypto.SHA256, root); err == nil ||
		!strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("an unreachable TSA must surface with its URL: %v", err)
	}
}

// ---- small helpers ---------------------------------------------------------

// asn1RawGarbage is a well-formed DER SEQUENCE that is not a TimeStampToken, used
// to make a token unparseable without breaking the record's DER.
func asn1RawGarbage() asn1.RawValue {
	return asn1.RawValue{FullBytes: []byte{0x30, 0x03, 0x02, 0x01, 0x00}}
}

func pkixAlg(oid asn1.ObjectIdentifier) pkix.AlgorithmIdentifier {
	return pkix.AlgorithmIdentifier{Algorithm: oid}
}
