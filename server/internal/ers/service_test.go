package ers

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// memStore is an in-memory Store for exercising the preservation service without
// a database. Events are contiguous and immutable once appended, so re-deriving
// an audit record's objects reproduces identical bytes.
type memStore struct {
	mu      sync.Mutex
	events  []audit.Event
	records map[string]*models.EvidenceRecord
	order   []string
	cursor  int64
	curInit bool
}

func newMemStore() *memStore {
	return &memStore{records: map[string]*models.EvidenceRecord{}}
}

func (m *memStore) appendN(n int) {
	for i := 0; i < n; i++ {
		_ = m.AppendEvent(&audit.Event{
			ID:     fmt.Sprintf("evt-%d", len(m.events)+1),
			Actor:  "alice",
			Action: audit.ActionCertIssue,
			Result: audit.ResultSuccess,
			Detail: fmt.Sprintf("cert %d", len(m.events)+1),
		})
	}
}

func (m *memStore) AppendEvent(e *audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	seq := int64(len(m.events) + 1)
	ev := *e
	ev.Seq = seq
	ev.Timestamp = time.Date(2026, 1, 1, 0, 0, int(seq), 0, time.UTC)
	ev.PrevHash = fmt.Sprintf("prev-%d", seq-1)
	ev.Hash = fmt.Sprintf("hash-%d", seq)
	m.events = append(m.events, ev)
	return nil
}

func (m *memStore) MaxEventSeq() (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return int64(len(m.events)), nil
}

func (m *memStore) GetErsCursor() (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cursor, nil
}

func (m *memStore) ErsCursorInitialized() (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.curInit, nil
}

func (m *memStore) SetErsCursor(seq int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cursor = seq
	m.curInit = true
	return nil
}

func (m *memStore) ListEventsSince(afterSeq int64, limit int) ([]audit.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []audit.Event
	for _, e := range m.events {
		if e.Seq > afterSeq {
			out = append(out, e)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (m *memStore) InsertEvidenceRecord(r *models.EvidenceRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *r
	m.records[r.ID] = &cp
	m.order = append(m.order, r.ID)
	return nil
}

func (m *memStore) UpdateEvidenceRecord(r *models.EvidenceRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *r
	m.records[r.ID] = &cp
	return nil
}

func (m *memStore) ListAllEvidenceRecords() ([]models.EvidenceRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]models.EvidenceRecord, 0, len(m.order))
	for _, id := range m.order {
		out = append(out, *m.records[id])
	}
	return out, nil
}

func (m *memStore) ListEvidenceRecords(limit, offset int) ([]models.EvidenceRecord, int, error) {
	all, _ := m.ListAllEvidenceRecords()
	return all, len(all), nil
}

// verifyRecord re-derives an audit record's objects and verifies it.
func (m *memStore) verifyRecord(t *testing.T, rec models.EvidenceRecord, roots []*x509.Certificate, now time.Time) *VerifyResult {
	t.Helper()
	er, err := Parse(rec.Record)
	if err != nil {
		t.Fatalf("parse record %s: %v", rec.ID, err)
	}
	events, _ := m.ListEventsSince(rec.FirstSeq-1, int(rec.LastSeq-rec.FirstSeq+1))
	var objs []DataObject
	for _, e := range events {
		if e.Seq >= rec.FirstSeq && e.Seq <= rec.LastSeq {
			objs = append(objs, DataObject{ID: eventObjectID(e.Seq), Bytes: auditObjectBytes(e)})
		}
	}
	res, err := Verify(er, VerifyOptions{Objects: objs, Roots: roots, Now: now})
	if err != nil {
		t.Fatalf("verify record %s: %v", rec.ID, err)
	}
	return res
}

// TestServicePreserveAndRenew drives the full leader-job logic on an in-memory
// store: cursor-tracked generation over audit batches, then time-stamp renewal
// and hash-tree renewal as the clock advances, with every record re-verified
// after each step by re-deriving its audit objects.
func TestServicePreserveAndRenew(t *testing.T) {
	h := newTSAHarness(t)
	roots := []*x509.Certificate{h.caCert}
	store := newMemStore()
	ctx := context.Background()

	// First enablement seeds the cursor at the current (empty) head; no records.
	svc := NewService(store, h.ts(), Options{Hash: crypto.SHA256, Batch: 3})
	if n, err := svc.GenerateAudit(ctx); err != nil || n != 0 {
		t.Fatalf("first GenerateAudit on empty log: n=%d err=%v", n, err)
	}

	// Append 7 events → batches of 3,3,1 → 3 records.
	store.appendN(7)
	t0 := time.Date(2028, 3, 1, 0, 0, 0, 0, time.UTC)
	h.setNow(t0)
	svc.SetClock(func() time.Time { return t0 })
	n, err := svc.GenerateAudit(ctx)
	if err != nil {
		t.Fatalf("GenerateAudit: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 records for 7 events at batch 3, got %d", n)
	}
	all, _ := store.ListAllEvidenceRecords()
	if len(all) != 3 {
		t.Fatalf("store should hold 3 records, got %d", len(all))
	}
	for _, rec := range all {
		if rec.Scope != ScopeAudit || rec.DigestAlg != "sha256" {
			t.Fatalf("unexpected record: %+v", rec)
		}
		res := store.verifyRecord(t, rec, roots, t0)
		if !res.Valid {
			t.Fatalf("fresh record %s should verify: %s", rec.ID, res.Reason)
		}
	}

	// --- time-stamp renewal: jump the clock to within the lookahead of the TSA
	// certificate expiry. RenewAll must re-stamp every record within one chain.
	notAfter, ok := mustParse(t, all[0].Record).LatestSignerNotAfter()
	if !ok {
		t.Fatal("record should carry a TSA cert expiry")
	}
	tRenew := notAfter.Add(-5 * 24 * time.Hour)
	h.setNow(tRenew)
	svc.SetClock(func() time.Time { return tRenew })
	renewed, pending, err := svc.RenewAll(ctx)
	if err != nil {
		t.Fatalf("RenewAll (timestamp): %v", err)
	}
	if renewed != 3 || pending != 0 {
		t.Fatalf("time-stamp renewal: renewed=%d pending=%d, want 3/0", renewed, pending)
	}
	all, _ = store.ListAllEvidenceRecords()
	for _, rec := range all {
		if rec.Chains != 1 {
			t.Fatalf("time-stamp renewal must stay in one chain, record %s has %d", rec.ID, rec.Chains)
		}
		if rec.RenewedAt == nil {
			t.Fatalf("record %s should be marked renewed", rec.ID)
		}
		if res := store.verifyRecord(t, rec, roots, tRenew); !res.Valid {
			t.Fatalf("record %s should verify after time-stamp renewal: %s", rec.ID, res.Reason)
		}
	}

	// --- hash-tree renewal: a service targeting SHA-512 sees the SHA-256 records
	// as weaker-than-target and migrates each into a new chain.
	tHash := notAfter.Add(-3 * 24 * time.Hour)
	h.setNow(tHash)
	svc512 := NewService(store, h.ts(), Options{Hash: crypto.SHA512})
	svc512.SetClock(func() time.Time { return tHash })
	renewed, pending, err = svc512.RenewAll(ctx)
	if err != nil {
		t.Fatalf("RenewAll (hashtree): %v", err)
	}
	if renewed != 3 || pending != 0 {
		t.Fatalf("hash-tree renewal: renewed=%d pending=%d, want 3/0", renewed, pending)
	}
	all, _ = store.ListAllEvidenceRecords()
	for _, rec := range all {
		if rec.Chains != 2 || rec.DigestAlg != "sha512" {
			t.Fatalf("hash-tree renewal: record %s chains=%d alg=%s, want 2/sha512", rec.ID, rec.Chains, rec.DigestAlg)
		}
		res := store.verifyRecord(t, rec, roots, tHash)
		if !res.Valid {
			t.Fatalf("record %s should verify after hash-tree renewal: %s", rec.ID, res.Reason)
		}
		for _, o := range res.Objects {
			if !o.Covered {
				t.Fatalf("object %q must remain covered across the algorithm transition", o.ID)
			}
		}
	}

	// A second pass at the SHA-512 target must NOT trigger another hash-tree
	// renewal: the algorithm already matches, so no new chain is added (a
	// time-stamp renewal may still fire because the clock is near the TSA cert's
	// expiry — that is correct, and it stays within the existing two chains).
	if _, _, err = svc512.RenewAll(ctx); err != nil {
		t.Fatalf("second RenewAll: %v", err)
	}
	all, _ = store.ListAllEvidenceRecords()
	for _, rec := range all {
		if rec.Chains != 2 {
			t.Fatalf("hash-tree renewal must not repeat: record %s now has %d chains", rec.ID, rec.Chains)
		}
	}
}

func mustParse(t *testing.T, der []byte) *EvidenceRecord {
	t.Helper()
	er, err := Parse(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return er
}
