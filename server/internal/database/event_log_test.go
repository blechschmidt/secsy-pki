//go:build sqlite

package database

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

func eventTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestAppendEventRequestID verifies the correlation request ID round-trips
// through the event log and that, because it is excluded from the hash
// canonicalization, it does not affect chain integrity.
func TestAppendEventRequestID(t *testing.T) {
	db := eventTestDB(t)

	e := &audit.Event{
		ID:        "evt-req",
		Actor:     "alice",
		Action:    audit.ActionCertIssue,
		Target:    "42",
		Result:    audit.ResultSuccess,
		RequestID: "req-xyz-789",
	}
	if err := db.AppendEvent(e); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}

	entries, _, err := db.ListEvents("", "", 10, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("ListEvents: %d %v", len(entries), err)
	}
	if entries[0].RequestID != "req-xyz-789" {
		t.Errorf("RequestID = %q, want req-xyz-789", entries[0].RequestID)
	}

	// The chain must still verify: request_id is not part of the hash, so its
	// presence does not perturb the stored hash relative to the recomputed one.
	res, err := db.VerifyEventChain()
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Errorf("chain invalid with request_id present: %+v", res)
	}
}

func TestAppendEventChains(t *testing.T) {
	db := eventTestDB(t)

	for i := 0; i < 5; i++ {
		e := &audit.Event{
			ID:     fmt.Sprintf("evt-%d", i),
			Actor:  "alice",
			Action: audit.ActionCertIssue,
			Target: fmt.Sprintf("%d", 100+i),
			Result: audit.ResultSuccess,
		}
		if err := db.AppendEvent(e); err != nil {
			t.Fatalf("AppendEvent %d: %v", i, err)
		}
		if e.Seq != int64(i+1) {
			t.Errorf("event %d Seq = %d, want %d", i, e.Seq, i+1)
		}
		if e.Hash == "" {
			t.Errorf("event %d has empty hash", i)
		}
	}

	// The persisted log verifies as an intact chain.
	res, err := db.VerifyEventChain()
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("freshly written chain is invalid: %+v", res)
	}
	if res.Count != 5 {
		t.Errorf("count = %d, want 5", res.Count)
	}

	// First entry anchors to the genesis; each entry links to its predecessor.
	events, err := db.ListAllEventsAsc()
	if err != nil {
		t.Fatal(err)
	}
	if events[0].PrevHash != audit.GenesisHash {
		t.Errorf("first prev_hash = %q, want genesis", events[0].PrevHash)
	}
	for i := 1; i < len(events); i++ {
		if events[i].PrevHash != events[i-1].Hash {
			t.Errorf("entry %d not linked to previous entry", i)
		}
	}
}

func TestVerifyDetectsRowTampering(t *testing.T) {
	db := eventTestDB(t)
	for i := 0; i < 3; i++ {
		if err := db.AppendEvent(&audit.Event{
			ID: fmt.Sprintf("e%d", i), Actor: "bob", Action: audit.ActionCertRevoke,
			Target: "42", Result: audit.ResultDenied,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Attacker edits a stored row in place (e.g. flips a denied action to
	// success) without being able to recompute downstream hashes.
	if _, err := db.exec(`UPDATE event_log SET result = ? WHERE seq = ?`, audit.ResultSuccess, 2); err != nil {
		t.Fatal(err)
	}

	res, err := db.VerifyEventChain()
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("row tampering was not detected by chain verification")
	}
	if res.BrokenAtSeq != 2 {
		t.Errorf("BrokenAtSeq = %d, want 2", res.BrokenAtSeq)
	}
}

func TestVerifyDetectsRowDeletion(t *testing.T) {
	db := eventTestDB(t)
	for i := 0; i < 4; i++ {
		if err := db.AppendEvent(&audit.Event{
			ID: fmt.Sprintf("e%d", i), Actor: "carol", Action: audit.ActionCACreate, Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// Delete a middle entry to hide it; the sequence becomes non-contiguous.
	if _, err := db.exec(`DELETE FROM event_log WHERE seq = ?`, 2); err != nil {
		t.Fatal(err)
	}

	res, err := db.VerifyEventChain()
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("row deletion (sequence gap) was not detected")
	}
}

// TestConcurrentAppendsProduceGapFreeChain ensures the eventMu + transactional
// last-hash read keeps the chain consistent under concurrent writers.
func TestConcurrentAppendsProduceGapFreeChain(t *testing.T) {
	db := eventTestDB(t)

	const n = 40
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- db.AppendEvent(&audit.Event{
				ID: fmt.Sprintf("c%d", i), Actor: "loadtest",
				Action: audit.ActionCertSignSSH, Result: audit.ResultSuccess,
			})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent AppendEvent: %v", err)
		}
	}

	res, err := db.VerifyEventChain()
	if err != nil {
		t.Fatal(err)
	}
	if !res.Valid {
		t.Fatalf("concurrent chain invalid: %+v", res)
	}
	if res.Count != n {
		t.Errorf("count = %d, want %d", res.Count, n)
	}

	// Sequence numbers must be exactly 1..n with no gaps or duplicates.
	events, err := db.ListAllEventsAsc()
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range events {
		if e.Seq != int64(i+1) {
			t.Fatalf("entry %d has Seq %d, want %d (gap or duplicate)", i, e.Seq, i+1)
		}
	}
}

// TestListEventsSinceAndCursor exercises the SIEM exporter's read path: forward
// streaming from a cursor with a bounded batch, the head sequence, and durable
// per-sink cursor persistence.
func TestListEventsSinceAndCursor(t *testing.T) {
	db := eventTestDB(t)
	for i := 0; i < 6; i++ {
		if err := db.AppendEvent(&audit.Event{
			ID: fmt.Sprintf("s%d", i), Actor: "alice", Action: audit.ActionCertIssue, Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatal(err)
		}
	}

	head, err := db.MaxEventSeq()
	if err != nil || head != 6 {
		t.Fatalf("MaxEventSeq = %d (%v), want 6", head, err)
	}

	// Bounded batch from the genesis.
	batch, err := db.ListEventsSince(0, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 4 || batch[0].Seq != 1 || batch[3].Seq != 4 {
		t.Fatalf("ListEventsSince(0,4) = %d events starting %d", len(batch), batch[0].Seq)
	}

	// Resume after seq 4.
	rest, err := db.ListEventsSince(4, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 2 || rest[0].Seq != 5 || rest[1].Seq != 6 {
		t.Fatalf("ListEventsSince(4,0) = %+v", rest)
	}

	// Cursor round-trips and defaults to 0 for an unknown sink.
	if c, err := db.GetSIEMCursor("splunk"); err != nil || c != 0 {
		t.Fatalf("initial cursor = %d (%v), want 0", c, err)
	}
	if err := db.SetSIEMCursor("splunk", 4); err != nil {
		t.Fatal(err)
	}
	if c, _ := db.GetSIEMCursor("splunk"); c != 4 {
		t.Errorf("cursor after set = %d, want 4", c)
	}
	// Upsert advances the same row.
	if err := db.SetSIEMCursor("splunk", 6); err != nil {
		t.Fatal(err)
	}
	if c, _ := db.GetSIEMCursor("splunk"); c != 6 {
		t.Errorf("cursor after second set = %d, want 6", c)
	}
	// A second sink keeps an independent cursor.
	if c, _ := db.GetSIEMCursor("elastic"); c != 0 {
		t.Errorf("independent sink cursor = %d, want 0", c)
	}
}

func TestListEventsByTimeRange(t *testing.T) {
	db := eventTestDB(t)
	base := time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if err := db.AppendEvent(&audit.Event{
			ID: fmt.Sprintf("t%d", i), Timestamp: base.Add(time.Duration(i) * time.Hour),
			Actor: "alice", Action: audit.ActionCertIssue, Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatal(err)
		}
	}

	// [base+1h, base+4h) selects events at +1h,+2h,+3h -> seqs 2,3,4.
	got, err := db.ListEventsByTimeRange(base.Add(time.Hour), base.Add(4*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0].Seq != 2 || got[2].Seq != 4 {
		t.Fatalf("time-range query = %d events %+v", len(got), seqs(got))
	}

	// Open-ended bounds select everything.
	all, err := db.ListEventsByTimeRange(time.Time{}, time.Time{})
	if err != nil || len(all) != 5 {
		t.Fatalf("open range = %d events (%v), want 5", len(all), err)
	}
}

func seqs(events []audit.Event) []int64 {
	out := make([]int64, len(events))
	for i, e := range events {
		out[i] = e.Seq
	}
	return out
}

func TestListEventsFilterAndPaging(t *testing.T) {
	db := eventTestDB(t)
	actions := []string{audit.ActionCertIssue, audit.ActionCertRevoke, audit.ActionCertIssue}
	for i, act := range actions {
		if err := db.AppendEvent(&audit.Event{
			ID: fmt.Sprintf("f%d", i), Actor: "dave", Action: act, Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatal(err)
		}
	}

	issues, total, err := db.ListEvents(audit.ActionCertIssue, "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Errorf("issue total = %d, want 2", total)
	}
	for _, e := range issues {
		if e.Action != audit.ActionCertIssue {
			t.Errorf("filter leaked action %q", e.Action)
		}
	}

	// Newest-first ordering.
	all, _, err := db.ListEvents("", "dave", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 3 || all[0].Seq != 3 {
		t.Errorf("expected newest-first, got %d entries head seq %d", len(all), all[0].Seq)
	}
}
