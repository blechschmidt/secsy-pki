//go:build sqlite

package database

import (
	"fmt"
	"sync"
	"testing"

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
