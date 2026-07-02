package audit

import (
	"testing"
	"time"
)

// buildChain seals a slice of events into a valid hash chain starting at the
// genesis, assigning sequence numbers 1..n.
func buildChain(events []Event) []Event {
	prev := GenesisHash
	for i := range events {
		Seal(&events[i], int64(i+1), prev)
		prev = events[i].Hash
	}
	return events
}

func sampleEvents() []Event {
	base := time.Date(2026, 7, 2, 10, 0, 0, 0, time.UTC)
	return []Event{
		{ID: "e1", Timestamp: base, Actor: "root", Action: ActionCAInitRoot, Target: "ca-1", Result: ResultSuccess},
		{ID: "e2", Timestamp: base.Add(time.Minute), Actor: "alice", ActorRoles: "issuer", Action: ActionCertIssue, Target: "42", Result: ResultSuccess},
		{ID: "e3", Timestamp: base.Add(2 * time.Minute), Actor: "bob", Action: ActionCertRevoke, Target: "42", Result: ResultDenied},
	}
}

func TestSealAndVerifyValidChain(t *testing.T) {
	chain := buildChain(sampleEvents())

	if chain[0].PrevHash != GenesisHash {
		t.Errorf("first entry prev_hash = %q, want genesis", chain[0].PrevHash)
	}
	for i := 1; i < len(chain); i++ {
		if chain[i].PrevHash != chain[i-1].Hash {
			t.Errorf("entry %d prev_hash not linked to previous entry hash", i)
		}
	}

	res := VerifyChain(chain)
	if !res.Valid {
		t.Fatalf("valid chain reported invalid: %+v", res)
	}
	if res.Count != 3 {
		t.Errorf("count = %d, want 3", res.Count)
	}
}

func TestVerifyDetectsContentTampering(t *testing.T) {
	chain := buildChain(sampleEvents())
	// Attacker flips a denied revoke into a success without recomputing hashes.
	chain[2].Result = ResultSuccess

	res := VerifyChain(chain)
	if res.Valid {
		t.Fatal("tampered content was not detected")
	}
	if res.BrokenAtSeq != 3 {
		t.Errorf("BrokenAtSeq = %d, want 3", res.BrokenAtSeq)
	}
}

func TestVerifyDetectsHashForgery(t *testing.T) {
	chain := buildChain(sampleEvents())
	// Attacker edits content AND recomputes that entry's own hash, but cannot
	// fix the forward links because every later hash depends on this one.
	chain[1].Actor = "mallory"
	chain[1].Hash = ComputeHash(&chain[1], chain[1].PrevHash)

	res := VerifyChain(chain)
	if res.Valid {
		t.Fatal("forgery propagating down the chain was not detected")
	}
	// Entry 2 now hashes fine on its own, but entry 3's prev_hash no longer
	// matches, so the break surfaces at seq 3.
	if res.BrokenAtSeq != 3 {
		t.Errorf("BrokenAtSeq = %d, want 3", res.BrokenAtSeq)
	}
}

func TestVerifyDetectsDeletion(t *testing.T) {
	chain := buildChain(sampleEvents())
	// Remove the middle entry to hide it; sequence numbers become non-contiguous.
	tampered := []Event{chain[0], chain[2]}

	res := VerifyChain(tampered)
	if res.Valid {
		t.Fatal("deleted entry (sequence gap) was not detected")
	}
}

func TestVerifyDetectsReordering(t *testing.T) {
	chain := buildChain(sampleEvents())
	reordered := []Event{chain[1], chain[0], chain[2]}

	res := VerifyChain(reordered)
	if res.Valid {
		t.Fatal("reordered entries were not detected")
	}
}

func TestVerifyEmptyChain(t *testing.T) {
	if res := VerifyChain(nil); !res.Valid {
		t.Errorf("empty chain should be valid, got %+v", res)
	}
}

// TestCanonicalNoFieldAmbiguity ensures length-prefixing prevents two distinct
// events from producing the same hash by shifting characters across a field
// boundary.
func TestCanonicalNoFieldAmbiguity(t *testing.T) {
	ts := time.Now().UTC()
	a := &Event{ID: "x", Timestamp: ts, Actor: "ab", Action: "c", Result: ResultSuccess}
	b := &Event{ID: "x", Timestamp: ts, Actor: "a", Action: "bc", Result: ResultSuccess}
	if ComputeHash(a, GenesisHash) == ComputeHash(b, GenesisHash) {
		t.Fatal("field boundary ambiguity: distinct events hash equal")
	}
}
