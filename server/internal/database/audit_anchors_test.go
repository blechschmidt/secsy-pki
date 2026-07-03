//go:build sqlite

package database

import (
	"bytes"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

func anchorTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestAuditAnchorRoundTrip covers insert, ascending listing, and the latest
// lookup, including that the DER token bytes survive the store untouched.
func TestAuditAnchorRoundTrip(t *testing.T) {
	db := anchorTestDB(t)

	if latest, err := db.LatestAuditAnchor(); err != nil || latest != nil {
		t.Fatalf("empty store: latest = %v, %v; want nil, nil", latest, err)
	}

	token1 := []byte{0x30, 0x82, 0x01, 0x00, 0xde, 0xad}
	a1 := &audit.Anchor{
		ID: "a1", Seq: 3, HeadHash: "ABCDEF0123", Token: token1,
		GenTime:   time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
		CreatedAt: time.Date(2026, 7, 1, 12, 0, 1, 0, time.UTC),
	}
	if err := db.InsertAuditAnchor(a1); err != nil {
		t.Fatalf("InsertAuditAnchor: %v", err)
	}
	a2 := &audit.Anchor{
		ID: "a2", Seq: 7, HeadHash: "1234abcd", Token: []byte{0x01},
		TSASource: "https://tsa.example/tsa",
		GenTime:   time.Date(2026, 7, 2, 12, 0, 0, 0, time.UTC),
		CreatedAt: time.Date(2026, 7, 2, 12, 0, 1, 0, time.UTC),
	}
	if err := db.InsertAuditAnchor(a2); err != nil {
		t.Fatalf("InsertAuditAnchor: %v", err)
	}

	anchors, err := db.ListAuditAnchorsAsc()
	if err != nil {
		t.Fatalf("ListAuditAnchorsAsc: %v", err)
	}
	if len(anchors) != 2 || anchors[0].ID != "a1" || anchors[1].ID != "a2" {
		t.Fatalf("listing order wrong: %+v", anchors)
	}
	// The head hash is canonicalized to lowercase on insert.
	if anchors[0].HeadHash != "abcdef0123" {
		t.Errorf("head hash not lowercased: %q", anchors[0].HeadHash)
	}
	if !bytes.Equal(anchors[0].Token, token1) {
		t.Errorf("token bytes mutated: got %x want %x", anchors[0].Token, token1)
	}
	if anchors[0].TSASource != "" || anchors[1].TSASource != "https://tsa.example/tsa" {
		t.Errorf("tsa sources wrong: %q, %q", anchors[0].TSASource, anchors[1].TSASource)
	}
	if !anchors[1].GenTime.Equal(a2.GenTime) || !anchors[1].CreatedAt.Equal(a2.CreatedAt) {
		t.Errorf("timestamps did not round-trip: %v / %v", anchors[1].GenTime, anchors[1].CreatedAt)
	}

	latest, err := db.LatestAuditAnchor()
	if err != nil {
		t.Fatalf("LatestAuditAnchor: %v", err)
	}
	if latest == nil || latest.ID != "a2" {
		t.Fatalf("latest = %+v; want a2", latest)
	}
}

// TestEventLogHead verifies the head lookup returns the newest entry's
// (seq, hash, action) and zero values on an empty log.
func TestEventLogHead(t *testing.T) {
	db := anchorTestDB(t)

	seq, hash, action, err := db.EventLogHead()
	if err != nil || seq != 0 || hash != "" || action != "" {
		t.Fatalf("empty log head = (%d, %q, %q, %v); want zeros", seq, hash, action, err)
	}

	for i, act := range []string{audit.ActionCertIssue, audit.ActionCertRevoke} {
		e := &audit.Event{ID: "e", Actor: "alice", Action: act, Result: audit.ResultSuccess}
		if err := db.AppendEvent(e); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	seq, hash, action, err = db.EventLogHead()
	if err != nil {
		t.Fatalf("EventLogHead: %v", err)
	}
	if seq != 2 || action != audit.ActionCertRevoke {
		t.Fatalf("head = (%d, %q); want (2, cert.revoke)", seq, action)
	}
	events, err := db.ListAllEventsAsc()
	if err != nil {
		t.Fatal(err)
	}
	if hash != events[1].Hash {
		t.Fatalf("head hash %q does not match stored tail hash %q", hash, events[1].Hash)
	}
}
