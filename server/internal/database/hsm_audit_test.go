//go:build sqlite

package database

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
)

func hsmAuditTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

const testAnchor = "369a47bf3d7353d627b7ce4e9c117fba"

func pinState(t *testing.T, db *DB) {
	t.Helper()
	err := db.SaveAuditState(context.Background(), &hsmaudit.AuditState{
		DeviceSerial:  "31650425",
		Anchor:        testAnchor,
		ProvisionedAt: time.Now().UTC(),
		Tail:          hsmaudit.Tail{Number: 1, Digest: testAnchor},
	})
	if err != nil {
		t.Fatalf("pinning audit state: %v", err)
	}
}

func TestAuditStateRoundTrip(t *testing.T) {
	db := hsmAuditTestDB(t)
	ctx := context.Background()

	if st, err := db.LoadAuditState(ctx); err != nil || st != nil {
		t.Fatalf("expected no state on a fresh store, got %v (err %v)", st, err)
	}
	pinState(t, db)

	st, err := db.LoadAuditState(ctx)
	if err != nil {
		t.Fatalf("loading state: %v", err)
	}
	if st.Anchor != testAnchor || st.DeviceSerial != "31650425" || st.Tail.Number != 1 {
		t.Fatalf("state did not round-trip: %+v", st)
	}
}

// The anchor is the root of trust for every export. Replacing it is how a
// fabricated history would be made to verify, so it must be refused.
func TestAuditStateRefusesToRePinAnchor(t *testing.T) {
	db := hsmAuditTestDB(t)
	pinState(t, db)

	err := db.SaveAuditState(context.Background(), &hsmaudit.AuditState{
		DeviceSerial:  "31650425",
		Anchor:        strings.Repeat("11", hsmaudit.DigestLen),
		ProvisionedAt: time.Now().UTC(),
	})
	if err == nil {
		t.Fatal("re-pinning the anchor with a different value was allowed")
	}
	if !strings.Contains(err.Error(), "refusing to re-pin") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func entry(number uint16, cmd uint8, target uint16, hash string) hsm.AuditLogEntry {
	return hsm.AuditLogEntry{
		Number: number, Command: cmd, Length: 64, SessionKey: 1,
		TargetKey: target, Result: cmd | 0x80, Tick: uint32(number) * 10, Hash: hash,
	}
}

func TestLogEntriesAreIdempotentByNumber(t *testing.T) {
	db := hsmAuditTestDB(t)
	ctx := context.Background()
	entries := []hsm.AuditLogEntry{
		entry(1, 0xff, 0xffff, testAnchor),
		entry(2, hsm.CmdSignECDSA, 0x6f42, strings.Repeat("aa", hsmaudit.DigestLen)),
	}
	if err := db.AppendLogEntries(ctx, entries); err != nil {
		t.Fatalf("first append: %v", err)
	}
	// Re-offering the same segment (the device re-delivers what it was not told
	// to forget) must be a no-op, not a duplicate.
	if err := db.AppendLogEntries(ctx, entries); err != nil {
		t.Fatalf("re-append: %v", err)
	}
	got, err := db.LogEntries(ctx)
	if err != nil {
		t.Fatalf("reading entries: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("stored %d entries after re-delivery, want 2", len(got))
	}
}

// The device log is immutable, so a re-delivery whose content differs from the
// stored copy means one of the two records is not genuine.
func TestLogEntriesRejectAlteredReDelivery(t *testing.T) {
	db := hsmAuditTestDB(t)
	ctx := context.Background()
	orig := entry(2, hsm.CmdSignECDSA, 0x6f42, strings.Repeat("aa", hsmaudit.DigestLen))
	if err := db.AppendLogEntries(ctx, []hsm.AuditLogEntry{orig}); err != nil {
		t.Fatalf("append: %v", err)
	}
	altered := orig
	altered.Hash = strings.Repeat("bb", hsmaudit.DigestLen)
	err := db.AppendLogEntries(ctx, []hsm.AuditLogEntry{altered})
	if err == nil {
		t.Fatal("an altered re-delivery was accepted")
	}
	if !strings.Contains(err.Error(), "not genuine") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLedgerChainSealsAndVerifies(t *testing.T) {
	db := hsmAuditTestDB(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		e := &hsmaudit.LedgerEntry{
			Timestamp: time.Now().UTC(),
			KeyLabel:  "audit-test-root",
			KeyID:     0x6f42,
			Digest:    strings.Repeat("0123456789abcdef", 4),
			Algorithm: "SHA-256",
			Purpose:   hsmaudit.PurposeCertificate,
		}
		if err := db.AppendLedger(ctx, e); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if e.Seq != int64(i+1) {
			t.Fatalf("entry %d got seq %d", i, e.Seq)
		}
	}
	rows, err := db.Ledger(ctx)
	if err != nil {
		t.Fatalf("reading ledger: %v", err)
	}
	if res := hsmaudit.VerifyLedger(rows); !res.Valid {
		t.Fatalf("ledger read back from the store does not verify: %s (seq %d)", res.Reason, res.BrokenAtSeq)
	}
}

// Signing is genuinely concurrent (the session pool is bounded but parallel), so
// the ledger append path must produce a gap-free, correctly linked chain under
// concurrency rather than a fork that later reads as tampering.
func TestConcurrentLedgerAppendsProduceGapFreeChain(t *testing.T) {
	db := hsmAuditTestDB(t)
	ctx := context.Background()

	const n = 40
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := db.AppendLedger(ctx, &hsmaudit.LedgerEntry{
				Timestamp: time.Now().UTC(),
				KeyLabel:  "audit-test-root",
				KeyID:     0x6f42,
				Digest:    strings.Repeat("ab", 32),
				Algorithm: "SHA-256",
				Purpose:   hsmaudit.PurposeCertificate,
			})
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent append: %v", err)
	}

	rows, err := db.Ledger(ctx)
	if err != nil {
		t.Fatalf("reading ledger: %v", err)
	}
	if len(rows) != n {
		t.Fatalf("stored %d rows, want %d", len(rows), n)
	}
	if res := hsmaudit.VerifyLedger(rows); !res.Valid {
		t.Fatalf("concurrent appends produced a broken chain: %s (seq %d)", res.Reason, res.BrokenAtSeq)
	}
}
