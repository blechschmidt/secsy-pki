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

// The device commitments (Task 178) are the only rows in this subsystem that
// carry an X.509 certificate and an optional timestamp token, so the round trip
// has more to lose than the others: a truncated PEM or a genTime that came back
// as the zero time instead of NULL would both read, at audit, as a forged or
// undated commitment rather than as a storage bug.
func TestCommitmentRoundTrip(t *testing.T) {
	db := hsmAuditTestDB(t)
	pinState(t, db)
	ctx := context.Background()

	const certPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	head := hsmaudit.Head{
		DeviceSerial: "31650425",
		Anchor:       testAnchor,
		DeviceNumber: 7,
		DeviceDigest: strings.Repeat("ab", hsmaudit.DigestLen),
		Signatures:   3,
		LedgerSeq:    3,
		LedgerHash:   strings.Repeat("cd", 32),
	}
	first := &hsmaudit.Commitment{
		Head:                 head,
		Label:                hsmaudit.CommitmentLabel(head),
		ObjectID:             hsmaudit.DefaultCommitmentKeyID,
		CertificatePEM:       certPEM,
		DeviceCertificatePEM: certPEM,
		CreatedAt:            time.Now().UTC().Truncate(time.Millisecond),
		GenTime:              time.Now().UTC().Truncate(time.Second),
		Source:               "https://tsa.example/tsr",
		Token:                []byte{0x30, 0x82, 0x01, 0x00},
	}
	if err := db.AppendCommitment(ctx, first); err != nil {
		t.Fatalf("appending commitment: %v", err)
	}
	if first.Seq != 1 {
		t.Fatalf("first commitment got seq %d, want 1", first.Seq)
	}

	// A commitment taken while no TSA was reachable: the date must come back
	// absent rather than as a zero time that a verifier would have to guess at.
	undated := &hsmaudit.Commitment{
		Head:           head,
		Label:          hsmaudit.CommitmentLabel(head),
		ObjectID:       hsmaudit.DefaultCommitmentKeyID,
		CertificatePEM: certPEM,
		CreatedAt:      time.Now().UTC().Truncate(time.Millisecond),
	}
	if err := db.AppendCommitment(ctx, undated); err != nil {
		t.Fatalf("appending an undated commitment: %v", err)
	}
	if undated.Seq != 2 {
		t.Fatalf("second commitment got seq %d, want 2", undated.Seq)
	}

	got, err := db.Commitments(ctx)
	if err != nil {
		t.Fatalf("reading commitments: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("read back %d commitment(s), want 2", len(got))
	}
	if got[0].Head != first.Head {
		t.Fatalf("head round trip: got %+v, want %+v", got[0].Head, first.Head)
	}
	if got[0].Label != first.Label || got[0].ObjectID != first.ObjectID {
		t.Fatalf("label/object round trip: got %q/0x%04x", got[0].Label, got[0].ObjectID)
	}
	if got[0].CertificatePEM != certPEM || got[0].DeviceCertificatePEM != certPEM {
		t.Fatal("certificate PEM did not survive the round trip")
	}
	if string(got[0].Token) != string(first.Token) {
		t.Fatalf("token round trip: got %x, want %x", got[0].Token, first.Token)
	}
	if !got[0].GenTime.Equal(first.GenTime) || got[0].Source != first.Source {
		t.Fatalf("date round trip: got %s from %q", got[0].GenTime, got[0].Source)
	}
	if !got[1].GenTime.IsZero() {
		t.Fatalf("an undated commitment came back dated %s", got[1].GenTime)
	}
}

// A commitment with no certificate is not a commitment; storing one would put a
// row in the record that fails verification with no way to tell whether the
// device or the row was at fault.
func TestCommitmentRequiresACertificate(t *testing.T) {
	db := hsmAuditTestDB(t)
	pinState(t, db)
	err := db.AppendCommitment(context.Background(), &hsmaudit.Commitment{
		Head:     hsmaudit.Head{DeviceSerial: "31650425"},
		ObjectID: hsmaudit.DefaultCommitmentKeyID,
	})
	if err == nil {
		t.Fatal("a commitment with no attestation certificate was stored")
	}
}
