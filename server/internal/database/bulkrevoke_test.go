//go:build sqlite

package database

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Task 70 store primitives: candidate selection and batched transactional
// revocation, exercised on both backends (SQLite always; PostgreSQL when
// SECSY_TEST_PG_DSN is set) including correctness under concurrent issuance
// and a bulk operation racing single revocations.

// seedBulkCA creates a CA with n issued certificates. Serials are zero-padded
// so lexicographic serial order matches numeric order in assertions.
func seedBulkCA(t *testing.T, db *DB, caID string, n int) {
	t.Helper()
	if err := db.CreateCA(&models.CA{ID: caID, Label: caID, PKCS11URI: "pkcs11:" + caID, KeyType: "ecdsa-p256", PublicKey: "k", Certificate: "x"}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	now := time.Now()
	for i := 0; i < n; i++ {
		if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
			ID:          fmt.Sprintf("%s-cert-%04d", caID, i),
			CAID:        caID,
			Serial:      fmt.Sprintf("%06d", i+1),
			Subject:     fmt.Sprintf("CN=host-%04d.example.com", i),
			CommonName:  fmt.Sprintf("host-%04d.example.com", i),
			SANs:        []string{fmt.Sprintf("host-%04d.example.com", i)},
			Profile:     "server",
			Certificate: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
			NotBefore:   now.Add(-time.Hour),
			NotAfter:    now.Add(90 * 24 * time.Hour),
			Status:      models.CertStatusValid,
		}); err != nil {
			t.Fatalf("RecordIssuedCertificate(%d): %v", i, err)
		}
	}
}

func testBulkRevokeStore(t *testing.T, db *DB) {
	seedBulkCA(t, db, "bulk-ca", 10)
	when := time.Now()

	// First batch: five serials, all newly revoked.
	applied, err := db.BulkRevokeCertificates("bulk-ca", []string{"000001", "000002", "000003", "000004", "000005"}, 1, when)
	if err != nil {
		t.Fatalf("BulkRevokeCertificates: %v", err)
	}
	if len(applied) != 5 {
		t.Fatalf("applied = %d, want 5 (%v)", len(applied), applied)
	}

	// Overlapping batch: only the two new serials are applied; the three
	// already-revoked ones are skipped untouched (no timestamp/reason churn).
	before, err := db.GetRevokedCertificate("bulk-ca", "000003")
	if err != nil || before == nil {
		t.Fatalf("GetRevokedCertificate: %v, %v", before, err)
	}
	applied, err = db.BulkRevokeCertificates("bulk-ca", []string{"000003", "000004", "000006", "000007"}, 2, when.Add(time.Hour))
	if err != nil {
		t.Fatalf("BulkRevokeCertificates overlap: %v", err)
	}
	if len(applied) != 2 || applied[0] != "000006" || applied[1] != "000007" {
		t.Fatalf("overlap applied = %v, want [000006 000007]", applied)
	}
	after, err := db.GetRevokedCertificate("bulk-ca", "000003")
	if err != nil || after == nil {
		t.Fatalf("GetRevokedCertificate after overlap: %v, %v", after, err)
	}
	if !after.RevokedAt.Equal(before.RevokedAt) || after.Reason != before.Reason {
		t.Errorf("already-revoked serial was churned: before=%v/%d after=%v/%d",
			before.RevokedAt, before.Reason, after.RevokedAt, after.Reason)
	}

	// Duplicates and empties inside one batch are tolerated.
	applied, err = db.BulkRevokeCertificates("bulk-ca", []string{"000008", "000008", "", "000008"}, 0, when)
	if err != nil || len(applied) != 1 {
		t.Fatalf("dedup batch applied = %v (%v), want exactly [000008]", applied, err)
	}

	// A serial unknown to the inventory still gets its bare revocation row.
	applied, err = db.BulkRevokeCertificates("bulk-ca", []string{"999999"}, 1, when)
	if err != nil || len(applied) != 1 {
		t.Fatalf("unknown-serial batch: %v (%v)", applied, err)
	}
	if rc, err := db.GetRevokedCertificate("bulk-ca", "999999"); err != nil || rc == nil {
		t.Fatalf("unknown serial not in revocation store: %v, %v", rc, err)
	}

	// Inventory rows reflect the revocations.
	ic, err := db.GetIssuedCertificate("bulk-ca", "000006")
	if err != nil || ic == nil {
		t.Fatalf("GetIssuedCertificate: %v", err)
	}
	if ic.Status != models.CertStatusRevoked || ic.RevokedAt == nil || ic.RevocationReason != 2 {
		t.Errorf("inventory row not updated: status=%s revoked_at=%v reason=%d", ic.Status, ic.RevokedAt, ic.RevocationReason)
	}

	// The full revocation store: 5 + 2 + 1 + 1 = 9 rows.
	revoked, err := db.ListRevokedCertificates("bulk-ca")
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 9 {
		t.Errorf("revocation store rows = %d, want 9", len(revoked))
	}
}

func testListRevocationCandidates(t *testing.T, db *DB) {
	caID := "cand-ca"
	if err := db.CreateCA(&models.CA{ID: caID, Label: caID, PKCS11URI: "pkcs11:" + caID, KeyType: "ecdsa-p256", PublicKey: "k", Certificate: "x"}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	add := func(serial, cn, profile string, notBefore, notAfter time.Time, status models.CertStatus) {
		t.Helper()
		if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
			ID: caID + "-" + serial, CAID: caID, Serial: serial, CommonName: cn,
			Subject: "CN=" + cn, SANs: []string{cn}, Profile: profile, Certificate: "PEM",
			NotBefore: notBefore, NotAfter: notAfter, Status: status,
		}); err != nil {
			t.Fatal(err)
		}
	}
	add("1", "a.example.com", "server", now.Add(-48*time.Hour), now.Add(time.Hour), models.CertStatusValid)
	add("2", "b.example.com", "client", now.Add(-24*time.Hour), now.Add(time.Hour), models.CertStatusValid)
	add("3", "c.example.com", "server", now.Add(-1*time.Hour), now.Add(time.Hour), models.CertStatusValid)
	add("4", "expired.example.com", "server", now.Add(-48*time.Hour), now.Add(-time.Minute), models.CertStatusValid) // expired but not yet marked
	add("5", "gone.example.com", "server", now.Add(-48*time.Hour), now.Add(time.Hour), models.CertStatusValid)
	if _, err := db.RevokeCertificate(caID, "5", 0, now); err != nil {
		t.Fatal(err)
	}

	sel := RevocationSelector{CAID: caID, Now: now}
	got, err := db.ListRevocationCandidates(sel)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"1", "2", "3"}; !sameSerials(got, want) {
		t.Errorf("default selection = %v, want %v (revoked and expired excluded)", serialsOf(got), want)
	}
	if got[0].CommonName != "a.example.com" || len(got[0].SANs) != 1 || got[0].Profile != "server" {
		t.Errorf("candidate projection incomplete: %+v", got[0])
	}

	sel.IncludeExpired = true
	if got, err = db.ListRevocationCandidates(sel); err != nil || !sameSerials(got, []string{"1", "2", "3", "4"}) {
		t.Errorf("include-expired selection = %v (%v), want [1 2 3 4]", serialsOf(got), err)
	}

	sel = RevocationSelector{CAID: caID, Profile: "client", Now: now}
	if got, err = db.ListRevocationCandidates(sel); err != nil || !sameSerials(got, []string{"2"}) {
		t.Errorf("profile selection = %v (%v), want [2]", serialsOf(got), err)
	}

	cut := now.Add(-30 * time.Hour)
	sel = RevocationSelector{CAID: caID, IssuedAfter: &cut, Now: now}
	if got, err = db.ListRevocationCandidates(sel); err != nil || !sameSerials(got, []string{"2", "3"}) {
		t.Errorf("issued-after selection = %v (%v), want [2 3]", serialsOf(got), err)
	}
	sel = RevocationSelector{CAID: caID, IssuedBefore: &cut, IncludeExpired: true, Now: now}
	if got, err = db.ListRevocationCandidates(sel); err != nil || !sameSerials(got, []string{"1", "4"}) {
		t.Errorf("issued-before selection = %v (%v), want [1 4]", serialsOf(got), err)
	}
}

// testBulkRevokeUnderConcurrentIssuance is the headline correctness property:
// a bulk revocation applied in batches while issuance keeps writing to the
// same CA neither loses revocations, nor revokes anything issued after the
// selection, nor corrupts counters.
func testBulkRevokeUnderConcurrentIssuance(t *testing.T, db *DB) {
	const preIssued = 200
	const batchSize = 25
	caID := "race-ca"
	seedBulkCA(t, db, caID, preIssued)

	candidates, err := db.ListRevocationCandidates(RevocationSelector{CAID: caID})
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != preIssued {
		t.Fatalf("candidates = %d, want %d", len(candidates), preIssued)
	}

	// Concurrent issuance: two writers keep recording fresh certificates (the
	// serial space is disjoint from the seeded one) for the whole duration of
	// the batched revocation.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var issued int
	var issuedMu sync.Mutex
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			now := time.Now()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				serial := fmt.Sprintf("9%d%06d", w, i)
				err := db.RecordIssuedCertificate(&models.IssuedCertificate{
					ID: fmt.Sprintf("%s-live-%d-%d", caID, w, i), CAID: caID, Serial: serial,
					CommonName: "live.example.com", Profile: "server", Certificate: "PEM",
					NotBefore: now, NotAfter: now.Add(24 * time.Hour), Status: models.CertStatusValid,
				})
				if err != nil {
					t.Errorf("concurrent issuance failed: %v", err)
					return
				}
				issuedMu.Lock()
				issued++
				issuedMu.Unlock()
			}
		}(w)
	}

	// Batched revocation of the pre-selected candidates.
	when := time.Now()
	var revoked int
	for i := 0; i < len(candidates); i += batchSize {
		end := i + batchSize
		if end > len(candidates) {
			end = len(candidates)
		}
		batch := make([]string, 0, batchSize)
		for _, c := range candidates[i:end] {
			batch = append(batch, c.Serial)
		}
		applied, err := db.BulkRevokeCertificates(caID, batch, 1, when)
		if err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("bulk batch %d: %v", i/batchSize, err)
		}
		revoked += len(applied)
	}
	close(stop)
	wg.Wait()

	if revoked != preIssued {
		t.Errorf("revoked = %d, want %d", revoked, preIssued)
	}
	issuedMu.Lock()
	liveIssued := issued
	issuedMu.Unlock()
	if liveIssued == 0 {
		t.Fatal("concurrent issuance recorded nothing; the race exercised nothing")
	}

	// Every seeded certificate is revoked; every concurrently issued one is not.
	rows, err := db.ListRevokedCertificates(caID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != preIssued {
		t.Errorf("revocation store rows = %d, want %d (concurrently issued certs must be untouched)", len(rows), preIssued)
	}
	remaining, err := db.ListRevocationCandidates(RevocationSelector{CAID: caID})
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != liveIssued {
		t.Errorf("remaining candidates = %d, want %d (exactly the concurrently issued set)", len(remaining), liveIssued)
	}
	t.Logf("revoked %d while %d certificates were issued concurrently", revoked, liveIssued)
}

// testBulkVersusSingleRevoke races a bulk batch against single revocations of
// the same serials: each serial must be "newly revoked" on exactly one path.
func testBulkVersusSingleRevoke(t *testing.T, db *DB) {
	const n = 60
	caID := "vs-ca"
	seedBulkCA(t, db, caID, n)

	serials := make([]string, n)
	for i := range serials {
		serials[i] = fmt.Sprintf("%06d", i+1)
	}

	when := time.Now()
	var wg sync.WaitGroup
	var singleApplied int64
	var singleMu sync.Mutex
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, s := range serials {
			applied, err := db.RevokeCertificate(caID, s, 1, when)
			if err != nil {
				t.Errorf("single revoke %s: %v", s, err)
				return
			}
			if applied {
				singleMu.Lock()
				singleApplied++
				singleMu.Unlock()
			}
		}
	}()

	var bulkApplied int
	for i := 0; i < n; i += 10 {
		applied, err := db.BulkRevokeCertificates(caID, serials[i:i+10], 1, when)
		if err != nil {
			wg.Wait()
			t.Fatalf("bulk batch: %v", err)
		}
		bulkApplied += len(applied)
	}
	wg.Wait()

	singleMu.Lock()
	total := int(singleApplied) + bulkApplied
	singleMu.Unlock()
	if total != n {
		t.Errorf("newly-revoked total across both paths = %d (bulk %d + single %d), want exactly %d",
			total, bulkApplied, singleApplied, n)
	}
	if rows, err := db.ListRevokedCertificates(caID); err != nil || len(rows) != n {
		t.Errorf("revocation store rows = %d (%v), want %d", len(rows), err, n)
	}
}

// --- SQLite (always) ---

func TestBulkRevokeStoreSQLite(t *testing.T)          { testBulkRevokeStore(t, fileTestDB(t)) }
func TestListRevocationCandidatesSQLite(t *testing.T) { testListRevocationCandidates(t, fileTestDB(t)) }
func TestBulkRevokeConcurrentIssuanceSQLite(t *testing.T) {
	testBulkRevokeUnderConcurrentIssuance(t, fileTestDB(t))
}
func TestBulkVersusSingleRevokeSQLite(t *testing.T) { testBulkVersusSingleRevoke(t, fileTestDB(t)) }

// fileTestDB opens a file-backed SQLite store so the concurrency tests run
// against the same journal/locking behavior as production file stores.
func fileTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", t.TempDir()+"/bulk-test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// --- PostgreSQL (when SECSY_TEST_PG_DSN is set) ---

func TestBulkRevokeStorePostgres(t *testing.T) { testBulkRevokeStore(t, freshPostgres(t)) }
func TestListRevocationCandidatesPostgres(t *testing.T) {
	testListRevocationCandidates(t, freshPostgres(t))
}
func TestBulkRevokeConcurrentIssuancePostgres(t *testing.T) {
	testBulkRevokeUnderConcurrentIssuance(t, freshPostgres(t))
}
func TestBulkVersusSingleRevokePostgres(t *testing.T) {
	testBulkVersusSingleRevoke(t, freshPostgres(t))
}

func serialsOf(cs []RevocationCandidate) []string {
	out := make([]string, len(cs))
	for i := range cs {
		out[i] = cs[i].Serial
	}
	return out
}

func sameSerials(cs []RevocationCandidate, want []string) bool {
	if len(cs) != len(want) {
		return false
	}
	for i := range cs {
		if cs[i].Serial != want[i] {
			return false
		}
	}
	return true
}
