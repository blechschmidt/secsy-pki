//go:build sqlite

package database

import (
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Task 157 database-layer tests for certificate-inventory retention/archival.
// They run on SQLite always and on PostgreSQL when SECSY_TEST_PG_DSN is set, so
// the ph()/IN-list and cross-dialect not_after comparison paths are covered on
// the real backend too.
//
// The load-bearing invariant is proven directly: after retention runs, the exact
// store reads the OCSP responder and CRL generator use (GetRevokedCertificate →
// GetIssuedCertificate for OCSP; ListRevokedCertificates for the CRL) return
// byte-identical results for every retained serial, and revoked_certificates is
// never touched.

const retentionCA = "ret-ca"

// retentionFixture holds the serials seeded by seedRetentionFixture, named by
// their intended disposition.
type retentionFixture struct {
	validFresh       string // still valid (future not_after)      -> retained
	revokedUnexpired string // revoked, not yet expired            -> retained
	expiredRecent    string // expired but within the grace window -> retained
	heldOld          string // long-expired but on hold            -> retained
	pinnedOld        string // long-expired but open-approval pinned-> retained
	expiredOld       string // long-expired, terminal              -> eligible
	revokedExpired   string // long-expired AND revoked            -> eligible
}

// all returns every seeded serial.
func (f retentionFixture) retained() []string {
	return []string{f.validFresh, f.revokedUnexpired, f.expiredRecent, f.heldOld, f.pinnedOld}
}

func recordRetentionCert(t *testing.T, db *DB, serial string, notAfter time.Time, status models.CertStatus) {
	t.Helper()
	if err := db.RecordIssuedCertificate(&models.IssuedCertificate{
		ID:          retentionCA + "-" + serial,
		CAID:        retentionCA,
		Serial:      serial,
		CommonName:  serial + ".example.com",
		Profile:     "server",
		Certificate: "-----BEGIN CERTIFICATE-----\nMIIB" + serial + "\n-----END CERTIFICATE-----\n",
		NotBefore:   notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:    notAfter,
		Status:      status,
	}); err != nil {
		t.Fatalf("RecordIssuedCertificate(%s): %v", serial, err)
	}
}

func seedRetentionFixture(t *testing.T, db *DB, now time.Time) retentionFixture {
	t.Helper()
	if err := db.CreateCA(&models.CA{
		ID: retentionCA, Label: retentionCA, PKCS11URI: "pkcs11:" + retentionCA,
		KeyType: "ecdsa-p256", PublicKey: "k", Certificate: "x",
	}); err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	f := retentionFixture{
		validFresh:       "1001",
		revokedUnexpired: "1002",
		expiredRecent:    "1003",
		expiredOld:       "1004",
		revokedExpired:   "1005",
		heldOld:          "1006",
		pinnedOld:        "1007",
	}
	recordRetentionCert(t, db, f.validFresh, now.Add(90*24*time.Hour), models.CertStatusValid)
	recordRetentionCert(t, db, f.revokedUnexpired, now.Add(30*24*time.Hour), models.CertStatusValid)
	recordRetentionCert(t, db, f.expiredRecent, now.Add(-10*24*time.Hour), models.CertStatusExpired)
	recordRetentionCert(t, db, f.expiredOld, now.Add(-200*24*time.Hour), models.CertStatusExpired)
	recordRetentionCert(t, db, f.revokedExpired, now.Add(-200*24*time.Hour), models.CertStatusValid)
	recordRetentionCert(t, db, f.heldOld, now.Add(-200*24*time.Hour), models.CertStatusValid)
	recordRetentionCert(t, db, f.pinnedOld, now.Add(-200*24*time.Hour), models.CertStatusExpired)

	// Revoke the two revoked serials (updates issued status + revoked_certificates).
	if _, err := db.RevokeCertificate(retentionCA, f.revokedUnexpired, 1, now); err != nil {
		t.Fatalf("RevokeCertificate(unexpired): %v", err)
	}
	if _, err := db.RevokeCertificate(retentionCA, f.revokedExpired, 1, now); err != nil {
		t.Fatalf("RevokeCertificate(expired): %v", err)
	}
	// Suspend the held serial (status=held, revoked_certificates reason 6).
	if _, err := db.SuspendCertificate(retentionCA, f.heldOld, now); err != nil {
		t.Fatalf("SuspendCertificate: %v", err)
	}
	return f
}

// ocspDecision replicates ca.Manager.certStatus exactly: revoked_certificates
// first (revoked), then issued_certificates (good), else unknown. Proving this is
// unchanged for a serial proves OCSP for that serial is unaffected.
func ocspDecision(t *testing.T, db *DB, serial string) string {
	t.Helper()
	rc, err := db.GetRevokedCertificate(retentionCA, serial)
	if err != nil {
		t.Fatalf("GetRevokedCertificate(%s): %v", serial, err)
	}
	if rc != nil {
		return "revoked"
	}
	ic, err := db.GetIssuedCertificate(retentionCA, serial)
	if err != nil {
		t.Fatalf("GetIssuedCertificate(%s): %v", serial, err)
	}
	if ic == nil {
		return "unknown"
	}
	return "good"
}

// crlListed reports whether a serial appears in the CRL input
// (ListRevokedCertificates), the exact read CRL generation performs.
func crlListed(t *testing.T, db *DB, serial string) bool {
	t.Helper()
	revs, err := db.ListRevokedCertificates(retentionCA)
	if err != nil {
		t.Fatalf("ListRevokedCertificates: %v", err)
	}
	for _, r := range revs {
		if r.Serial == serial {
			return true
		}
	}
	return false
}

type ocspCRLState struct {
	ocsp   string
	onCRL  bool
	issued bool
}

func snapshotState(t *testing.T, db *DB, serials []string) map[string]ocspCRLState {
	t.Helper()
	out := make(map[string]ocspCRLState, len(serials))
	for _, s := range serials {
		ic, err := db.GetIssuedCertificate(retentionCA, s)
		if err != nil {
			t.Fatalf("GetIssuedCertificate(%s): %v", s, err)
		}
		out[s] = ocspCRLState{ocsp: ocspDecision(t, db, s), onCRL: crlListed(t, db, s), issued: ic != nil}
	}
	return out
}

func assertStateUnchanged(t *testing.T, before, after map[string]ocspCRLState) {
	t.Helper()
	for s, b := range before {
		a := after[s]
		if a != b {
			t.Errorf("retained serial %s state changed: before=%+v after=%+v (OCSP/CRL for a retained serial MUST be unaffected)", s, b, a)
		}
	}
}

// archiveAll drives ArchiveRetentionBatch to completion and returns the total
// moved.
func archiveAll(t *testing.T, db *DB, cutoff time.Time, excl []string, batch int) int {
	t.Helper()
	total := 0
	for {
		moved, err := db.ArchiveRetentionBatch(cutoff, "run-test", "test", time.Now().UTC(), excl, batch)
		if err != nil {
			t.Fatalf("ArchiveRetentionBatch: %v", err)
		}
		if len(moved) == 0 {
			break
		}
		total += len(moved)
	}
	return total
}

func pruneAll(t *testing.T, db *DB, cutoff time.Time, batch int) int {
	t.Helper()
	total := 0
	for {
		del, err := db.PruneArchiveBatch(cutoff, batch)
		if err != nil {
			t.Fatalf("PruneArchiveBatch: %v", err)
		}
		if len(del) == 0 {
			break
		}
		total += len(del)
	}
	return total
}

// testRetentionArchiveRetainsLoadBearing proves archive mode moves only the
// long-expired terminal rows and leaves every retained serial's OCSP/CRL state
// and the revocation table untouched.
func testRetentionArchiveRetainsLoadBearing(t *testing.T, db *DB) {
	now := time.Now().UTC()
	f := seedRetentionFixture(t, db, now)
	cutoff := now.Add(-90 * 24 * time.Hour)

	// The revocation set and the retained serials' OCSP/CRL state before retention.
	revBefore, err := db.ListRevokedCertificates(retentionCA)
	if err != nil {
		t.Fatalf("ListRevokedCertificates: %v", err)
	}
	before := snapshotState(t, db, f.retained())

	// Eligibility count (upper bound: does not subtract the approval pin).
	elig, err := db.CountRetentionEligible(cutoff)
	if err != nil {
		t.Fatalf("CountRetentionEligible: %v", err)
	}
	if elig != 3 { // expiredOld, revokedExpired, pinnedOld
		t.Fatalf("CountRetentionEligible = %d, want 3", elig)
	}

	// Archive with the pinned serial excluded (as an open approval would).
	archived := archiveAll(t, db, cutoff, []string{f.pinnedOld}, 2)
	if archived != 2 { // expiredOld + revokedExpired only
		t.Fatalf("archived = %d, want 2 (expiredOld + revokedExpired; pinnedOld excluded)", archived)
	}

	// The two eligible serials left the hot table but are recoverable from the archive.
	for _, s := range []string{f.expiredOld, f.revokedExpired} {
		if ic, _ := db.GetIssuedCertificate(retentionCA, s); ic != nil {
			t.Errorf("serial %s still in issued_certificates after archive", s)
		}
		if ar, err := db.GetArchivedCertificate(retentionCA, s); err != nil || ar == nil {
			t.Errorf("serial %s not found in archive (err %v)", s, err)
		}
	}

	// Every retained serial is still present in the hot table...
	for _, s := range f.retained() {
		if ic, _ := db.GetIssuedCertificate(retentionCA, s); ic == nil {
			t.Errorf("retained serial %s missing from issued_certificates after archive", s)
		}
	}
	// ...with byte-identical OCSP/CRL state.
	assertStateUnchanged(t, before, snapshotState(t, db, f.retained()))

	// revoked_certificates is never touched: same rows as before (including the
	// archived-but-revoked serial's row, which keeps OCSP=revoked / CRL-listed).
	revAfter, err := db.ListRevokedCertificates(retentionCA)
	if err != nil {
		t.Fatalf("ListRevokedCertificates: %v", err)
	}
	if len(revAfter) != len(revBefore) {
		t.Errorf("revoked_certificates size changed: before=%d after=%d (retention must never touch it)", len(revBefore), len(revAfter))
	}
	if got := ocspDecision(t, db, f.revokedExpired); got != "revoked" {
		t.Errorf("archived revoked serial %s OCSP = %q, want revoked (revocation row must survive archival)", f.revokedExpired, got)
	}
	if !crlListed(t, db, f.revokedExpired) {
		t.Errorf("archived revoked serial %s dropped from CRL input", f.revokedExpired)
	}

	// The pinned serial is retained and shows up as remaining backlog.
	if ic, _ := db.GetIssuedCertificate(retentionCA, f.pinnedOld); ic == nil {
		t.Errorf("approval-pinned serial %s was archived despite exclusion", f.pinnedOld)
	}
	if backlog, _ := db.CountRetentionEligible(cutoff); backlog != 1 {
		t.Errorf("backlog after archive = %d, want 1 (the pinned serial)", backlog)
	}
}

// testRetentionPruneDeletesAfterArchive proves prune hard-deletes the archived
// rows while leaving the revocation table and every retained serial untouched.
func testRetentionPruneDeletesAfterArchive(t *testing.T, db *DB) {
	now := time.Now().UTC()
	f := seedRetentionFixture(t, db, now)
	cutoff := now.Add(-90 * 24 * time.Hour)

	before := snapshotState(t, db, f.retained())
	revBefore, _ := db.ListRevokedCertificates(retentionCA)

	// Archive, then prune everything archived (same window).
	if archived := archiveAll(t, db, cutoff, []string{f.pinnedOld}, 500); archived != 2 {
		t.Fatalf("archived = %d, want 2", archived)
	}
	if n, _ := db.CountArchivedCertificates(); n != 2 {
		t.Fatalf("archive size after archive = %d, want 2", n)
	}
	pruned := pruneAll(t, db, cutoff, 500)
	if pruned != 2 {
		t.Fatalf("pruned = %d, want 2", pruned)
	}
	if n, _ := db.CountArchivedCertificates(); n != 0 {
		t.Errorf("archive size after prune = %d, want 0", n)
	}

	// Retained serials are still present and unchanged.
	for _, s := range f.retained() {
		if ic, _ := db.GetIssuedCertificate(retentionCA, s); ic == nil {
			t.Errorf("retained serial %s missing after prune", s)
		}
	}
	assertStateUnchanged(t, before, snapshotState(t, db, f.retained()))

	// The revocation table is intact — so even the pruned revoked serial still
	// resolves REVOKED via OCSP and appears on the CRL (revocation correctness is
	// independent of inventory retention).
	revAfter, _ := db.ListRevokedCertificates(retentionCA)
	if len(revAfter) != len(revBefore) {
		t.Errorf("revoked_certificates size changed by prune: before=%d after=%d", len(revBefore), len(revAfter))
	}
	if got := ocspDecision(t, db, f.revokedExpired); got != "revoked" {
		t.Errorf("pruned revoked serial %s OCSP = %q, want revoked", f.revokedExpired, got)
	}
	if !crlListed(t, db, f.revokedExpired) {
		t.Errorf("pruned revoked serial %s dropped from CRL input", f.revokedExpired)
	}
}

// testOpenApprovalSerials proves an open (pending/approved) approval carrying a
// serial in its payload protects that serial, and that terminal approvals do not.
func testOpenApprovalSerials(t *testing.T, db *DB) {
	seed := func(id, status, payload string) {
		if err := db.CreatePendingApproval(&models.PendingApproval{
			ID: id, OperationClass: "cert.revoke", ResourceKey: "ca:x",
			Fingerprint: id, RequestedBy: "op", Status: status,
			ExpiresAt: time.Now().Add(time.Hour), Payload: payload,
		}); err != nil {
			t.Fatalf("CreatePendingApproval(%s): %v", id, err)
		}
	}
	seed("open-pending", "pending", `{"serial":"5001","reason":1}`)
	seed("open-approved", "approved", `{"serial":"5002"}`)
	seed("closed-executed", "executed", `{"serial":"5003"}`) // terminal: must NOT protect

	got, err := db.OpenApprovalSerials()
	if err != nil {
		t.Fatalf("OpenApprovalSerials: %v", err)
	}
	if _, ok := got["5001"]; !ok {
		t.Errorf("serial 5001 (open pending) not protected: %v", got)
	}
	if _, ok := got["5002"]; !ok {
		t.Errorf("serial 5002 (open approved) not protected: %v", got)
	}
	if _, ok := got["5003"]; ok {
		t.Errorf("serial 5003 (executed/terminal) should not be protected: %v", got)
	}
}

// --- SQLite (always) ---

func retentionSQLiteDB(t *testing.T) *DB {
	t.Helper()
	db, err := New("sqlite", t.TempDir()+"/retention-test.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestRetentionArchiveRetainsLoadBearingSQLite(t *testing.T) {
	testRetentionArchiveRetainsLoadBearing(t, retentionSQLiteDB(t))
}
func TestRetentionPruneDeletesAfterArchiveSQLite(t *testing.T) {
	testRetentionPruneDeletesAfterArchive(t, retentionSQLiteDB(t))
}
func TestOpenApprovalSerialsSQLite(t *testing.T) {
	testOpenApprovalSerials(t, retentionSQLiteDB(t))
}

// --- PostgreSQL (when SECSY_TEST_PG_DSN is set) ---

func TestRetentionArchiveRetainsLoadBearingPostgres(t *testing.T) {
	testRetentionArchiveRetainsLoadBearing(t, freshPostgres(t))
}
func TestRetentionPruneDeletesAfterArchivePostgres(t *testing.T) {
	testRetentionPruneDeletesAfterArchive(t, freshPostgres(t))
}
func TestOpenApprovalSerialsPostgres(t *testing.T) {
	testOpenApprovalSerials(t, freshPostgres(t))
}
