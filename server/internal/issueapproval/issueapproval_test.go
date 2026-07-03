//go:build sqlite

package issueapproval

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// approvalProfile is a custom high-assurance profile that requires manual
// issuance approval. It mirrors the built-in "server" shape.
const approvalProfileName = "hi-assurance"

// setup builds an issuance stack (sqlite + software provider + root CA) and a
// threshold-2 approval engine, and registers the require_approval profile.
func setup(t *testing.T) (*approval.Engine, *ca.Manager, *database.DB, string, ca.Profile) {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	mgr := ca.NewManager(db, prov)
	root, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		Label:    "issueapproval-root",
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "IssueApproval Root", Organization: "Secsy"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}

	profile := ca.Profile{
		Name:                approvalProfileName,
		Description:         "high-assurance profile requiring manual approval",
		KeyUsages:           []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:        []string{"serverAuth"},
		DefaultValidityDays: 90,
		MaxValidityDays:     90,
		RequireApproval:     true,
	}
	if err := ca.SetCustomProfiles([]ca.Profile{profile}); err != nil {
		t.Fatalf("SetCustomProfiles: %v", err)
	}
	t.Cleanup(func() { ca.SetCustomProfiles(nil) })

	eng := approval.NewEngine(db, db, approval.Policy{Enabled: true, DefaultThreshold: 2, TTL: 72 * time.Hour})
	eng.SetTerminalHook(NewTerminalHook(db))
	return eng, mgr, db, root.ID, profile
}

// makeCSR builds a PEM PKCS#10 CSR with the given common name and DNS SAN.
func makeCSR(t *testing.T, cn, dns string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{dns},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// park is a helper that holds an issuance for approval as the given requester.
func park(t *testing.T, eng *approval.Engine, mgr *ca.Manager, caID string, profile ca.Profile, csr []byte, requester string) *models.PendingApproval {
	t.Helper()
	pa, _, err := Park(context.Background(), ParkRequest{
		Engine:  eng,
		CAID:    caID,
		Profile: profile,
		CSRPEM:  csr,
		Actor:   requester,
		Tenant:  models.DefaultTenantID,
	})
	if err != nil {
		t.Fatalf("Park: %v", err)
	}
	return pa
}

func countIssued(t *testing.T, db *database.DB, caID string) int {
	t.Helper()
	certs, err := db.ListIssuedCertificates(caID)
	if err != nil {
		t.Fatalf("ListIssuedCertificates: %v", err)
	}
	return len(certs)
}

func countEvents(t *testing.T, db *database.DB, action string) int {
	t.Helper()
	_, total, err := db.ListEvents(action, "", "", 1, 0)
	if err != nil {
		t.Fatalf("ListEvents(%s): %v", action, err)
	}
	return total
}

// TestApproveThenIssue: two distinct approvers unlock the request, Complete
// issues and delivers the certificate, and a second Complete is idempotent.
func TestApproveThenIssue(t *testing.T) {
	eng, mgr, db, caID, profile := setup(t)
	csr := makeCSR(t, "leaf.example.com", "leaf.example.com")

	pa := park(t, eng, mgr, caID, profile, csr, "alice")
	if pa.Status != approval.StatusPending {
		t.Fatalf("parked request should be pending, got %s", pa.Status)
	}
	if countIssued(t, db, caID) != 0 {
		t.Fatal("no certificate must be issued while pending")
	}

	// Completing while still pending must not issue.
	if out, err := Complete(context.Background(), eng, mgr, db, pa.ID, "alice", "", ""); err != nil {
		t.Fatalf("Complete(pending): %v", err)
	} else if out.State != StatePending {
		t.Fatalf("pending request state = %q, want pending", out.State)
	}
	if countIssued(t, db, caID) != 0 {
		t.Fatal("completing a pending request must not issue")
	}

	if _, err := eng.Approve(context.Background(), pa.ID, "bob", "Bob", "", ""); err != nil {
		t.Fatalf("approve bob: %v", err)
	}
	if _, err := eng.Approve(context.Background(), pa.ID, "carol", "Carol", "", ""); err != nil {
		t.Fatalf("approve carol: %v", err)
	}

	out, err := Complete(context.Background(), eng, mgr, db, pa.ID, "alice", "Alice", "10.0.0.1")
	if err != nil {
		t.Fatalf("Complete(approved): %v", err)
	}
	if out.State != StateDelivered || out.Issued == nil {
		t.Fatalf("expected a delivered certificate, got state=%q issued=%v", out.State, out.Issued)
	}
	if out.Issued.CommonName != "leaf.example.com" {
		t.Errorf("issued CN = %q, want leaf.example.com", out.Issued.CommonName)
	}
	if out.Issued.Profile != approvalProfileName {
		t.Errorf("issued profile = %q, want %q", out.Issued.Profile, approvalProfileName)
	}
	// The returned chain must parse as leaf + issuer.
	if _, err := x509.ParseCertificate(mustDER(t, out.Issued.Certificate)); err != nil {
		t.Errorf("issued leaf does not parse: %v", err)
	}
	if countIssued(t, db, caID) != 1 {
		t.Fatalf("expected exactly one issued certificate, got %d", countIssued(t, db, caID))
	}
	if got := countEvents(t, db, audit.ActionCertIssueApproved); got != 1 {
		t.Errorf("cert.issue.approved events = %d, want 1", got)
	}

	// Idempotent: a second completion returns the SAME certificate, not a new one.
	out2, err := Complete(context.Background(), eng, mgr, db, pa.ID, "alice", "Alice", "")
	if err != nil {
		t.Fatalf("Complete(executed): %v", err)
	}
	if out2.State != StateDelivered || out2.Issued.Serial != out.Issued.Serial {
		t.Fatalf("second completion must redeliver the same serial, got state=%q serial=%q (first %q)",
			out2.State, out2.Issued.Serial, out.Issued.Serial)
	}
	if countIssued(t, db, caID) != 1 {
		t.Fatalf("re-completion must not issue a second certificate, got %d", countIssued(t, db, caID))
	}
}

// TestDenyNoIssue: a rejected request never issues and Complete reports denied.
func TestDenyNoIssue(t *testing.T) {
	eng, mgr, db, caID, profile := setup(t)
	pa := park(t, eng, mgr, caID, profile, makeCSR(t, "denied.example.com", "denied.example.com"), "alice")

	if _, err := eng.Reject(context.Background(), pa.ID, "bob", "Bob", "not allowed", ""); err != nil {
		t.Fatalf("reject: %v", err)
	}
	out, err := Complete(context.Background(), eng, mgr, db, pa.ID, "alice", "", "")
	if err != nil {
		t.Fatalf("Complete(rejected): %v", err)
	}
	if out.State != StateDenied {
		t.Fatalf("rejected request state = %q, want denied", out.State)
	}
	if countIssued(t, db, caID) != 0 {
		t.Fatal("a rejected request must never issue a certificate")
	}
	// The terminal hook must have recorded a cert.issue.denied event.
	if got := countEvents(t, db, audit.ActionCertIssueDenied); got != 1 {
		t.Errorf("cert.issue.denied events = %d, want 1", got)
	}
}

// TestSelfApprovalRejected: the requester cannot approve their own request, so
// it stays pending and never issues.
func TestSelfApprovalRejected(t *testing.T) {
	eng, mgr, db, caID, profile := setup(t)
	pa := park(t, eng, mgr, caID, profile, makeCSR(t, "self.example.com", "self.example.com"), "alice")

	if _, err := eng.Approve(context.Background(), pa.ID, "alice", "Alice", "", ""); err != approval.ErrSelfApproval {
		t.Fatalf("self-approval must be denied, got %v", err)
	}
	// One further distinct approval is still short of the threshold of 2.
	if _, err := eng.Approve(context.Background(), pa.ID, "bob", "Bob", "", ""); err != nil {
		t.Fatalf("approve bob: %v", err)
	}
	out, err := Complete(context.Background(), eng, mgr, db, pa.ID, "alice", "", "")
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if out.State != StatePending {
		t.Fatalf("state = %q, want pending (self-approval must not count toward the threshold)", out.State)
	}
	if countIssued(t, db, caID) != 0 {
		t.Fatal("a sub-threshold request must never issue")
	}
}

// mustDER extracts the DER bytes from a single PEM certificate block.
func mustDER(t *testing.T, pemStr string) []byte {
	t.Helper()
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		t.Fatal("certificate is not valid PEM")
	}
	return block.Bytes
}
