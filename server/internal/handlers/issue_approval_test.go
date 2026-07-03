//go:build sqlite

package handlers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/issueapproval"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// approvalIssueAPI builds an API with an enabled four-eyes engine (threshold 2
// on cert.issue) and a require_approval custom profile, plus an issuable root CA.
func approvalIssueAPI(t *testing.T, enableGate bool) (*API, string) {
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
	api := NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, "")

	if enableGate {
		eng := approval.NewEngine(db, db, approval.Policy{Enabled: true, DefaultThreshold: 2, TTL: 72 * time.Hour})
		eng.SetTerminalHook(issueapproval.NewTerminalHook(db))
		api.SetApprovals(eng)
	}

	root, err := ca.NewManager(db, prov).InitRoot(context.Background(), ca.RootSpec{
		Label:    "approval-issue-root",
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Approval Issue Root", Organization: "Secsy"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}

	if err := ca.SetCustomProfiles([]ca.Profile{{
		Name:                "hi-assurance",
		Description:         "requires manual approval",
		KeyUsages:           []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:        []string{"serverAuth"},
		DefaultValidityDays: 90,
		MaxValidityDays:     90,
		RequireApproval:     true,
	}}); err != nil {
		t.Fatalf("SetCustomProfiles: %v", err)
	}
	t.Cleanup(func() { ca.SetCustomProfiles(nil) })
	return api, root.ID
}

func issueCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func issueBody(t *testing.T, profile, cn string) string {
	t.Helper()
	b, _ := json.Marshal(models.IssueCertRequest{Profile: profile, CSR: issueCSR(t, cn)})
	return string(b)
}

// TestIssueRequiresApprovalThenDelivers walks the full REST flow: a
// require_approval profile parks the request (202), two distinct approvers unlock
// it, and the certificate is fetched from the certificate endpoint.
func TestIssueRequiresApprovalThenDelivers(t *testing.T) {
	api, caID := approvalIssueAPI(t, true)

	// 1) Issuance under the gated profile is held for approval (202), not issued.
	rec := httptest.NewRecorder()
	api.IssueCertificate(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/issue", rootUser(), caID, issueBody(t, "hi-assurance", "leaf.example.com")))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body=%s)", rec.Code, rec.Body.String())
	}
	approvalID := rec.Header().Get("X-Secsy-Approval-Id")
	if approvalID == "" {
		t.Fatal("202 response must carry X-Secsy-Approval-Id")
	}
	if certs, _ := api.db.ListIssuedCertificates(caID); len(certs) != 0 {
		t.Fatalf("no certificate must be issued while pending, got %d", len(certs))
	}

	// 2) Fetching before approval reports still-pending (202), still no issuance.
	rec = httptest.NewRecorder()
	api.GetApprovalCertificate(rec, reqAs(http.MethodGet, "/api/approvals/"+approvalID+"/certificate", rootUser(), approvalID, ""))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("fetch-before-approval status = %d, want 202 (body=%s)", rec.Code, rec.Body.String())
	}

	// 3) Two DISTINCT approvers sign off.
	for _, who := range []string{"bob", "carol"} {
		rec = httptest.NewRecorder()
		api.ApproveApproval(rec, reqAs(http.MethodPost, "/api/approvals/"+approvalID+"/approve",
			tenantUser(who, models.DefaultTenantID, "approver"), approvalID, `{}`))
		if rec.Code != http.StatusOK {
			t.Fatalf("approve by %s status = %d, want 200 (body=%s)", who, rec.Code, rec.Body.String())
		}
	}

	// 4) The certificate is now delivered.
	rec = httptest.NewRecorder()
	api.GetApprovalCertificate(rec, reqAs(http.MethodGet, "/api/approvals/"+approvalID+"/certificate", rootUser(), approvalID, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("fetch-after-approval status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var resp models.IssueCertResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode issued cert: %v", err)
	}
	leaf, err := parseLeafPEM(resp.Certificate)
	if err != nil {
		t.Fatalf("issued certificate does not parse: %v", err)
	}
	if leaf.Subject.CommonName != "leaf.example.com" {
		t.Errorf("issued CN = %q, want leaf.example.com", leaf.Subject.CommonName)
	}
	if certs, _ := api.db.ListIssuedCertificates(caID); len(certs) != 1 {
		t.Fatalf("expected exactly one issued certificate, got %d", len(certs))
	}
}

// TestIssueDeniedNeverIssues: a rejected request never produces a certificate,
// and the certificate endpoint reports the denial (409).
func TestIssueDeniedNeverIssues(t *testing.T) {
	api, caID := approvalIssueAPI(t, true)

	rec := httptest.NewRecorder()
	api.IssueCertificate(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/issue", rootUser(), caID, issueBody(t, "hi-assurance", "denied.example.com")))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body=%s)", rec.Code, rec.Body.String())
	}
	approvalID := rec.Header().Get("X-Secsy-Approval-Id")

	rec = httptest.NewRecorder()
	api.RejectApproval(rec, reqAs(http.MethodPost, "/api/approvals/"+approvalID+"/reject",
		tenantUser("bob", models.DefaultTenantID, "approver"), approvalID, `{"comment":"no"}`))
	if rec.Code != http.StatusOK {
		t.Fatalf("reject status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	api.GetApprovalCertificate(rec, reqAs(http.MethodGet, "/api/approvals/"+approvalID+"/certificate", rootUser(), approvalID, ""))
	if rec.Code != http.StatusConflict {
		t.Fatalf("fetch-after-reject status = %d, want 409 (body=%s)", rec.Code, rec.Body.String())
	}
	if certs, _ := api.db.ListIssuedCertificates(caID); len(certs) != 0 {
		t.Fatalf("a rejected request must never issue, got %d certificates", len(certs))
	}
}

// TestSelfApprovalRejectedOverHTTP: the requester cannot approve their own
// issuance request.
func TestSelfApprovalRejectedOverHTTP(t *testing.T) {
	api, caID := approvalIssueAPI(t, true)
	requester := tenantUser("alice", models.DefaultTenantID, "issuer")
	// Grant alice both issue and approve so the denial is by IDENTITY, not capability.
	requester.TenantRoles[models.DefaultTenantID] = []string{"issuer", "approver"}

	rec := httptest.NewRecorder()
	api.IssueCertificate(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/issue", requester, caID, issueBody(t, "hi-assurance", "self.example.com")))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202 (body=%s)", rec.Code, rec.Body.String())
	}
	approvalID := rec.Header().Get("X-Secsy-Approval-Id")

	rec = httptest.NewRecorder()
	api.ApproveApproval(rec, reqAs(http.MethodPost, "/api/approvals/"+approvalID+"/approve", requester, approvalID, `{}`))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("self-approval status = %d, want 403 (body=%s)", rec.Code, rec.Body.String())
	}
	if certs, _ := api.db.ListIssuedCertificates(caID); len(certs) != 0 {
		t.Fatal("self-approval must not lead to issuance")
	}
}

// TestProfileWithoutRequireApprovalIssuesImmediately: an ordinary profile is
// unaffected by the gate even when the engine is enabled.
func TestProfileWithoutRequireApprovalIssuesImmediately(t *testing.T) {
	api, caID := approvalIssueAPI(t, true)

	rec := httptest.NewRecorder()
	api.IssueCertificate(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/issue", rootUser(), caID, issueBody(t, "server", "plain.example.com")))
	if rec.Code != http.StatusCreated {
		t.Fatalf("ungated profile status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if certs, _ := api.db.ListIssuedCertificates(caID); len(certs) != 1 {
		t.Fatalf("ungated profile must issue immediately, got %d certificates", len(certs))
	}
}

// TestRequireApprovalInertWhenGateDisabled: with the approvals engine off, a
// require_approval profile still issues immediately (the flag is inert).
func TestRequireApprovalInertWhenGateDisabled(t *testing.T) {
	api, caID := approvalIssueAPI(t, false) // no engine installed

	rec := httptest.NewRecorder()
	api.IssueCertificate(rec, reqAs(http.MethodPost, "/api/ca/"+caID+"/issue", rootUser(), caID, issueBody(t, "hi-assurance", "inert.example.com")))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 when the gate is disabled (body=%s)", rec.Code, rec.Body.String())
	}
	if certs, _ := api.db.ListIssuedCertificates(caID); len(certs) != 1 {
		t.Fatalf("require_approval must be inert without the engine, got %d certificates", len(certs))
	}
}

func parseLeafPEM(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errNoPEM
	}
	return x509.ParseCertificate(block.Bytes)
}

var errNoPEM = &pemError{}

type pemError struct{}

func (*pemError) Error() string { return "not valid PEM" }
