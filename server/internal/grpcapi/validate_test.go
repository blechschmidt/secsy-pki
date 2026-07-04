//go:build sqlite

package grpcapi

import (
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// TestGRPCValidateChain exercises the ValidateChain RPC end to end against a real
// software CA: a freshly issued leaf validates, and revoking it flips both the
// revocation dimension and the overall verdict.
func TestGRPCValidateChain(t *testing.T) {
	svc, caID := newGRPCIssuerService(t)
	ctx := withUser(&models.UserInfo{Subject: "root", IsRoot: true})

	issued, err := svc.IssueCertificate(ctx, &pkiv1.IssueCertificateRequest{
		CaId:    caID,
		CsrPem:  grpcCSR(t, "grpc-validate.example.com"),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	resp, err := svc.ValidateChain(ctx, &pkiv1.ValidateChainRequest{CaId: caID, LeafPem: issued.GetCertificatePem()})
	if err != nil {
		t.Fatalf("ValidateChain: %v", err)
	}
	if !resp.GetChainBuilt() || !resp.GetValid() {
		t.Fatalf("fresh leaf should be valid: built=%v valid=%v reasons=%v", resp.GetChainBuilt(), resp.GetValid(), resp.GetReasons())
	}
	if resp.GetDecision() != "valid" {
		t.Errorf("decision = %q, want valid", resp.GetDecision())
	}
	if got := grpcCheckStatus(resp, "revocation"); got != "pass" {
		t.Errorf("revocation check = %q, want pass", got)
	}
	if len(resp.GetChain()) != 2 {
		t.Errorf("chain length = %d, want 2 (leaf + anchor)", len(resp.GetChain()))
	}

	// Revoke and re-validate: the revocation dimension fails and the verdict flips.
	if _, err := svc.RevokeCertificate(ctx, &pkiv1.RevokeCertificateRequest{CaId: caID, Serial: issued.GetSerial(), Reason: "keyCompromise"}); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	resp, err = svc.ValidateChain(ctx, &pkiv1.ValidateChainRequest{CaId: caID, LeafPem: issued.GetCertificatePem()})
	if err != nil {
		t.Fatalf("ValidateChain(after revoke): %v", err)
	}
	if resp.GetValid() {
		t.Fatalf("revoked leaf must be invalid")
	}
	if got := grpcCheckStatus(resp, "revocation"); got != "fail" {
		t.Errorf("revocation check after revoke = %q, want fail", got)
	}
	leaf := resp.GetChain()[0]
	if leaf.GetRevocation() == nil || leaf.GetRevocation().GetState() != "revoked" {
		t.Errorf("leaf revocation state = %v, want revoked", leaf.GetRevocation())
	}

	// Skipping revocation drops the store lookup: the same leaf is then valid.
	resp, err = svc.ValidateChain(ctx, &pkiv1.ValidateChainRequest{CaId: caID, LeafPem: issued.GetCertificatePem(), SkipRevocation: true})
	if err != nil {
		t.Fatalf("ValidateChain(skip revocation): %v", err)
	}
	if !resp.GetValid() {
		t.Fatalf("with revocation skipped the (otherwise good) leaf should validate: %v", resp.GetReasons())
	}
	if got := grpcCheckStatus(resp, "revocation"); got != "skipped" {
		t.Errorf("revocation check when skipped = %q, want skipped", got)
	}
}

func grpcCheckStatus(resp *pkiv1.ValidateChainResponse, name string) string {
	for _, c := range resp.GetChecks() {
		if c.GetName() == name {
			return c.GetStatus()
		}
	}
	return ""
}
