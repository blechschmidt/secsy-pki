//go:build sqlite

package grpcapi

import (
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/grpcapi/pkiv1"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// TestGRPCIssueQCStatementsPSD2Override covers the gRPC per-request PSD2 wiring
// (IssueCertificateRequest.psd2 → ca.IssueSpec.PSD2 → id-pe-qcStatements) on the
// built-in qualified-web (QWAC) profile, which permits per-request overrides.
func TestGRPCIssueQCStatementsPSD2Override(t *testing.T) {
	svc, caID := newGRPCIssuerService(t)
	ctx := withUser(&models.UserInfo{Subject: "root", IsRoot: true})

	resp, err := svc.IssueCertificate(ctx, &pkiv1.IssueCertificateRequest{
		CaId:    caID,
		CsrPem:  grpcCSR(t, "qwac.example.com"),
		Profile: "qualified-web",
		Psd2: &pkiv1.PSD2QCStatement{
			Roles:   []string{"PSP_AS", "PSP_IC"},
			NcaName: "Bundesanstalt für Finanzdienstleistungsaufsicht",
			NcaId:   "DE-BAFIN",
		},
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	cert, err := pki.ParseCertificatePEM([]byte(resp.GetCertificatePem()))
	if err != nil {
		t.Fatalf("parsing issued certificate: %v", err)
	}
	qc, present, err := pki.QCStatementsFromCertificate(cert)
	if err != nil || !present {
		t.Fatalf("QCStatementsFromCertificate = (present=%v, err=%v)", present, err)
	}
	if !qc.Compliance {
		t.Error("QWAC leaf missing QcCompliance")
	}
	if names := pki.QCTypeNames(qc.Types); len(names) != 1 || names[0] != "web" {
		t.Errorf("QcType = %v, want [web]", names)
	}
	if qc.PSD2 == nil {
		t.Fatal("PSD2 statement not stamped over gRPC")
	}
	if qc.PSD2.NCAID != "DE-BAFIN" {
		t.Errorf("NCAID = %q, want DE-BAFIN", qc.PSD2.NCAID)
	}
	if len(qc.PSD2.Roles) != 2 || qc.PSD2.Roles[0].Name != "PSP_AS" || qc.PSD2.Roles[1].Name != "PSP_IC" {
		t.Errorf("roles = %+v, want PSP_AS,PSP_IC", qc.PSD2.Roles)
	}

	// A PSD2 override on a non-QC profile (server) is rejected over gRPC.
	if _, err := svc.IssueCertificate(ctx, &pkiv1.IssueCertificateRequest{
		CaId:    caID,
		CsrPem:  grpcCSR(t, "plain.example.com"),
		Profile: "server",
		Psd2:    &pkiv1.PSD2QCStatement{Roles: []string{"PSP_AS"}, NcaName: "x", NcaId: "GB-x"},
	}); err == nil {
		t.Error("expected an error for a PSD2 override on a non-QC profile over gRPC")
	}
}
