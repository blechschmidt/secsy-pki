//go:build sqlite

package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// qcExtension returns the parsed id-pe-qcStatements extension a leaf carries, or
// nil when absent, asserting it is non-critical when present.
func qcExtension(t *testing.T, cert *x509.Certificate) *pkix.Extension {
	t.Helper()
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(pki.OIDQCStatements) {
			if cert.Extensions[i].Critical {
				t.Error("id-pe-qcStatements marked critical; ETSI EN 319 412-5 requires non-critical")
			}
			return &cert.Extensions[i]
		}
	}
	return nil
}

func TestQCStatementsIssuance(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "qc")

	issue := func(t *testing.T, profile string, psd2 *models.PSD2QCStatement) (*x509.Certificate, error) {
		t.Helper()
		res, err := mgr.IssueCertificate(ctx, IssueSpec{
			CAID:    root.ID,
			CSRPEM:  makeCSR(t, "qc.example.com", []string{"qc.example.com"}),
			Profile: profile,
			PSD2:    psd2,
		})
		if err != nil {
			return nil, err
		}
		return res.Certificate, nil
	}

	// The plain server profile emits no qcStatements extension.
	t.Run("non-qc-profile-omits", func(t *testing.T) {
		cert, err := issue(t, "server", nil)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if ext := qcExtension(t, cert); ext != nil {
			t.Errorf("server profile stamped qcStatements: % x", ext.Value)
		}
	})

	// The built-in qualified-esign profile stamps QcCompliance + QcType esign + QcSSCD.
	t.Run("qualified-esign", func(t *testing.T) {
		cert, err := issue(t, "qualified-esign", nil)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		ext := qcExtension(t, cert)
		if ext == nil {
			t.Fatal("qualified-esign did not stamp qcStatements")
		}
		qc, err := pki.ParseQCStatements(ext.Value)
		if err != nil {
			t.Fatalf("ParseQCStatements: %v", err)
		}
		if !qc.Compliance || !qc.SSCD {
			t.Errorf("want Compliance+SSCD, got %+v", qc)
		}
		if names := pki.QCTypeNames(qc.Types); len(names) != 1 || names[0] != "esign" {
			t.Errorf("QcType = %v, want [esign]", names)
		}
		if qc.PSD2 != nil {
			t.Errorf("unexpected PSD2 statement: %+v", qc.PSD2)
		}
	})

	// qualified-web permits a per-request PSD2 override.
	t.Run("qualified-web-with-psd2-override", func(t *testing.T) {
		cert, err := issue(t, "qualified-web", &models.PSD2QCStatement{
			Roles:   []string{"PSP_AS", "PSP_PI"},
			NCAName: "Financial Conduct Authority",
			NCAID:   "GB-FCA",
		})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		ext := qcExtension(t, cert)
		if ext == nil {
			t.Fatal("qualified-web did not stamp qcStatements")
		}
		qc, err := pki.ParseQCStatements(ext.Value)
		if err != nil {
			t.Fatalf("ParseQCStatements: %v", err)
		}
		if !qc.Compliance {
			t.Error("want QcCompliance on qualified-web")
		}
		if names := pki.QCTypeNames(qc.Types); len(names) != 1 || names[0] != "web" {
			t.Errorf("QcType = %v, want [web]", names)
		}
		if qc.PSD2 == nil {
			t.Fatal("PSD2 override was not stamped")
		}
		if qc.PSD2.NCAID != "GB-FCA" || qc.PSD2.NCAName != "Financial Conduct Authority" {
			t.Errorf("PSD2 NCA = %q/%q, want Financial Conduct Authority/GB-FCA", qc.PSD2.NCAName, qc.PSD2.NCAID)
		}
		gotRoles := []string{}
		for _, r := range qc.PSD2.Roles {
			gotRoles = append(gotRoles, r.Name)
		}
		if len(gotRoles) != 2 || gotRoles[0] != "PSP_AS" || gotRoles[1] != "PSP_PI" {
			t.Errorf("PSD2 roles = %v, want [PSP_AS PSP_PI]", gotRoles)
		}
	})

	// qualified-web without an override still stamps the profile's base statements.
	t.Run("qualified-web-no-override", func(t *testing.T) {
		cert, err := issue(t, "qualified-web", nil)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		ext := qcExtension(t, cert)
		if ext == nil {
			t.Fatal("qualified-web did not stamp qcStatements")
		}
		qc, _ := pki.ParseQCStatements(ext.Value)
		if qc.PSD2 != nil {
			t.Errorf("did not expect a PSD2 statement without an override: %+v", qc.PSD2)
		}
	})

	// A PSD2 override on a non-QC profile is a hard error (never fabricate QC).
	t.Run("psd2-on-non-qc-profile-rejected", func(t *testing.T) {
		_, err := issue(t, "server", &models.PSD2QCStatement{Roles: []string{"PSP_AS"}, NCAName: "x", NCAID: "GB-x"})
		if err == nil {
			t.Fatal("expected an error for a PSD2 override on a non-QC profile")
		}
	})

	// A PSD2 override on a QC profile that forbids overrides is rejected
	// (qualified-esign has allow_psd2_override=false).
	t.Run("psd2-override-not-permitted-rejected", func(t *testing.T) {
		_, err := issue(t, "qualified-esign", &models.PSD2QCStatement{Roles: []string{"PSP_AS"}, NCAName: "x", NCAID: "GB-x"})
		if err == nil {
			t.Fatal("expected an error for a PSD2 override on a profile that forbids it")
		}
	})

	// An unknown PSD2 role is rejected.
	t.Run("unknown-psd2-role-rejected", func(t *testing.T) {
		_, err := issue(t, "qualified-web", &models.PSD2QCStatement{Roles: []string{"PSP_XX"}, NCAName: "x", NCAID: "GB-x"})
		if err == nil {
			t.Fatal("expected an error for an unknown PSD2 role")
		}
	})

	// The non-mutating preview reports the qcstatements gate verdict (pass with a
	// summary for a QC profile, skipped for a non-QC profile, fail on a bad
	// override) without signing anything.
	t.Run("preview-gate", func(t *testing.T) {
		gate := func(t *testing.T, profile string, psd2 *models.PSD2QCStatement) GateVerdict {
			t.Helper()
			res, err := mgr.PreviewIssuance(ctx, PreviewSpec{
				CAID:    root.ID,
				CSRPEM:  makeCSR(t, "qc-preview.example.com", []string{"qc-preview.example.com"}),
				Profile: profile,
				PSD2:    psd2,
			})
			if err != nil {
				t.Fatalf("PreviewIssuance: %v", err)
			}
			for _, g := range res.Gates {
				if g.Name == GateQCStatements {
					return g
				}
			}
			t.Fatalf("no qcstatements gate in preview for profile %q", profile)
			return GateVerdict{}
		}

		if g := gate(t, "server", nil); g.Status != GateSkipped {
			t.Errorf("server qcstatements gate = %q, want skipped", g.Status)
		}
		if g := gate(t, "qualified-esign", nil); g.Status != GatePass || !strings.Contains(g.Reason, "QcCompliance") {
			t.Errorf("qualified-esign gate = %q/%q, want pass with a QcCompliance summary", g.Status, g.Reason)
		}
		if g := gate(t, "qualified-web", &models.PSD2QCStatement{Roles: []string{"PSP_AS"}, NCAName: "n", NCAID: "GB-FCA"}); g.Status != GatePass || !strings.Contains(g.Reason, "PSD2") {
			t.Errorf("qualified-web+psd2 gate = %q/%q, want pass with a PSD2 summary", g.Status, g.Reason)
		}
		if g := gate(t, "server", &models.PSD2QCStatement{Roles: []string{"PSP_AS"}, NCAName: "n", NCAID: "GB-x"}); g.Status != GateFail {
			t.Errorf("server+psd2 gate = %q, want fail", g.Status)
		}
	})
}

// TestQCStatementsCustomProfileValidation covers the profile-install validation
// of the qcstatements block.
func TestQCStatementsCustomProfileValidation(t *testing.T) {
	resetCustomProfiles(t)
	cases := []struct {
		name    string
		cfg     *QCStatementsConfig
		wantErr bool
	}{
		{"empty block", &QCStatementsConfig{}, true},
		{"compliance only", &QCStatementsConfig{Compliance: true}, false},
		{"bad type", &QCStatementsConfig{Type: "bogus"}, true},
		{"good web type", &QCStatementsConfig{Type: "web"}, false},
		{"bad pds language", &QCStatementsConfig{PDS: []QCPDSLocation{{URL: "https://x", Language: "eng"}}}, true},
		{"good pds", &QCStatementsConfig{PDS: []QCPDSLocation{{URL: "https://x", Language: "EN"}}}, false},
		{"psd2 missing nca", &QCStatementsConfig{PSD2: &QCPSD2Config{Roles: []string{"PSP_AS"}}}, true},
		{"psd2 unknown role", &QCStatementsConfig{PSD2: &QCPSD2Config{Roles: []string{"PSP_ZZ"}, NCAName: "n", NCAID: "i"}}, true},
		{"psd2 ok", &QCStatementsConfig{PSD2: &QCPSD2Config{Roles: []string{"PSP_AS"}, NCAName: "n", NCAID: "GB-i"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := SetCustomProfiles([]Profile{{
				Name:         "qc-custom",
				KeyUsages:    []string{"digitalSignature"},
				QCStatements: tc.cfg,
			}})
			if tc.wantErr && err == nil {
				t.Error("expected a validation error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
	resetCustomProfiles(t)
}
