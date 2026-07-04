package certlint

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// serverAuthCert builds a minimal, otherwise-clean serverAuth leaf for the
// TLS-feature checks. Tests mutate a copy per case.
func serverAuthCert() *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber:          big.NewInt(0).SetBytes([]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11}),
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             now,
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"leaf.example.com"},
		BasicConstraintsValid: true,
	}
}

// findingFor returns the finding with the given code, or nil.
func findingFor(res Result, code string) *Finding {
	for i := range res.Findings {
		if res.Findings[i].Code == code {
			return &res.Findings[i]
		}
	}
	return nil
}

func TestMustStapleLintRequire(t *testing.T) {
	tests := []struct {
		name     string
		policy   Policy
		mutate   func(c *x509.Certificate)
		wantCode string // "" = expect no must_staple/tls_feature finding
		wantMode Mode
	}{
		{
			name:     "require + serverAuth without extension warns",
			policy:   Policy{RequireMustStaple: true},
			mutate:   func(c *x509.Certificate) {},
			wantCode: CheckMustStaple,
			wantMode: ModeWarn,
		},
		{
			name:   "require + must-staple present passes",
			policy: Policy{RequireMustStaple: true},
			mutate: func(c *x509.Certificate) {
				c.ExtraExtensions = []pkix.Extension{pki.MustStapleExtension()}
			},
			wantCode: "",
		},
		{
			name:   "require + parsed Extensions form passes",
			policy: Policy{RequireMustStaple: true},
			mutate: func(c *x509.Certificate) {
				// Simulate an already-parsed certificate whose extensions live in
				// Extensions rather than ExtraExtensions.
				c.Extensions = []pkix.Extension{pki.MustStapleExtension()}
			},
			wantCode: "",
		},
		{
			name:   "require + clientAuth-only does not fire",
			policy: Policy{RequireMustStaple: true},
			mutate: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
			wantCode: "",
		},
		{
			name:     "not required + no extension does not fire",
			policy:   Policy{},
			mutate:   func(c *x509.Certificate) {},
			wantCode: "",
		},
		{
			name:     "require escalated to enforce via mode",
			policy:   Policy{RequireMustStaple: true, Mode: ModeEnforce},
			mutate:   func(c *x509.Certificate) {},
			wantCode: CheckMustStaple,
			wantMode: ModeEnforce,
		},
		{
			name: "require escalated to enforce via override",
			policy: Policy{
				RequireMustStaple: true,
				Overrides:         map[string]Mode{CheckMustStaple: ModeEnforce},
			},
			mutate:   func(c *x509.Certificate) {},
			wantCode: CheckMustStaple,
			wantMode: ModeEnforce,
		},
		{
			name:   "malformed tls feature extension flagged",
			policy: Policy{RequireMustStaple: true},
			mutate: func(c *x509.Certificate) {
				c.ExtraExtensions = []pkix.Extension{{
					Id:    pki.OIDTLSFeature,
					Value: []byte{0x02, 0x01, 0x05}, // bare INTEGER, not a SEQUENCE
				}}
			},
			// The extension is present-but-malformed → tls_feature (enforce); and
			// status_request is not decodable so must_staple also fires (warn). We
			// assert the malformed finding here.
			wantCode: CheckTLSFeature,
			wantMode: ModeEnforce,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := serverAuthCert()
			tc.mutate(cert)
			res := Lint(cert, tc.policy)

			f := findingFor(res, tc.wantCode)
			if tc.wantCode == "" {
				if got := findingFor(res, CheckMustStaple); got != nil {
					t.Errorf("unexpected must_staple finding: %+v", *got)
				}
				if got := findingFor(res, CheckTLSFeature); got != nil {
					t.Errorf("unexpected tls_feature finding: %+v", *got)
				}
				return
			}
			if f == nil {
				t.Fatalf("expected finding %q, got findings: %+v", tc.wantCode, res.Findings)
			}
			if f.Mode != tc.wantMode {
				t.Errorf("finding %q mode = %q, want %q", tc.wantCode, f.Mode, tc.wantMode)
			}
		})
	}
}

// TestMustStapleLintCleanBaseline confirms the require check never fires for a
// serverAuth cert that actually carries Must-Staple, across the default policy.
func TestMustStapleLintCleanBaseline(t *testing.T) {
	cert := serverAuthCert()
	cert.ExtraExtensions = []pkix.Extension{pki.MustStapleExtension()}
	res := Lint(cert, Policy{RequireMustStaple: true, Public: true})
	if got := findingFor(res, CheckMustStaple); got != nil {
		t.Errorf("must_staple finding on a compliant cert: %+v", *got)
	}
	if got := findingFor(res, CheckTLSFeature); got != nil {
		t.Errorf("tls_feature finding on a well-formed extension: %+v", *got)
	}
}
