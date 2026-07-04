package certlint

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// validQCExtension returns a well-formed, non-critical id-pe-qcStatements
// extension for the lint tests.
func validQCExtension(t *testing.T) pkix.Extension {
	t.Helper()
	ext, err := pki.QCStatements{Compliance: true, SSCD: true}.Extension()
	if err != nil {
		t.Fatalf("building qcStatements: %v", err)
	}
	return ext
}

func TestCheckQCStatements(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(c *x509.Certificate)
		wantCode string // "" = expect no qcstatements finding
	}{
		{
			name:     "absent extension → no finding",
			mutate:   func(c *x509.Certificate) {},
			wantCode: "",
		},
		{
			name: "well-formed non-critical extension is recognized (no finding)",
			mutate: func(c *x509.Certificate) {
				c.ExtraExtensions = []pkix.Extension{validQCExtension(t)}
			},
			wantCode: "",
		},
		{
			name: "already-parsed (Extensions) form is recognized",
			mutate: func(c *x509.Certificate) {
				c.Extensions = []pkix.Extension{validQCExtension(t)}
			},
			wantCode: "",
		},
		{
			name: "critical extension is flagged",
			mutate: func(c *x509.Certificate) {
				ext := validQCExtension(t)
				ext.Critical = true
				c.ExtraExtensions = []pkix.Extension{ext}
			},
			wantCode: CheckQCStatements,
		},
		{
			name: "malformed value is flagged",
			mutate: func(c *x509.Certificate) {
				c.ExtraExtensions = []pkix.Extension{{
					Id:    pki.OIDQCStatements,
					Value: []byte{0x02, 0x01, 0x05}, // bare INTEGER, not a SEQUENCE
				}}
			},
			wantCode: CheckQCStatements,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := serverAuthCert()
			tc.mutate(cert)
			res := Lint(cert, Policy{})
			f := findingFor(res, CheckQCStatements)
			if tc.wantCode == "" {
				if f != nil {
					t.Errorf("unexpected qcstatements finding: %+v", *f)
				}
				return
			}
			if f == nil {
				t.Fatalf("expected a %q finding, got: %+v", tc.wantCode, res.Findings)
			}
		})
	}
}
