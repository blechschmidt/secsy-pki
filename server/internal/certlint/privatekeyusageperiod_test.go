package certlint

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// validPKUPExtension returns a well-formed, non-critical
// id-ce-privateKeyUsagePeriod extension for the lint tests.
func validPKUPExtension(t *testing.T) pkix.Extension {
	t.Helper()
	nb := time.Now().Add(-time.Hour)
	ext, err := pki.PrivateKeyUsagePeriod{NotBefore: nb, NotAfter: nb.Add(90 * 24 * time.Hour)}.Extension()
	if err != nil {
		t.Fatalf("building privateKeyUsagePeriod: %v", err)
	}
	return ext
}

func TestCheckPrivateKeyUsagePeriod(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(c *x509.Certificate)
		wantCode string // "" = expect no finding
	}{
		{
			name:     "absent extension → no finding",
			mutate:   func(c *x509.Certificate) {},
			wantCode: "",
		},
		{
			name: "well-formed non-critical extension is recognized (no finding)",
			mutate: func(c *x509.Certificate) {
				c.ExtraExtensions = []pkix.Extension{validPKUPExtension(t)}
			},
			wantCode: "",
		},
		{
			name: "already-parsed (Extensions) form is recognized",
			mutate: func(c *x509.Certificate) {
				c.Extensions = []pkix.Extension{validPKUPExtension(t)}
			},
			wantCode: "",
		},
		{
			name: "critical extension is flagged",
			mutate: func(c *x509.Certificate) {
				ext := validPKUPExtension(t)
				ext.Critical = true
				c.ExtraExtensions = []pkix.Extension{ext}
			},
			wantCode: CheckPrivateKeyUsagePeriod,
		},
		{
			name: "malformed value is flagged",
			mutate: func(c *x509.Certificate) {
				c.ExtraExtensions = []pkix.Extension{{
					Id:    pki.OIDPrivateKeyUsagePeriod,
					Value: []byte{0x02, 0x01, 0x05}, // bare INTEGER, not a SEQUENCE
				}}
			},
			wantCode: CheckPrivateKeyUsagePeriod,
		},
		{
			name: "empty sequence (no bounds) is flagged",
			mutate: func(c *x509.Certificate) {
				c.ExtraExtensions = []pkix.Extension{{
					Id:    pki.OIDPrivateKeyUsagePeriod,
					Value: []byte{0x30, 0x00}, // SEQUENCE {} — neither bound present
				}}
			},
			wantCode: CheckPrivateKeyUsagePeriod,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := serverAuthCert()
			tc.mutate(cert)
			res := Lint(cert, Policy{})
			f := findingFor(res, CheckPrivateKeyUsagePeriod)
			if tc.wantCode == "" {
				if f != nil {
					t.Errorf("unexpected privateKeyUsagePeriod finding: %+v", *f)
				}
				return
			}
			if f == nil {
				t.Fatalf("expected a %q finding, got: %+v", tc.wantCode, res.Findings)
			}
		})
	}
}
