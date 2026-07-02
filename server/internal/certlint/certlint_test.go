package certlint

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// randomSerial returns a 128-bit random serial like the real issuer allocates.
func randomSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	if n.Sign() == 0 {
		n = big.NewInt(1)
	}
	return n
}

// baseCert builds a structurally valid TLS server leaf that passes every check
// under both an internal and a public policy. Tests mutate a copy per case.
func baseCert(t *testing.T) *x509.Certificate {
	t.Helper()
	now := time.Now()
	return &x509.Certificate{
		SerialNumber:          randomSerial(t),
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             now,
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"leaf.example.com", "www.example.com"},
		BasicConstraintsValid: true,
	}
}

// hasCode reports whether res contains a finding with the given code.
func hasCode(res Result, code string) bool {
	for _, f := range res.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestLintChecks(t *testing.T) {
	tests := []struct {
		name     string
		policy   Policy
		mutate   func(c *x509.Certificate)
		wantCode string // "" means expect a clean pass
		wantOK   bool   // whether the result should have no findings
	}{
		{
			name:   "valid internal cert passes",
			policy: Policy{},
			mutate: func(c *x509.Certificate) {},
			wantOK: true,
		},
		{
			name:   "valid public cert passes",
			policy: Policy{Public: true, MaxValidity: 397 * 24 * time.Hour},
			mutate: func(c *x509.Certificate) {},
			wantOK: true,
		},
		{
			name:     "zero serial rejected",
			policy:   Policy{},
			mutate:   func(c *x509.Certificate) { c.SerialNumber = big.NewInt(0) },
			wantCode: CheckSerialPositive,
		},
		{
			name:     "low-entropy serial rejected",
			policy:   Policy{},
			mutate:   func(c *x509.Certificate) { c.SerialNumber = big.NewInt(42) },
			wantCode: CheckSerialEntropy,
		},
		{
			name:     "notAfter before notBefore rejected",
			policy:   Policy{},
			mutate:   func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(-time.Hour) },
			wantCode: CheckValidityOrder,
		},
		{
			name:     "validity exceeds profile cap",
			policy:   Policy{MaxValidity: 30 * 24 * time.Hour},
			mutate:   func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(90 * 24 * time.Hour) },
			wantCode: CheckValidityCap,
		},
		{
			name:   "validity within profile cap plus grace passes",
			policy: Policy{MaxValidity: 90 * 24 * time.Hour},
			mutate: func(c *x509.Certificate) { c.NotBefore = c.NotBefore.Add(-5 * time.Minute) },
			wantOK: true,
		},
		{
			name:     "public 398-day cap enforced",
			policy:   Policy{Public: true},
			mutate:   func(c *x509.Certificate) { c.NotAfter = c.NotBefore.Add(400 * 24 * time.Hour) },
			wantCode: CheckValidityTLSMax,
		},
		{
			name:     "leaf asserting CA rejected",
			policy:   Policy{},
			mutate:   func(c *x509.Certificate) { c.IsCA = true },
			wantCode: CheckLeafNotCA,
		},
		{
			name:     "leaf with keyCertSign rejected",
			policy:   Policy{},
			mutate:   func(c *x509.Certificate) { c.KeyUsage |= x509.KeyUsageCertSign },
			wantCode: CheckKeyUsageLeaf,
		},
		{
			name:     "serverAuth without suitable KU rejected",
			policy:   Policy{},
			mutate:   func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageContentCommitment },
			wantCode: CheckEKUKUConsistency,
		},
		{
			name:   "codeSigning without digitalSignature rejected",
			policy: Policy{},
			mutate: func(c *x509.Certificate) {
				c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
				c.KeyUsage = x509.KeyUsageKeyEncipherment
			},
			wantCode: CheckEKUKUConsistency,
		},
		{
			name:     "public cert without SAN rejected",
			policy:   Policy{Public: true},
			mutate:   func(c *x509.Certificate) { c.DNSNames = nil },
			wantCode: CheckSANPresent,
		},
		{
			name:     "public cert CN not in SAN rejected",
			policy:   Policy{Public: true},
			mutate:   func(c *x509.Certificate) { c.DNSNames = []string{"other.example.com"} },
			wantCode: CheckCNInSAN,
		},
		{
			name:   "internal cert CN not in SAN allowed",
			policy: Policy{},
			mutate: func(c *x509.Certificate) { c.DNSNames = []string{"other.example.com"} },
			wantOK: true,
		},
		{
			name:   "public cert with internal TLD rejected",
			policy: Policy{Public: true},
			mutate: func(c *x509.Certificate) {
				c.Subject.CommonName = "host.local"
				c.DNSNames = []string{"host.local"}
			},
			wantCode: CheckInternalName,
		},
		{
			name:   "public cert with single-label name rejected",
			policy: Policy{Public: true},
			mutate: func(c *x509.Certificate) {
				c.Subject.CommonName = "intranet"
				c.DNSNames = []string{"intranet"}
			},
			wantCode: CheckInternalName,
		},
		{
			name:   "public cert with underscore rejected",
			policy: Policy{Public: true},
			mutate: func(c *x509.Certificate) {
				c.Subject.CommonName = "my_host.example.com"
				c.DNSNames = []string{"my_host.example.com"}
			},
			wantCode: CheckInternalName,
		},
		{
			name:   "public cert with private IP SAN rejected",
			policy: Policy{Public: true},
			mutate: func(c *x509.Certificate) {
				c.DNSNames = []string{"leaf.example.com"}
				c.IPAddresses = []net.IP{net.ParseIP("10.1.2.3")}
			},
			wantCode: CheckReservedIP,
		},
		{
			name:   "internal cert with private IP SAN allowed",
			policy: Policy{},
			mutate: func(c *x509.Certificate) {
				c.IPAddresses = []net.IP{net.ParseIP("10.1.2.3")}
			},
			wantOK: true,
		},
		{
			name:   "public cert with double wildcard rejected",
			policy: Policy{Public: true},
			mutate: func(c *x509.Certificate) {
				c.Subject.CommonName = ""
				c.DNSNames = []string{"*.*.example.com"}
			},
			wantCode: CheckWildcard,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cert := baseCert(t)
			tc.mutate(cert)
			res := Lint(cert, tc.policy)

			if tc.wantOK {
				if !res.OK() {
					t.Fatalf("expected clean pass, got findings: %v", res.Summary())
				}
				return
			}
			if !hasCode(res, tc.wantCode) {
				t.Fatalf("expected finding %q, got: %v", tc.wantCode, res.Summary())
			}
		})
	}
}

// TestModeControlsEnforcement verifies enforce vs warn: the same violation
// blocks under enforce and only warns under a warn policy or per-check override.
func TestModeControlsEnforcement(t *testing.T) {
	cert := baseCert(t)
	cert.SerialNumber = big.NewInt(7) // low entropy

	enforced := Lint(cert, Policy{})
	if !enforced.HasErrors() {
		t.Fatalf("enforce policy should block low-entropy serial: %v", enforced.Summary())
	}
	if enforced.Err() == nil {
		t.Fatal("Err() should be non-nil when there are enforce findings")
	}

	warned := Lint(cert, Policy{Mode: ModeWarn})
	if warned.HasErrors() {
		t.Fatalf("warn policy should not block: %v", warned.Summary())
	}
	if len(warned.Warnings()) == 0 {
		t.Fatal("warn policy should still report the finding as a warning")
	}
	if warned.Err() != nil {
		t.Fatalf("Err() should be nil when only warnings: %v", warned.Err())
	}

	override := Lint(cert, Policy{Overrides: map[string]Mode{CheckSerialEntropy: ModeWarn}})
	if override.HasErrors() {
		t.Fatalf("per-check warn override should not block: %v", override.Summary())
	}
}

// TestCertificateFromLeaf verifies the template view mirrors the leaf request
// fields the linter inspects, so pre-issuance linting sees the real template.
func TestCertificateFromLeaf(t *testing.T) {
	now := time.Now()
	req := pki.LeafCertRequest{
		Subject:     pkix.Name{CommonName: "leaf.example.com"},
		Serial:      randomSerial(t),
		NotBefore:   now,
		NotAfter:    now.Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"leaf.example.com"},
		IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		URIs:        []string{"spiffe://example.com/leaf"},
	}
	cert, err := CertificateFromLeaf(req)
	if err != nil {
		t.Fatalf("CertificateFromLeaf: %v", err)
	}
	if cert.SerialNumber.Cmp(req.Serial) != 0 {
		t.Error("serial not carried over")
	}
	if cert.Subject.CommonName != "leaf.example.com" {
		t.Error("subject not carried over")
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://example.com/leaf" {
		t.Errorf("URI SAN not parsed: %v", cert.URIs)
	}
	if res := Lint(cert, Policy{MaxValidity: 397 * 24 * time.Hour}); !res.OK() {
		t.Fatalf("expected valid internal leaf to pass: %v", res.Summary())
	}

	// A bad URI SAN must surface as an error rather than a signed certificate.
	if _, err := CertificateFromLeaf(pki.LeafCertRequest{URIs: []string{"://bad uri"}}); err == nil {
		t.Error("expected error for malformed URI SAN")
	}
}
