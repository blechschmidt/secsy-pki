package nameconstraints

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func mustConfig(t *testing.T, cfg Config) Constraints {
	t.Helper()
	c, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return c
}

func TestBuildParseRoundTrip(t *testing.T) {
	cfg := Config{
		Permitted: SubtreeConfig{
			DNS:      []string{"internal.example.com"},
			IP:       []string{"10.0.0.0/8"},
			Email:    []string{".corp.example.com"},
			URI:      []string{"example.com"},
			DirNames: []string{"O=Acme,C=US"},
		},
		Excluded: SubtreeConfig{
			DNS: []string{"secret.internal.example.com"},
		},
	}
	c := mustConfig(t, cfg)
	ext, ok, err := c.Extension()
	if err != nil || !ok {
		t.Fatalf("Extension: ok=%v err=%v", ok, err)
	}
	if !ext.Critical {
		t.Errorf("expected critical extension by default")
	}

	parsed, err := ParseExtension(ext.Value, ext.Critical)
	if err != nil {
		t.Fatalf("ParseExtension: %v", err)
	}
	if got := parsed.Permitted.DNS; len(got) != 1 || got[0] != "internal.example.com" {
		t.Errorf("permitted DNS round-trip = %v", got)
	}
	if got := parsed.Excluded.DNS; len(got) != 1 || got[0] != "secret.internal.example.com" {
		t.Errorf("excluded DNS round-trip = %v", got)
	}
	if len(parsed.Permitted.IP) != 1 || parsed.Permitted.IP[0].String() != "10.0.0.0/8" {
		t.Errorf("permitted IP round-trip = %v", parsed.Permitted.IP)
	}
	if len(parsed.Permitted.Email) != 1 || parsed.Permitted.Email[0] != ".corp.example.com" {
		t.Errorf("permitted email round-trip = %v", parsed.Permitted.Email)
	}
	if len(parsed.Permitted.URI) != 1 || parsed.Permitted.URI[0] != "example.com" {
		t.Errorf("permitted URI round-trip = %v", parsed.Permitted.URI)
	}
	if len(parsed.Permitted.DirNames) != 1 {
		t.Fatalf("permitted dirName round-trip = %v", parsed.Permitted.DirNames)
	}
	if o := parsed.Permitted.DirNames[0].Organization; len(o) != 1 || o[0] != "Acme" {
		t.Errorf("permitted dirName O = %v", o)
	}
}

// TestParsedByStdlib confirms crypto/x509 parses the extension we emit for the
// name forms it understands (DNS/IP/email/URI), so third-party verifiers do too.
func TestParsedByStdlib(t *testing.T) {
	c := mustConfig(t, Config{
		Permitted: SubtreeConfig{DNS: []string{"example.com"}, IP: []string{"192.0.2.0/24"}},
		Excluded:  SubtreeConfig{DNS: []string{"bad.example.com"}},
	})
	ext, _, err := c.Extension()
	if err != nil {
		t.Fatal(err)
	}
	der := selfSignedWithExt(t, ext)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("stdlib parse: %v", err)
	}
	if len(cert.PermittedDNSDomains) != 1 || cert.PermittedDNSDomains[0] != "example.com" {
		t.Errorf("stdlib PermittedDNSDomains = %v", cert.PermittedDNSDomains)
	}
	if len(cert.ExcludedDNSDomains) != 1 || cert.ExcludedDNSDomains[0] != "bad.example.com" {
		t.Errorf("stdlib ExcludedDNSDomains = %v", cert.ExcludedDNSDomains)
	}
	if len(cert.PermittedIPRanges) != 1 || cert.PermittedIPRanges[0].String() != "192.0.2.0/24" {
		t.Errorf("stdlib PermittedIPRanges = %v", cert.PermittedIPRanges)
	}
}

func selfSignedWithExt(t *testing.T, ext pkix.Extension) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtraExtensions:       []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func TestValidate(t *testing.T) {
	c := mustConfig(t, Config{
		Permitted: SubtreeConfig{
			DNS:   []string{"internal.example.com"},
			IP:    []string{"10.0.0.0/8"},
			Email: []string{"corp.example.com"},
			URI:   []string{"apps.example.com"},
		},
		Excluded: SubtreeConfig{
			DNS: []string{"secret.internal.example.com"},
		},
	})

	tests := []struct {
		name   string
		id     Identity
		wantOK bool
	}{
		{"dns in scope", Identity{DNSNames: []string{"host.internal.example.com"}}, true},
		{"dns exact", Identity{DNSNames: []string{"internal.example.com"}}, true},
		{"dns out of scope", Identity{DNSNames: []string{"host.other.com"}}, false},
		{"dns excluded", Identity{DNSNames: []string{"secret.internal.example.com"}}, false},
		{"dns excluded subdomain", Identity{DNSNames: []string{"a.secret.internal.example.com"}}, false},
		{"ip in scope", Identity{IPs: []net.IP{net.ParseIP("10.1.2.3")}}, true},
		{"ip out of scope", Identity{IPs: []net.IP{net.ParseIP("192.168.1.1")}}, false},
		{"email host", Identity{Emails: []string{"alice@corp.example.com"}}, true},
		{"email subdomain rejected", Identity{Emails: []string{"a@sub.corp.example.com"}}, false},
		{"uri in scope", Identity{URIs: []string{"https://apps.example.com/x"}}, true},
		{"uri out of scope", Identity{URIs: []string{"https://evil.com/x"}}, false},
		{"cn hostname in scope", Identity{Subject: pkix.Name{CommonName: "web.internal.example.com"}}, true},
		{"cn hostname out of scope", Identity{Subject: pkix.Name{CommonName: "web.other.com"}}, false},
		{"cn non-hostname ignored", Identity{Subject: pkix.Name{CommonName: "Acme Device 7"}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := c.Validate(tt.id)
			if res.Permitted() != tt.wantOK {
				t.Errorf("Validate() permitted=%v want %v (%s)", res.Permitted(), tt.wantOK, res.Summary())
			}
		})
	}
}

func TestValidateDirName(t *testing.T) {
	c := mustConfig(t, Config{
		Permitted: SubtreeConfig{DirNames: []string{"O=Acme,C=US"}},
	})
	inScope := Identity{Subject: pkix.Name{
		CommonName:   "device",
		Organization: []string{"Acme"},
		Country:      []string{"US"},
	}}
	if res := c.Validate(inScope); !res.Permitted() {
		t.Errorf("in-scope dirName rejected: %s", res.Summary())
	}
	outScope := Identity{Subject: pkix.Name{
		CommonName:   "device",
		Organization: []string{"Evil"},
		Country:      []string{"US"},
	}}
	if res := c.Validate(outScope); res.Permitted() {
		t.Errorf("out-of-scope dirName accepted")
	}
}

func TestEmptyConstraintsNoExtension(t *testing.T) {
	c, err := Config{}.Build()
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsZero() {
		t.Errorf("empty config should be zero")
	}
	if _, ok, _ := c.Extension(); ok {
		t.Errorf("empty constraints should emit no extension")
	}
}
