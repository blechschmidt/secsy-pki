package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func generateTestCSR(t *testing.T, cn string, dnsNames []string, ips []net.IP) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{
		Subject:    pkix.Name{CommonName: cn},
		DNSNames:   dnsNames,
		IPAddresses: ips,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
}

func TestParseSANs(t *testing.T) {
	dns, ips, emails := ParseSANs("example.com, 10.0.0.1, user@example.com, *.test.io")
	if len(dns) != 2 || dns[0] != "example.com" || dns[1] != "*.test.io" {
		t.Errorf("dns = %v", dns)
	}
	if len(ips) != 1 || !ips[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("ips = %v", ips)
	}
	if len(emails) != 1 || emails[0] != "user@example.com" {
		t.Errorf("emails = %v", emails)
	}

	// Empty
	dns, ips, emails = ParseSANs("")
	if len(dns)+len(ips)+len(emails) != 0 {
		t.Error("expected empty")
	}
}

func TestFormatSubject(t *testing.T) {
	name := FormatSubject(map[string]string{
		"CN": "test.example.com",
		"O":  "Test Corp",
		"OU": "Engineering",
		"C":  "US",
		"ST": "California",
		"L":  "San Francisco",
	})
	if name.CommonName != "test.example.com" {
		t.Errorf("CN = %q", name.CommonName)
	}
	if len(name.Organization) != 1 || name.Organization[0] != "Test Corp" {
		t.Errorf("O = %v", name.Organization)
	}
	if len(name.Country) != 1 || name.Country[0] != "US" {
		t.Errorf("C = %v", name.Country)
	}
}

func TestX509KeyUsageFromString(t *testing.T) {
	if _, ok := X509KeyUsageFromString["digitalSignature"]; !ok {
		t.Error("missing digitalSignature")
	}
	if _, ok := X509KeyUsageFromString["keyEncipherment"]; !ok {
		t.Error("missing keyEncipherment")
	}
	if _, ok := X509KeyUsageFromString["certSign"]; !ok {
		t.Error("missing certSign")
	}
}

func TestX509ExtKeyUsageFromString(t *testing.T) {
	if _, ok := X509ExtKeyUsageFromString["serverAuth"]; !ok {
		t.Error("missing serverAuth")
	}
	if _, ok := X509ExtKeyUsageFromString["clientAuth"]; !ok {
		t.Error("missing clientAuth")
	}
	if _, ok := X509ExtKeyUsageFromString["codeSigning"]; !ok {
		t.Error("missing codeSigning")
	}
}

func TestCSRParseInvalid(t *testing.T) {
	// Not a CSR
	_, _, err := SignX509Certificate(nil, []byte("not a pem"), time.Time{}, nil, nil, false, nil)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}

	// Wrong PEM type
	wrongPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})
	_, _, err = SignX509Certificate(nil, wrongPEM, time.Time{}, nil, nil, false, nil)
	if err == nil {
		t.Fatal("expected error for wrong PEM type")
	}
}
