package caext

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// TestFullExtensionSet_OpenSSLParse issues a CA certificate carrying the whole
// configurable extension set and hands it to a real `openssl x509 -text`.
//
// Go's own parser is not an independent witness: the same standard library
// encoded most of this. OpenSSL is — it decodes each extension's inner ASN.1 and
// prints the contents, so a structurally wrong value shows up as an "unable to
// print"/"BAD" rendering or a non-zero exit rather than passing unnoticed. Every
// extension whose OID OpenSSL 3 knows is asserted on by the label it prints.
func TestFullExtensionSet_OpenSSLParse(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH")
	}

	inhibit := 0
	cfg := &Config{
		KeyUsages:           []string{"certSign", "crlSign"},
		ExtKeyUsages:        []string{"serverAuth", "clientAuth", "ocspSigning"},
		ExtKeyUsageCritical: true,
		SubjectAltName: &GeneralNamesConfig{
			DNS:           []string{"ca.example.test"},
			IP:            []string{"192.0.2.10", "2001:db8::1"},
			Email:         []string{"pki@example.test"},
			URI:           []string{"https://ca.example.test/"},
			UPN:           []string{"svc@CORP.EXAMPLE"},
			DirNames:      []string{"O=Example Org,C=DE"},
			RegisteredIDs: []string{"1.3.6.1.4.1.99999.9"},
		},
		IssuerAltName:              &GeneralNamesConfig{URI: []string{"https://root.example.test/"}},
		CRLDistributionPoints:      []string{"http://crl.example.test/root.crl"},
		FreshestCRL:                []string{"http://crl.example.test/delta.crl"},
		OCSPServers:                []string{"http://ocsp.example.test/"},
		CAIssuers:                  []string{"http://pki.example.test/root.cer"},
		CARepositories:             []string{"http://pki.example.test/certs/"},
		TimestampServers:           []string{"http://tsa.example.test/"},
		InhibitAnyPolicy:           &inhibit,
		PrivateKeyUsagePeriod:      &PrivateKeyUsagePeriodConfig{Duration: "180d"},
		SubjectDirectoryAttributes: []AttributeConfig{{OID: "1.3.6.1.5.5.7.9.4", Encoding: "printable", Values: []string{"DE"}}},
		MustStaple:                 true,
		OCSPNoCheck:                true,
		NetscapeComment:            "Northwind issuing CA",
		NetscapeCertType:           []string{"sslCA", "smimeCA"},
		Custom: []CustomExtension{
			{OID: "1.3.6.1.4.1.99999.100", Encoding: "utf8", Value: "enterprise marker"},
		},
	}

	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := notBefore.Add(3650 * 24 * time.Hour)
	built, err := cfg.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := built.ApplyValidity(notBefore, notAfter); err != nil {
		t.Fatalf("ApplyValidity: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	der, err := pki.CreateCACertificate(key, nil, pki.CACertRequest{
		Subject:               pkix.Name{CommonName: "Northwind Issuing CA", Organization: []string{"Northwind"}},
		PublicKey:             &key.PublicKey,
		Serial:                big.NewInt(1),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              built.KeyUsage,
		CRLDistributionPoints: built.CRLDistributionPoints,
		OCSPServer:            built.OCSPServers,
		IssuingCertificateURL: built.CAIssuers,
		ExtraExtensions:       built.Extensions,
	})
	if err != nil {
		t.Fatalf("CreateCACertificate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing certificate: %v", err)
	}
	out, err := exec.Command(openssl, "x509", "-in", path, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -text failed: %v\n%s", err, out)
	}
	text := string(out)

	// Every extension OpenSSL has a printer for, by the label it prints.
	for _, want := range []string{
		"X509v3 Key Usage: critical",
		"Certificate Sign, CRL Sign",
		"X509v3 Extended Key Usage: critical",
		"TLS Web Server Authentication",
		"OCSP Signing",
		"X509v3 Subject Alternative Name",
		"DNS:ca.example.test",
		"IP Address:192.0.2.10",
		"IP Address:2001:DB8:0:0:0:0:0:1",
		"email:pki@example.test",
		"URI:https://ca.example.test/",
		"DirName:/O=Example Org/C=DE",
		"Registered ID:1.3.6.1.4.1.99999.9",
		"othername:",
		"X509v3 Issuer Alternative Name",
		"URI:https://root.example.test/",
		"X509v3 CRL Distribution Points",
		"URI:http://crl.example.test/root.crl",
		"X509v3 Freshest CRL",
		"URI:http://crl.example.test/delta.crl",
		"Authority Information Access",
		"OCSP - URI:http://ocsp.example.test/",
		"CA Issuers - URI:http://pki.example.test/root.cer",
		"Subject Information Access",
		"CA Repository - URI:http://pki.example.test/certs/",
		"AD Time Stamping - URI:http://tsa.example.test/",
		"X509v3 Inhibit Any Policy: critical",
		"X509v3 Private Key Usage Period",
		"X509v3 Subject Directory Attributes",
		"TLS Feature",
		"status_request",
		"OCSP No Check",
		"Netscape Comment",
		"Northwind issuing CA",
		"Netscape Cert Type",
		"SSL CA, S/MIME CA",
		"1.3.6.1.4.1.99999.100",
		"X509v3 Basic Constraints: critical",
		"CA:TRUE",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl output does not contain %q", want)
		}
	}
	// A malformed extension value shows up in OpenSSL's rendering rather than as
	// an error, so the rendering itself is checked for the complaints it uses.
	for _, bad := range []string{"BAD ", "unable to print", "Unable to load", "error:"} {
		if strings.Contains(text, bad) {
			t.Errorf("openssl reported a decoding problem (%q) in:\n%s", bad, text)
		}
	}
	if t.Failed() {
		t.Logf("openssl x509 -text output:\n%s", text)
	}
}
