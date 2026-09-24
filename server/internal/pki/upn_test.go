package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// knownAnswerSAN is the exact DER of a subjectAltName containing a single
// id-ms-UPN otherName carrying the UTF8String "user@EXAMPLE.COM". It was
// cross-checked with `openssl asn1parse`, which decodes it as:
//
//	SEQUENCE
//	  cont [ 0 ]                       -- otherName
//	    OBJECT :Microsoft User Principal Name   (1.3.6.1.4.1.311.20.2.3)
//	    cont [ 0 ]                     -- [0] EXPLICIT value
//	      UTF8STRING :user@EXAMPLE.COM
//
// Windows requires precisely this encoding to match a certificate's UPN SAN
// against a user's userPrincipalName for smartcard logon.
var knownAnswerSAN = []byte{
	0x30, 0x22, // SEQUENCE, length 34
	0xA0, 0x20, // [0] otherName, length 32
	0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x14, 0x02, 0x03, // OID 1.3.6.1.4.1.311.20.2.3
	0xA0, 0x12, // [0] EXPLICIT value, length 18
	0x0C, 0x10, // UTF8String, length 16
	'u', 's', 'e', 'r', '@', 'E', 'X', 'A', 'M', 'P', 'L', 'E', '.', 'C', 'O', 'M',
}

func TestSubjectAltNameExtensionKnownAnswer(t *testing.T) {
	ext, err := SubjectAltNameExtension(nil, nil, nil, nil, []string{"user@EXAMPLE.COM"}, false)
	if err != nil {
		t.Fatalf("SubjectAltNameExtension: %v", err)
	}
	if !ext.Id.Equal(OIDSubjectAltName) {
		t.Fatalf("extension OID = %v, want %v", ext.Id, OIDSubjectAltName)
	}
	if ext.Critical {
		t.Errorf("SAN with a non-empty subject should be non-critical")
	}
	if !bytes.Equal(ext.Value, knownAnswerSAN) {
		t.Fatalf("SAN encoding mismatch\n got: %x\nwant: %x", ext.Value, knownAnswerSAN)
	}
}

func TestUPNOtherNameRoundTrip(t *testing.T) {
	inputs := []string{
		"alice@EXAMPLE.COM",
		"bob@corp.example.com",
		"svc-01@example.io",
	}
	ext, err := SubjectAltNameExtension([]string{"host.example.com"}, nil, []string{"a@example.com"}, nil, inputs, false)
	if err != nil {
		t.Fatalf("SubjectAltNameExtension: %v", err)
	}
	got, err := UPNsFromSANValue(ext.Value)
	if err != nil {
		t.Fatalf("UPNsFromSANValue: %v", err)
	}
	if strings.Join(got, ",") != strings.Join(inputs, ",") {
		t.Fatalf("round-trip UPNs = %v, want %v", got, inputs)
	}
}

// TestUPNCertificateGoParser confirms Go's crypto/x509 parses a certificate
// carrying a UPN otherName SAN without error (it silently ignores the otherName)
// and that the UPN is recoverable from the raw extension, plus that the standard
// SAN types encoded alongside it round-trip into their typed fields.
func TestUPNCertificateGoParser(t *testing.T) {
	cert := issueTestUPNCert(t, []string{"admin@EXAMPLE.COM"}, []string{"admin-pc.example.com"}, "CN=admin")

	if got := UPNsFromCertificate(cert); len(got) != 1 || got[0] != "admin@EXAMPLE.COM" {
		t.Fatalf("UPNsFromCertificate = %v, want [admin@EXAMPLE.COM]", got)
	}
	// The dNSName encoded in the same hand-rolled SAN must reparse into DNSNames.
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "admin-pc.example.com" {
		t.Fatalf("DNSNames = %v, want [admin-pc.example.com]", cert.DNSNames)
	}
	// The custom EKUs must reparse into UnknownExtKeyUsage.
	var haveSC, havePKINIT bool
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(OIDExtKeyUsageMSSmartcardLogon) {
			haveSC = true
		}
		if oid.Equal(OIDExtKeyUsagePKINITClientAuth) {
			havePKINIT = true
		}
	}
	if !haveSC || !havePKINIT {
		t.Fatalf("UnknownExtKeyUsage = %v, want both smartcard-logon and PKINIT OIDs", cert.UnknownExtKeyUsage)
	}
}

// TestUPNCertificateOpenSSL confirms the encoding is interoperable with OpenSSL:
// `openssl x509 -text` must decode the UPN otherName (openssl recognizes the OID
// as "Microsoft User Principal Name") and both custom EKUs.
func TestUPNCertificateOpenSSL(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	cert := issueTestUPNCert(t, []string{"user@EXAMPLE.COM"}, nil, "CN=user")

	// Feed the leaf DER through `openssl x509 -text` and inspect the human dump.
	pemBytes := EncodeCertificatePEM(cert.Raw)
	f, err := os.CreateTemp(t.TempDir(), "upn-*.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(pemBytes); err != nil {
		t.Fatal(err)
	}
	f.Close()

	out, err := exec.Command("openssl", "x509", "-in", f.Name(), "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -text: %v\n%s", err, out)
	}
	text := string(out)
	// OpenSSL 3 prints the UPN otherName as "othername: UPN::user@EXAMPLE.COM" in
	// the -text dump. Assert both the otherName marker and the value are present.
	if !strings.Contains(text, "othername") || !strings.Contains(text, "UPN") {
		t.Errorf("openssl output missing the UPN otherName marker:\n%s", text)
	}
	if !strings.Contains(text, "user@EXAMPLE.COM") {
		t.Errorf("openssl output missing the UPN value:\n%s", text)
	}
	// Both custom EKUs (openssl prints friendly names for these OIDs).
	if !strings.Contains(text, "Microsoft Smartcard Login") && !strings.Contains(text, "1.3.6.1.4.1.311.20.2.2") {
		t.Errorf("openssl output missing the smartcard-logon EKU:\n%s", text)
	}
	if !strings.Contains(text, "1.3.6.1.5.2.3.4") && !strings.Contains(strings.ToLower(text), "pkinit") {
		t.Errorf("openssl output missing the PKINIT EKU:\n%s", text)
	}

	// Additionally verify the raw SAN extension value with `openssl asn1parse`.
	var sanValue []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDSubjectAltName) {
			sanValue = ext.Value
		}
	}
	if sanValue == nil {
		t.Fatal("issued certificate has no subjectAltName extension")
	}
	sanFile, err := os.CreateTemp(t.TempDir(), "san-*.der")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sanFile.Write(sanValue); err != nil {
		t.Fatal(err)
	}
	sanFile.Close()
	a1, err := exec.Command("openssl", "asn1parse", "-inform", "DER", "-in", sanFile.Name()).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl asn1parse: %v\n%s", err, a1)
	}
	if !strings.Contains(string(a1), "Microsoft User Principal Name") {
		t.Errorf("asn1parse did not identify the UPN OID:\n%s", a1)
	}
	if !strings.Contains(string(a1), "user@EXAMPLE.COM") {
		t.Errorf("asn1parse did not decode the UPN value:\n%s", a1)
	}
}

// issueTestUPNCert mints a self-signed leaf carrying the given UPN otherName SANs,
// DNS SANs, and both custom smartcard/PKINIT EKUs, using an ephemeral ECDSA key —
// enough to exercise the encoding and Go/OpenSSL parsing without an HSM.
func issueTestUPNCert(t *testing.T, upns, dns []string, cn string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sanExt, err := SubjectAltNameExtension(dns, nil, nil, nil, upns, false)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: strings.TrimPrefix(cn, "CN=")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{
			OIDExtKeyUsageMSSmartcardLogon,
			OIDExtKeyUsagePKINITClientAuth,
		},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{sanExt},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// issueTestUPNCSR builds a PKCS#10 request whose extensionRequest attribute
// carries a hand-rolled subjectAltName with the given UPN otherNames and DNS
// names, then parses it back — i.e. exactly the path an EST/SCEP/MS-WSTEP client
// takes when it asks for a smartcard-logon certificate.
func issueTestUPNCSR(t *testing.T, upns, dns []string) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sanExt, err := SubjectAltNameExtension(dns, nil, nil, nil, upns, false)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: "enrolling-device"},
		DNSNames:        dns,
		ExtraExtensions: []pkix.Extension{sanExt},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest rejected the hand-rolled SAN: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CheckSignature: %v", err)
	}
	return csr
}

// TestUPNsFromCSRRoundTrip is the enrollment-side counterpart of
// TestUPNCertificateGoParser: crypto/x509 discards otherName SANs from a parsed
// CSR, so a device's requested UPN survives only if it is recovered from the raw
// extension. Every EST/SCEP/MS-WSTEP issuance path calls this to decide which
// Active Directory principal the certificate will authenticate as.
func TestUPNsFromCSRRoundTrip(t *testing.T) {
	upns := []string{"alice@EXAMPLE.COM", "svc-01@corp.example.com"}
	dns := []string{"device01.example.com"}
	csr := issueTestUPNCSR(t, upns, dns)

	got := UPNsFromCSR(csr)
	if len(got) != len(upns) {
		t.Fatalf("UPNsFromCSR = %q, want %q", got, upns)
	}
	for i, want := range upns {
		if got[i] != want {
			t.Errorf("UPN[%d] = %q, want %q (order must be preserved)", i, got[i], want)
		}
	}
	// The hand-rolled SAN must still be a SAN crypto/x509 itself understands, so
	// the DNS names in the same extension are not lost.
	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != dns[0] {
		t.Errorf("DNSNames = %q, want %q", csr.DNSNames, dns)
	}
	// And crypto/x509 really does drop the otherName, which is why this exists.
	if len(csr.EmailAddresses) != 0 || len(csr.URIs) != 0 {
		t.Errorf("unexpected typed SANs: emails=%q uris=%v", csr.EmailAddresses, csr.URIs)
	}
}

// TestUPNsFromCSRWithoutUPNs: a CSR with no UPN — with or without other SANs —
// must yield nothing rather than an empty-string principal.
func TestUPNsFromCSRWithoutUPNs(t *testing.T) {
	if got := UPNsFromCSR(issueTestUPNCSR(t, nil, []string{"plain.example.com"})); got != nil {
		t.Errorf("UPNsFromCSR (DNS only) = %q, want nil", got)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "no-extensions"},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if got := UPNsFromCSR(csr); got != nil {
		t.Errorf("UPNsFromCSR (no extensions) = %q, want nil", got)
	}
}

// TestUPNsFromCSRIgnoresUndecodableSAN feeds the extractor the shapes a hostile
// or buggy client can put in an extensionRequest attribute. A CSR arrives
// unauthenticated at the EST/SCEP endpoints, so the requirement is that a
// malformed subjectAltName yields no UPN instead of panicking or inventing one —
// and that a second, well-formed SAN is still honored.
func TestUPNsFromCSRIgnoresUndecodableSAN(t *testing.T) {
	good, err := SubjectAltNameExtension(nil, nil, nil, nil, []string{"bob@EXAMPLE.COM"}, false)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		exts []pkix.Extension
		want []string
	}{
		{"empty value", []pkix.Extension{{Id: OIDSubjectAltName}}, nil},
		{"not DER", []pkix.Extension{{Id: OIDSubjectAltName, Value: []byte("nope")}}, nil},
		{"not a SEQUENCE", []pkix.Extension{{Id: OIDSubjectAltName, Value: []byte{0x05, 0x00}}}, nil},
		{"truncated SEQUENCE", []pkix.Extension{{Id: OIDSubjectAltName, Value: []byte{0x30, 0x7F, 0x86, 0x01}}}, nil},
		{"length claims 64 KiB", []pkix.Extension{{Id: OIDSubjectAltName, Value: []byte{0x30, 0x82, 0xFF, 0xFF}}}, nil},
		{"otherName with a foreign type-id", []pkix.Extension{{Id: OIDSubjectAltName, Value: []byte{
			0x30, 0x08, 0xA0, 0x06, 0x06, 0x01, 0x2A, 0xA0, 0x01, 0x00,
		}}}, nil},
		{"a different extension entirely", []pkix.Extension{{Id: oidExtensionKeyUsage, Value: []byte{0x03, 0x02, 0x07, 0x80}}}, nil},
		// A malformed SAN must not mask a well-formed one that follows it.
		{"malformed then valid", []pkix.Extension{
			{Id: OIDSubjectAltName, Value: []byte("nope")},
			good,
		}, []string{"bob@EXAMPLE.COM"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// UPNsFromCSR reads only csr.Extensions, so the request is built
			// directly: a CSR carrying a malformed SAN would not survive
			// x509.ParseCertificateRequest, yet these bytes can still reach the
			// extractor through other callers of the same field.
			got := UPNsFromCSR(&x509.CertificateRequest{Extensions: tc.exts})
			if len(got) != len(tc.want) {
				t.Fatalf("UPNsFromCSR = %q, want %q", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("UPN[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
