package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestQCStatements_OpenSSLParse issues a self-signed certificate carrying a full
// eIDAS QCStatements extension (QcCompliance, QcType=web, QcSSCD,
// QcRetentionPeriod, QcPDS, and the ETSI TS 119 495 PSD2 statement) and confirms
// that a real `openssl x509 -text` parses it without error and recognizes the
// extension. OpenSSL 3 decodes the id-pe-qcStatements OID and renders it as
// "Qualified Certificate Statements", proving the hand-rolled DER is well-formed
// against an independent implementation.
func TestQCStatements_OpenSSLParse(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH")
	}

	psAS, _ := PSD2RoleOID("PSP_AS")
	psAI, _ := PSD2RoleOID("PSP_AI")
	ext, err := QCStatements{
		Compliance:     true,
		Types:          []asn1.ObjectIdentifier{OIDEtsiQctWeb},
		SSCD:           true,
		RetentionYears: 20,
		PDS: []QCPDSLocation{
			{URL: "https://ca.example/pds/en.pdf", Language: "en"},
			{URL: "https://ca.example/pds/de.pdf", Language: "de"},
		},
		PSD2: &QCPSD2{
			Roles:   []QCPSD2Role{{OID: psAS, Name: "PSP_AS"}, {OID: psAI, Name: "PSP_AI"}},
			NCAName: "Bundesanstalt für Finanzdienstleistungsaufsicht",
			NCAID:   "DE-BAFIN",
		},
	}.Extension()
	if err != nil {
		t.Fatalf("building extension: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(1),
		Subject:         pkix.Name{CommonName: "qwac.example"},
		DNSNames:        []string{"qwac.example"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(24 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: []pkix.Extension{ext},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	// crypto/x509 must round-trip it too (it is non-critical, so parsing succeeds
	// and the extension lands in cert.Extensions).
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	qc, present, err := QCStatementsFromCertificate(cert)
	if err != nil || !present || !qc.Compliance || qc.PSD2 == nil {
		t.Fatalf("QCStatementsFromCertificate = (%+v, %v, %v)", qc, present, err)
	}

	path := filepath.Join(t.TempDir(), "qwac.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	out, err := exec.Command(openssl, "x509", "-in", path, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -text failed: %v\n%s", err, out)
	}
	text := string(out)
	// OpenSSL 3 labels the extension; older builds may only print the OID. Accept
	// either so the test is robust across openssl versions.
	if !strings.Contains(text, "Qualified Certificate Statements") &&
		!strings.Contains(text, "qcStatements") &&
		!strings.Contains(text, "1.3.6.1.5.5.7.1.3") {
		t.Errorf("openssl output does not mention the qcStatements extension:\n%s", text)
	}
	// The parse must not have flagged a decode error on our hand-rolled DER.
	if strings.Contains(strings.ToLower(text), "error") || strings.Contains(text, "BAD ENCODING") {
		t.Errorf("openssl reported a decode error:\n%s", text)
	}
}
