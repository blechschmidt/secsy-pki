package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"testing"
	"time"
)

// TestSignX509CertificateRejectsCAForgery locks in the Task 12 fix for the
// CA:TRUE forgery vector: a caller crafting a CSR that carries a BasicConstraints
// CA:TRUE extension (and keyCertSign usage) must NOT get those extensions copied
// into the issued certificate. The issued cert must be a plain leaf (IsCA=false).
func TestSignX509CertificateRejectsCAForgery(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subjKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// A hostile CSR requesting CA:TRUE via a raw basicConstraints extension.
	bc, err := asn1.Marshal(struct {
		IsCA       bool
		MaxPathLen int `asn1:"optional"`
	}{IsCA: true})
	if err != nil {
		t.Fatal(err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "attacker-sub-ca"},
		ExtraExtensions: []pkix.Extension{{
			Id:       asn1.ObjectIdentifier{2, 5, 29, 19}, // basicConstraints
			Critical: true,
			Value:    bc,
		}},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, subjKey)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	certPEM, _, err := SignX509Certificate(caKey, csrPEM, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("SignX509Certificate: %v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if cert.IsCA {
		t.Fatal("issued certificate has IsCA=true: CSR-driven CA forgery was NOT blocked")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Fatal("issued certificate has keyCertSign usage: forgery was NOT blocked")
	}
	if !cert.BasicConstraintsValid {
		t.Error("issued certificate should carry an explicit basic-constraints (cA=FALSE) extension")
	}
}
