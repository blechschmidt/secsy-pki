package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// TestOpenSSLInteropCAdESLT builds a detached CAdES-LT-shaped SignedData — signed
// signing-certificate-v2 + signing-time attributes, a populated SignedData `crls`
// field, and an id-aa-ets-revocationValues unsigned attribute carrying a CRL and
// an OCSP response — and confirms an independent implementation (OpenSSL) still
// verifies it. This guards the LTV encoding against being self-consistent but
// non-conformant: openssl must build the chain to the CA, check the signature
// over the authenticated attributes, and tolerate the added revocation material.
func TestOpenSSLInteropCAdESLT(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not available")
	}
	dir := t.TempDir()

	caCert, caKey := testCACert(t, "CAdES LT Interop CA")

	// A code-signing leaf issued by the CA.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(77),
		Subject:      pkix.Name{CommonName: "cades-lt-leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	// Long-term-validation material: a CRL and an OCSP "good" for the leaf.
	crl := testCRL(t, caCert, caKey, 1)
	ocspDER, err := pki.CreateOCSPResponse(caKey, caCert, pki.OCSPResponseSpec{
		Serial:     leaf.SerialNumber,
		Status:     pki.OCSPGood,
		ThisUpdate: time.Now().Add(-time.Minute),
		NextUpdate: time.Now().Add(time.Hour),
		IssuerHash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponse: %v", err)
	}

	scv2, err := SigningCertificateV2Attribute([]*x509.Certificate{leaf, caCert})
	if err != nil {
		t.Fatal(err)
	}
	revVals, err := RevocationValuesAttribute([][]byte{crl}, [][]byte{ocspDER})
	if err != nil {
		t.Fatal(err)
	}
	signingTime := Attribute{Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}, Value: time.Now().UTC().Truncate(time.Second)}

	content := []byte("release artifact protected by a CAdES-LT signature")
	signed, err := BuildSignedData(SignedDataOpts{
		Content:            content,
		Detached:           true,
		SignerCert:         leaf,
		Signer:             leafKey,
		Certificates:       []*x509.Certificate{leaf, caCert},
		CRLs:               [][]byte{crl},
		ExtraAttrs:         []Attribute{scv2, signingTime},
		ExtraUnsignedAttrs: []Attribute{revVals},
	})
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}

	// Our own parser must round-trip the LTV material.
	p, err := ParseSignedData(signed)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	if len(p.EmbeddedCRLs()) != 1 {
		t.Fatalf("EmbeddedCRLs = %d, want 1", len(p.EmbeddedCRLs()))
	}
	if _, ok := p.UnauthenticatedAttribute(OIDRevocationValues); !ok {
		t.Fatal("revocation-values unsigned attribute missing")
	}

	sigPath := filepath.Join(dir, "sig.p7s")
	contentPath := filepath.Join(dir, "content.bin")
	caPath := filepath.Join(dir, "ca.pem")
	writeFile(t, sigPath, signed)
	writeFile(t, contentPath, content)
	writeFile(t, caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}))

	// openssl must verify the detached signature, build the chain to the CA, and
	// accept the CAdES-LT structure. -purpose any tolerates the codeSigning EKU.
	out, err := exec.Command(openssl, "cms", "-verify", "-inform", "DER", "-in", sigPath,
		"-content", contentPath, "-CAfile", caPath, "-purpose", "any").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl cms -verify failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), string(content)) {
		t.Fatalf("openssl verify output did not echo the content:\n%s", out)
	}

	// openssl must also be able to print the CMS structure (parses crls + attrs).
	out, err = exec.Command(openssl, "cms", "-cmsout", "-inform", "DER", "-in", sigPath, "-noout", "-print").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl cms -cmsout failed: %v\n%s", err, out)
	}
}
