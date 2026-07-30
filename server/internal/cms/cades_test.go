package cms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// testCACert builds a self-signed CA certificate (with the certSign/crlSign key
// usages) plus its key, for producing real CRLs in the CAdES round-trip tests.
func testCACert(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	return cert, key
}

// testCRL builds a real DER CRL signed by the given CA, listing the supplied
// revoked serials.
func testCRL(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, number int64, revoked ...int64) []byte {
	t.Helper()
	entries := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, s := range revoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(s),
			RevocationTime: time.Now().Add(-time.Minute),
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                time.Now().Add(-time.Minute),
		NextUpdate:                time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	}, caCert, caKey)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}
	return der
}

func TestBasicOCSPResponseWrapRoundTrip(t *testing.T) {
	// A BasicOCSPResponse is opaque to these helpers; any DER TLV stands in.
	basic, err := asn1.Marshal(struct {
		A int
		B string
	}{A: 42, B: "basic-ocsp"})
	if err != nil {
		t.Fatal(err)
	}

	wrapped, err := WrapBasicOCSPResponse(basic)
	if err != nil {
		t.Fatalf("WrapBasicOCSPResponse: %v", err)
	}
	got, err := BasicOCSPResponse(wrapped)
	if err != nil {
		t.Fatalf("BasicOCSPResponse: %v", err)
	}
	if !bytes.Equal(got, basic) {
		t.Fatalf("round-trip mismatch: got %x want %x", got, basic)
	}

	// A non-basic (or empty) OCSP response must be rejected.
	bad, err := asn1.Marshal(struct{ Status asn1.Enumerated }{Status: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BasicOCSPResponse(bad); err == nil {
		t.Fatal("BasicOCSPResponse accepted a response with no BasicOCSPResponse")
	}
}

func TestRevocationValuesRoundTrip(t *testing.T) {
	caCert, caKey := testCACert(t, "CAdES Test CA")
	crl1 := testCRL(t, caCert, caKey, 1)
	crl2 := testCRL(t, caCert, caKey, 2, 99)

	basicA, _ := asn1.Marshal(struct{ N int }{N: 1})
	basicB, _ := asn1.Marshal(struct{ N int }{N: 2})
	respA, err := WrapBasicOCSPResponse(basicA)
	if err != nil {
		t.Fatal(err)
	}
	respB, err := WrapBasicOCSPResponse(basicB)
	if err != nil {
		t.Fatal(err)
	}

	attr, err := RevocationValuesAttribute([][]byte{crl1, crl2}, [][]byte{respA, respB})
	if err != nil {
		t.Fatalf("RevocationValuesAttribute: %v", err)
	}
	if !attr.Type.Equal(OIDRevocationValues) {
		t.Fatalf("attribute type = %v, want id-aa-ets-revocationValues", attr.Type)
	}
	raw, ok := attr.Value.(asn1.RawValue)
	if !ok {
		t.Fatalf("attribute value is %T, want asn1.RawValue", attr.Value)
	}

	rv, err := ParseRevocationValues(raw.FullBytes)
	if err != nil {
		t.Fatalf("ParseRevocationValues: %v", err)
	}
	if len(rv.CRLs) != 2 {
		t.Fatalf("parsed %d CRLs, want 2", len(rv.CRLs))
	}
	if !bytes.Equal(rv.CRLs[0], crl1) || !bytes.Equal(rv.CRLs[1], crl2) {
		t.Fatal("parsed CRL bytes do not match the originals")
	}
	if len(rv.BasicOCSPResponses) != 2 {
		t.Fatalf("parsed %d OCSP responses, want 2", len(rv.BasicOCSPResponses))
	}
	if !bytes.Equal(rv.BasicOCSPResponses[0], basicA) || !bytes.Equal(rv.BasicOCSPResponses[1], basicB) {
		t.Fatal("parsed BasicOCSPResponse bytes do not match the originals")
	}

	// The parsed CRLs must be real, re-parsable CertificateLists.
	if _, err := x509.ParseRevocationList(rv.CRLs[1]); err != nil {
		t.Fatalf("embedded CRL is not a valid CertificateList: %v", err)
	}

	// CRLs-only and OCSP-only forms must both encode and decode.
	crlOnly, err := RevocationValuesAttribute([][]byte{crl1}, nil)
	if err != nil {
		t.Fatalf("RevocationValuesAttribute crls-only: %v", err)
	}
	if rvv, err := ParseRevocationValues(crlOnly.Value.(asn1.RawValue).FullBytes); err != nil || len(rvv.CRLs) != 1 || len(rvv.BasicOCSPResponses) != 0 {
		t.Fatalf("crls-only round-trip wrong: err=%v %+v", err, rvv)
	}
	ocspOnly, err := RevocationValuesAttribute(nil, [][]byte{respA})
	if err != nil {
		t.Fatalf("RevocationValuesAttribute ocsp-only: %v", err)
	}
	if rvv, err := ParseRevocationValues(ocspOnly.Value.(asn1.RawValue).FullBytes); err != nil || len(rvv.CRLs) != 0 || len(rvv.BasicOCSPResponses) != 1 {
		t.Fatalf("ocsp-only round-trip wrong: err=%v %+v", err, rvv)
	}

	// Empty material is a programming error.
	if _, err := RevocationValuesAttribute(nil, nil); err == nil {
		t.Fatal("RevocationValuesAttribute accepted empty material")
	}
}

func TestSignedDataCRLsField(t *testing.T) {
	content := []byte("artifact covered by a CAdES-LT signature")
	signerCert, signerKey := testECDSACert(t, "cades-signer", 20)
	caCert, caKey := testCACert(t, "CAdES Test CA")
	crl1 := testCRL(t, caCert, caKey, 1)
	crl2 := testCRL(t, caCert, caKey, 2)

	der, err := BuildSignedData(SignedDataOpts{
		Content:    content,
		Detached:   true,
		SignerCert: signerCert,
		Signer:     signerKey,
		CRLs:       [][]byte{crl1, crl2},
	})
	if err != nil {
		t.Fatalf("BuildSignedData: %v", err)
	}

	p, err := ParseSignedData(der)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	// The signature still verifies with the crls field populated.
	if err := p.VerifyDetached(content); err != nil {
		t.Fatalf("VerifyDetached: %v", err)
	}
	embedded := p.EmbeddedCRLs()
	if len(embedded) != 2 {
		t.Fatalf("EmbeddedCRLs returned %d, want 2", len(embedded))
	}
	// Every embedded CRL must be a real CertificateList and match an original
	// (order is by DER, so compare as a set).
	originals := map[string]bool{string(crl1): true, string(crl2): true}
	for _, der := range embedded {
		if _, err := x509.ParseRevocationList(der); err != nil {
			t.Fatalf("embedded CRL not parseable: %v", err)
		}
		if !originals[string(der)] {
			t.Fatal("embedded CRL does not match an original")
		}
	}
}
