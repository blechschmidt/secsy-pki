package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// newTestCA builds an in-memory self-signed CA certificate and its signer, for
// exercising the OCSP builder without an HSM.
func newTestCA(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "secsy Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("creating CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA cert: %v", err)
	}
	return cert
}

// issuerKeyHashSHA1 recomputes the SHA-1 IssuerKeyHash the way a client would.
func issuerKeyHashSHA1(t *testing.T, issuer *x509.Certificate) []byte {
	t.Helper()
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatalf("unmarshaling issuer SPKI: %v", err)
	}
	sum := sha1.Sum(spki.SubjectPublicKey.RightAlign())
	return sum[:]
}

// buildRequestWithNonce marshals an OCSP request for serial under issuer,
// optionally carrying a nonce request extension (RFC 8954 OCTET STRING form).
func buildRequestWithNonce(t *testing.T, issuer *x509.Certificate, serial *big.Int, nonce []byte) []byte {
	t.Helper()
	nameHash := sha1.Sum(issuer.RawSubject)
	cid := certIDASN1{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA1, Parameters: asn1.RawValue{Tag: 5}},
		NameHash:      nameHash[:],
		IssuerKeyHash: issuerKeyHashSHA1(t, issuer),
		SerialNumber:  serial,
	}
	type reqEntry struct{ Cert certIDASN1 }
	entryDER, err := asn1.Marshal(reqEntry{Cert: cid})
	if err != nil {
		t.Fatalf("marshaling request entry: %v", err)
	}
	type tbs struct {
		RequestList []asn1.RawValue
		Extensions  []pkix.Extension `asn1:"explicit,tag:2,optional"`
	}
	type req struct{ TBS tbs }
	tbsVal := tbs{RequestList: []asn1.RawValue{{FullBytes: entryDER}}}
	if nonce != nil {
		ext, err := nonceExtension(nonce)
		if err != nil {
			t.Fatalf("building nonce extension: %v", err)
		}
		tbsVal.Extensions = []pkix.Extension{ext}
	}
	der, err := asn1.Marshal(req{TBS: tbsVal})
	if err != nil {
		t.Fatalf("marshaling request: %v", err)
	}
	return der
}

func TestExtractOCSPNonce(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newTestCA(t, key)
	serial := big.NewInt(42)

	nonce := bytes.Repeat([]byte{0xAB}, 16)
	der := buildRequestWithNonce(t, ca, serial, nonce)

	// The x/crypto parser must still accept the request (it ignores the nonce).
	if _, err := ocsp.ParseRequest(der); err != nil {
		t.Fatalf("ocsp.ParseRequest rejected our request: %v", err)
	}

	got, err := ExtractOCSPNonce(der)
	if err != nil {
		t.Fatalf("ExtractOCSPNonce: %v", err)
	}
	if !bytes.Equal(got, nonce) {
		t.Errorf("nonce = %x, want %x", got, nonce)
	}

	// No nonce -> nil, no error.
	noNonce := buildRequestWithNonce(t, ca, serial, nil)
	if got, err := ExtractOCSPNonce(noNonce); err != nil || got != nil {
		t.Errorf("ExtractOCSPNonce(no nonce) = %x, %v; want nil, nil", got, err)
	}

	// Oversized nonce -> ErrNonceTooLong.
	big := bytes.Repeat([]byte{0x01}, MaxNonceLength+1)
	over := buildRequestWithNonce(t, ca, serial, big)
	if _, err := ExtractOCSPNonce(over); !errors.Is(err, ErrNonceTooLong) {
		t.Errorf("oversized nonce error = %v, want ErrNonceTooLong", err)
	}
}

// parseResponseExtensions decodes the response-level responseExtensions of a
// signed OCSP response, where RFC 6960 places the echoed nonce. The x/crypto
// parser does not expose these, so the test reads them directly.
func parseResponseExtensions(t *testing.T, respDER []byte) []pkix.Extension {
	t.Helper()
	var outer ocspResponseASN1
	if _, err := asn1.Unmarshal(respDER, &outer); err != nil {
		t.Fatalf("unmarshaling response: %v", err)
	}
	var basic basicResponseASN1
	if _, err := asn1.Unmarshal(outer.Response.Response, &basic); err != nil {
		t.Fatalf("unmarshaling basicResponse: %v", err)
	}
	var tbs responseDataASN1
	if _, err := asn1.Unmarshal(basic.TBSResponseData.FullBytes, &tbs); err != nil {
		t.Fatalf("unmarshaling responseData: %v", err)
	}
	return tbs.ResponseExtensions
}

func TestCreateOCSPResponseNonceEchoedAtResponseLevel(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newTestCA(t, key)
	serial := big.NewInt(1234)
	nonce := bytes.Repeat([]byte{0x7E}, 16)

	now := time.Now()
	respDER, err := CreateOCSPResponse(key, ca, OCSPResponseSpec{
		Serial:     serial,
		Status:     OCSPGood,
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
		Nonce:      nonce,
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponse: %v", err)
	}

	// Signature and structure must verify against the CA (self-signed responder).
	parsed, err := ocsp.ParseResponse(respDER, ca)
	if err != nil {
		t.Fatalf("ocsp.ParseResponse: %v", err)
	}
	if parsed.Status != ocsp.Good {
		t.Errorf("status = %d, want Good", parsed.Status)
	}

	// The nonce must be present at the response level and equal the request nonce.
	exts := parseResponseExtensions(t, respDER)
	var found []byte
	for _, e := range exts {
		if e.Id.Equal(OIDNonce) {
			var inner []byte
			if _, err := asn1.Unmarshal(e.Value, &inner); err != nil {
				t.Fatalf("nonce extension is not an OCTET STRING: %v", err)
			}
			found = inner
		}
	}
	if !bytes.Equal(found, nonce) {
		t.Errorf("echoed nonce = %x, want %x", found, nonce)
	}
}

func TestCreateOCSPResponseDelegatedResponderChain(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newTestCA(t, caKey)

	// Build a delegated OCSP-signing certificate with its own key, signed by the
	// CA, carrying the OCSPSigning EKU and the ocsp-nocheck extension — exactly as
	// the ca package does in production.
	respKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	delegDER, err := CreateLeafCertificate(caKey, ca, LeafCertRequest{
		Subject:         pkix.Name{CommonName: "secsy Test CA OCSP Responder"},
		PublicKey:       respKey.Public(),
		Serial:          big.NewInt(99),
		NotBefore:       now.Add(-time.Minute),
		NotAfter:        now.Add(6 * time.Hour),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		ExtraExtensions: []pkix.Extension{OCSPNoCheckExtension()},
	})
	if err != nil {
		t.Fatalf("building delegated responder cert: %v", err)
	}
	deleg, err := x509.ParseCertificate(delegDER)
	if err != nil {
		t.Fatalf("parsing delegated cert: %v", err)
	}

	// The delegated cert must carry id-kp-OCSPSigning and id-pkix-ocsp-nocheck.
	if !hasOCSPSigningEKU(deleg) {
		t.Error("delegated cert missing id-kp-OCSPSigning EKU")
	}
	if !hasNoCheck(deleg) {
		t.Error("delegated cert missing id-pkix-ocsp-nocheck extension")
	}

	// Sign a response with the delegated key and embed the delegated cert.
	respDER, err := CreateOCSPResponse(respKey, ca, OCSPResponseSpec{
		Serial:     big.NewInt(1234),
		Status:     OCSPRevoked,
		RevokedAt:  now.Add(-time.Hour),
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
		Responder:  deleg,
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponse (delegated): %v", err)
	}

	// ParseResponse with the CA as issuer verifies BOTH: the response signature
	// against the embedded delegated cert, and that the delegated cert was signed
	// by the CA. That is the full delegated-responder chain.
	parsed, err := ocsp.ParseResponse(respDER, ca)
	if err != nil {
		t.Fatalf("delegated response failed chain verification: %v", err)
	}
	if parsed.Status != ocsp.Revoked {
		t.Errorf("status = %d, want Revoked", parsed.Status)
	}
	if parsed.Certificate == nil {
		t.Fatal("response did not embed the delegated responder certificate")
	}
	if parsed.Certificate.SerialNumber.Cmp(big.NewInt(99)) != 0 {
		t.Errorf("embedded responder serial = %s, want 99", parsed.Certificate.SerialNumber)
	}
}

func TestCreateOCSPResponseStatuses(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := newTestCA(t, caKey)
	now := time.Now()

	cases := []struct {
		name   string
		status int
	}{
		{"good", OCSPGood},
		{"revoked", OCSPRevoked},
		{"unknown", OCSPUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			respDER, err := CreateOCSPResponse(caKey, ca, OCSPResponseSpec{
				Serial:           big.NewInt(7),
				Status:           tc.status,
				RevokedAt:        now.Add(-time.Hour),
				RevocationReason: ocsp.KeyCompromise,
				ThisUpdate:       now.Add(-time.Minute),
				NextUpdate:       now.Add(time.Hour),
			})
			if err != nil {
				t.Fatalf("CreateOCSPResponse: %v", err)
			}
			parsed, err := ocsp.ParseResponse(respDER, ca)
			if err != nil {
				t.Fatalf("ParseResponse: %v", err)
			}
			if parsed.Status != tc.status {
				t.Errorf("status = %d, want %d", parsed.Status, tc.status)
			}
		})
	}
}

func TestCreateOCSPResponseRSA(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	ca := newTestCA(t, caKey)
	now := time.Now()
	respDER, err := CreateOCSPResponse(caKey, ca, OCSPResponseSpec{
		Serial:     big.NewInt(5),
		Status:     OCSPGood,
		ThisUpdate: now.Add(-time.Minute),
		NextUpdate: now.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponse (RSA): %v", err)
	}
	if _, err := ocsp.ParseResponse(respDER, ca); err != nil {
		t.Fatalf("RSA response verification: %v", err)
	}
}

// hasOCSPSigningEKU reports whether the certificate carries id-kp-OCSPSigning.
func hasOCSPSigningEKU(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageOCSPSigning {
			return true
		}
	}
	return false
}

// hasNoCheck reports whether the certificate carries id-pkix-ocsp-nocheck.
func hasNoCheck(cert *x509.Certificate) bool {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDOCSPNoCheck) {
			return true
		}
	}
	return false
}
