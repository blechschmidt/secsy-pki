package pki

// OCSP request construction and the DER accessors that read responses off the
// network (ocsp.go).
//
// Two distinct risks live here. BuildOCSPRequestForSerial hand-computes the
// RFC 6960 certID hashes and its output doubles as a *cache key* — the static
// publisher stores a pre-signed response under the base64url of these exact
// bytes, so a request that is merely semantically equivalent but not
// byte-identical becomes a cache miss (or, worse, a hit on the wrong serial).
// The accessors (OCSPResponseNonce, OCSPRequestSerial, OCSPResponseNextUpdate)
// run on unauthenticated bytes from a public endpoint or a remote responder, so
// the bar is that malformed input is refused rather than panicking or answering
// with a wrong value.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// leafUnder mints a certificate with the given serial issued by ca, so
// golang.org/x/crypto/ocsp's own CreateRequest can be used as an oracle for the
// hand-built canonical request.
func leafUnder(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial *big.Int) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "ocsp-subject.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// TestBuildOCSPRequestForSerialMatchesXCryptoOracle checks the hand-rolled
// certID against golang.org/x/crypto/ocsp.CreateRequest, which computes the
// issuer name/key hashes independently from a real certificate. Byte equality is
// the requirement, not just semantic equality: these bytes are the cache key.
func TestBuildOCSPRequestForSerialMatchesXCryptoOracle(t *testing.T) {
	caKey := newECDSAKey(t)
	ca := newTestCA(t, caKey)

	for _, serial := range []*big.Int{
		big.NewInt(1),
		big.NewInt(0x7FFFFFFF),
		new(big.Int).SetBytes(bytes.Repeat([]byte{0xAB}, 19)), // a 20-octet CA/B serial
	} {
		leaf := leafUnder(t, ca, caKey, serial)

		want, err := BuildOCSPRequest(leaf, ca)
		if err != nil {
			t.Fatalf("BuildOCSPRequest: %v", err)
		}
		got, err := BuildOCSPRequestForSerial(ca, serial)
		if err != nil {
			t.Fatalf("BuildOCSPRequestForSerial: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("serial %v: BuildOCSPRequestForSerial = %x, x/crypto emits %x", serial, got, want)
		}

		// Deterministic: the same (issuer, serial) must always produce the same
		// key, or the static-artifact lookup silently degrades to a full miss.
		again, err := BuildOCSPRequestForSerial(ca, serial)
		if err != nil {
			t.Fatalf("BuildOCSPRequestForSerial (second call): %v", err)
		}
		if !bytes.Equal(got, again) {
			t.Fatalf("serial %v: the canonical request is not deterministic", serial)
		}

		// And a real responder must be able to parse it back.
		parsed, err := ocsp.ParseRequest(got)
		if err != nil {
			t.Fatalf("serial %v: ocsp.ParseRequest rejected the canonical request: %v", serial, err)
		}
		if parsed.SerialNumber.Cmp(serial) != 0 {
			t.Errorf("parsed serial = %v, want %v", parsed.SerialNumber, serial)
		}
		if parsed.HashAlgorithm != crypto.SHA1 {
			t.Errorf("certID hash = %v, want SHA-1 (the RFC 6960 / RFC 5019 default)", parsed.HashAlgorithm)
		}
	}
}

// TestBuildOCSPRequestForSerialDistinguishesSerials guards the cache key against
// the failure that matters most: two different serials must never encode to the
// same request, or one certificate's status is served for another.
func TestBuildOCSPRequestForSerialDistinguishesSerials(t *testing.T) {
	caKey := newECDSAKey(t)
	ca := newTestCA(t, caKey)
	otherCA := newTestCA(t, newECDSAKey(t))

	a, err := BuildOCSPRequestForSerial(ca, big.NewInt(1))
	if err != nil {
		t.Fatalf("BuildOCSPRequestForSerial: %v", err)
	}
	b, err := BuildOCSPRequestForSerial(ca, big.NewInt(2))
	if err != nil {
		t.Fatalf("BuildOCSPRequestForSerial: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("serials 1 and 2 produce identical canonical requests")
	}
	// A different issuer with the same serial must also differ (the certID binds
	// the issuer name and key hashes).
	c, err := BuildOCSPRequestForSerial(otherCA, big.NewInt(1))
	if err != nil {
		t.Fatalf("BuildOCSPRequestForSerial: %v", err)
	}
	if bytes.Equal(a, c) {
		t.Error("two different issuers produce identical canonical requests for serial 1")
	}
}

func TestBuildOCSPRequestForSerialRejectsMissingInputs(t *testing.T) {
	ca := newTestCA(t, newECDSAKey(t))
	if _, err := BuildOCSPRequestForSerial(nil, big.NewInt(1)); err == nil {
		t.Error("a nil issuer was accepted")
	}
	if _, err := BuildOCSPRequestForSerial(ca, nil); err == nil {
		t.Error("a nil serial was accepted")
	}
	// An issuer whose SubjectPublicKeyInfo is not decodable must be reported, not
	// hashed into a bogus certID.
	broken := *ca
	broken.RawSubjectPublicKeyInfo = []byte{0x30, 0x01}
	if _, err := BuildOCSPRequestForSerial(&broken, big.NewInt(1)); err == nil {
		t.Error("an issuer with an unparseable SPKI was accepted")
	}
}

// TestBuildOCSPRequestWithNonceRoundTrip is the end-to-end nonce contract: what
// the builder puts in is exactly what the extractor pulls out, the request stays
// parseable by the x/crypto responder parser, and the serial survives.
func TestBuildOCSPRequestWithNonceRoundTrip(t *testing.T) {
	caKey := newECDSAKey(t)
	ca := newTestCA(t, caKey)
	serial := new(big.Int).SetBytes([]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF})

	nonces := [][]byte{
		{0x00},                         // shortest legal nonce (1 octet), and a zero byte
		bytes.Repeat([]byte{0xAB}, 16), // the common 16-octet nonce
		bytes.Repeat([]byte{0xFF}, MaxNonceLength), // the RFC 8954 maximum
		{0x04, 0x02, 0x30, 0x00},                   // bytes that also look like valid DER
	}
	for _, nonce := range nonces {
		der, err := BuildOCSPRequestWithNonce(ca, serial, nonce)
		if err != nil {
			t.Fatalf("BuildOCSPRequestWithNonce(%x): %v", nonce, err)
		}
		if _, err := ocsp.ParseRequest(der); err != nil {
			t.Fatalf("nonce %x: ocsp.ParseRequest rejected the request: %v", nonce, err)
		}
		got, err := ExtractOCSPNonce(der)
		if err != nil {
			t.Fatalf("nonce %x: ExtractOCSPNonce: %v", nonce, err)
		}
		if !bytes.Equal(got, nonce) {
			t.Errorf("nonce round-trip = %x, want %x", got, nonce)
		}
		s, ok := OCSPRequestSerial(der)
		if !ok {
			t.Fatalf("nonce %x: OCSPRequestSerial reported failure", nonce)
		}
		if s != serial.String() {
			t.Errorf("serial = %s, want %s", s, serial)
		}
	}
}

// TestBuildOCSPRequestWithNonceEmptyFallsBackToCanonical documents that an empty
// nonce yields the plain canonical request — the artifact publisher relies on
// that so an unnonced request still hits the pre-signed object.
func TestBuildOCSPRequestWithNonceEmptyFallsBackToCanonical(t *testing.T) {
	ca := newTestCA(t, newECDSAKey(t))
	serial := big.NewInt(4242)
	want, err := BuildOCSPRequestForSerial(ca, serial)
	if err != nil {
		t.Fatalf("BuildOCSPRequestForSerial: %v", err)
	}
	for _, nonce := range [][]byte{nil, {}} {
		got, err := BuildOCSPRequestWithNonce(ca, serial, nonce)
		if err != nil {
			t.Fatalf("BuildOCSPRequestWithNonce: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("empty nonce changed the canonical request")
		}
		if n, err := ExtractOCSPNonce(got); err != nil || n != nil {
			t.Errorf("ExtractOCSPNonce = %x, %v; want nil, nil", n, err)
		}
	}
	if _, err := BuildOCSPRequestWithNonce(nil, serial, []byte{1}); err == nil {
		t.Error("a nil issuer was accepted")
	}
}

// TestOCSPRequestSerialRejectsMalformedInput drives the cache-key extractor with
// the bytes a public endpoint actually receives. Every case must report false
// (so the caller signs freshly) rather than panic or invent a key.
func TestOCSPRequestSerialRejectsMalformedInput(t *testing.T) {
	ca := newTestCA(t, newECDSAKey(t))
	valid, err := BuildOCSPRequestForSerial(ca, big.NewInt(9))
	if err != nil {
		t.Fatalf("BuildOCSPRequestForSerial: %v", err)
	}

	cases := map[string][]byte{
		"nil":                     nil,
		"empty":                   {},
		"empty SEQUENCE":          {0x30, 0x00},
		"ASN.1 NULL":              {0x05, 0x00},
		"length claims 64 KiB":    {0x30, 0x82, 0xFF, 0xFF},
		"indefinite length":       {0x30, 0x80, 0x00, 0x00},
		"plain text":              []byte("GET /ocsp HTTP/1.1"),
		"truncated request":       valid[:len(valid)/2],
		"request with trailing":   append(append([]byte{}, valid...), 0x00),
		"a response, not request": OCSPMalformedResponse,
	}
	for name, der := range cases {
		t.Run(name, func(t *testing.T) {
			s, ok := OCSPRequestSerial(der)
			if ok {
				t.Fatalf("OCSPRequestSerial accepted %s, returning %q", name, s)
			}
			if s != "" {
				t.Errorf("returned %q alongside ok=false", s)
			}
		})
	}

	if s, ok := OCSPRequestSerial(valid); !ok || s != "9" {
		t.Errorf("OCSPRequestSerial(valid) = %q, %v; want \"9\", true", s, ok)
	}
}

// TestOCSPResponseNextUpdate covers the value the TLS stapler schedules its
// refresh from: present, absent, and unparseable.
func TestOCSPResponseNextUpdate(t *testing.T) {
	caKey := newECDSAKey(t)
	ca := newTestCA(t, caKey)
	// OCSP times are GeneralizedTime, i.e. second precision.
	thisUpdate := time.Now().Add(-time.Minute).Truncate(time.Second)
	nextUpdate := thisUpdate.Add(12 * time.Hour)

	withNext, err := CreateOCSPResponse(caKey, ca, OCSPResponseSpec{
		Serial: big.NewInt(1), Status: OCSPGood, ThisUpdate: thisUpdate, NextUpdate: nextUpdate,
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponse: %v", err)
	}
	got, ok := OCSPResponseNextUpdate(withNext)
	if !ok {
		t.Fatal("OCSPResponseNextUpdate reported no NextUpdate on a response that has one")
	}
	if !got.Equal(nextUpdate) {
		t.Errorf("NextUpdate = %v, want %v", got, nextUpdate)
	}

	// A response with no NextUpdate must report false: the stapler has to treat
	// "no expiry stated" as "cannot schedule a refresh from it", not as the zero
	// time (which would look infinitely stale).
	noNext, err := CreateOCSPResponse(caKey, ca, OCSPResponseSpec{
		Serial: big.NewInt(2), Status: OCSPGood, ThisUpdate: thisUpdate,
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponse: %v", err)
	}
	if ts, ok := OCSPResponseNextUpdate(noNext); ok {
		t.Errorf("OCSPResponseNextUpdate on a response without NextUpdate = %v, true", ts)
	}

	for name, der := range map[string][]byte{
		"nil":                nil,
		"empty":              {},
		"garbage":            []byte("not an OCSP response"),
		"empty SEQUENCE":     {0x30, 0x00},
		"unsigned try-later": OCSPTryLaterResponse,
		"truncated":          withNext[:len(withNext)/2],
	} {
		if ts, ok := OCSPResponseNextUpdate(der); ok {
			t.Errorf("OCSPResponseNextUpdate(%s) = %v, true; want false", name, ts)
		}
	}
}

// TestOCSPResponseNonceRoundTrip is the client-side check a nonce exists for:
// the value the responder echoed must come back byte-identical to the one the
// request carried, so a replayed pre-computed response can be spotted.
func TestOCSPResponseNonceRoundTrip(t *testing.T) {
	caKey := newECDSAKey(t)
	ca := newTestCA(t, caKey)
	serial := big.NewInt(0xBEEF)
	now := time.Now()

	for _, nonce := range [][]byte{
		{0x01},
		bytes.Repeat([]byte{0x7E}, 16),
		bytes.Repeat([]byte{0x00}, MaxNonceLength),
	} {
		reqDER, err := BuildOCSPRequestWithNonce(ca, serial, nonce)
		if err != nil {
			t.Fatalf("BuildOCSPRequestWithNonce: %v", err)
		}
		fromRequest, err := ExtractOCSPNonce(reqDER)
		if err != nil {
			t.Fatalf("ExtractOCSPNonce: %v", err)
		}

		respDER, err := CreateOCSPResponse(caKey, ca, OCSPResponseSpec{
			Serial: serial, Status: OCSPGood,
			ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour),
			Nonce: fromRequest,
		})
		if err != nil {
			t.Fatalf("CreateOCSPResponse: %v", err)
		}
		got, err := OCSPResponseNonce(respDER)
		if err != nil {
			t.Fatalf("OCSPResponseNonce: %v", err)
		}
		if !bytes.Equal(got, nonce) {
			t.Errorf("echoed nonce = %x, want %x", got, nonce)
		}
	}
}

// TestOCSPResponseNonceAbsent: a response carrying no nonce is not an error, it
// is "no nonce" — a client must be able to tell that apart from a parse failure.
func TestOCSPResponseNonceAbsent(t *testing.T) {
	caKey := newECDSAKey(t)
	ca := newTestCA(t, caKey)
	respDER, err := CreateOCSPResponse(caKey, ca, OCSPResponseSpec{
		Serial: big.NewInt(3), Status: OCSPGood,
		ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponse: %v", err)
	}
	got, err := OCSPResponseNonce(respDER)
	if err != nil {
		t.Fatalf("OCSPResponseNonce: %v", err)
	}
	if got != nil {
		t.Errorf("OCSPResponseNonce = %x, want nil", got)
	}
}

// TestOCSPResponseNonceRejectsMalformedInput walks each failure branch of the
// hand-rolled response decoder with bytes that could arrive from a hostile or
// merely broken responder. None may panic, and every error path must return a
// nil nonce so a caller that ignores the error cannot mistake garbage for a
// matching nonce.
func TestOCSPResponseNonceRejectsMalformedInput(t *testing.T) {
	// A well-formed outer response whose responseType is not id-pkix-ocsp-basic.
	notBasic, err := asn1.Marshal(ocspResponseASN1{
		Status: asn1.Enumerated(ocsp.Success),
		Response: responseBytesASN1{
			ResponseType: asn1.ObjectIdentifier{1, 2, 3, 4},
			Response:     []byte{0x30, 0x00},
		},
	})
	if err != nil {
		t.Fatalf("marshaling non-basic response: %v", err)
	}
	// Basic response type, but the inner responseBytes are not a BasicOCSPResponse.
	badBasic, err := asn1.Marshal(ocspResponseASN1{
		Status:   asn1.Enumerated(ocsp.Success),
		Response: responseBytesASN1{ResponseType: oidPKIXOCSPBasic, Response: []byte("not DER")},
	})
	if err != nil {
		t.Fatalf("marshaling bad basicResponse: %v", err)
	}
	// A BasicOCSPResponse whose tbsResponseData is a DER value but not a
	// ResponseData (an ASN.1 NULL): reaches the third error branch.
	badTBSInner, err := asn1.Marshal(basicResponseASN1{
		TBSResponseData:    asn1.RawValue{FullBytes: []byte{0x05, 0x00}},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWithSHA256},
		Signature:          asn1.BitString{Bytes: []byte{0x01}, BitLength: 8},
	})
	if err != nil {
		t.Fatalf("marshaling bad responseData: %v", err)
	}
	badTBS, err := asn1.Marshal(ocspResponseASN1{
		Status:   asn1.Enumerated(ocsp.Success),
		Response: responseBytesASN1{ResponseType: oidPKIXOCSPBasic, Response: badTBSInner},
	})
	if err != nil {
		t.Fatalf("marshaling bad responseData wrapper: %v", err)
	}

	cases := map[string][]byte{
		"nil":                    nil,
		"empty":                  {},
		"plain text":             []byte("503 Service Unavailable"),
		"empty SEQUENCE":         {0x30, 0x00},
		"length claims 64 KiB":   {0x30, 0x82, 0xFF, 0xFF},
		"ASN.1 NULL":             {0x05, 0x00},
		"unsigned malformed":     OCSPMalformedResponse,
		"unsigned try-later":     OCSPTryLaterResponse,
		"unsigned unauthorized":  OCSPUnauthorizedResponse,
		"non-basic responseType": notBasic,
		"undecodable basic":      badBasic,
		"undecodable tbs":        badTBS,
	}
	for name, der := range cases {
		t.Run(name, func(t *testing.T) {
			nonce, err := OCSPResponseNonce(der)
			if err == nil {
				t.Fatalf("OCSPResponseNonce accepted %s, returning %x", name, nonce)
			}
			if nonce != nil {
				t.Errorf("returned nonce %x alongside error %v", nonce, err)
			}
		})
	}
}

// TestOCSPResponseNonceAcceptsUnwrappedValue covers the interoperability
// fallback: RFC 8954 wraps the nonce in an OCTET STRING inside extnValue, but
// implementations predating it place the raw bytes there. The extractor peels
// one OCTET STRING layer when it can and otherwise hands back the raw value,
// which is what lets a client compare against its own nonce either way.
func TestOCSPResponseNonceAcceptsUnwrappedValue(t *testing.T) {
	caKey := newECDSAKey(t)
	ca := newTestCA(t, caKey)
	// 0xAB is not a plausible DER tag here, so the OCTET STRING peel fails and
	// the raw extension value is returned.
	raw := bytes.Repeat([]byte{0xAB}, 16)

	tbs := responseDataASN1{
		RawResponderID: asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: ca.RawSubject},
		ProducedAt:     time.Now().Truncate(time.Minute).UTC(),
		Responses: []singleResponseASN1{{
			CertID: certIDASN1{
				HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA1, Parameters: asn1.RawValue{Tag: 5}},
				NameHash:      make([]byte, 20),
				IssuerKeyHash: make([]byte, 20),
				SerialNumber:  big.NewInt(1),
			},
			Good:       true,
			ThisUpdate: time.Now().Truncate(time.Second).UTC(),
		}},
		// Deliberately *not* wrapped in an OCTET STRING.
		ResponseExtensions: []pkix.Extension{{Id: OIDNonce, Value: raw}},
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatalf("marshaling responseData: %v", err)
	}
	basicDER, err := asn1.Marshal(basicResponseASN1{
		TBSResponseData:    asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWithSHA256},
		Signature:          asn1.BitString{Bytes: []byte{0x01}, BitLength: 8},
	})
	if err != nil {
		t.Fatalf("marshaling basicResponse: %v", err)
	}
	respDER, err := asn1.Marshal(ocspResponseASN1{
		Status:   asn1.Enumerated(ocsp.Success),
		Response: responseBytesASN1{ResponseType: oidPKIXOCSPBasic, Response: basicDER},
	})
	if err != nil {
		t.Fatalf("marshaling response: %v", err)
	}

	got, err := OCSPResponseNonce(respDER)
	if err != nil {
		t.Fatalf("OCSPResponseNonce: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Errorf("unwrapped nonce = %x, want %x", got, raw)
	}
}
