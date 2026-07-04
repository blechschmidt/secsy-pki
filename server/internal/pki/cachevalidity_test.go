package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
	"time"
)

// TestOCSPResponseValidity checks the ThisUpdate/NextUpdate accessor the public
// responder relies on to derive RFC 5019 §6.2 caching headers, including the
// unparseable-input path.
func TestOCSPResponseValidity(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t, key)
	// OCSP times are GeneralizedTime (second precision); truncate so the parsed
	// values compare exactly.
	thisUpdate := time.Now().Add(-time.Minute).Truncate(time.Second)
	nextUpdate := thisUpdate.Add(24 * time.Hour)

	respDER, err := CreateOCSPResponse(key, ca, OCSPResponseSpec{
		Serial:     big.NewInt(42),
		Status:     OCSPGood,
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
		IssuerHash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("CreateOCSPResponse: %v", err)
	}

	gotThis, gotNext, ok := OCSPResponseValidity(respDER)
	if !ok {
		t.Fatal("OCSPResponseValidity ok = false, want true")
	}
	if !gotThis.Equal(thisUpdate) {
		t.Errorf("thisUpdate = %v, want %v", gotThis, thisUpdate)
	}
	if !gotNext.Equal(nextUpdate) {
		t.Errorf("nextUpdate = %v, want %v", gotNext, nextUpdate)
	}

	if _, _, ok := OCSPResponseValidity([]byte("not an OCSP response")); ok {
		t.Error("OCSPResponseValidity(garbage) ok = true, want false")
	}
}

// TestCRLValidity checks the number/ThisUpdate/NextUpdate accessor the CRL HTTP
// handlers rely on for cache metadata, including the unparseable-input path.
func TestCRLValidity(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t, key)
	// CRL times are UTCTime/GeneralizedTime (second precision).
	thisUpdate := time.Now().Add(-time.Minute).Truncate(time.Second)
	nextUpdate := thisUpdate.Add(7 * 24 * time.Hour)
	wantNumber := big.NewInt(7)

	der, err := CreateCRL(key, ca, CRLRequest{
		Number:     wantNumber,
		ThisUpdate: thisUpdate,
		NextUpdate: nextUpdate,
	})
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}

	number, gotThis, gotNext, ok := CRLValidity(der)
	if !ok {
		t.Fatal("CRLValidity ok = false, want true")
	}
	if number == nil || number.Cmp(wantNumber) != 0 {
		t.Errorf("number = %v, want %v", number, wantNumber)
	}
	if !gotThis.Equal(thisUpdate) {
		t.Errorf("thisUpdate = %v, want %v", gotThis, thisUpdate)
	}
	if !gotNext.Equal(nextUpdate) {
		t.Errorf("nextUpdate = %v, want %v", gotNext, nextUpdate)
	}

	if _, _, _, ok := CRLValidity([]byte("not a CRL")); ok {
		t.Error("CRLValidity(garbage) ok = true, want false")
	}
}
