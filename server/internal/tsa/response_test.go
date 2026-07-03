package tsa

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// TestExtractTokenAndParseTokenInfo drives the client-side response helpers:
// the token extracted from a granted response matches the wire helper the
// tests already use, and its TSTInfo decodes to the request's imprint/nonce.
func TestExtractTokenAndParseTokenInfo(t *testing.T) {
	h := newHarness(t)
	fixed := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	h.authority.SetClock(func() time.Time { return fixed })

	data := []byte("artifact signature bytes")
	digest := sha256.Sum256(data)
	nonce := big.NewInt(0x5eed)
	reqDER, err := MakeRequest(crypto.SHA256, digest[:], &RequestOptions{Nonce: nonce, CertReq: true})
	if err != nil {
		t.Fatalf("MakeRequest: %v", err)
	}
	result, err := h.authority.Stamp(context.Background(), reqDER)
	if err != nil {
		t.Fatalf("Stamp: %v", err)
	}
	if !result.Granted {
		t.Fatalf("request rejected: %s", result.Detail)
	}

	token, err := ExtractToken(result.Response)
	if err != nil {
		t.Fatalf("ExtractToken: %v", err)
	}
	if want := parseGrantedResp(t, result.Response); !bytes.Equal(token, want) {
		t.Fatal("ExtractToken and the test wire parser disagree")
	}

	info, err := ParseTokenInfo(token)
	if err != nil {
		t.Fatalf("ParseTokenInfo: %v", err)
	}
	if info.Hash != crypto.SHA256 || !bytes.Equal(info.HashedMessage, digest[:]) {
		t.Error("TSTInfo message imprint does not match the request")
	}
	if info.Nonce == nil || info.Nonce.Cmp(nonce) != 0 {
		t.Errorf("TSTInfo nonce = %v, want %v", info.Nonce, nonce)
	}
	if !info.GenTime.Equal(fixed) {
		t.Errorf("TSTInfo genTime = %v, want %v", info.GenTime, fixed)
	}
	if info.SerialNumber == nil || info.SerialNumber.Sign() <= 0 {
		t.Error("TSTInfo serial missing or non-positive")
	}
}

// TestExtractTokenRejection confirms a rejection response yields an error, not
// a token.
func TestExtractTokenRejection(t *testing.T) {
	respDER, err := rejectionResponse(FailureBadAlg, "nope")
	if err != nil {
		t.Fatalf("rejectionResponse: %v", err)
	}
	if _, err := ExtractToken(respDER); err == nil {
		t.Fatal("ExtractToken accepted a rejection response")
	}
}

// TestParseTokenInfoRejectsWrongContentType confirms a SignedData that is not
// a timestamp token (eContentType != id-ct-TSTInfo) is refused rather than
// having its content misinterpreted as a TSTInfo.
func TestParseTokenInfoRejectsWrongContentType(t *testing.T) {
	h := newHarness(t)
	// A perfectly valid CMS message over ordinary data, signed by the TSA cert.
	// Build it via the shared builder with the default (data) content type.
	signer, err := h.authority.provider.Signer(context.Background(), keyprovider.KeyRef{Label: "tsa"})
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	der, err := cms.BuildSignedData(cms.SignedDataOpts{
		Content:    []byte("not a TSTInfo"),
		SignerCert: h.tsaCert,
		Signer:     signer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseTokenInfo(der); err == nil {
		t.Fatal("ParseTokenInfo accepted a non-TSTInfo content type")
	}
}
