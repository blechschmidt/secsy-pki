package tstinfo

import (
	"encoding/asn1"
	"math/big"
	"testing"
)

// fuzzSeeds returns the well-formed and known-adversarial inputs both targets
// start from: a valid response, a valid token, and the DER shapes that most
// often break a length-driven parser.
func fuzzSeeds(f *testing.F) ([]byte, []byte) {
	f.Helper()
	token := tokenFor(f, baseTSTInfo())
	resp := respWith(f, testStatusInfo{Status: StatusGranted}, token)

	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x00})                               // empty SEQUENCE
	f.Add([]byte{0x30, 0x82, 0xff, 0xff})                   // length claims 64 KiB, no body
	f.Add([]byte{0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00}) // BER indefinite length
	f.Add([]byte{0x05, 0x00})                               // ASN.1 NULL
	f.Add([]byte{0x02, 0x01, 0x00})                         // bare INTEGER
	f.Add([]byte("not-der-at-all"))
	f.Add(deepNest(64))
	return resp, token
}

// FuzzExtractToken drives the TimeStampResp parser. Responses arrive over plain
// HTTP from whatever TSA URL an operator (or a peer's artifact metadata) names,
// so the parser sees fully attacker-chosen bytes before any signature check.
func FuzzExtractToken(f *testing.F) {
	resp, token := fuzzSeeds(f)
	f.Add(resp)
	f.Add(token) // a token where a response is expected
	f.Add(respWith(f, testStatusInfo{Status: 2, StatusString: freeText(f, "no"), FailInfo: failBits(15)}, nil))
	f.Add(respWith(f, testStatusInfo{Status: StatusGranted}, nil))
	f.Add(append(append([]byte{}, resp...), 0x00))

	f.Fuzz(func(t *testing.T, der []byte) {
		got, err := ExtractToken(der)
		if err != nil {
			if got != nil {
				t.Fatalf("ExtractToken returned a %d-byte token alongside error %v", len(got), err)
			}
			return
		}
		// On success the token must be a non-empty subslice of the input: the
		// only legitimate result is the FullBytes of the embedded field.
		if len(got) == 0 {
			t.Fatal("ExtractToken reported success with an empty token")
		}
		if len(got) > len(der) {
			t.Fatalf("ExtractToken returned %d bytes from a %d-byte input", len(got), len(der))
		}
		// Feeding the result straight back into the next stage is exactly what
		// every caller does; it must not panic on anything ExtractToken blessed.
		_, _ = ParseTokenInfo(got)
	})
}

// FuzzParseTokenInfo drives the TimeStampToken/TSTInfo decoder. Tokens reach it
// from CAdES signatures, RFC 4998 evidence records, and HSM audit commitments —
// all of them third-party data, and ParseTokenInfo runs BEFORE (or without) any
// signature verification, so it must never panic and must never hand back a
// TokenInfo with the nil fields its callers dereference.
func FuzzParseTokenInfo(f *testing.F) {
	_, token := fuzzSeeds(f)
	f.Add(token)

	withEverything := baseTSTInfo()
	withEverything.Nonce = big.NewInt(1 << 40)
	withEverything.Ordering = true
	withEverything.Accuracy = asn1.RawValue{FullBytes: mustMarshal(f, rawAccuracy{Seconds: 1, Millis: 2, Micros: 3})}
	f.Add(tokenFor(f, withEverything))
	f.Add(wrapToken(f, OIDTSTInfo, nil))                            // eContent absent
	f.Add(wrapToken(f, OIDTSTInfo, []byte{}))                       // eContent empty
	f.Add(wrapToken(f, testOIDData, mustMarshal(f, baseTSTInfo()))) // wrong eContentType

	f.Fuzz(func(t *testing.T, der []byte) {
		info, err := ParseTokenInfo(der)
		if err != nil {
			if info != nil {
				t.Fatalf("ParseTokenInfo returned a TokenInfo alongside error %v", err)
			}
			return
		}
		if info == nil {
			t.Fatal("ParseTokenInfo returned (nil, nil)")
		}
		// Callers immediately do info.Hash.New() and info.SerialNumber.String();
		// a successful parse must make both safe.
		if !info.Hash.Available() {
			t.Fatalf("ParseTokenInfo accepted a token whose hash %v is not linked in; New() would panic", info.Hash)
		}
		if info.SerialNumber == nil {
			t.Fatal("ParseTokenInfo accepted a token with no serial number")
		}
		// GenTime is deliberately NOT asserted non-zero: GeneralizedTime can
		// legitimately encode year 1, which is Go's zero Time. Callers bound it
		// against the wall clock instead.
	})
}
