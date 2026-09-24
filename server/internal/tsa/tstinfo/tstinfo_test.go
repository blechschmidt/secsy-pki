package tstinfo

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

// Everything in this file is attacker-reachable: a TimeStampResp arrives over
// plain HTTP from whatever TSA a peer names, and a TimeStampToken arrives inside
// a CAdES signature, an RFC 4998 evidence record, or an HSM audit commitment
// supplied by whoever produced the artifact. ParseTokenInfo explicitly does NOT
// verify the signature, so every byte it touches is untrusted at parse time.
// The tests therefore care about two things: no panic, and no silent misparse
// (a field that decodes to a plausible-but-wrong value is worse than an error).

// ---- DER builders ----------------------------------------------------------

// CMS content-type OIDs (RFC 5652 §4, §5.1).
var (
	testOIDSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	testOIDData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

// testContentInfo / testSignedData are the minimum CMS scaffolding needed to
// wrap a TSTInfo. Tokens are assembled, not signed: ParseTokenInfo deliberately
// ignores signatures, so a degenerate (signer-less) SignedData drives exactly
// the decode path being tested with no RSA key, keystore, or HSM involved. That
// keeps every case in this file deterministic and sub-millisecond.
type testContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type testEncapContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type testSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo      testEncapContentInfo
	Certificates     asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos      []asn1.RawValue `asn1:"set"`
}

// tstInfoTemplate is the MARSHALING layout of TSTInfo (RFC 3161 §2.4.2). It
// mirrors internal/tsa's rawTSTInfo, not this package's parsedTSTInfo, on
// purpose: encoding with the producer's layout and decoding with the parser's is
// the only way the optional-field tag dispatch (accuracy SEQUENCE vs. ordering
// BOOLEAN vs. nonce INTEGER) is actually put under test. Building with
// parsedTSTInfo would make the tests agree with the parser by construction.
type tstInfoTemplate struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       asn1.RawValue    `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

// testGenTime is a fixed, second-resolution UTC instant: GeneralizedTime has no
// sub-second field here, so anything finer would not survive the round trip.
var testGenTime = time.Date(2026, 3, 14, 15, 9, 26, 0, time.UTC)

// testDigest is a real SHA-256 digest, so the imprint length matches the
// declared algorithm in the baseline token.
var testDigest = sha256.Sum256([]byte("the quick brown fox"))

// baseTSTInfo returns a minimal conforming TSTInfo: only the mandatory fields,
// every optional one absent. Cases mutate one thing at a time from here.
func baseTSTInfo() tstInfoTemplate {
	return tstInfoTemplate{
		Version: 1,
		Policy:  asn1.ObjectIdentifier{2, 999, 1, 1},
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
			HashedMessage: testDigest[:],
		},
		SerialNumber: big.NewInt(0x0badc0de),
		GenTime:      testGenTime,
	}
}

func mustMarshal(t testing.TB, v any) []byte {
	t.Helper()
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatalf("asn1.Marshal(%T): %v", v, err)
	}
	return der
}

// wrapToken builds a TimeStampToken: a ContentInfo(signedData) whose
// encapsulated content has the given eContentType. A nil eContent omits the
// [0] eContent field entirely (the "ContentInfo whose eContent is absent" case).
func wrapToken(t testing.TB, eContentType asn1.ObjectIdentifier, eContent []byte) []byte {
	t.Helper()
	sd := testSignedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{},
		ContentInfo:      testEncapContentInfo{ContentType: eContentType},
		SignerInfos:      []asn1.RawValue{},
	}
	if eContent != nil {
		// eContent is [0] EXPLICIT OCTET STRING (RFC 5652 §5.2).
		sd.ContentInfo.Content = asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: mustMarshal(t, eContent),
		}
	}
	return mustMarshal(t, testContentInfo{
		ContentType: testOIDSignedData,
		Content: asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: mustMarshal(t, sd),
		},
	})
}

// tokenFor mints a TimeStampToken carrying the given TSTInfo template.
func tokenFor(t testing.TB, tmpl tstInfoTemplate) []byte {
	t.Helper()
	return wrapToken(t, OIDTSTInfo, mustMarshal(t, tmpl))
}

// testStatusInfo / testResp are the marshaling layouts of PKIStatusInfo and
// TimeStampResp, again deliberately independent of the parser's structs.
type testStatusInfo struct {
	Status       int
	StatusString asn1.RawValue  `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

type testResp struct {
	Status asn1.RawValue
	Token  asn1.RawValue `asn1:"optional"`
}

// freeText encodes a PKIFreeText (SEQUENCE OF UTF8String).
func freeText(t testing.TB, s string) asn1.RawValue {
	t.Helper()
	utf8DER, err := asn1.MarshalWithParams(s, "utf8")
	if err != nil {
		t.Fatalf("marshal utf8: %v", err)
	}
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: utf8DER}
}

// respWith builds a TimeStampResp around a status and an optional token.
func respWith(t testing.TB, status testStatusInfo, token []byte) []byte {
	t.Helper()
	r := testResp{Status: asn1.RawValue{FullBytes: mustMarshal(t, status)}}
	if token != nil {
		r.Token = asn1.RawValue{FullBytes: token}
	}
	return mustMarshal(t, r)
}

// failBits returns a BIT STRING with a single PKIFailureInfo bit set.
func failBits(bit int) asn1.BitString {
	n := bit + 1
	b := make([]byte, (n+7)/8)
	b[bit/8] |= 0x80 >> uint(bit%8)
	return asn1.BitString{Bytes: b, BitLength: n}
}

// deepNest returns `depth` nested SEQUENCE headers around an ASN.1 NULL. A
// parser that recurses per nesting level blows the stack on input like this, so
// the decoders must reject it without unwinding.
func deepNest(depth int) []byte {
	out := []byte{0x05, 0x00}
	for i := 0; i < depth; i++ {
		l := len(out)
		out = append([]byte{0x30, 0x82, byte(l >> 8), byte(l)}, out...)
	}
	return out
}

// ---- DigestForOID ----------------------------------------------------------

// TestDigestForOID pins the exact set of message-imprint hashes this package
// accepts. The negative half matters most: OID comparison must be exact, so a
// prefix of a supported OID, or a supported OID with an extra arc appended, must
// NOT be accepted — that is the shape a lenient (prefix-matching) rewrite would
// break, and it would let an attacker smuggle an unexpected algorithm past the
// allowlist.
func TestDigestForOID(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		want crypto.Hash
		ok   bool
	}{
		{"sha1", asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, crypto.SHA1, true},
		{"sha256", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, crypto.SHA256, true},
		{"sha384", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}, crypto.SHA384, true},
		{"sha512", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}, crypto.SHA512, true},

		{"nil OID", nil, 0, false},
		{"empty OID", asn1.ObjectIdentifier{}, 0, false},
		// sha224 and sha512/256 live in the same arc as the accepted hashes but
		// are not accepted message-imprint algorithms here.
		{"sha224 not accepted", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}, 0, false},
		{"sha512/256 not accepted", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 6}, 0, false},
		{"sha3-256 not accepted", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}, 0, false},
		{"md5 not accepted", asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}, 0, false},
		{"rsaEncryption is not a digest", asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, 0, false},
		// Exact-match guards.
		{"proper prefix of sha256", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2}, 0, false},
		{"sha256 with extra arc", asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1, 1}, 0, false},
		{"sha1 with extra arc", asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26, 0}, 0, false},
		{"proper prefix of sha1", asn1.ObjectIdentifier{1, 3, 14, 3, 2}, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := DigestForOID(tc.oid)
			if ok != tc.ok {
				t.Fatalf("DigestForOID(%v) ok = %v, want %v", tc.oid, ok, tc.ok)
			}
			if got != tc.want {
				t.Fatalf("DigestForOID(%v) = %v, want %v", tc.oid, got, tc.want)
			}
			if !ok {
				// A rejected OID must yield the zero Hash, never a usable one:
				// callers key off ok, but a non-zero hash here would make a
				// caller that forgot the check silently digest with it.
				if got != 0 {
					t.Fatalf("rejected OID yielded hash %v, want the zero Hash", got)
				}
				return
			}
			// Callers do info.Hash.New() — crypto.Hash.New panics when the
			// implementation is not linked into the binary, so every hash this
			// function can return must be registered.
			if !got.Available() {
				t.Fatalf("DigestForOID returned %v, which is not linked into the binary; "+
					"New() on it would panic in every caller", got)
			}
			if got.Size() != len(got.New().Sum(nil)) {
				t.Fatalf("%v reports Size %d but produces %d bytes", got, got.Size(), len(got.New().Sum(nil)))
			}
		})
	}
}

// TestDigestForOIDMatchesRFC3161ImprintSizes ties each accepted OID to a
// specific digest length. The sha384 and sha512 OIDs differ by a single arc, so
// a copy/paste swap between them would pass TestDigestForOID's generic
// self-consistency checks; only pinning the expected size catches it.
func TestDigestForOIDMatchesRFC3161ImprintSizes(t *testing.T) {
	tests := []struct {
		oid  asn1.ObjectIdentifier
		size int
	}{
		{asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, 20},             // sha1
		{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, 32}, // sha256
		{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}, 48}, // sha384
		{asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}, 64}, // sha512
	}
	for _, tc := range tests {
		h, ok := DigestForOID(tc.oid)
		if !ok {
			t.Fatalf("DigestForOID(%v) rejected a required algorithm", tc.oid)
		}
		if h.Size() != tc.size {
			t.Fatalf("DigestForOID(%v) = %v (size %d), want size %d", tc.oid, h, h.Size(), tc.size)
		}
	}
}

// ---- ExtractToken ----------------------------------------------------------

// TestExtractTokenMalformed covers the adversarial surface of the response
// parser. Every case must produce an error and no token; a panic or a returned
// token would be the bug.
func TestExtractTokenMalformed(t *testing.T) {
	validToken := tokenFor(t, baseTSTInfo())
	validResp := respWith(t, testStatusInfo{Status: StatusGranted}, validToken)

	tests := []struct {
		name    string
		der     []byte
		wantErr string // substring; "" means any error
	}{
		{"nil", nil, ""},
		{"empty", []byte{}, ""},
		{"empty SEQUENCE (no status)", []byte{0x30, 0x00}, ""},
		{"not DER at all", []byte("hello, world"), ""},
		{"ASN.1 NULL", []byte{0x05, 0x00}, ""},
		{"bare INTEGER", []byte{0x02, 0x01, 0x00}, ""},
		// A long-form length claiming 64 KiB with no body must not cause an
		// allocation of that size or an out-of-range slice.
		{"length claims 64 KiB, empty body", []byte{0x30, 0x82, 0xff, 0xff}, ""},
		// RFC 3161 is DER; BER indefinite lengths must be refused outright
		// rather than half-parsed.
		{"indefinite length (BER)", []byte{0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00}, "indefinite"},
		{"trailing garbage after response", append(append([]byte{}, validResp...), 0x00), "trailing data"},
		{"trailing valid DER after response", append(append([]byte{}, validResp...), 0x05, 0x00), "trailing data"},
		{"status is an INTEGER, not a PKIStatusInfo", mustMarshal(t, testResp{
			Status: asn1.RawValue{FullBytes: []byte{0x02, 0x01, 0x00}},
		}), "PKIStatusInfo"},
		// A status that does not fit a Go int must be rejected, not truncated
		// into the granted range.
		{"status integer too large for int", mustMarshal(t, testResp{
			Status: asn1.RawValue{FullBytes: mustMarshal(t, struct{ N *big.Int }{
				N: new(big.Int).Lsh(big.NewInt(1), 200),
			})},
		}), "PKIStatusInfo"},
		{"5000-deep nesting", deepNest(5000), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token, err := ExtractToken(tc.der)
			if err == nil {
				t.Fatalf("ExtractToken accepted %d bytes and returned a %d-byte token", len(tc.der), len(token))
			}
			if token != nil {
				t.Fatalf("ExtractToken returned both an error (%v) and a %d-byte token", err, len(token))
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestExtractTokenTruncated feeds every prefix of a well-formed response. A
// length-driven DER parser that trusts a declared length over the buffer it
// actually has slices out of range; none of these may panic or yield a token.
func TestExtractTokenTruncated(t *testing.T) {
	full := respWith(t, testStatusInfo{Status: StatusGranted}, tokenFor(t, baseTSTInfo()))
	for n := 0; n < len(full); n++ {
		token, err := ExtractToken(full[:n])
		if err == nil {
			t.Fatalf("ExtractToken accepted a %d-byte prefix of a %d-byte response (token %d bytes)",
				n, len(full), len(token))
		}
	}
	if _, err := ExtractToken(full); err != nil {
		t.Fatalf("the untruncated response must still parse: %v", err)
	}
}

// TestExtractTokenStatusHandling is the security-relevant half: a token must be
// surfaced for granted/grantedWithMods and for nothing else. A response that
// reports failure while still carrying a token is a real shape (a buggy or
// hostile TSA), and returning that token would hand the caller a timestamp the
// authority explicitly refused to vouch for.
func TestExtractTokenStatusHandling(t *testing.T) {
	token := tokenFor(t, baseTSTInfo())

	tests := []struct {
		name      string
		status    testStatusInfo
		token     []byte
		wantToken bool
		wantErr   string
	}{
		{"granted", testStatusInfo{Status: StatusGranted}, token, true, ""},
		{"grantedWithMods", testStatusInfo{Status: StatusGrantedWithMod}, token, true, ""},
		{
			"granted but no token",
			testStatusInfo{Status: StatusGranted}, nil, false, "carries no token",
		},
		{
			"rejection with statusString and failInfo",
			testStatusInfo{Status: 2, StatusString: freeText(t, "bad alg"), FailInfo: failBits(0)},
			nil, false, "status 2",
		},
		{
			// A rejection that still carries a token: the status must win.
			"rejection carrying a token anyway",
			testStatusInfo{Status: 2, StatusString: freeText(t, "no"), FailInfo: failBits(2)},
			token, false, "status 2",
		},
		{"waiting (3) with a token", testStatusInfo{Status: 3}, token, false, "status 3"},
		{"revocationWarning (4)", testStatusInfo{Status: 4}, token, false, "status 4"},
		{"revocationNotification (5)", testStatusInfo{Status: 5}, token, false, "status 5"},
		{"negative status", testStatusInfo{Status: -1}, token, false, "status -1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ExtractToken(respWith(t, tc.status, tc.token))
			if tc.wantToken {
				if err != nil {
					t.Fatalf("ExtractToken: %v", err)
				}
				if !bytes.Equal(got, token) {
					t.Fatal("ExtractToken did not return the embedded token verbatim")
				}
				// The bytes must be usable as-is by the CMS layer.
				if _, err := ParseTokenInfo(got); err != nil {
					t.Fatalf("extracted token does not parse: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ExtractToken accepted status %d and returned %d bytes", tc.status.Status, len(got))
			}
			if got != nil {
				t.Fatalf("ExtractToken returned a token alongside error %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestExtractTokenRejectionReportsFailInfo checks the failInfo bit length is
// reported for BOTH PKIStatusInfo shapes RFC 3161 permits. statusString is
// OPTIONAL, so a conforming TSA may send {status, failInfo} with no
// statusString; decoding that shape with an `optional` asn1.RawValue field would
// let the RawValue (which matches ANY tag) swallow the failInfo BIT STRING and
// report "bits 0" — exactly the hazard parsedTSTInfo's doc comment warns about.
func TestExtractTokenRejectionReportsFailInfo(t *testing.T) {
	const failUnacceptedPolicy = 15
	tests := []struct {
		name   string
		status testStatusInfo
	}{
		{"with statusString", testStatusInfo{
			Status:       2,
			StatusString: freeText(t, "policy not supported"),
			FailInfo:     failBits(failUnacceptedPolicy),
		}},
		{"statusString omitted", testStatusInfo{
			Status:   2,
			FailInfo: failBits(failUnacceptedPolicy),
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ExtractToken(respWith(t, tc.status, nil))
			if err == nil {
				t.Fatal("ExtractToken accepted a rejection response")
			}
			// failInfo bit 15 (unacceptedPolicy) trims to a 16-bit BIT STRING.
			if !strings.Contains(err.Error(), "failInfo bits 16") {
				t.Fatalf("error = %q, want it to report the failInfo bit length 16; "+
					"a zero here means the statusString field swallowed the failInfo BIT STRING", err)
			}
		})
	}
}

// TestExtractTokenIgnoresExtraSequenceElements documents that Go's encoding/asn1
// tolerates unknown trailing elements inside a SEQUENCE (forward
// compatibility). The property that matters is that the token actually returned
// is still the real one, not the smuggled extra element.
func TestExtractTokenIgnoresExtraSequenceElements(t *testing.T) {
	token := tokenFor(t, baseTSTInfo())
	type extended struct {
		Status asn1.RawValue
		Token  asn1.RawValue
		Extra  asn1.RawValue
	}
	der := mustMarshal(t, extended{
		Status: asn1.RawValue{FullBytes: mustMarshal(t, testStatusInfo{Status: StatusGranted})},
		Token:  asn1.RawValue{FullBytes: token},
		Extra:  asn1.RawValue{FullBytes: []byte{0x05, 0x00}},
	})
	got, err := ExtractToken(der)
	if err != nil {
		t.Fatalf("ExtractToken: %v", err)
	}
	if !bytes.Equal(got, token) {
		t.Fatal("ExtractToken returned something other than the real token")
	}
}

// ---- ParseTokenInfo: happy paths -------------------------------------------

// TestParseTokenInfoOptionalFields is the core anti-misparse test. TSTInfo has
// four optional fields in a row (accuracy, ordering, nonce, tsa) plus tagged
// extensions, and Go's asn1 dispatches them purely by tag. Every subset must
// decode to the same mandatory values, and — critically — the nonce must survive
// when accuracy is ABSENT: that is the case where an `optional` RawValue
// accuracy field would match the nonce INTEGER and silently eat it.
func TestParseTokenInfoOptionalFields(t *testing.T) {
	accuracy := asn1.RawValue{FullBytes: mustMarshal(t, rawAccuracy{Seconds: 1, Millis: 500})}
	// tsa is [0] EXPLICIT GeneralName; directoryName is the [4] choice.
	dirName := mustMarshal(t, asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true,
		Bytes: mustMarshal(t, pkix.Name{CommonName: "Test TSA"}.ToRDNSequence()),
	})
	tsaName := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: dirName}
	nonce := new(big.Int).SetBytes([]byte{0x7f, 0xff, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02})
	ext := pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: []byte{0x01}}

	tests := []struct {
		name      string
		mutate    func(*tstInfoTemplate)
		wantNonce *big.Int
	}{
		{"mandatory fields only", func(*tstInfoTemplate) {}, nil},
		{"accuracy only", func(i *tstInfoTemplate) { i.Accuracy = accuracy }, nil},
		{"ordering only", func(i *tstInfoTemplate) { i.Ordering = true }, nil},
		// The regression the decode layout exists for: no accuracy, nonce present.
		{"nonce, no accuracy", func(i *tstInfoTemplate) { i.Nonce = nonce }, nonce},
		{"nonce and accuracy", func(i *tstInfoTemplate) { i.Accuracy = accuracy; i.Nonce = nonce }, nonce},
		{"ordering and nonce, no accuracy", func(i *tstInfoTemplate) { i.Ordering = true; i.Nonce = nonce }, nonce},
		{"tsa name only", func(i *tstInfoTemplate) { i.TSA = tsaName }, nil},
		{"tsa name and nonce, no accuracy", func(i *tstInfoTemplate) { i.TSA = tsaName; i.Nonce = nonce }, nonce},
		{"extensions only", func(i *tstInfoTemplate) { i.Extensions = []pkix.Extension{ext} }, nil},
		{"extensions and nonce, no accuracy/tsa", func(i *tstInfoTemplate) {
			i.Nonce = nonce
			i.Extensions = []pkix.Extension{ext}
		}, nonce},
		{"every optional field present", func(i *tstInfoTemplate) {
			i.Accuracy = accuracy
			i.Ordering = true
			i.Nonce = nonce
			i.TSA = tsaName
			i.Extensions = []pkix.Extension{ext}
		}, nonce},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := baseTSTInfo()
			tc.mutate(&tmpl)
			info, err := ParseTokenInfo(tokenFor(t, tmpl))
			if err != nil {
				t.Fatalf("ParseTokenInfo: %v", err)
			}
			// The mandatory fields must be identical regardless of which
			// optionals surround them.
			if !info.Policy.Equal(tmpl.Policy) {
				t.Errorf("policy = %v, want %v", info.Policy, tmpl.Policy)
			}
			if info.SerialNumber == nil || info.SerialNumber.Cmp(tmpl.SerialNumber) != 0 {
				t.Errorf("serial = %v, want %v", info.SerialNumber, tmpl.SerialNumber)
			}
			if !info.GenTime.Equal(testGenTime) {
				t.Errorf("genTime = %v, want %v", info.GenTime, testGenTime)
			}
			if info.Hash != crypto.SHA256 {
				t.Errorf("hash = %v, want SHA-256", info.Hash)
			}
			if !bytes.Equal(info.HashedMessage, testDigest[:]) {
				t.Errorf("imprint = %x, want %x", info.HashedMessage, testDigest[:])
			}
			switch {
			case tc.wantNonce == nil && info.Nonce != nil:
				t.Errorf("nonce = %v, want nil", info.Nonce)
			case tc.wantNonce != nil && info.Nonce == nil:
				t.Error("nonce was dropped: an adjacent optional field swallowed the INTEGER")
			case tc.wantNonce != nil && info.Nonce.Cmp(tc.wantNonce) != 0:
				t.Errorf("nonce = %v, want %v", info.Nonce, tc.wantNonce)
			}
		})
	}
}

// TestParseTokenInfoEveryAcceptedHash checks each accepted message-imprint
// algorithm decodes with the right crypto.Hash and a correctly sized imprint,
// so the OID-to-hash mapping is exercised through the full token path and not
// only through DigestForOID.
func TestParseTokenInfoEveryAcceptedHash(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		hash crypto.Hash
	}{
		{"sha1", oidSHA1, crypto.SHA1},
		{"sha256", oidSHA256, crypto.SHA256},
		{"sha384", oidSHA384, crypto.SHA384},
		{"sha512", oidSHA512, crypto.SHA512},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			imprint := make([]byte, tc.hash.Size())
			for i := range imprint {
				imprint[i] = byte(i)
			}
			tmpl := baseTSTInfo()
			tmpl.MessageImprint = messageImprint{
				HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: tc.oid, Parameters: asn1.NullRawValue},
				HashedMessage: imprint,
			}
			info, err := ParseTokenInfo(tokenFor(t, tmpl))
			if err != nil {
				t.Fatalf("ParseTokenInfo: %v", err)
			}
			if info.Hash != tc.hash {
				t.Fatalf("hash = %v, want %v", info.Hash, tc.hash)
			}
			if !bytes.Equal(info.HashedMessage, imprint) {
				t.Fatalf("imprint = %x, want %x", info.HashedMessage, imprint)
			}
		})
	}
}

// TestParseTokenInfoMissingAlgorithmParameters confirms an AlgorithmIdentifier
// with the parameters field absent (the RFC 5754 preferred encoding for SHA-2)
// is accepted, not just the NULL-parameters form this repo emits. Refusing it
// would break interop with conforming third-party TSAs.
func TestParseTokenInfoMissingAlgorithmParameters(t *testing.T) {
	tmpl := baseTSTInfo()
	tmpl.MessageImprint.HashAlgorithm = pkix.AlgorithmIdentifier{Algorithm: oidSHA256}
	info, err := ParseTokenInfo(tokenFor(t, tmpl))
	if err != nil {
		t.Fatalf("ParseTokenInfo with absent algorithm parameters: %v", err)
	}
	if info.Hash != crypto.SHA256 {
		t.Fatalf("hash = %v, want SHA-256", info.Hash)
	}
}

// TestParseTokenInfoGenTimeIsUTC checks the genTime decodes to the exact instant
// encoded. Every caller compares it against wall-clock bounds ("is this token
// from the future?"), so a time-zone or offset slip is a silent trust bug.
func TestParseTokenInfoGenTimeIsUTC(t *testing.T) {
	// Encode a genTime expressed in a non-UTC zone: GeneralizedTime carries the
	// offset, and the decoded instant must still be the same point in time.
	zone := time.FixedZone("UTC+7", 7*3600)
	tmpl := baseTSTInfo()
	tmpl.GenTime = testGenTime.In(zone)

	info, err := ParseTokenInfo(tokenFor(t, tmpl))
	if err != nil {
		t.Fatalf("ParseTokenInfo: %v", err)
	}
	if !info.GenTime.Equal(testGenTime) {
		t.Fatalf("genTime = %v, want the same instant as %v", info.GenTime, testGenTime)
	}
	if got := info.GenTime.UTC().Format(time.RFC3339); got != "2026-03-14T15:09:26Z" {
		t.Fatalf("genTime in UTC = %s, want 2026-03-14T15:09:26Z", got)
	}
}

// TestParseTokenInfoAcceptsUTCTimeGenTime pins a deliberate leniency. RFC 3161
// §2.4.2 requires genTime to be a GeneralizedTime, and parsedTSTInfo declares it
// `generalized` — but encoding/asn1 maps both time types onto time.Time and
// accepts a UTCTime on the wire regardless of the struct tag (the timeType
// override only applies to context-tagged fields). A non-conforming TSA's token
// therefore still decodes. What must hold is that the INSTANT is right: UTCTime
// carries a two-digit year with a 1950..2049 sliding window, and a window slip
// would silently move a token decades, defeating every freshness check built on
// genTime.
func TestParseTokenInfoAcceptsUTCTimeGenTime(t *testing.T) {
	base := baseTSTInfo()
	type utcGenTime struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint messageImprint
		SerialNumber   *big.Int
		GenTime        time.Time `asn1:"utc"`
	}
	for _, at := range []time.Time{
		testGenTime, // 2026 -> "26...."
		time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC), // top of the window
		time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC),      // bottom of the window
	} {
		der := mustMarshal(t, utcGenTime{
			Version: 1, Policy: base.Policy, MessageImprint: base.MessageImprint,
			SerialNumber: base.SerialNumber, GenTime: at,
		})
		info, err := ParseTokenInfo(wrapToken(t, OIDTSTInfo, der))
		if err != nil {
			t.Fatalf("ParseTokenInfo with a UTCTime genTime of %s: %v", at.Format(time.RFC3339), err)
		}
		if !info.GenTime.Equal(at) {
			t.Fatalf("genTime = %s, want %s: the UTCTime two-digit year was mapped to the wrong century",
				info.GenTime.Format(time.RFC3339), at.Format(time.RFC3339))
		}
	}
}

// ---- ParseTokenInfo: rejections --------------------------------------------

// TestParseTokenInfoMalformed walks the malformed-token surface: broken CMS,
// right-shaped CMS with the wrong content, and TSTInfos missing or corrupting a
// mandatory field. All must error with no panic and no partially populated
// TokenInfo.
func TestParseTokenInfoMalformed(t *testing.T) {
	// A TSTInfo whose serialNumber (mandatory) is missing.
	type noSerial struct {
		Version        int
		Policy         asn1.ObjectIdentifier
		MessageImprint messageImprint
		GenTime        time.Time `asn1:"generalized"`
	}
	base := baseTSTInfo()
	missingSerial := mustMarshal(t, noSerial{
		Version: 1, Policy: base.Policy, MessageImprint: base.MessageImprint, GenTime: base.GenTime,
	})
	unknownHash := base
	unknownHash.MessageImprint.HashAlgorithm = pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}, // SHA3-256
	}
	version0 := base
	version0.Version = 0
	version2 := base
	version2.Version = 2

	tests := []struct {
		name    string
		der     []byte
		wantErr string
	}{
		{"nil", nil, ""},
		{"empty", []byte{}, ""},
		{"not DER", []byte("this is not a token"), ""},
		{"ASN.1 NULL", []byte{0x05, 0x00}, ""},
		{"empty SEQUENCE", []byte{0x30, 0x00}, ""},
		{"indefinite length (BER)", []byte{0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00}, "indefinite"},
		{"5000-deep nesting", deepNest(5000), ""},
		// Valid DER of the wrong type: a ContentInfo that is not signedData.
		{"ContentInfo of type data", mustMarshal(t, testContentInfo{
			ContentType: testOIDData,
			Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
				Bytes: mustMarshal(t, []byte("payload"))},
		}), "signedData"},
		// A bare certificate-style SEQUENCE: right outer shape, wrong content.
		{"SEQUENCE of integers", mustMarshal(t, struct{ A, B int }{1, 2}), ""},
		// A SignedData carrying data, not a TSTInfo: must be refused on the
		// eContentType rather than reinterpreting the bytes as a TSTInfo.
		{"eContentType is data", wrapToken(t, testOIDData, mustMarshal(t, base)), "id-ct-TSTInfo"},
		{"eContentType is a random OID", wrapToken(t,
			asn1.ObjectIdentifier{1, 2, 3, 4}, mustMarshal(t, base)), "id-ct-TSTInfo"},
		// eContent absent entirely, and eContent present but empty.
		{"eContent absent", wrapToken(t, OIDTSTInfo, nil), "no encapsulated TSTInfo"},
		{"eContent empty OCTET STRING", wrapToken(t, OIDTSTInfo, []byte{}), "no encapsulated TSTInfo"},
		{"eContent is not a TSTInfo", wrapToken(t, OIDTSTInfo, []byte{0x05, 0x00}), "parsing TSTInfo"},
		{"eContent is truncated DER", wrapToken(t, OIDTSTInfo, []byte{0x30, 0x7f, 0x02}), "parsing TSTInfo"},
		// Mandatory-field problems inside an otherwise well-formed token.
		{"TSTInfo missing serialNumber", wrapToken(t, OIDTSTInfo, missingSerial), "parsing TSTInfo"},
		{"version 0", tokenFor(t, version0), "unsupported TSTInfo version 0"},
		{"version 2", tokenFor(t, version2), "unsupported TSTInfo version 2"},
		{"unknown imprint hash OID", tokenFor(t, unknownHash), "unsupported message-imprint hash"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info, err := ParseTokenInfo(tc.der)
			if err == nil {
				t.Fatalf("ParseTokenInfo accepted %d bytes: %+v", len(tc.der), info)
			}
			if info != nil {
				t.Fatalf("ParseTokenInfo returned both an error (%v) and a TokenInfo", err)
			}
			if tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestParseTokenInfoTruncated feeds every prefix of a valid token. Truncation is
// the cheapest way to reach an out-of-range slice in a DER parser.
func TestParseTokenInfoTruncated(t *testing.T) {
	full := tokenFor(t, baseTSTInfo())
	for n := 0; n < len(full); n++ {
		if info, err := ParseTokenInfo(full[:n]); err == nil {
			t.Fatalf("ParseTokenInfo accepted a %d-byte prefix of a %d-byte token: %+v", n, len(full), info)
		}
	}
	if _, err := ParseTokenInfo(full); err != nil {
		t.Fatalf("the untruncated token must still parse: %v", err)
	}
}

// TestParseTokenInfoBitFlips walks a valid token flipping one bit at a time. The
// contract is only "never panic, never return (nil, nil)" — a flip inside the
// imprint bytes legitimately still parses.
func TestParseTokenInfoBitFlips(t *testing.T) {
	full := tokenFor(t, baseTSTInfo())
	for i := range full {
		for _, mask := range []byte{0x01, 0x80} {
			mutated := append([]byte{}, full...)
			mutated[i] ^= mask
			info, err := ParseTokenInfo(mutated)
			if err == nil && info == nil {
				t.Fatalf("ParseTokenInfo returned (nil, nil) for a flip of bit %#x at offset %d", mask, i)
			}
			if err == nil && info.SerialNumber == nil {
				// Callers call info.SerialNumber.String() straight out of the
				// parser; a successful parse must always populate it.
				t.Fatalf("ParseTokenInfo succeeded with a nil SerialNumber (flip %#x at %d)", mask, i)
			}
		}
	}
}

// TestParseTokenInfoRejectsTrailingDataAfterTSTInfo pins the DER strictness of
// the encapsulated content. Bytes appended after the TSTInfo inside eContent
// give the token two readings — one for a parser that stops at the SEQUENCE and
// another for one that keeps going — which is precisely the ambiguity
// ExtractToken and ParseRequest already refuse ("trailing data after ...").
func TestParseTokenInfoRejectsTrailingDataAfterTSTInfo(t *testing.T) {
	tstDER := mustMarshal(t, baseTSTInfo())
	for _, trailer := range [][]byte{
		{0x00},                 // a stray zero byte
		{0x05, 0x00},           // a well-formed ASN.1 NULL
		mustMarshal(t, 424242), // a second, complete DER value
	} {
		content := append(append([]byte{}, tstDER...), trailer...)
		if info, err := ParseTokenInfo(wrapToken(t, OIDTSTInfo, content)); err == nil {
			t.Fatalf("ParseTokenInfo accepted % x appended after the TSTInfo: %+v", trailer, info)
		}
	}
}

// TestParseTokenInfoImprintLengthIsNotSilentlyFixed guards the one misparse that
// would be dangerous: a message imprint whose length disagrees with the declared
// algorithm must never be padded, truncated, or otherwise reshaped to the hash
// size. Every caller verifies with bytes.Equal(h.Sum(nil), info.HashedMessage),
// so as long as the wrong length is surfaced verbatim (or the token is rejected)
// verification fails closed.
func TestParseTokenInfoImprintLengthIsNotSilentlyFixed(t *testing.T) {
	tests := []struct {
		name    string
		imprint []byte
	}{
		{"empty imprint", []byte{}},
		{"two bytes for sha256", []byte{0x01, 0x02}},
		{"sha1-length imprint declared as sha256", make([]byte, 20)},
		{"sha512-length imprint declared as sha256", make([]byte, 64)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := baseTSTInfo()
			tmpl.MessageImprint.HashedMessage = tc.imprint
			info, err := ParseTokenInfo(tokenFor(t, tmpl))
			if err != nil {
				return // rejecting a length-mismatched imprint is also fine
			}
			if info.Hash != crypto.SHA256 {
				t.Fatalf("hash = %v, want the declared SHA-256", info.Hash)
			}
			if len(info.HashedMessage) != len(tc.imprint) {
				t.Fatalf("imprint length = %d, want the %d bytes actually encoded; "+
					"reshaping it to the hash size would let a bogus imprint compare equal to a real digest",
					len(info.HashedMessage), len(tc.imprint))
			}
			if !bytes.Equal(info.HashedMessage, tc.imprint) {
				t.Fatalf("imprint = %x, want %x", info.HashedMessage, tc.imprint)
			}
		})
	}
}

// TestParseTokenInfoRoundTripThroughExtractToken exercises the pipeline every
// caller actually uses: a TimeStampResp in, a fully decoded TSTInfo out.
func TestParseTokenInfoRoundTripThroughExtractToken(t *testing.T) {
	nonce := big.NewInt(0x5eed5eed)
	tmpl := baseTSTInfo()
	tmpl.Nonce = nonce
	tmpl.Accuracy = asn1.RawValue{FullBytes: mustMarshal(t, rawAccuracy{Seconds: 1})}

	respDER := respWith(t, testStatusInfo{Status: StatusGrantedWithMod}, tokenFor(t, tmpl))
	token, err := ExtractToken(respDER)
	if err != nil {
		t.Fatalf("ExtractToken: %v", err)
	}
	info, err := ParseTokenInfo(token)
	if err != nil {
		t.Fatalf("ParseTokenInfo: %v", err)
	}
	if info.Nonce == nil || info.Nonce.Cmp(nonce) != 0 {
		t.Fatalf("nonce = %v, want %v", info.Nonce, nonce)
	}
	if !info.GenTime.Equal(testGenTime) {
		t.Fatalf("genTime = %v, want %v", info.GenTime, testGenTime)
	}
	// The imprint must be usable to re-derive the digest of the stamped data,
	// which is the whole point of the token.
	sum := info.Hash.New()
	sum.Write([]byte("the quick brown fox"))
	if !bytes.Equal(sum.Sum(nil), info.HashedMessage) {
		t.Fatal("the decoded imprint does not cover the data it was computed over")
	}
}
