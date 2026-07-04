package pki

import (
	"encoding/hex"
	"testing"
	"time"
)

// TestPrivateKeyUsagePeriodKnownAnswer pins the exact DER a fixed input encodes
// to, so an accidental change to the hand-rolled ASN.1 is caught immediately. The
// value is a SEQUENCE (30) of a [0] (80) and a [1] (81) IMPLICIT GeneralizedTime,
// each 15 ASCII bytes (0x0F) of the form YYYYMMDDHHMMSSZ.
func TestPrivateKeyUsagePeriodKnownAnswer(t *testing.T) {
	nb := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	na := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	ext, err := PrivateKeyUsagePeriod{NotBefore: nb, NotAfter: na}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	if ext.Critical {
		t.Error("privateKeyUsagePeriod must be non-critical")
	}
	if !ext.Id.Equal(OIDPrivateKeyUsagePeriod) {
		t.Errorf("extension OID = %v, want %v", ext.Id, OIDPrivateKeyUsagePeriod)
	}
	// 30 22                              SEQUENCE, length 34
	//    80 0F 3230323530313032303330343035 5A   [0] "20250102030405Z"
	//    81 0F 3230323630313032303330343035 5A   [1] "20260102030405Z"
	want := "3022" +
		"800f" + hex.EncodeToString([]byte("20250102030405Z")) +
		"810f" + hex.EncodeToString([]byte("20260102030405Z"))
	if got := hex.EncodeToString(ext.Value); got != want {
		t.Errorf("DER mismatch:\n got  %s\n want %s", got, want)
	}
}

func TestPrivateKeyUsagePeriodRoundTrip(t *testing.T) {
	nb := time.Date(2030, 6, 15, 12, 0, 0, 0, time.UTC)
	na := time.Date(2031, 6, 15, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		in   PrivateKeyUsagePeriod
	}{
		{"both bounds", PrivateKeyUsagePeriod{NotBefore: nb, NotAfter: na}},
		{"notBefore only", PrivateKeyUsagePeriod{NotBefore: nb}},
		{"notAfter only", PrivateKeyUsagePeriod{NotAfter: na}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ext, err := tc.in.Extension()
			if err != nil {
				t.Fatalf("Extension: %v", err)
			}
			got, err := ParsePrivateKeyUsagePeriod(ext.Value)
			if err != nil {
				t.Fatalf("ParsePrivateKeyUsagePeriod: %v", err)
			}
			if !got.NotBefore.Equal(tc.in.NotBefore) {
				t.Errorf("notBefore = %v, want %v", got.NotBefore, tc.in.NotBefore)
			}
			if !got.NotAfter.Equal(tc.in.NotAfter) {
				t.Errorf("notAfter = %v, want %v", got.NotAfter, tc.in.NotAfter)
			}
		})
	}
}

// TestPrivateKeyUsagePeriodTruncatesSubSecond confirms sub-second precision is
// dropped (GeneralizedTime here carries no fractional seconds), so a round trip
// is stable at one-second resolution.
func TestPrivateKeyUsagePeriodTruncatesSubSecond(t *testing.T) {
	nb := time.Date(2025, 3, 4, 5, 6, 7, 500_000_000, time.UTC)
	ext, err := PrivateKeyUsagePeriod{NotBefore: nb}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	got, err := ParsePrivateKeyUsagePeriod(ext.Value)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if want := nb.Truncate(time.Second); !got.NotBefore.Equal(want) {
		t.Errorf("notBefore = %v, want %v (truncated)", got.NotBefore, want)
	}
}

// TestPrivateKeyUsagePeriodNonUTCNormalized confirms a non-UTC input is emitted
// as the equivalent UTC instant (GeneralizedTime is always Z here).
func TestPrivateKeyUsagePeriodNonUTCNormalized(t *testing.T) {
	loc := time.FixedZone("UTC+2", 2*60*60)
	nb := time.Date(2025, 1, 1, 14, 0, 0, 0, loc) // == 12:00:00Z
	ext, err := PrivateKeyUsagePeriod{NotBefore: nb}.Extension()
	if err != nil {
		t.Fatalf("Extension: %v", err)
	}
	got, err := ParsePrivateKeyUsagePeriod(ext.Value)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if want := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC); !got.NotBefore.Equal(want) {
		t.Errorf("notBefore = %v, want %v", got.NotBefore, want)
	}
}

func TestPrivateKeyUsagePeriodEncodeErrors(t *testing.T) {
	if _, err := (PrivateKeyUsagePeriod{}).Extension(); err == nil {
		t.Error("empty PrivateKeyUsagePeriod should not encode")
	}
	bad := PrivateKeyUsagePeriod{
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if _, err := bad.Extension(); err == nil {
		t.Error("notAfter before notBefore should not encode")
	}
}

func TestParsePrivateKeyUsagePeriodMalformed(t *testing.T) {
	cases := []struct {
		name  string
		value []byte
	}{
		{"not a sequence", []byte{0x02, 0x01, 0x05}}, // bare INTEGER
		{"empty sequence", []byte{0x30, 0x00}},
		{"trailing bytes", append(mustEncodePKUP(t), 0x00)},
		{"garbage", []byte{0x30, 0x03, 0x80, 0x01, 0x41}}, // [0] with a 1-byte "time"
		{"universal generalizedtime not context tag", []byte{0x30, 0x11, 0x18, 0x0F,
			'2', '0', '2', '5', '0', '1', '0', '2', '0', '3', '0', '4', '0', '5', 'Z'}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParsePrivateKeyUsagePeriod(tc.value); err == nil {
				t.Errorf("expected a decode error for %s", tc.name)
			}
		})
	}
}

// TestParsePrivateKeyUsagePeriodRejectsOutOfOrder confirms a [1] before [0]
// (notAfter before notBefore in the SEQUENCE) is rejected: DER requires the
// optional context tags in ascending order.
func TestParsePrivateKeyUsagePeriodRejectsOutOfOrder(t *testing.T) {
	// SEQUENCE { [1] "...Z", [0] "...Z" } — notAfter field emitted first.
	t1 := []byte("20260102030405Z")
	t0 := []byte("20250102030405Z")
	body := append(append([]byte{0x81, 0x0F}, t1...), append([]byte{0x80, 0x0F}, t0...)...)
	value := append([]byte{0x30, byte(len(body))}, body...)
	if _, err := ParsePrivateKeyUsagePeriod(value); err == nil {
		t.Error("expected out-of-order bounds to be rejected")
	}
}

func mustEncodePKUP(t *testing.T) []byte {
	t.Helper()
	ext, err := PrivateKeyUsagePeriod{NotBefore: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}.Extension()
	if err != nil {
		t.Fatal(err)
	}
	return ext.Value
}
