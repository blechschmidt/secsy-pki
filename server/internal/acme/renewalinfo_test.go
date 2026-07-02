package acme

import (
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

// TestCertIDRoundTrip verifies the ARI CertID encoding matches the
// draft-ietf-acme-ari §4.1 construction and round-trips.
func TestCertIDRoundTrip(t *testing.T) {
	aki := []byte{0x69, 0x88, 0x5b, 0x6b, 0x87, 0x46, 0x40, 0x41, 0xe1, 0xb3,
		0x7b, 0x84, 0x7b, 0xa0, 0xae, 0x2c, 0xde, 0x01, 0xc8, 0xd4}
	serial := big.NewInt(0x8765_4321)

	certID, err := certIDForCertificate(aki, serial)
	if err != nil {
		t.Fatalf("certIDForCertificate: %v", err)
	}

	// The serial half must encode the DER content octets (leading zero because
	// 0x87 has its high bit set), matching the spec's worked example "AIdlQyE".
	if got := base64.RawURLEncoding.EncodeToString(aki) + ".AIdlQyE"; got != certID {
		t.Fatalf("CertID = %q, want %q", certID, got)
	}

	parsed, err := parseCertID(certID)
	if err != nil {
		t.Fatalf("parseCertID: %v", err)
	}
	if !bytesEqual(parsed.AKI, aki) {
		t.Errorf("AKI round-trip mismatch: got %x want %x", parsed.AKI, aki)
	}
	if parsed.Serial.Cmp(serial) != 0 {
		t.Errorf("serial round-trip mismatch: got %s want %s", parsed.Serial, serial)
	}
}

// TestParseCertIDRejectsMalformed rejects inputs that are not exactly
// base64url(AKI).base64url(Serial).
func TestParseCertIDRejectsMalformed(t *testing.T) {
	cases := []string{
		"",                 // empty
		"noDot",            // missing separator
		".onlySerial",      // empty AKI
		"onlyAKI.",         // empty serial
		"a.b.c",            // too many segments
		"!!!.AIdlQyE",      // invalid base64url in AKI
		"aGVsbG8.$$$",      // invalid base64url in serial
		"aGVsbG8=.AIdlQyE", // padded (RawURLEncoding rejects padding)
	}
	for _, c := range cases {
		if _, err := parseCertID(c); err == nil {
			t.Errorf("parseCertID(%q) = nil error, want error", c)
		}
	}
}

func TestComputeRenewalWindow(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(90 * 24 * time.Hour) // 90-day cert
	now := notBefore.Add(10 * 24 * time.Hour)

	t.Run("normal derives final-third window", func(t *testing.T) {
		start, end := computeRenewalWindow(notBefore, notAfter, now, false, false, renewalWindowParams{})
		// Default renewBefore = lifetime/3 = 30d, width = 15d.
		wantStart := notAfter.Add(-30 * 24 * time.Hour)
		if !start.Equal(wantStart) {
			t.Errorf("start = %s, want %s", start, wantStart)
		}
		if !end.Equal(wantStart.Add(15 * 24 * time.Hour)) {
			t.Errorf("end = %s, want %s", end, wantStart.Add(15*24*time.Hour))
		}
		if !end.After(start) || end.After(notAfter) {
			t.Errorf("window [%s,%s) is not a valid sub-interval of validity", start, end)
		}
	})

	t.Run("explicit params respected", func(t *testing.T) {
		p := renewalWindowParams{renewBefore: 20 * 24 * time.Hour, windowWidth: 48 * time.Hour}
		start, end := computeRenewalWindow(notBefore, notAfter, now, false, false, p)
		if !start.Equal(notAfter.Add(-20 * 24 * time.Hour)) {
			t.Errorf("start = %s", start)
		}
		if end.Sub(start) != 48*time.Hour {
			t.Errorf("width = %s, want 48h", end.Sub(start))
		}
	})

	t.Run("revoked forces immediate renewal", func(t *testing.T) {
		start, end := computeRenewalWindow(notBefore, notAfter, now, true, false, renewalWindowParams{})
		if end.After(now) {
			t.Errorf("revoked window end %s must not be after now %s", end, now)
		}
		if !end.After(start) {
			t.Errorf("window must be non-empty: [%s,%s)", start, end)
		}
	})

	t.Run("rotating forces immediate renewal", func(t *testing.T) {
		_, end := computeRenewalWindow(notBefore, notAfter, now, false, true, renewalWindowParams{})
		if end.After(now) {
			t.Errorf("rotating window end %s must not be after now %s", end, now)
		}
	})

	t.Run("window stays within validity", func(t *testing.T) {
		// A renewBefore larger than the lifetime must clamp to notBefore.
		p := renewalWindowParams{renewBefore: 365 * 24 * time.Hour}
		start, end := computeRenewalWindow(notBefore, notAfter, now, false, false, p)
		if start.Before(notBefore) {
			t.Errorf("start %s before notBefore %s", start, notBefore)
		}
		if end.After(notAfter) {
			t.Errorf("end %s after notAfter %s", end, notAfter)
		}
	})
}
