package webhook

import (
	"strings"
	"testing"
	"time"
)

// TestSignVerifyRoundTrip proves a signed body verifies under the same secret and
// fails under a wrong secret or a tampered body — the core authenticity property
// a receiver relies on.
func TestSignVerifyRoundTrip(t *testing.T) {
	secret := "s3cr3t"
	body := []byte(`{"event":"cert.issue","serial":"01"}`)
	ts := time.Unix(1_700_000_000, 0)

	header := Sign(secret, ts, body)
	if !strings.HasPrefix(header, "t=1700000000,v1=") {
		t.Fatalf("unexpected header format: %q", header)
	}

	// Correct secret + body + within tolerance of the signed time -> ok.
	if err := Verify(secret, header, body, time.Minute, ts.Add(10*time.Second)); err != nil {
		t.Errorf("Verify with correct secret failed: %v", err)
	}
	// Wrong secret -> mismatch.
	if err := Verify("wrong", header, body, 0, ts); err == nil {
		t.Errorf("Verify accepted a wrong secret")
	}
	// Tampered body -> mismatch.
	if err := Verify(secret, header, []byte(`{"event":"cert.revoke"}`), 0, ts); err == nil {
		t.Errorf("Verify accepted a tampered body")
	}
}

// TestVerifyReplayWindow proves the embedded timestamp blunts replay: a delivery
// captured and re-sent outside the freshness window is rejected, while tolerance
// <= 0 disables the check (HMAC only).
func TestVerifyReplayWindow(t *testing.T) {
	secret := "k"
	body := []byte("payload")
	ts := time.Unix(1_700_000_000, 0)
	header := Sign(secret, ts, body)

	// Replayed 10 minutes later, tolerance 5 minutes -> rejected.
	if err := Verify(secret, header, body, 5*time.Minute, ts.Add(10*time.Minute)); err == nil {
		t.Errorf("Verify accepted a replayed delivery outside the tolerance window")
	}
	// Same replay, tolerance disabled -> accepted (HMAC still valid).
	if err := Verify(secret, header, body, 0, ts.Add(10*time.Minute)); err != nil {
		t.Errorf("Verify with tolerance disabled rejected a valid HMAC: %v", err)
	}
}

// TestParseSignatureHeaderErrors covers malformed headers.
func TestParseSignatureHeaderErrors(t *testing.T) {
	for _, h := range []string{"", "t=abc,v1=deadbeef", "v1=deadbeef", "t=1700000000", "garbage"} {
		if err := Verify("k", h, []byte("b"), 0, time.Unix(1_700_000_000, 0)); err == nil {
			t.Errorf("Verify accepted a malformed header %q", h)
		}
	}
}

// TestGenerateSecretUnique proves generated secrets are non-empty and distinct.
func TestGenerateSecretUnique(t *testing.T) {
	a, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	b, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if a == "" || len(a) != 64 {
		t.Errorf("secret has unexpected length: %q", a)
	}
	if a == b {
		t.Errorf("two generated secrets collided")
	}
}
