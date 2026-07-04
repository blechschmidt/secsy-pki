package servingcert

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"testing"
	"time"
)

// TestHolderSwapAndStaple verifies the shared certificate holder: GetCertificate
// returns the current certificate, Set swaps it wholesale (hitless rotation), and
// SetStaple attaches an OCSP staple while preserving the chain and key — the two
// feeders (rotation and OCSP refresh) the holder is designed to serve.
func TestHolderSwapAndStaple(t *testing.T) {
	first := &tls.Certificate{Certificate: [][]byte{{0x01}}}
	h := NewHolder(first)

	got, err := h.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if got != first {
		t.Fatalf("GetCertificate returned a different certificate than the one held")
	}

	// SetStaple must attach the staple without dropping the certificate chain and
	// must not mutate the previous snapshot (a handshake may still read it).
	h.SetStaple([]byte("staple-1"))
	stapled := h.Current()
	if !bytes.Equal(stapled.OCSPStaple, []byte("staple-1")) {
		t.Fatalf("SetStaple did not set the staple, got %q", stapled.OCSPStaple)
	}
	if len(stapled.Certificate) != 1 || !bytes.Equal(stapled.Certificate[0], []byte{0x01}) {
		t.Fatalf("SetStaple dropped the certificate chain")
	}
	if len(first.OCSPStaple) != 0 {
		t.Fatalf("SetStaple mutated the previous certificate snapshot")
	}

	// Set replaces the whole certificate (rotation).
	second := &tls.Certificate{Certificate: [][]byte{{0x02}}}
	h.Set(second)
	if h.Current() != second {
		t.Fatalf("Set did not swap the certificate")
	}
}

// TestRenewBefore checks the renewal-threshold resolution: an explicit
// RenewBefore wins, and an unset one falls back to the fraction-based default of
// the certificate's lifetime — mirroring the monitor's fraction renewal.
func TestRenewBefore(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	lifetime := 90 * 24 * time.Hour
	leaf := &x509.Certificate{NotBefore: notBefore, NotAfter: notBefore.Add(lifetime)}

	// Explicit RenewBefore is honored verbatim.
	s := &SelfIssuer{cfg: Config{RenewBefore: 10 * 24 * time.Hour}}
	if got := s.renewBefore(leaf); got != 10*24*time.Hour {
		t.Errorf("renewBefore with explicit config = %s, want 240h", got)
	}

	// Unset RenewBefore falls back to a third of the lifetime.
	s = &SelfIssuer{cfg: Config{}}
	want := time.Duration(float64(lifetime) * defaultRenewFraction)
	if got := s.renewBefore(leaf); got != want {
		t.Errorf("renewBefore fraction default = %s, want %s", got, want)
	}
}

// TestTimeUntilRenew checks the wait computation: it is the gap to the renewal
// point and is clamped to zero once the certificate is already overdue.
func TestTimeUntilRenew(t *testing.T) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := notBefore.Add(30 * 24 * time.Hour)
	leaf := &x509.Certificate{NotBefore: notBefore, NotAfter: notAfter}

	renewBefore := 5 * 24 * time.Hour
	renewAt := notAfter.Add(-renewBefore) // 25 days after notBefore

	// 10 days in: 15 days until the renewal point.
	s := &SelfIssuer{
		cfg: Config{RenewBefore: renewBefore},
		now: func() time.Time { return notBefore.Add(10 * 24 * time.Hour) },
	}
	if got, want := s.timeUntilRenew(leaf), renewAt.Sub(notBefore.Add(10*24*time.Hour)); got != want {
		t.Errorf("timeUntilRenew mid-life = %s, want %s", got, want)
	}

	// Past the renewal point: clamp to zero (renew immediately).
	s.now = func() time.Time { return notAfter.Add(-time.Hour) }
	if got := s.timeUntilRenew(leaf); got != 0 {
		t.Errorf("timeUntilRenew when overdue = %s, want 0", got)
	}
}

// TestConfigDefaults checks the small resolution helpers used to fill in Config.
func TestConfigDefaults(t *testing.T) {
	c := Config{}
	if c.keyType() != "ecdsa-sha2-nistp256" {
		t.Errorf("default keyType = %q, want ecdsa-sha2-nistp256", c.keyType())
	}
	if c.requestedBy() != "system:serving-tls" {
		t.Errorf("default requestedBy = %q", c.requestedBy())
	}
	c = Config{KeyType: "rsa-2048", RequestedBy: "op"}
	if c.keyType() != "rsa-2048" || c.requestedBy() != "op" {
		t.Errorf("explicit Config not honored: %q / %q", c.keyType(), c.requestedBy())
	}
}
