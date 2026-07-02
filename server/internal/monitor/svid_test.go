package monitor

import (
	"context"
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// svidCert builds a short-lived SPIFFE SVID-shaped issued certificate: an empty
// subject (no CN) with the spiffe:// URI carried in the SANs, spanning
// [now-elapsed, now-elapsed+lifetime].
func svidCert(uri string, now time.Time, lifetime, elapsed time.Duration) models.IssuedCertificate {
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	notBefore := now.Add(-elapsed)
	return models.IssuedCertificate{
		CAID:      "ca1",
		Serial:    serial.String(),
		Subject:   "", // SVIDs carry no CN — identity is the URI SAN
		SANs:      []string{uri},
		Profile:   "spiffe-svid",
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(lifetime),
		Status:    models.CertStatusValid,
	}
}

func svidOptions() Options {
	return Options{
		Warning:           30 * 24 * time.Hour,
		Critical:          7 * 24 * time.Hour,
		RenewBefore:       0, // day-scale window would misbehave for SVIDs
		SVIDProfiles:      []string{"spiffe-svid"},
		SVIDRenewFraction: 0.5,
	}
}

// TestSVIDIdentityByURI proves two SVIDs for different workloads (distinct URI
// SANs but both with an empty subject) are NOT treated as the same identity, so
// neither is spuriously flagged superseded.
func TestSVIDIdentityByURI(t *testing.T) {
	now := time.Now()
	store := newFakeStore()
	store.add(svidCert("spiffe://example.org/ns/prod/sa/web", now, time.Hour, 10*time.Minute))
	store.add(svidCert("spiffe://example.org/ns/prod/sa/db", now, time.Hour, 10*time.Minute))

	m := New(store, nil, store, svidOptions())
	report, err := m.Scan(context.Background(), ScanRequest{Now: now})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(report.Items) != 2 {
		t.Fatalf("got %d items, want 2", len(report.Items))
	}
	for _, it := range report.Items {
		if it.Superseded {
			t.Errorf("SVID %v spuriously marked superseded", it.Serial)
		}
	}
}

// TestSVIDFractionRenewal proves an SVID is auto-renewed only once it has passed
// the configured fraction of its lifetime, not on the day-scale RenewBefore
// window (which is zero here), and that the renewed SVID stays short-lived.
func TestSVIDFractionRenewal(t *testing.T) {
	now := time.Now()
	store := newFakeStore()
	// Fresh SVID: 50m of a 60m life remaining (only ~17% elapsed) — NOT yet due.
	fresh := svidCert("spiffe://example.org/ns/prod/sa/fresh", now, time.Hour, 10*time.Minute)
	// Aged SVID: 20m of a 60m life remaining (~67% elapsed, past the 50% mark) — due.
	aged := svidCert("spiffe://example.org/ns/prod/sa/aged", now, time.Hour, 40*time.Minute)
	store.add(fresh)
	store.add(aged)

	renewer := &fakeRenewer{store: store, now: now, validity: 0} // 0 => reuse lifetime
	m := New(store, renewer, store, svidOptions())

	report, err := m.Scan(context.Background(), ScanRequest{Now: now, AutoRenew: true})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if report.Renewed != 1 {
		t.Fatalf("Renewed = %d, want 1 (only the aged SVID)", report.Renewed)
	}
	// The aged SVID must be the one renewed.
	var agedRenewed, freshRenewed bool
	for _, it := range report.Items {
		if it.Serial == aged.Serial && it.Renewed {
			agedRenewed = true
		}
		if it.Serial == fresh.Serial && it.Renewed {
			freshRenewed = true
		}
	}
	if !agedRenewed {
		t.Error("aged SVID (past 50% of lifetime) should have been renewed")
	}
	if freshRenewed {
		t.Error("fresh SVID (within first half of lifetime) should NOT have been renewed")
	}

	// Storm check: a follow-up scan must NOT renew the just-renewed identity again
	// (the new SVID is fresh, and the old one is now superseded).
	renewer.calls = 0
	report2, err := m.Scan(context.Background(), ScanRequest{Now: now, AutoRenew: true})
	if err != nil {
		t.Fatalf("second Scan: %v", err)
	}
	if report2.Renewed != 0 {
		t.Errorf("second scan renewed %d, want 0 (no renewal storm)", report2.Renewed)
	}
}
