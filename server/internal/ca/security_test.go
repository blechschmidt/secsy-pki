//go:build sqlite

package ca

import (
	"context"
	"math/big"
	"testing"
)

// TestRenewRejectsRevokedCertificate locks in the Task 12 hardening: a revoked
// certificate must never be renewable, otherwise revocation (e.g. after key
// compromise) could be silently undone by reissuing the same identity.
func TestRenewRejectsRevokedCertificate(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()
	root := newRoot(t, mgr, "revrenew")

	issued, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    root.ID,
		CSRPEM:  makeCSR(t, "revoke-me.example.com", []string{"revoke-me.example.com"}),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	// Renew works while the certificate is valid.
	if _, err := mgr.RenewCertificate(ctx, RenewSpec{CAID: root.ID, Serial: issued.Serial.String()}); err != nil {
		t.Fatalf("RenewCertificate (pre-revocation) should succeed: %v", err)
	}

	// Revoke it, then renewal must be refused.
	if _, err := mgr.RevokeCertificate(ctx, root.ID, issued.Serial.String(), "keyCompromise"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	if _, err := mgr.RenewCertificate(ctx, RenewSpec{CAID: root.ID, Serial: issued.Serial.String()}); err == nil {
		t.Fatal("RenewCertificate must reject a revoked certificate, but it succeeded")
	}
}

// TestLeafSerialsAreHighEntropy locks in the switch from predictable sequential
// serials to unpredictable random serials (RFC 5280 / CA-B Forum: >= 64 bits of
// entropy). Two consecutive issuances must not be adjacent integers and must be
// large.
func TestLeafSerialsAreHighEntropy(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()
	root := newRoot(t, mgr, "serial")

	a, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: root.ID, CSRPEM: makeCSR(t, "a.example.com", nil), Profile: "server"})
	if err != nil {
		t.Fatalf("IssueCertificate a: %v", err)
	}
	b, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: root.ID, CSRPEM: makeCSR(t, "b.example.com", nil), Profile: "server"})
	if err != nil {
		t.Fatalf("IssueCertificate b: %v", err)
	}

	if a.Serial.Cmp(b.Serial) == 0 {
		t.Fatal("two issuances produced identical serials")
	}
	// A predictable counter would yield serials differing by 1 and only a few
	// bits wide. Require real width on both.
	for _, s := range []struct {
		name  string
		bits  int
		value string
	}{
		{"a", a.Serial.BitLen(), a.Serial.String()},
		{"b", b.Serial.BitLen(), b.Serial.String()},
	} {
		if s.bits < 64 {
			t.Errorf("serial %s has only %d bits of width (%s); want >= 64 bits of entropy", s.name, s.bits, s.value)
		}
	}
	// Adjacent-integer serials are the fingerprint of a counter.
	diff := new(big.Int).Abs(new(big.Int).Sub(a.Serial, b.Serial))
	if diff.BitLen() < 8 {
		t.Errorf("consecutive serials differ by only %s; serials appear sequential, not random", diff)
	}
}
