//go:build sqlite

package sshca

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// certLifetime is the signed certificate's advertised lifetime, measured from
// the backdated ValidAfter the signer stamps.
func certLifetime(cert *ssh.Certificate) time.Duration {
	return time.Duration(cert.ValidBefore-cert.ValidAfter) * time.Second
}

// TestCAMaxValidityClampsSigning is the core of Task 217: a CA-level ceiling
// bounds every certificate the CA signs — the explicit request, the profile
// default, and a profile whose own maximum is more generous.
func TestCAMaxValidityClampsSigning(t *testing.T) {
	authority, _ := newTestAuthority(t)
	ctx := context.Background()

	// 8h ceiling, set at CA creation. user-default defaults to 12h and permits
	// up to 30d, so the ceiling is the binding constraint in every case below.
	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-cap-ca", MaxValidity: 8 * time.Hour})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	if ca.MaxSSHValiditySecs != int64((8 * time.Hour).Seconds()) {
		t.Fatalf("stored ceiling = %ds, want %ds", ca.MaxSSHValiditySecs, int64((8 * time.Hour).Seconds()))
	}

	sign := func(t *testing.T, requested time.Duration) *SignResult {
		t.Helper()
		res, err := authority.Sign(ctx, SignRequest{
			CAID: ca.ID, CertType: CertTypeUser, PublicKey: subjectKey(t),
			Principals: []string{"alice"}, KeyID: "alice", Validity: requested,
		})
		if err != nil {
			t.Fatalf("Sign(%s): %v", requested, err)
		}
		return res
	}

	// A request well past the ceiling is clamped to it, and says so.
	res := sign(t, 7*24*time.Hour)
	if got := certLifetime(res.Certificate); got != 8*time.Hour+clockSkewBackdate {
		t.Errorf("7d request: lifetime = %s, want %s", got, 8*time.Hour+clockSkewBackdate)
	}
	if !res.ClampedByCA {
		t.Error("7d request: ClampedByCA = false, want true")
	}
	if res.CAMaxValidity != 8*time.Hour {
		t.Errorf("CAMaxValidity = %s, want 8h", res.CAMaxValidity)
	}
	// The inventory record must agree with the certificate, or the console and
	// the expiry monitor would disagree with what sshd enforces.
	if got := res.Record.ValidBefore.Sub(res.Record.ValidAfter); got != 8*time.Hour+clockSkewBackdate {
		t.Errorf("record window = %s, want %s", got, 8*time.Hour+clockSkewBackdate)
	}

	// The PROFILE DEFAULT is clamped too: user-default would grant 12h, so a
	// request naming no validity at all must still come back at 8h. This is the
	// case a profile-only cap cannot express.
	res = sign(t, 0)
	if got := certLifetime(res.Certificate); got != 8*time.Hour+clockSkewBackdate {
		t.Errorf("profile default: lifetime = %s, want %s", got, 8*time.Hour+clockSkewBackdate)
	}
	if !res.ClampedByCA {
		t.Error("profile default: ClampedByCA = false, want true")
	}

	// A request inside the ceiling is untouched and NOT reported as clamped.
	res = sign(t, 2*time.Hour)
	if got := certLifetime(res.Certificate); got != 2*time.Hour+clockSkewBackdate {
		t.Errorf("2h request: lifetime = %s, want %s", got, 2*time.Hour+clockSkewBackdate)
	}
	if res.ClampedByCA {
		t.Error("2h request: ClampedByCA = true, want false")
	}

	// The clamped certificate is a real certificate: it verifies the way a
	// relying host would, inside the window and not after it.
	res = sign(t, 30*24*time.Hour)
	if _, err := authority.VerifyCertificate(ctx, ca.ID, res.AuthorizedKey, "alice", time.Now().Add(time.Hour)); err != nil {
		t.Errorf("clamped certificate rejected inside the window: %v", err)
	}
	if _, err := authority.VerifyCertificate(ctx, ca.ID, res.AuthorizedKey, "alice", time.Now().Add(9*time.Hour)); err == nil {
		t.Error("clamped certificate still verified past the CA ceiling")
	}
}

// TestCAMaxValidityBindsEveryProfile proves the ceiling is a property of the
// AUTHORITY, not of a profile: a custom profile asking for far more is still
// bound by it, and a host profile is bound just like a user profile.
func TestCAMaxValidityBindsEveryProfile(t *testing.T) {
	authority, _ := newTestAuthority(t)
	ctx := context.Background()
	t.Cleanup(func() { SetCustomProfiles(nil) })

	if err := SetCustomProfiles([]Profile{
		{Name: "long-user", CertType: CertTypeUser, DefaultValidity: 90 * 24 * time.Hour, MaxValidity: 365 * 24 * time.Hour},
		{Name: "long-host", CertType: CertTypeHost, DefaultValidity: 90 * 24 * time.Hour, MaxValidity: 365 * 24 * time.Hour},
	}); err != nil {
		t.Fatalf("SetCustomProfiles: %v", err)
	}

	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-cap-profiles-ca", MaxValidity: 36 * time.Hour})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	for _, tc := range []struct{ certType, profile, principal string }{
		{CertTypeUser, "long-user", "alice"},
		{CertTypeHost, "long-host", "web1.example.com"},
	} {
		res, err := authority.Sign(ctx, SignRequest{
			CAID: ca.ID, CertType: tc.certType, Profile: tc.profile,
			PublicKey: subjectKey(t), Principals: []string{tc.principal}, KeyID: "k",
			Validity: 365 * 24 * time.Hour,
		})
		if err != nil {
			t.Fatalf("Sign %s: %v", tc.certType, err)
		}
		if got := certLifetime(res.Certificate); got != 36*time.Hour+clockSkewBackdate {
			t.Errorf("%s/%s: lifetime = %s, want %s", tc.certType, tc.profile, got, 36*time.Hour+clockSkewBackdate)
		}
		if !res.ClampedByCA {
			t.Errorf("%s/%s: ClampedByCA = false, want true", tc.certType, tc.profile)
		}
	}
}

// TestSetMaxValidityLifecycle covers changing the ceiling after the fact:
// tightening binds the next signature immediately, clearing it restores the
// profile bounds, and already-signed certificates are untouched.
func TestSetMaxValidityLifecycle(t *testing.T) {
	authority, db := newTestAuthority(t)
	ctx := context.Background()

	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-cap-lifecycle-ca"})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	if ca.MaxSSHValiditySecs != 0 {
		t.Fatalf("a new CA should be uncapped, got %ds", ca.MaxSSHValiditySecs)
	}

	sign := func(t *testing.T, requested time.Duration) *SignResult {
		t.Helper()
		res, err := authority.Sign(ctx, SignRequest{
			CAID: ca.ID, CertType: CertTypeUser, PublicKey: subjectKey(t),
			Principals: []string{"alice"}, KeyID: "alice", Validity: requested,
		})
		if err != nil {
			t.Fatalf("Sign(%s): %v", requested, err)
		}
		return res
	}

	// Uncapped: the profile maximum (30d) applies, so a 7d request is honored.
	before := sign(t, 7*24*time.Hour)
	if got := certLifetime(before.Certificate); got != 7*24*time.Hour+clockSkewBackdate {
		t.Fatalf("uncapped 7d request: lifetime = %s, want %s", got, 7*24*time.Hour+clockSkewBackdate)
	}
	if before.ClampedByCA {
		t.Error("uncapped CA reported a clamp")
	}

	// Tighten to 1h. The change must be durable, and visible to the next
	// signature without reconstructing the Authority.
	updated, err := authority.SetMaxValidity(ctx, ca.ID, time.Hour)
	if err != nil {
		t.Fatalf("SetMaxValidity: %v", err)
	}
	if updated.MaxSSHValiditySecs != 3600 {
		t.Errorf("returned ceiling = %ds, want 3600", updated.MaxSSHValiditySecs)
	}
	reloaded, err := db.GetCA(ca.ID)
	if err != nil {
		t.Fatalf("GetCA: %v", err)
	}
	if reloaded.MaxSSHValiditySecs != 3600 {
		t.Errorf("persisted ceiling = %ds, want 3600", reloaded.MaxSSHValiditySecs)
	}
	after := sign(t, 7*24*time.Hour)
	if got := certLifetime(after.Certificate); got != time.Hour+clockSkewBackdate {
		t.Errorf("after tightening: lifetime = %s, want %s", got, time.Hour+clockSkewBackdate)
	}

	// The certificate signed before the change keeps the lifetime it was signed
	// with — a ceiling is not retroactive, and claiming otherwise would hide
	// long-lived credentials from an operator who thinks they just revoked them.
	if got := certLifetime(before.Certificate); got != 7*24*time.Hour+clockSkewBackdate {
		t.Errorf("pre-change certificate changed lifetime: %s", got)
	}

	// Clearing restores the profile bounds.
	if _, err := authority.SetMaxValidity(ctx, ca.ID, 0); err != nil {
		t.Fatalf("SetMaxValidity(0): %v", err)
	}
	cleared := sign(t, 7*24*time.Hour)
	if got := certLifetime(cleared.Certificate); got != 7*24*time.Hour+clockSkewBackdate {
		t.Errorf("after clearing: lifetime = %s, want %s", got, 7*24*time.Hour+clockSkewBackdate)
	}
	if cleared.ClampedByCA {
		t.Error("cleared ceiling still reported a clamp")
	}
}

// TestSetMaxValidityRejectsBadInput pins the input validation: a negative
// ceiling, a sub-second ceiling that would silently round to "uncapped", and an
// unknown CA are all errors rather than quiet no-ops.
func TestSetMaxValidityRejectsBadInput(t *testing.T) {
	authority, _ := newTestAuthority(t)
	ctx := context.Background()

	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-cap-validate-ca"})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	if _, err := authority.SetMaxValidity(ctx, ca.ID, -time.Hour); err == nil {
		t.Error("negative ceiling accepted")
	}
	// 500ms truncates to 0 seconds — "uncapped" — which would turn a tightening
	// into a loosening. It must be refused, and must not have changed anything.
	if _, err := authority.SetMaxValidity(ctx, ca.ID, 500*time.Millisecond); err == nil {
		t.Error("sub-second ceiling accepted")
	}
	if _, err := authority.SetMaxValidity(ctx, "no-such-ca", time.Hour); err == nil {
		t.Error("unknown CA accepted")
	} else if !strings.Contains(err.Error(), "not found") {
		t.Errorf("unknown CA error = %v, want a not-found error", err)
	}

	// InitCA validates the same way, so a bad spec never creates a key.
	if _, err := authority.InitCA(ctx, CASpec{Label: "ssh-cap-negative-ca", MaxValidity: -time.Second}); err == nil {
		t.Error("InitCA accepted a negative ceiling")
	}
}

// TestMaxValidityClampHelper pins the model helper every signing path shares,
// including the boundary where the request exactly equals the ceiling.
func TestMaxValidityClampHelper(t *testing.T) {
	authority, _ := newTestAuthority(t)
	ctx := context.Background()

	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-cap-helper-ca", MaxValidity: time.Hour})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	for _, tc := range []struct {
		name    string
		in      time.Duration
		want    time.Duration
		clamped bool
	}{
		{"below", 30 * time.Minute, 30 * time.Minute, false},
		{"equal", time.Hour, time.Hour, false},
		{"above", 90 * time.Minute, time.Hour, true},
	} {
		got, clamped := ca.ClampSSHValidity(tc.in)
		if got != tc.want || clamped != tc.clamped {
			t.Errorf("%s: ClampSSHValidity(%s) = (%s, %t), want (%s, %t)",
				tc.name, tc.in, got, clamped, tc.want, tc.clamped)
		}
	}

	// An uncapped CA passes everything through.
	ca.MaxSSHValiditySecs = 0
	if got, clamped := ca.ClampSSHValidity(365 * 24 * time.Hour); got != 365*24*time.Hour || clamped {
		t.Errorf("uncapped: ClampSSHValidity = (%s, %t), want (8760h0m0s, false)", got, clamped)
	}
}
