//go:build sqlite

package sshca

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

func newTestAuthority(t *testing.T) (*Authority, *database.DB) {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	t.Cleanup(func() { prov.Close() })
	return NewAuthority(db, prov), db
}

// subjectKey generates a fresh Ed25519 key pair to be certified, returning its
// authorized_keys line.
func subjectKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating subject key: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("converting subject key: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(sshPub))
}

// TestInitCASignAndVerify is the software-provider happy path: initialize a CA,
// sign a user and a host certificate under the built-in profiles, and verify
// both the way a relying host would.
func TestInitCASignAndVerify(t *testing.T) {
	authority, _ := newTestAuthority(t)
	ctx := context.Background()

	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-test-ca"})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	if !strings.HasPrefix(ca.PublicKey, "ssh-ed25519 ") {
		t.Fatalf("CA public key = %q, want an ssh-ed25519 authorized_keys line", ca.PublicKey)
	}

	// Duplicate labels must be refused (ambiguous provider lookups otherwise).
	if _, err := authority.InitCA(ctx, CASpec{Label: "ssh-test-ca"}); err == nil {
		t.Fatal("duplicate CA label accepted")
	}

	userResult, err := authority.Sign(ctx, SignRequest{
		CAID:        ca.ID,
		CertType:    CertTypeUser,
		PublicKey:   subjectKey(t),
		Principals:  []string{"alice", "admin-alice"},
		RequestedBy: "alice@corp",
	})
	if err != nil {
		t.Fatalf("Sign user: %v", err)
	}
	cert := userResult.Certificate
	// Serial 1 is reserved for the CA's own certificate by the store's counter
	// seeding, so store-allocated leaf serials start at 2.
	if cert.Serial != 2 {
		t.Errorf("first serial = %d, want 2 (store-allocated)", cert.Serial)
	}
	if cert.CertType != ssh.UserCert {
		t.Errorf("cert type = %d, want user", cert.CertType)
	}
	if cert.KeyId != "alice@corp" {
		t.Errorf("key ID = %q, want requester fallback", cert.KeyId)
	}
	if len(cert.Permissions.Extensions) != 5 || cert.Permissions.Extensions["permit-pty"] != "" {
		t.Errorf("extensions = %v, want the standard permit-* set", cert.Permissions.Extensions)
	}
	if _, err := authority.VerifyCertificate(ctx, ca.ID, userResult.AuthorizedKey, "alice", time.Now()); err != nil {
		t.Errorf("user certificate does not verify: %v", err)
	}
	// The wrong principal must not verify.
	if _, err := authority.VerifyCertificate(ctx, ca.ID, userResult.AuthorizedKey, "mallory", time.Now()); err == nil {
		t.Error("certificate verified for a principal it does not name")
	}

	hostResult, err := authority.Sign(ctx, SignRequest{
		CAID:       ca.ID,
		CertType:   CertTypeHost,
		PublicKey:  subjectKey(t),
		Principals: []string{"web1.example.com"},
		KeyID:      "web1.example.com",
	})
	if err != nil {
		t.Fatalf("Sign host: %v", err)
	}
	if hostResult.Certificate.Serial != cert.Serial+1 {
		t.Errorf("second serial = %d, want %d (monotonic)", hostResult.Certificate.Serial, cert.Serial+1)
	}
	if hostResult.Certificate.CertType != ssh.HostCert {
		t.Errorf("cert type = %d, want host", hostResult.Certificate.CertType)
	}
	if len(hostResult.Certificate.Permissions.Extensions) != 0 {
		t.Errorf("host cert carries extensions: %v", hostResult.Certificate.Permissions.Extensions)
	}
	if _, err := authority.VerifyCertificate(ctx, ca.ID, hostResult.AuthorizedKey, "web1.example.com", time.Now()); err != nil {
		t.Errorf("host certificate does not verify: %v", err)
	}

	// A certificate signed by a DIFFERENT CA must be rejected even if valid.
	otherCA, err := authority.InitCA(ctx, CASpec{Label: "ssh-other-ca"})
	if err != nil {
		t.Fatalf("InitCA other: %v", err)
	}
	if _, err := authority.VerifyCertificate(ctx, otherCA.ID, userResult.AuthorizedKey, "alice", time.Now()); err == nil {
		t.Error("certificate verified under a CA that did not sign it")
	}

	// The inventory reflects both certificates.
	certs, err := authority.db.ListSSHCertificates(ca.ID)
	if err != nil {
		t.Fatalf("ListSSHCertificates: %v", err)
	}
	if len(certs) != 2 {
		t.Errorf("inventory has %d certificates, want 2", len(certs))
	}
}

// TestProfileEnforcement proves the per-profile policy gates: principal
// patterns and counts, validity clamping, extension and critical-option
// allowlists, and cert-type matching.
func TestProfileEnforcement(t *testing.T) {
	authority, _ := newTestAuthority(t)
	ctx := context.Background()
	t.Cleanup(func() { SetCustomProfiles(nil) })

	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-policy-ca"})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	err = SetCustomProfiles([]Profile{{
		Name:              "ci-deploy",
		CertType:          CertTypeUser,
		DefaultValidity:   time.Hour,
		MaxValidity:       24 * time.Hour,
		AllowedPrincipals: []string{"deploy-*"},
		MaxPrincipals:     2,
		DefaultExtensions: map[string]string{"permit-pty": ""},
		AllowedCriticalOptions: []string{
			"source-address",
		},
	}})
	if err != nil {
		t.Fatalf("SetCustomProfiles: %v", err)
	}

	sign := func(req SignRequest) (*SignResult, error) {
		req.CAID = ca.ID
		req.CertType = CertTypeUser
		req.Profile = "ci-deploy"
		req.KeyID = "ci"
		if req.PublicKey == "" {
			req.PublicKey = subjectKey(t)
		}
		return authority.Sign(ctx, req)
	}

	// No principals: refused (a principal-less cert is valid for every user).
	if _, err := sign(SignRequest{}); err == nil {
		t.Error("empty principals accepted")
	}
	// Principal outside the allowed pattern: refused.
	if _, err := sign(SignRequest{Principals: []string{"admin"}}); err == nil {
		t.Error("disallowed principal accepted")
	}
	// Too many principals: refused.
	if _, err := sign(SignRequest{Principals: []string{"deploy-a", "deploy-b", "deploy-c"}}); err == nil {
		t.Error("principal count above max accepted")
	}
	// Disallowed critical option: refused.
	if _, err := sign(SignRequest{
		Principals:      []string{"deploy-web"},
		CriticalOptions: map[string]string{"force-command": "/bin/true"},
	}); err == nil {
		t.Error("disallowed critical option accepted")
	}
	// Extension outside defaults+allowlist: refused.
	if _, err := sign(SignRequest{
		Principals: []string{"deploy-web"},
		Extensions: map[string]string{"permit-agent-forwarding": ""},
	}); err == nil {
		t.Error("disallowed extension accepted")
	}

	// Compliant request: allowed principals, permitted critical option, and a
	// validity beyond the maximum that must be clamped to 24h.
	result, err := sign(SignRequest{
		Principals:      []string{"deploy-web", "deploy-db"},
		Validity:        1000 * time.Hour,
		CriticalOptions: map[string]string{"source-address": "10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("compliant request refused: %v", err)
	}
	lifetime := result.Record.ValidBefore.Sub(result.Record.ValidAfter)
	if want := 24*time.Hour + clockSkewBackdate; lifetime != want {
		t.Errorf("lifetime = %v, want clamped %v", lifetime, want)
	}
	if result.Certificate.Permissions.CriticalOptions["source-address"] != "10.0.0.0/8" {
		t.Errorf("critical options = %v", result.Certificate.Permissions.CriticalOptions)
	}
	if result.Record.Profile != "ci-deploy" {
		t.Errorf("recorded profile = %q", result.Record.Profile)
	}

	// Cert-type / profile mismatch: a user profile cannot sign a host cert.
	if _, err := authority.Sign(ctx, SignRequest{
		CAID: ca.ID, CertType: CertTypeHost, Profile: "ci-deploy",
		PublicKey: subjectKey(t), Principals: []string{"h1"}, KeyID: "h1",
	}); err == nil {
		t.Error("host request under a user profile accepted")
	}
	// Host certificates cannot carry extensions/critical options at all.
	if _, err := authority.Sign(ctx, SignRequest{
		CAID: ca.ID, CertType: CertTypeHost,
		PublicKey: subjectKey(t), Principals: []string{"h1"}, KeyID: "h1",
		Extensions: map[string]string{"permit-pty": ""},
	}); err == nil {
		t.Error("host request with extensions accepted")
	}
	// A certificate is not signable material.
	if _, err := authority.Sign(ctx, SignRequest{
		CAID: ca.ID, CertType: CertTypeUser,
		PublicKey: string(result.AuthorizedKey), Principals: []string{"deploy-x"}, KeyID: "x",
	}); err == nil {
		t.Error("signing a certificate (not a plain key) accepted")
	}
}

// TestRevocationAndKRL proves the revocation flow end to end in software: a
// revoked serial and a revoked key ID stop verifying, the generated KRL
// contains exactly the revoked material, and re-revocation is idempotent.
func TestRevocationAndKRL(t *testing.T) {
	authority, db := newTestAuthority(t)
	ctx := context.Background()

	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-krl-ca"})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	signFor := func(principal, keyID string) *SignResult {
		t.Helper()
		r, err := authority.Sign(ctx, SignRequest{
			CAID: ca.ID, CertType: CertTypeUser, PublicKey: subjectKey(t),
			Principals: []string{principal}, KeyID: keyID,
		})
		if err != nil {
			t.Fatalf("Sign(%s): %v", principal, err)
		}
		return r
	}
	alice := signFor("alice", "alice@corp")
	bob := signFor("bob", "bob@corp")
	carol := signFor("carol", "carol@corp")

	// Revoke alice's certificate by serial.
	rev, newly, err := authority.Revoke(ctx, RevokeRequest{
		CAID: ca.ID, Serial: alice.Record.Serial, Reason: "laptop stolen", RevokedBy: "secops",
	})
	if err != nil {
		t.Fatalf("Revoke by serial: %v", err)
	}
	if !newly {
		t.Error("first revocation reported as already revoked")
	}
	if rev.Serial != alice.Record.Serial {
		t.Errorf("revocation serial = %q, want %q", rev.Serial, alice.Record.Serial)
	}
	// Idempotent: revoking again is not "newly revoked".
	if _, newly, err = authority.Revoke(ctx, RevokeRequest{CAID: ca.ID, Serial: alice.Record.Serial}); err != nil {
		t.Fatalf("re-revoke: %v", err)
	} else if newly {
		t.Error("second revocation reported as newly revoked")
	}

	// Revoke every certificate bearing carol's key ID.
	if _, _, err := authority.Revoke(ctx, RevokeRequest{CAID: ca.ID, KeyID: "carol@corp"}); err != nil {
		t.Fatalf("Revoke by key ID: %v", err)
	}
	// Exactly one of serial/key_id must be set.
	if _, _, err := authority.Revoke(ctx, RevokeRequest{CAID: ca.ID}); err == nil {
		t.Error("revocation without a target accepted")
	}
	if _, _, err := authority.Revoke(ctx, RevokeRequest{CAID: ca.ID, Serial: "1", KeyID: "x"}); err == nil {
		t.Error("revocation with two targets accepted")
	}

	// Verification: alice (serial) and carol (key ID) fail, bob still passes.
	if _, err := authority.VerifyCertificate(ctx, ca.ID, alice.AuthorizedKey, "alice", time.Now()); err == nil {
		t.Error("revoked-by-serial certificate verified")
	}
	if _, err := authority.VerifyCertificate(ctx, ca.ID, carol.AuthorizedKey, "carol", time.Now()); err == nil {
		t.Error("revoked-by-key-ID certificate verified")
	}
	if _, err := authority.VerifyCertificate(ctx, ca.ID, bob.AuthorizedKey, "bob", time.Now()); err != nil {
		t.Errorf("unrevoked certificate rejected: %v", err)
	}

	// The inventory reflects the revocations.
	stored, err := db.GetSSHCertificate(ca.ID, alice.Record.Serial)
	if err != nil || stored == nil {
		t.Fatalf("GetSSHCertificate: %v", err)
	}
	if stored.Status != models.CertStatusRevoked {
		t.Errorf("alice status = %q, want revoked", stored.Status)
	}

	// The KRL carries exactly the revoked serial and key ID, versioned by the
	// number of revocation records.
	krl, err := authority.BuildKRL(ctx, ca.ID, "test")
	if err != nil {
		t.Fatalf("BuildKRL: %v", err)
	}
	parsed, err := ParseKRL(krl)
	if err != nil {
		t.Fatalf("ParseKRL: %v", err)
	}
	if parsed.Version != 2 {
		t.Errorf("KRL version = %d, want 2 (one serial + one key-ID revocation)", parsed.Version)
	}
	caKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey))
	if err != nil {
		t.Fatalf("parsing CA key: %v", err)
	}
	if !parsed.IsSerialRevoked(caKey, alice.Certificate.Serial) {
		t.Error("KRL does not revoke alice's serial")
	}
	if parsed.IsSerialRevoked(caKey, bob.Certificate.Serial) {
		t.Error("KRL revokes bob's serial")
	}
	if !parsed.IsKeyIDRevoked(caKey, "carol@corp") {
		t.Error("KRL does not revoke carol's key ID")
	}
}

// TestValidityWindowEnforced proves expired and not-yet-valid certificates are
// rejected at their evaluation time.
func TestValidityWindowEnforced(t *testing.T) {
	authority, _ := newTestAuthority(t)
	ctx := context.Background()

	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-expiry-ca"})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	result, err := authority.Sign(ctx, SignRequest{
		CAID: ca.ID, CertType: CertTypeUser, PublicKey: subjectKey(t),
		Principals: []string{"alice"}, KeyID: "alice", Validity: time.Hour,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if _, err := authority.VerifyCertificate(ctx, ca.ID, result.AuthorizedKey, "alice", time.Now()); err != nil {
		t.Errorf("fresh certificate rejected: %v", err)
	}
	if _, err := authority.VerifyCertificate(ctx, ca.ID, result.AuthorizedKey, "alice", time.Now().Add(2*time.Hour)); err == nil {
		t.Error("expired certificate verified")
	}
	if _, err := authority.VerifyCertificate(ctx, ca.ID, result.AuthorizedKey, "alice", time.Now().Add(-time.Hour)); err == nil {
		t.Error("not-yet-valid certificate verified")
	}
}

// TestSupersededCARefusesToSign proves a rotated-out CA no longer signs.
func TestSupersededCARefusesToSign(t *testing.T) {
	authority, db := newTestAuthority(t)
	ctx := context.Background()

	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-rotated-ca"})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	if err := db.SetCAStatus(ca.ID, models.CAStatusSuperseded); err != nil {
		t.Fatalf("SetCAStatus: %v", err)
	}
	if _, err := authority.Sign(ctx, SignRequest{
		CAID: ca.ID, CertType: CertTypeUser, PublicKey: subjectKey(t),
		Principals: []string{"alice"}, KeyID: "alice",
	}); err == nil {
		t.Error("superseded CA signed a certificate")
	}
}
