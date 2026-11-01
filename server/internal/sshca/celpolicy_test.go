//go:build sqlite

package sshca

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// recordingGate captures the facts an SSH certificate was checked against.
type recordingGate struct {
	seen []celpolicy.SigningRequest
	deny string
	errs error
}

func (g *recordingGate) CheckSigning(_ context.Context, req celpolicy.SigningRequest) error {
	g.seen = append(g.seen, req)
	if g.errs != nil {
		return g.errs
	}
	if g.deny != "" {
		return &celpolicy.DenyError{
			Subject: celpolicy.DenySubject(req.Operation),
			Decision: celpolicy.Decision{Violations: []celpolicy.Violation{
				{Rule: "test", Message: g.deny},
			}},
		}
	}
	return nil
}

func TestSSHSigningIsGated(t *testing.T) {
	authority, _ := newTestAuthority(t)
	gate := &recordingGate{deny: "an SSH certificate may not name root"}
	authority.SetPolicyGate(gate)
	ctx := context.Background()

	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-policy-ca"})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	_, err = authority.Sign(ctx, SignRequest{
		CAID: ca.ID, PublicKey: subjectKey(t), Principals: []string{"root"}, RequestedBy: "ops@example.com",
	})
	if err == nil {
		t.Fatal("a refused certificate must not be signed")
	}
	if !errors.Is(err, celpolicy.ErrDenied) {
		t.Errorf("the refusal must be a policy denial: %v", err)
	}
	if !strings.Contains(err.Error(), "may not name root") {
		t.Errorf("the operator's wording must reach the requester: %v", err)
	}
	// Nothing was recorded in the inventory: the certificate does not exist.
	if len(gate.seen) != 1 {
		t.Fatalf("the gate ran %d times, want 1", len(gate.seen))
	}
}

func TestSSHSigningFactsDescribeTheCertificate(t *testing.T) {
	authority, _ := newTestAuthority(t)
	gate := &recordingGate{}
	authority.SetPolicyGate(gate)
	ctx := context.Background()

	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-facts-ca", MaxValidity: 8 * time.Hour})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	res, err := authority.Sign(ctx, SignRequest{
		CAID:        ca.ID,
		PublicKey:   subjectKey(t),
		KeyID:       "ops@example.com",
		Principals:  []string{"deploy", "ops"},
		Validity:    24 * time.Hour, // clamped to the CA's 8h ceiling
		RequestedBy: "ops@example.com",
		Purpose:     "CHG-10482",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(gate.seen) != 1 {
		t.Fatalf("the gate ran %d times, want 1", len(gate.seen))
	}
	f := gate.seen[0]

	if f.Operation != celpolicy.OpSignSSHCert {
		t.Errorf("operation = %q", f.Operation)
	}
	if f.RequestedBy != "ops@example.com" || f.Purpose != "CHG-10482" {
		t.Errorf("attribution = %q / %q", f.RequestedBy, f.Purpose)
	}
	if f.Key.Name != "ssh-facts-ca" || f.Key.Algorithm != "Ed25519" || f.Key.Provider == "" {
		t.Errorf("key facts = %+v", f.Key)
	}
	if !f.SSH.Present || f.SSH.CertType != CertTypeUser || f.SSH.KeyID != "ops@example.com" {
		t.Errorf("ssh facts = %+v", f.SSH)
	}
	if len(f.SSH.Principals) != 2 || f.SSH.PrincipalCount != 2 {
		t.Errorf("principals = %v", f.SSH.Principals)
	}
	if f.SSH.Profile == "" || f.SSH.Serial == "" {
		t.Errorf("profile/serial = %q / %q", f.SSH.Profile, f.SSH.Serial)
	}
	if f.SSH.Serial != res.Record.Serial {
		t.Errorf("the serial a rule saw (%s) is not the certificate's (%s)", f.SSH.Serial, res.Record.Serial)
	}
	// The CA ceiling clamped the 24h request to 8h, and the facts must show the
	// clamped window — a rule is true of the certificate, not of the request.
	if f.SSH.Validity > 8*time.Hour+10*time.Minute {
		t.Errorf("validity = %s, want the CA-clamped 8h (plus backdating)", f.SSH.Validity)
	}
	if f.SSH.ValidBefore.Sub(f.SSH.ValidAfter) != f.SSH.Validity {
		t.Error("validity must be valid_before - valid_after exactly")
	}
	// The resolved extension names are what a rule reads, sorted.
	if len(f.SSH.Extensions) == 0 || f.SSH.Extensions[0] != "permit-X11-forwarding" {
		t.Errorf("extensions = %v", f.SSH.Extensions)
	}
	if f.SSH.PublicKey.Type != "ssh-ed25519" || f.SSH.PublicKey.Bits != 256 {
		t.Errorf("public key facts = %+v", f.SSH.PublicKey)
	}
	if f.SSH.PublicKey.HardwareBacked {
		t.Error("a software Ed25519 key is not hardware-backed")
	}
	if f.SSH.PublicKey.Fingerprint != res.Record.PublicKeyFingerprint {
		t.Errorf("fingerprint = %q, want %q", f.SSH.PublicKey.Fingerprint, res.Record.PublicKeyFingerprint)
	}
	if f.SSH.CA.ID != ca.ID || f.SSH.CA.Label != ca.Label {
		t.Errorf("ca facts = %+v", f.SSH.CA)
	}
	// The payload is the certificate itself: present, never a caller-supplied
	// digest, and with no byte length to report (see policyFacts).
	if !f.Payload.Present || f.Payload.Prehashed || f.Payload.DigestAlgorithm != "" {
		t.Errorf("payload facts = %+v (Ed25519 signs with no external hash)", f.Payload)
	}
}

func TestSSHHostCertificateFacts(t *testing.T) {
	authority, _ := newTestAuthority(t)
	gate := &recordingGate{}
	authority.SetPolicyGate(gate)
	ctx := context.Background()

	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-host-ca"})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	if _, err := authority.Sign(ctx, SignRequest{
		CAID: ca.ID, CertType: CertTypeHost, PublicKey: subjectKey(t),
		KeyID: "host-1", Principals: []string{"host1.example.com"},
	}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	f := gate.seen[0].SSH
	if f.CertType != CertTypeHost {
		t.Errorf("cert type = %q", f.CertType)
	}
	// A host certificate carries neither extensions nor critical options, and
	// the facts must say so as empty lists rather than as nil.
	if f.Extensions == nil || len(f.Extensions) != 0 {
		t.Errorf("host extensions = %v, want an empty list", f.Extensions)
	}
	if f.CriticalOptionValues == nil {
		t.Error("critical_option_values must be an empty map, not nil")
	}
}

func TestSSHSigningGateFailsClosed(t *testing.T) {
	authority, _ := newTestAuthority(t)
	authority.SetPolicyGate(&recordingGate{errs: errors.New("database is down")})
	ctx := context.Background()

	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-failclosed-ca"})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	_, err = authority.Sign(ctx, SignRequest{CAID: ca.ID, PublicKey: subjectKey(t), Principals: []string{"ops"}})
	if err == nil {
		t.Fatal("a gate failure must refuse the signature")
	}
	if errors.Is(err, celpolicy.ErrDenied) {
		t.Error("a store failure is not a policy denial")
	}
}

// TestSSHSigningGateIsWiredByDefault is the test that matters for the invariant:
// an authority built the ordinary way consults the rule table, so no surface can
// forget to install the gate.
func TestSSHSigningGateIsWiredByDefault(t *testing.T) {
	authority, db := newTestAuthority(t)
	if authority.policy == nil {
		t.Fatal("NewAuthority must wire the signing-restriction gate")
	}
	ctx := context.Background()
	ca, err := authority.InitCA(ctx, CASpec{Label: "ssh-wired-ca"})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	rule := celpolicy.Rule{
		ID: "r1", Kind: celpolicy.KindSigning, Name: "no-root", Enabled: true, Effect: celpolicy.EffectDeny,
		Expression: `signing.ssh.principals.exists(p, p == "root")`,
		Message:    "an SSH certificate may not name root",
	}
	if err := db.CreateCELPolicyRule(&rule); err != nil {
		t.Fatalf("CreateCELPolicyRule: %v", err)
	}
	_, err = authority.Sign(ctx, SignRequest{CAID: ca.ID, PublicKey: subjectKey(t), Principals: []string{"root"}})
	if err == nil || !strings.Contains(err.Error(), "may not name root") {
		t.Fatalf("the stored rule must refuse the certificate: %v", err)
	}
	// An ordinary request still goes through.
	if _, err := authority.Sign(ctx, SignRequest{CAID: ca.ID, PublicKey: subjectKey(t), Principals: []string{"deploy"}}); err != nil {
		t.Fatalf("a permitted certificate must still be signed: %v", err)
	}
	// And the refusal is in the audit log with its reason.
	events, _, err := db.ListEvents("sign.policy", "", "", 50, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Action == "sign.policy" && strings.Contains(e.Detail, "no-root[enforce]") {
			found = true
		}
	}
	if !found {
		t.Error("the refusal must be recorded as a sign.policy audit event")
	}
}

// TestSSHFactHelpers covers the key-shape helpers directly: the CA key
// algorithm is read from the stored key type with the CA's own public key as a
// fallback, and the signature digest is fixed by the CA key algorithm rather
// than chosen by the caller — both facts a rule may restrict on.
func TestSSHFactHelpers(t *testing.T) {
	for _, tc := range []struct {
		keyType, want string
	}{
		{"rsa-2048", "RSA"},
		{"RSA-4096", "RSA"},
		{"ecdsa-p256", "ECDSA"},
		{"ed25519", "Ed25519"},
		{"", ""},
	} {
		if got := caKeyAlgorithm(&models.CA{KeyType: tc.keyType}); got != tc.want {
			t.Errorf("caKeyAlgorithm(%q) = %q, want %q", tc.keyType, got, tc.want)
		}
	}
	// With no key type recorded, the CA's authorized_keys line answers.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	authorized := string(ssh.MarshalAuthorizedKey(sshPub))
	if got := caKeyAlgorithm(&models.CA{PublicKey: authorized}); got != "Ed25519" {
		t.Errorf("caKeyAlgorithm(from public key) = %q", got)
	}

	// The digest the CA's signature uses, per key algorithm. Ed25519 hashes
	// internally, so there is no externally selected message hash to report.
	if got := sshSignatureDigest(sshPub); got != "" {
		t.Errorf("Ed25519 digest = %q, want empty", got)
	}
	if got := sshSignatureDigest(nil); got != "SHA-256" {
		t.Errorf("nil key digest = %q", got)
	}
	for _, tc := range []struct {
		curve elliptic.Curve
		want  string
		bits  int
	}{
		{elliptic.P256(), "SHA-256", 256},
		{elliptic.P384(), "SHA-384", 384},
		{elliptic.P521(), "SHA-512", 521},
	} {
		key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ecPub, err := ssh.NewPublicKey(key.Public())
		if err != nil {
			t.Fatal(err)
		}
		if got := sshSignatureDigest(ecPub); got != tc.want {
			t.Errorf("%s digest = %q, want %q", tc.curve.Params().Name, got, tc.want)
		}
		if got := keyBits(ecPub); got != tc.bits {
			t.Errorf("%s bits = %d, want %d", tc.curve.Params().Name, got, tc.bits)
		}
		if got := sshKeyFacts(ecPub); got.HardwareBacked || got.Fingerprint == "" {
			t.Errorf("ECDSA key facts = %+v", got)
		}
	}

	// An RSA key reports its modulus size; a nil key reports nothing at all.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, err := ssh.NewPublicKey(rsaKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	if got := keyBits(rsaPub); got != 2048 {
		t.Errorf("RSA bits = %d", got)
	}
	if got := sshSignatureDigest(rsaPub); got != "SHA-256" {
		t.Errorf("RSA digest = %q", got)
	}
	if got := sshKeyFacts(nil); got.Type != "" || got.Bits != 0 {
		t.Errorf("nil key facts = %+v", got)
	}
	if got := certTypeName(99); got != "unknown" {
		t.Errorf("certTypeName(99) = %q", got)
	}
}
