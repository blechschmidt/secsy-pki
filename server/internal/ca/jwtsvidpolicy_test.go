//go:build sqlite

package ca

// The CEL signing-restriction gate on the JWT-SVID path (Task 224). A JWT-SVID
// is minted with a CA key and is not a certificate: no template, no inventory
// row, and therefore no pre-issuance gate. These tests pin that the *signing*
// rules govern it instead, and that they see the token that would be signed —
// the clamped TTL and the normalized audience, not the request.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

type recordingSignGate struct {
	seen []celpolicy.SigningRequest
	deny string
	errs error
}

func (g *recordingSignGate) CheckSigning(_ context.Context, req celpolicy.SigningRequest) error {
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

// jwtSVIDRoot initializes a root whose key can sign a JWT-SVID (ECDSA: an
// Ed25519 CA key cannot carry a JOSE "alg" for a JWT-SVID).
func jwtSVIDRoot(t *testing.T) (*Manager, *models.CA) {
	t.Helper()
	mgr := newTestManager(t, softwareProvider(t))
	root, err := mgr.InitRoot(context.Background(), RootSpec{
		Label:    "svid-policy-root",
		KeyType:  "ecdsa-p256",
		Subject:  PKIXName(models.CASubject{CommonName: "SVID Policy Root"}),
		Validity: 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	return mgr, root
}

func TestJWTSVIDIsGated(t *testing.T) {
	mgr, root := jwtSVIDRoot(t)
	gate := &recordingSignGate{deny: "this trust domain does not mint tokens for that audience"}
	mgr.SetSigningPolicyGate(gate)

	_, err := mgr.IssueJWTSVID(context.Background(), JWTSVIDSpec{
		CAID:        root.ID,
		SPIFFEID:    "spiffe://example.org/ns/prod/sa/payments",
		Audience:    []string{"spiffe://example.org/ns/prod/sa/ledger"},
		RequestedBy: "ops@example.com",
	})
	if err == nil {
		t.Fatal("a refused JWT-SVID must not be minted")
	}
	if !errors.Is(err, celpolicy.ErrDenied) {
		t.Errorf("the refusal must be a policy denial: %v", err)
	}
	if !strings.Contains(err.Error(), "does not mint tokens for that audience") {
		t.Errorf("the operator's wording must reach the requester: %v", err)
	}
	if len(gate.seen) != 1 {
		t.Fatalf("the gate ran %d times, want 1", len(gate.seen))
	}
}

func TestJWTSVIDFactsDescribeTheToken(t *testing.T) {
	mgr, root := jwtSVIDRoot(t)
	gate := &recordingSignGate{}
	mgr.SetSigningPolicyGate(gate)

	res, err := mgr.IssueJWTSVID(context.Background(), JWTSVIDSpec{
		CAID:     root.ID,
		SPIFFEID: "spiffe://example.org/ns/prod/sa/payments",
		Audience: []string{"spiffe://example.org/ns/prod/sa/ledger", ""},
		// Far beyond the maximum, so the facts must show the clamped lifetime.
		TTL:         30 * 24 * time.Hour,
		RequestedBy: "ops@example.com",
	})
	if err != nil {
		t.Fatalf("IssueJWTSVID: %v", err)
	}
	if len(gate.seen) != 1 {
		t.Fatalf("the gate ran %d times, want 1", len(gate.seen))
	}
	f := gate.seen[0]

	if f.Operation != celpolicy.OpSignJWTSVID {
		t.Errorf("operation = %q", f.Operation)
	}
	if f.RequestedBy != "ops@example.com" {
		t.Errorf("requested_by = %q", f.RequestedBy)
	}
	if f.Key.Name != root.Label || f.Key.Provider == "" {
		t.Errorf("key facts = %+v", f.Key)
	}
	if !f.JWTSVID.Present {
		t.Fatal("the jwt_svid fact group must be present")
	}
	if f.JWTSVID.SPIFFEID != "spiffe://example.org/ns/prod/sa/payments" {
		t.Errorf("spiffe_id = %q", f.JWTSVID.SPIFFEID)
	}
	if f.JWTSVID.TrustDomain != "example.org" || f.JWTSVID.Path != "/ns/prod/sa/payments" {
		t.Errorf("trust domain / path = %q / %q", f.JWTSVID.TrustDomain, f.JWTSVID.Path)
	}
	// The audience a rule sees is the normalized one the token carries, with the
	// empty entry dropped — not the request's.
	if len(f.JWTSVID.Audience) != 1 || f.JWTSVID.Audience[0] != "spiffe://example.org/ns/prod/sa/ledger" {
		t.Errorf("audience = %v", f.JWTSVID.Audience)
	}
	if f.JWTSVID.Algorithm != res.Algorithm || f.JWTSVID.KeyID != res.KeyID {
		t.Errorf("alg/kid = %q/%q, want %q/%q", f.JWTSVID.Algorithm, f.JWTSVID.KeyID, res.Algorithm, res.KeyID)
	}
	// 30 days was clamped to the maximum, and the facts must show the clamp.
	if f.JWTSVID.TTL != JWTSVIDMaxTTL {
		t.Errorf("ttl = %s, want the clamped %s", f.JWTSVID.TTL, JWTSVIDMaxTTL)
	}
	if f.JWTSVID.TTLSeconds != int(JWTSVIDMaxTTL/time.Second) {
		t.Errorf("ttl_seconds = %d", f.JWTSVID.TTLSeconds)
	}
	if f.JWTSVID.Expiry.IsZero() || !f.JWTSVID.Expiry.After(f.JWTSVID.NotBefore) {
		t.Errorf("window = %s..%s", f.JWTSVID.NotBefore, f.JWTSVID.Expiry)
	}
	if f.JWTSVID.CA.ID != root.ID || f.JWTSVID.CA.Label != root.Label {
		t.Errorf("ca facts = %+v", f.JWTSVID.CA)
	}
	if !f.Payload.Present || f.Payload.Prehashed {
		t.Errorf("payload facts = %+v", f.Payload)
	}
}

func TestJWTSVIDGateFailsClosed(t *testing.T) {
	mgr, root := jwtSVIDRoot(t)
	mgr.SetSigningPolicyGate(&recordingSignGate{errs: errors.New("database is down")})
	_, err := mgr.IssueJWTSVID(context.Background(), JWTSVIDSpec{
		CAID:     root.ID,
		SPIFFEID: "spiffe://example.org/ns/prod/sa/payments",
		Audience: []string{"spiffe://example.org/ns/prod/sa/ledger"},
	})
	if err == nil {
		t.Fatal("a gate failure must refuse the token")
	}
	if errors.Is(err, celpolicy.ErrDenied) {
		t.Error("a store failure is not a policy denial")
	}
}

// TestJWTSVIDGateIsWiredByDefault is the invariant: a manager built the ordinary
// way consults the rule table, so no surface can forget to install the gate.
func TestJWTSVIDGateIsWiredByDefault(t *testing.T) {
	mgr, root := jwtSVIDRoot(t)
	if mgr.signPolicy == nil {
		t.Fatal("NewManager must wire the signing-restriction gate")
	}
	rule := celpolicy.Rule{
		ID: "s-1", Kind: celpolicy.KindSigning, Name: "svid-audience-allowlist", Enabled: true,
		Operations: []string{celpolicy.OpSignJWTSVID},
		Expression: `signing.jwt_svid.audience.all(a, a.startsWith("spiffe://example.org/"))`,
		Message:    "a JWT-SVID may only be minted for an audience inside this trust domain",
	}
	if err := mgr.db.CreateCELPolicyRule(&rule); err != nil {
		t.Fatalf("CreateCELPolicyRule: %v", err)
	}
	_, err := mgr.IssueJWTSVID(context.Background(), JWTSVIDSpec{
		CAID:     root.ID,
		SPIFFEID: "spiffe://example.org/ns/prod/sa/payments",
		Audience: []string{"https://external.example.net"},
	})
	if err == nil || !strings.Contains(err.Error(), "inside this trust domain") {
		t.Fatalf("the stored rule must refuse the token: %v", err)
	}
	// An in-domain audience still mints.
	if _, err := mgr.IssueJWTSVID(context.Background(), JWTSVIDSpec{
		CAID:     root.ID,
		SPIFFEID: "spiffe://example.org/ns/prod/sa/payments",
		Audience: []string{"spiffe://example.org/ns/prod/sa/ledger"},
	}); err != nil {
		t.Fatalf("a permitted token must be minted: %v", err)
	}
	// And a *certificate* rule must not be consulted on this path.
	certRule := celpolicy.Rule{
		ID: "c-1", Name: "one-san", Enabled: true,
		Expression: `request.san_count <= 1`,
	}
	if err := mgr.db.CreateCELPolicyRule(&certRule); err != nil {
		t.Fatalf("CreateCELPolicyRule: %v", err)
	}
	if _, err := mgr.IssueJWTSVID(context.Background(), JWTSVIDSpec{
		CAID:     root.ID,
		SPIFFEID: "spiffe://example.org/ns/prod/sa/payments",
		Audience: []string{"spiffe://example.org/ns/prod/sa/ledger"},
	}); err != nil {
		t.Fatalf("a certificate rule must not be evaluated on the JWT-SVID path: %v", err)
	}
}

func TestSplitSPIFFEID(t *testing.T) {
	cases := []struct {
		in           string
		domain, path string
		ok           bool
	}{
		{"spiffe://example.org/ns/prod/sa/payments", "example.org", "/ns/prod/sa/payments", true},
		{"spiffe://example.org", "example.org", "", true},
		{"spiffe://example.org/", "example.org", "/", true},
		{"https://example.org/x", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		domain, path, ok := splitSPIFFEID(tc.in)
		if ok != tc.ok || domain != tc.domain || path != tc.path {
			t.Errorf("splitSPIFFEID(%q) = %q, %q, %v; want %q, %q, %v",
				tc.in, domain, path, ok, tc.domain, tc.path, tc.ok)
		}
	}
}
