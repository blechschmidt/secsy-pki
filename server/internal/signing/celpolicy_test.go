package signing

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// recordingGate captures the facts a signature was checked against and answers
// with a fixed verdict, so a test can assert on the facts rather than on a rule.
type recordingGate struct {
	seen  []celpolicy.SigningRequest
	deny  string // non-empty: refuse with this reason
	fails error  // non-nil: the gate itself failed (an unreadable rule set)
}

func (g *recordingGate) CheckSigning(_ context.Context, req celpolicy.SigningRequest) error {
	g.seen = append(g.seen, req)
	if g.fails != nil {
		return g.fails
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

// signingHarness builds a service with one code-signing identity and a gate.
func signingHarness(t *testing.T, gate celpolicy.SigningChecker) (*Service, *harness) {
	t.Helper()
	h := newHarness(t)
	cert := h.issueCodeSigningCert(t, "codesign-policy", keyprovider.KeyTypeECDSAP256,
		time.Now().Add(-time.Hour), time.Now().Add(time.Hour), codeSigningEKU())
	svc := h.service(t, SignerConfig{
		Name:        "release",
		KeyLabel:    "codesign-policy",
		Certificate: cert,
		Chain:       []*x509.Certificate{cert, h.caCert},
		TenantID:    "acme",
	})
	svc.SetPolicyGate(gate)
	return svc, h
}

func TestArtifactSigningIsGated(t *testing.T) {
	gate := &recordingGate{deny: "the release-signing key is reserved for the release workflow"}
	svc, _ := signingHarness(t, gate)

	_, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: []byte("tarball")})
	if err == nil {
		t.Fatal("a refused signature must not be produced")
	}
	if !errors.Is(err, celpolicy.ErrDenied) {
		t.Errorf("the refusal must be a policy denial: %v", err)
	}
	if !strings.Contains(err.Error(), "reserved for the release workflow") {
		t.Errorf("the operator's wording must reach the caller: %v", err)
	}
	if len(gate.seen) != 1 {
		t.Fatalf("the gate ran %d times, want 1", len(gate.seen))
	}
}

func TestArtifactSigningFactsDescribeTheSignature(t *testing.T) {
	gate := &recordingGate{}
	svc, _ := signingHarness(t, gate)
	artifact := []byte("v1.2.3 release tarball bytes")

	res, err := svc.Sign(context.Background(), SignRequest{
		Signer: "release", Content: artifact, Name: "product-1.2.3.tar.gz", Purpose: "CHG-10482",
		RequestedBy: "ci@example.com",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(gate.seen) != 1 {
		t.Fatalf("the gate ran %d times, want 1", len(gate.seen))
	}
	facts := gate.seen[0]

	if facts.Operation != celpolicy.OpSignArtifact {
		t.Errorf("operation = %q", facts.Operation)
	}
	if facts.Tenant != "acme" || facts.Key.Tenant != "acme" {
		t.Errorf("tenant = %q / %q", facts.Tenant, facts.Key.Tenant)
	}
	if facts.RequestedBy != "ci@example.com" || facts.Purpose != "CHG-10482" {
		t.Errorf("attribution = %q / %q", facts.RequestedBy, facts.Purpose)
	}
	if facts.Key.Name != "release" || facts.Key.Label != "codesign-policy" {
		t.Errorf("key = %+v", facts.Key)
	}
	if facts.Key.Algorithm != "ECDSA" || facts.Key.Curve != "P-256" {
		t.Errorf("key algorithm = %q %q", facts.Key.Algorithm, facts.Key.Curve)
	}
	if facts.Key.Fingerprint == "" || !strings.HasPrefix(facts.Key.Fingerprint, "SHA256:") {
		t.Errorf("key fingerprint = %q", facts.Key.Fingerprint)
	}
	if !facts.Artifact.Present || facts.Artifact.Signer != "release" || facts.Artifact.Name != "product-1.2.3.tar.gz" {
		t.Errorf("artifact facts = %+v", facts.Artifact)
	}
	if facts.Artifact.Certificate.Subject == "" || len(facts.Artifact.Certificate.ExtKeyUsages) == 0 {
		t.Errorf("signer certificate facts = %+v", facts.Artifact.Certificate)
	}
	if got := facts.Artifact.Certificate.ExtKeyUsages[0]; got != "codeSigning" {
		t.Errorf("signer EKU = %q, want codeSigning", got)
	}
	// The digest the rule saw must be the digest the signature covers.
	want := sha256.Sum256(artifact)
	if facts.Payload.Digest != hex.EncodeToString(want[:]) {
		t.Errorf("payload digest = %q, want the artifact's SHA-256", facts.Payload.Digest)
	}
	if facts.Payload.Digest != hex.EncodeToString(res.ArtifactDigest) {
		t.Error("the fact digest and the produced signature's digest disagree")
	}
	if facts.Payload.Size != len(artifact) || facts.Payload.Prehashed {
		t.Errorf("payload = %+v", facts.Payload)
	}
	if facts.Payload.DigestAlgorithm != "SHA-256" {
		t.Errorf("digest algorithm = %q", facts.Payload.DigestAlgorithm)
	}
}

func TestArtifactSigningFactsReportDigestInput(t *testing.T) {
	gate := &recordingGate{}
	svc, _ := signingHarness(t, gate)
	sum := sha256.Sum256([]byte("a very large image"))

	if _, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Digest: sum[:]}); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	facts := gate.seen[0]
	if !facts.Payload.Prehashed {
		t.Error("a digest-input request must be reported as pre-hashed: the service never saw the bytes")
	}
	if facts.Payload.Size != 0 {
		t.Errorf("payload size = %d, want 0 for digest input", facts.Payload.Size)
	}
	if facts.Payload.Digest != hex.EncodeToString(sum[:]) {
		t.Errorf("payload digest = %q", facts.Payload.Digest)
	}
}

func TestArtifactSigningFactsReportTheResolvedLevel(t *testing.T) {
	gate := &recordingGate{}
	svc, _ := signingHarness(t, gate)

	// B (no timestamp) and T (timestamped) must be distinguishable, because
	// "an artifact signature must carry a trusted timestamp" is a rule.
	if _, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: []byte("x"), Level: LevelB}); err != nil {
		t.Fatalf("Sign(b): %v", err)
	}
	if got := gate.seen[0].Artifact; got.Level != "b" || got.Timestamped {
		t.Errorf("level b facts = %+v", got)
	}
	if _, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: []byte("x"), Level: LevelT}); err != nil {
		t.Fatalf("Sign(t): %v", err)
	}
	if got := gate.seen[1].Artifact; got.Level != "t" || !got.Timestamped {
		t.Errorf("level t facts = %+v", got)
	}
}

func TestArtifactSigningGateFailsClosed(t *testing.T) {
	gate := &recordingGate{fails: errors.New("loading signing restriction rules: database is down")}
	svc, _ := signingHarness(t, gate)

	_, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: []byte("x")})
	if err == nil {
		t.Fatal("a gate failure must refuse the signature")
	}
	if errors.Is(err, celpolicy.ErrDenied) {
		t.Error("a store failure is not a policy denial")
	}
}

func TestArtifactSigningWithoutGateIsUnrestricted(t *testing.T) {
	svc, _ := signingHarness(t, nil)
	if svc.PolicyGateWired() {
		t.Error("PolicyGateWired must report a service with no gate")
	}
	if _, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: []byte("x")}); err != nil {
		t.Fatalf("a service with no rule store must sign: %v", err)
	}
}

func TestArtifactGateRunsBeforeTheKeyIsOpened(t *testing.T) {
	// A refused request must not touch the HSM. The provider is closed first, so
	// opening the key would fail with a distinctive error — if the gate ran
	// after, that is the error the caller would see instead of the refusal.
	gate := &recordingGate{deny: "refused"}
	svc, h := signingHarness(t, gate)
	h.provider.Close()

	_, err := svc.Sign(context.Background(), SignRequest{Signer: "release", Content: []byte("x")})
	if !errors.Is(err, celpolicy.ErrDenied) {
		t.Fatalf("the refusal must come from the gate, not from the closed provider: %v", err)
	}
}
