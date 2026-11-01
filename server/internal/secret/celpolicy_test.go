package secret

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
)

// recordingGate captures the facts a raw signature was checked against.
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

func TestDataSigningIsGated(t *testing.T) {
	provider := newSoftwareProvider(t)
	defer provider.Close()
	store := newFakeSigningKeyStore()
	row, err := CreateSigningKey(context.Background(), provider, store, CreateSigningKeySpec{
		TenantID: "acme", Name: "release-signing", Algorithm: AlgECDSAP256,
	})
	if err != nil {
		t.Fatalf("CreateSigningKey: %v", err)
	}
	gate := &recordingGate{deny: "the release-signing key signs content, not a caller-supplied digest"}

	_, err = Sign(context.Background(), provider, row, []byte("payload"), "", false,
		WithPolicy(SignPolicy{Gate: gate, RequestedBy: "ops@example.com", Purpose: "CHG-1", Source: celpolicy.SourceCLI}))
	if err == nil {
		t.Fatal("a refused signature must not be produced")
	}
	if !errors.Is(err, celpolicy.ErrDenied) {
		t.Errorf("the refusal must be a policy denial: %v", err)
	}
	if !strings.Contains(err.Error(), "not a caller-supplied digest") {
		t.Errorf("the operator's wording must reach the caller: %v", err)
	}
	if len(gate.seen) != 1 {
		t.Fatalf("the gate ran %d times, want 1", len(gate.seen))
	}
	f := gate.seen[0]
	if f.Operation != celpolicy.OpSignData || f.Source != celpolicy.SourceCLI {
		t.Errorf("operation/source = %q / %q", f.Operation, f.Source)
	}
	if f.RequestedBy != "ops@example.com" || f.Purpose != "CHG-1" {
		t.Errorf("attribution = %q / %q", f.RequestedBy, f.Purpose)
	}
	if f.Tenant != "acme" || f.Key.Tenant != "acme" {
		t.Errorf("tenant = %q / %q", f.Tenant, f.Key.Tenant)
	}
	if f.Key.Name != "release-signing" || f.Key.Algorithm != "ecdsa-p256" {
		t.Errorf("key facts = %+v", f.Key)
	}
	if f.Key.Size != 256 || f.Key.Curve != "P-256" || !strings.HasPrefix(f.Key.Fingerprint, "SHA256:") {
		t.Errorf("key algorithm facts = %+v", f.Key)
	}
	if f.Key.Provider == "" || f.Key.Ref == "" {
		t.Errorf("key provider facts = %+v", f.Key)
	}
	if !f.Data.Present || f.Data.Key != "release-signing" || f.Data.Hash != "SHA-256" {
		t.Errorf("data facts = %+v", f.Data)
	}
	want := sha256.Sum256([]byte("payload"))
	if f.Payload.Digest != hex.EncodeToString(want[:]) {
		t.Errorf("payload digest = %q, want the message's SHA-256", f.Payload.Digest)
	}
	if f.Payload.Size != len("payload") || f.Payload.Prehashed {
		t.Errorf("payload facts = %+v", f.Payload)
	}
}

func TestDataSigningReportsPrehashedInput(t *testing.T) {
	provider := newSoftwareProvider(t)
	defer provider.Close()
	store := newFakeSigningKeyStore()
	row, err := CreateSigningKey(context.Background(), provider, store, CreateSigningKeySpec{
		TenantID: "acme", Name: "k", Algorithm: AlgECDSAP256,
	})
	if err != nil {
		t.Fatalf("CreateSigningKey: %v", err)
	}
	gate := &recordingGate{}
	digest := sha256.Sum256([]byte("a very large artifact"))
	if _, err := Sign(context.Background(), provider, row, digest[:], "sha256", true,
		WithPolicy(SignPolicy{Gate: gate})); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	f := gate.seen[0].Payload
	if !f.Prehashed {
		t.Error("a pre-hashed request must be reported as such: the service never saw the message")
	}
	if f.Size != 0 {
		t.Errorf("payload size = %d, want 0 for a caller-supplied digest", f.Size)
	}
	if f.Digest != hex.EncodeToString(digest[:]) {
		t.Errorf("payload digest = %q", f.Digest)
	}
}

func TestEd25519SigningIsGatedWithNoExternalHash(t *testing.T) {
	provider := newSoftwareProvider(t)
	defer provider.Close()
	store := newFakeSigningKeyStore()
	row, err := CreateSigningKey(context.Background(), provider, store, CreateSigningKeySpec{
		TenantID: "acme", Name: "ed", Algorithm: AlgEd25519,
	})
	if err != nil {
		t.Fatalf("CreateSigningKey: %v", err)
	}
	gate := &recordingGate{}
	if _, err := Sign(context.Background(), provider, row, []byte("message"), "", false,
		WithPolicy(SignPolicy{Gate: gate})); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(gate.seen) != 1 {
		t.Fatalf("the Ed25519 path must consult the gate too (ran %d times)", len(gate.seen))
	}
	f := gate.seen[0]
	if f.Data.Hash != "" || f.Payload.DigestAlgorithm != "" {
		t.Errorf("Ed25519 has no externally selected message hash: %+v / %+v", f.Data, f.Payload)
	}
	if f.Payload.Size != len("message") {
		t.Errorf("payload size = %d", f.Payload.Size)
	}
	if f.Key.Algorithm != "ed25519" {
		t.Errorf("key algorithm = %q", f.Key.Algorithm)
	}

	// And it refuses when a rule says so.
	gate.deny = "no"
	if _, err := Sign(context.Background(), provider, row, []byte("message"), "", false,
		WithPolicy(SignPolicy{Gate: gate})); !errors.Is(err, celpolicy.ErrDenied) {
		t.Errorf("the Ed25519 path must honour a refusal: %v", err)
	}
}

func TestDataSigningGateFailsClosed(t *testing.T) {
	provider := newSoftwareProvider(t)
	defer provider.Close()
	store := newFakeSigningKeyStore()
	row, err := CreateSigningKey(context.Background(), provider, store, CreateSigningKeySpec{
		TenantID: "acme", Name: "k", Algorithm: AlgECDSAP256,
	})
	if err != nil {
		t.Fatalf("CreateSigningKey: %v", err)
	}
	gate := &recordingGate{errs: errors.New("database is down")}
	_, err = Sign(context.Background(), provider, row, []byte("x"), "", false, WithPolicy(SignPolicy{Gate: gate}))
	if err == nil {
		t.Fatal("a gate failure must refuse the signature")
	}
	if errors.Is(err, celpolicy.ErrDenied) {
		t.Error("a store failure is not a policy denial")
	}
}

func TestSignWithoutPolicyOptionIsUnrestricted(t *testing.T) {
	provider := newSoftwareProvider(t)
	defer provider.Close()
	store := newFakeSigningKeyStore()
	row, err := CreateSigningKey(context.Background(), provider, store, CreateSigningKeySpec{
		TenantID: "acme", Name: "k", Algorithm: AlgECDSAP256,
	})
	if err != nil {
		t.Fatalf("CreateSigningKey: %v", err)
	}
	// The pre-Task-224 call shape still compiles and still signs.
	if _, err := Sign(context.Background(), provider, row, []byte("x"), "", false); err != nil {
		t.Fatalf("an ungated call must sign: %v", err)
	}
	// As does one with a zero policy (no gate).
	if _, err := Sign(context.Background(), provider, row, []byte("x"), "", false, WithPolicy(SignPolicy{})); err != nil {
		t.Fatalf("a zero policy must permit: %v", err)
	}
}
