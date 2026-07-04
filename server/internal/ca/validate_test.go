//go:build sqlite

package ca

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/certvalidate"
)

// validateLeaf is a small helper that assembles the trust anchors and live
// revocation resolver for root and runs the certvalidate engine over res's leaf,
// evaluated at a point inside the leaf's validity.
func validateLeaf(t *testing.T, mgr *Manager, root string, res *IssueResult) *certvalidate.Report {
	t.Helper()
	roots, inter, err := mgr.TrustAnchorsFor(root)
	if err != nil {
		t.Fatalf("TrustAnchorsFor: %v", err)
	}
	cas, err := mgr.db.ListCAs()
	if err != nil {
		t.Fatalf("ListCAs: %v", err)
	}
	return certvalidate.Validate(certvalidate.Options{
		Roots:         roots,
		Intermediates: inter,
		Revocation:    mgr.NewChainRevocationResolver(cas),
		Now:           res.Certificate.NotBefore.Add(time.Minute),
	}, res.Certificate, nil)
}

// TestChainValidationRevocationIntegration proves the validation service consults
// the real revocation store (the same one OCSP and the CRL use), including the
// reversible on-hold state from Task 82, across a freshly issued leaf's lifecycle.
func TestChainValidationRevocationIntegration(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()
	root := newRoot(t, mgr, "validate-revocation")

	// A freshly issued leaf validates cleanly.
	leaf := issueLeaf(t, mgr, root.ID, "good.example.com")
	rep := validateLeaf(t, mgr, root.ID, leaf)
	if !rep.ChainBuilt || !rep.Valid {
		t.Fatalf("fresh leaf should be valid: built=%v valid=%v reasons=%v", rep.ChainBuilt, rep.Valid, rep.Reasons)
	}
	if rep.Chain[0].Revocation == nil || rep.Chain[0].Revocation.State != certvalidate.RevocationGood {
		t.Fatalf("fresh leaf revocation = %+v, want good", rep.Chain[0].Revocation)
	}

	// Permanent revocation flips the verdict to invalid via the revocation gate.
	if _, err := mgr.RevokeCertificate(ctx, root.ID, leaf.Serial.String(), "keyCompromise"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	rep = validateLeaf(t, mgr, root.ID, leaf)
	if rep.Valid {
		t.Fatalf("revoked leaf must be invalid")
	}
	if got := rep.Chain[0].Revocation; got == nil || got.State != certvalidate.RevocationRevoked {
		t.Fatalf("revoked leaf revocation = %+v, want revoked", got)
	}
	if rep.Chain[0].Revocation.ReasonText != "keyCompromise" {
		t.Errorf("revocation reason text = %q, want keyCompromise", rep.Chain[0].Revocation.ReasonText)
	}

	// A second leaf placed on reversible hold reports "held" (invalid while held),
	// then returns to valid once released — the Task 82 suspend/release path.
	held := issueLeaf(t, mgr, root.ID, "held.example.com")
	if _, err := mgr.SuspendCertificate(ctx, root.ID, held.Serial.String()); err != nil {
		t.Fatalf("SuspendCertificate: %v", err)
	}
	rep = validateLeaf(t, mgr, root.ID, held)
	if rep.Valid {
		t.Fatalf("suspended leaf must be invalid while on hold")
	}
	if got := rep.Chain[0].Revocation; got == nil || got.State != certvalidate.RevocationHeld {
		t.Fatalf("held leaf revocation = %+v, want held", got)
	}

	if err := mgr.ReleaseCertificate(ctx, root.ID, held.Serial.String()); err != nil {
		t.Fatalf("ReleaseCertificate: %v", err)
	}
	rep = validateLeaf(t, mgr, root.ID, held)
	if !rep.Valid {
		t.Fatalf("released leaf should be valid again: %v", rep.Reasons)
	}
}

// TestLiveRevocationStatus checks the exported status wrapper directly, including
// the unknown-serial case.
func TestLiveRevocationStatus(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()
	root := newRoot(t, mgr, "live-status")
	leaf := issueLeaf(t, mgr, root.ID, "status.example.com")

	got, err := mgr.LiveRevocationStatus(root.ID, leaf.Serial)
	if err != nil {
		t.Fatalf("LiveRevocationStatus: %v", err)
	}
	if got.State != certvalidate.RevocationGood {
		t.Errorf("issued leaf status = %q, want good", got.State)
	}

	// A serial the CA never issued is unknown, not an error.
	unknown, err := mgr.LiveRevocationStatus(root.ID, big.NewInt(999999999))
	if err != nil {
		t.Fatalf("LiveRevocationStatus(unknown): %v", err)
	}
	if unknown.State != certvalidate.RevocationUnknown {
		t.Errorf("unknown serial status = %q, want unknown", unknown.State)
	}

	if _, err := mgr.SuspendCertificate(ctx, root.ID, leaf.Serial.String()); err != nil {
		t.Fatalf("SuspendCertificate: %v", err)
	}
	held, err := mgr.LiveRevocationStatus(root.ID, leaf.Serial)
	if err != nil {
		t.Fatalf("LiveRevocationStatus(held): %v", err)
	}
	if held.State != certvalidate.RevocationHeld {
		t.Errorf("held status = %q, want held", held.State)
	}
}

// TestTrustAnchorsForIntermediate proves a leaf under an intermediate validates
// against the root anchor with the intermediate bridging the path.
func TestTrustAnchorsForIntermediate(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	root, inter := newRootAndIntermediate(t, mgr, "validate-inter", 5*365*24*time.Hour)

	res, err := mgr.IssueCertificate(context.Background(), IssueSpec{
		CAID:    inter.ID,
		CSRPEM:  makeCSR(t, "under-inter.example.com", []string{"under-inter.example.com"}),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate under intermediate: %v", err)
	}

	// Validate against the intermediate's anchor set: TrustAnchorsFor(inter) yields
	// the root as the anchor and the intermediate as a bridging CA.
	roots, bridge, err := mgr.TrustAnchorsFor(inter.ID)
	if err != nil {
		t.Fatalf("TrustAnchorsFor: %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("expected exactly one root anchor, got %d", len(roots))
	}
	cas, _ := mgr.db.ListCAs()
	rep := certvalidate.Validate(certvalidate.Options{
		Roots:         roots,
		Intermediates: bridge,
		Revocation:    mgr.NewChainRevocationResolver(cas),
		Now:           res.Certificate.NotBefore.Add(time.Minute),
	}, res.Certificate, nil)

	if !rep.ChainBuilt || !rep.Valid {
		t.Fatalf("leaf under intermediate should validate: built=%v valid=%v reasons=%v", rep.ChainBuilt, rep.Valid, rep.Reasons)
	}
	if len(rep.Chain) != 3 {
		t.Fatalf("chain length = %d, want 3 (leaf, intermediate, root)", len(rep.Chain))
	}
	_ = root
}
