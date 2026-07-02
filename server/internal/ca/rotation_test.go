//go:build sqlite

package ca

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// newRootAndIntermediate provisions a root and one intermediate CA under it,
// returning both. The intermediate validity is caller-controlled so tests can
// exercise the near-expiry auto-rotation path.
func newRootAndIntermediate(t *testing.T, mgr *Manager, tag string, interValidity time.Duration) (*models.CA, *models.CA) {
	t.Helper()
	ctx := context.Background()
	root := newRoot(t, mgr, tag)
	inter, err := mgr.IssueIntermediate(ctx, IntermediateSpec{
		ParentID: root.ID,
		Label:    uniqueLabel(t, tag+"-inter"),
		KeyType:  "ecdsa-p256",
		Subject:  PKIXName(models.CASubject{CommonName: "Rotation Test Intermediate " + tag}),
		Validity: interValidity,
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}
	return root, inter
}

// parseChainPools splits a combined-chain PEM bundle into a roots pool
// (self-signed certs) and an intermediates pool (everything else), so a leaf can
// be verified against exactly the certificates a relying party would receive.
func parseChainPools(t *testing.T, chainPEM []byte) (*x509.CertPool, *x509.CertPool, int) {
	t.Helper()
	roots := x509.NewCertPool()
	inters := x509.NewCertPool()
	rest := chainPEM
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing chain cert: %v", err)
		}
		n++
		// A self-signed cert (subject == issuer) is the trust anchor.
		if cert.CheckSignatureFrom(cert) == nil {
			roots.AddCert(cert)
		} else {
			inters.AddCert(cert)
		}
	}
	return roots, inters, n
}

// verifyLeaf checks that a leaf certificate validates against the supplied
// combined chain at time now.
func verifyLeaf(t *testing.T, leaf *x509.Certificate, chainPEM []byte, now time.Time) error {
	t.Helper()
	roots, inters, _ := parseChainPools(t, chainPEM)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

// TestIntermediateRotationContinuity is the core Task 24 proof: after rotating
// an intermediate's signing key, a leaf issued under the OLD key still validates
// against the combined overlap chain, and a leaf issued under the NEW key (via
// the same CA id, transparently routed to the active successor) also validates —
// establishing dual-chain continuity across the rollover.
func TestIntermediateRotationContinuity(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runRotationContinuity(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runRotationContinuity(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()
	now := time.Now()
	_, inter := newRootAndIntermediate(t, mgr, tag, 2*365*24*time.Hour)

	// Issue a leaf under the original intermediate key.
	csr1 := makeCSR(t, "old-key-leaf.example.com", []string{"old-key-leaf.example.com"})
	leaf1, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: inter.ID, CSRPEM: csr1, Profile: "server"})
	if err != nil {
		t.Fatalf("IssueCertificate (pre-rotation): %v", err)
	}
	if leaf1.Record.CAID != inter.ID {
		t.Fatalf("pre-rotation leaf recorded under %q, want %q", leaf1.Record.CAID, inter.ID)
	}

	// Rotate the intermediate signing key.
	res, err := mgr.RotateIntermediate(ctx, RotateSpec{CAID: inter.ID, RequestedBy: "test"})
	if err != nil {
		t.Fatalf("RotateIntermediate: %v", err)
	}
	if res.NewCA.ID == inter.ID {
		t.Fatal("rotation did not create a new CA")
	}
	if res.OldCA.Status != models.CAStatusSuperseded {
		t.Errorf("old CA status = %q, want superseded", res.OldCA.Status)
	}
	if res.NewCA.Status != models.CAStatusActive {
		t.Errorf("new CA status = %q, want active", res.NewCA.Status)
	}
	if res.NewCA.Subject != res.OldCA.Subject {
		t.Errorf("new intermediate subject %q != old %q (must be a drop-in issuer DN)", res.NewCA.Subject, res.OldCA.Subject)
	}
	if res.OldCA.PublicKey == res.NewCA.PublicKey {
		t.Error("rotated intermediate reused the old public key; a new keypair must be generated")
	}
	if res.RetireAfter == nil {
		t.Error("expected a retire-after deadline while an outstanding leaf remains")
	}

	// The pre-rotation leaf must still validate against the combined overlap chain.
	if err := verifyLeaf(t, leaf1.Certificate, res.CombinedChainPEM, now); err != nil {
		t.Fatalf("pre-rotation leaf failed to validate against combined chain after rotation: %v", err)
	}

	// Issuing under the ORIGINAL CA id now transparently uses the new active key.
	csr2 := makeCSR(t, "new-key-leaf.example.com", []string{"new-key-leaf.example.com"})
	leaf2, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: inter.ID, CSRPEM: csr2, Profile: "server"})
	if err != nil {
		t.Fatalf("IssueCertificate (post-rotation): %v", err)
	}
	if leaf2.Record.CAID != res.NewCA.ID {
		t.Errorf("post-rotation leaf recorded under %q, want new CA %q", leaf2.Record.CAID, res.NewCA.ID)
	}
	// The new leaf must chain via the NEW intermediate (present in the bundle).
	if err := verifyLeaf(t, leaf2.Certificate, res.CombinedChainPEM, now); err != nil {
		t.Fatalf("post-rotation leaf failed to validate against combined chain: %v", err)
	}

	// The combined chain must carry BOTH intermediates plus the root (3 certs).
	_, _, nCerts := parseChainPools(t, res.CombinedChainPEM)
	if nCerts != 3 {
		t.Errorf("combined chain has %d certs, want 3 (new + old intermediate + root)", nCerts)
	}

	// Independent fetch of the combined chain must match what rotation returned.
	chain, err := mgr.CombinedChainPEM(res.NewCA.ID)
	if err != nil {
		t.Fatalf("CombinedChainPEM: %v", err)
	}
	if err := verifyLeaf(t, leaf1.Certificate, chain, now); err != nil {
		t.Fatalf("old-key leaf failed against freshly built chain: %v", err)
	}
	if err := verifyLeaf(t, leaf2.Certificate, chain, now); err != nil {
		t.Fatalf("new-key leaf failed against freshly built chain: %v", err)
	}
}

// TestIntermediateRetirement verifies the controlled-retirement half of the
// rollover: retirement is refused while outstanding leaves remain, forced
// retirement revokes the old intermediate under its parent and refreshes the
// parent CRL, and a retired intermediate drops out of freshly published chains.
func TestIntermediateRetirement(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()
	now := time.Now()

	root, inter := newRootAndIntermediate(t, mgr, "retire", 2*365*24*time.Hour)

	// One outstanding leaf under the old key.
	csr := makeCSR(t, "leaf.example.com", []string{"leaf.example.com"})
	leaf, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: inter.ID, CSRPEM: csr, Profile: "server"})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}

	res, err := mgr.RotateIntermediate(ctx, RotateSpec{CAID: inter.ID, RequestedBy: "test"})
	if err != nil {
		t.Fatalf("RotateIntermediate: %v", err)
	}

	// Status: old key superseded, one outstanding leaf, not safe to retire.
	st, err := mgr.RotationStatus(inter.ID)
	if err != nil {
		t.Fatalf("RotationStatus: %v", err)
	}
	if st.OutstandingLeaves != 1 {
		t.Errorf("outstanding leaves = %d, want 1", st.OutstandingLeaves)
	}
	if st.SafeToRetire {
		t.Error("SafeToRetire = true while an outstanding leaf remains")
	}

	// Retirement without force must be refused.
	if _, err := mgr.RetireIntermediate(ctx, RetireSpec{CAID: inter.ID}); err == nil {
		t.Fatal("RetireIntermediate succeeded despite an outstanding leaf; expected refusal")
	}

	// Revoke the outstanding leaf under the OLD CA (where it was issued); now the
	// old key drains and retirement becomes safe.
	if _, err := mgr.RevokeCertificate(ctx, inter.ID, leaf.Serial.String(), "superseded"); err != nil {
		t.Fatalf("revoking outstanding leaf: %v", err)
	}

	st, err = mgr.RotationStatus(inter.ID)
	if err != nil {
		t.Fatalf("RotationStatus after revoke: %v", err)
	}
	if st.OutstandingLeaves != 0 {
		t.Errorf("outstanding leaves = %d after revoke, want 0", st.OutstandingLeaves)
	}
	if !st.SafeToRetire {
		t.Error("SafeToRetire = false after draining outstanding leaves")
	}

	// Retire the old key: it is revoked under the root and the root CRL refreshed.
	ret, err := mgr.RetireIntermediate(ctx, RetireSpec{CAID: inter.ID, RequestedBy: "test"})
	if err != nil {
		t.Fatalf("RetireIntermediate: %v", err)
	}
	if ret.RetiredCA.Status != models.CAStatusRetired {
		t.Errorf("retired CA status = %q, want retired", ret.RetiredCA.Status)
	}
	if ret.RevokedSerial != inter.Serial {
		t.Errorf("revoked serial = %q, want old intermediate serial %q", ret.RevokedSerial, inter.Serial)
	}

	// The root CRL must now list the retired intermediate's serial.
	crl, err := x509.ParseRevocationList(ret.CRLDER)
	if err != nil {
		t.Fatalf("parsing refreshed root CRL: %v", err)
	}
	found := false
	for _, rc := range crl.RevokedCertificateEntries {
		if rc.SerialNumber.String() == inter.Serial {
			found = true
		}
	}
	if !found {
		t.Errorf("root CRL does not list retired intermediate serial %q", inter.Serial)
	}

	// A retired intermediate must drop out of freshly published overlap chains.
	chain, err := mgr.CombinedChainPEM(res.NewCA.ID)
	if err != nil {
		t.Fatalf("CombinedChainPEM after retirement: %v", err)
	}
	_, _, nCerts := parseChainPools(t, chain)
	if nCerts != 2 {
		t.Errorf("post-retirement chain has %d certs, want 2 (new intermediate + root)", nCerts)
	}
	_ = root
	_ = now
}

// TestAutoRotateDue verifies the monitor-facing bulk trigger: an intermediate
// whose own certificate is within the threshold is rotated; one comfortably far
// from expiry is left alone.
func TestAutoRotateDue(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()

	// Near-expiry intermediate (10 days) and a long-lived one (2 years).
	_, near := newRootAndIntermediate(t, mgr, "near", 10*24*time.Hour)
	longRoot, far := newRootAndIntermediate(t, mgr, "far", 2*365*24*time.Hour)
	_ = longRoot

	results, err := mgr.AutoRotateDue(ctx, AutoRotateSpec{
		Before:      30 * 24 * time.Hour,
		RequestedBy: "monitor",
	})
	if err != nil {
		t.Fatalf("AutoRotateDue: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("AutoRotateDue rotated %d CAs, want 1 (only the near-expiry one)", len(results))
	}
	if results[0].OldCA.ID != near.ID {
		t.Errorf("rotated CA = %q, want near-expiry intermediate %q", results[0].OldCA.ID, near.ID)
	}

	// The far-from-expiry intermediate must remain active and un-rotated.
	st, err := mgr.RotationStatus(far.ID)
	if err != nil {
		t.Fatalf("RotationStatus(far): %v", err)
	}
	if st.CA.Status != models.CAStatusActive || st.CA.SuccessorID != nil {
		t.Errorf("far intermediate was rotated unexpectedly: status=%q successor=%v", st.CA.Status, st.CA.SuccessorID)
	}

	// A second pass must not re-rotate the already-superseded near CA (no storm).
	results2, err := mgr.AutoRotateDue(ctx, AutoRotateSpec{Before: 30 * 24 * time.Hour, RequestedBy: "monitor"})
	if err != nil {
		t.Fatalf("AutoRotateDue (2nd pass): %v", err)
	}
	// The freshly rotated-in key inherits the old 10-day span, so it too is now
	// within the 30-day window and will rotate again — but the ORIGINAL near CA
	// must not. Assert no result references the already-superseded original.
	for _, r := range results2 {
		if r.OldCA.ID == near.ID {
			t.Errorf("second pass re-rotated the already-superseded original CA %q", near.ID)
		}
	}
}
