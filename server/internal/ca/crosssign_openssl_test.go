//go:build sqlite

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// TestCrossSignBridgeChains is the Task 47 acceptance test. It cross-signs a
// single intermediate under two independent roots and proves BOTH resulting
// chains build and validate:
//
//	root1 ──issues──▶ intermediate ──▶ leaf        (native chain)
//	root2 ──cross-signs──▶ intermediate            (alternate chain)
//
// The intermediate keeps one HSM-backed key; both root1's natively issued
// certificate and root2's cross-signed certificate carry that same subject key
// and DN, so the leaf (signed once by the intermediate's key) chains to either
// root. The test verifies each chain with Go's x509 verifier and, when openssl is
// present, with `openssl verify` — the authoritative interop check. It runs
// against both the software provider and SoftHSM (skipped when unconfigured).
func TestCrossSignBridgeChains(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	} {
		t.Run(name, func(t *testing.T) {
			runCrossSignBridge(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runCrossSignBridge(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()

	// Two independent roots — the two trust anchors of a bridge topology.
	root1, err := mgr.InitRoot(ctx, RootSpec{
		Label:    uniqueLabel(t, tag+"-root1"),
		KeyType:  "ecdsa-p256",
		Subject:  PKIXName(models.CASubject{CommonName: "Cross Root One " + tag, Organization: "OrgA"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot root1: %v", err)
	}
	root2, err := mgr.InitRoot(ctx, RootSpec{
		Label:    uniqueLabel(t, tag+"-root2"),
		KeyType:  "ecdsa-p256",
		Subject:  PKIXName(models.CASubject{CommonName: "Cross Root Two " + tag, Organization: "OrgB"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot root2: %v", err)
	}

	// One intermediate, natively issued under root1.
	inter, err := mgr.IssueIntermediate(ctx, IntermediateSpec{
		ParentID:   root1.ID,
		Label:      uniqueLabel(t, tag+"-inter"),
		KeyType:    "ecdsa-p256",
		Subject:    PKIXName(models.CASubject{CommonName: "Cross Bridged Intermediate " + tag}),
		Validity:   5 * 365 * 24 * time.Hour,
		MaxPathLen: intPtr(0),
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}
	interCert := mustParse(t, inter.Certificate)

	// Cross-sign the intermediate under root2. Only its public key + DN are
	// re-certified; the HSM key is untouched.
	res, err := mgr.CrossSign(ctx, CrossSignSpec{
		IssuerCAID:  root2.ID,
		SubjectCAID: inter.ID,
		RequestedBy: "test",
	})
	if err != nil {
		t.Fatalf("CrossSign: %v", err)
	}
	crossCert, err := x509.ParseCertificate(pemToDER(t, res.CertificatePEM))
	if err != nil {
		t.Fatalf("parsing cross-signed cert: %v", err)
	}

	// --- The cross-signed cert must be a true drop-in issuer for the intermediate.
	if crossCert.Subject.String() != interCert.Subject.String() {
		t.Errorf("cross-signed subject = %q, want %q (must match to be interchangeable)",
			crossCert.Subject.String(), interCert.Subject.String())
	}
	if hex.EncodeToString(crossCert.RawSubject) != hex.EncodeToString(interCert.RawSubject) {
		t.Error("cross-signed RawSubject differs from the intermediate's; DN not preserved byte-for-byte")
	}
	if hex.EncodeToString(crossCert.SubjectKeyId) != hex.EncodeToString(interCert.SubjectKeyId) {
		t.Errorf("cross-signed SKI = %x, want %x (subordinate AKIs would not match)",
			crossCert.SubjectKeyId, interCert.SubjectKeyId)
	}
	interPub, ok := interCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("intermediate public key is not ECDSA")
	}
	crossPub, ok := crossCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("cross-signed public key is not ECDSA")
	}
	if interPub.X.Cmp(crossPub.X) != 0 || interPub.Y.Cmp(crossPub.Y) != 0 {
		t.Fatal("cross-signed cert does not carry the intermediate's public key")
	}
	if !crossCert.IsCA {
		t.Error("cross-signed cert is not marked as a CA")
	}

	// The cross-signed cert must verify under root2's key.
	root2Cert := mustParse(t, root2.Certificate)
	if err := crossCert.CheckSignatureFrom(root2Cert); err != nil {
		t.Fatalf("cross-signed cert not signed by root2: %v", err)
	}
	// And its record must be tenant-scoped to the issuer.
	if res.CrossSign.TenantID != root2.TenantID {
		t.Errorf("cross-sign tenant = %q, want issuer tenant %q", res.CrossSign.TenantID, root2.TenantID)
	}
	if res.CrossSign.SubjectCAID == nil || *res.CrossSign.SubjectCAID != inter.ID {
		t.Errorf("cross-sign subject CA link = %v, want %q", res.CrossSign.SubjectCAID, inter.ID)
	}

	// Issue a leaf under the intermediate (signed once by the intermediate key).
	leaf, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    inter.ID,
		CSRPEM:  makeCSR(t, "leaf."+tag+".example.com", []string{"leaf." + tag + ".example.com"}),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate (leaf under intermediate): %v", err)
	}

	// AlternateChains must surface exactly the two publishable chains: native
	// (root1) and cross-signed (root2).
	chains, err := mgr.AlternateChains(inter.ID)
	if err != nil {
		t.Fatalf("AlternateChains: %v", err)
	}
	byIssuer := map[string]AlternateChain{}
	for _, c := range chains {
		byIssuer[c.IssuerCAID] = c
	}
	if _, ok := byIssuer[root1.ID]; !ok {
		t.Errorf("native chain via root1 (%s) missing from AlternateChains", root1.ID)
	}
	if _, ok := byIssuer[root2.ID]; !ok {
		t.Errorf("cross-signed chain via root2 (%s) missing from AlternateChains", root2.ID)
	}
	if native := byIssuer[root1.ID]; !native.Native {
		t.Error("chain via root1 should be marked native")
	}
	if cross := byIssuer[root2.ID]; cross.Native || cross.CrossSignID != res.CrossSign.ID {
		t.Errorf("chain via root2 should be the cross-sign %q, got native=%t id=%q",
			res.CrossSign.ID, cross.Native, cross.CrossSignID)
	}

	// --- Both chains must validate the leaf, in Go and in openssl.
	leafPEM := pki.EncodeCertificatePEM(leaf.Certificate.Raw)
	verifyChainBuilds(t, "native(root1)", leafPEM, []byte(byIssuer[root1.ID].PEM))
	verifyChainBuilds(t, "cross(root2)", leafPEM, []byte(byIssuer[root2.ID].PEM))
}

// verifyChainBuilds asserts a leaf validates against the supplied alternate chain
// bundle both with Go's x509 verifier and, when available, `openssl verify`.
func verifyChainBuilds(t *testing.T, name string, leafPEM, chainPEM []byte) {
	t.Helper()

	// Go verification: split the bundle into a roots pool (self-signed) and an
	// intermediates pool, then build the path.
	roots, inters, n := parseChainPools(t, chainPEM)
	if n < 2 {
		t.Fatalf("%s: chain bundle has %d certs, want >= 2 (subject + anchor)", name, n)
	}
	leaf := mustParse(t, string(leafPEM))
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters}); err != nil {
		t.Fatalf("%s: Go chain verification failed: %v", name, err)
	}

	// openssl verification (authoritative interop). Split the bundle into the
	// self-signed anchor (CAfile) and the rest (untrusted intermediates).
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Logf("%s: openssl not found; skipping interop verify", name)
		return
	}
	dir := t.TempDir()
	anchorPEM, untrustedPEM := splitAnchor(t, chainPEM)
	if len(anchorPEM) == 0 {
		t.Fatalf("%s: no self-signed anchor found in chain bundle", name)
	}
	caFile := filepath.Join(dir, "anchor.pem")
	leafFile := filepath.Join(dir, "leaf.pem")
	writeFile(t, caFile, anchorPEM)
	writeFile(t, leafFile, leafPEM)

	args := []string{"verify", "-CAfile", caFile}
	if len(untrustedPEM) > 0 {
		untrustedFile := filepath.Join(dir, "untrusted.pem")
		writeFile(t, untrustedFile, untrustedPEM)
		args = append(args, "-untrusted", untrustedFile)
	}
	args = append(args, leafFile)
	out := runCombined(t, openssl, args...)
	if !strings.Contains(out, ": OK") {
		t.Fatalf("%s: openssl verify did not report OK:\n%s", name, out)
	}
}

// splitAnchor divides a chain bundle into the self-signed trust anchor and the
// remaining (untrusted) intermediate certificates, each as PEM.
func splitAnchor(t *testing.T, chainPEM []byte) (anchor, untrusted []byte) {
	t.Helper()
	for _, cert := range parseCertsForTest(t, chainPEM) {
		block := pki.EncodeCertificatePEM(cert.Raw)
		if cert.CheckSignatureFrom(cert) == nil {
			anchor = append(anchor, block...)
		} else {
			untrusted = append(untrusted, block...)
		}
	}
	return anchor, untrusted
}

func parseCertsForTest(t *testing.T, pemBytes []byte) []*x509.Certificate {
	t.Helper()
	certs, err := pki.ParseCertificateChainPEM(pemBytes)
	if err != nil {
		t.Fatalf("parsing chain: %v", err)
	}
	return certs
}

func pemToDER(t *testing.T, pemBytes []byte) []byte {
	t.Helper()
	certs, err := pki.ParseCertificateChainPEM(pemBytes)
	if err != nil || len(certs) == 0 {
		t.Fatalf("decoding PEM cert: %v", err)
	}
	return certs[0].Raw
}
