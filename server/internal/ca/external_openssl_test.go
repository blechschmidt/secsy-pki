//go:build sqlite

package ca

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// readFileT reads a file or fails the test.
func readFileT(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return data
}

// TestExternalCAOpenSSLRoot is the Task 69 acceptance test: openssl plays the
// offline corporate root, end to end.
//
//	openssl root (external, key never enters our store)
//	   │  signs our CSR out-of-band
//	   ▼
//	imported subordinate CA (key in our HSM)  ──issues──▶ leaf
//	   │
//	   └──issues──▶ child intermediate ──issues──▶ leaf   (+ key rotation)
//
// The subordinate key is generated inside the key provider (SoftHSM on the
// pkcs11 leg), its PKCS#10 CSR is signed by an openssl-managed external root,
// the certificate + root are imported, and every resulting chain — leaf under
// the imported CA, leaf under a child intermediate, and leaf under a rotated
// child key — must validate with `openssl verify` against the external root
// only. That proves the served chains genuinely reach the external trust
// anchor.
func TestExternalCAOpenSSLRoot(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found on PATH; it plays the external root in this test")
	}
	for name, mk := range map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	} {
		t.Run(name, func(t *testing.T) {
			runExternalCAOpenSSLRoot(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runExternalCAOpenSSLRoot(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()
	dir := t.TempDir()
	rootKey := filepath.Join(dir, "root.key")
	rootPEM := filepath.Join(dir, "root.pem")

	// --- The external root: created and held entirely by openssl. Its key never
	// touches our provider or database.
	run(t, "openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", rootKey)
	run(t, "openssl", "req", "-x509", "-new", "-key", rootKey, "-sha256", "-days", "3650",
		"-subj", "/O=Ext Corp/CN=Ext Corp Offline Root "+tag,
		"-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=critical,keyCertSign,cRLSign",
		"-out", rootPEM)

	// --- Half 1: HSM-backed key + CSR.
	subLabel := uniqueLabel(t, tag+"-extsub")
	res, err := mgr.GenerateExternalCACSR(ctx, ExternalCACSRSpec{
		Label:      subLabel,
		KeyType:    "ecdsa-p256",
		Subject:    PKIXName(models.CASubject{CommonName: "Ext Corp Issuing CA " + tag, Organization: "Ext Corp"}),
		MaxPathLen: intPtr(1),
	})
	if err != nil {
		t.Fatalf("GenerateExternalCACSR: %v", err)
	}
	csrFile := filepath.Join(dir, "sub.csr.pem")
	writeFile(t, csrFile, res.CSRPEM)

	// The CSR must be openssl-verifiable and carry the requested CA attributes.
	out := runCombined(t, "openssl", "req", "-in", csrFile, "-noout", "-verify", "-text")
	if !strings.Contains(out, "CA:TRUE") || !strings.Contains(out, "Certificate Sign") {
		t.Fatalf("openssl does not see the CA attributes in the CSR:\n%s", out)
	}

	// --- Out-of-band signing ceremony: the external root signs the CSR with
	// openssl, honoring the requested extensions.
	extCnf := filepath.Join(dir, "v3.cnf")
	writeFile(t, extCnf, []byte(
		"basicConstraints=critical,CA:TRUE,pathlen:1\n"+
			"keyUsage=critical,keyCertSign,cRLSign,digitalSignature\n"+
			"subjectKeyIdentifier=hash\n"+
			"authorityKeyIdentifier=keyid:always\n"))
	signedPEM := filepath.Join(dir, "sub.pem")
	run(t, "openssl", "x509", "-req", "-in", csrFile, "-CA", rootPEM, "-CAkey", rootKey,
		"-CAcreateserial", "-days", "1825", "-sha256", "-extfile", extCnf, "-out", signedPEM)

	// --- Half 2: validated import of the certificate + external root chain.
	signed := readFileT(t, signedPEM)
	rootBytes := readFileT(t, rootPEM)
	imp, err := mgr.ImportExternalCACertificate(ctx, ImportExternalCACertSpec{
		CAID:           res.CA.ID,
		CertificatePEM: signed,
		ChainPEM:       rootBytes,
	})
	if err != nil {
		t.Fatalf("ImportExternalCACertificate: %v", err)
	}
	if len(imp.Warnings) != 0 {
		t.Errorf("clean external signature produced warnings: %q", imp.Warnings)
	}
	if imp.CA.Status != models.CAStatusActive {
		t.Fatalf("imported CA status = %q, want active", imp.CA.Status)
	}
	if imp.CA.MaxPathLen == nil || *imp.CA.MaxPathLen != 1 {
		t.Errorf("imported pathlen = %v, want 1", imp.CA.MaxPathLen)
	}

	// The served chain (what /api/ca/{id}/chain returns) must reach the external root.
	assertChainServesExternalRoot(t, mgr, imp.CA.ID, "Ext Corp Offline Root "+tag)

	// --- Issuance from the imported CA, verified by openssl against ONLY the
	// external root as trust anchor.
	leaf1, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    res.CA.ID,
		CSRPEM:  makeCSR(t, "one."+tag+".example.com", []string{"one." + tag + ".example.com"}),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate under imported CA: %v", err)
	}
	opensslVerifyLeaf(t, mgr, dir, "leaf1", rootPEM, imp.CA.ID, leaf1.Certificate.Raw)

	// --- A child intermediate under the imported CA (the local hierarchy keeps
	// growing normally below the external anchor)...
	child, err := mgr.IssueIntermediate(ctx, IntermediateSpec{
		ParentID:   res.CA.ID,
		Label:      uniqueLabel(t, tag + "-extchild"),
		KeyType:    "ecdsa-p256",
		Subject:    PKIXName(models.CASubject{CommonName: "Ext Corp Issuing CA L2 " + tag}),
		Validity:   365 * 24 * time.Hour,
		MaxPathLen: intPtr(0),
	})
	if err != nil {
		t.Fatalf("IssueIntermediate under imported CA: %v", err)
	}
	leaf2, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    child.ID,
		CSRPEM:  makeCSR(t, "two."+tag+".example.com", []string{"two." + tag + ".example.com"}),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate under child intermediate: %v", err)
	}
	assertChainServesExternalRoot(t, mgr, child.ID, "Ext Corp Offline Root "+tag)
	opensslVerifyLeaf(t, mgr, dir, "leaf2", rootPEM, child.ID, leaf2.Certificate.Raw)

	// --- ...and rotation of that child works normally: the imported CA signs
	// the successor key on the HSM, and leaves signed by the rotated key still
	// validate to the external root through the overlap bundle.
	rot, err := mgr.RotateIntermediate(ctx, RotateSpec{CAID: child.ID, RequestedBy: "test"})
	if err != nil {
		t.Fatalf("RotateIntermediate under imported CA: %v", err)
	}
	leaf3, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    rot.NewCA.ID,
		CSRPEM:  makeCSR(t, "three."+tag+".example.com", []string{"three." + tag + ".example.com"}),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate under rotated child: %v", err)
	}
	opensslVerifyLeaf(t, mgr, dir, "leaf3", rootPEM, rot.NewCA.ID, leaf3.Certificate.Raw)

	// Rotating the externally-signed CA itself must refuse with out-of-band
	// guidance: its parent key is not ours to sign with.
	if _, err := mgr.RotateIntermediate(ctx, RotateSpec{CAID: res.CA.ID}); err == nil ||
		!strings.Contains(err.Error(), "externally signed") {
		t.Errorf("rotating the imported CA: err = %v, want 'externally signed' guidance", err)
	}
}

// assertChainServesExternalRoot asserts the CombinedChainPEM bundle (the body
// of /api/ca/{id}/chain) contains a certificate with the external root's CN.
func assertChainServesExternalRoot(t *testing.T, mgr *Manager, caID, rootCN string) {
	t.Helper()
	chain, err := mgr.CombinedChainPEM(caID)
	if err != nil {
		t.Fatalf("CombinedChainPEM(%s): %v", caID, err)
	}
	certs, err := pki.ParseCertificateChainPEM(chain)
	if err != nil {
		t.Fatalf("parsing served chain: %v", err)
	}
	for _, c := range certs {
		if c.Subject.CommonName == rootCN {
			return
		}
	}
	t.Fatalf("served chain for %s does not include the external root %q (%d certs)", caID, rootCN, len(certs))
}

// opensslVerifyLeaf writes the leaf and the CA's served chain bundle to disk
// and runs `openssl verify` with the external root as the ONLY trust anchor.
func opensslVerifyLeaf(t *testing.T, mgr *Manager, dir, name, rootPEM, caID string, leafDER []byte) {
	t.Helper()
	chain, err := mgr.CombinedChainPEM(caID)
	if err != nil {
		t.Fatalf("CombinedChainPEM: %v", err)
	}
	leafFile := filepath.Join(dir, name+".pem")
	chainFile := filepath.Join(dir, name+"-chain.pem")
	writeFile(t, leafFile, pki.EncodeCertificatePEM(leafDER))
	writeFile(t, chainFile, chain)
	out := runCombined(t, "openssl", "verify", "-CAfile", rootPEM, "-untrusted", chainFile, leafFile)
	if !strings.Contains(out, ": OK") {
		t.Fatalf("%s: openssl verify against the external root did not report OK:\n%s", name, out)
	}
}
