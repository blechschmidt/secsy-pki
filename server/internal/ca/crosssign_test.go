//go:build sqlite

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// TestCrossSignValidation covers the argument-validation guards.
func TestCrossSignValidation(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "xsign-val")

	cases := map[string]CrossSignSpec{
		"no subject":        {IssuerCAID: root.ID},
		"two subjects":      {IssuerCAID: root.ID, SubjectCAID: root.ID, CSRPEM: []byte("x")},
		"no issuer":         {SubjectCAID: root.ID},
		"self cross-sign":   {IssuerCAID: root.ID, SubjectCAID: root.ID},
		"csr without valid": {IssuerCAID: root.ID, CSRPEM: makeCACSR(t, "csr.example")},
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := mgr.CrossSign(ctx, spec); err == nil {
				t.Fatalf("expected error for %q, got nil", name)
			}
		})
	}
}

// TestCrossSignExternalCertificate cross-signs an externally supplied self-signed
// root certificate, proving the bridge-import path: after cross-signing, a leaf
// the external root issued still chains through our cross-certificate to our own
// trust anchor.
func TestCrossSignExternalCertificate(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	ourRoot := newRoot(t, mgr, "xsign-ext")

	// An external CA we do not hold the key for, plus a leaf it signed.
	extKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	extRoot := selfSignedCA(t, extKey, "External Bridge Root")
	extLeaf := leafSignedBy(t, extRoot, extKey, "device.external.example")

	// Cross-sign the external root under our root.
	res, err := mgr.CrossSign(ctx, CrossSignSpec{
		IssuerCAID: ourRoot.ID,
		CertPEM:    pki.EncodeCertificatePEM(extRoot.Raw),
		Validity:   2 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("CrossSign external cert: %v", err)
	}
	if res.CrossSign.Source != models.CrossSignSourceCertificate {
		t.Errorf("source = %q, want %q", res.CrossSign.Source, models.CrossSignSourceCertificate)
	}
	if res.CrossSign.SubjectCAID != nil {
		t.Errorf("external subject should have no local subject CA link, got %v", res.CrossSign.SubjectCAID)
	}

	// The external leaf must chain through our cross-cert to our root.
	roots, inters, _ := parseChainPools(t, res.ChainPEM)
	if _, err := extLeaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters}); err != nil {
		t.Fatalf("external leaf failed to chain via our cross-sign: %v", err)
	}
}

// TestCrossSignRootTransition models a new root cross-signed by an old root: a
// leaf issued under the new root validates for relying parties that still trust
// only the old root, until they distribute the new anchor.
func TestCrossSignRootTransition(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	oldRoot := newRoot(t, mgr, "xsign-old")
	newRootCA, err := mgr.InitRoot(ctx, RootSpec{
		Label:      uniqueLabel(t, "xsign-new-root"),
		KeyType:    "ecdsa-p256",
		Subject:    PKIXName(models.CASubject{CommonName: "Transition New Root"}),
		Validity:   10 * 365 * 24 * time.Hour,
		MaxPathLen: intPtr(1),
	})
	if err != nil {
		t.Fatalf("InitRoot new root: %v", err)
	}

	// Old root cross-signs the new root's key.
	res, err := mgr.CrossSign(ctx, CrossSignSpec{
		IssuerCAID:  oldRoot.ID,
		SubjectCAID: newRootCA.ID,
	})
	if err != nil {
		t.Fatalf("CrossSign new root under old root: %v", err)
	}

	// A leaf issued under the new root.
	leaf, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    newRootCA.ID,
		CSRPEM:  makeCSR(t, "svc.transition.example", []string{"svc.transition.example"}),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate under new root: %v", err)
	}

	// Relying party trusting ONLY the old root: leaf + [new-root-cross-cert] must
	// build to the old root via the cross-sign's alternate chain.
	roots, inters, _ := parseChainPools(t, res.ChainPEM)
	if _, err := leaf.Certificate.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters}); err != nil {
		t.Fatalf("leaf under new root did not validate via old-root cross-sign: %v", err)
	}
}

// --- helpers ---------------------------------------------------------------

func makeCACSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func selfSignedCA(t *testing.T, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func leafSignedBy(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
