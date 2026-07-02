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
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pqc"
)

func pemCSR(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestIssuePQCProfile exercises the pure post-quantum path end to end on the
// software provider: an ML-DSA root and intermediate, a leaf issued from an
// ML-DSA CSR under the pqc-server profile, and full ML-DSA chain verification.
func TestIssuePQCProfile(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))

	root, err := mgr.InitRoot(ctx, RootSpec{
		Label:     uniqueLabel(t, "pqc-root"),
		KeyType:   pqc.KeyTypeMLDSA65,
		Algorithm: AlgPQC,
		Subject:   PKIXName(models.CASubject{CommonName: "PQC Root CA"}),
		Validity:  5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot(pqc): %v", err)
	}
	if root.KeyType != pqc.KeyTypeMLDSA65 {
		t.Errorf("root key type = %q", root.KeyType)
	}

	inter, err := mgr.IssueIntermediate(ctx, IntermediateSpec{
		ParentID:  root.ID,
		Label:     uniqueLabel(t, "pqc-inter"),
		KeyType:   pqc.KeyTypeMLDSA65,
		Algorithm: AlgPQC,
		Subject:   PKIXName(models.CASubject{CommonName: "PQC Intermediate CA"}),
		Validity:  2 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueIntermediate(pqc): %v", err)
	}

	// Subject key + CSR are ML-DSA.
	leafKey, err := pqc.GenerateKey(pqc.KeyTypeMLDSA44)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := pqc.CreatePQCCSR(&x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "device.pqc.example"},
		DNSNames: []string{"device.pqc.example"},
	}, leafKey)
	if err != nil {
		t.Fatalf("CreatePQCCSR: %v", err)
	}

	res, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        inter.ID,
		CSRPEM:      pemCSR(csrDER),
		Profile:     "pqc-server",
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("IssueCertificate(pqc): %v", err)
	}
	if res.CT == nil || res.CT.Enabled {
		t.Error("CT should be disabled for PQC issuance")
	}

	// The issued leaf must be ML-DSA signed and chain to the ML-DSA root.
	leafDER := res.Certificate.Raw
	interDER := mustParse(t, inter.Certificate).Raw
	rootDER := mustParse(t, root.Certificate).Raw
	if err := pqc.VerifyChain([][]byte{leafDER, interDER, rootDER}, pqc.VerifyOptions{}); err != nil {
		t.Fatalf("VerifyChain(pqc): %v", err)
	}

	// Sanity: the leaf's own key is ML-DSA and crypto/x509 leaves PublicKey nil.
	if res.Certificate.PublicKey != nil {
		t.Error("expected crypto/x509 to leave ML-DSA PublicKey nil")
	}
	pub, isPQC, err := pqc.PublicKeyFromCert(res.Certificate)
	if err != nil || !isPQC {
		t.Fatalf("PublicKeyFromCert: pqc=%v err=%v", isPQC, err)
	}
	if kt, _ := pqc.KeyTypeOf(pub); kt != pqc.KeyTypeMLDSA44 {
		t.Errorf("leaf key type = %q", kt)
	}
}

// TestIssueHybridProfile exercises the catalyst hybrid path: a hybrid root
// (classical primary + ML-DSA alternative), a leaf issued from a hybrid CSR under
// the hybrid-server profile, and verification of BOTH the classical chain (via
// the standard library) and the alternative ML-DSA chain.
func TestIssueHybridProfile(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))

	root, err := mgr.InitRoot(ctx, RootSpec{
		Label:      uniqueLabel(t, "hyb-root"),
		KeyType:    "ecdsa-p256",
		Algorithm:  AlgHybrid,
		AltKeyType: pqc.KeyTypeMLDSA65,
		Subject:    PKIXName(models.CASubject{CommonName: "Hybrid Root CA"}),
		Validity:   5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot(hybrid): %v", err)
	}
	rootCert := mustParse(t, root.Certificate)
	if !pqc.IsHybridCertificate(rootCert) {
		t.Fatal("root is not a hybrid certificate")
	}

	// Hybrid CSR: classical primary key + ML-DSA alternative key.
	classical, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	altKey, err := pqc.GenerateKey(pqc.KeyTypeMLDSA65)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := pqc.CreateHybridCSR(&x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "svc.hybrid.example"},
		DNSNames: []string{"svc.hybrid.example"},
	}, classical, altKey)
	if err != nil {
		t.Fatalf("CreateHybridCSR: %v", err)
	}

	res, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      pemCSR(csrDER),
		Profile:     "hybrid-server",
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("IssueCertificate(hybrid): %v", err)
	}

	leafDER := res.Certificate.Raw
	rootDER := rootCert.Raw

	// Both dimensions must verify.
	if err := pqc.VerifyHybridChain([][]byte{leafDER, rootDER}, pqc.VerifyOptions{}); err != nil {
		t.Fatalf("VerifyHybridChain: %v", err)
	}

	// Classical-only relying party: the standard library must accept the chain.
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	if _, err := res.Certificate.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("classical x509.Verify: %v", err)
	}

	// The leaf must carry a working alternative key.
	if _, _, err := pqc.AltPublicKey(res.Certificate); err != nil {
		t.Fatalf("leaf alt key: %v", err)
	}
}
