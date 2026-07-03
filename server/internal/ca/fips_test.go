//go:build sqlite

package ca

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// withFIPSPolicy enables the fail-closed FIPS policy for the test, restoring
// the previous state afterwards. Not safe with t.Parallel.
func withFIPSPolicy(t *testing.T) {
	t.Helper()
	prev := fips.PolicyEnforced()
	fips.SetPolicy(true)
	t.Cleanup(func() { fips.SetPolicy(prev) })
}

// csrFromKey builds a PEM CSR for the supplied signer key.
func csrFromKey(t *testing.T, key any, cn string) []byte {
	t.Helper()
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// TestFIPSIssuanceGates is the Task 65 policy acceptance test on the issuance
// path: with security.fips enforced, approved algorithms keep working while
// Ed25519 leaves, small RSA leaves, PQC profiles, and non-approved CA key
// generation are all rejected fail-closed, before any signature is made.
func TestFIPSIssuanceGates(t *testing.T) {
	withFIPSPolicy(t)
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))

	// Positive control: an approved hierarchy works under the policy.
	root, err := mgr.InitRoot(ctx, RootSpec{
		Label:    uniqueLabel(t, "fips-root"),
		KeyType:  "ecdsa-p256",
		Subject:  PKIXName(models.CASubject{CommonName: "FIPS Test Root"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot (approved key) under FIPS policy: %v", err)
	}
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    root.ID,
		CSRPEM:  makeCSR(t, "ok.example.com", []string{"ok.example.com"}),
		Profile: "server",
	}); err != nil {
		t.Fatalf("issuing approved ECDSA leaf under FIPS policy: %v", err)
	}

	// Ed25519 subject key: rejected at the pki issuance gate.
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    root.ID,
		CSRPEM:  csrFromKey(t, edPriv, "ed.example.com"),
		Profile: "server",
	})
	if !errors.Is(err, fips.ErrNotApproved) {
		t.Errorf("Ed25519 leaf: want ErrNotApproved, got %v", err)
	}

	// RSA-1024 subject key: rejected at the pki issuance gate.
	smallRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Skipf("cannot generate RSA-1024 probe key in this mode: %v", err)
	}
	_, err = mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    root.ID,
		CSRPEM:  csrFromKey(t, smallRSA, "small.example.com"),
		Profile: "server",
	})
	if !errors.Is(err, fips.ErrNotApproved) {
		t.Errorf("RSA-1024 leaf: want ErrNotApproved, got %v", err)
	}

	// PQC / hybrid profiles: rejected before their dedicated signing paths run.
	for _, profile := range []string{"pqc-server", "hybrid-server"} {
		_, err = mgr.IssueCertificate(ctx, IssueSpec{
			CAID:    root.ID,
			CSRPEM:  makeCSR(t, "pq.example.com", []string{"pq.example.com"}),
			Profile: profile,
		})
		if !errors.Is(err, fips.ErrNotApproved) {
			t.Errorf("profile %s: want ErrNotApproved, got %v", profile, err)
		}
	}

	// Non-approved CA key generation: rejected at the key provider, so the key
	// never comes into existence.
	_, err = mgr.InitRoot(ctx, RootSpec{
		Label:    uniqueLabel(t, "fips-ed-root"),
		KeyType:  "ed25519",
		Subject:  PKIXName(models.CASubject{CommonName: "Ed25519 Root"}),
		Validity: 365 * 24 * time.Hour,
	})
	if !errors.Is(err, fips.ErrNotApproved) {
		t.Errorf("ed25519 root key: want ErrNotApproved, got %v", err)
	}
}

// TestFIPSCustomProfileGate verifies that installing a PQC/hybrid custom
// profile fails at startup under the policy.
func TestFIPSCustomProfileGate(t *testing.T) {
	withFIPSPolicy(t)
	t.Cleanup(func() {
		if err := SetCustomProfiles(nil); err != nil {
			t.Fatalf("resetting custom profiles: %v", err)
		}
	})

	err := SetCustomProfiles([]Profile{{
		Name:      "pq-custom",
		KeyUsages: []string{"digitalSignature"},
		Algorithm: AlgPQC,
	}})
	if !errors.Is(err, fips.ErrNotApproved) {
		t.Errorf("custom PQC profile: want ErrNotApproved, got %v", err)
	}

	// A classical custom profile still installs fine under the policy.
	if err := SetCustomProfiles([]Profile{{
		Name:      "fips-ok",
		KeyUsages: []string{"digitalSignature"},
	}}); err != nil {
		t.Errorf("classical custom profile rejected under policy: %v", err)
	}
}
