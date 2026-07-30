//go:build sqlite

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// TestCollectRevocation exercises the CAdES-LT revocation gathering: for a
// root -> intermediate -> leaf chain it must return an OCSP response for the
// recorded leaf plus one CRL per issuing CA, skip an OCSP for the intermediate
// (an unknown serial to its issuer), and skip the self-signed root entirely.
func TestCollectRevocation(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()

	root, inter := newRootAndIntermediate(t, mgr, "ltv", 365*24*time.Hour)
	rootCert := mustParse(t, root.Certificate)
	interCert := mustParse(t, inter.Certificate)

	leafRes := issueLeaf(t, mgr, inter.ID, "ltv-leaf.example.com")
	leaf := leafRes.Certificate
	chain := []*x509.Certificate{leaf, interCert, rootCert}

	ocsps, crls, err := mgr.CollectRevocation(ctx, chain)
	if err != nil {
		t.Fatalf("CollectRevocation: %v", err)
	}
	// One OCSP for the leaf (the intermediate is not a recorded leaf under the
	// root, so an OCSP for it would be "unknown" and is skipped).
	if len(ocsps) != 1 {
		t.Fatalf("collected %d OCSP responses, want 1 (leaf only)", len(ocsps))
	}
	// One CRL per issuing CA: the intermediate (issuer of the leaf) and the root
	// (issuer of the intermediate). The self-signed root itself is skipped.
	if len(crls) != 2 {
		t.Fatalf("collected %d CRLs, want 2 (intermediate + root)", len(crls))
	}

	// The leaf OCSP must be a valid "good" response for the leaf serial, signed
	// by the intermediate.
	resp, err := ocsp.ParseResponse(ocsps[0], interCert)
	if err != nil {
		t.Fatalf("ParseResponse (leaf): %v", err)
	}
	if resp.Status != ocsp.Good {
		t.Errorf("leaf OCSP status = %d, want Good", resp.Status)
	}
	if resp.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Errorf("leaf OCSP serial mismatch")
	}

	// Both CRLs must be valid CertificateLists issued by a chain CA, and neither
	// may list the (still-valid) leaf serial.
	issuers := map[string]*x509.Certificate{
		string(interCert.RawSubject): interCert,
		string(rootCert.RawSubject):  rootCert,
	}
	seenIssuers := map[string]bool{}
	for _, der := range crls {
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			t.Fatalf("ParseRevocationList: %v", err)
		}
		issuer := issuers[string(crl.RawIssuer)]
		if issuer == nil {
			t.Fatalf("CRL issuer %q is not a chain CA", crl.Issuer)
		}
		seenIssuers[string(crl.RawIssuer)] = true
		if err := crl.CheckSignatureFrom(issuer); err != nil {
			t.Fatalf("CRL signature does not verify against its issuer: %v", err)
		}
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				t.Fatal("CRL lists the still-valid leaf serial")
			}
		}
	}
	if len(seenIssuers) != 2 {
		t.Fatalf("CRLs cover %d distinct issuers, want 2", len(seenIssuers))
	}

	// After revoking the leaf, its freshly generated OCSP response must flip to
	// revoked (the OCSP path is not cached, unlike the base CRL).
	if _, err := mgr.RevokeCertificate(ctx, inter.ID, leaf.SerialNumber.String(), "keyCompromise"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	ocsps2, _, err := mgr.CollectRevocation(ctx, chain)
	if err != nil {
		t.Fatalf("CollectRevocation after revoke: %v", err)
	}
	if len(ocsps2) != 1 {
		t.Fatalf("collected %d OCSP responses after revoke, want 1", len(ocsps2))
	}
	resp2, err := ocsp.ParseResponse(ocsps2[0], interCert)
	if err != nil {
		t.Fatalf("ParseResponse after revoke: %v", err)
	}
	if resp2.Status != ocsp.Revoked {
		t.Errorf("leaf OCSP status after revoke = %d, want Revoked", resp2.Status)
	}
}

// TestCollectRevocationUnknownIssuer confirms best-effort behavior: a chain whose
// issuer is not a CA of this deployment yields no revocation material rather than
// an error.
func TestCollectRevocationUnknownIssuer(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()

	// A self-signed certificate unrelated to any CA in the store.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "foreign-root"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	foreignCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	ocsps, crls, err := mgr.CollectRevocation(ctx, []*x509.Certificate{foreignCert})
	if err != nil {
		t.Fatalf("CollectRevocation: %v", err)
	}
	if len(ocsps) != 0 || len(crls) != 0 {
		t.Fatalf("expected no material for an unknown issuer, got %d ocsps / %d crls", len(ocsps), len(crls))
	}
}
