//go:build sqlite

package e2e

// SPIFFE X.509-SVID issuance and trust-bundle test, exercised end-to-end against
// a real, HSM-backed CA (SoftHSM in CI). It proves the SVID structure required by
// the SPIFFE X.509-SVID spec (single spiffe:// URI SAN as the sole identity, no
// CN reliance, CA:false, digitalSignature key usage), that the SVID chains to
// the HSM-backed root, and that the SPIFFE trust bundle (JWKS) advertises the
// CA's X.509 authorities.

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/spiffe"
)

func TestSPIFFESVIDHSM(t *testing.T) {
	ctx := context.Background()
	provider := hsmProvider(t)
	mgr := newManager(t, provider)

	const keyType = keyprovider.KeyTypeECDSAP256

	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    uniqueLabel(t, "svid-root"),
		KeyType:  keyType,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Secsy SVID Root CA", Organization: "Secsy"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	rootCert := mustParse(t, root.Certificate)

	inter, err := mgr.IssueIntermediate(ctx, ca.IntermediateSpec{
		ParentID:   root.ID,
		Label:      uniqueLabel(t, "svid-inter"),
		KeyType:    keyType,
		Subject:    ca.PKIXName(models.CASubject{CommonName: "Secsy SVID Intermediate CA"}),
		Validity:   5 * 365 * 24 * time.Hour,
		MaxPathLen: intPtr(0),
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}
	interCert := mustParse(t, inter.Certificate)

	const spiffeID = "spiffe://prod.example.org/ns/prod/sa/web"

	// The workload generates its own key; only its CSR (public key) reaches the CA.
	// The CSR deliberately carries a CN and a DNS SAN that must NOT leak into the
	// SVID — the SVID identity is the spiffe:// URI alone.
	csr := makeCSR(t, "should-be-ignored", []string{"should-not-appear.example.com"})

	svid, err := mgr.IssueSVID(ctx, ca.SVIDSpec{
		CAID:     inter.ID,
		CSRPEM:   csr,
		SPIFFEID: spiffeID,
	})
	if err != nil {
		t.Fatalf("IssueSVID: %v", err)
	}
	cert := svid.Certificate

	// --- SPIFFE X.509-SVID structural requirements. ---
	if svid.Profile != ca.SVIDProfileName {
		t.Errorf("SVID profile = %q, want %q", svid.Profile, ca.SVIDProfileName)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != spiffeID {
		t.Fatalf("SVID URIs = %v, want exactly [%s]", cert.URIs, spiffeID)
	}
	if len(cert.DNSNames) != 0 {
		t.Errorf("SVID must have no DNS SANs by default, got %v", cert.DNSNames)
	}
	if len(cert.IPAddresses) != 0 {
		t.Errorf("SVID must have no IP SANs by default, got %v", cert.IPAddresses)
	}
	if cert.Subject.CommonName != "" {
		t.Errorf("SVID must not rely on a CN, got %q", cert.Subject.CommonName)
	}
	if cert.IsCA {
		t.Error("SVID must be CA:false")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("SVID must carry the digitalSignature key usage")
	}
	if cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		t.Error("SVID must not carry CA key usages (certSign/crlSign)")
	}
	if !hasExtKeyUsage(cert, x509.ExtKeyUsageClientAuth) || !hasExtKeyUsage(cert, x509.ExtKeyUsageServerAuth) {
		t.Error("SVID should carry serverAuth+clientAuth EKUs for mutual TLS")
	}
	// Short-lived: the built-in profile defaults to a 1h validity.
	if life := cert.NotAfter.Sub(cert.NotBefore); life > 25*time.Hour {
		t.Errorf("SVID lifetime %s is not short-lived", life)
	}

	// --- The SVID chains to the HSM-backed root. ---
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	inters := x509.NewCertPool()
	inters.AddCert(interCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("SVID chain does not verify to the root: %v", err)
	}

	// --- Trust bundle (JWKS) advertises the CA authorities. ---
	authorities, err := mgr.TrustBundleAuthorities(inter.ID)
	if err != nil {
		t.Fatalf("TrustBundleAuthorities: %v", err)
	}
	bundleJSON, err := spiffe.BuildBundle(authorities, 60*time.Second, 1)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	parsed, err := spiffe.ParseBundle(bundleJSON)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}
	// The bundle must contain the intermediate and the root, and every entry must
	// be a CA that can (transitively) anchor the SVID.
	var haveRoot, haveInter bool
	for _, c := range parsed {
		if c.Equal(rootCert) {
			haveRoot = true
		}
		if c.Equal(interCert) {
			haveInter = true
		}
		if !c.IsCA {
			t.Errorf("trust bundle contains a non-CA authority %q", c.Subject)
		}
	}
	if !haveRoot {
		t.Error("trust bundle is missing the root CA")
	}
	if !haveInter {
		t.Error("trust bundle is missing the intermediate CA")
	}

	// The SVID must verify against a pool built solely from the bundle's anchors,
	// which is exactly what a SPIRE-style consumer does.
	bundlePool := x509.NewCertPool()
	for _, c := range parsed {
		bundlePool.AddCert(c)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         bundlePool,
		Intermediates: bundlePool,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("SVID does not verify against the trust bundle: %v", err)
	}
}

// TestSPIFFEJWTSVIDHSM exercises the JWT-SVID path end-to-end against an
// HSM-backed CA: the CA's HSM key signs a compact JWS, the JWKS trust bundle
// publishes the same key as a jwt-svid entry, and the server-side validator
// verifies the signature and claims. Signing on the HSM through go-jose's
// opaque-signer bridge is the part that can only be proven with a real token —
// the ECDSA raw-R||S encoding a JWS requires must round-trip through the device.
func TestSPIFFEJWTSVIDHSM(t *testing.T) {
	ctx := context.Background()
	provider := hsmProvider(t)
	mgr := newManager(t, provider)

	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    uniqueLabel(t, "jwtsvid-root"),
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Secsy JWT-SVID Root CA", Organization: "Secsy"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	inter, err := mgr.IssueIntermediate(ctx, ca.IntermediateSpec{
		ParentID:   root.ID,
		Label:      uniqueLabel(t, "jwtsvid-inter"),
		KeyType:    keyprovider.KeyTypeECDSAP256,
		Subject:    ca.PKIXName(models.CASubject{CommonName: "Secsy JWT-SVID Intermediate CA"}),
		Validity:   5 * 365 * 24 * time.Hour,
		MaxPathLen: intPtr(0),
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}

	const spiffeID = "spiffe://prod.example.org/ns/prod/sa/api"
	const audience = "spiffe://prod.example.org/ns/prod/sa/db"

	result, err := mgr.IssueJWTSVID(ctx, ca.JWTSVIDSpec{
		CAID:        inter.ID,
		SPIFFEID:    spiffeID,
		Audience:    []string{audience},
		TTL:         30 * time.Minute,
		RequestedBy: "e2e",
	})
	if err != nil {
		t.Fatalf("IssueJWTSVID: %v", err)
	}
	if result.SPIFFEID != spiffeID {
		t.Errorf("token sub = %q, want %q", result.SPIFFEID, spiffeID)
	}
	if result.Algorithm != "ES256" {
		t.Errorf("token alg = %q, want ES256 (P-256 CA key)", result.Algorithm)
	}
	if result.Expiry.Sub(result.IssuedAt) > 31*time.Minute {
		t.Errorf("token lifetime %s exceeds the requested TTL", result.Expiry.Sub(result.IssuedAt))
	}

	// Build the JWKS trust bundle the relying party would fetch.
	authorities, err := mgr.TrustBundleAuthorities(inter.ID)
	if err != nil {
		t.Fatalf("TrustBundleAuthorities: %v", err)
	}
	bundle, err := spiffe.BuildBundle(authorities, 60*time.Second, 1)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	// The token's kid must resolve to a jwt-svid key in the bundle (the active
	// issuer, the intermediate, whose HSM key signed the token).
	jwtKeys, err := spiffe.ParseJWTBundleKeys(bundle)
	if err != nil {
		t.Fatalf("ParseJWTBundleKeys: %v", err)
	}
	if _, ok := jwtKeys[result.KeyID]; !ok {
		t.Fatalf("bundle has no jwt-svid key for the token kid %q", result.KeyID)
	}

	// --- Happy path: the HSM-signed token validates against the bundle. ---
	verified, err := spiffe.ValidateJWTSVID(result.Token, bundle, spiffe.JWTValidationOptions{
		Audience:     audience,
		TrustDomains: []string{"prod.example.org"},
	})
	if err != nil {
		t.Fatalf("ValidateJWTSVID (HSM-signed): %v", err)
	}
	if verified.SPIFFEID != spiffeID || verified.TrustDomain != "prod.example.org" {
		t.Errorf("verified identity = %q/%q, want %q/prod.example.org", verified.SPIFFEID, verified.TrustDomain, spiffeID)
	}

	// --- Rejections: wrong audience, and a foreign trust domain. ---
	if _, err := spiffe.ValidateJWTSVID(result.Token, bundle, spiffe.JWTValidationOptions{
		Audience:     "spiffe://prod.example.org/ns/prod/sa/other",
		TrustDomains: []string{"prod.example.org"},
	}); err == nil {
		t.Error("validation should reject the wrong audience")
	}
	if _, err := spiffe.ValidateJWTSVID(result.Token, bundle, spiffe.JWTValidationOptions{
		Audience:     audience,
		TrustDomains: []string{"other.example.net"},
	}); err == nil {
		t.Error("validation should reject a trust domain outside the allowlist")
	}

	// --- Rejection: an expired token (past exp, HSM-signed). ---
	expired, err := mgr.IssueJWTSVID(ctx, ca.JWTSVIDSpec{
		CAID: inter.ID, SPIFFEID: spiffeID, Audience: []string{audience}, TTL: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("IssueJWTSVID (expired): %v", err)
	}
	if _, err := spiffe.ValidateJWTSVID(expired.Token, bundle, spiffe.JWTValidationOptions{
		Audience:     audience,
		TrustDomains: []string{"prod.example.org"},
		Now:          time.Now().Add(time.Hour), // well past the (nanosecond) exp, beyond leeway
	}); err == nil {
		t.Error("validation should reject an expired token")
	}
}
