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
