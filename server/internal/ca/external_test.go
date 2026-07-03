//go:build sqlite

package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// externalRoot is an in-test stand-in for the offline corporate root: a plain
// Go key + self-signed certificate that signs our CSRs "out-of-band".
type externalRoot struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newExternalRoot(t *testing.T, cn string) *externalRoot {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating external root key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"External Corp"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating external root: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing external root: %v", err)
	}
	return &externalRoot{key: key, cert: cert}
}

func (r *externalRoot) pem() []byte { return pki.EncodeCertificatePEM(r.cert.Raw) }

// extSignOpts controls how the in-test external root signs a CSR, so the
// import validations can be exercised one deviation at a time.
type extSignOpts struct {
	isCA      bool
	noBasic   bool // omit basic constraints entirely
	keyUsage  x509.KeyUsage
	notBefore time.Time
	notAfter  time.Time
	pathLen   *int
	publicKey crypto.PublicKey // override the CSR's key (mismatch case)
	subject   *pkix.Name       // override the CSR's subject (DN rewrite case)
}

// sign plays the external parent: it signs the CSR's key into a certificate
// under the external root, applying the requested deviations.
func (r *externalRoot) sign(t *testing.T, csrPEM []byte, o extSignOpts) []byte {
	t.Helper()
	csr, err := pki.ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatalf("parsing CSR: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		t.Fatal(err)
	}
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(5 * 365 * 24 * time.Hour)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		KeyUsage:              o.keyUsage,
		BasicConstraintsValid: !o.noBasic,
		IsCA:                  o.isCA,
	}
	if o.subject != nil {
		tmpl.Subject = *o.subject
	}
	if o.pathLen != nil {
		tmpl.MaxPathLen = *o.pathLen
		tmpl.MaxPathLenZero = *o.pathLen == 0
	}
	pub := csr.PublicKey
	if o.publicKey != nil {
		pub = o.publicKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, r.cert, pub, r.key)
	if err != nil {
		t.Fatalf("external root signing: %v", err)
	}
	return pki.EncodeCertificatePEM(der)
}

// goodOpts is the deviation-free external signature: CA=true, full CA key
// usage, currently valid, path length as requested.
func goodOpts(pathLen *int) extSignOpts {
	return extSignOpts{
		isCA:     true,
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		pathLen:  pathLen,
	}
}

// TestExternalCACSR verifies the "ca csr" half: the HSM-backed key is created,
// the CA is pending, and the emitted PKCS#10 CSR carries the CA attributes an
// external parent needs (basicConstraints cA=TRUE + pathlen, CA keyUsage).
func TestExternalCACSR(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	label := uniqueLabel(t, "ext-csr")

	res, err := mgr.GenerateExternalCACSR(ctx, ExternalCACSRSpec{
		Label:      label,
		KeyType:    "ecdsa-p256",
		Subject:    PKIXName(models.CASubject{CommonName: "Ext Sub CA", Organization: "Acme"}),
		MaxPathLen: intPtr(1),
	})
	if err != nil {
		t.Fatalf("GenerateExternalCACSR: %v", err)
	}
	if res.CA.Status != models.CAStatusPending {
		t.Errorf("status = %q, want %q", res.CA.Status, models.CAStatusPending)
	}
	if res.CA.Certificate != "" {
		t.Error("pending CA unexpectedly has a certificate")
	}
	if res.CA.CSR != string(res.CSRPEM) {
		t.Error("stored CSR differs from the returned one")
	}

	csr, err := pki.ParseCSRPEM(res.CSRPEM)
	if err != nil {
		t.Fatalf("emitted CSR does not parse/verify: %v", err)
	}
	if csr.Subject.CommonName != "Ext Sub CA" {
		t.Errorf("CSR CN = %q, want %q", csr.Subject.CommonName, "Ext Sub CA")
	}

	// The requested extensions ride in the CSR's extensionRequest attribute:
	// crypto/x509 surfaces them via csr.Extensions.
	var sawBC, sawKU bool
	for _, ext := range csr.Extensions {
		switch ext.Id.String() {
		case "2.5.29.19": // basicConstraints
			sawBC = true
			if !ext.Critical {
				t.Error("basicConstraints in CSR is not critical")
			}
		case "2.5.29.15": // keyUsage
			sawKU = true
			if !ext.Critical {
				t.Error("keyUsage in CSR is not critical")
			}
		}
	}
	if !sawBC || !sawKU {
		t.Fatalf("CSR extensionRequest missing CA attributes: basicConstraints=%t keyUsage=%t", sawBC, sawKU)
	}

	// Prove the attributes decode to what a parent honoring the CSR would issue:
	// sign a certificate from the CSR copying its extensions verbatim and let
	// crypto/x509 interpret them.
	ext := newExternalRoot(t, "Attr Check Root")
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: csr.Subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		ExtraExtensions: csr.Extensions}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ext.cert, csr.PublicKey, ext.key)
	if err != nil {
		t.Fatalf("signing verbatim-extension cert: %v", err)
	}
	verbatim, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !verbatim.IsCA || !verbatim.BasicConstraintsValid {
		t.Error("CSR basicConstraints does not decode to cA=TRUE")
	}
	if verbatim.MaxPathLen != 1 {
		t.Errorf("CSR pathlen = %d, want 1", verbatim.MaxPathLen)
	}
	want := x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	if verbatim.KeyUsage != want {
		t.Errorf("CSR keyUsage = %b, want %b", verbatim.KeyUsage, want)
	}

	// The stored CSR is re-emittable byte-for-byte.
	again, err := mgr.ExternalCACSR(res.CA.ID)
	if err != nil {
		t.Fatalf("ExternalCACSR: %v", err)
	}
	if string(again) != string(res.CSRPEM) {
		t.Error("re-emitted CSR differs from the original")
	}

	// A pending CA must not issue anything.
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    res.CA.ID,
		CSRPEM:  makeCSR(t, "leaf.example.com", []string{"leaf.example.com"}),
		Profile: "server",
	}); err == nil {
		t.Fatal("issuing from a pending CA unexpectedly succeeded")
	}

	// Label uniqueness and PQC rejection.
	if _, err := mgr.GenerateExternalCACSR(ctx, ExternalCACSRSpec{
		Label:   label,
		KeyType: "ecdsa-p256",
		Subject: PKIXName(models.CASubject{CommonName: "dup"}),
	}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("duplicate label: err = %v, want 'already exists'", err)
	}
	if _, err := mgr.GenerateExternalCACSR(ctx, ExternalCACSRSpec{
		Label:   uniqueLabel(t, "ext-pqc"),
		KeyType: "ml-dsa-65",
		Subject: PKIXName(models.CASubject{CommonName: "pqc"}),
	}); err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Errorf("pqc key type: err = %v, want 'not supported'", err)
	}
}

// TestImportExternalCACertValidation exercises the fail-closed import gate one
// deviation at a time: every certificate an external parent could hand back
// that would produce a broken or wrong CA must be rejected with a clear error.
func TestImportExternalCACertValidation(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	ext := newExternalRoot(t, "Validation Root")

	newPending := func(base string) *models.CA {
		t.Helper()
		res, err := mgr.GenerateExternalCACSR(ctx, ExternalCACSRSpec{
			Label:   uniqueLabel(t, base),
			KeyType: "ecdsa-p256",
			Subject: PKIXName(models.CASubject{CommonName: "Import Validation Sub"}),
		})
		if err != nil {
			t.Fatalf("GenerateExternalCACSR: %v", err)
		}
		return res.CA
	}
	importCert := func(caID string, certPEM []byte, chainPEM []byte) error {
		_, err := mgr.ImportExternalCACertificate(ctx, ImportExternalCACertSpec{
			CAID: caID, CertificatePEM: certPEM, ChainPEM: chainPEM,
		})
		return err
	}

	pend := newPending("val")
	csrPEM := []byte(pend.CSR)

	cases := []struct {
		name    string
		cert    []byte
		chain   []byte
		wantErr string
	}{
		{
			name: "key mismatch",
			cert: func() []byte {
				other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				o := goodOpts(nil)
				o.publicKey = &other.PublicKey
				return ext.sign(t, csrPEM, o)
			}(),
			wantErr: "does not match the CA key",
		},
		{
			name:    "not a CA",
			cert:    ext.sign(t, csrPEM, extSignOpts{isCA: false, keyUsage: x509.KeyUsageCertSign}),
			wantErr: "cA=FALSE",
		},
		{
			name:    "missing keyCertSign",
			cert:    ext.sign(t, csrPEM, extSignOpts{isCA: true, keyUsage: x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}),
			wantErr: "lacks keyCertSign",
		},
		{
			name: "expired",
			cert: func() []byte {
				o := goodOpts(nil)
				o.notBefore = time.Now().Add(-48 * time.Hour)
				o.notAfter = time.Now().Add(-time.Hour)
				return ext.sign(t, csrPEM, o)
			}(),
			wantErr: "expired",
		},
		{
			name: "not yet valid",
			cert: func() []byte {
				o := goodOpts(nil)
				o.notBefore = time.Now().Add(24 * time.Hour)
				o.notAfter = time.Now().Add(48 * time.Hour)
				return ext.sign(t, csrPEM, o)
			}(),
			wantErr: "not valid until",
		},
		{
			// Issuer DN == subject DN reads as self-signed even when the key is
			// ours: a mispasted root or a self-issued cert must not import.
			name: "self-signed (issuer equals subject)",
			cert: func() []byte {
				o := goodOpts(nil)
				o.subject = &ext.cert.Subject
				return ext.sign(t, csrPEM, o)
			}(),
			wantErr: "self-signed",
		},
		{
			// The root's own certificate carries the wrong key — the strongest
			// check (key match against the provider) fires first.
			name:    "foreign certificate (the root itself)",
			cert:    ext.pem(),
			wantErr: "does not match the CA key",
		},
		{
			name:    "chain does not verify",
			cert:    ext.sign(t, csrPEM, goodOpts(nil)),
			chain:   newExternalRoot(t, "Unrelated Root").pem(),
			wantErr: "does not verify against the supplied external chain",
		},
		{
			name:    "garbage PEM",
			cert:    []byte("not a certificate"),
			wantErr: "no CERTIFICATE block",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := importCert(pend.ID, tc.cert, tc.chain)
			if err == nil {
				t.Fatalf("import unexpectedly succeeded")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
			// The CA must remain pending after a rejected import.
			cur, gerr := mgr.db.GetCA(pend.ID)
			if gerr != nil || cur == nil || cur.Status != models.CAStatusPending || cur.Certificate != "" {
				t.Fatalf("CA mutated by rejected import: %+v (err %v)", cur, gerr)
			}
		})
	}

	t.Run("wrong target", func(t *testing.T) {
		// A locally created root is not awaiting an external certificate.
		root, err := mgr.InitRoot(ctx, RootSpec{
			Label:    uniqueLabel(t, "val-root"),
			KeyType:  "ecdsa-p256",
			Subject:  PKIXName(models.CASubject{CommonName: "Local Root"}),
			Validity: 24 * time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		err = importCert(root.ID, ext.sign(t, csrPEM, goodOpts(nil)), nil)
		if err == nil || !strings.Contains(err.Error(), "was not created for external signing") {
			t.Fatalf("import onto local root: err = %v", err)
		}
	})
}

// TestImportExternalCACertLifecycle covers the happy path and the warnings /
// replace semantics: import with chain, issue a leaf that verifies to the
// external root, then renew the certificate for the same key with Replace.
func TestImportExternalCACertLifecycle(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	ext := newExternalRoot(t, "Lifecycle Root")

	res, err := mgr.GenerateExternalCACSR(ctx, ExternalCACSRSpec{
		Label:      uniqueLabel(t, "life"),
		KeyType:    "ecdsa-p256",
		Subject:    PKIXName(models.CASubject{CommonName: "Lifecycle Sub CA"}),
		MaxPathLen: intPtr(0),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Sign without cRLSign and without pathlen to provoke both warnings.
	certPEM := ext.sign(t, []byte(res.CA.CSR), extSignOpts{
		isCA:     true,
		keyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	})
	imp, err := mgr.ImportExternalCACertificate(ctx, ImportExternalCACertSpec{
		CAID: res.CA.ID, CertificatePEM: certPEM, ChainPEM: ext.pem(),
	})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if imp.CA.Status != models.CAStatusActive {
		t.Errorf("status after import = %q, want active", imp.CA.Status)
	}
	if imp.CA.ExternalChain == "" {
		t.Error("external chain not stored")
	}
	wantWarn := map[string]bool{"cRLSign": false, "path-length": false}
	for _, w := range imp.Warnings {
		for k := range wantWarn {
			if strings.Contains(w, k) {
				wantWarn[k] = true
			}
		}
	}
	for k, seen := range wantWarn {
		if !seen {
			t.Errorf("expected a %s warning, got %q", k, imp.Warnings)
		}
	}

	// The served chain must include the imported certificate AND the external root.
	chainCerts, err := pki.ParseCertificateChainPEM(imp.ChainPEM)
	if err != nil {
		t.Fatal(err)
	}
	var haveOwn, haveRoot bool
	for _, c := range chainCerts {
		if c.Subject.CommonName == "Lifecycle Sub CA" {
			haveOwn = true
		}
		if c.Subject.CommonName == "Lifecycle Root" {
			haveRoot = true
		}
	}
	if !haveOwn || !haveRoot {
		t.Fatalf("served chain missing certs: own=%t externalRoot=%t", haveOwn, haveRoot)
	}

	// Issuance from the imported CA works and the leaf verifies to the external root.
	leaf, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    res.CA.ID,
		CSRPEM:  makeCSR(t, "app.example.com", []string{"app.example.com"}),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate from imported CA: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ext.cert)
	inters := x509.NewCertPool()
	inters.AddCert(mustParse(t, imp.CA.Certificate))
	if _, err := leaf.Certificate.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters}); err != nil {
		t.Fatalf("leaf does not verify to the external root: %v", err)
	}

	// Re-import without Replace must refuse; with Replace a renewed certificate
	// for the same key installs, and the previously imported chain is retained
	// when none is supplied.
	renewed := ext.sign(t, []byte(res.CA.CSR), goodOpts(nil))
	if _, err := mgr.ImportExternalCACertificate(ctx, ImportExternalCACertSpec{
		CAID: res.CA.ID, CertificatePEM: renewed,
	}); err == nil || !strings.Contains(err.Error(), "pass replace") {
		t.Fatalf("re-import without replace: err = %v", err)
	}
	ren, err := mgr.ImportExternalCACertificate(ctx, ImportExternalCACertSpec{
		CAID: res.CA.ID, CertificatePEM: renewed, Replace: true,
	})
	if err != nil {
		t.Fatalf("replace import: %v", err)
	}
	if ren.CA.ExternalChain == "" {
		t.Error("replace import dropped the previously imported external chain")
	}
	if ren.CA.Serial == imp.CA.Serial {
		t.Error("renewed certificate kept the old serial (same cert re-imported?)")
	}
	// The old leaf still verifies through the renewed CA cert (same key & DN).
	inters2 := x509.NewCertPool()
	inters2.AddCert(mustParse(t, ren.CA.Certificate))
	if _, err := leaf.Certificate.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters2}); err != nil {
		t.Fatalf("existing leaf broken by renewal: %v", err)
	}

	// A replace-import signed by a DIFFERENT external root, without a fresh
	// chain, must be refused: the retained chain no longer verifies the
	// certificate, and silently publishing it would break every relying party.
	newRoot := newExternalRoot(t, "Migrated Root")
	migrated := newRoot.sign(t, []byte(res.CA.CSR), goodOpts(nil))
	if _, err := mgr.ImportExternalCACertificate(ctx, ImportExternalCACertSpec{
		CAID: res.CA.ID, CertificatePEM: migrated, Replace: true,
	}); err == nil || !strings.Contains(err.Error(), "does not verify against the supplied external chain") {
		t.Fatalf("stale retained chain: err = %v, want chain verification failure", err)
	}
	// Supplying the new root's chain makes the same migration succeed, and the
	// stored chain switches to the new root.
	mig, err := mgr.ImportExternalCACertificate(ctx, ImportExternalCACertSpec{
		CAID: res.CA.ID, CertificatePEM: migrated, Replace: true, ChainPEM: newRoot.pem(),
	})
	if err != nil {
		t.Fatalf("migration with fresh chain: %v", err)
	}
	if !strings.Contains(mig.CA.ExternalChain, string(newRoot.pem())) {
		t.Error("stored external chain was not switched to the new root")
	}
}
