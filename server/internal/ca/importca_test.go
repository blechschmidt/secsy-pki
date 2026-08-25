//go:build sqlite

package ca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Task 194: adopting an existing CA. The scenario throughout is the real one —
// a CA that was created in software long ago, whose certificate is already
// distributed, being moved under this PKI without re-keying.

// legacyCA is a CA that exists before this PKI does: a plain Go key and its
// certificate, exactly what an operator would hand us.
type legacyCA struct {
	key  crypto.Signer
	cert *x509.Certificate
}

func newLegacyRoot(t *testing.T, cn string, mutate func(*x509.Certificate)) *legacyCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating legacy CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Legacy Corp"}},
		NotBefore:             time.Now().Add(-365 * 24 * time.Hour),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if mutate != nil {
		mutate(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("creating legacy CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing legacy CA certificate: %v", err)
	}
	return &legacyCA{key: key, cert: cert}
}

// issueSub plays the legacy root issuing a subordinate CA, so the adoption of a
// whole hierarchy can be exercised.
func (l *legacyCA) issueSub(t *testing.T, cn string) *legacyCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-30 * 24 * time.Hour),
		NotAfter:              time.Now().Add(2 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, l.cert, key.Public(), l.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &legacyCA{key: key, cert: cert}
}

func (l *legacyCA) pem() []byte { return pki.EncodeCertificatePEM(l.cert.Raw) }

// TestImportCAAdoptsRootAndKeepsIssuing is the headline case: after adoption the
// CA issues, and what it issues still chains to the certificate the world
// already trusts. That is the entire point of importing rather than re-keying.
func TestImportCAAdoptsRootAndKeepsIssuing(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			mgr := newTestManager(t, mk(t))
			legacy := newLegacyRoot(t, "Legacy Root CA", nil)
			label := uniqueLabel(t, name+"-adopted")

			res, err := mgr.ImportCA(ctx, ImportCASpec{
				Label:          label,
				PrivateKey:     legacy.key,
				CertificatePEM: legacy.pem(),
			})
			if err != nil {
				t.Fatalf("ImportCA: %v", err)
			}
			if !res.SelfSigned {
				t.Error("SelfSigned = false for a self-signed root")
			}
			if !res.KeyImported {
				t.Error("KeyImported = false although key material was supplied")
			}
			if res.CA.Status != models.CAStatusActive {
				t.Errorf("status = %q, want %q", res.CA.Status, models.CAStatusActive)
			}
			if res.CA.Serial != legacy.cert.SerialNumber.String() {
				t.Errorf("serial = %q, want the certificate's own serial %q", res.CA.Serial, legacy.cert.SerialNumber)
			}
			if res.KeyFingerprint == "" {
				t.Error("no key fingerprint recorded")
			}

			// The adopted CA must issue, on the provider, under the legacy key.
			inter, err := mgr.IssueIntermediate(ctx, IntermediateSpec{
				ParentID: res.CA.ID,
				Label:    uniqueLabel(t, name+"-sub"),
				KeyType:  keyprovider.KeyTypeECDSAP256,
				Subject:  pkix.Name{CommonName: "New Sub CA"},
				Validity: 365 * 24 * time.Hour,
			})
			if err != nil {
				t.Fatalf("issuing under the adopted CA: %v", err)
			}
			interCert, err := pki.ParseCertificatePEM([]byte(inter.Certificate))
			if err != nil {
				t.Fatal(err)
			}
			roots := x509.NewCertPool()
			roots.AddCert(legacy.cert)
			if _, err := interCert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
				t.Fatalf("a certificate issued after adoption does not chain to the legacy root: %v", err)
			}
		})
	}
}

// TestImportCAAdoptsHierarchy adopts a legacy root and then its subordinate,
// and expects the subordinate to be linked to the parent already in the PKI
// rather than carrying a pasted chain.
func TestImportCAAdoptsHierarchy(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newLegacyRoot(t, "Legacy Root", nil)
	sub := root.issueSub(t, "Legacy Issuing CA")

	rootRes, err := mgr.ImportCA(ctx, ImportCASpec{
		Label: "legacy-root", PrivateKey: root.key, CertificatePEM: root.pem(),
	})
	if err != nil {
		t.Fatalf("adopting the root: %v", err)
	}
	subRes, err := mgr.ImportCA(ctx, ImportCASpec{
		Label: "legacy-sub", PrivateKey: sub.key, CertificatePEM: sub.pem(),
	})
	if err != nil {
		t.Fatalf("adopting the subordinate: %v", err)
	}
	if subRes.SelfSigned {
		t.Error("SelfSigned = true for a subordinate")
	}
	if subRes.CA.ParentID == nil || *subRes.CA.ParentID != rootRes.CA.ID {
		t.Fatalf("parent_id = %v, want the adopted root %q", subRes.CA.ParentID, rootRes.CA.ID)
	}
	if subRes.CA.ExternalChain != "" {
		t.Error("a subordinate linked to an in-PKI parent should carry no external chain")
	}
	// The served chain must reach the root, which is what relying parties need.
	if !strings.Contains(string(subRes.ChainPEM), string(root.pem())) {
		t.Error("the served chain does not include the adopted root")
	}
}

// TestImportCAExternalParent covers the subordinate whose parent stays outside
// this PKI: the chain is recorded as external chain material instead.
func TestImportCAExternalParent(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newLegacyRoot(t, "Offline Root", nil)
	sub := root.issueSub(t, "Sub Of Offline Root")

	res, err := mgr.ImportCA(ctx, ImportCASpec{
		Label:          "external-sub",
		PrivateKey:     sub.key,
		CertificatePEM: sub.pem(),
		ChainPEM:       root.pem(),
	})
	if err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
	if res.CA.ParentID != nil {
		t.Error("parent_id should be nil when the parent is not in this PKI")
	}
	if res.CA.ExternalChain == "" {
		t.Fatal("the external chain was not recorded")
	}
	if !strings.Contains(res.CA.ExternalChain, string(root.pem())) {
		t.Error("the external chain does not contain the offline root")
	}
}

// TestImportCAAdoptsKeyAlreadyInProvider covers the two-step flow: the key was
// put into the provider out of band (or by `key import`), and only the
// certificate is being adopted now.
func TestImportCAAdoptsKeyAlreadyInProvider(t *testing.T) {
	ctx := context.Background()
	provider := softwareProvider(t)
	mgr := newTestManager(t, provider)
	legacy := newLegacyRoot(t, "Preplaced Key CA", nil)

	if _, err := keyprovider.ImportKey(ctx, provider, keyprovider.ImportSpec{
		Label: "preplaced", PrivateKey: legacy.key,
	}); err != nil {
		t.Fatalf("staging the key: %v", err)
	}
	res, err := mgr.ImportCA(ctx, ImportCASpec{
		Label:            "adopted-preplaced",
		ExistingKeyLabel: "preplaced",
		CertificatePEM:   legacy.pem(),
	})
	if err != nil {
		t.Fatalf("ImportCA: %v", err)
	}
	if res.KeyImported {
		t.Error("KeyImported = true although the key was already in the provider")
	}
	// The CA record must point at the pre-existing key, not at a new one under
	// the CA's own label.
	if !strings.Contains(res.CA.PKCS11URI, "preplaced") {
		t.Errorf("pkcs11_uri = %q, want it to address the pre-existing key", res.CA.PKCS11URI)
	}
}

// TestImportCARejects covers every fail-closed path. Each of these, if allowed,
// produces a CA record that looks healthy and cannot actually do its job.
func TestImportCARejects(t *testing.T) {
	ctx := context.Background()
	root := newLegacyRoot(t, "Reject Root", nil)
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	expired := newLegacyRoot(t, "Expired Root", func(c *x509.Certificate) {
		c.NotBefore = time.Now().Add(-2 * 365 * 24 * time.Hour)
		c.NotAfter = time.Now().Add(-24 * time.Hour)
	})
	notCA := newLegacyRoot(t, "Not A CA", func(c *x509.Certificate) {
		c.IsCA = false
		c.KeyUsage = x509.KeyUsageDigitalSignature
	})
	noCertSign := newLegacyRoot(t, "No certSign", func(c *x509.Certificate) {
		c.KeyUsage = x509.KeyUsageDigitalSignature
	})

	cases := []struct {
		name    string
		spec    ImportCASpec
		wantErr string
	}{
		{
			name:    "key does not match certificate",
			spec:    ImportCASpec{Label: "x", PrivateKey: otherKey, CertificatePEM: root.pem()},
			wantErr: "not a pair",
		},
		{
			name:    "expired certificate",
			spec:    ImportCASpec{Label: "x", PrivateKey: expired.key, CertificatePEM: expired.pem()},
			wantErr: "expired",
		},
		{
			name:    "not a CA certificate",
			spec:    ImportCASpec{Label: "x", PrivateKey: notCA.key, CertificatePEM: notCA.pem()},
			wantErr: "not a CA certificate",
		},
		{
			name:    "keyUsage lacks keyCertSign",
			spec:    ImportCASpec{Label: "x", PrivateKey: noCertSign.key, CertificatePEM: noCertSign.pem()},
			wantErr: "keyCertSign",
		},
		{
			name:    "no certificate",
			spec:    ImportCASpec{Label: "x", PrivateKey: root.key},
			wantErr: "certificate is required",
		},
		{
			name:    "no key at all",
			spec:    ImportCASpec{Label: "x", CertificatePEM: root.pem()},
			wantErr: "exactly one of",
		},
		{
			name: "both a key and an existing label",
			spec: ImportCASpec{Label: "x", PrivateKey: root.key, ExistingKeyLabel: "k",
				CertificatePEM: root.pem()},
			wantErr: "exactly one of",
		},
		{
			name:    "unknown existing key",
			spec:    ImportCASpec{Label: "x", ExistingKeyLabel: "nope", CertificatePEM: root.pem()},
			wantErr: "no key labeled",
		},
		{
			name:    "unknown named parent",
			spec:    ImportCASpec{Label: "x", PrivateKey: root.key, CertificatePEM: root.pem(), ParentID: "missing"},
			wantErr: "", // self-signed: the parent is simply not consulted
		},
	}
	for _, tc := range cases {
		if tc.wantErr == "" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			mgr := newTestManager(t, softwareProvider(t))
			_, err := mgr.ImportCA(ctx, tc.spec)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// TestImportCARejectsDuplicateLabel prevents an adoption from shadowing a CA
// that already exists.
func TestImportCARejectsDuplicateLabel(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	legacy := newLegacyRoot(t, "Dup", nil)
	if _, err := mgr.ImportCA(ctx, ImportCASpec{Label: "dup", PrivateKey: legacy.key, CertificatePEM: legacy.pem()}); err != nil {
		t.Fatal(err)
	}
	other := newLegacyRoot(t, "Dup2", nil)
	if _, err := mgr.ImportCA(ctx, ImportCASpec{Label: "dup", PrivateKey: other.key, CertificatePEM: other.pem()}); err == nil {
		t.Fatal("expected a duplicate CA label to be refused")
	}
}

// TestImportCARejectsBlockedKey proves the compromised-key blocklist covers the
// CA's own key: moving a known-compromised key into an HSM does not rehabilitate
// it, and the gate must say so before anything is persisted.
func TestImportCARejectsBlockedKey(t *testing.T) {
	ctx := context.Background()
	provider := softwareProvider(t)
	mgr := newTestManager(t, provider)
	legacy := newLegacyRoot(t, "Compromised Root", nil)

	fp, err := keycheck.Fingerprint(legacy.cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.db.AddBlockedKey(&models.BlockedKey{
		Fingerprint: fp, Reason: "known compromised", Source: "test",
	}); err != nil {
		t.Fatalf("blocking the key: %v", err)
	}
	_, err = mgr.ImportCA(ctx, ImportCASpec{Label: "blocked", PrivateKey: legacy.key, CertificatePEM: legacy.pem()})
	if err == nil {
		t.Fatal("expected a blocklisted CA key to be refused")
	}
	if !strings.Contains(err.Error(), "key-quality gate") {
		t.Fatalf("error = %v, want it to name the key-quality gate", err)
	}
	// Nothing may have been persisted or written to the provider.
	if ca, _ := mgr.db.GetCAByLabel("blocked"); ca != nil {
		t.Error("a CA record was persisted despite the refusal")
	}
	if _, err := provider.FindKey(ctx, keyprovider.KeyRef{Label: "blocked"}); err == nil {
		t.Error("key material was written to the provider despite the refusal")
	}
}

// TestImportCAMismatchLeavesNoOrphanKey checks the ordering that matters: the
// key/certificate pairing is validated before anything is written, so a
// mismatched import cannot strand key material on the token under the CA's label.
func TestImportCAMismatchLeavesNoOrphanKey(t *testing.T) {
	ctx := context.Background()
	provider := softwareProvider(t)
	mgr := newTestManager(t, provider)
	legacy := newLegacyRoot(t, "Orphan Test", nil)
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.ImportCA(ctx, ImportCASpec{
		Label: "orphan", PrivateKey: wrongKey, CertificatePEM: legacy.pem(),
	}); err == nil {
		t.Fatal("expected a mismatched key/certificate pair to be refused")
	}
	if _, err := provider.FindKey(ctx, keyprovider.KeyRef{Label: "orphan"}); err == nil {
		t.Fatal("the refused import left key material behind in the provider")
	}
}

// TestImportCASelfSignedMustVerify proves a corrupted root is caught: a
// self-signed certificate whose signature does not check out would otherwise
// become a trust anchor no path can be built through.
func TestImportCASelfSignedMustVerify(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	legacy := newLegacyRoot(t, "Tampered Root", nil)

	// Flip a byte in the signature.
	tampered := make([]byte, len(legacy.cert.Raw))
	copy(tampered, legacy.cert.Raw)
	tampered[len(tampered)-1] ^= 0xff
	// A mangled signature still parses; only verification catches it.
	if _, err := x509.ParseCertificate(tampered); err != nil {
		t.Skipf("the tampered DER no longer parses (%v); the verification path is covered by the parse instead", err)
	}
	_, err := mgr.ImportCA(ctx, ImportCASpec{
		Label: "tampered", PrivateKey: legacy.key, CertificatePEM: pki.EncodeCertificatePEM(tampered),
	})
	if err == nil {
		t.Fatal("expected a self-signed certificate with a bad signature to be refused")
	}
	if !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("error = %v, want it to report a failed self-signature check", err)
	}
}

// TestImportCAWarnsOnSoftwareProvider makes sure the operator is told when the
// adopted key lands somewhere it can still be copied. Silence here would let a
// migration "finish" without achieving the thing it was for.
func TestImportCAWarnsOnSoftwareProvider(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	legacy := newLegacyRoot(t, "Warn Root", nil)
	res, err := mgr.ImportCA(ctx, ImportCASpec{Label: "warn", PrivateKey: legacy.key, CertificatePEM: legacy.pem()})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, w := range res.Warnings {
		if strings.Contains(w, "software keystore") {
			found = true
		}
	}
	if !found {
		t.Errorf("no warning about the software keystore; got %v", res.Warnings)
	}
}
