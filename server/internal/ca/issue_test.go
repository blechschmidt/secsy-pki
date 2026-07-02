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

	"golang.org/x/crypto/ocsp"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// makeCSR builds a PEM CSR for a fresh ECDSA key with the given CN and DNS SANs.
func makeCSR(t *testing.T, cn string, dnsNames []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsNames,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func newRoot(t *testing.T, mgr *Manager, tag string) *models.CA {
	t.Helper()
	root, err := mgr.InitRoot(context.Background(), RootSpec{
		Label:    uniqueLabel(t, tag+"-root"),
		KeyType:  "ecdsa-p256",
		Subject:  PKIXName(models.CASubject{CommonName: "Issuance Test Root " + tag}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	return root
}

func TestIssueRenewRevokeCRLOCSP(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runIssuanceLifecycle(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runIssuanceLifecycle(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()
	root := newRoot(t, mgr, tag)
	rootCert := mustParse(t, root.Certificate)

	// --- Issue -------------------------------------------------------------
	csr := makeCSR(t, "leaf.example.com", []string{"leaf.example.com", "www.example.com"})
	issued, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    root.ID,
		CSRPEM:  csr,
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	if issued.Serial.Cmp(big.NewInt(1)) <= 0 {
		t.Errorf("leaf serial = %s, want > 1 (1 is the root self-cert)", issued.Serial)
	}

	leaf := issued.Certificate
	// Chain must verify against the root.
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf chain verification failed: %v", err)
	}
	// Profile applied: serverAuth EKU and appropriate key usage.
	if !hasExtKeyUsage(leaf, x509.ExtKeyUsageServerAuth) {
		t.Error("leaf missing serverAuth EKU from profile")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("leaf missing digitalSignature key usage from profile")
	}
	// AKI must chain to the root's SKI.
	if len(leaf.AuthorityKeyId) == 0 {
		t.Error("leaf has no Authority Key Identifier")
	}
	// SANs preserved.
	if len(leaf.DNSNames) != 2 {
		t.Errorf("leaf DNS SANs = %v, want 2", leaf.DNSNames)
	}

	// --- Renew -------------------------------------------------------------
	renewed, err := mgr.RenewCertificate(ctx, RenewSpec{CAID: root.ID, Serial: issued.Serial.String()})
	if err != nil {
		t.Fatalf("RenewCertificate: %v", err)
	}
	if renewed.Serial.Cmp(issued.Serial) == 0 {
		t.Error("renewed certificate reused the original serial")
	}
	if renewed.Certificate.Subject.CommonName != "leaf.example.com" {
		t.Errorf("renewed CN = %q, want leaf.example.com", renewed.Certificate.Subject.CommonName)
	}
	if _, err := renewed.Certificate.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("renewed leaf chain verification failed: %v", err)
	}

	// --- OCSP before revocation: Good --------------------------------------
	assertOCSP(t, mgr, root.ID, rootCert, issued.Serial, ocsp.Good)

	// --- Revoke ------------------------------------------------------------
	applied, err := mgr.RevokeCertificate(ctx, root.ID, issued.Serial.String(), "keyCompromise")
	if err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	if !applied {
		t.Error("expected revocation to be newly applied")
	}
	// Re-revoking is idempotent (not newly applied).
	if again, _ := mgr.RevokeCertificate(ctx, root.ID, issued.Serial.String(), "superseded"); again {
		t.Error("re-revocation should not report as newly applied")
	}

	// --- CRL ---------------------------------------------------------------
	crlDER, err := mgr.GenerateCRL(ctx, root.ID)
	if err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("parsing CRL: %v", err)
	}
	if err := crl.CheckSignatureFrom(rootCert); err != nil {
		t.Fatalf("CRL not signed by root: %v", err)
	}
	found := false
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(issued.Serial) == 0 {
			found = true
			if e.ReasonCode != pki.RevocationReasonSuperseded {
				t.Errorf("CRL reason = %d, want %d (superseded, from re-revoke)", e.ReasonCode, pki.RevocationReasonSuperseded)
			}
		}
	}
	if !found {
		t.Error("revoked serial not present in CRL")
	}

	// A second CRL must carry a strictly greater CRL number.
	crlDER2, err := mgr.GenerateCRL(ctx, root.ID)
	if err != nil {
		t.Fatalf("GenerateCRL (2): %v", err)
	}
	crl2, _ := x509.ParseRevocationList(crlDER2)
	if crl2.Number.Cmp(crl.Number) <= 0 {
		t.Errorf("second CRL number %s not greater than first %s", crl2.Number, crl.Number)
	}

	// --- OCSP after revocation: Revoked ------------------------------------
	assertOCSP(t, mgr, root.ID, rootCert, issued.Serial, ocsp.Revoked)

	// --- OCSP unknown serial ----------------------------------------------
	assertOCSP(t, mgr, root.ID, rootCert, big.NewInt(999999), ocsp.Unknown)
}

// assertOCSP builds an OCSP request for serial, has the manager answer it, and
// checks the parsed status.
func assertOCSP(t *testing.T, mgr *Manager, caID string, issuerCert *x509.Certificate, serial *big.Int, wantStatus int) {
	t.Helper()
	reqDER, err := ocsp.CreateRequest(&x509.Certificate{SerialNumber: serial}, issuerCert, nil)
	if err != nil {
		t.Fatalf("building OCSP request: %v", err)
	}
	respDER, err := mgr.OCSPRespond(context.Background(), caID, reqDER)
	if err != nil {
		t.Fatalf("OCSPRespond: %v", err)
	}
	resp, err := ocsp.ParseResponse(respDER, issuerCert)
	if err != nil {
		t.Fatalf("parsing OCSP response: %v", err)
	}
	if resp.Status != wantStatus {
		t.Errorf("OCSP status = %d, want %d", resp.Status, wantStatus)
	}
}

func hasExtKeyUsage(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == want {
			return true
		}
	}
	return false
}
