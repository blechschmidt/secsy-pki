//go:build sqlite

// Package e2e contains the end-to-end integration test for secsy-pki, exercised
// against a real PKCS#11 token (SoftHSM in CI). Unlike the per-package tests, it
// drives the entire product flow in one sequential scenario:
//
//	initialize token  -> generate HSM CA key -> issue root + intermediate + leaf
//	-> verify the full chain -> revoke the leaf and validate CRL + OCSP
//	-> run password encrypt/decrypt round-trips (HSM-backed envelope encryption).
//
// Every private-key operation (CA signing, CRL/OCSP signing, DEK unwrap) happens
// on the token; the test only ever handles public keys and ciphertext.
//
// It is gated on the SECSY_* environment emitted by scripts/setup-softhsm.sh so a
// plain `go test ./...` with no HSM stays green. Run the whole thing with a
// single command:
//
//	./scripts/integration-test.sh
package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// hsmProvider builds a PKCS#11 provider from the SECSY_* variables emitted by
// scripts/setup-softhsm.sh --export-env, or skips the test if none are present.
func hsmProvider(t *testing.T) keyprovider.Provider {
	t.Helper()
	module := os.Getenv("SECSY_PKCS11_MODULE")
	token := os.Getenv("SECSY_TOKEN_LABEL")
	if module == "" || token == "" {
		t.Skip("SoftHSM not configured: run  eval \"$(scripts/setup-softhsm.sh --export-env)\"  first " +
			"(or use ./scripts/integration-test.sh)")
	}
	pin := os.Getenv("SECSY_USER_PIN")
	if pin == "" {
		pin = "1234"
	}
	p, err := keyprovider.New(keyprovider.Config{
		Type: keyprovider.ProviderPKCS11,
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath: module,
			Pin:        pin,
			TokenLabel: token,
		},
	})
	if err != nil {
		t.Fatalf("connecting to SoftHSM token: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

// uniqueLabel derives a fresh CKA_LABEL per call so repeated runs against a
// persistent token never collide (duplicate labels cause intermittent verify
// failures — see the pkcs11-duplicate-label note).
func uniqueLabel(t *testing.T, base string) string {
	t.Helper()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "e2e-" + base + "-" + hex.EncodeToString(b[:])
}

// newManager wires a ca.Manager to a fresh sqlite database and the HSM provider.
func newManager(t *testing.T, provider keyprovider.Provider) *ca.Manager {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "e2e.db")
	db, err := database.New("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return ca.NewManager(db, provider)
}

// makeCSR builds a PEM PKCS#10 CSR for a fresh ECDSA leaf key. The leaf's private
// key stays with the "subscriber" (this test); only the CSR reaches the CA.
func makeCSR(t *testing.T, cn string, dnsNames []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func mustParse(t *testing.T, pemStr string) *x509.Certificate {
	t.Helper()
	cert, err := pki.ParseCertificatePEM([]byte(pemStr))
	if err != nil {
		t.Fatalf("parsing certificate PEM: %v", err)
	}
	return cert
}

// TestFullFlow runs the complete PKI + secrets lifecycle against the HSM as one
// ordered scenario. Sub-tests share state and run in declaration order, so a
// failure is reported against the precise stage while later stages still build
// on the earlier results.
func TestFullFlow(t *testing.T) {
	ctx := context.Background()
	provider := hsmProvider(t)
	mgr := newManager(t, provider)

	const keyType = keyprovider.KeyTypeECDSAP256

	var (
		root, inter       *models.CA
		rootCert          *x509.Certificate
		interCert         *x509.Certificate
		leaf              *ca.IssueResult
		leafSerial        *big.Int
		roots             = x509.NewCertPool()
		intermediatesPool = x509.NewCertPool()
	)

	// --- 1. Generate the HSM-backed root CA key and self-signed root cert. ---
	t.Run("InitRootCA", func(t *testing.T) {
		var err error
		root, err = mgr.InitRoot(ctx, ca.RootSpec{
			Label:    uniqueLabel(t, "root"),
			KeyType:  keyType,
			Subject:  ca.PKIXName(models.CASubject{CommonName: "Secsy E2E Root CA", Organization: "Secsy"}),
			Validity: 10 * 365 * 24 * time.Hour,
		})
		if err != nil {
			t.Fatalf("InitRoot: %v", err)
		}
		rootCert = mustParse(t, root.Certificate)
		if !rootCert.IsCA {
			t.Fatal("root certificate is not marked as a CA")
		}
		if err := rootCert.CheckSignatureFrom(rootCert); err != nil {
			t.Fatalf("root is not validly self-signed: %v", err)
		}
		roots.AddCert(rootCert)
	})

	// --- 2. Issue an intermediate CA under the root (signed on the HSM). ---
	t.Run("IssueIntermediateCA", func(t *testing.T) {
		if root == nil {
			t.Skip("root CA not initialized")
		}
		var err error
		inter, err = mgr.IssueIntermediate(ctx, ca.IntermediateSpec{
			ParentID:   root.ID,
			Label:      uniqueLabel(t, "inter"),
			KeyType:    keyType,
			Subject:    ca.PKIXName(models.CASubject{CommonName: "Secsy E2E Intermediate CA"}),
			Validity:   5 * 365 * 24 * time.Hour,
			MaxPathLen: intPtr(0),
		})
		if err != nil {
			t.Fatalf("IssueIntermediate: %v", err)
		}
		interCert = mustParse(t, inter.Certificate)
		if err := interCert.CheckSignatureFrom(rootCert); err != nil {
			t.Fatalf("intermediate not signed by root: %v", err)
		}
		if _, err := interCert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
			t.Fatalf("intermediate chain does not verify: %v", err)
		}
		intermediatesPool.AddCert(interCert)
	})

	// --- 3. Issue a leaf certificate off the intermediate from a CSR. ---
	t.Run("IssueLeaf", func(t *testing.T) {
		if inter == nil {
			t.Skip("intermediate CA not issued")
		}
		csr := makeCSR(t, "app.e2e.example.com", []string{"app.e2e.example.com", "www.e2e.example.com"})
		var err error
		leaf, err = mgr.IssueCertificate(ctx, ca.IssueSpec{
			CAID:    inter.ID,
			CSRPEM:  csr,
			Profile: "server",
		})
		if err != nil {
			t.Fatalf("IssueCertificate: %v", err)
		}
		leafSerial = leaf.Serial
		if !hasExtKeyUsage(leaf.Certificate, x509.ExtKeyUsageServerAuth) {
			t.Error("leaf missing serverAuth EKU from the server profile")
		}
		if got := leaf.Certificate.DNSNames; len(got) != 2 {
			t.Errorf("leaf SANs = %v, want 2 preserved from CSR", got)
		}
		if leaf.Certificate.IsCA {
			t.Error("leaf must not be a CA")
		}
	})

	// --- 4. Verify the complete leaf -> intermediate -> root chain. ---
	t.Run("VerifyChain", func(t *testing.T) {
		if leaf == nil {
			t.Skip("leaf not issued")
		}
		chains, err := leaf.Certificate.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediatesPool,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			t.Fatalf("full chain verification failed: %v", err)
		}
		// leaf, intermediate, root.
		if n := len(chains[0]); n != 3 {
			t.Errorf("verified chain length = %d, want 3 (leaf/intermediate/root)", n)
		}
		// The emitted ChainPEM should include the intermediate so clients can
		// present a complete chain.
		if !bytes.Contains(leaf.ChainPEM, []byte("BEGIN CERTIFICATE")) {
			t.Error("ChainPEM does not contain any certificates")
		}
	})

	// --- 5. OCSP says Good before revocation. ---
	t.Run("OCSPGoodBeforeRevoke", func(t *testing.T) {
		if leaf == nil {
			t.Skip("leaf not issued")
		}
		assertOCSP(t, mgr, inter.ID, interCert, leafSerial, ocsp.Good)
	})

	// --- 6. Revoke the leaf. ---
	t.Run("RevokeLeaf", func(t *testing.T) {
		if leaf == nil {
			t.Skip("leaf not issued")
		}
		applied, err := mgr.RevokeCertificate(ctx, inter.ID, leafSerial.String(), "keyCompromise")
		if err != nil {
			t.Fatalf("RevokeCertificate: %v", err)
		}
		if !applied {
			t.Error("first revocation should report as newly applied")
		}
		if again, _ := mgr.RevokeCertificate(ctx, inter.ID, leafSerial.String(), "keyCompromise"); again {
			t.Error("re-revoking the same serial should be idempotent (not newly applied)")
		}
	})

	// --- 7. The intermediate's CRL is HSM-signed and lists the revoked leaf. ---
	t.Run("CRLContainsRevoked", func(t *testing.T) {
		if leaf == nil {
			t.Skip("leaf not issued")
		}
		crlDER, err := mgr.GenerateCRL(ctx, inter.ID)
		if err != nil {
			t.Fatalf("GenerateCRL: %v", err)
		}
		crl, err := x509.ParseRevocationList(crlDER)
		if err != nil {
			t.Fatalf("parsing CRL: %v", err)
		}
		if err := crl.CheckSignatureFrom(interCert); err != nil {
			t.Fatalf("CRL is not signed by the intermediate CA: %v", err)
		}
		found := false
		for _, e := range crl.RevokedCertificateEntries {
			if e.SerialNumber.Cmp(leafSerial) == 0 {
				found = true
				if e.ReasonCode != pki.RevocationReasonKeyCompromise {
					t.Errorf("CRL reason = %d, want %d (keyCompromise)", e.ReasonCode, pki.RevocationReasonKeyCompromise)
				}
			}
		}
		if !found {
			t.Error("revoked leaf serial is not present in the CRL")
		}

		// A regenerated CRL must carry a strictly greater CRL number (RFC 5280).
		crlDER2, err := mgr.GenerateCRL(ctx, inter.ID)
		if err != nil {
			t.Fatalf("GenerateCRL (second): %v", err)
		}
		crl2, err := x509.ParseRevocationList(crlDER2)
		if err != nil {
			t.Fatalf("parsing second CRL: %v", err)
		}
		if crl2.Number.Cmp(crl.Number) <= 0 {
			t.Errorf("second CRL number %s is not greater than first %s", crl2.Number, crl.Number)
		}
	})

	// --- 8. OCSP now reports Revoked, and Unknown for a serial never issued. ---
	t.Run("OCSPRevokedAfterRevoke", func(t *testing.T) {
		if leaf == nil {
			t.Skip("leaf not issued")
		}
		assertOCSP(t, mgr, inter.ID, interCert, leafSerial, ocsp.Revoked)
		assertOCSP(t, mgr, inter.ID, interCert, big.NewInt(0xDEADBEEF), ocsp.Unknown)
	})

	// --- 9. HSM-backed password encrypt/decrypt round-trips. ---
	t.Run("PasswordEnvelopeRoundTrip", func(t *testing.T) {
		kekLabel := uniqueLabel(t, "kek")
		svc, err := secret.ProvisionKEK(ctx, provider, kekLabel, keyprovider.KeyTypeRSA2048)
		if err != nil {
			t.Fatalf("ProvisionKEK on HSM: %v", err)
		}
		if info := svc.KEKInfo(); info.Provider != "pkcs11" {
			t.Errorf("KEK provider = %q, want pkcs11 (key must live on the token)", info.Provider)
		}

		secrets := [][]byte{
			[]byte("correct horse battery staple"),
			[]byte(""),                                       // empty plaintext is a legitimate edge case
			bytes.Repeat([]byte{0x00, 0x01, 0xff, 0x7f}, 64), // binary, larger than one block
		}
		for i, plaintext := range secrets {
			blob, err := svc.EncryptToJSON(plaintext, nil)
			if err != nil {
				t.Fatalf("EncryptToJSON[%d]: %v", i, err)
			}
			if len(plaintext) > 0 && bytes.Contains(blob, plaintext) {
				t.Fatalf("plaintext[%d] leaked into the envelope", i)
			}

			// Rebind a fresh Service to the token-resident KEK to prove decryption
			// depends only on the HSM key, not on in-memory provisioning state.
			svc2, err := secret.NewService(ctx, provider, keyprovider.KeyRef{Label: kekLabel})
			if err != nil {
				t.Fatalf("NewService[%d]: %v", i, err)
			}
			got, err := svc2.DecryptJSON(blob, nil)
			if err != nil {
				t.Fatalf("DecryptJSON[%d]: %v", i, err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatalf("round-trip[%d] mismatch: got %q want %q", i, got, plaintext)
			}
		}

		// Context binding: decrypting with the wrong AAD must fail (no oracle).
		bound, err := svc.Encrypt([]byte("bound-secret"), []byte("service=payments"))
		if err != nil {
			t.Fatalf("Encrypt with context: %v", err)
		}
		if _, err := svc.Decrypt(bound, []byte("service=payments")); err != nil {
			t.Fatalf("decrypt with correct context failed: %v", err)
		}
		if _, err := svc.Decrypt(bound, []byte("service=other")); err == nil {
			t.Error("decrypt with wrong context must fail")
		}

		// Tamper detection: flipping a ciphertext bit must fail authentication.
		tampered := *bound
		tampered.Ciphertext = append([]byte(nil), bound.Ciphertext...)
		tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 0x80
		if _, err := svc.Decrypt(&tampered, []byte("service=payments")); err == nil {
			t.Error("decrypt of tampered ciphertext must fail")
		}
	})
}

// assertOCSP asks the manager to answer an OCSP request for serial (issued by the
// CA identified by caID / issuerCert) and checks the parsed status.
func assertOCSP(t *testing.T, mgr *ca.Manager, caID string, issuerCert *x509.Certificate, serial *big.Int, wantStatus int) {
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

func intPtr(v int) *int { return &v }
