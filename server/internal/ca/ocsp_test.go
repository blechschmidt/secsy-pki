//go:build sqlite

package ca

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// issueLeaf issues a server certificate under root and returns it.
func issueLeaf(t *testing.T, mgr *Manager, rootID, cn string) *IssueResult {
	t.Helper()
	res, err := mgr.IssueCertificate(context.Background(), IssueSpec{
		CAID:    rootID,
		CSRPEM:  makeCSR(t, cn, []string{cn}),
		Profile: "server",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	return res
}

func TestOCSPNonceEchoed(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	} {
		t.Run(name, func(t *testing.T) {
			mgr := newTestManager(t, mk(t))
			ctx := context.Background()
			root := newRoot(t, mgr, "ocsp-nonce")
			rootCert := mustParse(t, root.Certificate)
			leaf := issueLeaf(t, mgr, root.ID, "nonce.example.com")

			reqDER, err := pki.BuildOCSPRequest(leaf.Certificate, rootCert)
			if err != nil {
				t.Fatalf("BuildOCSPRequest: %v", err)
			}
			nonce := bytes.Repeat([]byte{0x5A}, 20)

			respDER, err := mgr.OCSPRespondWithOptions(ctx, root.ID, reqDER, OCSPRespondOptions{
				Nonce:    nonce,
				Validity: time.Minute,
			})
			if err != nil {
				t.Fatalf("OCSPRespondWithOptions: %v", err)
			}
			parsed, err := ocsp.ParseResponse(respDER, rootCert)
			if err != nil {
				t.Fatalf("ParseResponse: %v", err)
			}
			if parsed.Status != ocsp.Good {
				t.Errorf("status = %d, want Good", parsed.Status)
			}
			got, err := pki.OCSPResponseNonce(respDER)
			if err != nil {
				t.Fatalf("OCSPResponseNonce: %v", err)
			}
			if !bytes.Equal(got, nonce) {
				t.Errorf("echoed nonce = %x, want %x", got, nonce)
			}
		})
	}
}

func TestOCSPDelegatedResponder(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	} {
		t.Run(name, func(t *testing.T) {
			mgr := newTestManager(t, mk(t))
			ctx := context.Background()
			root := newRoot(t, mgr, "ocsp-deleg")
			rootCert := mustParse(t, root.Certificate)
			leaf := issueLeaf(t, mgr, root.ID, "deleg.example.com")

			cache := NewDelegatedResponderCache(2*time.Hour, keyprovider.KeyTypeECDSAP256)
			delegCert, ref, err := cache.Responder(ctx, mgr, root.ID)
			if err != nil {
				t.Fatalf("Responder: %v", err)
			}

			// The delegated cert must chain to the root, carry the OCSPSigning EKU
			// and the ocsp-nocheck extension, and be short-lived.
			if err := delegCert.CheckSignatureFrom(rootCert); err != nil {
				t.Errorf("delegated cert not signed by CA: %v", err)
			}
			if !hasExtKeyUsage(delegCert, x509.ExtKeyUsageOCSPSigning) {
				t.Error("delegated cert missing id-kp-OCSPSigning EKU")
			}
			hasNoCheck := false
			for _, ext := range delegCert.Extensions {
				if ext.Id.Equal(pki.OIDOCSPNoCheck) {
					hasNoCheck = true
				}
			}
			if !hasNoCheck {
				t.Error("delegated cert missing id-pkix-ocsp-nocheck")
			}

			// A second call must reuse the cached responder (same serial).
			delegCert2, _, err := cache.Responder(ctx, mgr, root.ID)
			if err != nil {
				t.Fatalf("Responder (2nd): %v", err)
			}
			if delegCert2.SerialNumber.Cmp(delegCert.SerialNumber) != 0 {
				t.Errorf("responder cert not cached: serials %s vs %s", delegCert.SerialNumber, delegCert2.SerialNumber)
			}

			// Sign a response with the delegated responder and verify the whole
			// chain via ParseResponse (embedded cert signed by CA + response signed
			// by embedded cert).
			reqDER, err := pki.BuildOCSPRequest(leaf.Certificate, rootCert)
			if err != nil {
				t.Fatalf("BuildOCSPRequest: %v", err)
			}
			respDER, err := mgr.OCSPRespondWithOptions(ctx, root.ID, reqDER, OCSPRespondOptions{
				Responder:       delegCert,
				ResponderKeyRef: &ref,
			})
			if err != nil {
				t.Fatalf("OCSPRespondWithOptions (delegated): %v", err)
			}
			parsed, err := ocsp.ParseResponse(respDER, rootCert)
			if err != nil {
				t.Fatalf("delegated response chain verification: %v", err)
			}
			if parsed.Certificate == nil {
				t.Fatal("delegated response did not embed the responder certificate")
			}
			if parsed.Certificate.SerialNumber.Cmp(delegCert.SerialNumber) != 0 {
				t.Errorf("embedded responder serial mismatch")
			}
			if parsed.Status != ocsp.Good {
				t.Errorf("status = %d, want Good", parsed.Status)
			}
		})
	}
}

func TestOCSPDelegatedResponderConcurrent(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()
	root := newRoot(t, mgr, "ocsp-deleg-conc")
	cache := NewDelegatedResponderCache(2*time.Hour, keyprovider.KeyTypeECDSAP256)

	const goroutines = 24
	var wg sync.WaitGroup
	serials := make([]string, goroutines)
	errs := make([]error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cert, _, err := cache.Responder(ctx, mgr, root.ID)
			if err != nil {
				errs[idx] = err
				return
			}
			serials[idx] = cert.SerialNumber.String()
		}(i)
	}
	wg.Wait()

	// All callers must succeed and receive the same, single cached responder
	// certificate (only one issuance happened despite the concurrency).
	first := serials[0]
	for i := 0; i < goroutines; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if serials[i] != first {
			t.Errorf("goroutine %d got serial %s, want %s (multiple issuances)", i, serials[i], first)
		}
	}
}

func TestOCSPStatusesAndUnauthorized(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()
	root := newRoot(t, mgr, "ocsp-status")
	rootCert := mustParse(t, root.Certificate)
	leaf := issueLeaf(t, mgr, root.ID, "status.example.com")

	// Good.
	reqGood, _ := pki.BuildOCSPRequest(leaf.Certificate, rootCert)
	if resp := mustOCSP(t, mgr, root.ID, reqGood, rootCert); resp.Status != ocsp.Good {
		t.Errorf("issued cert status = %d, want Good", resp.Status)
	}

	// Unknown: a serial this CA never issued.
	unknown := &x509.Certificate{SerialNumber: big.NewInt(0x0BADC0DE)}
	reqUnknown, _ := pki.BuildOCSPRequest(unknown, rootCert)
	if resp := mustOCSP(t, mgr, root.ID, reqUnknown, rootCert); resp.Status != ocsp.Unknown {
		t.Errorf("unknown serial status = %d, want Unknown", resp.Status)
	}

	// Revoked.
	if _, err := mgr.RevokeCertificate(ctx, root.ID, leaf.Serial.String(), "keyCompromise"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	if resp := mustOCSP(t, mgr, root.ID, reqGood, rootCert); resp.Status != ocsp.Revoked {
		t.Errorf("revoked cert status = %d, want Revoked", resp.Status)
	}

	// Unauthorized: an unknown CA id must surface ErrOCSPUnauthorized.
	if _, err := mgr.OCSPRespondWithOptions(ctx, "no-such-ca", reqGood, OCSPRespondOptions{}); !errors.Is(err, ErrOCSPUnauthorized) {
		t.Errorf("unknown CA error = %v, want ErrOCSPUnauthorized", err)
	}

	// Malformed: garbage request bytes must surface ErrOCSPMalformed.
	if _, err := mgr.OCSPRespondWithOptions(ctx, root.ID, []byte("not-a-request"), OCSPRespondOptions{}); !errors.Is(err, ErrOCSPMalformed) {
		t.Errorf("malformed request error = %v, want ErrOCSPMalformed", err)
	}
}

func TestOCSPStapleForCertificate(t *testing.T) {
	mgr := newTestManager(t, softwareProvider(t))
	ctx := context.Background()
	root := newRoot(t, mgr, "ocsp-staple")
	rootCert := mustParse(t, root.Certificate)
	leaf := issueLeaf(t, mgr, root.ID, "staple.example.com")

	staple, err := mgr.OCSPStapleForCertificate(ctx, root.ID, leaf.Certificate, OCSPRespondOptions{})
	if err != nil {
		t.Fatalf("OCSPStapleForCertificate: %v", err)
	}
	parsed, err := ocsp.ParseResponse(staple, rootCert)
	if err != nil {
		t.Fatalf("staple verification: %v", err)
	}
	if parsed.Status != ocsp.Good {
		t.Errorf("staple status = %d, want Good", parsed.Status)
	}
	if parsed.SerialNumber.Cmp(leaf.Certificate.SerialNumber) != 0 {
		t.Errorf("staple serial mismatch")
	}

	// A certificate issued by a different CA must be refused (unauthorized): its
	// signature does not chain to this CA.
	otherRoot := newRoot(t, mgr, "ocsp-staple-other")
	foreign := issueLeaf(t, mgr, otherRoot.ID, "foreign.example.com")
	if _, err := mgr.OCSPStapleForCertificate(ctx, root.ID, foreign.Certificate, OCSPRespondOptions{}); !errors.Is(err, ErrOCSPUnauthorized) {
		t.Errorf("stapling foreign cert error = %v, want ErrOCSPUnauthorized", err)
	}
}

func mustOCSP(t *testing.T, mgr *Manager, caID string, reqDER []byte, issuer *x509.Certificate) *ocsp.Response {
	t.Helper()
	respDER, err := mgr.OCSPRespondWithOptions(context.Background(), caID, reqDER, OCSPRespondOptions{})
	if err != nil {
		t.Fatalf("OCSPRespondWithOptions: %v", err)
	}
	parsed, err := ocsp.ParseResponse(respDER, issuer)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	return parsed
}
