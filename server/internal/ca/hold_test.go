//go:build sqlite

package ca

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ocsp"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// crlEntryReason returns the RFC 5280 reason code recorded for a serial in a
// CRL, or -1 if the serial is absent.
func crlEntryReason(crl *x509.RevocationList, serial *big.Int) int {
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(serial) == 0 {
			return e.ReasonCode
		}
	}
	return -1
}

// mustParseCRL parses a DER-encoded CRL, failing the test on error.
func mustParseCRL(t *testing.T, der []byte) *x509.RevocationList {
	t.Helper()
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parsing CRL: %v", err)
	}
	return crl
}

// TestSuspendReleaseLifecycle exercises the full reversible-hold flow at the Go
// level against both key providers (so the SoftHSM signing path is covered):
// issue -> suspend -> OCSP revoked(certificateHold) and serial on the base CRL
// -> release -> OCSP good, the serial removed from a freshly generated complete
// CRL, and a removeFromCRL(8) entry present in the delta CRL that references the
// base cut while the certificate was held (RFC 5280 §5.2.4 / §5.3.1).
func TestSuspendReleaseLifecycle(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	} {
		t.Run(name, func(t *testing.T) {
			withCRLConfig(t, CRLDistConfig{Shards: 1, BaseURL: "https://pki.example.com"})
			mgr := newTestManager(t, mk(t))
			ctx := context.Background()
			root := newRoot(t, mgr, "hold")
			rootCert := mustParse(t, root.Certificate)
			leaf := issueLeaf(t, mgr, root.ID, "hold.example.com")
			reqDER, err := pki.BuildOCSPRequest(leaf.Certificate, rootCert)
			if err != nil {
				t.Fatalf("BuildOCSPRequest: %v", err)
			}

			// A freshly issued certificate is good.
			if resp := mustOCSP(t, mgr, root.ID, reqDER, rootCert); resp.Status != ocsp.Good {
				t.Fatalf("pre-suspend status = %d, want Good", resp.Status)
			}

			// Suspend: the certificate is placed on hold.
			applied, err := mgr.SuspendCertificate(ctx, root.ID, leaf.Serial.String())
			if err != nil {
				t.Fatalf("SuspendCertificate: %v", err)
			}
			if !applied {
				t.Fatal("SuspendCertificate reported not-newly-held for a fresh certificate")
			}
			// Suspending again is idempotent (already-held).
			if again, err := mgr.SuspendCertificate(ctx, root.ID, leaf.Serial.String()); err != nil || again {
				t.Fatalf("second suspend: applied=%v err=%v, want applied=false err=nil", again, err)
			}

			// While held, OCSP reports revoked with reason certificateHold.
			if resp := mustOCSP(t, mgr, root.ID, reqDER, rootCert); resp.Status != ocsp.Revoked {
				t.Errorf("held status = %d, want Revoked", resp.Status)
			} else if resp.RevocationReason != ocsp.CertificateHold {
				t.Errorf("held reason = %d, want CertificateHold(%d)", resp.RevocationReason, ocsp.CertificateHold)
			}

			// The base CRL, cut while the certificate is held, lists the serial with
			// reason certificateHold.
			base := parseCRL(t, mgr, ctx, root.ID, FullScope, false)
			if r := crlEntryReason(base, leaf.Serial); r != pki.RevocationReasonCertificateHold {
				t.Errorf("base CRL entry reason for held serial = %d, want certificateHold(%d)", r, pki.RevocationReasonCertificateHold)
			}
			baseNumber := base.Number

			// Release: the hold is removed.
			if err := mgr.ReleaseCertificate(ctx, root.ID, leaf.Serial.String()); err != nil {
				t.Fatalf("ReleaseCertificate: %v", err)
			}

			// OCSP reports good again.
			if resp := mustOCSP(t, mgr, root.ID, reqDER, rootCert); resp.Status != ocsp.Good {
				t.Errorf("post-release status = %d, want Good", resp.Status)
			}

			// The delta CRL — relative to the base cut while the cert was held —
			// carries removeFromCRL(8) for the released serial and references that
			// base by number (RFC 5280 §5.2.4).
			delta := parseCRL(t, mgr, ctx, root.ID, FullScope, true)
			if r := crlEntryReason(delta, leaf.Serial); r != pki.RevocationReasonRemoveFromCRL {
				t.Errorf("delta CRL entry reason for released serial = %d, want removeFromCRL(%d)", r, pki.RevocationReasonRemoveFromCRL)
			}
			if bn := deltaIndicatorValue(t, delta); bn.Cmp(baseNumber) != 0 {
				t.Errorf("delta Delta CRL Indicator = %s, want base number %s", bn, baseNumber)
			}

			// A freshly generated complete CRL omits the released serial entirely:
			// once a base is cut after the release, the serial is gone for good.
			freshDER, err := mgr.GenerateCRL(ctx, root.ID)
			if err != nil {
				t.Fatalf("GenerateCRL: %v", err)
			}
			fresh := mustParseCRL(t, freshDER)
			if crlHasSerial(fresh, leaf.Serial) {
				t.Errorf("released serial %s still present in a freshly generated complete CRL", leaf.Serial)
			}
		})
	}
}

// TestReleaseRejectsPermanentRevocation is the negative case: a certificate
// revoked for a permanent reason (keyCompromise) cannot be released. The hold
// path must never resurrect a withdrawn credential.
func TestReleaseRejectsPermanentRevocation(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	} {
		t.Run(name, func(t *testing.T) {
			mgr := newTestManager(t, mk(t))
			ctx := context.Background()
			root := newRoot(t, mgr, "hold-neg")
			leaf := issueLeaf(t, mgr, root.ID, "perm.example.com")

			if _, err := mgr.RevokeCertificate(ctx, root.ID, leaf.Serial.String(), "keyCompromise"); err != nil {
				t.Fatalf("RevokeCertificate: %v", err)
			}

			// Release must be refused with ErrNotOnHold — the revocation is permanent.
			err := mgr.ReleaseCertificate(ctx, root.ID, leaf.Serial.String())
			if !errors.Is(err, ErrNotOnHold) {
				t.Fatalf("release of keyCompromise-revoked cert: err = %v, want ErrNotOnHold", err)
			}

			// Suspending a permanently revoked certificate is likewise refused.
			if _, err := mgr.SuspendCertificate(ctx, root.ID, leaf.Serial.String()); err == nil {
				t.Error("suspend of a permanently revoked certificate unexpectedly succeeded")
			}

			// The certificate stays revoked (keyCompromise), not downgraded to hold.
			rc, err := mgr.db.GetRevokedCertificate(root.ID, leaf.Serial.String())
			if err != nil || rc == nil {
				t.Fatalf("GetRevokedCertificate: rc=%v err=%v", rc, err)
			}
			if rc.Reason != pki.RevocationReasonKeyCompromise {
				t.Errorf("reason after failed release = %d, want keyCompromise(%d)", rc.Reason, pki.RevocationReasonKeyCompromise)
			}

			// Releasing a serial that was never revoked is refused with ErrNotRevoked.
			live := issueLeaf(t, mgr, root.ID, "live.example.com")
			if err := mgr.ReleaseCertificate(ctx, root.ID, live.Serial.String()); !errors.Is(err, ErrNotRevoked) {
				t.Errorf("release of never-revoked cert: err = %v, want ErrNotRevoked", err)
			}
		})
	}
}

// TestReleaseSentinelIsDatabaseSentinel guards the re-export in ca/hold.go so the
// ca-level and database-level sentinels stay identical (errors.Is across the
// boundary keeps working for handlers/gRPC).
func TestReleaseSentinelIsDatabaseSentinel(t *testing.T) {
	if !errors.Is(ErrNotOnHold, database.ErrNotOnHold) {
		t.Error("ca.ErrNotOnHold does not match database.ErrNotOnHold")
	}
	if !errors.Is(ErrNotRevoked, database.ErrNotRevoked) {
		t.Error("ca.ErrNotRevoked does not match database.ErrNotRevoked")
	}
}

// TestSuspendReleaseOpenSSL feeds the HSM-signed CRLs to the reference `openssl`
// client: while held, `openssl verify -crl_check` rejects the leaf as revoked;
// after release, a freshly generated complete CRL accepts it again, and the
// delta CRL's entry decodes as "Remove From CRL".
func TestSuspendReleaseOpenSSL(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH")
	}
	for name, mk := range map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	} {
		t.Run(name, func(t *testing.T) {
			withCRLConfig(t, CRLDistConfig{Shards: 1, BaseURL: "https://pki.example.com"})
			mgr := newTestManager(t, mk(t))
			ctx := context.Background()
			root := newRoot(t, mgr, "hold-openssl")
			leaf := issueLeaf(t, mgr, root.ID, "hold-openssl.example.com")

			dir := t.TempDir()
			caPEM := filepath.Join(dir, "ca.pem")
			leafPEM := filepath.Join(dir, "leaf.pem")
			writeFile(t, caPEM, []byte(root.Certificate))
			writeFile(t, leafPEM, pki.EncodeCertificatePEM(leaf.Certificate.Raw))

			// Suspend, then cut the base CRL while the certificate is held.
			if _, err := mgr.SuspendCertificate(ctx, root.ID, leaf.Serial.String()); err != nil {
				t.Fatalf("SuspendCertificate: %v", err)
			}
			heldBaseDER, err := mgr.GetBaseCRL(ctx, root.ID, FullScope)
			if err != nil {
				t.Fatalf("GetBaseCRL (held): %v", err)
			}
			heldCRLPEM := filepath.Join(dir, "held-crl.pem")
			writeFile(t, heldCRLPEM, pki.EncodeCRLPEM(heldBaseDER))

			// openssl rejects the held certificate as revoked.
			if out, err := verify(openssl, caPEM, heldCRLPEM, leafPEM, false); err == nil {
				t.Errorf("openssl accepted a held certificate:\n%s", out)
			} else if !strings.Contains(out, "revoked") {
				t.Errorf("expected 'revoked' verifying a held cert, got:\n%s", out)
			}

			// Release, then fetch the delta CRL (relative to the held base).
			if err := mgr.ReleaseCertificate(ctx, root.ID, leaf.Serial.String()); err != nil {
				t.Fatalf("ReleaseCertificate: %v", err)
			}
			deltaDER, err := mgr.GetDeltaCRL(ctx, root.ID, FullScope)
			if err != nil {
				t.Fatalf("GetDeltaCRL: %v", err)
			}
			deltaPEM := filepath.Join(dir, "delta.pem")
			writeFile(t, deltaPEM, pki.EncodeCRLPEM(deltaDER))

			// openssl decodes the delta entry as a removeFromCRL reason.
			out := runOut(t, openssl, "crl", "-in", deltaPEM, "-noout", "-text")
			if !strings.Contains(out, "Remove From CRL") {
				t.Errorf("openssl did not report a Remove From CRL reason in the delta CRL:\n%s", out)
			}

			// A freshly generated complete CRL omits the released serial, so openssl
			// accepts the certificate again.
			freshDER, err := mgr.GenerateCRL(ctx, root.ID)
			if err != nil {
				t.Fatalf("GenerateCRL: %v", err)
			}
			freshCRLPEM := filepath.Join(dir, "fresh-crl.pem")
			writeFile(t, freshCRLPEM, pki.EncodeCRLPEM(freshDER))
			if out, err := verify(openssl, caPEM, freshCRLPEM, leafPEM, false); err != nil {
				t.Errorf("openssl rejected a released certificate against a fresh CRL:\n%s", out)
			}
		})
	}
}
