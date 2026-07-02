//go:build sqlite

package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// withCRLConfig installs a CRL distribution policy for the duration of a test and
// restores the (zero, unsharded) default afterwards so package-global state does
// not leak between tests.
func withCRLConfig(t *testing.T, c CRLDistConfig) {
	t.Helper()
	SetCRLConfig(c)
	t.Cleanup(func() { SetCRLConfig(CRLDistConfig{}) })
}

var (
	oidDeltaCRLIndicatorTest = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIDPTest               = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidFreshestCRLTest       = asn1.ObjectIdentifier{2, 5, 29, 46}
)

func hasExt(exts []pkix.Extension, oid asn1.ObjectIdentifier) bool {
	for _, e := range exts {
		if e.Id.Equal(oid) {
			return true
		}
	}
	return false
}

// TestCRLShardMembership verifies that (1) each issued certificate is stamped
// with the CRLDistributionPoints URL of the shard its serial deterministically
// maps to, and (2) a revoked serial appears in exactly that shard's base CRL and
// no other. It runs over both key providers so the SoftHSM signing path is
// exercised.
func TestCRLShardMembership(t *testing.T) {
	const shards = 4
	for name, mk := range map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	} {
		t.Run(name, func(t *testing.T) {
			withCRLConfig(t, CRLDistConfig{Shards: shards, BaseURL: "https://pki.example.com"})
			mgr := newTestManager(t, mk(t))
			ctx := context.Background()
			root := newRoot(t, mgr, "crl-shard")

			// Issue several leaves; record each serial and the shard it maps to.
			type leaf struct {
				serial *big.Int
				shard  int
			}
			var leaves []leaf
			for i := 0; i < 16; i++ {
				res := issueLeaf(t, mgr, root.ID, "shard-host.example.com")
				shard := ShardForSerial(res.Serial)
				leaves = append(leaves, leaf{serial: res.Serial, shard: shard})

				// The stamped CDP must name this serial's shard CRL.
				want := crlURL(root.ID, shard)
				got := res.Certificate.CRLDistributionPoints
				if len(got) != 1 || got[0] != want {
					t.Fatalf("leaf CDP = %v, want [%s]", got, want)
				}
				if shard < 0 || shard >= shards {
					t.Fatalf("serial mapped to out-of-range shard %d", shard)
				}
			}

			// Revoke one certificate from a shard we know has members.
			victim := leaves[0]
			if _, err := mgr.RevokeCertificate(ctx, root.ID, victim.serial.String(), "keyCompromise"); err != nil {
				t.Fatalf("RevokeCertificate: %v", err)
			}

			// The victim serial must appear in its own shard CRL...
			ownCRL := parseCRL(t, mgr, ctx, root.ID, victim.shard, false)
			if !crlHasSerial(ownCRL, victim.serial) {
				t.Fatalf("revoked serial %s absent from its own shard %d CRL", victim.serial, victim.shard)
			}
			// ...and in NO other shard CRL.
			for s := 0; s < shards; s++ {
				if s == victim.shard {
					continue
				}
				other := parseCRL(t, mgr, ctx, root.ID, s, false)
				if crlHasSerial(other, victim.serial) {
					t.Errorf("revoked serial %s wrongly present in shard %d CRL", victim.serial, s)
				}
			}

			// The shard CRL must carry the critical Issuing Distribution Point and
			// the Freshest CRL pointer (RFC 5280 §5.2.5 / §5.2.6).
			if !hasExt(ownCRL.Extensions, oidIDPTest) {
				t.Error("shard base CRL is missing the Issuing Distribution Point extension")
			}
			if !hasExt(ownCRL.Extensions, oidFreshestCRLTest) {
				t.Error("shard base CRL is missing the Freshest CRL extension")
			}
			if err := ownCRL.CheckSignatureFrom(mustParse(t, root.Certificate)); err != nil {
				t.Errorf("shard CRL not signed by the CA: %v", err)
			}
		})
	}
}

// TestDeltaCRLMonotonicAndIndicator verifies delta-CRL semantics at the Go level:
// a delta references its base via the Delta CRL Indicator, carries a strictly
// greater CRL number, and lists only the entries revoked since the base was cut.
func TestDeltaCRLMonotonicAndIndicator(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	} {
		t.Run(name, func(t *testing.T) {
			withCRLConfig(t, CRLDistConfig{Shards: 1, BaseURL: "https://pki.example.com"})
			mgr := newTestManager(t, mk(t))
			ctx := context.Background()
			root := newRoot(t, mgr, "crl-delta")
			a := issueLeaf(t, mgr, root.ID, "a.example.com")
			b := issueLeaf(t, mgr, root.ID, "b.example.com")

			// Revoke A, cut the base CRL.
			if _, err := mgr.RevokeCertificate(ctx, root.ID, a.Serial.String(), "superseded"); err != nil {
				t.Fatalf("revoke A: %v", err)
			}
			base := parseCRL(t, mgr, ctx, root.ID, FullScope, false)
			if !crlHasSerial(base, a.Serial) {
				t.Fatal("base CRL missing revoked serial A")
			}

			// Revoke B, cut the delta CRL. It must reference the base, be newer,
			// contain B, and NOT re-list A (which predates the base).
			if _, err := mgr.RevokeCertificate(ctx, root.ID, b.Serial.String(), "keyCompromise"); err != nil {
				t.Fatalf("revoke B: %v", err)
			}
			delta := parseCRL(t, mgr, ctx, root.ID, FullScope, true)
			if !hasExt(delta.Extensions, oidDeltaCRLIndicatorTest) {
				t.Fatal("delta CRL missing the Delta CRL Indicator extension")
			}
			if delta.Number.Cmp(base.Number) <= 0 {
				t.Errorf("delta CRL number %s not greater than base %s", delta.Number, base.Number)
			}
			if !crlHasSerial(delta, b.Serial) {
				t.Error("delta CRL missing serial B (revoked after the base)")
			}
			if crlHasSerial(delta, a.Serial) {
				t.Error("delta CRL should not re-list serial A (already in the base)")
			}

			// The Delta CRL Indicator value must equal the base's CRL number.
			baseNum := deltaIndicatorValue(t, delta)
			if baseNum.Cmp(base.Number) != 0 {
				t.Errorf("Delta CRL Indicator = %s, want base number %s", baseNum, base.Number)
			}
		})
	}
}

// TestDeltaCRLOpenSSLReconstruction feeds our HSM-signed base and delta CRLs to
// the reference `openssl verify` client and confirms it reconstructs the union:
// a certificate revoked only in the delta is rejected when deltas are enabled and
// the base+delta pair is supplied, but accepted when only the base is supplied.
func TestDeltaCRLOpenSSLReconstruction(t *testing.T) {
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
			root := newRoot(t, mgr, "crl-openssl")
			a := issueLeaf(t, mgr, root.ID, "a.example.com")
			b := issueLeaf(t, mgr, root.ID, "b.example.com")

			// Revoke A -> base; revoke B -> delta.
			if _, err := mgr.RevokeCertificate(ctx, root.ID, a.Serial.String(), "superseded"); err != nil {
				t.Fatalf("revoke A: %v", err)
			}
			baseDER, err := mgr.GetBaseCRL(ctx, root.ID, FullScope)
			if err != nil {
				t.Fatalf("GetBaseCRL: %v", err)
			}
			if _, err := mgr.RevokeCertificate(ctx, root.ID, b.Serial.String(), "keyCompromise"); err != nil {
				t.Fatalf("revoke B: %v", err)
			}
			deltaDER, err := mgr.GetDeltaCRL(ctx, root.ID, FullScope)
			if err != nil {
				t.Fatalf("GetDeltaCRL: %v", err)
			}

			dir := t.TempDir()
			caPEM := filepath.Join(dir, "ca.pem")
			aPEM := filepath.Join(dir, "a.pem")
			bPEM := filepath.Join(dir, "b.pem")
			basePEM := filepath.Join(dir, "base.pem")
			bothPEM := filepath.Join(dir, "both.pem")
			writeFile(t, caPEM, []byte(root.Certificate))
			writeFile(t, aPEM, pki.EncodeCertificatePEM(a.Certificate.Raw))
			writeFile(t, bPEM, pki.EncodeCertificatePEM(b.Certificate.Raw))
			writeFile(t, basePEM, pki.EncodeCRLPEM(baseDER))
			// The combined file holds base + delta, as a relying party would gather.
			writeFile(t, bothPEM, append(pki.EncodeCRLPEM(baseDER), pki.EncodeCRLPEM(deltaDER)...))

			// openssl parses our hand-rolled delta extensions without error and
			// reports it as a delta CRL (proving the DER is wire-correct).
			deltaPEMPath := filepath.Join(dir, "delta.pem")
			writeFile(t, deltaPEMPath, pki.EncodeCRLPEM(deltaDER))
			if out := runOut(t, openssl, "crl", "-in", deltaPEMPath, "-noout", "-text"); !strings.Contains(out, "Delta CRL Indicator") {
				t.Errorf("openssl did not recognize the Delta CRL Indicator:\n%s", out)
			}

			// (1) A is revoked in the BASE: verifying A against base alone fails.
			if out, err := verify(openssl, caPEM, basePEM, aPEM, false); err == nil {
				t.Errorf("openssl accepted A though it is revoked in the base CRL:\n%s", out)
			} else if !strings.Contains(out, "revoked") {
				t.Errorf("expected 'revoked' verifying A against base, got:\n%s", out)
			}

			// (2) B is NOT in the base: verifying B against base alone succeeds.
			if out, err := verify(openssl, caPEM, basePEM, bPEM, false); err != nil {
				t.Errorf("openssl rejected B against base-only CRL (should be valid):\n%s\n%v", out, err)
			}

			// (3) base+delta reconstruction: with deltas enabled, B is now revoked.
			if out, err := verify(openssl, caPEM, bothPEM, bPEM, true); err == nil {
				t.Errorf("openssl accepted B though the delta CRL revokes it:\n%s", out)
			} else if !strings.Contains(out, "revoked") {
				t.Errorf("expected 'revoked' verifying B against base+delta, got:\n%s", out)
			}
		})
	}
}

// verify runs `openssl verify` with CRL checking, optionally enabling delta CRL
// reconstruction. It returns combined output and the process error (non-nil when
// verification fails, e.g. the certificate is revoked).
func verify(openssl, caPEM, crlPEM, certPEM string, useDeltas bool) (string, error) {
	args := []string{"verify", "-crl_check", "-CAfile", caPEM, "-CRLfile", crlPEM}
	if useDeltas {
		args = append(args, "-use_deltas", "-extended_crl")
	}
	args = append(args, certPEM)
	out, err := exec.Command(openssl, args...).CombinedOutput()
	return string(out), err
}

// runOut runs a command and returns combined output, failing the test on error.
func runOut(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// parseCRL fetches and parses a base or delta CRL for a scope.
func parseCRL(t *testing.T, mgr *Manager, ctx context.Context, caID string, shard int, delta bool) *x509.RevocationList {
	t.Helper()
	var (
		der []byte
		err error
	)
	if delta {
		der, err = mgr.GetDeltaCRL(ctx, caID, shard)
	} else {
		der, err = mgr.GetBaseCRL(ctx, caID, shard)
	}
	if err != nil {
		t.Fatalf("get CRL (shard=%d delta=%v): %v", shard, delta, err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatalf("parsing CRL: %v", err)
	}
	return crl
}

func crlHasSerial(crl *x509.RevocationList, serial *big.Int) bool {
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

// deltaIndicatorValue extracts the base CRL number carried in the Delta CRL
// Indicator (2.5.29.27) extension.
func deltaIndicatorValue(t *testing.T, crl *x509.RevocationList) *big.Int {
	t.Helper()
	for _, e := range crl.Extensions {
		if e.Id.Equal(oidDeltaCRLIndicatorTest) {
			var n *big.Int
			if _, err := asn1.Unmarshal(e.Value, &n); err != nil {
				t.Fatalf("decoding Delta CRL Indicator: %v", err)
			}
			return n
		}
	}
	t.Fatal("no Delta CRL Indicator extension present")
	return nil
}
