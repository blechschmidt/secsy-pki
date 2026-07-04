//go:build sqlite

package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// publishedROCAModulusHex is the real CVE-2017-15361 test vector (mod01 from the
// CRoCS roca detector, github.com/crocs-muni/roca). Certifying it must be refused.
const publishedROCAModulusHex = "944e13208a280c37efc31c3114485e590192adbb8e11c87cad60cdef0037ce99278330d3f471a2538fa667802ed2a3c44a8b7dea826e888d0aa341fd664f7fa7"

func rocaPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	n, ok := new(big.Int).SetString(publishedROCAModulusHex, 16)
	if !ok {
		t.Fatal("bad ROCA modulus")
	}
	return &rsa.PublicKey{N: n, E: 65537}
}

// TestKeyQualityGate_FailClosed proves the pre-issuance key-quality gate (Task
// 120, CA/Browser Forum BR §6.1.1.3) rejects weak and compromised subject keys
// BEFORE any HSM signature, across the software provider and — when configured —
// SoftHSM. Each rejection is verified to leave no issued-certificate record and to
// record a cert.keycheck error event, proving the gate is fail-closed: nothing is
// signed and nothing is persisted.
func TestKeyQualityGate_FailClosed(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runKeyQualityGate(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runKeyQualityGate(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()
	root := newRoot(t, mgr, tag)

	// Rejection cases via template-based issuance (raw public key; the gate runs
	// identically to the CSR path). Each must fail with a key-quality error and
	// persist nothing.
	rejectCases := []struct {
		name    string
		pub     *rsa.PublicKey
		wantSub string // substring the error must contain
	}{
		{"roca-vulnerable", rocaPublicKey(t), "roca"},
		{"weak-exponent", &rsa.PublicKey{N: freshModulus(t), E: 3}, keycheck.CodeWeakExponent},
		{"even-exponent", &rsa.PublicKey{N: freshModulus(t), E: 65538}, keycheck.CodeWeakExponent},
	}
	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			before := issuedCount(t, mgr, root.ID)
			_, err := mgr.IssueCertificateFromTemplate(ctx, TemplateIssueSpec{
				CAID:      root.ID,
				Subject:   pkix.Name{CommonName: tc.name + ".keycheck.example"},
				PublicKey: tc.pub,
				Profile:   "server",
			})
			if err == nil {
				t.Fatalf("%s: issuance succeeded, want fail-closed rejection", tc.name)
			}
			if !strings.Contains(err.Error(), "key-quality") || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("%s: error = %q, want a key-quality error mentioning %q", tc.name, err, tc.wantSub)
			}
			if after := issuedCount(t, mgr, root.ID); after != before {
				t.Fatalf("%s: issued-certificate count changed %d -> %d; the gate is NOT fail-closed", tc.name, before, after)
			}
			assertKeyCheckErrorEvent(t, mgr)
		})
	}

	// Operator compromised-key blocklist via the CSR path (a real key with a
	// private half, so a valid CSR can be built): block the fingerprint, then a
	// certificate request bearing that key is refused.
	t.Run("operator-blocklist", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		fp, err := keycheck.Fingerprint(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mgr.db.AddBlockedKey(&models.BlockedKey{Fingerprint: fp, Reason: "test compromise"}); err != nil {
			t.Fatalf("AddBlockedKey: %v", err)
		}
		csr := csrForKey(t, key, "blocked.keycheck.example")
		before := issuedCount(t, mgr, root.ID)
		if _, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: root.ID, CSRPEM: csr, Profile: "server"}); err == nil {
			t.Fatal("issuance with a blocklisted key succeeded, want rejection")
		} else if !strings.Contains(err.Error(), keycheck.CodeBlockedKey) {
			t.Fatalf("error = %q, want a blocked_key rejection", err)
		}
		if after := issuedCount(t, mgr, root.ID); after != before {
			t.Fatalf("blocked-key issuance persisted a record (%d -> %d)", before, after)
		}

		// The same request is reported as a reject by the non-mutating preview,
		// proving the preview and issuance paths share the verdict.
		prev, err := mgr.PreviewIssuance(ctx, PreviewSpec{CAID: root.ID, CSRPEM: csr, Profile: "server"})
		if err != nil {
			t.Fatalf("PreviewIssuance: %v", err)
		}
		if prev.Decision != "reject" {
			t.Fatalf("preview decision = %q, want reject", prev.Decision)
		}
		if v := keycheckGate(t, prev); v.Status != GateFail {
			t.Fatalf("preview keycheck gate status = %q, want fail", v.Status)
		}

		// Un-blocking restores issuance (proving removal takes effect).
		if _, err := mgr.db.RemoveBlockedKey(fp); err != nil {
			t.Fatalf("RemoveBlockedKey: %v", err)
		}
		if _, err := mgr.IssueCertificate(ctx, IssueSpec{CAID: root.ID, CSRPEM: csr, Profile: "server"}); err != nil {
			t.Fatalf("issuance after un-blocking failed: %v", err)
		}
	})

	// Positive control: a healthy RSA-2048 key issues cleanly (the gate does not
	// block good keys).
	t.Run("healthy-key-issues", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mgr.IssueCertificate(ctx, IssueSpec{
			CAID: root.ID, CSRPEM: csrForKey(t, key, "healthy.keycheck.example"), Profile: "server",
		}); err != nil {
			t.Fatalf("healthy key was wrongly rejected: %v", err)
		}
	})
}

// TestKeyQualityGate_WarnAndDuplicate covers the warn-mode escape hatch and the
// opt-in duplicate/reused-subject-key detection, on the software provider.
func TestKeyQualityGate_WarnAndDuplicate(t *testing.T) {
	ctx := context.Background()

	// Warn mode: a compromised key is recorded but not blocked.
	t.Run("warn-mode-does-not-block", func(t *testing.T) {
		if err := SetCustomProfiles([]Profile{{
			Name:            "warn-keychecks",
			KeyUsages:       []string{"digitalSignature"},
			ExtKeyUsages:    []string{"clientAuth"},
			DefaultValidity: 30 * day,
			MaxValidity:     30 * day,
			KeyChecks:       &KeyCheckConfig{Mode: "warn"},
		}}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = SetCustomProfiles(nil) })

		mgr := newTestManager(t, softwareProvider(t))
		root := newRoot(t, mgr, "warn")
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		fp, _ := keycheck.Fingerprint(&key.PublicKey)
		if _, err := mgr.db.AddBlockedKey(&models.BlockedKey{Fingerprint: fp, Reason: "warn test"}); err != nil {
			t.Fatal(err)
		}
		res, err := mgr.IssueCertificate(ctx, IssueSpec{
			CAID: root.ID, CSRPEM: csrForKey(t, key, "warn.example"), Profile: "warn-keychecks",
		})
		if err != nil {
			t.Fatalf("warn mode blocked issuance (should only warn): %v", err)
		}
		if res == nil || res.Certificate == nil {
			t.Fatal("warn mode did not issue a certificate")
		}
		// A warn-mode finding is still audited (as a success-result cert.keycheck).
		events, _, err := mgr.db.ListEvents("cert.keycheck", "", "", 10, 0)
		if err != nil || len(events) == 0 {
			t.Fatalf("warn mode recorded no cert.keycheck audit event (err=%v)", err)
		}
	})

	// Duplicate detection: the same subject key certified for a different subject
	// is flagged when the profile opts in.
	t.Run("duplicate-subject-key", func(t *testing.T) {
		if err := SetCustomProfiles([]Profile{{
			Name:            "dup-keychecks",
			KeyUsages:       []string{"digitalSignature"},
			ExtKeyUsages:    []string{"clientAuth"},
			DefaultValidity: 30 * day,
			MaxValidity:     30 * day,
			KeyChecks:       &KeyCheckConfig{DetectDuplicates: true},
		}}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = SetCustomProfiles(nil) })

		mgr := newTestManager(t, softwareProvider(t))
		root := newRoot(t, mgr, "dup")
		key, _ := rsa.GenerateKey(rand.Reader, 2048)

		// First issuance under subject A succeeds and records the key→subject binding.
		if _, err := mgr.IssueCertificate(ctx, IssueSpec{
			CAID: root.ID, CSRPEM: csrForKey(t, key, "alice.example"), Profile: "dup-keychecks",
		}); err != nil {
			t.Fatalf("first issuance failed: %v", err)
		}
		// Re-using the SAME key for a DIFFERENT subject is rejected.
		if _, err := mgr.IssueCertificate(ctx, IssueSpec{
			CAID: root.ID, CSRPEM: csrForKey(t, key, "bob.example"), Profile: "dup-keychecks",
		}); err == nil {
			t.Fatal("reusing a subject key for a different subject was allowed")
		} else if !strings.Contains(err.Error(), keycheck.CodeDuplicateKey) {
			t.Fatalf("error = %q, want a duplicate_key rejection", err)
		}
		// Re-using the SAME key for the SAME subject (a renewal-shaped request) is
		// fine — it is not a cross-subject reuse.
		if _, err := mgr.IssueCertificate(ctx, IssueSpec{
			CAID: root.ID, CSRPEM: csrForKey(t, key, "alice.example"), Profile: "dup-keychecks",
		}); err != nil {
			t.Fatalf("re-issuing to the same subject was wrongly rejected: %v", err)
		}
	})
}

// --- helpers ---

// freshModulus returns the modulus of a freshly generated RSA-2048 key — a
// healthy 2048-bit odd modulus, so a key built from it trips only the exponent
// check under test (not the modulus checks).
func freshModulus(t *testing.T) *big.Int {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k.N
}

func csrForKey(t *testing.T, key *rsa.PrivateKey, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func issuedCount(t *testing.T, mgr *Manager, caID string) int {
	t.Helper()
	certs, err := mgr.db.ListIssuedCertificates(caID)
	if err != nil {
		t.Fatalf("ListIssuedCertificates: %v", err)
	}
	return len(certs)
}

func assertKeyCheckErrorEvent(t *testing.T, mgr *Manager) {
	t.Helper()
	events, _, err := mgr.db.ListEvents("cert.keycheck", "", "", 20, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	for _, e := range events {
		if e.Result == "error" {
			return
		}
	}
	t.Fatal("no cert.keycheck audit event with an error result was recorded")
}

func keycheckGate(t *testing.T, res *PreviewResult) GateVerdict {
	t.Helper()
	for _, g := range res.Gates {
		if g.Name == GateKeyCheck {
			return g
		}
	}
	t.Fatalf("preview has no %q gate (gates: %v)", GateKeyCheck, res.Gates)
	return GateVerdict{}
}
