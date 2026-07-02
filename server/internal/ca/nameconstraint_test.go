//go:build sqlite

package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/certpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/nameconstraints"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// countNameConstraintEvents returns the number of cert.nameconstraint audit
// events recorded so far.
func countNameConstraintEvents(t *testing.T, m *Manager) int {
	t.Helper()
	events, _, err := m.db.ListEvents(audit.ActionCertNameConstraint, "", "", 1000, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	return len(events)
}

// newConstrainedIntermediate provisions a root and a name-constrained
// intermediate that permits the internal.example.com DNS subtree and the
// 10.0.0.0/8 IP subtree, while excluding secret.internal.example.com. It also
// asserts a certificate policy so policy emission is exercised end-to-end.
func newConstrainedIntermediate(t *testing.T, mgr *Manager, tag string) (*models.CA, *models.CA) {
	t.Helper()
	ctx := context.Background()
	root := newRoot(t, mgr, "nc-"+tag)

	ncCfg := nameconstraints.Config{
		Permitted: nameconstraints.SubtreeConfig{
			DNS: []string{"internal.example.com"},
			IP:  []string{"10.0.0.0/8"},
		},
		Excluded: nameconstraints.SubtreeConfig{
			DNS: []string{"secret.internal.example.com"},
		},
	}
	nc, err := ncCfg.Build()
	if err != nil {
		t.Fatalf("building name constraints: %v", err)
	}
	polCfg := certpolicy.PolicyConfig{OIDs: []string{"1.3.6.1.4.1.99999.7.1"}}
	pol, err := polCfg.Build()
	if err != nil {
		t.Fatalf("building policies: %v", err)
	}

	inter, err := mgr.IssueIntermediate(ctx, IntermediateSpec{
		ParentID:        root.ID,
		Label:           uniqueLabel(t, tag+"-nc-inter"),
		KeyType:         "ecdsa-p256",
		Subject:         PKIXName(models.CASubject{CommonName: "Name-Constrained Intermediate " + tag}),
		Validity:        2 * 365 * 24 * time.Hour,
		NameConstraints: nc,
		Policies:        pol,
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}

	// The emitted intermediate must actually carry the Name Constraints extension.
	interCert := mustParse(t, inter.Certificate)
	if _, ok, err := nameconstraints.FromExtensions(interCert.Extensions); err != nil || !ok {
		t.Fatalf("intermediate is missing a parseable name-constraints extension (ok=%v err=%v)", ok, err)
	}
	return root, inter
}

// TestPreIssuanceNameConstraintGate proves the Name Constraints gate is
// fail-closed over both key providers: a leaf whose SAN/subject is outside the
// issuing CA's permitted subtrees (or inside an excluded subtree) is rejected
// before the HSM signs it, with a cert.nameconstraint audit event, while an
// in-scope leaf issues cleanly.
func TestPreIssuanceNameConstraintGate(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runNameConstraintGate(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runNameConstraintGate(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()
	_, inter := newConstrainedIntermediate(t, mgr, tag)

	withProfiles(t, []Profile{{
		Name:            "nc-server",
		KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
		ExtKeyUsages:    []string{"serverAuth"},
		DefaultValidity: 90 * day,
		MaxValidity:     90 * day,
	}})

	issue := func(cn string, dns []string) (*IssueResult, error) {
		return mgr.IssueCertificate(ctx, IssueSpec{
			CAID:        inter.ID,
			CSRPEM:      makeCSR(t, cn, dns),
			Profile:     "nc-server",
			RequestedBy: "tester",
		})
	}

	// --- In-scope leaf issues cleanly.
	okRes, err := issue("host.internal.example.com", []string{"host.internal.example.com"})
	if err != nil {
		t.Fatalf("in-scope issuance failed: %v", err)
	}
	if okRes.Certificate == nil {
		t.Fatal("expected a certificate for in-scope issuance")
	}

	// --- Out-of-scope DNS name is rejected (not-permitted), fail-closed.
	eventsBefore := countNameConstraintEvents(t, mgr)
	certsBefore := countIssued(t, mgr, inter.ID)
	if _, err := issue("host.evil.com", []string{"host.evil.com"}); err == nil {
		t.Fatal("expected out-of-scope issuance to be rejected")
	} else if !strings.Contains(err.Error(), "name-constraint") {
		t.Fatalf("error should mention the name-constraint gate, got: %v", err)
	}
	if got := countIssued(t, mgr, inter.ID); got != certsBefore {
		t.Fatalf("fail-closed gate must not record a certificate: before=%d after=%d", certsBefore, got)
	}
	if got := countNameConstraintEvents(t, mgr); got != eventsBefore+1 {
		t.Fatalf("expected one new cert.nameconstraint event, got %d (was %d)", got, eventsBefore)
	}

	// --- Excluded subtree is rejected even though it is under the permitted one.
	if _, err := issue("secret.internal.example.com", []string{"secret.internal.example.com"}); err == nil {
		t.Fatal("expected excluded-subtree issuance to be rejected")
	} else if !strings.Contains(err.Error(), "excluded") {
		t.Fatalf("error should identify the exclusion, got: %v", err)
	}

	// --- A CN that is an out-of-scope hostname is caught even with no SAN clash.
	if _, err := issue("host.other.example.net", []string{"host.internal.example.com"}); err == nil {
		t.Fatal("expected an out-of-scope CN hostname to be rejected")
	}
}

// TestRotationPreservesNameConstraints proves an intermediate key rotation
// (Task 24) carries the Name Constraints and certificate-policy extensions
// forward verbatim: the rotated key still emits the constraints and the gate
// still enforces them for issuance directed at the rotated CA.
func TestRotationPreservesNameConstraints(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			mgr := newTestManager(t, mk(t))
			ctx := context.Background()
			_, inter := newConstrainedIntermediate(t, mgr, "rot-"+name)

			rot, err := mgr.RotateIntermediate(ctx, RotateSpec{CAID: inter.ID, RequestedBy: "tester"})
			if err != nil {
				t.Fatalf("RotateIntermediate: %v", err)
			}

			// The rotated certificate must still carry the name constraints and the
			// certificate policy.
			newCert := mustParse(t, rot.NewCA.Certificate)
			nc, ok, err := nameconstraints.FromExtensions(newCert.Extensions)
			if err != nil || !ok {
				t.Fatalf("rotated intermediate lost its name constraints (ok=%v err=%v)", ok, err)
			}
			if len(nc.Permitted.DNS) != 1 || nc.Permitted.DNS[0] != "internal.example.com" {
				t.Fatalf("rotated permitted DNS = %v", nc.Permitted.DNS)
			}
			hasPolicy := false
			for _, e := range newCert.Extensions {
				if e.Id.String() == "2.5.29.32" {
					hasPolicy = true
				}
			}
			if !hasPolicy {
				t.Fatal("rotated intermediate lost its certificate-policies extension")
			}

			withProfiles(t, []Profile{{
				Name:            "rot-nc",
				KeyUsages:       []string{"digitalSignature"},
				ExtKeyUsages:    []string{"serverAuth"},
				DefaultValidity: 30 * day,
				MaxValidity:     30 * day,
			}})

			// Issuance directed at the (now-superseded) original id routes to the
			// active successor and is still gated by the preserved constraints.
			if _, err := mgr.IssueCertificate(ctx, IssueSpec{
				CAID:    inter.ID,
				CSRPEM:  makeCSR(t, "svc.internal.example.com", []string{"svc.internal.example.com"}),
				Profile: "rot-nc",
			}); err != nil {
				t.Fatalf("in-scope issuance under rotated CA failed: %v", err)
			}
			if _, err := mgr.IssueCertificate(ctx, IssueSpec{
				CAID:    inter.ID,
				CSRPEM:  makeCSR(t, "svc.evil.com", []string{"svc.evil.com"}),
				Profile: "rot-nc",
			}); err == nil {
				t.Fatal("out-of-scope issuance under rotated CA should be rejected")
			}
		})
	}
}

// countIssued returns how many certificates a CA has recorded.
func countIssued(t *testing.T, m *Manager, caID string) int {
	t.Helper()
	certs, err := m.db.ListIssuedCertificates(caID)
	if err != nil {
		t.Fatalf("ListIssuedCertificates: %v", err)
	}
	return len(certs)
}

// TestNameConstraintOpenSSLVerify builds a name-constrained intermediate on the
// HSM (SoftHSM via the pkcs11 provider) and confirms the reference `openssl
// verify` client — which independently enforces RFC 5280 name constraints —
// accepts an in-scope leaf and rejects an out-of-scope leaf signed by the same
// constrained intermediate. The out-of-scope leaf is minted directly (bypassing
// the pre-issuance gate) precisely so OpenSSL, not our own gate, is the one
// enforcing the constraint here.
func TestNameConstraintOpenSSLVerify(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH")
	}
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			mgr := newTestManager(t, mk(t))
			ctx := context.Background()
			root, inter := newConstrainedIntermediate(t, mgr, name)

			withProfiles(t, []Profile{{
				Name:            "nc-openssl",
				KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
				ExtKeyUsages:    []string{"serverAuth"},
				DefaultValidity: 90 * day,
				MaxValidity:     90 * day,
			}})

			dir := t.TempDir()
			rootPEM := filepath.Join(dir, "root.pem")
			interPEM := filepath.Join(dir, "inter.pem")
			writeFile(t, rootPEM, []byte(root.Certificate))
			writeFile(t, interPEM, []byte(inter.Certificate))

			// In-scope leaf, issued through the full gated path.
			okRes, err := mgr.IssueCertificate(ctx, IssueSpec{
				CAID:        inter.ID,
				CSRPEM:      makeCSR(t, "web.internal.example.com", []string{"web.internal.example.com"}),
				Profile:     "nc-openssl",
				RequestedBy: "tester",
			})
			if err != nil {
				t.Fatalf("in-scope issuance failed: %v", err)
			}
			okLeafPEM := filepath.Join(dir, "leaf-ok.pem")
			writeFile(t, okLeafPEM, okRes.PEM)

			// openssl must accept the in-scope leaf: this proves the emitted
			// name-constraints extension is well-formed AND the leaf is genuinely
			// within it according to a real path validator.
			if out, err := opensslVerifyNC(openssl, rootPEM, interPEM, okLeafPEM); err != nil {
				t.Fatalf("openssl rejected an in-scope leaf that should validate:\n%s\n%v", out, err)
			}

			// Out-of-scope leaf, signed directly by the constrained intermediate so
			// OpenSSL is the enforcer.
			badLeafPEM := filepath.Join(dir, "leaf-bad.pem")
			writeFile(t, badLeafPEM, mintOutOfScopeLeaf(t, ctx, mgr, inter))

			out, err := opensslVerifyNC(openssl, rootPEM, interPEM, badLeafPEM)
			if err == nil {
				t.Fatalf("openssl accepted an out-of-scope leaf though the intermediate's name constraints forbid it:\n%s", out)
			}
			if !strings.Contains(strings.ToLower(out), "constraint") && !strings.Contains(strings.ToLower(out), "excluded") && !strings.Contains(strings.ToLower(out), "permitted") {
				t.Fatalf("openssl rejected the leaf but not for a name-constraint reason:\n%s", out)
			}
		})
	}
}

// opensslVerifyNC runs `openssl verify` with the root as the trust anchor and the
// intermediate supplied untrusted, so name-constraint checking on the leaf is
// exercised. It returns combined output and the process error.
func opensslVerifyNC(openssl, rootPEM, interPEM, leafPEM string) (string, error) {
	out, err := exec.Command(openssl, "verify",
		"-CAfile", rootPEM,
		"-untrusted", interPEM,
		leafPEM,
	).CombinedOutput()
	return string(out), err
}

// mintOutOfScopeLeaf signs a leaf with an out-of-scope DNS SAN directly under the
// constrained intermediate's HSM key, deliberately bypassing the pre-issuance
// gate so the resulting certificate exists for OpenSSL to reject.
func mintOutOfScopeLeaf(t *testing.T, ctx context.Context, mgr *Manager, inter *models.CA) []byte {
	t.Helper()
	interCert := mustParse(t, inter.Certificate)
	signer, err := mgr.provider.Signer(ctx, keyRefForCA(inter))
	if err != nil {
		t.Fatalf("opening intermediate signer: %v", err)
	}
	defer signer.Close()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	der, err := pki.CreateLeafCertificate(signer, interCert, pki.LeafCertRequest{
		Subject:     pkix.Name{CommonName: "host.evil.com"},
		PublicKey:   &key.PublicKey,
		Serial:      big.NewInt(0xBADBEEF),
		NotBefore:   now.Add(-time.Hour),
		NotAfter:    now.Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"host.evil.com"},
	})
	if err != nil {
		t.Fatalf("directly signing out-of-scope leaf: %v", err)
	}
	return pki.EncodeCertificatePEM(der)
}
