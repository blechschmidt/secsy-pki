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
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// makeEmailCSR builds a PEM CSR carrying rfc822Name SANs, signed by the given
// subject key (the subscriber's key — always software-held in these tests; only
// the CA key lives on the provider/HSM).
func makeEmailCSR(t *testing.T, key crypto.Signer, cn string, emails []string) []byte {
	t.Helper()
	tmpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: cn},
		EmailAddresses: emails,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// withTenantEmailDomains installs a per-tenant e-mail domain scoping for the
// duration of a test, restoring the previous registry afterwards.
func withTenantEmailDomains(t *testing.T, domains map[string][]string) {
	t.Helper()
	prev := tenantEmailDomains
	if err := SetTenantEmailDomains(domains); err != nil {
		t.Fatalf("SetTenantEmailDomains: %v", err)
	}
	t.Cleanup(func() { tenantEmailDomains = prev })
}

// countEvents returns the number of audit events with the given action and
// result recorded so far.
func countEvents(t *testing.T, m *Manager, action, result string) int {
	t.Helper()
	events, _, err := m.db.ListEvents(action, "", "", 1000, 0)
	if err != nil {
		t.Fatalf("ListEvents: %v", err)
	}
	n := 0
	for _, e := range events {
		if e.Result == result {
			n++
		}
	}
	return n
}

// TestSMIMEIssuance is the Task 66 acceptance test for the S/MIME profile
// family. It proves, against both the software provider and SoftHSM:
//
//   - a sign+encrypt pair issues with the correct KU split and an
//     emailProtection-only EKU;
//   - rfc822Name SANs are validated and normalized (case folding, punycode,
//     de-duplication) before signing;
//   - the lint gate rejects SAN-less and serverAuth-mixed requests fail-closed
//     (nothing signed or recorded), gradable to warn per profile;
//   - profile and tenant domain allowlists block out-of-scope mailboxes with a
//     cert.smime audit event;
//   - renewal preserves the normalized identity, and revocation/CRL work
//     unchanged for S/MIME certificates.
func TestSMIMEIssuance(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runSMIMEIssuance(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runSMIMEIssuance(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()
	root := newRoot(t, mgr, "smime-"+tag)
	signKey, encKey := rsaKey(t), rsaKey(t)

	// --- Sign + encrypt pair with the correct usage split -------------------
	signRes, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeEmailCSR(t, signKey, "Alice Example", []string{"alice@example.com"}),
		Profile:     "smime-sign",
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("issuing smime-sign certificate: %v", err)
	}
	encRes, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeEmailCSR(t, encKey, "Alice Example", []string{"alice@example.com"}),
		Profile:     "smime-encrypt",
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("issuing smime-encrypt certificate: %v", err)
	}

	signCert, encCert := signRes.Certificate, encRes.Certificate
	if signCert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("sign cert KU = %v, want digitalSignature only", signCert.KeyUsage)
	}
	if encCert.KeyUsage != x509.KeyUsageKeyEncipherment {
		t.Errorf("encrypt cert KU = %v, want keyEncipherment only", encCert.KeyUsage)
	}
	for _, c := range []*x509.Certificate{signCert, encCert} {
		if len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageEmailProtection {
			t.Errorf("EKU = %v, want exactly emailProtection", c.ExtKeyUsage)
		}
		if len(c.EmailAddresses) != 1 || c.EmailAddresses[0] != "alice@example.com" {
			t.Errorf("SAN = %v, want [alice@example.com]", c.EmailAddresses)
		}
		if len(c.DNSNames)+len(c.IPAddresses)+len(c.URIs) != 0 {
			t.Errorf("S/MIME cert must carry only rfc822Name SANs, got DNS=%v IP=%v URI=%v",
				c.DNSNames, c.IPAddresses, c.URIs)
		}
	}

	// --- Normalization: case folding + de-duplication (CSR path) ------------
	// A CSR's rfc822Name is IA5String, so a standards-compliant client can only
	// send ASCII here; uppercase A-labels and domain case are still normalized.
	dualKey := rsaKey(t)
	normRes, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID: root.ID,
		CSRPEM: makeEmailCSR(t, dualKey, "Postmaster", []string{
			"Postmaster@XN--BCHER-KVA.Example", // uppercase A-label domain
			"Postmaster@xn--bcher-kva.example", // duplicate after normalization
		}),
		Profile:     "smime",
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("issuing with unnormalized addresses: %v", err)
	}
	got := normRes.Certificate.EmailAddresses
	if len(got) != 1 || got[0] != "Postmaster@xn--bcher-kva.example" {
		t.Fatalf("normalized SANs = %v, want [Postmaster@xn--bcher-kva.example]", got)
	}
	// The stored inventory record carries the normalized SAN too.
	if rec := normRes.Record; len(rec.SANs) != 1 || rec.SANs[0] != "Postmaster@xn--bcher-kva.example" {
		t.Fatalf("recorded SANs = %v, want the normalized address", normRes.Record.SANs)
	}

	// --- IDN punycode via the template path (CMP-shaped requests) -----------
	// Template-based issuance takes EmailAddresses directly, so an
	// internationalized U-label domain can arrive here; the gate folds it to
	// its A-label form, which IS encodable as IA5String.
	idnRes, err := mgr.IssueCertificateFromTemplate(ctx, TemplateIssueSpec{
		CAID:           root.ID,
		Subject:        pkix.Name{CommonName: "Postmaster IDN"},
		PublicKey:      dualKey.Public(),
		EmailAddresses: []string{"post@bücher.example"},
		Profile:        "smime",
		RequestedBy:    "tester",
	})
	if err != nil {
		t.Fatalf("template issuance with a U-label domain: %v", err)
	}
	if got := idnRes.Certificate.EmailAddresses; len(got) != 1 || got[0] != "post@xn--bcher-kva.example" {
		t.Fatalf("punycoded SANs = %v, want [post@xn--bcher-kva.example]", got)
	}

	// --- Malformed address is rejected by the gate (fail-closed) ------------
	failBefore := countEvents(t, mgr, audit.ActionCertSMIME, audit.ResultError)
	_, err = mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeEmailCSR(t, dualKey, "Bad", []string{"not an address"}),
		Profile:     "smime",
		RequestedBy: "tester",
	})
	if err == nil || !strings.Contains(err.Error(), "S/MIME") {
		t.Fatalf("expected the S/MIME gate to reject a malformed address, got: %v", err)
	}
	if got := countEvents(t, mgr, audit.ActionCertSMIME, audit.ResultError); got != failBefore+1 {
		t.Fatalf("expected one new cert.smime error event, got %d (was %d)", got, failBefore)
	}

	// --- Lint gate: SAN-less request rejected, nothing signed ---------------
	certsBefore, err := mgr.db.ListIssuedCertificates(root.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, err = mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeEmailCSR(t, dualKey, "No Address Here", nil),
		Profile:     "smime",
		RequestedBy: "tester",
	})
	if err == nil || !strings.Contains(err.Error(), "smime_san_present") {
		t.Fatalf("expected smime_san_present rejection for SAN-less request, got: %v", err)
	}
	// --- Lint gate: EC subject key cannot carry keyEncipherment -------------
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeEmailCSR(t, ecKey, "EC Alice", []string{"alice@example.com"}),
		Profile:     "smime",
		RequestedBy: "tester",
	})
	if err == nil || !strings.Contains(err.Error(), "smime_key_usage") {
		t.Fatalf("expected smime_key_usage rejection for an EC key under the RSA dual-use profile, got: %v", err)
	}
	if after, _ := mgr.db.ListIssuedCertificates(root.ID); len(after) != len(certsBefore) {
		t.Fatalf("blocked issuances must not record certificates: %d -> %d", len(certsBefore), len(after))
	}

	// --- serverAuth mixing blocked under enforce, gradable to warn ----------
	withProfiles(t, []Profile{
		{
			Name:            "smime-mixed",
			KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:    []string{"emailProtection", "serverAuth"},
			DefaultValidity: 365 * day,
			MaxValidity:     2 * 365 * day,
			SMIME:           &SMIMEConfig{},
		},
		{
			Name:            "smime-mixed-warn",
			KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:    []string{"emailProtection", "serverAuth"},
			DefaultValidity: 365 * day,
			MaxValidity:     2 * 365 * day,
			SMIME:           &SMIMEConfig{},
			Lint:            &LintConfig{Overrides: map[string]string{"smime_eku": "warn"}},
		},
		{
			Name:            "smime-corp",
			KeyUsages:       []string{"digitalSignature", "keyEncipherment"},
			ExtKeyUsages:    []string{"emailProtection"},
			DefaultValidity: 365 * day,
			MaxValidity:     2 * 365 * day,
			SMIME:           &SMIMEConfig{AllowedDomains: []string{"corp.example", "*.corp.example"}, SubjectEmail: true},
		},
	})

	_, err = mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeEmailCSR(t, dualKey, "Mixed", []string{"alice@example.com"}),
		Profile:     "smime-mixed",
		RequestedBy: "tester",
	})
	if err == nil || !strings.Contains(err.Error(), "smime_eku") {
		t.Fatalf("expected smime_eku rejection for serverAuth mixing, got: %v", err)
	}
	warned, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeEmailCSR(t, dualKey, "Mixed Warn", []string{"alice@example.com"}),
		Profile:     "smime-mixed-warn",
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("warn-graded serverAuth mixing should issue: %v", err)
	}
	if len(warned.Certificate.ExtKeyUsage) != 2 {
		t.Fatalf("warn-graded certificate should keep its configured EKUs, got %v", warned.Certificate.ExtKeyUsage)
	}

	// --- Profile domain allowlist + subject emailAddress mirroring ----------
	_, err = mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeEmailCSR(t, dualKey, "Outsider", []string{"bob@evil.example"}),
		Profile:     "smime-corp",
		RequestedBy: "tester",
	})
	if err == nil || !strings.Contains(err.Error(), "not permitted by profile") {
		t.Fatalf("expected the profile allowlist to reject bob@evil.example, got: %v", err)
	}
	corpRes, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeEmailCSR(t, dualKey, "Carol Corp", []string{"carol@mail.corp.example"}),
		Profile:     "smime-corp",
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("allowlisted issuance failed: %v", err)
	}
	foundSubjectEmail := false
	for _, atv := range corpRes.Certificate.Subject.Names {
		if atv.Type.Equal(oidEmailAddress) {
			foundSubjectEmail = true
			if s, ok := atv.Value.(string); !ok || s != "carol@mail.corp.example" {
				t.Fatalf("subject emailAddress = %v, want carol@mail.corp.example", atv.Value)
			}
		}
	}
	if !foundSubjectEmail {
		t.Fatal("subject_email profile should mirror the address into the subject DN")
	}

	// --- Tenant scoping ------------------------------------------------------
	withTenantEmailDomains(t, map[string][]string{
		models.DefaultTenantID: {"tenant.example"},
	})
	_, err = mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeEmailCSR(t, dualKey, "Cross Tenant", []string{"alice@example.com"}),
		Profile:     "smime",
		RequestedBy: "tester",
	})
	if err == nil || !strings.Contains(err.Error(), "not permitted for tenant") {
		t.Fatalf("expected the tenant allowlist to reject alice@example.com, got: %v", err)
	}
	tenantRes, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeEmailCSR(t, dualKey, "In Tenant", []string{"dave@tenant.example"}),
		Profile:     "smime",
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("tenant-scoped issuance failed: %v", err)
	}
	withTenantEmailDomains(t, nil) // clear for the rest of the test

	// --- Renewal preserves the normalized identity ---------------------------
	renewed, err := mgr.RenewCertificate(ctx, RenewSpec{
		CAID:        root.ID,
		Serial:      normRes.Serial.String(),
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("renewing S/MIME certificate: %v", err)
	}
	if got := renewed.Certificate.EmailAddresses; len(got) != 1 || got[0] != "Postmaster@xn--bcher-kva.example" {
		t.Fatalf("renewed SANs = %v, want the original normalized address", got)
	}

	// --- Revocation and CRL are unchanged for S/MIME leaves ------------------
	applied, err := mgr.RevokeCertificate(ctx, root.ID, tenantRes.Serial.String(), "keyCompromise")
	if err != nil || !applied {
		t.Fatalf("revoking S/MIME certificate: applied=%v err=%v", applied, err)
	}
	crlDER, err := mgr.GenerateCRL(ctx, root.ID)
	if err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("parsing CRL: %v", err)
	}
	foundRevoked := false
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(tenantRes.Serial) == 0 {
			foundRevoked = true
		}
	}
	if !foundRevoked {
		t.Fatal("revoked S/MIME certificate serial missing from the CRL")
	}
}

// TestSMIMEOpenSSLInterop issues a sign+encrypt pair and proves interop with
// openssl's S/MIME implementation: a message signed with the issued signing
// certificate verifies (including chain and purpose checks), and a message
// encrypted to the issued encryption certificate decrypts with its key. Runs
// against both the software provider and SoftHSM; skipped when the openssl
// binary is unavailable.
func TestSMIMEOpenSSLInterop(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl binary not available")
	}
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runSMIMEOpenSSL(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runSMIMEOpenSSL(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()
	root := newRoot(t, mgr, "smime-ossl-"+tag)
	dir := t.TempDir()

	writeFile := func(name string, data []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	openssl := func(args ...string) (string, error) {
		t.Helper()
		out, err := exec.Command("openssl", args...).CombinedOutput()
		return string(out), err
	}

	issue := func(profile string, key *rsa.PrivateKey) *IssueResult {
		t.Helper()
		res, err := mgr.IssueCertificate(ctx, IssueSpec{
			CAID:        root.ID,
			CSRPEM:      makeEmailCSR(t, key, "Alice Example", []string{"alice@example.com"}),
			Profile:     profile,
			RequestedBy: "tester",
		})
		if err != nil {
			t.Fatalf("issuing %s certificate: %v", profile, err)
		}
		return res
	}
	keyPEM := func(key *rsa.PrivateKey) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}

	signKey, encKey := rsaKey(t), rsaKey(t)
	signRes := issue("smime-sign", signKey)
	encRes := issue("smime-encrypt", encKey)

	caPath := writeFile("ca.pem", []byte(root.Certificate))
	signCertPath := writeFile("sign.crt", signRes.PEM)
	signKeyPath := writeFile("sign.key", keyPEM(signKey))
	encCertPath := writeFile("enc.crt", encRes.PEM)
	encKeyPath := writeFile("enc.key", keyPEM(encKey))
	msgPath := writeFile("msg.txt", []byte("Subject: interop\n\nHello S/MIME from secsy-pki.\n"))

	// Sign → verify round trip. openssl smime -verify applies the smimesign
	// purpose: it checks the signer's emailProtection EKU and digitalSignature
	// KU as well as the chain to the (HSM-backed) root — a full interop proof.
	signedPath := filepath.Join(dir, "msg.p7s")
	if out, err := openssl("smime", "-sign",
		"-in", msgPath, "-out", signedPath, "-text",
		"-signer", signCertPath, "-inkey", signKeyPath); err != nil {
		t.Fatalf("openssl smime -sign failed: %v\n%s", err, out)
	}
	if out, err := openssl("smime", "-verify", "-in", signedPath, "-CAfile", caPath); err != nil {
		t.Fatalf("openssl smime -verify failed: %v\n%s", err, out)
	}

	// A signature by a NON-signing (encryption-profile) certificate must fail
	// the purpose check — proving the KU split is meaningful to relying parties.
	wrongPath := filepath.Join(dir, "wrong.p7s")
	if out, err := openssl("smime", "-sign",
		"-in", msgPath, "-out", wrongPath, "-text",
		"-signer", encCertPath, "-inkey", encKeyPath); err != nil {
		// Newer openssl refuses at signing time; that also proves the split.
		t.Logf("openssl refused to sign with the encryption certificate (ok): %s", out)
	} else if out, err := openssl("smime", "-verify", "-in", wrongPath, "-CAfile", caPath); err == nil {
		t.Fatalf("verification with the encryption-only certificate should fail the purpose check\n%s", out)
	}

	// Encrypt → decrypt round trip against the encryption certificate. -binary
	// skips MIME text canonicalization so the payload round-trips byte-exact.
	encryptedPath := filepath.Join(dir, "msg.p7m")
	if out, err := openssl("smime", "-encrypt", "-aes-128-cbc", "-binary",
		"-in", msgPath, "-out", encryptedPath, encCertPath); err != nil {
		t.Fatalf("openssl smime -encrypt failed: %v\n%s", err, out)
	}
	decryptedPath := filepath.Join(dir, "msg.dec")
	if out, err := openssl("smime", "-decrypt", "-binary",
		"-in", encryptedPath, "-out", decryptedPath,
		"-recip", encCertPath, "-inkey", encKeyPath); err != nil {
		t.Fatalf("openssl smime -decrypt failed: %v\n%s", err, out)
	}
	plain, err := os.ReadFile(msgPath)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := os.ReadFile(decryptedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(plain) {
		t.Fatalf("decrypted message differs from the original:\n%q\nvs\n%q", decrypted, plain)
	}

	// The issued pair also verifies with Go's verifier for good measure.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(root.Certificate)) {
		t.Fatal("appending root to pool")
	}
	for _, c := range []*x509.Certificate{signRes.Certificate, encRes.Certificate} {
		if _, err := c.Verify(x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
			// Validate at a fixed point inside the validity window.
			CurrentTime: c.NotBefore.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Go chain verification failed: %v", err)
		}
	}
}
