//go:build sqlite

package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// makeCNCSR builds a minimal PEM CSR carrying only a common name — the UPN is
// supplied out-of-band on the IssueSpec (as the REST/gRPC/CLI paths do), not in
// the CSR.
func makeCNCSR(t *testing.T, key crypto.Signer, cn string) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// withTenantUPNRealms installs a per-tenant UPN realm scoping for the duration
// of a test, restoring the previous registry afterwards.
func withTenantUPNRealms(t *testing.T, realms map[string][]string) {
	t.Helper()
	prev := tenantUPNRealms
	if err := SetTenantUPNRealms(realms); err != nil {
		t.Fatalf("SetTenantUPNRealms: %v", err)
	}
	t.Cleanup(func() { tenantUPNRealms = prev })
}

func hasEKU(cert *x509.Certificate, eku x509.ExtKeyUsage) bool {
	for _, e := range cert.ExtKeyUsage {
		if e == eku {
			return true
		}
	}
	return false
}

func hasUnknownEKU(cert *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, o := range cert.UnknownExtKeyUsage {
		if o.Equal(oid) {
			return true
		}
	}
	return false
}

func TestUPNIssuance(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runUPNIssuance(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runUPNIssuance(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()
	root := newRoot(t, mgr, "upn-"+tag)

	// --- smartcard-logon: UPN otherName + msSmartcardLogon/clientAuth EKU -------
	res, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeCNCSR(t, rsaKey(t), "Alice Example"),
		Profile:     "smartcard-logon",
		UPNs:        []string{"alice@EXAMPLE.COM"},
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("issuing smartcard-logon certificate: %v", err)
	}
	cert := res.Certificate
	if cert.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("smartcard KU = %v, want digitalSignature only", cert.KeyUsage)
	}
	if !hasEKU(cert, x509.ExtKeyUsageClientAuth) {
		t.Errorf("smartcard cert missing clientAuth EKU: %v", cert.ExtKeyUsage)
	}
	if !hasUnknownEKU(cert, pki.OIDExtKeyUsageMSSmartcardLogon) {
		t.Errorf("smartcard cert missing msSmartcardLogon EKU: %v", cert.UnknownExtKeyUsage)
	}
	if got := pki.UPNsFromCertificate(cert); len(got) != 1 || got[0] != "alice@EXAMPLE.COM" {
		t.Fatalf("UPN SAN = %v, want [alice@EXAMPLE.COM]", got)
	}
	// The stored inventory record records the UPN (as upn:<value>).
	if rec := res.Record; !containsStr(rec.SANs, "upn:alice@EXAMPLE.COM") {
		t.Errorf("recorded SANs = %v, want to include upn:alice@EXAMPLE.COM", res.Record.SANs)
	}
	// crypto/x509 must parse the leaf without error (proven by the ParseCertificate
	// in issueLeaf succeeding) and must not surface the otherName on a typed field.
	if len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.URIs)+len(cert.IPAddresses) != 0 {
		t.Errorf("a UPN-only smartcard cert should have no typed SANs, got DNS=%v email=%v", cert.DNSNames, cert.EmailAddresses)
	}

	// --- pkinit-client: pkinitClientAuth EKU -----------------------------------
	pkRes, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeCNCSR(t, rsaKey(t), "Bob Example"),
		Profile:     "pkinit-client",
		UPNs:        []string{"bob@corp.example.com"},
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("issuing pkinit-client certificate: %v", err)
	}
	if !hasUnknownEKU(pkRes.Certificate, pki.OIDExtKeyUsagePKINITClientAuth) {
		t.Errorf("pkinit cert missing pkinitClientAuth EKU: %v", pkRes.Certificate.UnknownExtKeyUsage)
	}

	// --- multiple UPNs, deduped & preserved ------------------------------------
	multiRes, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeCNCSR(t, rsaKey(t), "Multi"),
		Profile:     "smartcard-pkinit",
		UPNs:        []string{"a@EXAMPLE.COM", "b@EXAMPLE.COM", "A@example.com"}, // last dups a@ (case)
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("issuing with multiple UPNs: %v", err)
	}
	if got := pki.UPNsFromCertificate(multiRes.Certificate); len(got) != 2 {
		t.Errorf("multi-UPN cert has %d UPNs, want 2 (deduped): %v", len(got), got)
	}

	// --- template path (CMP-shaped) carries a UPN ------------------------------
	tmplRes, err := mgr.IssueCertificateFromTemplate(ctx, TemplateIssueSpec{
		CAID:        root.ID,
		Subject:     pkix.Name{CommonName: "Template User"},
		PublicKey:   rsaKey(t).Public(),
		Profile:     "smartcard-logon",
		UPNs:        []string{"tmpl@EXAMPLE.COM"},
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("template issuance with a UPN: %v", err)
	}
	if got := pki.UPNsFromCertificate(tmplRes.Certificate); len(got) != 1 || got[0] != "tmpl@EXAMPLE.COM" {
		t.Fatalf("template UPN SAN = %v, want [tmpl@EXAMPLE.COM]", got)
	}

	// --- renewal preserves the UPN ---------------------------------------------
	renewed, err := mgr.RenewCertificate(ctx, RenewSpec{
		CAID:        root.ID,
		Serial:      res.Serial.String(),
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("renewing smartcard cert: %v", err)
	}
	if got := pki.UPNsFromCertificate(renewed.Certificate); len(got) != 1 || got[0] != "alice@EXAMPLE.COM" {
		t.Fatalf("renewed UPN SAN = %v, want [alice@EXAMPLE.COM] preserved", got)
	}
	if !hasUnknownEKU(renewed.Certificate, pki.OIDExtKeyUsageMSSmartcardLogon) {
		t.Errorf("renewed cert dropped the smartcard EKU: %v", renewed.Certificate.UnknownExtKeyUsage)
	}
}

// TestUPNGateRejections exercises the fail-closed conditions of the UPN gate.
func TestUPNGateRejections(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "upn-reject")

	mustFail := func(name string, spec IssueSpec, want string) {
		t.Helper()
		_, err := mgr.IssueCertificate(ctx, spec)
		if err == nil {
			t.Fatalf("%s: expected issuance to be rejected", name)
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error = %q, want it to mention %q", name, err, want)
		}
	}

	// A smartcard-logon profile requires a UPN.
	mustFail("missing required UPN", IssueSpec{
		CAID: root.ID, CSRPEM: makeCNCSR(t, rsaKey(t), "NoUPN"),
		Profile: "smartcard-logon", RequestedBy: "tester",
	}, "requires a User Principal Name")

	// A UPN on a non-UPN profile is refused.
	mustFail("UPN on non-UPN profile", IssueSpec{
		CAID: root.ID, CSRPEM: makeCNCSR(t, rsaKey(t), "Client"),
		Profile: "client", UPNs: []string{"x@EXAMPLE.COM"}, RequestedBy: "tester",
	}, "does not permit User Principal Name")

	// A malformed UPN is refused.
	mustFail("malformed UPN", IssueSpec{
		CAID: root.ID, CSRPEM: makeCNCSR(t, rsaKey(t), "Bad"),
		Profile: "smartcard-logon", UPNs: []string{"not-a-upn"}, RequestedBy: "tester",
	}, "UPN check failed")

	// A blocked UPN issuance appends a cert.upn audit event.
	if n := countEvents(t, mgr, "cert.upn", "error"); n == 0 {
		t.Error("expected at least one cert.upn error audit event from the rejections above")
	}
}

// TestUPNRealmAllowlists proves both the profile-level and tenant-level realm
// scoping, analogous to the S/MIME e-mail domain scoping (Task 66).
func TestUPNRealmAllowlists(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "upn-allow")

	// --- profile-level allowed_realms ------------------------------------------
	t.Cleanup(func() { customProfiles = map[string]Profile{} })
	if err := SetCustomProfiles([]Profile{{
		Name:         "sc-scoped",
		KeyUsages:    []string{"digitalSignature"},
		ExtKeyUsages: []string{"clientAuth", "msSmartcardLogon"},
		UPN:          &UPNConfig{AllowedRealms: []string{"CORP.EXAMPLE.NET"}, RequireUPN: true},
	}}); err != nil {
		t.Fatalf("SetCustomProfiles: %v", err)
	}

	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID: root.ID, CSRPEM: makeCNCSR(t, rsaKey(t), "InRealm"),
		Profile: "sc-scoped", UPNs: []string{"alice@CORP.EXAMPLE.NET"}, RequestedBy: "tester",
	}); err != nil {
		t.Fatalf("issuance within the profile realm allowlist should succeed: %v", err)
	}
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID: root.ID, CSRPEM: makeCNCSR(t, rsaKey(t), "OutRealm"),
		Profile: "sc-scoped", UPNs: []string{"alice@OTHER.NET"}, RequestedBy: "tester",
	}); err == nil {
		t.Fatal("issuance outside the profile realm allowlist should be rejected")
	}

	// --- tenant-level allowed_upn_realms (default tenant) ----------------------
	withTenantUPNRealms(t, map[string][]string{"default": {"EXAMPLE.COM"}})
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID: root.ID, CSRPEM: makeCNCSR(t, rsaKey(t), "TenantIn"),
		Profile: "smartcard-logon", UPNs: []string{"user@EXAMPLE.COM"}, RequestedBy: "tester",
	}); err != nil {
		t.Fatalf("issuance within the tenant realm allowlist should succeed: %v", err)
	}
	if _, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID: root.ID, CSRPEM: makeCNCSR(t, rsaKey(t), "TenantOut"),
		Profile: "smartcard-logon", UPNs: []string{"user@ELSEWHERE.COM"}, RequestedBy: "tester",
	}); err == nil {
		t.Fatal("issuance outside the tenant realm allowlist should be rejected")
	}
}

// TestUPNOpenSSLInterop issues a real smartcard-logon certificate and confirms
// `openssl x509 -text` decodes the UPN otherName and the smartcard EKU.
func TestUPNOpenSSLInterop(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "upn-ossl")

	res, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:        root.ID,
		CSRPEM:      makeCNCSR(t, rsaKey(t), "Interop User"),
		Profile:     "smartcard-pkinit",
		UPNs:        []string{"interop@EXAMPLE.COM"},
		RequestedBy: "tester",
	})
	if err != nil {
		t.Fatalf("issuing certificate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "leaf.pem")
	if err := os.WriteFile(path, res.PEM, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("openssl", "x509", "-in", path, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -text: %v\n%s", err, out)
	}
	text := string(out)
	for _, want := range []string{"othername", "interop@EXAMPLE.COM", "Microsoft Smartcard Login"} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl output missing %q:\n%s", want, text)
		}
	}
	if !strings.Contains(text, "1.3.6.1.5.2.3.4") && !strings.Contains(strings.ToLower(text), "pkinit") {
		t.Errorf("openssl output missing the PKINIT EKU:\n%s", text)
	}
}

func containsStr(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
