//go:build sqlite

package ca

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// delegationUsageExtValue is the exact DER of the RFC 9345 id-ce-delegationUsage
// extension value: an ASN.1 NULL (05 00).
var delegationUsageExtValue = []byte{0x05, 0x00}

// assertDelegationUsage checks whether a leaf carries the RFC 9345
// id-ce-delegationUsage extension with exactly the expected presence, and — when
// present — that it is non-critical and carries the exact NULL DER.
func assertDelegationUsage(t *testing.T, cert *x509.Certificate, want bool) {
	t.Helper()
	var ext *pkix.Extension
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(pki.OIDDelegationUsage) {
			ext = &cert.Extensions[i]
			break
		}
	}
	if want {
		if ext == nil {
			t.Fatalf("expected id-ce-delegationUsage extension, none present")
		}
		if ext.Critical {
			t.Errorf("delegation usage extension marked critical; RFC 9345 §4.2 requires non-critical")
		}
		if !bytes.Equal(ext.Value, delegationUsageExtValue) {
			t.Errorf("extension value = % x, want % x", ext.Value, delegationUsageExtValue)
		}
		if !pki.HasDelegationUsage(cert) {
			t.Errorf("pki.HasDelegationUsage = false for a leaf carrying the extension")
		}
	} else if ext != nil {
		t.Fatalf("did not expect id-ce-delegationUsage extension, but found value % x", ext.Value)
	}
}

// TestDelegationUsageIssuance proves the built-in server-delegation profile
// stamps the RFC 9345 marker and that a plain server profile does not.
func TestDelegationUsageIssuance(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			mgr := newTestManager(t, mk(t))
			resetCustomProfiles(t)
			root := newRoot(t, mgr, "deleg-"+name)

			issue := func(profile string) *x509.Certificate {
				t.Helper()
				res, err := mgr.IssueCertificate(ctx, IssueSpec{
					CAID:    root.ID,
					CSRPEM:  makeCSR(t, "leaf.example.com", []string{"leaf.example.com"}),
					Profile: profile,
				})
				if err != nil {
					t.Fatalf("IssueCertificate(profile=%s): %v", profile, err)
				}
				return res.Certificate
			}

			assertDelegationUsage(t, issue("server-delegation"), true)
			assertDelegationUsage(t, issue("server"), false)
		})
	}
}

// TestDelegationUsageCustomProfile proves a custom profile can opt into the
// marker and that it is stamped on issuance.
func TestDelegationUsageCustomProfile(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	resetCustomProfiles(t)
	if err := SetCustomProfiles([]Profile{{
		Name:                "deleg-custom",
		KeyUsages:           []string{"digitalSignature"},
		ExtKeyUsages:        []string{"serverAuth"},
		DefaultValidityDays: 90, MaxValidityDays: 90,
		DelegationUsage: true,
	}}); err != nil {
		t.Fatalf("SetCustomProfiles: %v", err)
	}
	root := newRoot(t, mgr, "deleg-custom")
	res, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    root.ID,
		CSRPEM:  makeCSR(t, "leaf.example.com", []string{"leaf.example.com"}),
		Profile: "deleg-custom",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	assertDelegationUsage(t, res.Certificate, true)
}

// TestDelegationUsageMustStapleMutualExclusion covers both halves of the RFC 9345
// §4.2 guard: the static install-time rejection (SetCustomProfiles) and the
// fail-closed runtime chokepoint (applyDelegationUsage).
func TestDelegationUsageMustStapleMutualExclusion(t *testing.T) {
	resetCustomProfiles(t)

	// Static: a profile that sets both, or that merely permits a Must-Staple
	// override alongside delegation usage, is refused at install time.
	staticCases := []struct {
		name    string
		profile Profile
	}{
		{"both-fixed", Profile{
			Name: "bad-both", KeyUsages: []string{"digitalSignature"}, ExtKeyUsages: []string{"serverAuth"},
			DefaultValidityDays: 90, MaxValidityDays: 90, DelegationUsage: true, MustStaple: true,
		}},
		{"delegation-plus-override", Profile{
			Name: "bad-override", KeyUsages: []string{"digitalSignature"}, ExtKeyUsages: []string{"serverAuth"},
			DefaultValidityDays: 90, MaxValidityDays: 90, DelegationUsage: true, AllowMustStapleOverride: true,
		}},
		{"delegation-without-digital-signature", Profile{
			Name: "bad-noku", KeyUsages: []string{"keyEncipherment"}, ExtKeyUsages: []string{"serverAuth"},
			DefaultValidityDays: 90, MaxValidityDays: 90, DelegationUsage: true,
		}},
	}
	for _, tc := range staticCases {
		t.Run("static/"+tc.name, func(t *testing.T) {
			resetCustomProfiles(t)
			if err := SetCustomProfiles([]Profile{tc.profile}); err == nil {
				t.Fatalf("SetCustomProfiles accepted an invalid delegation_usage profile %q", tc.profile.Name)
			}
		})
	}

	// Runtime: applyDelegationUsage refuses to stamp the marker when Must-Staple is
	// also on (defense-in-depth even though the static guard makes it unreachable
	// through configuration), and is a clean no-op when the profile does not opt in.
	t.Run("runtime/guard", func(t *testing.T) {
		p := Profile{Name: "deleg", DelegationUsage: true}
		if _, err := applyDelegationUsage(pki.LeafCertRequest{}, p, true); err == nil {
			t.Fatal("applyDelegationUsage did not reject delegation_usage + Must-Staple")
		}
		out, err := applyDelegationUsage(pki.LeafCertRequest{}, p, false)
		if err != nil {
			t.Fatalf("applyDelegationUsage(mustStaple=false) errored: %v", err)
		}
		if len(out.ExtraExtensions) != 1 || !out.ExtraExtensions[0].Id.Equal(pki.OIDDelegationUsage) {
			t.Fatalf("applyDelegationUsage did not append the delegation-usage extension")
		}
	})
	t.Run("runtime/noop", func(t *testing.T) {
		out, err := applyDelegationUsage(pki.LeafCertRequest{}, Profile{Name: "plain"}, true)
		if err != nil {
			t.Fatalf("applyDelegationUsage no-op errored: %v", err)
		}
		if len(out.ExtraExtensions) != 0 {
			t.Fatalf("applyDelegationUsage appended an extension for a non-delegation profile")
		}
	})
}

// TestDelegationUsageOpenSSLInterop issues a delegation-eligible leaf and confirms
// that `openssl x509 -text` renders the id-ce-delegationUsage extension OID.
func TestDelegationUsageOpenSSLInterop(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH")
	}
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	resetCustomProfiles(t)
	root := newRoot(t, mgr, "deleg-openssl")

	res, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    root.ID,
		CSRPEM:  makeCSR(t, "deleg.example.com", []string{"deleg.example.com"}),
		Profile: "server-delegation",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	assertDelegationUsage(t, res.Certificate, true)

	leafPEM := filepath.Join(t.TempDir(), "leaf.pem")
	if err := os.WriteFile(leafPEM, res.PEM, 0o600); err != nil {
		t.Fatalf("writing leaf: %v", err)
	}
	out, err := exec.Command(openssl, "x509", "-in", leafPEM, "-text", "-noout").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -text: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "1.3.6.1.4.1.44363.44") {
		t.Errorf("openssl output does not mention the delegation-usage OID:\n%s", out)
	}
}
