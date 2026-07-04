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
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

func boolPtr(b bool) *bool { return &b }

// mustStapleExtValue is the exact DER of the RFC 7633 Must-Staple TLS Feature
// extension value: SEQUENCE { INTEGER 5 } (status_request).
var mustStapleExtValue = []byte{0x30, 0x03, 0x02, 0x01, 0x05}

// assertMustStaple checks whether a leaf carries the RFC 7633 TLS Feature /
// Must-Staple extension with exactly the expected presence, and — when present —
// that it is non-critical and carries the exact status_request DER.
func assertMustStaple(t *testing.T, cert *x509.Certificate, want bool) {
	t.Helper()
	var ext *pkix.Extension
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(pki.OIDTLSFeature) {
			ext = &cert.Extensions[i]
			break
		}
	}
	if want {
		if ext == nil {
			t.Fatalf("expected id-pe-tlsfeature (Must-Staple) extension, none present")
		}
		if ext.Critical {
			t.Errorf("Must-Staple extension marked critical; RFC 7633 requires non-critical")
		}
		if !bytes.Equal(ext.Value, mustStapleExtValue) {
			t.Errorf("extension value = % x, want % x", ext.Value, mustStapleExtValue)
		}
	} else if ext != nil {
		t.Fatalf("did not expect id-pe-tlsfeature extension, but found value % x", ext.Value)
	}
}

// registerMustStapleProfiles installs the serverAuth profile matrix used by the
// override tests and restores the empty overlay afterward.
func registerMustStapleProfiles(t *testing.T) {
	t.Helper()
	resetCustomProfiles(t)
	profiles := []Profile{
		{Name: "ms-on-override", KeyUsages: []string{"digitalSignature"}, ExtKeyUsages: []string{"serverAuth"},
			DefaultValidityDays: 90, MaxValidityDays: 90, MustStaple: true, AllowMustStapleOverride: true},
		{Name: "ms-on-fixed", KeyUsages: []string{"digitalSignature"}, ExtKeyUsages: []string{"serverAuth"},
			DefaultValidityDays: 90, MaxValidityDays: 90, MustStaple: true, AllowMustStapleOverride: false},
		{Name: "ms-off-override", KeyUsages: []string{"digitalSignature"}, ExtKeyUsages: []string{"serverAuth"},
			DefaultValidityDays: 90, MaxValidityDays: 90, MustStaple: false, AllowMustStapleOverride: true},
		{Name: "ms-off-fixed", KeyUsages: []string{"digitalSignature"}, ExtKeyUsages: []string{"serverAuth"},
			DefaultValidityDays: 90, MaxValidityDays: 90, MustStaple: false, AllowMustStapleOverride: false},
	}
	if err := SetCustomProfiles(profiles); err != nil {
		t.Fatalf("SetCustomProfiles: %v", err)
	}
}

func TestMustStapleIssuance(t *testing.T) {
	providers := map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	}
	for name, mk := range providers {
		t.Run(name, func(t *testing.T) {
			runMustStapleIssuance(t, newTestManager(t, mk(t)), name)
		})
	}
}

func runMustStapleIssuance(t *testing.T, mgr *Manager, tag string) {
	ctx := context.Background()
	registerMustStapleProfiles(t)
	root := newRoot(t, mgr, "muststaple-"+tag)

	issue := func(profile string, override *bool) *x509.Certificate {
		t.Helper()
		res, err := mgr.IssueCertificate(ctx, IssueSpec{
			CAID:       root.ID,
			CSRPEM:     makeCSR(t, "leaf.example.com", []string{"leaf.example.com"}),
			Profile:    profile,
			MustStaple: override,
		})
		if err != nil {
			t.Fatalf("IssueCertificate(profile=%s): %v", profile, err)
		}
		return res.Certificate
	}

	// Core positive: the built-in server-muststaple profile stamps the extension.
	assertMustStaple(t, issue("server-muststaple", nil), true)
	// Core negative: the plain server profile emits no extension (the knob unset).
	assertMustStaple(t, issue("server", nil), false)

	// Per-request override matrix.
	cases := []struct {
		profile  string
		override *bool
		want     bool
	}{
		{"ms-on-override", nil, true},             // profile default on
		{"ms-on-override", boolPtr(false), false}, // override turns it off
		{"ms-on-override", boolPtr(true), true},   // override keeps it on
		{"ms-off-override", nil, false},           // profile default off
		{"ms-off-override", boolPtr(true), true},  // override turns it on
		{"ms-off-override", boolPtr(false), false},
		{"ms-on-fixed", boolPtr(false), true},  // override ignored (not permitted)
		{"ms-off-fixed", boolPtr(true), false}, // override ignored (not permitted)
	}
	for _, tc := range cases {
		ov := "nil"
		if tc.override != nil {
			ov = map[bool]string{true: "true", false: "false"}[*tc.override]
		}
		t.Run(tc.profile+"/override="+ov, func(t *testing.T) {
			assertMustStaple(t, issue(tc.profile, tc.override), tc.want)
		})
	}
}

// TestMustStaplePreservedOnRenewal proves a Must-Staple commitment survives
// renewal — including one applied only via a per-request override at first
// issuance (profile default off).
func TestMustStaplePreservedOnRenewal(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			mgr := newTestManager(t, mk(t))
			registerMustStapleProfiles(t)
			root := newRoot(t, mgr, "ms-renew-"+name)

			// Profile default is OFF; the override turns Must-Staple on.
			orig, err := mgr.IssueCertificate(ctx, IssueSpec{
				CAID:       root.ID,
				CSRPEM:     makeCSR(t, "renew.example.com", []string{"renew.example.com"}),
				Profile:    "ms-off-override",
				MustStaple: boolPtr(true),
			})
			if err != nil {
				t.Fatalf("IssueCertificate: %v", err)
			}
			assertMustStaple(t, orig.Certificate, true)

			// Renewal carries no override field, yet must preserve the commitment.
			renewed, err := mgr.RenewCertificate(ctx, RenewSpec{
				CAID:        root.ID,
				Serial:      orig.Serial.String(),
				RequestedBy: "test",
			})
			if err != nil {
				t.Fatalf("RenewCertificate: %v", err)
			}
			assertMustStaple(t, renewed.Certificate, true)
		})
	}
}

// TestMustStaplePreservedOnRotation proves that issuing under a Must-Staple
// profile continues to stamp the extension after the issuing intermediate's
// signing key is rotated (issuance follows the successor via ActiveIssuerID).
func TestMustStaplePreservedOnRotation(t *testing.T) {
	for name, mk := range map[string]func(*testing.T) keyprovider.Provider{
		"software": softwareProvider,
		"pkcs11":   pkcs11Provider,
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			mgr := newTestManager(t, mk(t))
			registerMustStapleProfiles(t)
			_, inter := newRootAndIntermediate(t, mgr, "ms-rot-"+name, 5*365*24*time.Hour)

			before, err := mgr.IssueCertificate(ctx, IssueSpec{
				CAID:    inter.ID,
				CSRPEM:  makeCSR(t, "a.example.com", []string{"a.example.com"}),
				Profile: "ms-on-override",
			})
			if err != nil {
				t.Fatalf("IssueCertificate (pre-rotation): %v", err)
			}
			assertMustStaple(t, before.Certificate, true)

			if _, err := mgr.RotateIntermediate(ctx, RotateSpec{CAID: inter.ID, NewLabel: uniqueLabel(t, "ms-rot-new"), RequestedBy: "test"}); err != nil {
				t.Fatalf("RotateIntermediate: %v", err)
			}

			// Issue against the original (now superseded) id: ActiveIssuerID routes
			// to the rotated successor key, and the profile still stamps Must-Staple.
			after, err := mgr.IssueCertificate(ctx, IssueSpec{
				CAID:    inter.ID,
				CSRPEM:  makeCSR(t, "b.example.com", []string{"b.example.com"}),
				Profile: "ms-on-override",
			})
			if err != nil {
				t.Fatalf("IssueCertificate (post-rotation): %v", err)
			}
			assertMustStaple(t, after.Certificate, true)
		})
	}
}

// TestMustStapleOpenSSLInterop issues a Must-Staple leaf and confirms that
// `openssl x509 -text` renders the human-readable "TLS Feature: status_request".
func TestMustStapleOpenSSLInterop(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH")
	}
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "ms-openssl")

	res, err := mgr.IssueCertificate(ctx, IssueSpec{
		CAID:    root.ID,
		CSRPEM:  makeCSR(t, "staple.example.com", []string{"staple.example.com"}),
		Profile: "server-muststaple",
	})
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	assertMustStaple(t, res.Certificate, true)

	leafPEM := filepath.Join(t.TempDir(), "leaf.pem")
	if err := os.WriteFile(leafPEM, res.PEM, 0o600); err != nil {
		t.Fatalf("writing leaf: %v", err)
	}
	out, err := exec.Command(openssl, "x509", "-in", leafPEM, "-text", "-noout").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -text: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "TLS Feature") {
		t.Errorf("openssl output does not mention the TLS Feature extension:\n%s", text)
	}
	if !strings.Contains(text, "status_request") {
		t.Errorf("openssl output does not render status_request:\n%s", text)
	}
}
