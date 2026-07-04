//go:build sqlite

package ca

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// pkupFromCert returns the parsed id-ce-privateKeyUsagePeriod a leaf carries, or
// nil when absent, asserting it is non-critical when present.
func pkupFromCert(t *testing.T, cert *x509.Certificate) *pki.PrivateKeyUsagePeriod {
	t.Helper()
	for i := range cert.Extensions {
		if !cert.Extensions[i].Id.Equal(pki.OIDPrivateKeyUsagePeriod) {
			continue
		}
		if cert.Extensions[i].Critical {
			t.Error("id-ce-privateKeyUsagePeriod marked critical; RFC 5280 requires non-critical")
		}
		p, err := pki.ParsePrivateKeyUsagePeriod(cert.Extensions[i].Value)
		if err != nil {
			t.Fatalf("ParsePrivateKeyUsagePeriod: %v", err)
		}
		return &p
	}
	return nil
}

// approxEqual reports whether two instants are within a couple of seconds — the
// GeneralizedTime bounds and the certificate validity are both truncated to the
// second from the same underlying time, so they should match closely.
func approxEqual(a, b time.Time) bool {
	d := a.Sub(b)
	if d < 0 {
		d = -d
	}
	return d <= 2*time.Second
}

func TestPrivateKeyUsagePeriodIssuance(t *testing.T) {
	ctx := context.Background()
	mgr := newTestManager(t, softwareProvider(t))
	root := newRoot(t, mgr, "pkup")

	resetCustomProfiles(t)
	// A signing profile with a 180-day default usage period, well inside its
	// 730-day validity, that also permits a per-request override.
	if err := SetCustomProfiles([]Profile{
		{
			Name:                "pkup-signer",
			KeyUsages:           []string{"digitalSignature", "contentCommitment"},
			DefaultValidityDays: 730,
			MaxValidityDays:     730,
			PrivateKeyUsagePeriod: &PrivateKeyUsagePeriodConfig{
				Duration:      "180d",
				AllowOverride: true,
			},
		},
		{
			Name:                "pkup-fixed",
			KeyUsages:           []string{"digitalSignature"},
			DefaultValidityDays: 365,
			MaxValidityDays:     365,
			// Half-of-validity default, no override permitted.
			PrivateKeyUsagePeriod: &PrivateKeyUsagePeriodConfig{Fraction: 0.5},
		},
	}); err != nil {
		t.Fatalf("SetCustomProfiles: %v", err)
	}
	t.Cleanup(func() { resetCustomProfiles(t) })

	issue := func(t *testing.T, profile string, pkup *models.PrivateKeyUsagePeriod) (*x509.Certificate, error) {
		t.Helper()
		res, err := mgr.IssueCertificate(ctx, IssueSpec{
			CAID:                  root.ID,
			CSRPEM:                makeCSR(t, "signer.example.com", []string{"signer.example.com"}),
			Profile:               profile,
			PrivateKeyUsagePeriod: pkup,
		})
		if err != nil {
			return nil, err
		}
		return res.Certificate, nil
	}

	// A plain profile without a PKUP block emits no extension.
	t.Run("non-pkup-profile-omits", func(t *testing.T) {
		cert, err := issue(t, "server", nil)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if p := pkupFromCert(t, cert); p != nil {
			t.Errorf("server profile stamped a privateKeyUsagePeriod: %+v", p)
		}
	})

	// The profile default (180d duration) is stamped, starting at the cert's
	// notBefore and ending 180 days later (inside the 730-day validity).
	t.Run("profile-default-duration", func(t *testing.T) {
		cert, err := issue(t, "pkup-signer", nil)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		p := pkupFromCert(t, cert)
		if p == nil {
			t.Fatal("pkup-signer did not stamp a privateKeyUsagePeriod")
		}
		if !approxEqual(p.NotBefore, cert.NotBefore) {
			t.Errorf("pkup notBefore = %v, want cert notBefore %v", p.NotBefore, cert.NotBefore)
		}
		if want := cert.NotBefore.Add(180 * 24 * time.Hour); !approxEqual(p.NotAfter, want) {
			t.Errorf("pkup notAfter = %v, want %v", p.NotAfter, want)
		}
		if !p.NotAfter.Before(cert.NotAfter) {
			t.Errorf("usage period notAfter %v must be strictly before cert expiry %v", p.NotAfter, cert.NotAfter)
		}
	})

	// A fraction-based default: half of the 365-day validity.
	t.Run("profile-default-fraction", func(t *testing.T) {
		cert, err := issue(t, "pkup-fixed", nil)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		p := pkupFromCert(t, cert)
		if p == nil {
			t.Fatal("pkup-fixed did not stamp a privateKeyUsagePeriod")
		}
		span := cert.NotAfter.Sub(cert.NotBefore)
		if want := cert.NotBefore.Add(span / 2); !approxEqual(p.NotAfter, want) {
			t.Errorf("pkup notAfter = %v, want %v (half of validity)", p.NotAfter, want)
		}
	})

	// A per-request override (30d) replaces the profile default (180d).
	t.Run("per-request-override", func(t *testing.T) {
		cert, err := issue(t, "pkup-signer", &models.PrivateKeyUsagePeriod{Duration: "30d"})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		p := pkupFromCert(t, cert)
		if p == nil {
			t.Fatal("override did not stamp a privateKeyUsagePeriod")
		}
		if want := cert.NotBefore.Add(30 * 24 * time.Hour); !approxEqual(p.NotAfter, want) {
			t.Errorf("override notAfter = %v, want %v (30d)", p.NotAfter, want)
		}
	})

	// An override on a profile that has no PKUP block is a hard error.
	t.Run("override-on-non-pkup-profile-rejected", func(t *testing.T) {
		if _, err := issue(t, "server", &models.PrivateKeyUsagePeriod{Duration: "30d"}); err == nil {
			t.Fatal("expected an error: a request cannot fabricate a PKUP the profile did not grant")
		}
	})

	// An override on a profile that forbids overrides is rejected.
	t.Run("override-not-permitted-rejected", func(t *testing.T) {
		if _, err := issue(t, "pkup-fixed", &models.PrivateKeyUsagePeriod{Duration: "30d"}); err == nil {
			t.Fatal("expected an error: pkup-fixed does not set allow_override")
		}
	})

	// Renewal re-applies the profile's usage period against the fresh window.
	t.Run("renewal-preserves-pkup", func(t *testing.T) {
		res, err := mgr.IssueCertificate(ctx, IssueSpec{
			CAID:    root.ID,
			CSRPEM:  makeCSR(t, "renew.example.com", []string{"renew.example.com"}),
			Profile: "pkup-signer",
		})
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		renewed, err := mgr.RenewCertificate(ctx, RenewSpec{CAID: root.ID, Serial: res.Serial.String()})
		if err != nil {
			t.Fatalf("renew: %v", err)
		}
		p := pkupFromCert(t, renewed.Certificate)
		if p == nil {
			t.Fatal("renewed certificate dropped the privateKeyUsagePeriod")
		}
		if want := renewed.Certificate.NotBefore.Add(180 * 24 * time.Hour); !approxEqual(p.NotAfter, want) {
			t.Errorf("renewed pkup notAfter = %v, want %v (recomputed from the new window)", p.NotAfter, want)
		}
	})

	// The non-mutating preview reports the private_key_usage_period gate verdict.
	t.Run("preview-gate", func(t *testing.T) {
		gate := func(t *testing.T, profile string, pkup *models.PrivateKeyUsagePeriod) GateVerdict {
			t.Helper()
			res, err := mgr.PreviewIssuance(ctx, PreviewSpec{
				CAID:                  root.ID,
				CSRPEM:                makeCSR(t, "preview.example.com", []string{"preview.example.com"}),
				Profile:               profile,
				PrivateKeyUsagePeriod: pkup,
			})
			if err != nil {
				t.Fatalf("PreviewIssuance: %v", err)
			}
			for _, g := range res.Gates {
				if g.Name == GatePrivateKeyUsage {
					return g
				}
			}
			t.Fatalf("no private_key_usage_period gate in preview for profile %q", profile)
			return GateVerdict{}
		}
		if g := gate(t, "server", nil); g.Status != GateSkipped {
			t.Errorf("server pkup gate = %q, want skipped", g.Status)
		}
		if g := gate(t, "pkup-signer", nil); g.Status != GatePass {
			t.Errorf("pkup-signer gate = %q/%q, want pass", g.Status, g.Reason)
		}
		if g := gate(t, "server", &models.PrivateKeyUsagePeriod{Duration: "30d"}); g.Status != GateFail {
			t.Errorf("server+override gate = %q, want fail", g.Status)
		}
	})
}
