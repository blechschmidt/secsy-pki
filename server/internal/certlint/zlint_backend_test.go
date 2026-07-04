//go:build zlint

package certlint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// buildLeafDER builds a root CA and a leaf signed by it, returning the leaf DER.
// The leaf deliberately omits AIA, CRL distribution points, and certificate
// policies and carries a common name, so the CA/Browser Forum lints fire.
func buildLeafDER(t *testing.T) []byte {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	leafTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"leaf.example.com"},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return leafDER
}

func TestZLintAvailableUnderTag(t *testing.T) {
	if !ZLintAvailable() {
		t.Fatal("ZLintAvailable() = false under -tags zlint; expected true")
	}
}

func TestZLintFindingsRealSuite(t *testing.T) {
	der := buildLeafDER(t)
	// Surface every level so the mapping is observable.
	pol := ZLintPolicy{NoticeMode: ModeWarn}
	findings := ZLintFindings(der, pol)
	if len(findings) == 0 {
		t.Fatal("expected zlint findings for a policy-less, AIA-less leaf; got none")
	}
	// Every finding must be namespaced and carry a resolved, non-ignore mode.
	sawEnforce := false
	for _, f := range findings {
		if len(f.Code) < len(ZLintCodePrefix) || f.Code[:len(ZLintCodePrefix)] != ZLintCodePrefix {
			t.Errorf("finding code %q is not namespaced with %q", f.Code, ZLintCodePrefix)
		}
		if f.Mode != ModeEnforce && f.Mode != ModeWarn {
			t.Errorf("finding %q has unexpected mode %q", f.Code, f.Mode)
		}
		if f.Mode == ModeEnforce {
			sawEnforce = true
		}
		t.Logf("%s [%s] %s", f.Code, f.Mode, f.Description)
	}
	if !sawEnforce {
		t.Error("expected at least one enforce-mode (error-level) zlint finding")
	}
	// Findings must be sorted by code for deterministic audit output.
	for i := 1; i < len(findings); i++ {
		if findings[i-1].Code > findings[i].Code {
			t.Errorf("findings not sorted: %q before %q", findings[i-1].Code, findings[i].Code)
		}
	}
}

func TestZLintSourceFilter(t *testing.T) {
	der := buildLeafDER(t)
	// Restrict to RFC5280 only: no CABF_BR-specific findings should appear.
	pol := ZLintPolicy{NoticeMode: ModeWarn, IncludeSources: []string{"RFC5280"}}
	findings := ZLintFindings(der, pol)
	for _, f := range findings {
		if wantsCABFOnly(f.Description) {
			t.Errorf("RFC5280-only filter leaked a CABF_BR finding: %s (%s)", f.Code, f.Description)
		}
	}
}

// wantsCABFOnly reports whether a finding description names CABF_BR as its
// source (the description embeds the zlint source label).
func wantsCABFOnly(desc string) bool {
	return len(desc) >= len("CABF_BR") && containsToken(desc, "CABF_BR")
}

func containsToken(s, tok string) bool {
	for i := 0; i+len(tok) <= len(s); i++ {
		if s[i:i+len(tok)] == tok {
			return true
		}
	}
	return false
}

func TestZLintOverrideDropsFinding(t *testing.T) {
	der := buildLeafDER(t)
	base := ZLintFindings(der, ZLintPolicy{NoticeMode: ModeWarn})
	if len(base) == 0 {
		t.Skip("no findings to override")
	}
	// Drop the first finding by name via an "ignore" override; it must disappear.
	target := base[0].Code[len(ZLintCodePrefix):]
	filtered := ZLintFindings(der, ZLintPolicy{
		NoticeMode: ModeWarn,
		Overrides:  map[string]Mode{target: "ignore"},
	})
	for _, f := range filtered {
		if f.Code == base[0].Code {
			t.Errorf("override ignore did not drop finding %q", f.Code)
		}
	}
}
