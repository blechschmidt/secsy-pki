package pki

// Independent decode of the hand-rolled CRL partitioning extensions.
//
// crypto/x509 can neither emit nor parse the Delta CRL Indicator, the Issuing
// Distribution Point, or the Freshest CRL, so a Go-only test can at best compare
// crl.go against itself. OpenSSL decodes all three, and a relying party that
// rejects a partitioned CRL takes a CA's revocation data offline — which makes an
// outside decoder worth the exec.

import (
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCreateCRL_OpenSSLDecodesPartitioningExtensions issues a delta CRL that is
// scoped to a partition (Issuing Distribution Point with two mirror URLs and
// onlyContainsUserCerts), references its base CRL (Delta CRL Indicator), and
// advertises where its own delta lives (Freshest CRL) — then requires `openssl
// crl -text` to both accept the CRL and render every field back. A wrong context
// tag or a missing constructed bit anywhere in crl.go's RawValue nesting shows up
// here as a parse failure or a missing line, neither of which a Go test could see.
func TestCreateCRL_OpenSSLDecodesPartitioningExtensions(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not found in PATH")
	}

	caCert, caKey := testCA(t)
	const (
		shardURL  = "http://crl.example/leaf-shard-7.crl"
		mirrorURL = "http://mirror.example/leaf-shard-7.crl"
		deltaURL  = "http://crl.example/leaf-shard-7-delta.crl"
	)
	der, err := CreateCRL(caKey, caCert, CRLRequest{
		Number:          big.NewInt(42),
		ThisUpdate:      time.Now().Add(-time.Minute),
		NextUpdate:      time.Now().Add(24 * time.Hour),
		BaseCRLNumber:   big.NewInt(41),
		FreshestCRLURLs: []string{deltaURL},
		IDP: &IssuingDistributionPoint{
			DistributionPointURLs: []string{shardURL, mirrorURL},
			OnlyContainsUserCerts: true,
		},
		Revoked: []RevokedEntry{
			{Serial: big.NewInt(1234), RevokedAt: time.Now().Add(-time.Hour), Reason: RevocationReasonKeyCompromise},
		},
	})
	if err != nil {
		t.Fatalf("CreateCRL: %v", err)
	}

	path := filepath.Join(t.TempDir(), "crl.pem")
	if err := os.WriteFile(path, EncodeCRLPEM(der), 0o600); err != nil {
		t.Fatalf("writing CRL: %v", err)
	}

	out, err := exec.Command(openssl, "crl", "-text", "-noout", "-in", path).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl crl rejected the CRL: %v\n%s", err, out)
	}
	text := string(out)

	// OpenSSL names each extension it recognized; an unparseable value would
	// instead be dumped as raw hex (or abort the command above).
	for _, want := range []string{
		"X509v3 Issuing Distribution Point: critical",
		"Only User Certificates",
		"X509v3 Delta CRL Indicator: critical",
		"X509v3 Freshest CRL",
		"X509v3 CRL Number",
		"URI:" + shardURL,
		"URI:" + mirrorURL,
		"URI:" + deltaURL,
		"Key Compromise",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("openssl output is missing %q\n--- openssl crl -text ---\n%s", want, text)
		}
	}
	// The Delta CRL Indicator must render as the base CRL number we asked for.
	if idx := strings.Index(text, "Delta CRL Indicator"); idx >= 0 {
		if !strings.Contains(text[idx:min(idx+120, len(text))], "41") {
			t.Errorf("Delta CRL Indicator does not render base number 41:\n%s", text[idx:min(idx+120, len(text))])
		}
	}
	// A hex dump under one of our extensions means OpenSSL could not decode it.
	if strings.Contains(text, "Issuing Distribution Point") && strings.Contains(text, "0000 - ") {
		t.Errorf("openssl fell back to a hex dump, i.e. an extension did not decode:\n%s", text)
	}
}
