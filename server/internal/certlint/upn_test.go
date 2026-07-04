package certlint

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// upnLeafCert builds the *x509.Certificate view of a smartcard-logon leaf
// request: a UPN otherName as the only SAN, clientAuth plus the smartcard-logon
// EKU, and the given key-usage bitmask.
func upnLeafCert(t *testing.T, ku x509.KeyUsage, upns []string) *x509.Certificate {
	t.Helper()
	now := time.Now()
	req := pki.LeafCertRequest{
		Serial:             randomSerial(t),
		NotBefore:          now,
		NotAfter:           now.Add(90 * 24 * time.Hour),
		KeyUsage:           ku,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{pki.OIDExtKeyUsageMSSmartcardLogon},
		UPNs:               upns,
	}
	cert, err := CertificateFromLeaf(req)
	if err != nil {
		t.Fatalf("CertificateFromLeaf: %v", err)
	}
	return cert
}

// TestUPNSANAwareness confirms a certificate whose only identity is a UPN
// otherName is not falsely flagged as having no subjectAltName under a public
// policy — the linter accounts for the otherName (Task 122).
func TestUPNSANAwareness(t *testing.T) {
	cert := upnLeafCert(t, x509.KeyUsageDigitalSignature, []string{"alice@EXAMPLE.COM"})
	res := Lint(cert, Policy{Public: true})
	if hasCode(res, CheckSANPresent) {
		t.Errorf("UPN-only certificate falsely flagged as having no SAN: %s", res.Summary())
	}
	// Sanity: certUPNs recovers the UPN from the synthesized template.
	if got := certUPNs(cert); len(got) != 1 || got[0] != "alice@EXAMPLE.COM" {
		t.Errorf("certUPNs = %v, want [alice@EXAMPLE.COM]", got)
	}
}

// TestUPNEKUConsistency confirms the smartcard/PKINIT EKUs are recognized: a
// certificate carrying them with digitalSignature passes, and one carrying them
// without digitalSignature is flagged.
func TestUPNEKUConsistency(t *testing.T) {
	ok := upnLeafCert(t, x509.KeyUsageDigitalSignature, []string{"a@EXAMPLE.COM"})
	if res := Lint(ok, Policy{}); hasCode(res, CheckEKUKUConsistency) {
		t.Errorf("smartcard cert with digitalSignature should pass EKU/KU consistency: %s", res.Summary())
	}
	bad := upnLeafCert(t, x509.KeyUsageKeyEncipherment, []string{"a@EXAMPLE.COM"})
	if res := Lint(bad, Policy{}); !hasCode(res, CheckEKUKUConsistency) {
		t.Errorf("smartcard EKU without digitalSignature should be flagged: %s", res.Summary())
	}
}
