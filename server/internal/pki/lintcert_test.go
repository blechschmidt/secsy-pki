package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// makeIssuer builds and parses a self-signed CA cert of the requested algorithm.
func makeIssuer(t *testing.T, key any) *x509.Certificate {
	t.Helper()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Lint Test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	var pub, priv any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub, priv = &k.PublicKey, k
	case *ecdsa.PrivateKey:
		pub, priv = &k.PublicKey, k
	default:
		t.Fatalf("unsupported key type %T", key)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func sampleLeafReq(t *testing.T) LeafCertRequest {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	now := time.Now()
	return LeafCertRequest{
		Subject:               pkix.Name{CommonName: "leaf.example.com"},
		PublicKey:             &leafKey.PublicKey,
		Serial:                serial,
		NotBefore:             now,
		NotAfter:              now.Add(90 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"leaf.example.com", "www.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("192.0.2.10")},
		CRLDistributionPoints: []string{"http://crl.example.com/ca.crl"},
		OCSPServer:            []string{"http://ocsp.example.com"},
	}
}

// TestLintCertificateDERFaithful verifies the synthesized linting certificate is
// parseable and reproduces the template's TBSCertificate fields (subject, SANs,
// validity, serial, key usage, EKU, SKI, and authority key identifier from the
// issuer) — the encoding a linter must inspect — with a matching signature
// algorithm for the issuer's key type.
func TestLintCertificateDERFaithful(t *testing.T) {
	for _, tc := range []struct {
		name    string
		issuer  *x509.Certificate
		wantSig x509.SignatureAlgorithm
	}{
		{"ecdsa", makeIssuer(t, mustECDSA(t)), x509.ECDSAWithSHA256},
		{"rsa", makeIssuer(t, mustRSA(t)), x509.SHA256WithRSA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := sampleLeafReq(t)
			der, err := LintCertificateDER(tc.issuer, req)
			if err != nil {
				t.Fatalf("LintCertificateDER: %v", err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("parsing synthesized DER: %v", err)
			}
			if cert.Subject.CommonName != "leaf.example.com" {
				t.Errorf("subject CN = %q", cert.Subject.CommonName)
			}
			if cert.SerialNumber.Cmp(req.Serial) != 0 {
				t.Errorf("serial = %s, want %s", cert.SerialNumber, req.Serial)
			}
			if got := cert.DNSNames; len(got) != 2 || got[0] != "leaf.example.com" {
				t.Errorf("DNSNames = %v", got)
			}
			if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(net.ParseIP("192.0.2.10")) {
				t.Errorf("IPAddresses = %v", cert.IPAddresses)
			}
			if len(cert.CRLDistributionPoints) != 1 {
				t.Errorf("CRLDistributionPoints = %v", cert.CRLDistributionPoints)
			}
			if len(cert.OCSPServer) != 1 {
				t.Errorf("OCSPServer = %v", cert.OCSPServer)
			}
			if len(cert.SubjectKeyId) == 0 {
				t.Error("missing subject key identifier")
			}
			if len(cert.AuthorityKeyId) == 0 {
				t.Error("missing authority key identifier (should come from issuer SKI)")
			}
			if cert.SignatureAlgorithm != tc.wantSig {
				t.Errorf("signature algorithm = %v, want %v", cert.SignatureAlgorithm, tc.wantSig)
			}
			if cert.KeyUsage != (x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment) {
				t.Errorf("key usage = %v", cert.KeyUsage)
			}
			if cert.IsCA {
				t.Error("linting certificate must not be a CA")
			}
		})
	}
}

// TestLintCertificateDERUnsupportedIssuer confirms an unsupported (e.g. nil)
// issuer key yields a clear error so the caller skips DER-based linting.
func TestLintCertificateDERUnsupportedIssuer(t *testing.T) {
	if _, err := LintCertificateDER(nil, sampleLeafReq(t)); err == nil {
		t.Fatal("expected error for a nil issuer")
	}
	// An issuer with an unsupported public key type is rejected by the signer
	// selection.
	bad := &x509.Certificate{PublicKey: "not-a-key"}
	if _, err := LintCertificateDER(bad, sampleLeafReq(t)); err == nil {
		t.Fatal("expected error for an unsupported issuer key type")
	}
}

func mustECDSA(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
