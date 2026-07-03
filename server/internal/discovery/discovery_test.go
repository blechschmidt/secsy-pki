package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// certOpts parameterizes the self-contained certificates the tests generate.
type certOpts struct {
	cn        string
	dnsNames  []string
	notBefore time.Time
	notAfter  time.Time
	rsaBits   int            // >0 => RSA of this size; else EC P-256
	ecCurve   elliptic.Curve // overrides the default P-256 when set
	sigAlg    x509.SignatureAlgorithm
	isCA      bool
	parent    *x509.Certificate
	parentKey interface{}
}

// makeCert builds a certificate (self-signed unless a parent is supplied) and
// returns the parsed cert and its private key.
func makeCert(t *testing.T, o certOpts) (*x509.Certificate, interface{}) {
	t.Helper()
	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(365 * 24 * time.Hour)
	}

	var priv interface{}
	var pub interface{}
	if o.rsaBits > 0 {
		k, err := rsa.GenerateKey(rand.Reader, o.rsaBits)
		if err != nil {
			t.Fatalf("rsa key: %v", err)
		}
		priv, pub = k, &k.PublicKey
	} else {
		curve := o.ecCurve
		if curve == nil {
			curve = elliptic.P256()
		}
		k, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("ec key: %v", err)
		}
		priv, pub = k, &k.PublicKey
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: o.cn},
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		DNSNames:              o.dnsNames,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if o.sigAlg != x509.UnknownSignatureAlgorithm {
		tmpl.SignatureAlgorithm = o.sigAlg
	}
	if o.isCA {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
		tmpl.ExtKeyUsage = nil
	}

	parent := tmpl
	signKey := priv
	if o.parent != nil {
		parent = o.parent
		signKey = o.parentKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert, priv
}

// startTLSServer serves the given certificate chain over TLS and returns its
// host:port. The chain is leaf-first; intermediates (if any) follow.
func startTLSServer(t *testing.T, chain []*x509.Certificate, leafKey interface{}) string {
	t.Helper()
	var raw [][]byte
	for _, c := range chain {
		raw = append(raw, c.Raw)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{{Certificate: raw, PrivateKey: leafKey, Leaf: chain[0]}},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	u := srv.URL // https://127.0.0.1:port
	host := u[len("https://"):]
	return host
}

// scanOneEndpoint is a helper that scans a single host:port with the given SNI.
func scanOneEndpoint(t *testing.T, s *Scanner, hostport, sni string) Finding {
	t.Helper()
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	target := Target{Host: host, Port: port, ServerName: sni}
	findings := s.Scan(context.Background(), []Target{target})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	return findings[0]
}

func TestScanHealthyCert(t *testing.T) {
	leaf, key := makeCert(t, certOpts{cn: "healthy.example.com", dnsNames: []string{"healthy.example.com"}})
	addr := startTLSServer(t, []*x509.Certificate{leaf}, key)

	s := NewScanner(30, nil)
	f := scanOneEndpoint(t, s, addr, "healthy.example.com")

	if !f.Reachable {
		t.Fatalf("expected reachable, error=%q", f.Error)
	}
	if f.CommonName != "healthy.example.com" {
		t.Errorf("common name = %q", f.CommonName)
	}
	if f.KeyAlgorithm != "ECDSA" || f.KeySize != 256 {
		t.Errorf("key = %s-%d, want ECDSA-256", f.KeyAlgorithm, f.KeySize)
	}
	if f.ExpiringSoon {
		t.Errorf("healthy long-lived cert should not be expiring soon")
	}
	if f.WeakKey || f.SHA1Signature || f.HostnameMismatch {
		t.Errorf("unexpected weak/sha1/mismatch flag: %+v", f.Flags)
	}
	if f.Fingerprint == "" || f.LeafPEM == "" {
		t.Errorf("expected fingerprint and PEM to be populated")
	}
	// No known PKI => everything self-signed-or-external; this leaf is self-signed.
	if !f.SelfSigned {
		t.Errorf("expected self-signed for a standalone leaf")
	}
}

func TestScanExpiringSoon(t *testing.T) {
	leaf, key := makeCert(t, certOpts{
		cn:        "expiring.example.com",
		dnsNames:  []string{"expiring.example.com"},
		notBefore: time.Now().Add(-48 * time.Hour),
		notAfter:  time.Now().Add(5 * 24 * time.Hour), // 5 days left
	})
	addr := startTLSServer(t, []*x509.Certificate{leaf}, key)

	s := NewScanner(30, nil) // 30-day window
	f := scanOneEndpoint(t, s, addr, "expiring.example.com")

	if !f.ExpiringSoon {
		t.Errorf("cert with 5 days left should be flagged expiring (30-day window)")
	}
	if f.Severity != SeverityWarning {
		t.Errorf("severity = %q, want warning", f.Severity)
	}
}

func TestScanExpired(t *testing.T) {
	leaf, key := makeCert(t, certOpts{
		cn:        "expired.example.com",
		dnsNames:  []string{"expired.example.com"},
		notBefore: time.Now().Add(-72 * time.Hour),
		notAfter:  time.Now().Add(-time.Hour),
	})
	addr := startTLSServer(t, []*x509.Certificate{leaf}, key)

	s := NewScanner(30, nil)
	f := scanOneEndpoint(t, s, addr, "expired.example.com")

	if !f.ExpiringSoon || f.Severity != SeverityCritical {
		t.Errorf("expired cert should be critical+expiring: expiring=%v sev=%q", f.ExpiringSoon, f.Severity)
	}
}

func TestScanWeakRSAKey(t *testing.T) {
	leaf, key := makeCert(t, certOpts{
		cn:       "weak.example.com",
		dnsNames: []string{"weak.example.com"},
		rsaBits:  1024,
	})
	addr := startTLSServer(t, []*x509.Certificate{leaf}, key)

	s := NewScanner(30, nil)
	f := scanOneEndpoint(t, s, addr, "weak.example.com")

	if !f.WeakKey {
		t.Errorf("1024-bit RSA key should be flagged weak")
	}
	if f.KeyAlgorithm != "RSA" || f.KeySize != 1024 {
		t.Errorf("key = %s-%d, want RSA-1024", f.KeyAlgorithm, f.KeySize)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("weak key should raise critical severity, got %q", f.Severity)
	}
}

func TestScanSHA1Signature(t *testing.T) {
	leaf, key := makeCert(t, certOpts{
		cn:       "sha1.example.com",
		dnsNames: []string{"sha1.example.com"},
		rsaBits:  2048,
		sigAlg:   x509.SHA1WithRSA,
	})
	addr := startTLSServer(t, []*x509.Certificate{leaf}, key)

	s := NewScanner(30, nil)
	f := scanOneEndpoint(t, s, addr, "sha1.example.com")

	if !f.SHA1Signature {
		t.Errorf("SHA1WithRSA signature should be flagged")
	}
}

func TestScanHostnameMismatch(t *testing.T) {
	leaf, key := makeCert(t, certOpts{cn: "real.example.com", dnsNames: []string{"real.example.com"}})
	addr := startTLSServer(t, []*x509.Certificate{leaf}, key)

	s := NewScanner(30, nil)
	// Present a different SNI than the cert is valid for.
	f := scanOneEndpoint(t, s, addr, "wrong.example.com")

	if !f.HostnameMismatch {
		t.Errorf("expected hostname mismatch when SNI != cert SANs")
	}
}

func TestScanUnreachable(t *testing.T) {
	s := NewScanner(30, nil)
	// A port nothing is listening on. 127.0.0.1:1 is reliably closed.
	f := scanOneEndpoint(t, s, "127.0.0.1:1", "")
	if f.Reachable {
		t.Errorf("expected unreachable")
	}
	if f.Error == "" {
		t.Errorf("expected an error message for an unreachable endpoint")
	}
}

func TestRogueVsIssuedByThisPKI(t *testing.T) {
	// Build this PKI's own CA and a leaf it issued.
	caCert, caKey := makeCert(t, certOpts{cn: "Secsy Test CA", isCA: true})
	ourLeaf, ourKey := makeCert(t, certOpts{
		cn:        "mine.example.com",
		dnsNames:  []string{"mine.example.com"},
		parent:    caCert,
		parentKey: caKey,
	})
	// A rogue leaf signed by an unrelated CA (self-signed here).
	rogueLeaf, rogueKey := makeCert(t, certOpts{cn: "rogue.example.com", dnsNames: []string{"rogue.example.com"}})

	knownPool := x509.NewCertPool()
	knownPool.AddCert(caCert)
	s := NewScanner(30, knownPool)

	ourAddr := startTLSServer(t, []*x509.Certificate{ourLeaf, caCert}, ourKey)
	rogueAddr := startTLSServer(t, []*x509.Certificate{rogueLeaf}, rogueKey)

	our := scanOneEndpoint(t, s, ourAddr, "mine.example.com")
	if !our.IssuedByPKI {
		t.Errorf("leaf issued by our CA should be recognized as issued-by-this-PKI")
	}
	if our.Rogue {
		t.Errorf("our own leaf must not be flagged rogue")
	}

	rogue := scanOneEndpoint(t, s, rogueAddr, "rogue.example.com")
	if rogue.IssuedByPKI {
		t.Errorf("unrelated leaf must not be recognized as issued-by-this-PKI")
	}
	// Self-signed leaves are reported as self-signed rather than rogue.
	if !rogue.SelfSigned {
		t.Errorf("standalone leaf should be self-signed")
	}
}

func TestRogueNonSelfSigned(t *testing.T) {
	// A leaf signed by a foreign CA (not self-signed, not ours) is the true
	// rogue/shadow case.
	foreignCA, foreignKey := makeCert(t, certOpts{cn: "Foreign CA", isCA: true})
	foreignLeaf, leafKey := makeCert(t, certOpts{
		cn:        "shadow.example.com",
		dnsNames:  []string{"shadow.example.com"},
		parent:    foreignCA,
		parentKey: foreignKey,
	})
	ourCA, _ := makeCert(t, certOpts{cn: "Our CA", isCA: true})
	knownPool := x509.NewCertPool()
	knownPool.AddCert(ourCA)

	addr := startTLSServer(t, []*x509.Certificate{foreignLeaf, foreignCA}, leafKey)
	s := NewScanner(30, knownPool)
	f := scanOneEndpoint(t, s, addr, "shadow.example.com")

	if f.IssuedByPKI {
		t.Errorf("foreign-CA leaf must not be issued-by-this-PKI")
	}
	if f.SelfSigned {
		t.Errorf("foreign-CA leaf is not self-signed")
	}
	if !f.Rogue {
		t.Errorf("foreign-CA leaf served on an endpoint should be flagged rogue")
	}
	if f.Severity != SeverityCritical {
		t.Errorf("rogue cert should raise critical severity, got %q", f.Severity)
	}
}

func TestPoolFromCerts(t *testing.T) {
	caCert, _ := makeCert(t, certOpts{cn: "PEM CA", isCA: true})
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})
	if p := PoolFromCerts([]string{string(pemBytes)}); p == nil {
		t.Errorf("expected a non-nil pool from a valid PEM cert")
	}
	if p := PoolFromCerts([]string{"", "not a pem"}); p != nil {
		t.Errorf("expected nil pool when nothing parses")
	}
}

func TestReportCounts(t *testing.T) {
	findings := []Finding{
		{Reachable: true, Severity: SeverityWarning, ExpiringSoon: true},
		{Reachable: true, Severity: SeverityCritical, Rogue: true, WeakKey: true},
		{Reachable: false},
		{Reachable: true, Severity: SeverityOK, IssuedByPKI: true},
	}
	r := BuildReport(findings, 30, time.Now())
	if r.Counts.Total != 4 || r.Counts.Reachable != 3 || r.Counts.Unreachable != 1 {
		t.Errorf("totals wrong: %+v", r.Counts)
	}
	if r.Counts.ExpiringSoon != 1 || r.Counts.Rogue != 1 || r.Counts.WeakKey != 1 || r.Counts.IssuedByPKI != 1 {
		t.Errorf("flag counts wrong: %+v", r.Counts)
	}
	if r.Counts.Warning != 1 || r.Counts.Critical != 1 {
		t.Errorf("severity counts wrong: %+v", r.Counts)
	}
}
