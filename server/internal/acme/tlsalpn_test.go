package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net"
	"testing"
	"time"
)

// validationCertOpts controls how the tls-alpn-01 validation certificate is
// crafted so tests can build both correct and deliberately malformed variants.
type validationCertOpts struct {
	digest    []byte            // value committed by the acmeIdentifier extension
	extValue  []byte            // raw override for the extension value (else DER OCTET STRING of digest)
	omitExt   bool              // omit the id-pe-acmeIdentifier extension entirely
	critical  bool              // whether the extension is marked critical
	dnsNames  []string          // subjectAltName dNSNames
	ipAddrs   []net.IP          // subjectAltName iPAddresses
	signerKey *ecdsa.PrivateKey // sign with this key instead of the cert's own (breaks self-signature)
	subjectCN string            // subject/issuer common name (default set below)
}

// newValidationCert builds a self-signed certificate per validationCertOpts and
// wraps it in a tls.Certificate for an in-process responder.
func newValidationCert(t *testing.T, opts validationCertOpts) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cn := opts.subjectCN
	if cn == "" {
		cn = "acme-tls/1 validation"
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     opts.dnsNames,
		IPAddresses:  opts.ipAddrs,
	}
	if !opts.omitExt {
		val := opts.extValue
		if val == nil {
			enc, err := asn1.Marshal(opts.digest)
			if err != nil {
				t.Fatalf("marshal digest: %v", err)
			}
			val = enc
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{
			Id:       idPEACMEIdentifier,
			Critical: opts.critical,
			Value:    val,
		})
	}
	signer := key
	if opts.signerKey != nil {
		signer = opts.signerKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, signer)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSALPNResponder stands up an in-process TLS listener that presents cert
// over the given ALPN protocols, emulating an ACME client's tls-alpn-01 solver.
// It returns the listener address.
func startTLSALPNResponder(t *testing.T, cert tls.Certificate, alpn []string) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   alpn,
		MinVersion:   tls.VersionTLS12,
	}
	go func() {
		for {
			conn, err := lis.Accept()
			if err != nil {
				return
			}
			go func() {
				tc := tls.Server(conn, cfg)
				_ = tc.Handshake() // best-effort: the validator only needs the presented cert
				tc.Close()
			}()
		}
	}()
	return lis.Addr().String()
}

// validatorForAddr returns a Validator whose tls-alpn-01 dials are redirected to
// addr regardless of the identifier, so tests never touch the real network.
func validatorForAddr(addr string) *Validator {
	return &Validator{
		TLSALPNPort: 443,
		TLSDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
}

func TestValidateTLSALPN01(t *testing.T) {
	const domain = "example.test"
	keyAuth := keyAuthorization("token-abc", "thumbprint-xyz")
	sum := sha256.Sum256([]byte(keyAuth))
	digest := sum[:]

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("other key: %v", err)
	}

	// A digest committing to a *different* key authorization.
	wrongSum := sha256.Sum256([]byte("not the right key authorization"))

	cases := []struct {
		name     string
		opts     validationCertOpts
		alpn     []string // server ALPN protocols; nil => acme-tls/1
		wantOK   bool
		wantType string
	}{
		{
			name:   "correct certificate validates",
			opts:   validationCertOpts{digest: digest, critical: true, dnsNames: []string{domain}},
			wantOK: true,
		},
		{
			name:     "wrong digest is rejected",
			opts:     validationCertOpts{digest: wrongSum[:], critical: true, dnsNames: []string{domain}},
			wantType: probUnauthorized,
		},
		{
			name:     "missing acmeIdentifier extension is rejected",
			opts:     validationCertOpts{omitExt: true, dnsNames: []string{domain}},
			wantType: probIncorrectResponse,
		},
		{
			name:     "non-critical extension is rejected",
			opts:     validationCertOpts{digest: digest, critical: false, dnsNames: []string{domain}},
			wantType: probIncorrectResponse,
		},
		{
			name:     "mismatched subjectAltName is rejected",
			opts:     validationCertOpts{digest: digest, critical: true, dnsNames: []string{"other.test"}},
			wantType: probIncorrectResponse,
		},
		{
			name:     "malformed extension value is rejected",
			opts:     validationCertOpts{extValue: []byte{0x05, 0x00}, critical: true, dnsNames: []string{domain}},
			wantType: probIncorrectResponse,
		},
		{
			name:     "foreign signature (not self-signed) is rejected",
			opts:     validationCertOpts{digest: digest, critical: true, dnsNames: []string{domain}, signerKey: otherKey},
			wantType: probIncorrectResponse,
		},
		{
			name:     "server that does not negotiate acme-tls/1 is rejected",
			opts:     validationCertOpts{digest: digest, critical: true, dnsNames: []string{domain}},
			alpn:     []string{}, // no ALPN offered by the responder
			wantType: probTLS,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			alpn := tc.alpn
			if alpn == nil {
				alpn = []string{acmeTLS1ALPN}
			}
			cert := newValidationCert(t, tc.opts)
			addr := startTLSALPNResponder(t, cert, alpn)
			v := validatorForAddr(addr)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			prob := v.ValidateTLSALPN01(ctx, domain, keyAuth)

			if tc.wantOK {
				if prob != nil {
					t.Fatalf("expected success, got problem: %v", prob)
				}
				return
			}
			if prob == nil {
				t.Fatalf("expected problem %q, got success", tc.wantType)
			}
			if prob.Type != tc.wantType {
				t.Fatalf("problem type = %q, want %q (detail: %s)", prob.Type, tc.wantType, prob.Detail)
			}
		})
	}
}

// TestValidateTLSALPN01_IPIdentifier covers the RFC 8738 §5 path: an IP-address
// identifier validated via tls-alpn-01, where the certificate carries the IP in
// its subjectAltName and the client sends no SNI.
func TestValidateTLSALPN01_IPIdentifier(t *testing.T) {
	const ip = "192.0.2.10"
	keyAuth := keyAuthorization("token-ip", "thumbprint-ip")
	sum := sha256.Sum256([]byte(keyAuth))

	cert := newValidationCert(t, validationCertOpts{
		digest:   sum[:],
		critical: true,
		ipAddrs:  []net.IP{net.ParseIP(ip)},
	})
	addr := startTLSALPNResponder(t, cert, []string{acmeTLS1ALPN})
	v := validatorForAddr(addr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if prob := v.ValidateTLSALPN01(ctx, ip, keyAuth); prob != nil {
		t.Fatalf("expected IP tls-alpn-01 validation to succeed, got: %v", prob)
	}

	// A certificate presenting the wrong IP must fail the subjectAltName check.
	certWrong := newValidationCert(t, validationCertOpts{
		digest:   sum[:],
		critical: true,
		ipAddrs:  []net.IP{net.ParseIP("192.0.2.99")},
	})
	addrWrong := startTLSALPNResponder(t, certWrong, []string{acmeTLS1ALPN})
	if prob := validatorForAddr(addrWrong).ValidateTLSALPN01(ctx, ip, keyAuth); prob == nil {
		t.Fatal("expected mismatched IP subjectAltName to be rejected")
	}
}

// TestValidateTLSALPN01_DialFailure confirms an unreachable responder yields a
// connection problem rather than a panic or success.
func TestValidateTLSALPN01_DialFailure(t *testing.T) {
	v := &Validator{
		TLSDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Err: errUnreachable{}}
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	prob := v.ValidateTLSALPN01(ctx, "example.test", "ka")
	if prob == nil || prob.Type != probConnection {
		t.Fatalf("expected connection problem, got %v", prob)
	}
}

type errUnreachable struct{}

func (errUnreachable) Error() string { return "network is unreachable" }
