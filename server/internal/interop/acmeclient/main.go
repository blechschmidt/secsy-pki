// Command acmeclient is a small helper used by the external-client interop
// suite (scripts/interop-test.sh) for the two ACME checks the shell client
// acme.sh cannot perform:
//
//   - mode "iporder": drive a full RFC 8738 IP-identifier order (newAccount with
//     External Account Binding, newOrder for an "ip" identifier, http-01
//     validation served from an in-process responder, finalize) and assert the
//     issued certificate carries the requested IP SAN. It uses
//     golang.org/x/crypto/acme — the ACME stack real Go clients (lego, etc.)
//     build on — so it is an independent client, not this server's own code.
//
//   - mode "certid": print the draft-ietf-acme-ari CertID for a PEM certificate,
//     so the shell suite can query the renewalInfo endpoint for an acme.sh-issued
//     certificate. The CertID is computed with the server's exported reference
//     helper (acme.CertID), the authoritative encoding of §4.1.
//
// It is a test-only helper, run with `go run`; it is not part of the product.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/blechschmidt/secsy-pki/server/internal/acme"
)

func main() {
	mode := flag.String("mode", "iporder", "iporder | certid")
	dir := flag.String("dir", "", "ACME directory URL")
	eabKID := flag.String("eab-kid", "", "External Account Binding key id")
	eabHMAC := flag.String("eab-hmac", "", "External Account Binding HMAC key (base64url)")
	ip := flag.String("ip", "127.0.0.1", "IP identifier to enroll")
	httpPort := flag.Int("http-port", 5002, "port to serve the http-01 response on")
	caFile := flag.String("cafile", "", "PEM file to trust for the ACME server TLS cert")
	insecure := flag.Bool("insecure", false, "skip ACME server TLS verification")
	certOut := flag.String("certout", "", "write the issued certificate PEM here")
	certIn := flag.String("cert", "", "certificate PEM to compute a CertID for (mode certid)")
	flag.Parse()

	switch *mode {
	case "certid":
		if err := runCertID(*certIn); err != nil {
			log.Fatalf("acmeclient certid: %v", err)
		}
	case "iporder":
		if err := runIPOrder(ipOrderConfig{
			dir: *dir, eabKID: *eabKID, eabHMAC: *eabHMAC, ip: *ip,
			httpPort: *httpPort, caFile: *caFile, insecure: *insecure, certOut: *certOut,
		}); err != nil {
			log.Fatalf("acmeclient iporder: %v", err)
		}
	default:
		log.Fatalf("acmeclient: unknown mode %q", *mode)
	}
}

// runCertID prints the ARI CertID of a PEM certificate using the server's
// reference encoder.
func runCertID(path string) error {
	if path == "" {
		return fmt.Errorf("-cert is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("no PEM certificate in %s", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	id, err := acme.CertID(cert)
	if err != nil {
		return err
	}
	fmt.Println(id)
	return nil
}

type ipOrderConfig struct {
	dir, eabKID, eabHMAC, ip, caFile, certOut string
	httpPort                                  int
	insecure                                  bool
}

// runIPOrder performs an RFC 8738 IP-identifier order end to end and verifies
// the issued certificate carries the requested IP SAN.
func runIPOrder(cfg ipOrderConfig) error {
	if cfg.dir == "" || cfg.eabKID == "" || cfg.eabHMAC == "" {
		return fmt.Errorf("-dir, -eab-kid and -eab-hmac are required")
	}
	ipAddr := net.ParseIP(cfg.ip)
	if ipAddr == nil {
		return fmt.Errorf("invalid -ip %q", cfg.ip)
	}
	hmacKey, err := base64.RawURLEncoding.DecodeString(cfg.eabHMAC)
	if err != nil {
		// Tolerate standard base64 with padding.
		hmacKey, err = base64.StdEncoding.DecodeString(cfg.eabHMAC)
		if err != nil {
			return fmt.Errorf("decoding EAB HMAC key: %w", err)
		}
	}

	httpClient, err := acmeHTTPClient(cfg.caFile, cfg.insecure)
	if err != nil {
		return err
	}

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	client := &xacme.Client{Key: accountKey, DirectoryURL: cfg.dir, HTTPClient: httpClient}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Serve the http-01 key authorizations from an in-process responder. The
	// server validates by connecting to the IP identifier directly (no DNS).
	responses := &challengeResponder{resp: map[string]string{}}
	srv := &http.Server{Addr: fmt.Sprintf(":%d", cfg.httpPort), Handler: responses}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("binding http-01 responder on :%d: %w", cfg.httpPort, err)
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	acct := &xacme.Account{ExternalAccountBinding: &xacme.ExternalAccountBinding{KID: cfg.eabKID, Key: hmacKey}}
	if _, err := client.Register(ctx, acct, xacme.AcceptTOS); err != nil {
		return fmt.Errorf("newAccount (EAB): %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, xacme.IPIDs(cfg.ip))
	if err != nil {
		return fmt.Errorf("newOrder (ip identifier): %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authzURL)
		if err != nil {
			return fmt.Errorf("getAuthorization: %w", err)
		}
		if authz.Status == xacme.StatusValid {
			continue
		}
		var chal *xacme.Challenge
		for _, ch := range authz.Challenges {
			if ch.Type == "http-01" {
				chal = ch
			}
		}
		if chal == nil {
			return fmt.Errorf("no http-01 challenge offered for IP identifier")
		}
		keyAuth, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return err
		}
		responses.set(client.HTTP01ChallengePath(chal.Token), keyAuth)
		if _, err := client.Accept(ctx, chal); err != nil {
			return fmt.Errorf("accept http-01: %w", err)
		}
		if _, err := client.WaitAuthorization(ctx, authzURL); err != nil {
			return fmt.Errorf("waitAuthorization: %w", err)
		}
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	// An IP-identifier CSR carries only the IP SAN: a CommonName would be matched
	// against the order as a DNS identifier and rejected (RFC 8555 §7.4).
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		IPAddresses: []net.IP{ipAddr},
	}, leafKey)
	if err != nil {
		return fmt.Errorf("building CSR: %w", err)
	}

	ders, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return fmt.Errorf("finalize: %w", err)
	}
	if len(ders) == 0 {
		return fmt.Errorf("finalize returned no certificate")
	}
	leaf, err := x509.ParseCertificate(ders[0])
	if err != nil {
		return fmt.Errorf("parsing issued certificate: %w", err)
	}

	found := false
	for _, got := range leaf.IPAddresses {
		if got.Equal(ipAddr) {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("issued certificate does not carry IP SAN %s (got %v)", cfg.ip, leaf.IPAddresses)
	}

	if cfg.certOut != "" {
		if err := os.WriteFile(cfg.certOut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ders[0]}), 0o644); err != nil {
			return err
		}
	}
	fmt.Printf("issued IP-identifier certificate: serial=%s ip_sans=%v\n", leaf.SerialNumber, leaf.IPAddresses)
	return nil
}

// acmeHTTPClient builds an HTTP client that trusts the ACME server's TLS
// certificate (from caFile) or, with insecure, skips verification.
func acmeHTTPClient(caFile string, insecure bool) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	switch {
	case insecure:
		tlsCfg.InsecureSkipVerify = true
	case caFile != "":
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates parsed from %s", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// challengeResponder serves http-01 key authorizations by request path. It is
// written from the ordering goroutine and read from the HTTP server goroutine,
// so accesses are guarded.
type challengeResponder struct {
	mu   sync.Mutex
	resp map[string]string
}

func (c *challengeResponder) set(path, body string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.resp[path] = body
}

func (c *challengeResponder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	body, ok := c.resp[r.URL.Path]
	c.mu.Unlock()
	if ok {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte(body))
		return
	}
	http.NotFound(w, r)
}
