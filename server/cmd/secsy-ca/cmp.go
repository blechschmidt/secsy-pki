package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cmp"
)

// cmdCMP is a Lightweight CMP (RFC 9483) client for smoke-testing a running
// /cmp endpoint. It generates a fresh EC key, sends a MAC-protected ir (or cr)
// request authenticated by a shared secret, and prints the issued certificate.
func cmdCMP(args []string) error {
	fs := flag.NewFlagSet("cmp", flag.ContinueOnError)
	url := fs.String("url", "", "CMP endpoint URL, e.g. https://host:8443/cmp (required)")
	reference := fs.String("reference", "", "shared-secret reference value / senderKID (required)")
	secret := fs.String("secret", "", "shared secret value (required)")
	cn := fs.String("cn", "", "subject common name for the requested certificate (required)")
	dns := fs.String("dns", "", "comma-separated DNS SANs")
	operation := fs.String("operation", "ir", "request type: ir (initialization) or cr (certification)")
	certOut := fs.String("cert-out", "", "write the issued certificate PEM to this file")
	keyOut := fs.String("key-out", "", "write the generated private key PEM to this file")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification (testing only)")
	timeout := fs.Duration("timeout", 30*time.Second, "HTTP request timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *url == "" || *reference == "" || *secret == "" || *cn == "" {
		fs.Usage()
		return fmt.Errorf("cmp: -url, -reference, -secret and -cn are required")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating key: %w", err)
	}

	var dnsNames []string
	for _, d := range strings.Split(*dns, ",") {
		if d = strings.TrimSpace(d); d != "" {
			dnsNames = append(dnsNames, d)
		}
	}

	subject := pkix.Name{CommonName: *cn}
	opts := cmp.RequestOptions{DNSNames: dnsNames, ImplicitConfirm: true}

	var reqDER []byte
	switch strings.ToLower(*operation) {
	case "ir":
		reqDER, err = cmp.BuildInitializationRequest(*reference, *secret, subject, key, opts)
	case "cr":
		reqDER, err = cmp.BuildCertificationRequest(*reference, *secret, subject, key, opts)
	default:
		return fmt.Errorf("cmp: unknown -operation %q (want ir or cr)", *operation)
	}
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}

	respDER, err := postCMP(*url, reqDER, *insecure, *timeout)
	if err != nil {
		return err
	}

	res, err := cmp.ParseResponse(respDER)
	if err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}
	if !res.Accepted() {
		detail := res.StatusText
		if detail == "" {
			detail = fmt.Sprintf("status=%d", res.Status)
		}
		return fmt.Errorf("CMP request rejected: %s", detail)
	}
	if res.Certificate == nil {
		return fmt.Errorf("CMP response was accepted but carried no certificate")
	}

	cert := res.Certificate
	fmt.Printf("Enrollment succeeded.\n")
	fmt.Printf("  Subject: %s\n", cert.Subject)
	fmt.Printf("  Serial:  %s\n", cert.SerialNumber)
	fmt.Printf("  Issuer:  %s\n", cert.Issuer)
	fmt.Printf("  Expires: %s\n", cert.NotAfter.UTC().Format(time.RFC3339))

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if *certOut != "" {
		if err := os.WriteFile(*certOut, certPEM, 0o644); err != nil {
			return fmt.Errorf("writing certificate: %w", err)
		}
		fmt.Printf("  Wrote certificate to %s\n", *certOut)
	} else {
		fmt.Printf("\n%s", certPEM)
	}

	if *keyOut != "" {
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return fmt.Errorf("marshaling key: %w", err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		if err := os.WriteFile(*keyOut, keyPEM, 0o600); err != nil {
			return fmt.Errorf("writing key: %w", err)
		}
		fmt.Printf("  Wrote private key to %s\n", *keyOut)
	}
	return nil
}

// postCMP sends a PKIMessage to a CMP endpoint and returns the response body.
func postCMP(url string, reqDER []byte, insecure bool, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	if insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(reqDER))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/pkixcmp")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending CMP request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CMP endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}
