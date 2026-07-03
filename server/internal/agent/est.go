package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
)

// maxESTResponseBytes bounds enrollment response reads.
const maxESTResponseBytes = 1 << 20

// estClient speaks RFC 7030 against the server's EST endpoints.
type estClient struct {
	baseURL  string // e.g. https://pki.example.com/.well-known/est
	username string
	password string
	http     *http.Client
}

func newESTClient(cfg ESTConfig, client *http.Client) (*estClient, error) {
	password := cfg.Password
	if cfg.PasswordFile != "" {
		data, err := os.ReadFile(cfg.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("reading est.password_file: %w", err)
		}
		password = strings.TrimSpace(string(data))
	}
	return &estClient{
		baseURL:  strings.TrimRight(cfg.URL, "/"),
		username: cfg.Username,
		password: password,
		http:     client,
	}, nil
}

// Enroll performs simpleenroll (or simplereenroll when reenroll is true) with
// the given PKCS#10 request and returns the certificates from the server's
// certs-only PKCS#7 response, leaf first.
//
// Authentication is HTTP Basic with the configured bootstrap credential. When
// renewing over TLS and the previous certificate/key pair is supplied, it is
// additionally presented as a TLS client certificate so servers configured
// with allow_tls_client_reenroll accept the request even without Basic
// credentials (RFC 7030 §3.3.2).
func (c *estClient) Enroll(ctx context.Context, csrDER []byte, reenroll bool, clientCert *tls.Certificate) ([]*x509.Certificate, error) {
	endpoint := c.baseURL + "/simpleenroll"
	if reenroll {
		endpoint = c.baseURL + "/simplereenroll"
	}
	body := base64.StdEncoding.EncodeToString(csrDER)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("building EST request: %w", err)
	}
	req.Header.Set("Content-Type", "application/pkcs10")
	req.Header.Set("Content-Transfer-Encoding", "base64")
	if c.username != "" {
		req.SetBasicAuth(c.username, c.password)
	}

	client := c.http
	if clientCert != nil && strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		client = c.clientWithCert(clientCert)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("EST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxESTResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading EST response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EST %s returned %s: %s", endpoint, resp.Status, summarizeBody(raw))
	}
	certs, err := parseCertsOnlyPKCS7(raw)
	if err != nil {
		return nil, fmt.Errorf("EST enrollment response: %w", err)
	}
	return certs, nil
}

// CACerts fetches the server's CA chain from /cacerts.
func (c *estClient) CACerts(ctx context.Context) ([]*x509.Certificate, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/cacerts", nil)
	if err != nil {
		return nil, fmt.Errorf("building cacerts request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("EST cacerts: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxESTResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading cacerts response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EST cacerts returned %s: %s", resp.Status, summarizeBody(raw))
	}
	certs, err := parseCertsOnlyPKCS7(raw)
	if err != nil {
		return nil, fmt.Errorf("EST cacerts response: %w", err)
	}
	return certs, nil
}

// clientWithCert clones the agent's HTTP client with a TLS client certificate
// attached for certificate-based reenrollment.
func (c *estClient) clientWithCert(cert *tls.Certificate) *http.Client {
	base, _ := c.http.Transport.(*http.Transport)
	var transport *http.Transport
	if base != nil {
		transport = base.Clone()
	} else {
		transport = &http.Transport{}
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.Certificates = []tls.Certificate{*cert}
	return &http.Client{Timeout: c.http.Timeout, Transport: transport}
}

// parseCertsOnlyPKCS7 decodes an RFC 7030 response body: base64 (whitespace
// and line wraps tolerated) wrapping a certs-only PKCS#7. Raw DER is accepted
// as a fallback.
func parseCertsOnlyPKCS7(body []byte) ([]*x509.Certificate, error) {
	compact := strings.Join(strings.Fields(string(body)), "")
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		der = body
	}
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return nil, err
	}
	if len(sd.Certificates) == 0 {
		return nil, fmt.Errorf("PKCS#7 holds no certificates")
	}
	return sd.Certificates, nil
}

// summarizeBody renders an error response body for diagnostics without
// dumping binary blobs into logs.
func summarizeBody(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	if s == "" {
		return "(empty body)"
	}
	for _, r := range s {
		if r < 0x09 || (r > 0x0d && r < 0x20) {
			return "(binary body)"
		}
	}
	return s
}
