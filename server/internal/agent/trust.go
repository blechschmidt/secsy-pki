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
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
)

// maxTrustBundleBytes bounds how much of a bundle response is read.
const maxTrustBundleBytes = 1 << 20

// trustBundle is the set of anchors newly issued chains must verify against
// before they are installed.
type trustBundle struct {
	// roots holds every bundle certificate: trust anchors need not be
	// self-signed (an operator may pin an intermediate).
	roots *x509.CertPool
	// intermediates additionally holds the non-self-signed bundle certificates
	// so partial chains from the server can still be completed.
	intermediates *x509.CertPool
	// issuers are the non-leaf certificates in fetch order, used to build
	// chain_file contents for EST enrollments (which return only the leaf).
	issuers   []*x509.Certificate
	fetchedAt time.Time
}

// loadTrustBundle resolves the configured trust source. File bundles are
// re-read every call; URL bundles are fetched with client.
func (a *Agent) loadTrustBundle(ctx context.Context) (*trustBundle, error) {
	cfg := a.cfg.Trust
	if cfg.BundleFile != "" {
		data, err := os.ReadFile(cfg.BundleFile)
		if err != nil {
			return nil, fmt.Errorf("reading trust bundle: %w", err)
		}
		certs, err := parseCertsPEM(data)
		if err != nil {
			return nil, fmt.Errorf("trust bundle %s: %w", cfg.BundleFile, err)
		}
		return newTrustBundle(certs, a.now()), nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.BundleURL, nil)
	if err != nil {
		return nil, fmt.Errorf("building trust bundle request: %w", err)
	}
	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching trust bundle: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching trust bundle: %s returned %s", cfg.BundleURL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTrustBundleBytes))
	if err != nil {
		return nil, fmt.Errorf("reading trust bundle: %w", err)
	}
	certs, err := parseBundleBody(body)
	if err != nil {
		return nil, fmt.Errorf("trust bundle from %s: %w", cfg.BundleURL, err)
	}
	return newTrustBundle(certs, a.now()), nil
}

// parseBundleBody accepts a PEM concatenation or an EST-style base64
// certs-only PKCS#7 (as served by /cacerts).
func parseBundleBody(body []byte) ([]*x509.Certificate, error) {
	trimmed := strings.TrimSpace(string(body))
	if strings.Contains(trimmed, "-----BEGIN") {
		return parseCertsPEM(body)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(trimmed), ""))
	if err != nil {
		return nil, fmt.Errorf("body is neither PEM nor base64 PKCS#7: %w", err)
	}
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS#7: %w", err)
	}
	if len(sd.Certificates) == 0 {
		return nil, fmt.Errorf("PKCS#7 bundle holds no certificates")
	}
	return sd.Certificates, nil
}

func newTrustBundle(certs []*x509.Certificate, now time.Time) *trustBundle {
	tb := &trustBundle{
		roots:         x509.NewCertPool(),
		intermediates: x509.NewCertPool(),
		fetchedAt:     now,
	}
	for _, c := range certs {
		tb.roots.AddCert(c)
		if !c.IsCA {
			continue
		}
		tb.issuers = append(tb.issuers, c)
		if !isSelfSigned(c) {
			tb.intermediates.AddCert(c)
		}
	}
	return tb
}

func isSelfSigned(c *x509.Certificate) bool {
	if !c.IsCA || c.Subject.String() != c.Issuer.String() {
		return false
	}
	return c.CheckSignatureFrom(c) == nil
}

// verifyChain checks that leaf verifies to the trust bundle at time now, using
// the enrollment response's extra certificates plus the bundle's issuers as
// intermediates. It returns the verified chain (leaf first, anchors last).
func (tb *trustBundle) verifyChain(leaf *x509.Certificate, extras []*x509.Certificate, now time.Time) ([]*x509.Certificate, error) {
	inters := x509.NewCertPool()
	for _, c := range extras {
		inters.AddCert(c)
	}
	for _, c := range tb.issuers {
		inters.AddCert(c)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         tb.roots,
		Intermediates: inters,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("issued certificate does not chain to the trust bundle: %w", err)
	}
	return chains[0], nil
}

// newHTTPClient builds the client used for all server traffic (EST, ACME,
// trust bundle, ARI) honoring the transport-trust settings.
func newHTTPClient(cfg ServerConfig) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.InsecureSkipVerify {
		tlsCfg.InsecureSkipVerify = true
	}
	if cfg.TLSCAFile != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		pemData, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("reading server.tls_ca_file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("server.tls_ca_file %s holds no usable certificates", cfg.TLSCAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &http.Client{
		Timeout: cfg.Timeout.Std(),
		Transport: &http.Transport{
			TLSClientConfig:   tlsCfg,
			ForceAttemptHTTP2: true,
			Proxy:             http.ProxyFromEnvironment,
		},
	}, nil
}
