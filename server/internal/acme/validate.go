package acme

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Resolver is the DNS lookup surface used for dns-01 validation. It is an
// interface so tests can inject a deterministic resolver instead of hitting the
// network.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// Validator performs the outbound checks that satisfy ACME challenges. It is
// configured with an HTTP client and DNS resolver so the network behavior is
// controllable in tests.
type Validator struct {
	// HTTPClient issues the http-01 GET. It should have a modest timeout and
	// bounded redirects.
	HTTPClient *http.Client
	// Resolver answers dns-01 TXT lookups.
	Resolver Resolver
	// HTTPPort is the TCP port used for http-01 validation. RFC 8555 mandates
	// port 80; it is configurable only so integration tests can run without
	// binding a privileged port.
	HTTPPort int
	// TLSALPNPort is the TCP port used for tls-alpn-01 validation. RFC 8737
	// mandates port 443; it is configurable only so tests can avoid a privileged
	// port. Zero means 443.
	TLSALPNPort int
	// TLSDialContext, when non-nil, establishes the raw TCP connection used for
	// the tls-alpn-01 handshake. Production leaves it nil to use a default
	// dialer; tests point it at an in-process listener.
	TLSDialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// maxHTTP01Body bounds how many bytes we read from the challenge resource.
const maxHTTP01Body = 4096

// newValidator builds a Validator with sane production defaults. dnsResolver,
// when non-empty, is a host:port DNS server address that pins ALL challenge
// validation to a single DNS view: dns-01 TXT lookups, the http-01 fetch's
// A/AAAA resolution, and the tls-alpn-01 dial's A/AAAA resolution. The default
// (empty) leaves each to the system resolver, preserving prior behavior.
func newValidator(httpPort, tlsALPNPort int, dnsResolver string) *Validator {
	if httpPort == 0 {
		httpPort = 80
	}
	if tlsALPNPort == 0 {
		tlsALPNPort = 443
	}
	v := &Validator{
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		Resolver:    net.DefaultResolver,
		HTTPPort:    httpPort,
		TLSALPNPort: tlsALPNPort,
	}
	// When a resolver is pinned, use it for the dns-01 TXT lookup and route the
	// http-01 and tls-alpn-01 dials through it so a name resolves the same way for
	// every challenge type. Used by the interop test harness (which serves the
	// challenge targets and TXT records from one local DNS server) and by
	// split-horizon deployments that must validate against a specific view.
	if addr := strings.TrimSpace(dnsResolver); addr != "" {
		res := pinnedResolver(addr)
		v.Resolver = res
		dial := resolvingDialContext(res)
		v.HTTPClient.Transport = &http.Transport{
			DialContext:         dial,
			TLSHandshakeTimeout: 10 * time.Second,
		}
		v.TLSDialContext = dial
	}
	return v
}

// pinnedResolver returns a Go resolver that sends every query to the DNS server
// at addr (host:port).
func pinnedResolver(addr string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
}

// resolvingDialContext returns a DialContext that resolves the target host with
// res before connecting, so http-01 fetches and tls-alpn-01 handshakes use the
// pinned DNS view. An address that is already an IP (as for RFC 8738 ip-type
// identifiers) is dialed directly.
func resolvingDialContext(res *net.Resolver) func(ctx context.Context, network, addr string) (net.Conn, error) {
	d := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || net.ParseIP(host) != nil {
			return d.DialContext(ctx, network, addr)
		}
		ips, err := res.LookupHost(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no addresses for %s", host)
		}
		return d.DialContext(ctx, network, net.JoinHostPort(ips[0], port))
	}
}

// ValidateHTTP01 performs an http-01 challenge check (RFC 8555 §8.3): it fetches
// http://<domain>/.well-known/acme-challenge/<token> and requires the body to
// equal the key authorization. It returns nil on success or an ACME problem.
func (v *Validator) ValidateHTTP01(ctx context.Context, domain, token, keyAuth string) *Problem {
	host := domain
	if v.HTTPPort != 0 && v.HTTPPort != 80 {
		host = net.JoinHostPort(domain, fmt.Sprintf("%d", v.HTTPPort))
	}
	url := fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", host, token)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return newProblem(probMalformed, http.StatusBadRequest, "building http-01 request: "+err.Error())
	}
	req.Header.Set("User-Agent", "secsy-pki-acme/1.0")
	req.Header.Set("Accept", "*/*")

	resp, err := v.HTTPClient.Do(req)
	if err != nil {
		return newProblem(probConnection, http.StatusBadRequest,
			fmt.Sprintf("fetching http-01 challenge at %s: %v", url, err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return newProblem(probUnauthorized, http.StatusForbidden,
			fmt.Sprintf("http-01 challenge at %s returned HTTP %d", url, resp.StatusCode))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTP01Body))
	if err != nil {
		return newProblem(probConnection, http.StatusBadRequest, "reading http-01 response body: "+err.Error())
	}

	// The response body must equal the key authorization. Trailing whitespace is
	// tolerated per common practice (RFC 8555 §8.3).
	got := strings.TrimSpace(string(body))
	if got != keyAuth {
		return newProblem(probIncorrectResponse, http.StatusForbidden,
			"http-01 response did not match the expected key authorization")
	}
	return nil
}

// ValidateDNS01 performs a dns-01 challenge check (RFC 8555 §8.4): it looks up
// the TXT records at _acme-challenge.<domain> and requires one to equal
// base64url(SHA-256(keyAuthorization)).
func (v *Validator) ValidateDNS01(ctx context.Context, domain, keyAuth string) *Problem {
	want := dns01Digest(keyAuth)
	name := "_acme-challenge." + strings.TrimSuffix(domain, ".")

	txts, err := v.Resolver.LookupTXT(ctx, name)
	if err != nil {
		return newProblem(probDNS, http.StatusBadRequest,
			fmt.Sprintf("looking up TXT %s: %v", name, err))
	}
	for _, txt := range txts {
		if strings.TrimSpace(txt) == want {
			return nil
		}
	}
	return newProblem(probIncorrectResponse, http.StatusForbidden,
		fmt.Sprintf("no TXT record at %s matched the expected dns-01 digest", name))
}

// dns01Digest computes the base64url(SHA-256(keyAuthorization)) value expected in
// the _acme-challenge TXT record.
func dns01Digest(keyAuth string) string {
	sum := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
