//go:build sqlite

// These tests exercise the ACME server end-to-end using the golang.org/x/crypto
// /acme client and the software key provider, so they run without an HSM (a
// SoftHSM-backed variant lives in internal/e2e). They cover the full protocol —
// account registration, http-01 and dns-01 orders, finalize, download — plus
// error paths (nonce replay, CSR/identifier mismatch).
package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	xacme "golang.org/x/crypto/acme"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

type testEnv struct {
	db       *database.DB
	srv      *Server
	caID     string
	dirURL   string
	baseURL  string
	roots    *x509.CertPool
	inters   *x509.CertPool
	resolver *fakeResolver
	httpMu   sync.Mutex
	httpResp map[string]string
	// tlsALPNAddr is the address of the in-process tls-alpn-01 responder the
	// validator dials; set by tls-alpn-01 tests before accepting the challenge.
	tlsALPNAddr string
}

type fakeResolver struct {
	mu   sync.Mutex
	recs map[string][]string
}

func (f *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if v, ok := f.recs[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "not found", Name: name, IsNotFound: true}
}

// newTestEnv builds a hermetic ACME server (software provider, SQLite, in-process
// challenge responders). Optional opts mutate the acme.Config before the server
// is constructed — used by the ACME Profiles tests to configure a selectable
// profile allowlist; existing callers pass none and get the single-profile server.
func newTestEnv(t *testing.T, opts ...func(*Config)) *testEnv {
	t.Helper()
	provider, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()},
	})
	if err != nil {
		t.Fatalf("software provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	db, err := database.New("sqlite", t.TempDir()+"/acme.db")
	if err != nil {
		t.Fatalf("db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	mgr := ca.NewManager(db, provider)
	ctx := context.Background()
	root, err := mgr.InitRoot(ctx, ca.RootSpec{
		Label:    "acme-unit-root",
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "ACME Unit Root"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("InitRoot: %v", err)
	}
	inter, err := mgr.IssueIntermediate(ctx, ca.IntermediateSpec{
		ParentID: root.ID,
		Label:    "acme-unit-inter",
		KeyType:  keyprovider.KeyTypeECDSAP256,
		Subject:  ca.PKIXName(models.CASubject{CommonName: "ACME Unit Issuing CA"}),
		Validity: 5 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("IssueIntermediate: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(mustDER(t, root.Certificate))
	interCert, _ := x509.ParseCertificate(mustDER(t, inter.Certificate))
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	inters := x509.NewCertPool()
	inters.AddCert(interCert)

	env := &testEnv{
		db:       db,
		roots:    roots,
		inters:   inters,
		resolver: &fakeResolver{recs: map[string][]string{}},
		httpResp: map[string]string{},
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	solverAddr := lis.Addr().String()
	solver := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		const prefix = "/.well-known/acme-challenge/"
		token := strings.TrimPrefix(r.URL.Path, prefix)
		env.httpMu.Lock()
		resp, ok := env.httpResp[token]
		env.httpMu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(resp))
	})}
	go solver.Serve(lis)
	t.Cleanup(func() { solver.Close() })

	cfg := Config{CAID: inter.ID, Profile: "server"}
	for _, opt := range opts {
		opt(&cfg)
	}
	srv := New(db, provider, cfg)
	srv.SetValidator(&Validator{
		HTTPClient: &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, solverAddr)
			},
		}},
		Resolver:    env.resolver,
		HTTPPort:    80,
		TLSALPNPort: 443,
		// tls-alpn-01 dials are redirected to the per-test in-process responder.
		TLSDialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			env.httpMu.Lock()
			addr := env.tlsALPNAddr
			env.httpMu.Unlock()
			if addr == "" {
				return nil, &net.OpError{Op: "dial", Err: errNoTLSALPNResponder{}}
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	})
	mux := http.NewServeMux()
	srv.Register(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	env.srv = srv
	env.caID = inter.ID
	env.baseURL = ts.URL
	env.dirURL = ts.URL + "/acme/directory"
	return env
}

func mustDER(t *testing.T, pemStr string) []byte {
	t.Helper()
	rest := []byte(pemStr)
	for {
		var p *pem.Block
		p, rest = pem.Decode(rest)
		if p == nil {
			t.Fatalf("no CERTIFICATE block in PEM")
		}
		if p.Type == "CERTIFICATE" {
			return p.Bytes
		}
	}
}

func (env *testEnv) client(t *testing.T) *xacme.Client {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &xacme.Client{Key: key, DirectoryURL: env.dirURL}
	if _, err := c.Register(context.Background(), &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return c
}

func (env *testEnv) solve(t *testing.T, c *xacme.Client, order *xacme.Order, challType string, domain string) {
	t.Helper()
	ctx := context.Background()
	for _, au := range order.AuthzURLs {
		authz, err := c.GetAuthorization(ctx, au)
		if err != nil {
			t.Fatalf("GetAuthorization: %v", err)
		}
		var chal *xacme.Challenge
		for _, ch := range authz.Challenges {
			if ch.Type == challType {
				chal = ch
			}
		}
		if chal == nil {
			t.Fatalf("no %s challenge", challType)
		}
		switch challType {
		case "http-01":
			resp, _ := c.HTTP01ChallengeResponse(chal.Token)
			env.httpMu.Lock()
			env.httpResp[chal.Token] = resp
			env.httpMu.Unlock()
		case "dns-01":
			rec, _ := c.DNS01ChallengeRecord(chal.Token)
			env.resolver.mu.Lock()
			env.resolver.recs["_acme-challenge."+domain] = []string{rec}
			env.resolver.mu.Unlock()
		}
		if _, err := c.Accept(ctx, chal); err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if _, err := c.WaitAuthorization(ctx, au); err != nil {
			t.Fatalf("WaitAuthorization: %v", err)
		}
	}
}

func csrFor(t *testing.T, domain string) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestACME_HTTP01(t *testing.T) {
	env := newTestEnv(t)
	c := env.client(t)
	ctx := context.Background()
	domain := "web.example.test"
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	env.solve(t, c, order, "http-01", domain)
	if _, err := c.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	der, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, domain), true)
	if err != nil {
		t.Fatalf("CreateOrderCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: env.roots, Intermediates: env.inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
}

func TestACME_DNS01(t *testing.T) {
	env := newTestEnv(t)
	c := env.client(t)
	ctx := context.Background()
	domain := "dns.example.test"
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	env.solve(t, c, order, "dns-01", domain)
	if _, err := c.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	if _, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, domain), true); err != nil {
		t.Fatalf("CreateOrderCert: %v", err)
	}
}

// TestACME_TLSALPN01 drives a full order to a certificate over the tls-alpn-01
// challenge (RFC 8737), using the x/crypto client's own validation-certificate
// builder as an interop check: the server must offer tls-alpn-01, dial the
// in-process responder over "acme-tls/1", accept the presented certificate, and
// finalize the order.
func TestACME_TLSALPN01(t *testing.T) {
	env := newTestEnv(t)
	c := env.client(t)
	ctx := context.Background()
	domain := "alpn.example.test"
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}

	var chal *xacme.Challenge
	for _, au := range order.AuthzURLs {
		authz, err := c.GetAuthorization(ctx, au)
		if err != nil {
			t.Fatalf("GetAuthorization: %v", err)
		}
		for _, ch := range authz.Challenges {
			if ch.Type == "tls-alpn-01" {
				chal = ch
			}
		}
	}
	if chal == nil {
		t.Fatal("server did not offer a tls-alpn-01 challenge")
	}

	cert, err := c.TLSALPN01ChallengeCert(chal.Token, domain)
	if err != nil {
		t.Fatalf("TLSALPN01ChallengeCert: %v", err)
	}
	addr := startTLSALPNResponder(t, cert, []string{acmeTLS1ALPN})
	env.httpMu.Lock()
	env.tlsALPNAddr = addr
	env.httpMu.Unlock()

	if _, err := c.Accept(ctx, chal); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	for _, au := range order.AuthzURLs {
		if _, err := c.WaitAuthorization(ctx, au); err != nil {
			t.Fatalf("WaitAuthorization: %v", err)
		}
	}
	if _, err := c.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	der, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, domain), true)
	if err != nil {
		t.Fatalf("CreateOrderCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: env.roots, Intermediates: env.inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
}

// TestACME_TLSALPN01_BadCertRejected confirms the authorization is marked invalid
// when the responder presents a certificate committing to the wrong key
// authorization.
func TestACME_TLSALPN01_BadCertRejected(t *testing.T) {
	env := newTestEnv(t)
	c := env.client(t)
	ctx := context.Background()
	domain := "bad-alpn.example.test"
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	var chal *xacme.Challenge
	for _, au := range order.AuthzURLs {
		authz, _ := c.GetAuthorization(ctx, au)
		for _, ch := range authz.Challenges {
			if ch.Type == "tls-alpn-01" {
				chal = ch
			}
		}
	}
	if chal == nil {
		t.Fatal("server did not offer a tls-alpn-01 challenge")
	}
	// Present a certificate for a *different* token, so its committed digest does
	// not match this challenge's key authorization.
	cert, err := c.TLSALPN01ChallengeCert(chal.Token+"-wrong", domain)
	if err != nil {
		t.Fatalf("TLSALPN01ChallengeCert: %v", err)
	}
	addr := startTLSALPNResponder(t, cert, []string{acmeTLS1ALPN})
	env.httpMu.Lock()
	env.tlsALPNAddr = addr
	env.httpMu.Unlock()

	if _, err := c.Accept(ctx, chal); err != nil {
		t.Fatalf("Accept: %v", err)
	}
	// The authorization must end up invalid, not valid.
	if _, err := c.WaitAuthorization(ctx, order.AuthzURLs[0]); err == nil {
		t.Fatal("expected authorization to fail for a mismatched tls-alpn-01 certificate")
	}
}

// errNoTLSALPNResponder is returned by the test validator's tls-alpn-01 dialer
// when a test has not stood up a responder.
type errNoTLSALPNResponder struct{}

func (errNoTLSALPNResponder) Error() string { return "no tls-alpn-01 responder configured" }

func TestACME_CSRIdentifierMismatchRejected(t *testing.T) {
	env := newTestEnv(t)
	c := env.client(t)
	ctx := context.Background()
	domain := "match.example.test"
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	env.solve(t, c, order, "http-01", domain)
	if _, err := c.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	// A CSR for a different name than was authorized must be refused.
	if _, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrFor(t, "evil.example.test"), true); err == nil {
		t.Fatal("finalize with a mismatched CSR domain must be rejected")
	}
}

func TestACME_RejectsUnauthorizedSANInjection(t *testing.T) {
	env := newTestEnv(t)
	c := env.client(t)
	ctx := context.Background()
	domain := "san.example.test"
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	env.solve(t, c, order, "http-01", domain)
	if _, err := c.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	// CSR authorizes the ordered DNS name but smuggles in an unauthorized email
	// SAN. Finalize must reject it (SAN injection guard).
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames:       []string{domain},
		EmailAddresses: []string{"attacker@evil.example"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true); err == nil {
		t.Fatal("finalize with an unauthorized email SAN must be rejected")
	}
}

func TestACME_DuplicateAccountReturnsSame(t *testing.T) {
	env := newTestEnv(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ctx := context.Background()

	c1 := &xacme.Client{Key: key, DirectoryURL: env.dirURL}
	if _, err := c1.Register(ctx, &xacme.Account{}, xacme.AcceptTOS); err != nil {
		t.Fatalf("first register: %v", err)
	}
	// Registering again with the same key must be recognized as the existing
	// account: the client surfaces the server's 200 as ErrAccountAlreadyExists.
	c2 := &xacme.Client{Key: key, DirectoryURL: env.dirURL}
	_, err := c2.Register(ctx, &xacme.Account{}, xacme.AcceptTOS)
	if err != xacme.ErrAccountAlreadyExists {
		t.Fatalf("re-register with same key: got %v, want ErrAccountAlreadyExists", err)
	}
	// And the account is retrievable, confirming the key binding is stable.
	if _, err := c2.GetReg(ctx, ""); err != nil {
		t.Fatalf("GetReg after existing-account: %v", err)
	}
}
