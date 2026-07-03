package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	xacme "golang.org/x/crypto/acme"
)

// accountKeyFile is the ACME account key location inside the state dir.
const accountKeyFile = "acme-account.key"

// errARIUnsupported reports that the server's directory does not advertise
// the renewalInfo resource; callers fall back to fraction-of-lifetime timing.
var errARIUnsupported = errors.New("acme server does not advertise renewalInfo")

// acmeClient wraps golang.org/x/crypto/acme with account bootstrap (including
// EAB), http-01 solving, and the ARI renewal-info extension the stdlib client
// lacks.
type acmeClient struct {
	cfg      ACMEConfig
	stateDir string
	http     *http.Client
	solver   http01Solver

	mu         sync.Mutex
	client     *xacme.Client
	registered bool
	ariURL     string // renewalInfo base URL; "" until discovered
	ariLooked  bool
}

func newACMEClient(cfg ACMEConfig, stateDir string, httpClient *http.Client) *acmeClient {
	var solver http01Solver
	if cfg.HTTP01.Webroot != "" {
		solver = &webrootSolver{dir: cfg.HTTP01.Webroot}
	} else {
		solver = &listenerSolver{addr: cfg.HTTP01.Listen}
	}
	return &acmeClient{cfg: cfg, stateDir: stateDir, http: httpClient, solver: solver}
}

// ensureAccount lazily loads (or creates) the account key and registers the
// account, presenting External Account Binding credentials when configured.
// Registration against an already-known key is treated as success.
func (c *acmeClient) ensureAccount(ctx context.Context) (*xacme.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil && c.registered {
		return c.client, nil
	}
	if c.client == nil {
		key, err := c.loadOrCreateAccountKey()
		if err != nil {
			return nil, err
		}
		c.client = &xacme.Client{
			Key:          key,
			HTTPClient:   c.http,
			DirectoryURL: c.cfg.Directory,
			UserAgent:    "secsy-agent",
		}
	}
	acct := &xacme.Account{Contact: c.cfg.Contact}
	if c.cfg.EABKid != "" {
		hmacKey, err := c.eabHMACKey()
		if err != nil {
			return nil, err
		}
		acct.ExternalAccountBinding = &xacme.ExternalAccountBinding{KID: c.cfg.EABKid, Key: hmacKey}
	}
	_, err := c.client.Register(ctx, acct, xacme.AcceptTOS)
	if err != nil && !errors.Is(err, xacme.ErrAccountAlreadyExists) {
		return nil, fmt.Errorf("registering ACME account: %w", err)
	}
	c.registered = true
	return c.client, nil
}

// loadOrCreateAccountKey persists the ACME account key in the state dir so
// the account (and its EAB binding) survives restarts.
func (c *acmeClient) loadOrCreateAccountKey() (*ecdsa.PrivateKey, error) {
	path := filepath.Join(c.stateDir, accountKeyFile)
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("account key %s is not PEM", path)
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing account key %s: %w", path, err)
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("account key %s is a %T, want ECDSA", path, key)
		}
		return ec, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reading account key: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating account key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling account key: %w", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writeFileAtomic(path, pemData, 0o600); err != nil {
		return nil, fmt.Errorf("persisting account key: %w", err)
	}
	return key, nil
}

// eabHMACKey resolves and decodes the EAB HMAC key, tolerating the same
// base64 variants the server accepts.
func (c *acmeClient) eabHMACKey() ([]byte, error) {
	raw := c.cfg.EABHMACKey
	if c.cfg.EABHMACKeyFile != "" {
		data, err := os.ReadFile(c.cfg.EABHMACKeyFile)
		if err != nil {
			return nil, fmt.Errorf("reading acme.eab_hmac_key_file: %w", err)
		}
		raw = strings.TrimSpace(string(data))
	}
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding, base64.RawStdEncoding,
	} {
		if key, err := enc.DecodeString(raw); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("acme.eab_hmac_key is not valid base64")
}

// Enroll drives a full ACME order for the spec's SANs, answering http-01
// challenges, and finalizes it with csrDER. It returns the issued chain, leaf
// first.
func (c *acmeClient) Enroll(ctx context.Context, spec *CertSpec, csrDER []byte, now time.Time) ([]*x509.Certificate, error) {
	client, err := c.ensureAccount(ctx)
	if err != nil {
		return nil, err
	}

	ids := xacme.DomainIDs(spec.DNSNames...)
	if len(spec.IPAddresses) > 0 {
		ids = append(ids, xacme.IPIDs(spec.IPAddresses...)...)
	}
	var opts []xacme.OrderOption
	if spec.Validity > 0 {
		opts = append(opts, xacme.WithOrderNotAfter(now.Add(spec.Validity.Std())))
	}
	order, err := client.AuthorizeOrder(ctx, ids, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating ACME order: %w", err)
	}

	for _, authzURL := range order.AuthzURLs {
		if err := c.solveAuthorization(ctx, client, authzURL); err != nil {
			return nil, err
		}
	}
	order, err = client.WaitOrder(ctx, order.URI)
	if err != nil {
		return nil, fmt.Errorf("waiting for ACME order: %w", err)
	}
	ders, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		return nil, fmt.Errorf("finalizing ACME order: %w", err)
	}
	chain := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing issued certificate: %w", err)
		}
		chain = append(chain, cert)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("ACME finalize returned no certificates")
	}
	return chain, nil
}

// solveAuthorization answers one authorization's http-01 challenge and waits
// for the server to validate it.
func (c *acmeClient) solveAuthorization(ctx context.Context, client *xacme.Client, authzURL string) error {
	authz, err := client.GetAuthorization(ctx, authzURL)
	if err != nil {
		return fmt.Errorf("fetching authorization: %w", err)
	}
	if authz.Status == xacme.StatusValid {
		return nil
	}
	var chal *xacme.Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "http-01" {
			chal = ch
			break
		}
	}
	if chal == nil {
		return fmt.Errorf("authorization for %s offers no http-01 challenge (agent solves http-01 only)", authz.Identifier.Value)
	}
	keyAuth, err := client.HTTP01ChallengeResponse(chal.Token)
	if err != nil {
		return fmt.Errorf("computing key authorization: %w", err)
	}
	if err := c.solver.provision(chal.Token, keyAuth); err != nil {
		return fmt.Errorf("provisioning http-01 response: %w", err)
	}
	defer c.solver.cleanup(chal.Token)

	if _, err := client.Accept(ctx, chal); err != nil {
		return fmt.Errorf("accepting challenge: %w", err)
	}
	if _, err := client.WaitAuthorization(ctx, authz.URI); err != nil {
		return fmt.Errorf("authorization for %s failed: %w", authz.Identifier.Value, err)
	}
	return nil
}

// closeSolver releases http-01 resources (the standalone listener's port)
// between passes.
func (c *acmeClient) closeSolver() {
	if c.solver != nil {
		c.solver.close()
	}
}

// ---- ACME Renewal Information (draft-ietf-acme-ari) ----

// ariInfo is the parsed renewalInfo response.
type ariInfo struct {
	WindowStart    time.Time
	WindowEnd      time.Time
	RetryAfter     time.Duration
	ExplanationURL string
}

// RenewalInfo fetches the ARI suggested window for cert. It returns
// errARIUnsupported when the directory has no renewalInfo resource, and other
// errors for transport or certificate-identity problems.
func (c *acmeClient) RenewalInfo(ctx context.Context, cert *x509.Certificate) (*ariInfo, error) {
	base, err := c.renewalInfoURL(ctx)
	if err != nil {
		return nil, err
	}
	certID, err := ariCertID(cert)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+certID, nil)
	if err != nil {
		return nil, fmt.Errorf("building renewal-info request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching renewal-info: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("reading renewal-info: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("renewal-info returned %s: %s", resp.Status, summarizeBody(body))
	}
	var wire struct {
		SuggestedWindow struct {
			Start string `json:"start"`
			End   string `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL"`
	}
	if err := json.Unmarshal(body, &wire); err != nil {
		return nil, fmt.Errorf("parsing renewal-info: %w", err)
	}
	start, err := time.Parse(time.RFC3339, wire.SuggestedWindow.Start)
	if err != nil {
		return nil, fmt.Errorf("parsing window start %q: %w", wire.SuggestedWindow.Start, err)
	}
	end, err := time.Parse(time.RFC3339, wire.SuggestedWindow.End)
	if err != nil {
		return nil, fmt.Errorf("parsing window end %q: %w", wire.SuggestedWindow.End, err)
	}
	info := &ariInfo{WindowStart: start, WindowEnd: end, ExplanationURL: wire.ExplanationURL}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
			info.RetryAfter = time.Duration(secs) * time.Second
		}
	}
	return info, nil
}

// renewalInfoURL discovers (and caches) the directory's renewalInfo resource.
func (c *acmeClient) renewalInfoURL(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.ariLooked {
		url := c.ariURL
		c.mu.Unlock()
		if url == "" {
			return "", errARIUnsupported
		}
		return url, nil
	}
	c.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Directory, nil)
	if err != nil {
		return "", fmt.Errorf("building directory request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetching ACME directory: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("ACME directory returned %s", resp.Status)
	}
	var dir struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&dir); err != nil {
		return "", fmt.Errorf("parsing ACME directory: %w", err)
	}

	c.mu.Lock()
	c.ariLooked = true
	c.ariURL = strings.TrimRight(dir.RenewalInfo, "/")
	url := c.ariURL
	c.mu.Unlock()
	if url == "" {
		return "", errARIUnsupported
	}
	return url, nil
}

// ariCertID builds the draft-ietf-acme-ari CertID:
// base64url(AuthorityKeyIdentifier) "." base64url(Serial as DER INTEGER
// content octets).
func ariCertID(cert *x509.Certificate) (string, error) {
	if len(cert.AuthorityKeyId) == 0 {
		return "", fmt.Errorf("certificate has no AuthorityKeyIdentifier")
	}
	serial, err := serialContentOctets(cert.SerialNumber)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(cert.AuthorityKeyId) + "." + enc.EncodeToString(serial), nil
}

// serialContentOctets encodes a serial as DER INTEGER content octets:
// big-endian, minimal, with a leading zero when the top bit is set.
func serialContentOctets(serial *big.Int) ([]byte, error) {
	if serial == nil || serial.Sign() < 0 {
		return nil, fmt.Errorf("certificate serial is missing or negative")
	}
	b := serial.Bytes()
	if len(b) == 0 {
		b = []byte{0}
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return b, nil
}

// ---- http-01 solvers ----

// http01Solver publishes and withdraws http-01 key authorizations.
type http01Solver interface {
	provision(token, keyAuth string) error
	cleanup(token string)
	close() error
}

// listenerSolver answers challenges from a built-in HTTP listener bound only
// while challenges are outstanding, so the port stays free between passes.
type listenerSolver struct {
	addr string

	mu     sync.Mutex
	tokens map[string]string
	lis    net.Listener
	srv    *http.Server
}

const challengePathPrefix = "/.well-known/acme-challenge/"

func (s *listenerSolver) provision(token, keyAuth string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokens == nil {
		s.tokens = make(map[string]string)
	}
	s.tokens[token] = keyAuth
	if s.lis != nil {
		return nil
	}
	lis, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("binding http-01 listener on %s: %w", s.addr, err)
	}
	s.lis = lis
	s.srv = &http.Server{
		Handler:           http.HandlerFunc(s.serve),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go s.srv.Serve(lis) //nolint:errcheck // Serve returns ErrServerClosed on close
	return nil
}

func (s *listenerSolver) serve(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, challengePathPrefix)
	if token == r.URL.Path || token == "" {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	keyAuth, ok := s.tokens[token]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, keyAuth) //nolint:errcheck
}

func (s *listenerSolver) cleanup(token string) {
	s.mu.Lock()
	delete(s.tokens, token)
	s.mu.Unlock()
}

func (s *listenerSolver) close() error {
	s.mu.Lock()
	srv := s.srv
	s.srv, s.lis, s.tokens = nil, nil, nil
	s.mu.Unlock()
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
	return nil
}

// addr returns the bound listener address (tests use it with port ":0").
func (s *listenerSolver) boundAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lis == nil {
		return ""
	}
	return s.lis.Addr().String()
}

// webrootSolver drops key authorizations into a directory served by an
// existing web server.
type webrootSolver struct {
	dir string
}

func (s *webrootSolver) challengeDir() string {
	return filepath.Join(s.dir, ".well-known", "acme-challenge")
}

func (s *webrootSolver) provision(token, keyAuth string) error {
	dir := s.challengeDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating webroot challenge directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, token), []byte(keyAuth), 0o644); err != nil {
		return fmt.Errorf("writing webroot challenge file: %w", err)
	}
	return nil
}

func (s *webrootSolver) cleanup(token string) {
	os.Remove(filepath.Join(s.challengeDir(), token)) //nolint:errcheck
}

func (s *webrootSolver) close() error { return nil }
