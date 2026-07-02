// Package discovery implements an external certificate discovery scanner for
// secsy-pki (Task 54).
//
// The scanner connects to a list of TLS endpoints (host:port, with SNI, plus
// optional CIDR ranges and host files), retrieves the served certificate chain,
// and records the leaf's details — subject/SANs, issuer, validity, key
// algorithm/size, signature algorithm, and chain completeness. Each observation
// is analyzed for a set of security flags:
//
//   - ExpiringSoon:     the leaf expires within a configurable number of days.
//   - WeakKey:          RSA < 2048 bits, or a deprecated/small EC curve.
//   - SHA1Signature:    the leaf is signed with a SHA-1 (or weaker) algorithm.
//   - SelfSigned:       the leaf is its own issuer.
//   - HostnameMismatch: the leaf is not valid for the SNI/hostname scanned.
//   - Rogue:            the leaf was NOT issued by this PKI (shadow/rogue cert).
//
// "Issued by this PKI" is decided by attempting to build a chain from the served
// leaf to one of the operator's own CA certificates (supplied as a trust pool),
// so a certificate minted by this deployment is recognized even when the served
// chain is incomplete. Everything else served on a scanned endpoint is, by
// definition, a shadow certificate the operator should know about.
//
// The scanner performs no HSM operations and holds no private keys: it is a pure
// TLS client plus X.509 analysis, so it is exercised entirely with in-process
// test servers.
package discovery

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultPort is used for targets given without an explicit port.
const DefaultPort = 443

// DefaultDialTimeout bounds each endpoint's TCP+TLS handshake.
const DefaultDialTimeout = 8 * time.Second

// DefaultExpiryDays is the "expiring soon" window when the caller does not set one.
const DefaultExpiryDays = 30

// Target is a single endpoint to scan: a host and port, plus the SNI server name
// to present (which defaults to the host when it is a DNS name).
type Target struct {
	Host       string
	Port       int
	ServerName string
}

// Address returns the host:port dial address.
func (t Target) Address() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// String renders the target as it is displayed in reports (host:port[#sni]).
func (t Target) String() string {
	addr := t.Address()
	if t.ServerName != "" && t.ServerName != t.Host {
		addr += "#" + t.ServerName
	}
	return addr
}

// Finding is the result of scanning one endpoint. When the endpoint could not be
// reached (Reachable is false) only Endpoint, ServerName, and Error are set.
type Finding struct {
	Endpoint   string `json:"endpoint"`
	ServerName string `json:"server_name,omitempty"`
	Reachable  bool   `json:"reachable"`
	Error      string `json:"error,omitempty"`

	Subject            string    `json:"subject,omitempty"`
	CommonName         string    `json:"common_name,omitempty"`
	SANs               []string  `json:"sans,omitempty"`
	Issuer             string    `json:"issuer,omitempty"`
	Serial             string    `json:"serial,omitempty"`
	NotBefore          time.Time `json:"not_before,omitempty"`
	NotAfter           time.Time `json:"not_after,omitempty"`
	KeyAlgorithm       string    `json:"key_algorithm,omitempty"`
	KeySize            int       `json:"key_size,omitempty"`
	SignatureAlgorithm string    `json:"signature_algorithm,omitempty"`
	ChainLength        int       `json:"chain_length,omitempty"`
	ChainComplete      bool      `json:"chain_complete"`
	Fingerprint        string    `json:"fingerprint,omitempty"`
	LeafPEM            string    `json:"leaf_pem,omitempty"`

	IssuedByPKI      bool `json:"issued_by_pki"`
	Rogue            bool `json:"rogue"`
	SelfSigned       bool `json:"self_signed"`
	WeakKey          bool `json:"weak_key"`
	SHA1Signature    bool `json:"sha1_signature"`
	HostnameMismatch bool `json:"hostname_mismatch"`
	ExpiringSoon     bool `json:"expiring_soon"`
	ExpiresInDays    int  `json:"expires_in_days"`

	Flags        []string  `json:"flags,omitempty"`
	Severity     string    `json:"severity"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// Severity levels for a finding, aligned with the expiry monitor's vocabulary so
// findings can be dispatched through the same notification sinks.
const (
	SeverityOK       = "ok"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Scanner performs certificate discovery against a set of TLS endpoints. It is
// safe for concurrent use once constructed.
type Scanner struct {
	// ExpiryDays is the "expiring soon" window in days (<=0 uses DefaultExpiryDays).
	ExpiryDays int
	// DialTimeout bounds each endpoint's TCP+TLS handshake (<=0 uses the default).
	DialTimeout time.Duration
	// KnownRoots holds this PKI's CA certificates. A served leaf that chains to one
	// of them is recognized as issued-by-this-PKI; everything else is flagged rogue.
	// nil means "no known PKI" — every served leaf is then treated as external.
	KnownRoots *x509.CertPool
	// Concurrency bounds parallel endpoint dials (<=0 defaults to 16).
	Concurrency int
	// now overrides the clock for tests; nil uses time.Now.
	now func() time.Time
}

// NewScanner builds a Scanner with the given expiry window and known-CA pool.
func NewScanner(expiryDays int, knownRoots *x509.CertPool) *Scanner {
	return &Scanner{ExpiryDays: expiryDays, KnownRoots: knownRoots}
}

func (s *Scanner) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func (s *Scanner) expiryWindow() time.Duration {
	days := s.ExpiryDays
	if days <= 0 {
		days = DefaultExpiryDays
	}
	return time.Duration(days) * 24 * time.Hour
}

func (s *Scanner) dialTimeout() time.Duration {
	if s.DialTimeout <= 0 {
		return DefaultDialTimeout
	}
	return s.DialTimeout
}

// Scan probes every target and returns one Finding per target, preserving input
// order. Unreachable endpoints yield a Finding with Reachable=false rather than
// aborting the scan. Targets are probed concurrently, bounded by Concurrency.
func (s *Scanner) Scan(ctx context.Context, targets []Target) []Finding {
	findings := make([]Finding, len(targets))
	limit := s.Concurrency
	if limit <= 0 {
		limit = 16
	}
	sem := make(chan struct{}, limit)
	done := make(chan int, len(targets))
	for i, t := range targets {
		sem <- struct{}{}
		go func(i int, t Target) {
			defer func() { <-sem; done <- i }()
			findings[i] = s.scanOne(ctx, t)
		}(i, t)
	}
	for range targets {
		<-done
	}
	return findings
}

// scanOne dials a single endpoint and analyzes the served leaf certificate.
func (s *Scanner) scanOne(ctx context.Context, t Target) Finding {
	f := Finding{
		Endpoint:     t.Address(),
		ServerName:   t.ServerName,
		DiscoveredAt: s.clock(),
		Severity:     SeverityOK,
	}

	dialer := &net.Dialer{Timeout: s.dialTimeout()}
	// InsecureSkipVerify is intentional: the whole point of discovery is to
	// retrieve and analyze whatever certificate is served, including expired,
	// self-signed, untrusted, or hostname-mismatched ones. All verification is
	// done by us, below, against this PKI's own roots.
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         t.ServerName,
	}
	conn, err := tls.DialWithDialer(dialer, "tcp", t.Address(), tlsCfg)
	if err != nil {
		f.Error = err.Error()
		return f
	}
	defer conn.Close()

	state := conn.ConnectionState()
	chain := state.PeerCertificates
	if len(chain) == 0 {
		f.Error = "server presented no certificates"
		return f
	}
	f.Reachable = true
	s.analyze(&f, t, chain)
	return f
}

// analyze fills in the leaf details and security flags for a served chain.
func (s *Scanner) analyze(f *Finding, t Target, chain []*x509.Certificate) {
	leaf := chain[0]
	now := s.clock()

	f.Subject = leaf.Subject.String()
	f.CommonName = leaf.Subject.CommonName
	f.SANs = collectSANs(leaf)
	f.Issuer = leaf.Issuer.String()
	if leaf.SerialNumber != nil {
		f.Serial = leaf.SerialNumber.String()
	}
	f.NotBefore = leaf.NotBefore
	f.NotAfter = leaf.NotAfter
	f.KeyAlgorithm, f.KeySize = keyDetails(leaf)
	f.SignatureAlgorithm = leaf.SignatureAlgorithm.String()
	f.ChainLength = len(chain)
	fp := sha256.Sum256(leaf.Raw)
	f.Fingerprint = hex.EncodeToString(fp[:])
	f.LeafPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))

	// --- flags ---
	var flags []string

	// Expiry.
	remaining := leaf.NotAfter.Sub(now)
	f.ExpiresInDays = int(remaining / (24 * time.Hour))
	if remaining <= 0 {
		f.ExpiringSoon = true
		f.Severity = SeverityCritical
		flags = append(flags, "expired")
	} else if remaining <= s.expiryWindow() {
		f.ExpiringSoon = true
		f.Severity = SeverityWarning
		flags = append(flags, fmt.Sprintf("expiring in %dd", f.ExpiresInDays))
	}

	// Self-signed: subject == issuer and the certificate verifies its own
	// signature. CheckSignature (rather than CheckSignatureFrom) is used so the
	// determination does not depend on the leaf also being a CA — an ordinary
	// self-signed server certificate is still recognized.
	if bytesEqual(leaf.RawSubject, leaf.RawIssuer) {
		if err := leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err == nil {
			f.SelfSigned = true
			flags = append(flags, "self-signed")
		}
	}

	// Weak key.
	if weak, why := weakKey(leaf); weak {
		f.WeakKey = true
		flags = append(flags, why)
		f.Severity = escalate(f.Severity, SeverityCritical)
	}

	// SHA-1 (or weaker) signature.
	if isDeprecatedSignature(leaf.SignatureAlgorithm) {
		f.SHA1Signature = true
		flags = append(flags, "sha1-signature")
		f.Severity = escalate(f.Severity, SeverityCritical)
	}

	// Hostname mismatch — only meaningful when a DNS SNI was presented.
	if t.ServerName != "" && net.ParseIP(t.ServerName) == nil {
		if err := leaf.VerifyHostname(t.ServerName); err != nil {
			f.HostnameMismatch = true
			flags = append(flags, "hostname-mismatch")
			f.Severity = escalate(f.Severity, SeverityWarning)
		}
	}

	// Chain completeness and PKI ownership.
	f.ChainComplete = chainComplete(chain, now)
	f.IssuedByPKI = s.issuedByThisPKI(chain)
	if !f.IssuedByPKI && !f.SelfSigned {
		f.Rogue = true
		flags = append(flags, "not-issued-by-this-pki")
		f.Severity = escalate(f.Severity, SeverityCritical)
	}
	if !f.ChainComplete {
		flags = append(flags, "incomplete-chain")
	}

	f.Flags = flags
}

// issuedByThisPKI reports whether the served leaf chains to one of this PKI's own
// CA certificates. Intermediates presented by the server are used to bridge the
// gap, and verification is done at a time within the leaf's own validity so that
// an expired-but-genuinely-ours certificate is still recognized as ours.
func (s *Scanner) issuedByThisPKI(chain []*x509.Certificate) bool {
	if s.KnownRoots == nil {
		return false
	}
	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	verifyAt := leaf.NotBefore.Add(time.Second)
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         s.KnownRoots,
		Intermediates: intermediates,
		CurrentTime:   verifyAt,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

// chainComplete reports whether the served chain builds to a publicly trusted
// root using the system trust store (plus the presented intermediates). It is
// evaluated at a time within the leaf's validity so an otherwise-complete chain
// on an expired leaf is not reported as incomplete purely because of expiry.
func chainComplete(chain []*x509.Certificate, now time.Time) bool {
	leaf := chain[0]
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	verifyAt := now
	if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		verifyAt = leaf.NotBefore.Add(time.Second)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		CurrentTime:   verifyAt,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

// collectSANs renders every subject alternative name into a stable, sorted list.
func collectSANs(c *x509.Certificate) []string {
	var sans []string
	for _, d := range c.DNSNames {
		sans = append(sans, d)
	}
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, e := range c.EmailAddresses {
		sans = append(sans, e)
	}
	for _, u := range c.URIs {
		sans = append(sans, u.String())
	}
	sort.Strings(sans)
	return sans
}

// keyDetails returns the leaf's public-key algorithm name and key size in bits.
func keyDetails(c *x509.Certificate) (string, int) {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		if pub.Curve != nil {
			return "ECDSA", pub.Curve.Params().BitSize
		}
		return "ECDSA", 0
	case ed25519.PublicKey:
		return "Ed25519", 256
	default:
		return c.PublicKeyAlgorithm.String(), 0
	}
}

// weakKey reports whether a certificate's public key is below current strength
// guidance: RSA under 2048 bits, or an EC curve under 256 bits (P-192/P-224).
func weakKey(c *x509.Certificate) (bool, string) {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub.N.BitLen() < 2048 {
			return true, fmt.Sprintf("weak-rsa-%d", pub.N.BitLen())
		}
	case *ecdsa.PublicKey:
		if pub.Curve != nil && pub.Curve.Params().BitSize < 256 {
			return true, fmt.Sprintf("weak-ec-%d", pub.Curve.Params().BitSize)
		}
	}
	return false, ""
}

// isDeprecatedSignature reports whether a signature algorithm relies on SHA-1 or
// MD5, both of which are disallowed for certificate signatures.
func isDeprecatedSignature(a x509.SignatureAlgorithm) bool {
	switch a {
	case x509.MD2WithRSA, x509.MD5WithRSA,
		x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return true
	default:
		return false
	}
}

// escalate returns the more urgent of two severities.
func escalate(cur, next string) string {
	rank := map[string]int{SeverityOK: 0, SeverityWarning: 1, SeverityCritical: 2}
	if rank[next] > rank[cur] {
		return next
	}
	return cur
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// PoolFromCerts builds an x509 pool from a slice of PEM-encoded certificates,
// tolerating individual bad entries. It returns nil when nothing parsed, so a
// caller can treat "no known PKI" as scanning purely external certificates.
func PoolFromCerts(pemCerts []string) *x509.CertPool {
	pool := x509.NewCertPool()
	added := 0
	for _, p := range pemCerts {
		if strings.TrimSpace(p) == "" {
			continue
		}
		if pool.AppendCertsFromPEM([]byte(p)) {
			added++
		}
	}
	if added == 0 {
		return nil
	}
	return pool
}
