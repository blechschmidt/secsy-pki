// Package servingcert implements the self-managed serving-TLS certificate the
// server issues for its own HTTPS listener (Task 118).
//
// When server.tls.self_issue is enabled the server dogfoods its own listener
// certificate from a designated internal CA via ca.Manager instead of loading a
// static cert/key pair from disk. Two invariants drive the design:
//
//   - The private key never touches disk. It is generated in and used through
//     the configured key provider (HSM / software / cloud KMS); the TLS stack
//     signs handshakes through a provider-backed crypto.Signer, so on a PKCS#11
//     HSM the key stays non-extractable on the token.
//   - Rotation is hitless. A background loop re-issues the certificate before it
//     expires and swaps it through the single tls.Config.GetCertificate hook
//     shared with the OCSP-stapling path (the Holder), so in-flight and new
//     handshakes always see a consistent certificate and the listener never
//     restarts.
//
// The renewal schedule mirrors the monitor's fraction-based renewal for
// short-lived certificates: renew once the remaining validity drops below
// RenewBefore, which defaults to a fixed fraction of the certificate's lifetime
// when the operator does not pin an absolute duration.
package servingcert

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// defaultRenewFraction is the fraction of a certificate's lifetime that must
// remain before the loop re-issues it, used when RenewBefore is unset. Renewing
// with a third of the lifetime left leaves ample headroom for retries and
// mirrors the monitor's fraction-based renewal for short-lived certificates.
const defaultRenewFraction = 1.0 / 3.0

// rotationRetryDelay bounds how soon the loop retries after a failed rotation.
// The previous certificate keeps being served until a rotation succeeds or it
// expires, so a transient issuance failure never takes the listener down.
const rotationRetryDelay = 30 * time.Second

// Holder holds the current server TLS certificate and hands it to the TLS stack
// through GetCertificate, so the served certificate can be swapped hitlessly
// while the listener stays up. It is the single tls.Config.GetCertificate hook
// shared by two feeders — the OCSP-staple refresher (SetStaple, a staple-only
// update to the current leaf) and the self-issue auto-rotation loop (Set, a
// whole new leaf backed by a provider-held key). Both mutate under one lock, so
// every handshake observes a consistent certificate.
type Holder struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

// NewHolder returns a Holder serving cert.
func NewHolder(cert *tls.Certificate) *Holder {
	return &Holder{cert: cert}
}

// GetCertificate is the tls.Config.GetCertificate hook: it returns the current
// certificate for every handshake.
func (h *Holder) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cert, nil
}

// Set replaces the whole certificate (used by the rotation loop). The swap is
// atomic under the lock, so a concurrent handshake sees either the old or the
// new certificate, never a half-updated one.
func (h *Holder) Set(cert *tls.Certificate) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cert = cert
}

// SetStaple attaches a refreshed OCSP staple to the current certificate,
// preserving the certificate chain and key. It copies the certificate value so
// a handshake in progress keeps reading the previous immutable snapshot.
func (h *Holder) SetStaple(staple []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	c := *h.cert
	c.OCSPStaple = staple
	h.cert = &c
}

// Current returns the certificate currently served. Used by tests and by the
// rotation loop to read the live leaf's expiry.
func (h *Holder) Current() *tls.Certificate {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cert
}

// Issuer is the subset of *ca.Manager the self-issuer needs: mint a leaf from a
// subject/public-key template (so the private key stays in the provider) and
// build the issuing CA's chain to serve alongside the leaf. Narrowing it to an
// interface keeps the package testable with a fake issuer.
type Issuer interface {
	IssueCertificateFromTemplate(ctx context.Context, spec ca.TemplateIssueSpec) (*ca.IssueResult, error)
	CombinedChainPEM(caID string) ([]byte, error)
}

// KeyProvider is the subset of keyprovider.Provider the self-issuer uses to
// provision and sign with the serving key, which never leaves the provider.
type KeyProvider interface {
	GenerateKey(ctx context.Context, spec keyprovider.KeySpec) (*keyprovider.KeyInfo, error)
	FindKey(ctx context.Context, ref keyprovider.KeyRef) (*keyprovider.KeyInfo, error)
	Signer(ctx context.Context, ref keyprovider.KeyRef) (keyprovider.Signer, error)
	PublicKey(ctx context.Context, ref keyprovider.KeyRef) (crypto.PublicKey, error)
}

// Config parameterizes the self-issued serving certificate. It is the resolved
// form of config.SelfIssueConfig (defaults already applied by the caller for the
// fields that have them).
type Config struct {
	// CAID is the internal CA that issues the serving certificate.
	CAID string
	// Profile is the issuance profile (a serverAuth TLS-leaf profile).
	Profile string
	// CommonName and DNSNames/IPs form the certificate's identity.
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	// KeyLabel is the provider label the serving key is generated under and
	// reused across rotations. KeyType is its algorithm (default ecdsa P-256).
	KeyLabel string
	KeyType  string
	// RenewBefore is the remaining-validity threshold at which the loop
	// re-issues. Zero falls back to defaultRenewFraction of the lifetime.
	RenewBefore time.Duration
	// Validity overrides the issued certificate's lifetime. Zero uses the
	// profile default.
	Validity time.Duration
	// RequestedBy labels the issuance in the audit log.
	RequestedBy string
}

func (c Config) keyType() string {
	if c.KeyType != "" {
		return c.KeyType
	}
	return keyprovider.KeyTypeECDSAP256
}

func (c Config) requestedBy() string {
	if c.RequestedBy != "" {
		return c.RequestedBy
	}
	return "system:serving-tls"
}

// SelfIssuer owns the self-managed serving certificate: it provisions the
// provider-held key, issues the initial certificate, exposes the GetCertificate
// hook through its Holder, and (via Run) rotates the certificate before expiry.
type SelfIssuer struct {
	issuer Issuer
	keys   KeyProvider
	cfg    Config
	holder *Holder
	logger *log.Logger

	// now is the clock, overridable in tests.
	now func() time.Time

	mu      sync.Mutex
	current *x509.Certificate // the leaf currently served
}

// New provisions the serving key, issues the initial certificate, and returns a
// ready-to-serve SelfIssuer. The listener can be started immediately with
// si.Holder().GetCertificate; call Run to enable auto-rotation.
func New(ctx context.Context, issuer Issuer, keys KeyProvider, cfg Config, logger *log.Logger) (*SelfIssuer, error) {
	if issuer == nil || keys == nil {
		return nil, fmt.Errorf("servingcert: issuer and key provider are required")
	}
	if cfg.CAID == "" {
		return nil, fmt.Errorf("servingcert: CAID is required")
	}
	if logger == nil {
		logger = log.Default()
	}
	s := &SelfIssuer{issuer: issuer, keys: keys, cfg: cfg, logger: logger, now: time.Now}

	tlsCert, leaf, err := s.issue(ctx)
	if err != nil {
		return nil, fmt.Errorf("servingcert: issuing initial serving certificate: %w", err)
	}
	s.holder = NewHolder(tlsCert)
	s.current = leaf
	metrics.ServingCertExpiry.Set(float64(leaf.NotAfter.Unix()))
	metrics.ServingCertRotations.Inc(metrics.ResultSuccess)
	s.logger.Printf("serving-tls: issued initial serving certificate serial=%s cn=%q sans=%v not_after=%s (key in provider, label=%q)",
		leaf.SerialNumber, leaf.Subject.CommonName, sans(leaf), leaf.NotAfter.UTC().Format(time.RFC3339), s.keyLabel())
	return s, nil
}

// Holder returns the shared certificate holder whose GetCertificate method wires
// into tls.Config.
func (s *SelfIssuer) Holder() *Holder { return s.holder }

// Current returns the leaf currently served (for diagnostics/tests).
func (s *SelfIssuer) Current() *x509.Certificate {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

// keyLabel resolves the provider label for the serving key.
func (s *SelfIssuer) keyLabel() string {
	if s.cfg.KeyLabel != "" {
		return s.cfg.KeyLabel
	}
	return "serving-tls-" + s.cfg.CAID
}

// Run drives the auto-rotation loop until ctx is cancelled. It sleeps until the
// current certificate reaches its renewal point, re-issues, and swaps the new
// certificate into the holder — keeping the listener up throughout. A failed
// rotation is logged and retried after rotationRetryDelay; the previous
// certificate keeps being served until a rotation succeeds or it expires.
func (s *SelfIssuer) Run(ctx context.Context) {
	for {
		wait := s.timeUntilRenew(s.Current())
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		if err := s.Rotate(ctx); err != nil {
			s.logger.Printf("serving-tls: rotation failed: %v; retrying in %s (still serving the previous certificate)", err, rotationRetryDelay)
			select {
			case <-ctx.Done():
				return
			case <-time.After(rotationRetryDelay):
			}
		}
	}
}

// Rotate re-issues the serving certificate and swaps it into the holder. It is
// exported so an operator-driven path (or a test) can force a rotation. On
// success the expiry gauge and rotation counter are updated; on failure the
// previous certificate remains served.
func (s *SelfIssuer) Rotate(ctx context.Context) error {
	tlsCert, leaf, err := s.issue(ctx)
	if err != nil {
		metrics.ServingCertRotations.Inc(metrics.ResultError)
		return err
	}
	s.holder.Set(tlsCert)
	s.mu.Lock()
	s.current = leaf
	s.mu.Unlock()
	metrics.ServingCertExpiry.Set(float64(leaf.NotAfter.Unix()))
	metrics.ServingCertRotations.Inc(metrics.ResultSuccess)
	s.logger.Printf("serving-tls: rotated serving certificate serial=%s not_after=%s",
		leaf.SerialNumber, leaf.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// timeUntilRenew returns how long to wait before re-issuing leaf. It is never
// negative: an already-overdue certificate renews immediately.
func (s *SelfIssuer) timeUntilRenew(leaf *x509.Certificate) time.Duration {
	renewAt := leaf.NotAfter.Add(-s.renewBefore(leaf))
	d := renewAt.Sub(s.now())
	if d < 0 {
		return 0
	}
	return d
}

// renewBefore resolves the remaining-validity threshold at which leaf is
// re-issued: the configured absolute duration, or defaultRenewFraction of the
// certificate's lifetime when none is configured.
func (s *SelfIssuer) renewBefore(leaf *x509.Certificate) time.Duration {
	if s.cfg.RenewBefore > 0 {
		return s.cfg.RenewBefore
	}
	lifetime := leaf.NotAfter.Sub(leaf.NotBefore)
	if lifetime <= 0 {
		return 0
	}
	return time.Duration(float64(lifetime) * defaultRenewFraction)
}

// issue provisions (or reuses) the serving key in the provider, mints a leaf for
// its public key under the configured CA/profile, and assembles a tls.Certificate
// whose private key is a provider-backed signer (so the key stays in the
// provider) and whose chain runs leaf → issuing CA → root.
func (s *SelfIssuer) issue(ctx context.Context) (*tls.Certificate, *x509.Certificate, error) {
	ref := keyprovider.KeyRef{Label: s.keyLabel()}
	pub, err := s.ensureKey(ctx, ref)
	if err != nil {
		return nil, nil, err
	}

	res, err := s.issuer.IssueCertificateFromTemplate(ctx, ca.TemplateIssueSpec{
		CAID:        s.cfg.CAID,
		Subject:     pkix.Name{CommonName: s.cfg.CommonName},
		PublicKey:   pub,
		DNSNames:    s.cfg.DNSNames,
		IPAddresses: s.cfg.IPs,
		Profile:     s.cfg.Profile,
		Validity:    s.cfg.Validity,
		RequestedBy: s.cfg.requestedBy(),
		Marker:      models.CertMarkerServingTLS,
	})
	if err != nil {
		return nil, nil, err
	}

	chainDER, err := s.chain(res.Certificate)
	if err != nil {
		return nil, nil, err
	}

	signer := &providerSigner{keys: s.keys, ref: ref, pub: pub}
	return &tls.Certificate{
		Certificate: chainDER,
		PrivateKey:  signer,
		Leaf:        res.Certificate,
	}, res.Certificate, nil
}

// ensureKey returns the public key of the serving key, generating it in the
// provider on first use and reusing it thereafter. A lost generate race (another
// replica created it concurrently) degrades to a second FindKey.
func (s *SelfIssuer) ensureKey(ctx context.Context, ref keyprovider.KeyRef) (crypto.PublicKey, error) {
	info, err := s.keys.FindKey(ctx, ref)
	if err != nil {
		info, err = s.keys.GenerateKey(ctx, keyprovider.KeySpec{
			Label:   ref.Label,
			KeyType: s.cfg.keyType(),
			Usage:   keyprovider.KeyUsageSign,
		})
		if err != nil {
			if found, ferr := s.keys.FindKey(ctx, ref); ferr == nil {
				info = found
			} else {
				return nil, fmt.Errorf("provisioning serving-tls key %q: %w", ref.Label, err)
			}
		}
	}
	if info.PublicKey == nil {
		return nil, fmt.Errorf("serving-tls key %q has no public key", ref.Label)
	}
	return info.PublicKey, nil
}

// chain assembles the DER chain the listener serves: the leaf followed by the
// issuing CA and its ancestors up to (and including) the root. Serving the root
// is harmless — relying parties anchor on their own copy — and keeps the bundle
// self-contained for clients that lack the intermediate.
func (s *SelfIssuer) chain(leaf *x509.Certificate) ([][]byte, error) {
	chainPEM, err := s.issuer.CombinedChainPEM(s.cfg.CAID)
	if err != nil {
		return nil, fmt.Errorf("building serving chain: %w", err)
	}
	issuers, err := pki.ParseCertificateChainPEM(chainPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing serving chain: %w", err)
	}
	der := make([][]byte, 0, 1+len(issuers))
	der = append(der, leaf.Raw)
	for _, c := range issuers {
		der = append(der, c.Raw)
	}
	return der, nil
}

// sans renders a leaf's SANs compactly for a log line.
func sans(cert *x509.Certificate) []string {
	out := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	out = append(out, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// providerSigner is a long-lived crypto.Signer that acquires a fresh
// provider-backed signer (and its session) per Sign and releases it
// immediately, so the serving key stays in the provider and each TLS handshake
// signs through the bounded session pool without pinning a session between
// handshakes. It mirrors cmd/server's providerBackedSigner.
type providerSigner struct {
	keys KeyProvider
	ref  keyprovider.KeyRef
	pub  crypto.PublicKey
}

func (s *providerSigner) Public() crypto.PublicKey { return s.pub }

func (s *providerSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signer, err := s.keys.Signer(context.Background(), s.ref)
	if err != nil {
		return nil, err
	}
	defer signer.Close()
	return signer.Sign(rand, digest, opts)
}
