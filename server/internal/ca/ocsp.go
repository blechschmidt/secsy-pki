package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
	"go.opentelemetry.io/otel/attribute"
)

// OCSP responder error sentinels. They let the HTTP layer map a failure to the
// correct RFC 6960 §4.2.1 response status (malformed / unauthorized / tryLater /
// internalError) instead of collapsing everything to internalError. Callers
// should use errors.Is against these.
var (
	// ErrOCSPUnauthorized indicates the responder is not authoritative for the
	// request (unknown CA / not an X.509 issuer). RFC 6960 "unauthorized".
	ErrOCSPUnauthorized = errors.New("ocsp: responder not authoritative for request")
	// ErrOCSPMalformed indicates the request could not be parsed. RFC 6960
	// "malformed".
	ErrOCSPMalformed = errors.New("ocsp: malformed request")
	// ErrOCSPTryLater indicates a transient failure (signing backend/HSM
	// unavailable or shedding load). RFC 6960 "tryLater".
	ErrOCSPTryLater = errors.New("ocsp: try later")
)

// OCSPRespondOptions tunes a single OCSP response.
type OCSPRespondOptions struct {
	// Nonce, when non-empty, is echoed in the response's responseExtensions
	// (RFC 8954). It must already have been validated for length by the caller.
	Nonce []byte
	// Responder and ResponderKeyRef, when both set, make the CA sign the
	// response with a delegated OCSP-signing certificate (Responder) whose key
	// is ResponderKeyRef, rather than with the CA key directly. The delegated
	// certificate is embedded in the response.
	Responder       *x509.Certificate
	ResponderKeyRef *keyprovider.KeyRef
	// Validity overrides the response NextUpdate window. Zero uses
	// defaultOCSPValidity. Nonce-bearing responses typically use a short window.
	Validity time.Duration
}

// OCSPRespond answers an OCSP request (DER) about a certificate issued by the
// given CA, signing the response with the CA key. It preserves the original
// Task 6 signature for existing callers and tests.
func (m *Manager) OCSPRespond(ctx context.Context, caID string, reqDER []byte) ([]byte, error) {
	return m.OCSPRespondWithOptions(ctx, caID, reqDER, OCSPRespondOptions{})
}

// OCSPRespondWithOptions answers an OCSP request with control over the nonce,
// delegated responder, and validity window. The response is signed on the
// provider (HSM). The returned bytes are a DER-encoded OCSP response.
func (m *Manager) OCSPRespondWithOptions(ctx context.Context, caID string, reqDER []byte, opts OCSPRespondOptions) (_ []byte, err error) {
	ctx, span := tracing.Start(ctx, "ca.ocsp_respond", attribute.String("ca.id", caID))
	defer func() { tracing.End(span, err) }()

	issuerCA, issuerCert, err := m.loadIssuer(caID)
	if err != nil {
		// An unknown or non-X.509 CA is not something we can attest to.
		return nil, fmt.Errorf("%w: %v", ErrOCSPUnauthorized, err)
	}

	req, err := pki.ParseOCSPRequest(reqDER)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOCSPMalformed, err)
	}

	status, revokedAt, reason, err := m.certStatus(caID, req.SerialNumber)
	if err != nil {
		return nil, err
	}

	validity := opts.Validity
	if validity <= 0 {
		validity = defaultOCSPValidity
	}
	now := time.Now()
	spec := pki.OCSPResponseSpec{
		Serial:           req.SerialNumber,
		Status:           status,
		RevokedAt:        revokedAt,
		RevocationReason: reason,
		ThisUpdate:       now.Add(-clockSkew),
		NextUpdate:       now.Add(validity),
		IssuerHash:       req.HashAlgorithm,
		Nonce:            opts.Nonce,
		Responder:        opts.Responder,
	}

	// Choose the signing key: the delegated responder key when supplied,
	// otherwise the CA key itself.
	signerRef := keyRefForCA(issuerCA)
	if opts.ResponderKeyRef != nil {
		signerRef = *opts.ResponderKeyRef
	}
	signer, err := m.provider.Signer(ctx, signerRef)
	if err != nil {
		return nil, fmt.Errorf("%w: opening OCSP signer: %v", ErrOCSPTryLater, err)
	}
	defer signer.Close()

	der, err := pki.CreateOCSPResponse(signer, issuerCert, spec)
	if err != nil {
		return nil, fmt.Errorf("%w: signing OCSP response: %v", ErrOCSPTryLater, err)
	}
	return der, nil
}

// certStatus resolves the OCSP status of a serial under a CA: revoked (with time
// and reason), good (known issued), or unknown (no record).
func (m *Manager) certStatus(caID string, serial *big.Int) (status int, revokedAt time.Time, reason int, err error) {
	serialStr := serial.String()
	revoked, err := m.db.GetRevokedCertificate(caID, serialStr)
	if err != nil {
		return 0, time.Time{}, 0, fmt.Errorf("looking up revocation: %w", err)
	}
	if revoked != nil {
		return pki.OCSPRevoked, revoked.RevokedAt, revoked.Reason, nil
	}
	issued, err := m.db.GetIssuedCertificate(caID, serialStr)
	if err != nil {
		return 0, time.Time{}, 0, fmt.Errorf("looking up issued certificate: %w", err)
	}
	if issued == nil {
		return pki.OCSPUnknown, time.Time{}, 0, nil
	}
	return pki.OCSPGood, time.Time{}, 0, nil
}

// -----------------------------------------------------------------------------
// TLS certificate-status (OCSP stapling) generation
// -----------------------------------------------------------------------------

// OCSPStapleForCertificate produces a signed OCSP response for cert, issued by
// caID, suitable for TLS certificate_status stapling (RFC 6066). The server can
// call this to staple a fresh, HSM-signed status to its own TLS certificate so
// clients need not contact the responder. No nonce is used (staples are
// pre-produced and shared across connections). The delegated responder is used
// when opts requests it.
func (m *Manager) OCSPStapleForCertificate(ctx context.Context, caID string, cert *x509.Certificate, opts OCSPRespondOptions) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("stapling requires a certificate")
	}
	if cert.SerialNumber == nil {
		return nil, fmt.Errorf("stapling requires a certificate serial")
	}
	_, issuerCert, err := m.loadIssuer(caID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrOCSPUnauthorized, err)
	}
	// Verify the certificate really chains to this issuer before vouching for it.
	if err := cert.CheckSignatureFrom(issuerCert); err != nil {
		return nil, fmt.Errorf("%w: certificate is not issued by CA %s: %v", ErrOCSPUnauthorized, caID, err)
	}
	// Build a request for this cert and reuse the normal response path so status
	// lookup, delegated signing, and validity handling stay identical.
	reqDER, err := pki.BuildOCSPRequest(cert, issuerCert)
	if err != nil {
		return nil, fmt.Errorf("building staple request: %w", err)
	}
	staple := opts
	staple.Nonce = nil // staples never carry a nonce
	return m.OCSPRespondWithOptions(ctx, caID, reqDER, staple)
}

// -----------------------------------------------------------------------------
// Delegated OCSP responder certificate management
// -----------------------------------------------------------------------------

// DelegatedResponderCache manages, per CA, a short-lived HSM-backed OCSP-signing
// certificate carrying the id-kp-OCSPSigning EKU and the id-pkix-ocsp-nocheck
// extension (RFC 6960 §4.2.2.2). Signing OCSP responses with a delegated,
// short-lived certificate rather than the CA key limits exposure of the CA key
// and lets responder credentials be rotated frequently.
//
// The signing *key* is generated once on the provider under a stable per-CA
// label and reused across certificate renewals; the *certificate* is re-issued
// (by the CA key) as it approaches expiry. Both are cached in memory. The cache
// is safe for concurrent use.
type DelegatedResponderCache struct {
	validity time.Duration
	keyType  string

	// mu guards entries and issueLocks only; it is never held across a provider
	// (HSM) round-trip, so a cache hit never blocks behind an in-flight issuance.
	mu         sync.Mutex
	entries    map[string]*delegatedResponder
	issueLocks map[string]*sync.Mutex

	// now is injectable for tests; nil means time.Now.
	now func() time.Time
}

type delegatedResponder struct {
	cert     *x509.Certificate
	keyRef   keyprovider.KeyRef
	notAfter time.Time
}

// DefaultDelegatedResponderValidity is the lifetime of a delegated OCSP-signing
// certificate when none is configured. Short lifetimes are the point of a
// delegated, nocheck responder.
const DefaultDelegatedResponderValidity = 7 * 24 * time.Hour

// NewDelegatedResponderCache constructs a cache issuing responder certificates
// of the given validity and key type. A non-positive validity uses
// DefaultDelegatedResponderValidity; an empty keyType uses ECDSA P-256.
func NewDelegatedResponderCache(validity time.Duration, keyType string) *DelegatedResponderCache {
	if validity <= 0 {
		validity = DefaultDelegatedResponderValidity
	}
	if keyType == "" {
		keyType = keyprovider.KeyTypeECDSAP256
	}
	return &DelegatedResponderCache{
		validity:   validity,
		keyType:    keyType,
		entries:    make(map[string]*delegatedResponder),
		issueLocks: make(map[string]*sync.Mutex),
	}
}

func (c *DelegatedResponderCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// delegatedLabel is the stable provider key label for a CA's delegated OCSP
// responder key.
func delegatedLabel(caID string) string { return "ocsp-responder-" + caID }

// fresh reports whether a cached responder is still comfortably valid (before
// its refresh point). The refresh lead is half the certificate's *actual*
// lifetime, so a responder issued against a CA that is itself near expiry (its
// notAfter clamped to the CA's) is not treated as instantly stale — which would
// otherwise force a re-issue on every request. When the remaining life is very
// short (CA about to expire), the responder is served until it actually expires.
func (c *DelegatedResponderCache) fresh(e *delegatedResponder) bool {
	life := e.notAfter.Sub(e.cert.NotBefore)
	lead := life / 2
	if life <= 2*time.Minute {
		lead = 0 // near CA expiry: reuse until the responder actually expires
	}
	return c.clock().Before(e.notAfter.Add(-lead))
}

// lookup returns a still-fresh cached responder under the map lock, without
// touching the provider.
func (c *DelegatedResponderCache) lookup(caID string) (*delegatedResponder, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[caID]
	if ok && c.fresh(e) {
		return e, true
	}
	return e, false
}

// issueLock returns the per-CA issuance mutex, creating it on first use. Holding
// a per-CA lock (rather than the shared map lock) across the HSM round-trips of
// an issuance means only concurrent requests for the *same* CA serialize, and
// only behind the first one — cache hits and other CAs are never blocked.
func (c *DelegatedResponderCache) issueLock(caID string) *sync.Mutex {
	c.mu.Lock()
	defer c.mu.Unlock()
	il, ok := c.issueLocks[caID]
	if !ok {
		il = &sync.Mutex{}
		c.issueLocks[caID] = il
	}
	return il
}

// Responder returns a currently-valid delegated OCSP-signing certificate for the
// CA and the key reference to sign with, (re)issuing it if absent or nearing
// expiry. It uses m to reach the provider and database.
func (c *DelegatedResponderCache) Responder(ctx context.Context, m *Manager, caID string) (*x509.Certificate, keyprovider.KeyRef, error) {
	// Fast path: serve a still-fresh cached responder without any lock contention
	// against an in-flight issuance.
	if e, ok := c.lookup(caID); ok {
		return e.cert, e.keyRef, nil
	}

	// Issuance path: serialize per CA so at most one issuance runs per CA.
	il := c.issueLock(caID)
	il.Lock()
	defer il.Unlock()

	// Re-check under the per-CA lock: a concurrent request may have just issued.
	if e, ok := c.lookup(caID); ok {
		return e.cert, e.keyRef, nil
	}

	cert, ref, err := c.issue(ctx, m, caID)
	if err != nil {
		// If (re)issuance failed but we still hold an unexpired certificate, keep
		// serving it rather than dropping delegated signing entirely.
		c.mu.Lock()
		e, ok := c.entries[caID]
		c.mu.Unlock()
		if ok && c.clock().Before(e.notAfter) {
			return e.cert, e.keyRef, nil
		}
		return nil, keyprovider.KeyRef{}, err
	}

	c.mu.Lock()
	c.entries[caID] = &delegatedResponder{cert: cert, keyRef: ref, notAfter: cert.NotAfter}
	c.mu.Unlock()
	return cert, ref, nil
}

// issue generates (or reuses) the responder key and signs a fresh OCSP-signing
// certificate with the CA key. The caller holds the per-CA issue lock (not
// c.mu), so this may perform provider round-trips freely.
func (c *DelegatedResponderCache) issue(ctx context.Context, m *Manager, caID string) (*x509.Certificate, keyprovider.KeyRef, error) {
	issuerCA, issuerCert, err := m.loadIssuer(caID)
	if err != nil {
		return nil, keyprovider.KeyRef{}, err
	}

	label := delegatedLabel(caID)
	ref := keyprovider.KeyRef{Label: label}

	// Reuse the responder key if it already exists on the provider; otherwise
	// generate it. GenerateKey rejects a duplicate label, so a lost race falls
	// back to a second FindKey.
	info, err := m.provider.FindKey(ctx, ref)
	if err != nil {
		info, err = m.provider.GenerateKey(ctx, keyprovider.KeySpec{
			Label:   label,
			KeyType: c.keyType,
			Usage:   keyprovider.KeyUsageSign,
		})
		if err != nil {
			if found, ferr := m.provider.FindKey(ctx, ref); ferr == nil {
				info = found
			} else {
				return nil, keyprovider.KeyRef{}, fmt.Errorf("provisioning delegated OCSP responder key: %w", err)
			}
		}
	}
	if info.PublicKey == nil {
		return nil, keyprovider.KeyRef{}, fmt.Errorf("delegated OCSP responder key has no public key")
	}

	serial, err := m.db.AllocateSerial(caID)
	if err != nil {
		return nil, keyprovider.KeyRef{}, fmt.Errorf("allocating serial for delegated responder: %w", err)
	}

	now := c.clock()
	notAfter := now.Add(c.validity)
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
	}

	caSigner, err := m.provider.Signer(ctx, keyRefForCA(issuerCA))
	if err != nil {
		return nil, keyprovider.KeyRef{}, fmt.Errorf("opening CA signer for delegated responder: %w", err)
	}
	defer caSigner.Close()

	der, err := pki.CreateLeafCertificate(caSigner, issuerCert, pki.LeafCertRequest{
		Subject:     pkix.Name{CommonName: responderCN(issuerCert)},
		PublicKey:   info.PublicKey,
		Serial:      big.NewInt(serial),
		NotBefore:   now.Add(-clockSkew),
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		// id-pkix-ocsp-nocheck: relying parties must not check this short-lived
		// responder certificate's own revocation status.
		ExtraExtensions: []pkix.Extension{pki.OCSPNoCheckExtension()},
	})
	if err != nil {
		return nil, keyprovider.KeyRef{}, fmt.Errorf("signing delegated responder certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, keyprovider.KeyRef{}, fmt.Errorf("parsing delegated responder certificate: %w", err)
	}
	return cert, ref, nil
}

// responderCN derives a subject common name for a delegated responder from its
// issuing CA.
func responderCN(issuer *x509.Certificate) string {
	base := issuer.Subject.CommonName
	if base == "" {
		base = "CA"
	}
	return base + " OCSP Responder"
}
