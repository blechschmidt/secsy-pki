package brski

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// MASAClient obtains a signed voucher for a registrar voucher-request (RVR). The
// registrar builds and signs the RVR, then calls RequestVoucher; the returned
// bytes are the CMS-signed RFC 8366 voucher, relayed unchanged to the pledge.
//
// Implementations: InProcessMASA (the built-in Service, for single-binary
// deployments and tests) and HTTPMASA (an external RFC 8995 MASA over HTTPS).
type MASAClient interface {
	// RequestVoucher submits the CMS-signed registrar voucher-request and returns
	// the CMS-signed voucher, or an error (including MASAError for a MASA that
	// answered with a non-2xx status).
	RequestVoucher(ctx context.Context, registrarVoucherRequest []byte) ([]byte, error)
}

// MASAError is returned by HTTPMASA when the MASA answered with a non-success
// HTTP status, carrying the status code and a bounded snippet of the body so the
// registrar can surface a useful audit detail without leaking a large response.
type MASAError struct {
	StatusCode int
	Body       string
}

func (e *MASAError) Error() string {
	body := e.Body
	if len(body) > 200 {
		body = body[:200]
	}
	return fmt.Sprintf("masa: request rejected with status %d: %s", e.StatusCode, strings.TrimSpace(body))
}

// ServiceConfig configures the built-in MASA Service.
type ServiceConfig struct {
	// Signer holds the MASA voucher-signing key (the pledge trusts the matching
	// certificate via its pre-installed MASA trust anchor). RSA or ECDSA.
	Signer crypto.Signer
	// Cert is the MASA signing certificate, embedded in every issued voucher.
	Cert *x509.Certificate
	// Chain is the issuer chain embedded alongside Cert (optional).
	Chain []*x509.Certificate
	// IDevIDRoots / IDevIDIntermediates verify the pledge's IDevID inside the
	// prior-signed-voucher-request: the manufacturer only vouches for devices it
	// made. Optional — when nil the MASA skips the manufacturer-side IDevID chain
	// check and relies on the embedded pledge signature alone (useful for a test
	// MASA that shares no roots with the registrar).
	IDevIDRoots         *x509.CertPool
	IDevIDIntermediates []*x509.Certificate
	// Nonceless issues vouchers bounded by expires-on rather than echoing a nonce,
	// for pledges without a real-time clock or online path. Default false, i.e.
	// nonceful (replay-resistant) vouchers, which RFC 8995 prefers.
	Nonceless bool
	// VoucherValidity bounds a nonceless voucher (default 24h). Ignored when a
	// nonce is present.
	VoucherValidity time.Duration
	// Assertion is the ownership assertion stamped on issued vouchers (default
	// "logged": the built-in MASA records issuance in the server log/audit).
	Assertion string
	// Now overrides the clock (tests). Defaults to time.Now.
	Now func() time.Time
	// Log receives one line per issued/refused voucher (default log.Printf).
	Log func(format string, args ...any)
}

// Service is the minimal built-in MASA. It validates a registrar voucher-request
// and the pledge voucher-request nested inside it, then issues a signed voucher
// pinning the domain (registrar) certificate the pledge asserted proximity to.
// It is deliberately policy-light — a real MASA additionally consults a
// sales-channel/ownership database — but it performs the security-relevant
// validation RFC 8995 §5.5 requires.
type Service struct {
	cfg ServiceConfig
}

// NewService constructs the built-in MASA Service, validating that a signer and
// certificate are present and that the certificate matches the signer's key.
func NewService(cfg ServiceConfig) (*Service, error) {
	if cfg.Signer == nil || cfg.Cert == nil {
		return nil, errors.New("brski: MASA service requires a signer and certificate")
	}
	if !publicKeyMatchesCert(cfg.Signer.Public(), cfg.Cert) {
		return nil, errors.New("brski: MASA signer key does not match the MASA certificate")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.VoucherValidity <= 0 {
		cfg.VoucherValidity = 24 * time.Hour
	}
	if strings.TrimSpace(cfg.Assertion) == "" {
		cfg.Assertion = AssertionLogged
	}
	if cfg.Log == nil {
		cfg.Log = log.Printf
	}
	return &Service{cfg: cfg}, nil
}

// Issue validates a registrar voucher-request and returns a CMS-signed voucher.
// The flow (RFC 8995 §5.5):
//
//  1. Verify the RVR CMS signature (the registrar holds the key for its cert).
//  2. Extract and verify the embedded pledge voucher-request (PVR): the pledge
//     signed it with its IDevID, and — when manufacturer roots are configured —
//     the IDevID chains to one of them.
//  3. Cross-check the serial numbers agree across the RVR, the PVR, and the
//     IDevID subject.
//  4. Pin the pledge-asserted proximity-registrar-cert as the voucher's
//     pinned-domain-cert and sign the voucher.
func (s *Service) Issue(ctx context.Context, rvrCMS []byte) ([]byte, error) {
	voucher, err := s.issue(ctx, rvrCMS)
	metrics.RecordBRSKIVoucherIssued(err)
	return voucher, err
}

func (s *Service) issue(_ context.Context, rvrCMS []byte) ([]byte, error) {
	// (1) The registrar voucher-request, signed by the registrar.
	rvrSD, rvrJSON, err := parseSignedVoucherCMS(rvrCMS)
	if err != nil {
		return nil, fmt.Errorf("registrar voucher-request: %w", err)
	}
	rvr, err := ParseVoucherRequest(rvrJSON)
	if err != nil {
		return nil, fmt.Errorf("registrar voucher-request: %w", err)
	}
	registrarCert := rvrSD.SignerCertificate()

	// (2) The pledge voucher-request nested inside it, signed by the IDevID.
	if len(rvr.PriorSignedVoucherRequest) == 0 {
		return nil, errors.New("registrar voucher-request lacks prior-signed-voucher-request")
	}
	pvrSD, pvrJSON, err := parseSignedVoucherCMS(rvr.PriorSignedVoucherRequest)
	if err != nil {
		return nil, fmt.Errorf("pledge voucher-request: %w", err)
	}
	pvr, err := ParseVoucherRequest(pvrJSON)
	if err != nil {
		return nil, fmt.Errorf("pledge voucher-request: %w", err)
	}
	idevid := pvrSD.SignerCertificate()

	// The manufacturer only issues vouchers for devices it made: the IDevID must
	// chain to a configured manufacturer root when one is supplied.
	if s.cfg.IDevIDRoots != nil {
		if err := verifyCertChain(s.cfg.IDevIDRoots, s.cfg.IDevIDIntermediates, idevid, s.cfg.Now()); err != nil {
			return nil, fmt.Errorf("pledge IDevID is not a device this MASA vouches for: %w", err)
		}
	}

	// (3) Serial-number agreement across every layer (RFC 8995 §5.5.1). The
	// pledge's asserted serial, the registrar's copy, and the IDevID must match,
	// so a registrar cannot request a voucher for a different device than the one
	// that actually signed the pledge request.
	idevidSerial := deviceSerial(idevid)
	if err := requireSameSerial("IDevID", idevidSerial, "pledge request", pvr.SerialNumber); err != nil {
		return nil, err
	}
	if err := requireSameSerial("pledge request", pvr.SerialNumber, "registrar request", rvr.SerialNumber); err != nil {
		return nil, err
	}

	// The pledge pinned a registrar cert from its provisional TLS connection; that
	// is precisely the domain certificate the voucher must direct it to trust.
	if len(pvr.ProximityRegistrarCert) == 0 {
		return nil, errors.New("pledge voucher-request lacks proximity-registrar-cert")
	}
	if _, err := x509.ParseCertificate(pvr.ProximityRegistrarCert); err != nil {
		return nil, fmt.Errorf("proximity-registrar-cert is not a valid certificate: %w", err)
	}

	// (4) Build and sign the voucher.
	now := s.cfg.Now()
	v := &Voucher{
		CreatedOn:        now,
		Assertion:        s.cfg.Assertion,
		SerialNumber:     pvr.SerialNumber,
		IDevIDIssuer:     idevid.AuthorityKeyId,
		PinnedDomainCert: pvr.ProximityRegistrarCert,
	}
	switch {
	case !s.cfg.Nonceless && len(pvr.Nonce) > 0:
		v.Nonce = pvr.Nonce
	default:
		// Nonceless voucher: bound its lifetime with expires-on so it cannot be
		// replayed indefinitely.
		exp := now.Add(s.cfg.VoucherValidity)
		v.ExpiresOn = &exp
	}

	content, err := MarshalVoucher(v)
	if err != nil {
		return nil, err
	}
	signed, err := signVoucherCMS(content, s.cfg.Signer, s.cfg.Cert, s.cfg.Chain)
	if err != nil {
		return nil, fmt.Errorf("signing voucher: %w", err)
	}
	registrarName := "<unknown>"
	if registrarCert != nil {
		registrarName = registrarCert.Subject.CommonName
	}
	s.cfg.Log("brski masa: issued voucher for serial=%s registrar=%q nonceful=%v", v.SerialNumber, registrarName, len(v.Nonce) > 0)
	return signed, nil
}

// Register mounts the MASA's /requestvoucher endpoint under basePath (default
// /.well-known/brski). This lets the built-in Service run as a standalone HTTP
// MASA an HTTPMASA client can reach; single-binary deployments use InProcessMASA
// and need not call this.
func (s *Service) Register(mux *http.ServeMux, basePath string) {
	basePath = normalizeBasePath(basePath)
	mux.HandleFunc("POST "+basePath+"/requestvoucher", s.handleRequestVoucher)
	log.Printf("BRSKI MASA enabled at %s/requestvoucher", basePath)
}

func (s *Service) handleRequestVoucher(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxVoucherRequestBytes))
	if err != nil {
		http.Error(w, "reading request", http.StatusBadRequest)
		return
	}
	voucher, err := s.Issue(r.Context(), body)
	if err != nil {
		http.Error(w, "voucher request rejected: "+err.Error(), http.StatusForbidden)
		log.Printf("brski masa: refused voucher request: %v", err)
		return
	}
	w.Header().Set("Content-Type", MediaTypeVoucherCMS)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(voucher)
}

// InProcessMASA adapts the built-in Service to the MASAClient interface so a
// single binary can act as both registrar and MASA with no network hop.
type InProcessMASA struct{ Service *Service }

// RequestVoucher implements MASAClient by calling the in-process Service.
func (m InProcessMASA) RequestVoucher(ctx context.Context, rvr []byte) ([]byte, error) {
	return m.Service.Issue(ctx, rvr)
}

// HTTPMASA is a MASAClient that POSTs the registrar voucher-request to an
// external RFC 8995 MASA at <BaseURL>/requestvoucher.
type HTTPMASA struct {
	// BaseURL is the MASA base, e.g. "https://masa.example.com/.well-known/brski".
	BaseURL string
	// Client is the HTTP client (default http.DefaultClient). A production
	// deployment should pin the MASA server trust anchor on this client's
	// transport.
	Client *http.Client
}

// RequestVoucher implements MASAClient over HTTPS.
func (m HTTPMASA) RequestVoucher(ctx context.Context, rvr []byte) ([]byte, error) {
	url := strings.TrimRight(m.BaseURL, "/") + "/requestvoucher"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(rvr))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", MediaTypeVoucherCMS)
	req.Header.Set("Accept", MediaTypeVoucherCMS)
	client := m.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("masa: request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVoucherBytes))
	if err != nil {
		return nil, fmt.Errorf("masa: reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &MASAError{StatusCode: resp.StatusCode, Body: string(body)}
	}
	return body, nil
}
