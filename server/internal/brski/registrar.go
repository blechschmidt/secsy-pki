package brski

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// DefaultPledgeTTL bounds how long a bootstrapped pledge stays authorized to
// EST-enroll after its voucher exchange completes.
const DefaultPledgeTTL = 10 * time.Minute

// Config configures the BRSKI registrar.
type Config struct {
	// BasePath is the URL prefix for the registrar endpoints (default
	// /.well-known/brski).
	BasePath string
	// CAID is the domain issuing CA the pledge's LDevID is ultimately issued from
	// (via the EST handoff). Recorded for audit; the actual issuance is EST's.
	CAID string
	// Profile is the issuance profile a bootstrapped pledge enrolls under.
	Profile string
	// EnabledProfiles is the set of issuance profiles for which BRSKI onboarding is
	// permitted (per-profile enable). When non-empty, Profile must appear in it or
	// the registrar refuses to onboard; when empty, Profile is implicitly allowed.
	EnabledProfiles map[string]bool
	// DomainCert is the registrar's provisioning/TLS certificate — the certificate
	// a pledge provisionally connects to and pins as proximity-registrar-cert, and
	// which the MASA pins as the voucher's pinned-domain-cert. Required.
	DomainCert *x509.Certificate
	// RegistrarKey / RegistrarCert sign the registrar voucher-request sent to the
	// MASA. RegistrarKey is typically HSM-backed (a keyprovider.Signer). When
	// RegistrarCert is nil it defaults to DomainCert (a single registrar identity).
	RegistrarKey   crypto.Signer
	RegistrarCert  *x509.Certificate
	RegistrarChain []*x509.Certificate
	// IDevIDRoots / IDevIDIntermediates are the trusted manufacturer anchors the
	// pledge's IDevID must chain to — the same trust anchors that gate hardware
	// attestation (Task 49). Required.
	IDevIDRoots         *x509.CertPool
	IDevIDIntermediates []*x509.Certificate
	// MASA issues the voucher for a registrar voucher-request. Required.
	MASA MASAClient
	// RequireProximity enforces that the pledge-asserted proximity-registrar-cert
	// equals DomainCert (the RFC 8995 proximity assertion — the pledge really is
	// talking to this registrar). Default true; disable only for testing.
	RequireProximity *bool
	// PledgeTTL bounds the post-bootstrap EST enrollment window (default
	// DefaultPledgeTTL).
	PledgeTTL time.Duration
	// Now overrides the clock (tests). Defaults to time.Now.
	Now func() time.Time
}

func (c Config) requireProximity() bool { return c.RequireProximity == nil || *c.RequireProximity }

func (c Config) profileEnabled(profile string) bool {
	if len(c.EnabledProfiles) == 0 {
		return true
	}
	return c.EnabledProfiles[profile]
}

// Registrar implements the RFC 8995 registrar (JRC) endpoints and the EST handoff
// authorizer. Construct it with New and mount it with Register.
type Registrar struct {
	db      *database.DB
	cfg     Config
	pledges *pledgeStore
	now     func() time.Time

	registrarCert  *x509.Certificate
	registrarChain []*x509.Certificate
}

// New validates the configuration and constructs a Registrar.
func New(db *database.DB, cfg Config) (*Registrar, error) {
	if cfg.DomainCert == nil {
		return nil, errors.New("brski: registrar requires a domain certificate")
	}
	if cfg.RegistrarKey == nil {
		return nil, errors.New("brski: registrar requires a signing key")
	}
	if cfg.MASA == nil {
		return nil, errors.New("brski: registrar requires a MASA client")
	}
	if cfg.IDevIDRoots == nil || len(cfg.IDevIDRoots.Subjects()) == 0 { //nolint:staticcheck // emptiness check
		return nil, errors.New("brski: registrar requires trusted IDevID manufacturer roots")
	}
	regCert := cfg.RegistrarCert
	if regCert == nil {
		regCert = cfg.DomainCert
	}
	if !publicKeyMatchesCert(cfg.RegistrarKey.Public(), regCert) {
		return nil, errors.New("brski: registrar signing key does not match the registrar certificate")
	}
	if cfg.PledgeTTL <= 0 {
		cfg.PledgeTTL = DefaultPledgeTTL
	}
	if !cfg.profileEnabled(cfg.Profile) {
		return nil, fmt.Errorf("brski: issuance profile %q is not BRSKI-enabled", cfg.Profile)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Registrar{
		db:             db,
		cfg:            cfg,
		pledges:        newPledgeStore(now),
		now:            now,
		registrarCert:  regCert,
		registrarChain: cfg.RegistrarChain,
	}, nil
}

// Register mounts the registrar endpoints on mux (RFC 8995 §5):
//
//	POST <base>/requestvoucher — pledge submits a voucher-request, gets a voucher
//	POST <base>/voucher_status — pledge reports voucher-processing telemetry
//	POST <base>/enrollstatus   — pledge reports enrollment telemetry
func (r *Registrar) Register(mux *http.ServeMux) {
	base := normalizeBasePath(r.cfg.BasePath)
	mux.HandleFunc("POST "+base+"/requestvoucher", r.handleRequestVoucher)
	mux.HandleFunc("POST "+base+"/voucher_status", r.handleVoucherStatus)
	mux.HandleFunc("POST "+base+"/enrollstatus", r.handleEnrollStatus)
	log.Printf("BRSKI registrar enabled at %s (CA=%s profile=%s, proximity=%v)",
		base, r.cfg.CAID, r.cfg.Profile, r.cfg.requireProximity())
}

// handleRequestVoucher runs the registrar's half of the voucher exchange (RFC
// 8995 §5.3–5.6): validate the pledge and its request, build and sign a registrar
// voucher-request, obtain the voucher from the MASA, authorize the pledge to
// enroll, and relay the voucher back.
func (r *Registrar) handleRequestVoucher(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(io.LimitReader(req.Body, maxVoucherRequestBytes))
	if err != nil {
		r.fail(req, "", "reading request body", w, http.StatusBadRequest, "reading request")
		return
	}

	// (1) Verify the pledge voucher-request signature and recover the IDevID.
	pvrSD, pvrJSON, err := parseSignedVoucherCMS(body)
	if err != nil {
		r.fail(req, "", "invalid pledge voucher-request: "+err.Error(), w, http.StatusBadRequest, "invalid voucher-request")
		return
	}
	idevid := pvrSD.SignerCertificate()
	pvr, err := ParseVoucherRequest(pvrJSON)
	if err != nil {
		r.fail(req, "", "malformed pledge voucher-request: "+err.Error(), w, http.StatusBadRequest, "malformed voucher-request")
		return
	}
	serial := deviceSerial(idevid)
	actor := "brski-pledge:" + serial

	// (2) The IDevID must chain to a trusted manufacturer root — the same anchors
	// the attestation gate uses. This is the fail-closed authenticity check.
	if err := verifyCertChain(r.cfg.IDevIDRoots, r.cfg.IDevIDIntermediates, idevid, r.now()); err != nil {
		metrics.RecordBRSKIVoucherRequest(metrics.BRSKIResultDenied)
		r.audit(req, actor, audit.ResultDenied, "IDevID untrusted: "+err.Error())
		http.Error(w, "pledge IDevID is not chained to a trusted manufacturer root", http.StatusForbidden)
		return
	}

	// (3) When the connection carried a TLS client certificate it must be the same
	// IDevID that signed the request, so a relayed request cannot be attributed to
	// the wrong device.
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		if !publicKeyMatchesCert(req.TLS.PeerCertificates[0].PublicKey, idevid) {
			metrics.RecordBRSKIVoucherRequest(metrics.BRSKIResultDenied)
			r.audit(req, actor, audit.ResultDenied, "TLS client certificate does not match the IDevID that signed the request")
			http.Error(w, "TLS client certificate does not match the voucher-request signer", http.StatusForbidden)
			return
		}
	}

	// (4) Proximity assertion: the pledge must have pinned this registrar's domain
	// certificate (RFC 8995 §5.3). This binds the request to the exact TLS peer.
	if r.cfg.requireProximity() {
		if len(pvr.ProximityRegistrarCert) == 0 {
			metrics.RecordBRSKIVoucherRequest(metrics.BRSKIResultDenied)
			r.audit(req, actor, audit.ResultDenied, "voucher-request lacks proximity-registrar-cert")
			http.Error(w, "voucher-request lacks proximity-registrar-cert", http.StatusForbidden)
			return
		}
		if !certEqual(pvr.ProximityRegistrarCert, r.cfg.DomainCert.Raw) {
			metrics.RecordBRSKIVoucherRequest(metrics.BRSKIResultDenied)
			r.audit(req, actor, audit.ResultDenied, "proximity-registrar-cert does not match this registrar's domain certificate")
			http.Error(w, "proximity-registrar-cert does not match this registrar", http.StatusForbidden)
			return
		}
	}

	// (5) Serial-number agreement between the pledge's assertion and its IDevID.
	if err := requireSameSerial("IDevID", serial, "voucher-request", pvr.SerialNumber); err != nil {
		metrics.RecordBRSKIVoucherRequest(metrics.BRSKIResultDenied)
		r.audit(req, actor, audit.ResultDenied, err.Error())
		http.Error(w, "voucher-request serial-number does not match the IDevID", http.StatusForbidden)
		return
	}

	// (6) Per-profile enable gate.
	if !r.cfg.profileEnabled(r.cfg.Profile) {
		metrics.RecordBRSKIVoucherRequest(metrics.BRSKIResultDenied)
		r.audit(req, actor, audit.ResultDenied, "issuance profile "+r.cfg.Profile+" is not BRSKI-enabled")
		http.Error(w, "BRSKI onboarding is not enabled for this profile", http.StatusForbidden)
		return
	}

	// (7) Build and sign the registrar voucher-request, embedding the pledge's own
	// signed request so the MASA can validate the pledge assertion independently.
	rvr := &Voucher{
		CreatedOn:                 r.now(),
		Nonce:                     pvr.Nonce,
		SerialNumber:              serialOr(pvr.SerialNumber, serial),
		Assertion:                 AssertionProximity,
		IDevIDIssuer:              idevid.AuthorityKeyId,
		PriorSignedVoucherRequest: body,
	}
	rvrJSON, err := MarshalVoucherRequest(rvr)
	if err != nil {
		r.fail(req, actor, "marshaling registrar voucher-request: "+err.Error(), w, http.StatusInternalServerError, "internal error")
		return
	}
	rvrCMS, err := signVoucherCMS(rvrJSON, r.cfg.RegistrarKey, r.registrarCert, r.registrarChain)
	if err != nil {
		r.fail(req, actor, "signing registrar voucher-request: "+err.Error(), w, http.StatusInternalServerError, "internal error")
		return
	}

	// (8) Obtain the voucher from the MASA.
	voucherCMS, err := r.cfg.MASA.RequestVoucher(req.Context(), rvrCMS)
	if err != nil {
		metrics.RecordBRSKIVoucherRequest(metrics.BRSKIResultError)
		r.audit(req, actor, audit.ResultError, "MASA declined: "+err.Error())
		http.Error(w, "MASA declined to issue a voucher", http.StatusBadGateway)
		log.Printf("brski registrar: MASA error for serial=%s: %v", serial, err)
		return
	}

	// (9) Sanity-check the voucher the pledge will receive: it must parse, echo
	// the nonce (nonceful case), and pin a domain certificate. The pledge performs
	// the authoritative MASA-signature verification with its own trust anchor.
	if err := r.sanityCheckVoucher(voucherCMS, pvr); err != nil {
		metrics.RecordBRSKIVoucherRequest(metrics.BRSKIResultError)
		r.audit(req, actor, audit.ResultError, "MASA returned an unusable voucher: "+err.Error())
		http.Error(w, "MASA returned an unusable voucher", http.StatusBadGateway)
		return
	}

	// (10) Authorize the pledge to complete the follow-up EST enrollment.
	r.pledges.authorize(idevid, serial, r.cfg.Profile, r.cfg.PledgeTTL)

	metrics.RecordBRSKIVoucherRequest(metrics.BRSKIResultSuccess)
	r.audit(req, actor, audit.ResultSuccess,
		fmt.Sprintf("voucher issued serial=%s profile=%s ca=%s", serial, r.cfg.Profile, r.cfg.CAID))
	w.Header().Set("Content-Type", MediaTypeVoucherCMS)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(voucherCMS)
}

// sanityCheckVoucher parses the MASA voucher (without verifying the MASA
// signature — that is the pledge's job with its pre-installed anchor) and confirms
// it is coherent with the pledge request: a pinned domain certificate is present,
// and a nonceful request is answered with the same nonce.
func (r *Registrar) sanityCheckVoucher(voucherCMS []byte, pvr *Voucher) error {
	content, err := parseVoucherContent(voucherCMS)
	if err != nil {
		return err
	}
	v, err := ParseVoucher(content)
	if err != nil {
		return err
	}
	if len(v.PinnedDomainCert) == 0 {
		return errors.New("voucher has no pinned-domain-cert")
	}
	// A nonceful voucher must carry exactly the request nonce (catches a MASA that
	// echoes the wrong nonce, or injects one we did not ask for). A nonceless
	// voucher — none present — is left to the pledge's own acceptance policy, so we
	// do not reject it here.
	if len(v.Nonce) > 0 && !bytesEqual(pvr.Nonce, v.Nonce) {
		return errors.New("voucher nonce does not match the request nonce")
	}
	return nil
}

// handleVoucherStatus records the pledge's voucher-processing telemetry (RFC 8995
// §5.7). The report is informational: it is always accepted with 200, and its
// outcome is audited and metered.
func (r *Registrar) handleVoucherStatus(w http.ResponseWriter, req *http.Request) {
	r.handleStatus(w, req, "voucher")
}

// handleEnrollStatus records the pledge's enrollment telemetry (RFC 8995 §5.9.4).
func (r *Registrar) handleEnrollStatus(w http.ResponseWriter, req *http.Request) {
	r.handleStatus(w, req, "enroll")
}

// statusReport is the shared shape of the voucher_status and enrollstatus
// telemetry documents (RFC 8995 §5.7 / §5.9.4).
type statusReport struct {
	Version string `json:"version"`
	Status  bool   `json:"status"`
	Reason  string `json:"reason"`
}

func (r *Registrar) handleStatus(w http.ResponseWriter, req *http.Request, kind string) {
	body, err := io.ReadAll(io.LimitReader(req.Body, maxStatusBytes))
	if err != nil {
		http.Error(w, "reading request", http.StatusBadRequest)
		return
	}
	var report statusReport
	if err := json.Unmarshal(body, &report); err != nil {
		http.Error(w, "malformed status report", http.StatusBadRequest)
		return
	}
	actor := "brski-pledge:" + r.peerSerial(req)
	statusLabel := metrics.BRSKIStatusFailure
	result := audit.ResultError
	if report.Status {
		statusLabel = metrics.BRSKIStatusSuccess
		result = audit.ResultSuccess
	}
	metrics.RecordBRSKIStatusReport(kind, statusLabel)
	detail := fmt.Sprintf("%s_status status=%v", kind, report.Status)
	if report.Reason != "" {
		detail += " reason=" + report.Reason
	}
	r.audit(req, actor, result, detail)
	w.WriteHeader(http.StatusOK)
}

// AuthorizePledge implements the EST handoff (est.PledgeAuthorizer): a device
// whose IDevID (presented as the TLS client certificate on the follow-up EST
// connection) completed BRSKI bootstrapping is authorized to enroll its LDevID
// under the profile recorded at voucher time. Returns ("","",false) for any
// certificate that is not a currently-authorized pledge.
func (r *Registrar) AuthorizePledge(clientCert *x509.Certificate) (profile, actor string, ok bool) {
	g, found := r.pledges.lookup(clientCert)
	if !found {
		metrics.RecordBRSKIEnrollAuthorized(metrics.BRSKIResultDenied)
		return "", "", false
	}
	metrics.RecordBRSKIEnrollAuthorized(metrics.BRSKIResultSuccess)
	return g.profile, "brski-pledge:" + g.serial, true
}

// ---- audit / helpers ------------------------------------------------------

// fail audits an error outcome and writes an HTTP error with a client-safe
// message (the detailed reason goes to the audit log, not the wire).
func (r *Registrar) fail(req *http.Request, actor, detail string, w http.ResponseWriter, code int, clientMsg string) {
	metrics.RecordBRSKIVoucherRequest(metrics.BRSKIResultError)
	r.audit(req, actor, audit.ResultError, detail)
	http.Error(w, clientMsg, code)
}

func (r *Registrar) audit(req *http.Request, actor, result, detail string) {
	if actor == "" {
		actor = "brski-pledge:anonymous"
	}
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		ActorRoles: "brski",
		Action:     audit.ActionCertBRSKI,
		Target:     r.cfg.CAID,
		Result:     result,
		Detail:     detail,
		IP:         clientIP(req),
	}
	if err := r.db.AppendEvent(e); err != nil {
		log.Printf("brski: appending audit event: %v", err)
	}
}

// peerSerial returns the serial of a TLS-presented client certificate for status
// telemetry attribution, or "anonymous".
func (r *Registrar) peerSerial(req *http.Request) string {
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		if s := deviceSerial(req.TLS.PeerCertificates[0]); s != "" {
			return s
		}
	}
	return "anonymous"
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}

func serialOr(primary, fallback string) string {
	if primary != "" {
		return primary
	}
	return fallback
}
