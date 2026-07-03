package scep

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/attestation"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Grant is an operator-provisioned enrollment credential: a challenge password
// that authorizes SCEP enrollment under a specific certificate profile. Grants
// are the SCEP analogue of an RBAC role assignment — an administrator issues a
// challenge secret to a device fleet, and every certificate enrolled with it is
// constrained to the grant's profile and attributed to the grant in the audit
// log.
type Grant struct {
	Name      string
	Challenge string
	Profile   string
}

// Config configures the SCEP server. It is populated from the scep block of the
// application config.
type Config struct {
	// DirectoryPath is the URL prefix the SCEP endpoint mounts under (default
	// "/scep"). The single endpoint dispatches on the ?operation= query.
	DirectoryPath string
	// CAID is the id of the issuing CA. It MUST be an RSA CA: SCEP wraps the
	// request in a PKCS#7 EnvelopedData whose key transport requires the CA to
	// hold an RSA key.
	CAID string
	// Profile is the default certificate profile, used for renewals and for
	// grants that do not name their own profile (default "client").
	Profile string
	// Grants lists the challenge-password enrollment credentials.
	Grants []Grant
	// RequireChallenge, when true (the default), rejects an initial enrollment
	// that does not present a challenge password matching a configured grant.
	RequireChallenge bool
	// AllowRenewal permits a client to renew by signing a PKCSReq with a
	// currently-valid certificate previously issued by this CA, without a
	// challenge password.
	AllowRenewal bool
	// EncryptionKeyLabel is the provider label of the dedicated, decrypt-capable
	// RSA key used as the SCEP RA recipient. When empty it defaults to
	// "<ca-label>-scep-enc" and is auto-provisioned on first use.
	EncryptionKeyLabel string
	// Caps overrides the GetCACaps capability list.
	Caps []string
	// Attestation, when set, verifies hardware key-attestation evidence carried in
	// the enrollment CSR before issuance, per the profile's attestation mode
	// (Task 49). A nil verifier disables the gate (attestation off everywhere).
	Attestation *attestation.Verifier
}

func (c Config) withDefaults() Config {
	if c.DirectoryPath == "" {
		c.DirectoryPath = "/scep"
	}
	c.DirectoryPath = "/" + strings.Trim(c.DirectoryPath, "/")
	if c.Profile == "" {
		// "client" is the closest built-in profile for device/MDM identities
		// (TLS client authentication). Operators can point this at a custom
		// device profile via configuration.
		c.Profile = "client"
	}
	if len(c.Caps) == 0 {
		// POSTPKIOperation lets clients POST binary pkiMessages (avoiding the GET
		// base64 length limit); SHA-256/AES advertise modern algorithm support;
		// Renewal advertises support for certificate renewal. Under the FIPS
		// policy the legacy SHA-1/DES3 capabilities are not advertised (and the
		// cms layer rejects SHA-1-digested requests outright).
		c.Caps = []string{"POSTPKIOperation", "SHA-256", "SHA-1", "AES", "DES3", "SCEPStandard", "Renewal"}
		if fips.PolicyEnforced() {
			c.Caps = []string{"POSTPKIOperation", "SHA-256", "AES", "SCEPStandard", "Renewal"}
		}
	}
	return c
}

// Server implements the SCEP protocol endpoints.
type Server struct {
	db       *database.DB
	provider keyprovider.Provider
	caMgr    *ca.Manager
	cfg      Config
	now      func() time.Time

	// RA encryption identity, provisioned once on first use (see ra.go).
	raOnce sync.Once
	ra     *raIdentity
	raErr  error
}

// New constructs a SCEP server. It does not start a listener; call Register.
func New(db *database.DB, provider keyprovider.Provider, cfg Config) *Server {
	return &Server{
		db:       db,
		provider: provider,
		caMgr:    ca.NewManager(db, provider),
		cfg:      cfg.withDefaults(),
		now:      time.Now,
	}
}

// SetClock overrides the time source (used by tests).
func (s *Server) SetClock(now func() time.Time) { s.now = now }

// Register mounts the SCEP endpoint on mux. SCEP uses a single URL with the
// operation selected by the ?operation= query parameter; the classic Microsoft
// "/pkiclient.exe" path is registered as an alias.
func (s *Server) Register(mux *http.ServeMux) {
	p := s.cfg.DirectoryPath
	for _, path := range []string{p, p + "/pkiclient.exe"} {
		mux.HandleFunc("GET "+path, s.handle)
		mux.HandleFunc("POST "+path, s.handle)
	}
	log.Printf("SCEP server enabled at %s (CA=%s profile=%s, %d grant(s))", p, s.cfg.CAID, s.cfg.Profile, len(s.cfg.Grants))
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	switch strings.ToLower(r.URL.Query().Get("operation")) {
	case "getcacaps":
		s.handleGetCACaps(w, r)
	case "getcacert":
		s.handleGetCACert(w, r)
	case "pkioperation":
		s.handlePKIOperation(w, r)
	default:
		http.Error(w, "unknown SCEP operation", http.StatusBadRequest)
	}
}

func (s *Server) handleGetCACaps(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, strings.Join(s.cfg.Caps, "\n")+"\n")
}

// handleGetCACert returns the issuing CA certificate together with the SCEP RA
// encryption certificate as a degenerate certs-only PKCS#7
// (application/x-x509-ca-ra-cert, RFC 8894 §4.2). The client encrypts requests
// to the RA certificate (keyEncipherment usage) and trusts issued certificates
// through the CA certificate.
func (s *Server) handleGetCACert(w http.ResponseWriter, r *http.Request) {
	chain, err := s.caChain()
	if err != nil {
		http.Error(w, "CA unavailable", http.StatusInternalServerError)
		log.Printf("scep: GetCACert: %v", err)
		return
	}
	ra, err := s.ensureRA(r.Context())
	if err != nil {
		http.Error(w, "SCEP RA unavailable", http.StatusInternalServerError)
		log.Printf("scep: provisioning RA: %v", err)
		return
	}
	// CA (and any parents) followed by the RA encryption certificate.
	certs := append([]*x509.Certificate{}, chain...)
	certs = append(certs, ra.encCert)

	p7, err := cms.DegenerateCertsOnly(certs)
	if err != nil {
		http.Error(w, "encoding CA chain", http.StatusInternalServerError)
		return
	}
	s.recordEvent(r, "scep:anonymous", audit.ActionSCEPGetCACert, s.cfg.CAID, audit.ResultSuccess, "")
	w.Header().Set("Content-Type", "application/x-x509-ca-ra-cert")
	w.WriteHeader(http.StatusOK)
	w.Write(p7)
}

func (s *Server) handlePKIOperation(w http.ResponseWriter, r *http.Request) {
	body, err := s.readPKIBody(r)
	if err != nil {
		http.Error(w, "reading pkiMessage: "+err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	caCert, caModel, err := s.caCertModel()
	if err != nil {
		http.Error(w, "CA unavailable", http.StatusInternalServerError)
		log.Printf("scep: %v", err)
		return
	}

	ra, err := s.ensureRA(ctx)
	if err != nil {
		http.Error(w, "SCEP RA unavailable", http.StatusInternalServerError)
		log.Printf("scep: provisioning RA: %v", err)
		return
	}
	dec, err := s.encDecrypter(ctx, ra)
	if err != nil {
		http.Error(w, "RA decryption unavailable", http.StatusInternalServerError)
		log.Printf("scep: opening RA decrypter: %v", err)
		return
	}
	defer dec.Close()

	// The request is enveloped to the RA encryption certificate.
	msg, err := parseRequest(body, ra.encCert, dec)
	if err != nil {
		// A malformed or unverifiable pkiMessage cannot carry a transaction id we
		// trust, so respond with a plain error rather than a signed CertRep.
		http.Error(w, "invalid pkiMessage", http.StatusBadRequest)
		log.Printf("scep: parsing request: %v", err)
		return
	}

	if msg.MessageType != msgTypePKCSReq {
		s.writeFailure(w, r, caCert, msg, failInfoBadRequest, "unsupported message type "+msg.MessageType)
		return
	}

	profile, actor, isRenewal, failInfo := s.authorize(caCert, msg)
	if failInfo != "" {
		s.recordEvent(r, actor, enrollAction(isRenewal), csrCN(msg.CSR), audit.ResultDenied, "authorization failed")
		s.writeFailure(w, r, caCert, msg, failInfo, "enrollment not authorized")
		return
	}

	if !s.enforceAttestation(r, msg.CSR, profile, actor) {
		s.writeFailure(w, r, caCert, msg, failInfoBadRequest, "hardware key attestation required and missing or invalid")
		return
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: msg.CSR.Raw})
	result, err := s.caMgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:        s.cfg.CAID,
		CSRPEM:      csrPEM,
		Profile:     profile,
		RequestedBy: actor,
	})
	if err != nil {
		s.recordEvent(r, actor, enrollAction(isRenewal), csrCN(msg.CSR), audit.ResultError, err.Error())
		// SCEP's failInfo vocabulary has no throttling value, so tenant gate
		// refusals stay badRequest with a distinguishing failInfoText.
		failMsg := "issuance failed"
		var susp *models.TenantSuspendedError
		var quota *models.QuotaExceededError
		switch {
		case errors.As(err, &susp):
			failMsg = "tenant is suspended; enrollment is disabled"
		case errors.As(err, &quota):
			failMsg = "tenant issuance quota exceeded"
		}
		s.writeFailure(w, r, caCert, msg, failInfoBadRequest, failMsg)
		log.Printf("scep: issuance failed: %v", err)
		return
	}

	resp, err := s.signedCertRep(ctx, caModel, caCert, certRepArgs{
		transactionID:  msg.TransactionID,
		recipientNonce: msg.SenderNonce,
		senderNonce:    s.newNonce(),
		issued:         result.Certificate,
		chain:          []*x509.Certificate{result.Certificate, caCert},
		recipient:      msg.SignerCert,
		caCert:         caCert,
	})
	if err != nil {
		http.Error(w, "building response", http.StatusInternalServerError)
		log.Printf("scep: building CertRep: %v", err)
		return
	}

	s.recordEvent(r, actor, enrollAction(isRenewal), csrCN(msg.CSR), audit.ResultSuccess,
		"serial="+result.Serial.String()+" profile="+result.Profile)
	s.writePKIResponse(w, resp)
}

// authorize decides whether an enrollment is permitted, returning the profile to
// use, an audit actor label, whether it is a renewal, and (on denial) a SCEP
// failInfo. Renewal (a PKCSReq signed by a currently-valid certificate this CA
// issued) is allowed without a challenge when configured; otherwise the CSR must
// carry a challenge password matching a configured grant.
func (s *Server) authorize(caCert *x509.Certificate, msg *pkiMessage) (profile, actor string, isRenewal bool, failInfo string) {
	if s.cfg.AllowRenewal && s.isRenewalSigner(caCert, msg.SignerCert) {
		return s.cfg.Profile, "scep-renew:" + msg.SignerCert.Subject.CommonName, true, ""
	}

	challenge := challengePasswordFromCSR(msg.CSR)
	for _, g := range s.cfg.Grants {
		if subtle.ConstantTimeCompare([]byte(challenge), []byte(g.Challenge)) == 1 && challenge != "" {
			p := g.Profile
			if p == "" {
				p = s.cfg.Profile
			}
			return p, "scep:" + g.Name, false, ""
		}
	}

	if !s.cfg.RequireChallenge {
		return s.cfg.Profile, "scep:anonymous", false, ""
	}
	return "", "scep:unauthorized", false, failInfoBadRequest
}

// isRenewalSigner reports whether cert is a currently-valid, non-revoked
// certificate this CA issued — the precondition for a challenge-free renewal.
func (s *Server) isRenewalSigner(caCert, cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	// Must be signed by our CA key.
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		return false
	}
	now := s.now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false
	}
	// Must be a known, non-revoked certificate.
	rec, err := s.db.GetIssuedCertificate(s.cfg.CAID, cert.SerialNumber.String())
	if err != nil || rec == nil {
		return false
	}
	return rec.Status == models.CertStatusValid
}

// signedCertRep signs a success CertRep with the CA key (HSM-backed).
func (s *Server) signedCertRep(ctx context.Context, caModel *models.CA, caCert *x509.Certificate, args certRepArgs) ([]byte, error) {
	signer, err := s.signer(ctx, caModel)
	if err != nil {
		return nil, err
	}
	defer signer.Close()
	args.signer = signer
	args.caCert = caCert
	return buildCertRep(args)
}

// writeFailure signs and returns a FAILURE CertRep.
func (s *Server) writeFailure(w http.ResponseWriter, r *http.Request, caCert *x509.Certificate, msg *pkiMessage, failInfo, detail string) {
	caModel, _ := s.db.GetCA(s.cfg.CAID)
	signer, err := s.signer(r.Context(), caModel)
	if err != nil {
		http.Error(w, "building response", http.StatusInternalServerError)
		return
	}
	defer signer.Close()
	resp, err := buildCertRep(certRepArgs{
		transactionID:  msg.TransactionID,
		recipientNonce: msg.SenderNonce,
		senderNonce:    s.newNonce(),
		failInfo:       failInfo,
		caCert:         caCert,
		signer:         signer,
	})
	if err != nil {
		http.Error(w, "building response", http.StatusInternalServerError)
		return
	}
	log.Printf("scep: enrollment failure (failInfo=%s): %s", failInfo, detail)
	s.writePKIResponse(w, resp)
}

func (s *Server) writePKIResponse(w http.ResponseWriter, resp []byte) {
	w.Header().Set("Content-Type", "application/x-pki-message")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

// readPKIBody reads the pkiMessage bytes from a POST body (raw DER) or a GET
// ?message= parameter (base64).
func (s *Server) readPKIBody(r *http.Request) ([]byte, error) {
	if r.Method == http.MethodPost {
		return io.ReadAll(r.Body)
	}
	m := r.URL.Query().Get("message")
	if m == "" {
		return nil, fmt.Errorf("missing message parameter")
	}
	// SCEP GET messages are base64; some clients additionally URL-escape them,
	// which net/http already decoded. Tolerate standard and URL-safe alphabets.
	if b, err := base64.StdEncoding.DecodeString(m); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(m)
}

// ---- CA / provider plumbing ----------------------------------------------

func (s *Server) caCertModel() (*x509.Certificate, *models.CA, error) {
	caModel, err := s.db.GetCA(s.cfg.CAID)
	if err != nil {
		return nil, nil, fmt.Errorf("looking up CA %q: %w", s.cfg.CAID, err)
	}
	if caModel == nil || caModel.Certificate == "" {
		return nil, nil, fmt.Errorf("SCEP CA %q not found or has no certificate", s.cfg.CAID)
	}
	cert, err := pki.ParseCertificatePEM([]byte(caModel.Certificate))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA certificate: %w", err)
	}
	return cert, caModel, nil
}

// caChain returns the issuing CA certificate followed by its parents up to the
// root, for GetCACert.
func (s *Server) caChain() ([]*x509.Certificate, error) {
	var chain []*x509.Certificate
	id := s.cfg.CAID
	for id != "" {
		m, err := s.db.GetCA(id)
		if err != nil {
			return nil, err
		}
		if m == nil || m.Certificate == "" {
			break
		}
		cert, err := pki.ParseCertificatePEM([]byte(m.Certificate))
		if err != nil {
			return nil, err
		}
		chain = append(chain, cert)
		if m.ParentID == nil {
			break
		}
		id = *m.ParentID
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("SCEP CA %q not found", s.cfg.CAID)
	}
	return chain, nil
}

func (s *Server) keyRef(caModel *models.CA) keyprovider.KeyRef {
	label := pki.ExtractKeyLabel(caModel.PKCS11URI)
	if label == "" {
		label = caModel.Label
	}
	return keyprovider.KeyRef{Label: label}
}

func (s *Server) signer(ctx context.Context, caModel *models.CA) (keyprovider.Signer, error) {
	return s.provider.Signer(ctx, s.keyRef(caModel))
}

func (s *Server) newNonce() []byte {
	var n [16]byte
	if _, err := rand.Read(n[:]); err != nil {
		// Extremely unlikely; fall back to a UUID's bytes.
		u := uuid.New()
		copy(n[:], u[:])
	}
	return n[:]
}

// enforceAttestation runs the enrollment key-attestation gate against the SCEP
// CSR and returns whether issuance may proceed, recording a cert.attestation
// audit event and metrics for every outcome. A nil verifier is inert.
func (s *Server) enforceAttestation(r *http.Request, csr *x509.CertificateRequest, profile, actor string) bool {
	dec := s.cfg.Attestation.VerifyEnrollment(profile, csr)
	if dec.Mode == attestation.ModeOff {
		return true
	}
	result := attestationResultLabel(dec)
	metrics.AttestationChecks.Inc("scep", string(dec.Mode), result)
	if dec.Result != nil && dec.Result.Verified {
		metrics.AttestationVerified.Inc(dec.Result.Format)
	}
	if !dec.Allow {
		metrics.AttestationDenied.Inc("scep")
		s.recordEvent(r, actor, audit.ActionCertAttestation, csrCN(csr), audit.ResultDenied, dec.Detail)
		return false
	}
	s.recordEvent(r, actor, audit.ActionCertAttestation, csrCN(csr), audit.ResultSuccess, dec.Detail)
	return true
}

// attestationResultLabel maps an attestation decision to the metric "result"
// label ("pass"|"missing"|"invalid"|"skip").
func attestationResultLabel(dec attestation.Decision) string {
	switch {
	case dec.Mode == attestation.ModeOff:
		return "skip"
	case dec.Result != nil && dec.Result.Verified:
		return "pass"
	case dec.Missing:
		return "missing"
	default:
		return "invalid"
	}
}

func (s *Server) recordEvent(r *http.Request, actor, action, target, result, detail string) {
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		ActorRoles: "scep",
		Action:     action,
		Target:     target,
		Result:     result,
		Detail:     detail,
		IP:         clientIP(r),
	}
	if err := s.db.AppendEvent(e); err != nil {
		log.Printf("scep: appending audit event %q: %v", action, err)
	}
}

func enrollAction(isRenewal bool) string {
	if isRenewal {
		return audit.ActionSCEPRenew
	}
	return audit.ActionSCEPEnroll
}

func csrCN(csr *x509.CertificateRequest) string {
	if csr == nil {
		return ""
	}
	return csr.Subject.CommonName
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}
