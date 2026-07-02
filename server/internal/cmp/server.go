package cmp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// contentType is the media type for CMP over HTTP (RFC 6712 / RFC 9483 §6).
const contentType = "application/pkixcmp"

// maxMessageBytes bounds a PKIMessage body to guard against memory exhaustion.
const maxMessageBytes = 256 * 1024

// failBadPOP is the PKIFailureInfo bit for a bad proof of possession.
const failBadPOP = 9

// Secret is an operator-provisioned shared secret for MAC-based (PasswordBasedMac)
// message protection. Reference is the senderKID a client presents to select it.
type Secret struct {
	// Reference is the senderKID (reference value) identifying this secret.
	Reference string
	// Secret is the shared secret value used to key the PBM.
	Secret string
	// Profile constrains what this credential may enroll (empty = server default).
	Profile string
}

// Config configures the CMP server.
type Config struct {
	// Path is the URL the endpoint mounts under (default "/cmp").
	Path string
	// CAID is the issuing CA (must be an X.509 issuer).
	CAID string
	// Profile is the default certificate profile (default "client").
	Profile string
	// Secrets are the shared secrets for MAC-protected requests, keyed by their
	// reference value (senderKID).
	Secrets []Secret
	// AllowSignatureProtection enables signature-protected flows (kur, and rr by a
	// certificate this CA previously issued). Defaults to true.
	AllowSignatureProtection *bool
}

func (c Config) withDefaults() Config {
	if c.Path == "" {
		c.Path = "/cmp"
	}
	c.Path = "/" + strings.Trim(c.Path, "/")
	if c.Profile == "" {
		c.Profile = "client"
	}
	return c
}

func (c Config) signatureProtectionEnabled() bool {
	return c.AllowSignatureProtection == nil || *c.AllowSignatureProtection
}

// Server implements the Lightweight CMP endpoint.
type Server struct {
	db       *database.DB
	provider keyprovider.Provider
	caMgr    *ca.Manager
	cfg      Config
	secrets  map[string]Secret
	now      func() time.Time
}

// New constructs a CMP server. Call Register to attach the endpoint.
func New(db *database.DB, provider keyprovider.Provider, cfg Config) *Server {
	cfg = cfg.withDefaults()
	secrets := make(map[string]Secret, len(cfg.Secrets))
	for _, s := range cfg.Secrets {
		secrets[s.Reference] = s
	}
	return &Server{
		db:       db,
		provider: provider,
		caMgr:    ca.NewManager(db, provider),
		cfg:      cfg,
		secrets:  secrets,
		now:      time.Now,
	}
}

// SetClock overrides the time source (used by tests).
func (s *Server) SetClock(now func() time.Time) { s.now = now }

// Register mounts the CMP endpoint on mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+s.cfg.Path, s.handle)
	log.Printf("CMP server enabled at %s (CA=%s profile=%s, signature-protection=%v)",
		s.cfg.Path, s.cfg.CAID, s.cfg.Profile, s.cfg.signatureProtectionEnabled())
}

// handle parses a PKIMessage and dispatches on its body type.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxMessageBytes))
	if err != nil {
		http.Error(w, "reading request body", http.StatusBadRequest)
		return
	}
	msg, err := parseMessage(body)
	if err != nil {
		http.Error(w, "invalid PKIMessage: "+err.Error(), http.StatusBadRequest)
		return
	}

	switch msg.bodyTag {
	case bodyIR:
		s.handleCertRequest(w, r, msg, bodyIP, audit.ActionCMPInitialization)
	case bodyCR:
		s.handleCertRequest(w, r, msg, bodyCP, audit.ActionCMPCertification)
	case bodyKUR:
		s.handleKeyUpdate(w, r, msg)
	case bodyRR:
		s.handleRevocation(w, r, msg)
	default:
		s.writeError(w, r, msg, nil, failBadRequest, fmt.Sprintf("unsupported PKIBody type %d", msg.bodyTag), "", audit.ActionCMPInitialization)
	}
}

// handleCertRequest services ir and cr: MAC-authenticated issuance from a
// CertTemplate. The response mirrors the request's MAC protection.
func (s *Server) handleCertRequest(w http.ResponseWriter, r *http.Request, msg *message, respTag int, action string) {
	secret, ok := s.secrets[string(msg.header.SenderKID)]
	if !ok {
		s.writeError(w, r, msg, nil, failNotAuthorized, "unknown reference value", "", action)
		return
	}
	if err := verifyPBM([]byte(secret.Secret), msg); err != nil {
		s.recordEvent(r, actorForKID(msg.header.SenderKID), action, "", audit.ResultDenied, "MAC verification failed")
		s.writeError(w, r, msg, nil, failBadMessageCheck, "message protection verification failed", "", action)
		return
	}

	reqMsg, err := s.singleRequest(msg)
	if err != nil {
		s.writeError(w, r, msg, nil, failBadRequest, err.Error(), "", action)
		return
	}
	if err := verifyPOP(reqMsg); err != nil {
		s.writeError(w, r, msg, nil, failBadPOP, err.Error(), "", action)
		return
	}

	profile := secret.Profile
	if profile == "" {
		profile = s.cfg.Profile
	}
	actor := actorForKID(msg.header.SenderKID)
	result, err := s.issue(r.Context(), reqMsg.req, profile, actor)
	if err != nil {
		s.recordEvent(r, actor, action, reqMsg.req.subject.CommonName, audit.ResultError, err.Error())
		s.writeError(w, r, msg, nil, failSystemFailure, "issuance failed", "", action)
		log.Printf("cmp: issuance failed: %v", err)
		return
	}

	params, err := defaultPBM()
	if err != nil {
		s.writeError(w, r, msg, nil, failSystemFailure, "internal error", "", action)
		return
	}
	prot := pbmProtector{secret: []byte(secret.Secret), params: params}
	if err := s.respond(w, msg, respTag, buildCertRepMessage(mustCertResponse(reqMsg.req.certReqID, result.Certificate.Raw)), msg.header.SenderKID, prot); err != nil {
		log.Printf("cmp: writing response: %v", err)
		return
	}
	s.recordEvent(r, actor, action, result.Certificate.Subject.CommonName, audit.ResultSuccess,
		"serial="+result.Serial.String()+" profile="+result.Profile)
}

// handleKeyUpdate services kur: signature-authenticated rekey. The request is
// protected by a certificate this CA previously issued; the response is signed
// by the CA.
func (s *Server) handleKeyUpdate(w http.ResponseWriter, r *http.Request, msg *message) {
	const action = audit.ActionCMPKeyUpdate
	if !s.cfg.signatureProtectionEnabled() {
		s.writeError(w, r, msg, nil, failNotAuthorized, "signature-protected requests are disabled", "", action)
		return
	}
	if len(msg.extraCerts) == 0 {
		s.writeError(w, r, msg, nil, failSignerNotTrusted, "no signer certificate in extraCerts", "", action)
		return
	}
	signerCert := msg.extraCerts[0]
	if err := s.validateSignerCert(signerCert); err != nil {
		s.recordEvent(r, actorForCert(signerCert), action, signerCert.Subject.CommonName, audit.ResultDenied, err.Error())
		s.writeError(w, r, msg, nil, failSignerNotTrusted, "signer certificate is not a valid certificate issued by this CA", "", action)
		return
	}
	if err := verifySignatureProtection(signerCert, msg); err != nil {
		s.recordEvent(r, actorForCert(signerCert), action, signerCert.Subject.CommonName, audit.ResultDenied, "signature verification failed")
		s.writeError(w, r, msg, nil, failBadMessageCheck, "message protection verification failed", "", action)
		return
	}

	reqMsg, err := s.singleRequest(msg)
	if err != nil {
		s.writeError(w, r, msg, nil, failBadRequest, err.Error(), "", action)
		return
	}
	if err := verifyPOP(reqMsg); err != nil {
		s.writeError(w, r, msg, nil, failBadPOP, err.Error(), "", action)
		return
	}

	// Carry forward the identity of the certificate being updated when the
	// template omits a subject/SANs, then rekey to the requested public key.
	req := reqMsg.req
	if req.subject.CommonName == "" && len(req.subject.ToRDNSequence()) == 0 {
		req.subject = signerCert.Subject
	}
	if len(req.dnsNames)+len(req.ipAddresses)+len(req.emails)+len(req.uris) == 0 {
		req.dnsNames = signerCert.DNSNames
		req.ipAddresses = signerCert.IPAddresses
		req.emails = signerCert.EmailAddresses
		for _, u := range signerCert.URIs {
			req.uris = append(req.uris, u.String())
		}
	}

	actor := actorForCert(signerCert)
	result, err := s.issue(r.Context(), req, s.cfg.Profile, actor)
	if err != nil {
		s.recordEvent(r, actor, action, req.subject.CommonName, audit.ResultError, err.Error())
		s.writeError(w, r, msg, nil, failSystemFailure, "issuance failed", "", action)
		log.Printf("cmp: kur issuance failed: %v", err)
		return
	}

	prot, chain, err := s.caSigProtector(r.Context())
	if err != nil {
		s.writeError(w, r, msg, nil, failSystemFailure, "internal error", "", action)
		log.Printf("cmp: building CA protector: %v", err)
		return
	}
	prot.chain = chain
	if err := s.respond(w, msg, bodyKUP, buildCertRepMessage(mustCertResponse(req.certReqID, result.Certificate.Raw)), nil, prot); err != nil {
		log.Printf("cmp: writing kur response: %v", err)
		return
	}
	s.recordEvent(r, actor, action, result.Certificate.Subject.CommonName, audit.ResultSuccess,
		"serial="+result.Serial.String()+" prior="+signerCert.SerialNumber.String())
}

// handleRevocation services rr. It authenticates the request by MAC (an operator
// secret) or by a signature from a valid certificate this CA issued (self-
// revocation), revokes the identified serial, and returns rp.
func (s *Server) handleRevocation(w http.ResponseWriter, r *http.Request, msg *message) {
	const action = audit.ActionCMPRevocation

	serial, err := parseRevocationTarget(msg.bodyContent)
	if err != nil {
		s.writeError(w, r, msg, nil, failBadRequest, err.Error(), "", action)
		return
	}

	prot, actor, err := s.authorizeRevocation(r.Context(), msg, serial)
	if err != nil {
		s.recordEvent(r, actor, action, serial.String(), audit.ResultDenied, err.Error())
		s.writeError(w, r, msg, nil, failNotAuthorized, "not authorized to revoke this certificate", "", action)
		return
	}

	applied, err := s.caMgr.RevokeCertificate(r.Context(), s.cfg.CAID, serial.String(), "")
	if err != nil {
		s.recordEvent(r, actor, action, serial.String(), audit.ResultError, err.Error())
		s.writeError(w, r, msg, nil, failSystemFailure, "revocation failed", "", action)
		return
	}

	rp, err := buildRevRepContent(statusAccepted)
	if err != nil {
		s.writeError(w, r, msg, nil, failSystemFailure, "internal error", "", action)
		return
	}
	if err := s.respond(w, msg, bodyRP, rp, msg.header.SenderKID, prot); err != nil {
		log.Printf("cmp: writing rr response: %v", err)
		return
	}
	detail := "serial=" + serial.String()
	if !applied {
		detail += " (already revoked)"
	}
	s.recordEvent(r, actor, action, serial.String(), audit.ResultSuccess, detail)
}

// authorizeRevocation selects the response protector and audit actor for a
// revocation request, enforcing the authorization policy: an operator shared
// secret may revoke any serial; a signature-protected request may revoke only
// the signer's own certificate (self-revocation).
func (s *Server) authorizeRevocation(ctx context.Context, msg *message, serial *big.Int) (protector, string, error) {
	if msg.header.ProtectionAlg.Algorithm.Equal(oidPasswordBasedMac) {
		secret, ok := s.secrets[string(msg.header.SenderKID)]
		if !ok {
			return nil, actorForKID(msg.header.SenderKID), fmt.Errorf("unknown reference value")
		}
		if err := verifyPBM([]byte(secret.Secret), msg); err != nil {
			return nil, actorForKID(msg.header.SenderKID), fmt.Errorf("MAC verification failed")
		}
		params, err := defaultPBM()
		if err != nil {
			return nil, "", err
		}
		return pbmProtector{secret: []byte(secret.Secret), params: params}, actorForKID(msg.header.SenderKID), nil
	}

	if !s.cfg.signatureProtectionEnabled() || len(msg.extraCerts) == 0 {
		return nil, "", fmt.Errorf("no acceptable message protection")
	}
	signerCert := msg.extraCerts[0]
	actor := actorForCert(signerCert)
	if err := s.validateSignerCert(signerCert); err != nil {
		return nil, actor, err
	}
	if err := verifySignatureProtection(signerCert, msg); err != nil {
		return nil, actor, fmt.Errorf("signature verification failed")
	}
	if signerCert.SerialNumber.Cmp(serial) != 0 {
		return nil, actor, fmt.Errorf("a certificate may only revoke itself")
	}
	prot, chain, err := s.caSigProtector(ctx)
	if err != nil {
		return nil, actor, err
	}
	prot.chain = chain
	return prot, actor, nil
}

// singleRequest extracts exactly one CertReqMsg; Lightweight CMP carries one.
func (s *Server) singleRequest(msg *message) (certReqMsg, error) {
	reqs, err := parseCertReqMessages(msg.bodyContent)
	if err != nil {
		return certReqMsg{}, err
	}
	if len(reqs) != 1 {
		return certReqMsg{}, fmt.Errorf("expected exactly one CertReqMsg, got %d", len(reqs))
	}
	return reqs[0], nil
}

// issue signs a parsed CertTemplate through the shared HSM-backed ca.Manager.
func (s *Server) issue(ctx context.Context, req certRequest, profile, actor string) (*ca.IssueResult, error) {
	return s.caMgr.IssueCertificateFromTemplate(ctx, ca.TemplateIssueSpec{
		CAID:           s.cfg.CAID,
		Subject:        req.subject,
		PublicKey:      req.publicKey,
		DNSNames:       req.dnsNames,
		IPAddresses:    req.ipAddresses,
		EmailAddresses: req.emails,
		URIs:           req.uris,
		Profile:        profile,
		RequestedBy:    actor,
	})
}

// verifyPOP requires a signature proof of possession and verifies it over the
// CertRequest DER, proving the requester controls the requested private key.
func verifyPOP(m certReqMsg) error {
	if m.popSig == nil {
		return fmt.Errorf("missing proof of possession")
	}
	if m.req.publicKey == nil {
		return fmt.Errorf("certificate template has no public key")
	}
	if err := verifySignature(m.req.publicKey, m.popSig.alg, m.req.rawCertReq, m.popSig.sig); err != nil {
		return fmt.Errorf("proof of possession is invalid")
	}
	return nil
}

// validateSignerCert reports whether cert is a currently-valid, non-revoked
// certificate this CA issued (used to authorize kur and self-revocation).
func (s *Server) validateSignerCert(cert *x509.Certificate) error {
	caCert, err := s.caCert()
	if err != nil {
		return err
	}
	if err := cert.CheckSignatureFrom(caCert); err != nil {
		return fmt.Errorf("not issued by this CA")
	}
	now := s.now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("certificate is not currently valid")
	}
	rec, err := s.db.GetIssuedCertificate(s.cfg.CAID, cert.SerialNumber.String())
	if err != nil {
		return err
	}
	if rec == nil || rec.Status != models.CertStatusValid {
		return fmt.Errorf("certificate is unknown or revoked")
	}
	if revoked, err := s.db.GetRevokedCertificate(s.cfg.CAID, cert.SerialNumber.String()); err != nil {
		return err
	} else if revoked != nil {
		return fmt.Errorf("certificate is revoked")
	}
	return nil
}

// ---- response assembly ----------------------------------------------------

// respond builds a protected PKIMessage response and writes it.
func (s *Server) respond(w http.ResponseWriter, req *message, bodyTag int, bodyContent, senderKID []byte, prot protector) error {
	hdr, err := s.responseHeader(req, senderKID)
	if err != nil {
		return err
	}
	out, err := buildResponse(hdr, bodyTag, bodyContent, prot)
	if err != nil {
		return err
	}
	writeMessage(w, out)
	return nil
}

// writeError writes a PKIMessage error response. When a protector is available
// the error is protected; otherwise it is sent unprotected (permitted by RFC
// 4210 for messages that cannot be authenticated).
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, req *message, prot protector, failBit int, text, _ string, action string) {
	s.recordEvent(r, actorForKID(req.header.SenderKID), action, "", audit.ResultDenied, text)
	content, err := buildErrorContent(text, failBit)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hdr, err := s.responseHeader(req, req.header.SenderKID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var out []byte
	if prot != nil {
		out, err = buildResponse(hdr, bodyError, content, prot)
	} else {
		out, err = buildUnprotected(hdr, bodyError, content)
	}
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeMessage(w, out)
}

// responseHeader builds a response header echoing the transaction id and
// swapping the nonces (RFC 4210 §5.1.1), naming the CA as sender.
func (s *Server) responseHeader(req *message, senderKID []byte) (headerFields, error) {
	caCert, err := s.caCert()
	if err != nil {
		return headerFields{}, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return headerFields{}, err
	}
	recipient := req.header.Sender
	if len(recipient.FullBytes) == 0 {
		recipient = generalNameDirectory(pkix.Name{})
	}
	return headerFields{
		Pvno:            req.header.Pvno,
		Sender:          generalNameDirectory(caCert.Subject),
		Recipient:       recipient,
		MessageTime:     s.now(),
		SenderKID:       senderKID,
		TransactionID:   req.header.TransactionID,
		SenderNonce:     nonce,
		RecipNonce:      req.header.SenderNonce,
		ImplicitConfirm: requestedImplicitConfirm(req),
	}, nil
}

// caSigProtector opens a CA signer and builds a signature protector plus the CA
// certificate chain for the response's extraCerts.
func (s *Server) caSigProtector(ctx context.Context) (sigProtector, [][]byte, error) {
	caModel, err := s.db.GetCA(s.cfg.CAID)
	if err != nil {
		return sigProtector{}, nil, err
	}
	if caModel == nil || caModel.Certificate == "" {
		return sigProtector{}, nil, fmt.Errorf("CMP CA %q not found or has no certificate", s.cfg.CAID)
	}
	caCert, err := pki.ParseCertificatePEM([]byte(caModel.Certificate))
	if err != nil {
		return sigProtector{}, nil, err
	}
	alg, hash, eddsa, err := signatureAlgForKey(caCert.PublicKey)
	if err != nil {
		return sigProtector{}, nil, err
	}
	label := pki.ExtractKeyLabel(caModel.PKCS11URI)
	if label == "" {
		label = caModel.Label
	}
	signer, err := s.provider.Signer(ctx, keyprovider.KeyRef{Label: label})
	if err != nil {
		return sigProtector{}, nil, fmt.Errorf("opening CA signer: %w", err)
	}
	chain, err := s.caChainDER()
	if err != nil {
		signer.Close()
		return sigProtector{}, nil, err
	}
	return sigProtector{signer: signerCloser{signer}, alg: alg, hash: hash, eddsa: eddsa}, chain, nil
}

// signerCloser wraps a keyprovider signer so buildResponse can use it as a
// crypto.Signer; the underlying session is released by the caller via Close.
type signerCloser struct{ s keyprovider.Signer }

func (c signerCloser) Public() crypto.PublicKey { return c.s.Public() }
func (c signerCloser) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	defer c.s.Close()
	return c.s.Sign(rand, digest, opts)
}

// ---- CA plumbing ----------------------------------------------------------

func (s *Server) caCert() (*x509.Certificate, error) {
	m, err := s.db.GetCA(s.cfg.CAID)
	if err != nil {
		return nil, err
	}
	if m == nil || m.Certificate == "" {
		return nil, fmt.Errorf("CMP CA %q not found or has no certificate", s.cfg.CAID)
	}
	return pki.ParseCertificatePEM([]byte(m.Certificate))
}

// caChainDER returns the CA certificate and its issuers as raw DER, for the
// response extraCerts.
func (s *Server) caChainDER() ([][]byte, error) {
	var chain [][]byte
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
		chain = append(chain, cert.Raw)
		if m.ParentID == nil {
			break
		}
		id = *m.ParentID
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("CMP CA %q not found", s.cfg.CAID)
	}
	return chain, nil
}

func (s *Server) recordEvent(r *http.Request, actor, action, target, result, detail string) {
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		ActorRoles: "cmp",
		Action:     action,
		Target:     target,
		Result:     result,
		Detail:     detail,
		IP:         clientIP(r),
	}
	if err := s.db.AppendEvent(e); err != nil {
		log.Printf("cmp: appending audit event %q: %v", action, err)
	}
}

// ---- small helpers --------------------------------------------------------

func writeMessage(w http.ResponseWriter, der []byte) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(http.StatusOK)
	w.Write(der)
}

// mustCertResponse builds a CertResponse, panicking only on an internal encoding
// error (the inputs are already-parsed DER).
func mustCertResponse(certReqID int, certDER []byte) []byte {
	cr, err := buildCertResponse(certReqID, certDER)
	if err != nil {
		panic(err)
	}
	return cr
}

// parseRevocationTarget extracts the serial number to revoke from an rr body
// (RevReqContent -> RevDetails -> certDetails CertTemplate).
func parseRevocationTarget(bodyContent []byte) (*big.Int, error) {
	details, err := seqElements(bodyContent)
	if err != nil {
		return nil, fmt.Errorf("decoding RevReqContent: %w", err)
	}
	if len(details) == 0 {
		return nil, fmt.Errorf("no RevDetails in revocation request")
	}
	fields, err := walkSequence(details[0].Bytes)
	if err != nil {
		return nil, fmt.Errorf("decoding RevDetails: %w", err)
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("RevDetails missing certDetails")
	}
	var req certRequest
	if err := parseCertTemplate(fields[0].Bytes, &req); err != nil {
		return nil, err
	}
	if req.serial == nil {
		return nil, fmt.Errorf("revocation request does not identify a serial number")
	}
	return req.serial, nil
}

// requestedImplicitConfirm reports whether the request asked for implicit
// confirmation via generalInfo.
func requestedImplicitConfirm(msg *message) bool {
	if len(msg.header.GeneralInfo.Bytes) == 0 {
		return false
	}
	elems, err := walkSequence(msg.header.GeneralInfo.Bytes)
	if err != nil {
		return false
	}
	for _, el := range elems {
		var itav infoTypeAndValue
		if _, err := asn1.Unmarshal(el.FullBytes, &itav); err != nil {
			continue
		}
		if itav.Type.Equal(oidImplicitConfirm) {
			return true
		}
	}
	return false
}

func actorForKID(kid []byte) string {
	if len(kid) == 0 {
		return "cmp:anonymous"
	}
	return "cmp:" + string(kid)
}

func actorForCert(cert *x509.Certificate) string {
	return "cmp-cert:" + cert.Subject.CommonName
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}
