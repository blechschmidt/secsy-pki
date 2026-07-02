package tsa

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// Content types for the RFC 3161 HTTP transport (§3.4).
const (
	contentTypeQuery = "application/timestamp-query"
	contentTypeReply = "application/timestamp-reply"
)

// maxRequestBytes bounds a decoded TimeStampReq. A legitimate request is a small
// hash plus a nonce and a few OIDs; anything larger is rejected before parsing.
const maxRequestBytes = 64 << 10

// Config configures the Time-Stamp Authority. The signing certificate and key
// are provisioned offline with `secsy-ca tsa-key`; the server references the key
// by provider label and loads the certificate (and issuer chain) from config.
type Config struct {
	// Path is the URL the /tsa endpoint mounts under (default "/tsa").
	Path string
	// KeyLabel is the provider label of the TSA signing key. It MUST be an RSA
	// key: the CMS SignedData is signed with RSA PKCS#1 v1.5.
	KeyLabel string
	// Certificate is the TSA signing certificate. It MUST carry id-kp-timeStamping
	// as its sole extended key usage and hold an RSA public key.
	Certificate *x509.Certificate
	// Chain is the TSA certificate followed by its issuer(s) up to (but not
	// necessarily including) the root, embedded when a request sets certReq.
	Chain []*x509.Certificate
	// PolicyOID is the TSA policy asserted in every token. Defaults to
	// DefaultPolicyOID when unset.
	PolicyOID asn1.ObjectIdentifier
	// Accuracy bounds genTime's deviation from real time; omitted when zero.
	Accuracy Accuracy
	// Ordering asserts that tokens with the same policy are strictly ordered in
	// time (RFC 3161 §2.4.2). Only enable it when the genTime source guarantees it.
	Ordering bool
	// SignatureDigest is the hash used for the CMS signature (default SHA-256).
	SignatureDigest crypto.Hash
	// AcceptedHashes restricts the message-imprint hash algorithms the TSA will
	// stamp. When empty it defaults to SHA-256/384/512 (SHA-1 is refused).
	AcceptedHashes []crypto.Hash
	// IncludeTSAName embeds the signing certificate's subject as the informational
	// tsa GeneralName in each token.
	IncludeTSAName bool
}

func (c Config) withDefaults() Config {
	if c.Path == "" {
		c.Path = "/tsa"
	}
	c.Path = "/" + strings.Trim(c.Path, "/")
	if len(c.PolicyOID) == 0 {
		c.PolicyOID = DefaultPolicyOID
	}
	if c.SignatureDigest == 0 {
		c.SignatureDigest = crypto.SHA256
	}
	if len(c.AcceptedHashes) == 0 {
		c.AcceptedHashes = []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}
	}
	return c
}

// Authority is an RFC 3161 Time-Stamp Authority bound to a signing key in the
// key provider. It is safe for concurrent use.
type Authority struct {
	db       *database.DB
	provider keyprovider.Provider
	cfg      Config
	now      func() time.Time
	serial   func() (*big.Int, error)
}

// New constructs a TSA. It validates that the configured certificate is a usable
// RSA time-stamping certificate; a misconfigured TSA fails fast at startup
// rather than emitting unverifiable tokens.
func New(db *database.DB, provider keyprovider.Provider, cfg Config) (*Authority, error) {
	cfg = cfg.withDefaults()
	if cfg.KeyLabel == "" {
		return nil, fmt.Errorf("tsa: key_label is required")
	}
	if cfg.Certificate == nil {
		return nil, fmt.Errorf("tsa: a signing certificate is required")
	}
	if _, ok := cfg.Certificate.PublicKey.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("tsa: signing certificate key is %T, an RSA key is required", cfg.Certificate.PublicKey)
	}
	if err := checkTimeStampingEKU(cfg.Certificate); err != nil {
		return nil, err
	}
	if !cfg.SignatureDigest.Available() {
		return nil, fmt.Errorf("tsa: signature digest %v is not available", cfg.SignatureDigest)
	}
	return &Authority{
		db:       db,
		provider: provider,
		cfg:      cfg,
		now:      time.Now,
		serial:   newSerial,
	}, nil
}

// SetClock overrides the time source (tests only).
func (a *Authority) SetClock(now func() time.Time) { a.now = now }

// checkTimeStampingEKU enforces RFC 3161 §2.3: the signing certificate must have
// id-kp-timeStamping as its only extended key usage.
func checkTimeStampingEKU(cert *x509.Certificate) error {
	hasTS := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			hasTS = true
		}
	}
	if !hasTS {
		return fmt.Errorf("tsa: signing certificate lacks the id-kp-timeStamping extended key usage")
	}
	// The critical-EKU / sole-EKU rule: any additional EKU (or unknown EKU OIDs)
	// makes the certificate unfit as a dedicated TSA credential.
	if len(cert.ExtKeyUsage) != 1 || len(cert.UnknownExtKeyUsage) != 0 {
		return fmt.Errorf("tsa: signing certificate must carry id-kp-timeStamping as its sole extended key usage")
	}
	return nil
}

// Register mounts the /tsa endpoint. Time-stamp requests are POST-only with an
// application/timestamp-query body.
func (a *Authority) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST "+a.cfg.Path, a.handle)
	log.Printf("TSA (RFC 3161) enabled at %s (key=%s policy=%v)", a.cfg.Path, a.cfg.KeyLabel, a.cfg.PolicyOID)
}

// Path returns the configured mount path (used to advertise the endpoint).
func (a *Authority) Path() string { return a.cfg.Path }

func (a *Authority) handle(w http.ResponseWriter, r *http.Request) {
	// Content-Type is advisory; accept the request as long as we can read a body.
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, contentTypeQuery) {
		// Be lenient: some clients omit or vary the type. Log and continue.
		log.Printf("tsa: unexpected Content-Type %q (continuing)", ct)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil {
		http.Error(w, "reading request body", http.StatusBadRequest)
		return
	}
	if len(body) > maxRequestBytes {
		http.Error(w, "time-stamp request too large", http.StatusRequestEntityTooLarge)
		return
	}

	result, err := a.Stamp(r.Context(), body)
	if err != nil {
		// We could not even produce a signed-free rejection; this is an internal
		// fault, not a protocol rejection.
		metrics.TimestampRequests.Inc("error")
		a.record(r, audit.ResultError, "", err.Error())
		http.Error(w, "internal error", http.StatusInternalServerError)
		log.Printf("tsa: producing response: %v", err)
		return
	}

	if result.Granted {
		metrics.TimestampRequests.Inc("granted")
		a.record(r, audit.ResultSuccess, result.Detail, "")
	} else {
		metrics.TimestampRequests.Inc("rejected")
		a.record(r, audit.ResultDenied, "", result.Detail)
	}

	w.Header().Set("Content-Type", contentTypeReply)
	w.WriteHeader(http.StatusOK)
	w.Write(result.Response)
}

// Result is the outcome of a Stamp call. Response is always a DER-encoded
// TimeStampResp (granted or rejected); Detail is a short audit/log string.
type Result struct {
	Response []byte
	Granted  bool
	Detail   string
}

// Stamp validates a DER TimeStampReq and produces a DER TimeStampResp. A
// well-formed but unacceptable request yields a token-less rejection response
// with the appropriate PKIFailureInfo (Result.Granted = false); a genuine
// internal failure (signer unavailable, marshal error) is returned as a Go
// error so the caller can distinguish it from a protocol rejection.
func (a *Authority) Stamp(ctx context.Context, reqDER []byte) (*Result, error) {
	req, err := ParseRequest(reqDER)
	if err != nil {
		return a.reject(err)
	}

	// Enforce the operator's accepted-hash allowlist (ParseRequest already ruled
	// out unknown algorithms; this narrows to the configured subset).
	if !a.hashAccepted(req.Hash) {
		return a.reject(badRequest(FailureBadAlg, "hash algorithm %v is not accepted by this TSA", req.Hash))
	}

	// If the client requested a specific policy, we must assert exactly that one.
	if len(req.ReqPolicy) > 0 && !req.ReqPolicy.Equal(a.cfg.PolicyOID) {
		return a.reject(badRequest(FailureUnacceptedPolicy,
			"requested policy %v is not supported (this TSA asserts %v)", req.ReqPolicy, a.cfg.PolicyOID))
	}

	serial, err := a.serial()
	if err != nil {
		return nil, fmt.Errorf("tsa: allocating token serial: %w", err)
	}

	params := tstInfoParams{
		Policy:       a.cfg.PolicyOID,
		SerialNumber: serial,
		GenTime:      a.now(),
		Accuracy:     a.cfg.Accuracy,
		Ordering:     a.cfg.Ordering,
	}
	if a.cfg.IncludeTSAName {
		params.TSAName = a.cfg.Certificate.RawSubject
	}

	tstInfoDER, err := buildTSTInfo(req, params)
	if err != nil {
		return nil, err
	}

	signer, err := a.provider.Signer(ctx, keyprovider.KeyRef{Label: a.cfg.KeyLabel})
	if err != nil {
		return nil, fmt.Errorf("tsa: opening signing key %q: %w", a.cfg.KeyLabel, err)
	}
	defer signer.Close()

	tokenDER, err := buildToken(signer, a.cfg.Certificate, a.cfg.Chain, a.cfg.SignatureDigest, tstInfoDER, req.CertReq)
	if err != nil {
		return nil, fmt.Errorf("tsa: signing token: %w", err)
	}

	respDER, err := grantedResponse(tokenDER)
	if err != nil {
		return nil, err
	}
	return &Result{
		Response: respDER,
		Granted:  true,
		Detail:   fmt.Sprintf("serial=%s hash=%v certReq=%t", serial, req.Hash, req.CertReq),
	}, nil
}

// reject turns a validation *RequestError into a token-less rejection response.
func (a *Authority) reject(err error) (*Result, error) {
	re, ok := err.(*RequestError)
	if !ok {
		re = &RequestError{Failure: FailureBadRequest, Message: err.Error()}
	}
	respDER, marshalErr := rejectionResponse(re.Failure, re.Message)
	if marshalErr != nil {
		return nil, marshalErr
	}
	return &Result{Response: respDER, Granted: false, Detail: re.Message}, nil
}

// hashAccepted reports whether h is in the configured accepted-hash allowlist.
func (a *Authority) hashAccepted(h crypto.Hash) bool {
	for _, accepted := range a.cfg.AcceptedHashes {
		if accepted == h {
			return true
		}
	}
	return false
}

// record appends a TSA audit event. Time-stamping is anonymous, so the actor is
// a fixed pseudo-principal; target/detail carry the token serial or the reason.
func (a *Authority) record(r *http.Request, result, target, detail string) {
	if a.db == nil {
		return
	}
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      "tsa:anonymous",
		ActorRoles: "tsa",
		Action:     audit.ActionTSATimestamp,
		Target:     target,
		Result:     result,
		Detail:     detail,
		IP:         clientIP(r),
	}
	if err := a.db.AppendEvent(e); err != nil {
		log.Printf("tsa: appending audit event: %v", err)
	}
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}

// newSerial returns a cryptographically random, positive 128-bit token serial,
// matching the unpredictable-serial policy used for certificates.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, err
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}
