package acme

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/attestation"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Config configures the ACME server. It is populated from the acme block of the
// application config (see internal/config).
type Config struct {
	// BaseURL is the externally reachable origin of the server, e.g.
	// "https://pki.example.com". When empty, the origin is derived from each
	// request (scheme + Host, honoring X-Forwarded-Proto/Host). It must not have
	// a trailing slash.
	BaseURL string
	// DirectoryPath is the URL prefix the ACME endpoints are mounted under
	// (default "/acme").
	DirectoryPath string
	// CAID is the id of the CA that issues ACME certificates. Every ACME leaf is
	// signed by this CA through the shared, HSM-backed ca.Manager.
	CAID string
	// Profile is the default certificate profile applied to ACME-issued
	// certificates when the client does not select one (default "server"). It is
	// the fallback for orders that omit the newOrder "profile" field, so the
	// server stays backward compatible whether or not the ACME Profiles extension
	// is configured.
	Profile string
	// Profiles, when non-empty, enables the ACME Profiles extension (RFC 9773):
	// a single ACME endpoint can offer several client-selectable issuance
	// profiles. Each entry maps an ACME-visible profile name — advertised in the
	// directory's meta.profiles and accepted in the newOrder "profile" field — to
	// its internal ca issuance profile id. A newOrder that names a profile not in
	// this allowlist is rejected with an invalidProfile problem. When empty, the
	// extension is not advertised and every order uses Profile.
	Profiles map[string]ACMEProfile
	// TermsOfService, if set, is advertised in the directory metadata and clients
	// must agree to it on account creation.
	TermsOfService string
	// HTTP01Port overrides the port used for http-01 validation (default 80).
	// Intended for tests, which cannot bind port 80.
	HTTP01Port int
	// TLSALPN01Port overrides the port used for tls-alpn-01 validation
	// (default 443). Intended for tests, which cannot bind port 443.
	TLSALPN01Port int
	// DNSResolver, when set (host:port), pins ALL challenge validation — dns-01
	// TXT lookups plus the http-01 / tls-alpn-01 name resolution — to that DNS
	// server instead of the system resolver. Intended for the interop test
	// harness (which serves the challenge targets and TXT records from one local
	// DNS server) and for split-horizon deployments validating a specific view.
	DNSResolver string
	// ChallengeTypes lists the challenge types offered per authorization
	// (default: http-01, dns-01, and tls-alpn-01).
	ChallengeTypes []string
	// RequireEAB, when true, requires a valid External Account Binding on account
	// creation, tying each account to an operator-provisioned key (the ACME
	// analogue of an RBAC grant).
	RequireEAB bool
	// EABHMACKeys maps an EAB key id to its base64url-encoded HMAC key.
	EABHMACKeys map[string]string
	// AllowIPIdentifiers permits "ip"-type identifiers (RFC 8738). Off by default.
	AllowIPIdentifiers bool
	// OrderValidity / AuthzValidity bound how long orders and authorizations
	// remain pending before expiring.
	OrderValidity time.Duration
	AuthzValidity time.Duration

	// ---- ACME Renewal Information (ARI, draft-ietf-acme-ari) ----
	// RenewBefore is how long before expiry the suggested renewal window begins.
	// Zero derives it per certificate as a third of the certificate's lifetime.
	RenewBefore time.Duration
	// RenewalWindowWidth is the width of the suggested renewal window. Zero derives
	// it as half of RenewBefore, giving clients a band over which to spread load.
	RenewalWindowWidth time.Duration
	// RenewalPollInterval is advertised in the renewalInfo Retry-After header
	// (default 6h). A forced-renewal signal shortens it so clients re-poll sooner.
	RenewalPollInterval time.Duration
	// ExplanationURL, if set, is returned in every renewalInfo response and points
	// operators/clients at a page explaining an active mass-renewal event.
	ExplanationURL string

	// Attestation, when set, verifies device-attest-01 hardware key-attestation
	// evidence (draft-ietf-acme-device-attest) against trusted manufacturer roots
	// (Task 49). When the ACME profile's attestation mode is not "off", the
	// server offers a device-attest-01 challenge and validates the returned
	// WebAuthn attestation object. A nil verifier disables the challenge.
	Attestation *attestation.Verifier

	// NonceSecret optionally pins the shared secret used to sign self-
	// authenticating anti-replay nonces (Task 97). When empty (the default), the
	// server loads — or generates once and persists — a durable shared secret from
	// the store, so every replica sharing the store agrees without configuration.
	// Set it (identically on every replica, at least nonceMinSecretLen bytes) to
	// skip the startup store read or to rotate the signing key. It is never logged.
	NonceSecret []byte

	// Email, when set with both a MailSender and a MailInbox, enables the RFC 8823
	// email-reply-00 challenge for "email"-type identifiers (S/MIME issuance via
	// ACME, Task 108). The server then accepts email orders, offers the challenge,
	// and runs an inbound-mail poller (register RunEmailChallengePoller as a
	// leader-elected job). Absent or half-configured, the challenge is not offered
	// and email identifiers are rejected as unsupported.
	Email *EmailChallengeConfig
}

// ACMEProfile is one client-selectable issuance profile exposed by the ACME
// Profiles extension (RFC 9773). It maps an ACME-visible profile name to an
// internal ca issuance profile id, plus the human-readable description
// advertised in the directory's meta.profiles.
type ACMEProfile struct {
	// Description is the human-readable text advertised in meta.profiles.
	Description string
	// Profile is the internal ca issuance profile id this selection maps to. When
	// empty, the server's default Config.Profile is used.
	Profile string
}

// profilesEnabled reports whether the ACME Profiles extension is configured.
func (c Config) profilesEnabled() bool { return len(c.Profiles) > 0 }

// resolveProfile maps a client-supplied newOrder "profile" name to the internal
// ca issuance profile id to issue under. An empty name selects the default
// (c.Profile), keeping omit-the-field orders backward compatible. A non-empty
// name must be one of the configured, advertised profiles; otherwise ok is false
// and the caller returns an invalidProfile problem (RFC 9773).
func (c Config) resolveProfile(name string) (internalID string, ok bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return c.Profile, true
	}
	p, found := c.Profiles[name]
	if !found {
		return "", false
	}
	if p.Profile == "" {
		return c.Profile, true
	}
	return p.Profile, true
}

// advertisedProfiles returns the directory meta.profiles map (ACME-visible name
// → description), or nil when the extension is not configured so the field is
// omitted from the directory entirely.
func (c Config) advertisedProfiles() map[string]string {
	if !c.profilesEnabled() {
		return nil
	}
	out := make(map[string]string, len(c.Profiles))
	for name, p := range c.Profiles {
		out[name] = p.Description
	}
	return out
}

// profileNames returns the configured ACME-visible profile names, sorted, for
// the invalidProfile problem detail.
func (c Config) profileNames() []string {
	out := make([]string, 0, len(c.Profiles))
	for name := range c.Profiles {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// withDefaults returns a copy of the config with zero-valued fields filled in.
func (c Config) withDefaults() Config {
	if c.DirectoryPath == "" {
		c.DirectoryPath = "/acme"
	}
	c.DirectoryPath = "/" + strings.Trim(c.DirectoryPath, "/")
	if c.Profile == "" {
		c.Profile = "server"
	}
	if c.HTTP01Port == 0 {
		c.HTTP01Port = 80
	}
	if len(c.ChallengeTypes) == 0 {
		c.ChallengeTypes = []string{"http-01", "dns-01", "tls-alpn-01"}
	}
	if c.OrderValidity == 0 {
		c.OrderValidity = 7 * 24 * time.Hour
	}
	if c.AuthzValidity == 0 {
		c.AuthzValidity = 7 * 24 * time.Hour
	}
	if c.RenewalPollInterval == 0 {
		c.RenewalPollInterval = 6 * time.Hour
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	return c
}

// Server implements the ACME protocol endpoints. It is safe for concurrent use.
type Server struct {
	db        *database.DB
	provider  keyprovider.Provider
	caMgr     *ca.Manager
	cfg       Config
	nonces    *nonceStore
	validator *Validator
	email     *emailChallenger
	now       func() time.Time
}

// New constructs an ACME server. It does not start any listener; call Register
// to attach the endpoints to an http.ServeMux.
func New(db *database.DB, provider keyprovider.Provider, cfg Config) *Server {
	cfg = cfg.withDefaults()
	return &Server{
		db:        db,
		provider:  provider,
		caMgr:     ca.NewManager(db, provider),
		cfg:       cfg,
		nonces:    newNonceStore(db, resolveNonceSecret(db, cfg.NonceSecret), time.Now),
		validator: newValidator(cfg.HTTP01Port, cfg.TLSALPN01Port, cfg.DNSResolver),
		email:     newEmailChallenger(cfg.Email),
		now:       time.Now,
	}
}

// resolveNonceSecret returns the shared secret used to sign anti-replay nonces.
// An explicit secret from config wins; otherwise it loads (or generates once)
// the durable shared secret from the store, so every replica sharing the store
// signs and verifies nonces with the same key. If the store is unreachable it
// falls back to a per-instance random secret so the server still starts — nonces
// are simply not shared across replicas until the store is reachable, matching
// the pre-Task-97 per-instance behavior rather than failing startup outright.
func resolveNonceSecret(db *database.DB, explicit []byte) []byte {
	if len(explicit) >= nonceMinSecretLen {
		return explicit
	}
	if secret, err := db.GetOrCreateACMENonceSecret(); err == nil && len(secret) >= nonceMinSecretLen {
		return secret
	} else if err != nil {
		log.Printf("acme: could not load shared nonce secret (%v); falling back to a per-instance secret", err)
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		panic("acme: crypto/rand failed generating nonce secret: " + err.Error())
	}
	return buf
}

// SetValidator overrides the challenge validator. Used by tests to inject a
// controllable HTTP client / DNS resolver.
func (s *Server) SetValidator(v *Validator) { s.validator = v }

// SetClock overrides the time source. Used by tests.
func (s *Server) SetClock(now func() time.Time) {
	s.now = now
	s.nonces.now = now
}

// nonceGCInterval is how often RunNonceGC prunes expired consumed-nonce records.
// It is well under the nonce TTL so the consumed-set stays small; the exact
// cadence is not correctness-critical, because an expired nonce is rejected by
// its embedded timestamp before the consumed-set is ever consulted.
const nonceGCInterval = 5 * time.Minute

// RunNonceGC periodically evicts expired consumed-nonce records until ctx is
// cancelled. Register it as a leader-elected background job (like the other
// periodic sweeps) so one replica prunes the shared consumed-set; the sweep is
// idempotent, so a redundant run on another replica is harmless. It runs one
// sweep immediately, then on each tick, and returns promptly on ctx
// cancellation.
func (s *Server) RunNonceGC(ctx context.Context) {
	t := time.NewTicker(nonceGCInterval)
	defer t.Stop()
	for {
		if n, err := s.nonces.gc(); err != nil {
			log.Printf("acme: nonce GC: %v", err)
		} else if n > 0 {
			log.Printf("acme: nonce GC evicted %d expired consumed nonce(s)", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// DirectoryURL returns the absolute URL of the directory resource for a request.
func (s *Server) DirectoryURL(r *http.Request) string {
	return s.link(r, "/directory")
}

// Register mounts the ACME endpoints on mux under the configured DirectoryPath.
// Patterns include the prefix so that r.URL.Path stays intact, keeping the
// signed-url check straightforward.
func (s *Server) Register(mux *http.ServeMux) {
	p := s.cfg.DirectoryPath
	mux.HandleFunc("GET "+p+"/directory", s.handleDirectory)
	mux.HandleFunc("GET "+p+"/new-nonce", s.handleNewNonce)
	mux.HandleFunc("HEAD "+p+"/new-nonce", s.handleNewNonce)
	mux.HandleFunc("POST "+p+"/new-account", s.handleNewAccount)
	mux.HandleFunc("POST "+p+"/new-order", s.handleNewOrder)
	mux.HandleFunc("POST "+p+"/order/{id}", s.handleOrder)
	mux.HandleFunc("POST "+p+"/order/{id}/finalize", s.handleFinalize)
	mux.HandleFunc("POST "+p+"/authz/{id}", s.handleAuthz)
	mux.HandleFunc("POST "+p+"/chall/{id}", s.handleChallenge)
	mux.HandleFunc("POST "+p+"/cert/{id}", s.handleCertificate)
	// Alternate certificate chains (RFC 8555 §7.4.2): the same leaf served with a
	// differently-rooted trust path, one per cross-sign of the issuing CA (Task 47).
	mux.HandleFunc("POST "+p+"/cert/{id}/{n}", s.handleAlternateCertificate)
	mux.HandleFunc("POST "+p+"/acct/{id}", s.handleAccount)
	mux.HandleFunc("POST "+p+"/acct/{id}/orders", s.handleAccountOrders)
	mux.HandleFunc("POST "+p+"/revoke-cert", s.handleRevokeCert)
	mux.HandleFunc("POST "+p+"/key-change", s.handleKeyChange)
	// ACME Renewal Information (ARI, draft-ietf-acme-ari): an unauthenticated GET
	// keyed by the certificate's CertID (AKI+serial).
	mux.HandleFunc("GET "+p+"/renewal-info/{certid}", s.handleRenewalInfo)
	if s.cfg.profilesEnabled() {
		log.Printf("ACME server enabled at %s/directory (CA=%s default-profile=%s selectable-profiles=%s)",
			p, s.cfg.CAID, s.cfg.Profile, strings.Join(s.cfg.profileNames(), ","))
	} else {
		log.Printf("ACME server enabled at %s/directory (CA=%s profile=%s)", p, s.cfg.CAID, s.cfg.Profile)
	}
}

// ---- URL helpers ----------------------------------------------------------

// externalBase returns the scheme://host origin the client used, honoring an
// explicit BaseURL override and common reverse-proxy headers.
func (s *Server) externalBase(r *http.Request) string {
	if s.cfg.BaseURL != "" {
		return s.cfg.BaseURL
	}
	scheme := "https"
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	} else if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		host = xfh
	}
	return scheme + "://" + host
}

// link builds an absolute URL for a path suffix under the ACME prefix.
func (s *Server) link(r *http.Request, suffix string) string {
	return s.externalBase(r) + s.cfg.DirectoryPath + suffix
}

// requestURL reconstructs the absolute URL the client addressed, used to verify
// the JWS "url" header.
func (s *Server) requestURL(r *http.Request) string {
	return s.externalBase(r) + r.URL.Path
}

func (s *Server) accountURL(r *http.Request, id string) string { return s.link(r, "/acct/"+id) }
func (s *Server) orderURL(r *http.Request, id string) string   { return s.link(r, "/order/"+id) }
func (s *Server) authzURL(r *http.Request, id string) string   { return s.link(r, "/authz/"+id) }
func (s *Server) challURL(r *http.Request, id string) string   { return s.link(r, "/chall/"+id) }
func (s *Server) certURL(r *http.Request, id string) string    { return s.link(r, "/cert/"+id) }

// altCertURL returns the URL of the n-th (1-based) alternate certificate chain
// for an order, per RFC 8555 §7.4.2. Index 0 is the default chain at certURL.
func (s *Server) altCertURL(r *http.Request, id string, n int) string {
	return s.link(r, fmt.Sprintf("/cert/%s/%d", id, n))
}

// renewalInfoURL returns the base URL of the ARI renewalInfo resource. Clients
// append "/<certID>" to it.
func (s *Server) renewalInfoURL(r *http.Request) string { return s.link(r, "/renewal-info") }

// ---- Response helpers -----------------------------------------------------

// addNonce attaches a fresh Replay-Nonce header. Every ACME response should
// carry one so the client always has a usable nonce for its next request.
func (s *Server) addNonce(w http.ResponseWriter) {
	nonce, err := s.nonces.Issue()
	if err != nil {
		log.Printf("acme: failed to issue nonce: %v", err)
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Cache-Control", "no-store")
}

// writeJSON writes a JSON response with a fresh nonce and content type.
func (s *Server) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	s.addNonce(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			log.Printf("acme: encoding response: %v", err)
		}
	}
}

// writeProblem writes an RFC 7807 problem document with a fresh nonce.
func (s *Server) writeProblem(w http.ResponseWriter, p *Problem) {
	s.addNonce(w)
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.httpStatus())
	_ = json.NewEncoder(w).Encode(p)
}

// writeProblemNoNonce writes a problem document without issuing a Replay-Nonce.
// It is used by the unauthenticated ARI renewalInfo GET, which is not part of
// the nonce-anchored POST flow.
func (s *Server) writeProblemNoNonce(w http.ResponseWriter, p *Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(p.httpStatus())
	_ = json.NewEncoder(w).Encode(p)
}

// writeJSONBody writes a JSON body with an explicit status and no nonce. Callers
// that need a Replay-Nonce use writeJSON instead.
func writeJSONBody(w http.ResponseWriter, status int, v interface{}) {
	w.WriteHeader(status)
	if v != nil {
		if err := json.NewEncoder(w).Encode(v); err != nil {
			log.Printf("acme: encoding response: %v", err)
		}
	}
}

// ---- Directory & nonce ----------------------------------------------------

func (s *Server) handleDirectory(w http.ResponseWriter, r *http.Request) {
	dir := wireDirectory{
		NewNonce:    s.link(r, "/new-nonce"),
		NewAccount:  s.link(r, "/new-account"),
		NewOrder:    s.link(r, "/new-order"),
		RevokeCert:  s.link(r, "/revoke-cert"),
		KeyChange:   s.link(r, "/key-change"),
		RenewalInfo: s.renewalInfoURL(r),
		Meta: directoryMeta{
			TermsOfService:          s.cfg.TermsOfService,
			ExternalAccountRequired: s.cfg.RequireEAB,
			Profiles:                s.cfg.advertisedProfiles(),
		},
	}
	s.writeJSON(w, http.StatusOK, dir)
}

func (s *Server) handleNewNonce(w http.ResponseWriter, r *http.Request) {
	s.addNonce(w)
	w.Header().Set("Link", fmt.Sprintf("<%s>;rel=\"index\"", s.DirectoryURL(r)))
	// HEAD → 200; GET → 204 (RFC 8555 §7.2).
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Shared auth helpers --------------------------------------------------

// authAccount decodes and verifies a kid-authenticated request, returning the
// authenticated account and the request payload. It enforces that the account
// exists and is valid.
func (s *Server) authAccount(r *http.Request) (*acmeAccount, []byte, *Problem) {
	d, prob := s.decodeJWS(r)
	if prob != nil {
		return nil, nil, prob
	}
	if d.KID == "" {
		return nil, nil, newProblem(probMalformed, http.StatusBadRequest, "this request must be authenticated with an account \"kid\", not an embedded \"jwk\"")
	}
	acctID := s.accountIDFromKID(d.KID)
	if acctID == "" {
		return nil, nil, newProblem(probMalformed, http.StatusBadRequest, "malformed account \"kid\" URL")
	}
	rec, err := s.db.GetACMEAccount(acctID)
	if err != nil {
		return nil, nil, newProblem(probServerInternal, http.StatusInternalServerError, "account lookup failed")
	}
	if rec == nil {
		return nil, nil, newProblem(probAccountDoesntExist, http.StatusBadRequest, "account does not exist")
	}
	if rec.Status != "valid" {
		return nil, nil, newProblem(probUnauthorized, http.StatusUnauthorized, "account is "+rec.Status)
	}

	jwk, prob := parseStoredJWK(rec.JWK)
	if prob != nil {
		return nil, nil, prob
	}
	payload, prob := d.verify(jwk)
	if prob != nil {
		return nil, nil, prob
	}
	return &acmeAccount{rec: rec, jwk: jwk}, payload, nil
}

// accountIDFromKID extracts the account id from a kid URL of the form
// ".../acct/<id>".
func (s *Server) accountIDFromKID(kid string) string {
	marker := s.cfg.DirectoryPath + "/acct/"
	i := strings.Index(kid, marker)
	if i < 0 {
		return ""
	}
	rest := kid[i+len(marker):]
	// Guard against trailing path segments.
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// parseStoredJWK unmarshals a stored account JWK.
func parseStoredJWK(raw string) (*jose.JSONWebKey, *Problem) {
	var jwk jose.JSONWebKey
	if err := json.Unmarshal([]byte(raw), &jwk); err != nil {
		return nil, newProblem(probServerInternal, http.StatusInternalServerError, "stored account key is corrupt")
	}
	return &jwk, nil
}

// acmeAccount pairs a stored account record with its parsed public key.
type acmeAccount struct {
	rec *models.ACMEAccount
	jwk *jose.JSONWebKey
}

// newUUID returns a fresh random identifier for ACME objects.
func newUUID() string { return uuid.New().String() }

// recordEvent appends a tamper-evident audit event for an ACME operation. The
// actor is the ACME account. Failures are logged, never fatal to the request.
func (s *Server) recordEvent(r *http.Request, accountID, action, target, result, detail string) {
	e := &audit.Event{
		ID:         newUUID(),
		Actor:      "acme:" + accountID,
		ActorRoles: "acme",
		Action:     action,
		Target:     target,
		Result:     result,
		Detail:     detail,
		IP:         clientIP(r),
	}
	if err := s.db.AppendEvent(e); err != nil {
		log.Printf("acme: failed to append audit event %q: %v", action, err)
	}
}

// clientIP extracts a best-effort client IP, honoring X-Forwarded-For.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return fwd
	}
	return r.RemoteAddr
}
