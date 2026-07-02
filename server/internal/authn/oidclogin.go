package authn

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// PrincipalResolver turns a verified OIDC identity into a console principal,
// applying the claim/group -> RBAC role mapping. It is supplied by main.go,
// which owns the rbac assignments and the ClaimMapper. Returning an error denies
// the login (e.g. the operator matched no role and the deployment forbids
// zero-role logins).
type PrincipalResolver func(idToken *oidc.IDToken, claims map[string]interface{}) (*models.UserInfo, error)

// OIDCLogin implements the server-side OpenID Connect Authorization-Code flow
// (with PKCE) for the operator console. Unlike a bare token verifier, it drives
// the full browser redirect handshake and establishes a server-side session, so
// the console never has to hold or refresh an IdP token itself.
type OIDCLogin struct {
	mgr      *Manager
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	resolve  PrincipalResolver
	// txKey signs the short-lived transaction cookie carrying the CSRF state,
	// nonce, and PKCE verifier across the redirect. It is random per process.
	txKey []byte
	now   func() time.Time
}

// OIDCLoginConfig configures the interactive login handler.
type OIDCLoginConfig struct {
	Provider     *oidc.Provider
	Verifier     *oidc.IDTokenVerifier
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
	Resolve      PrincipalResolver
}

// NewOIDCLogin builds the login handler and binds it to the manager (for session
// creation, cookies, and audit). The default scopes request an id token with
// profile and email; operators may add a groups scope in config.
func NewOIDCLogin(mgr *Manager, cfg OIDCLoginConfig) (*OIDCLogin, error) {
	if cfg.Provider == nil || cfg.Verifier == nil {
		return nil, errors.New("authn: OIDC login requires a provider and verifier")
	}
	if cfg.RedirectURL == "" {
		return nil, errors.New("authn: OIDC login requires a redirect_url")
	}
	if cfg.Resolve == nil {
		return nil, errors.New("authn: OIDC login requires a principal resolver")
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	return &OIDCLogin{
		mgr:      mgr,
		verifier: cfg.Verifier,
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     cfg.Provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		resolve: cfg.Resolve,
		txKey:   []byte(randToken(32)),
		now:     time.Now,
	}, nil
}

// oidcTx is the state carried across the redirect in a signed cookie. Keeping it
// client-side (rather than in server memory) makes the flow stateless and
// resilient across replicas, while the HMAC signature and short TTL prevent
// tampering and replay.
type oidcTx struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Issued   int64  `json:"t"`
}

// Begin starts the login: it generates CSRF state, an OIDC nonce, and a PKCE
// verifier, stashes them in a signed transaction cookie, and redirects the
// browser to the IdP's authorization endpoint.
func (l *OIDCLogin) Begin(w http.ResponseWriter, r *http.Request) {
	tx := oidcTx{
		State:    randToken(24),
		Nonce:    randToken(24),
		Verifier: oauth2.GenerateVerifier(),
		Issued:   l.now().Unix(),
	}
	l.setTxCookie(w, tx)
	url := l.oauth.AuthCodeURL(tx.State,
		oidc.Nonce(tx.Nonce),
		oauth2.S256ChallengeOption(tx.Verifier),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

// Callback completes the login: it validates the state, exchanges the code (with
// the PKCE verifier), verifies the id token and nonce, resolves the principal,
// and establishes a session before redirecting to the console.
func (l *OIDCLogin) Callback(w http.ResponseWriter, r *http.Request) {
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		l.fail(w, r, http.StatusUnauthorized, "idp_error", fmt.Sprintf("idp returned error %q", errParam))
		return
	}
	tx, err := l.readTxCookie(r)
	l.clearTxCookie(w)
	if err != nil {
		l.fail(w, r, http.StatusBadRequest, "bad_tx", "missing or invalid login transaction")
		return
	}
	// Constant-time state comparison defeats CSRF on the callback.
	if state := r.URL.Query().Get("state"); !constantTimeEqual(state, tx.State) {
		l.fail(w, r, http.StatusBadRequest, "state_mismatch", "state mismatch")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		l.fail(w, r, http.StatusBadRequest, "no_code", "missing authorization code")
		return
	}

	ctx := r.Context()
	token, err := l.oauth.Exchange(ctx, code, oauth2.VerifierOption(tx.Verifier))
	if err != nil {
		l.fail(w, r, http.StatusUnauthorized, "exchange_failed", "code exchange failed: "+err.Error())
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		l.fail(w, r, http.StatusUnauthorized, "no_id_token", "token response carried no id_token")
		return
	}
	idToken, err := l.verifier.Verify(ctx, rawID)
	if err != nil {
		l.fail(w, r, http.StatusUnauthorized, "verify_failed", "id token verification failed: "+err.Error())
		return
	}
	// Bind the nonce to defeat token replay/injection.
	if !constantTimeEqual(idToken.Nonce, tx.Nonce) {
		l.fail(w, r, http.StatusUnauthorized, "nonce_mismatch", "id token nonce mismatch")
		return
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		l.fail(w, r, http.StatusUnauthorized, "claims_failed", "could not parse id token claims")
		return
	}
	user, err := l.resolve(idToken, claims)
	if err != nil {
		l.fail(w, r, http.StatusForbidden, "no_access", err.Error())
		return
	}

	sess := l.mgr.startSession(w, user, MethodOIDC)
	recordLoginMetric(MethodOIDC, true)
	l.mgr.record(r, user, audit.ActionAuthLogin, sess.ID, audit.ResultSuccess, "method=oidc")
	http.Redirect(w, r, l.mgr.consoleRedirect, http.StatusFound)
}

// fail records a failed login (metric + audit) and returns an error response.
// For the redirect-based callback a browser lands here, so a compact JSON error
// is acceptable; the console's login page surfaces the reason on retry.
func (l *OIDCLogin) fail(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	recordLoginMetric(MethodOIDC, false)
	l.mgr.record(r, nil, audit.ActionAuthLoginFailed, "", audit.ResultDenied, "method=oidc reason="+code+" "+detail)
	writeJSON(w, status, map[string]string{"error": detail, "code": code})
}

// --- signed transaction cookie ---

func (l *OIDCLogin) txCookieName() string { return l.mgr.sessionCookie + oidcTxCookieSuffix }

func (l *OIDCLogin) setTxCookie(w http.ResponseWriter, tx oidcTx) {
	payload, _ := json.Marshal(tx)
	b := base64.RawURLEncoding.EncodeToString(payload)
	sig := l.sign(b)
	setCookie(w, l.txCookieName(), b+"."+sig, 600, true, l.mgr.secure)
}

func (l *OIDCLogin) clearTxCookie(w http.ResponseWriter) {
	clearCookie(w, l.txCookieName(), l.mgr.secure)
}

func (l *OIDCLogin) readTxCookie(r *http.Request) (oidcTx, error) {
	c, err := r.Cookie(l.txCookieName())
	if err != nil {
		return oidcTx{}, err
	}
	b, sig, ok := splitDot(c.Value)
	if !ok || !hmac.Equal([]byte(l.sign(b)), []byte(sig)) {
		return oidcTx{}, errors.New("bad signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(b)
	if err != nil {
		return oidcTx{}, err
	}
	var tx oidcTx
	if err := json.Unmarshal(payload, &tx); err != nil {
		return oidcTx{}, err
	}
	if l.now().Unix()-tx.Issued > 600 {
		return oidcTx{}, errors.New("login transaction expired")
	}
	return tx, nil
}

func (l *OIDCLogin) sign(b string) string {
	mac := hmac.New(sha256.New, l.txKey)
	mac.Write([]byte(b))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// splitDot splits "a.b" into (a, b, true), or ("", "", false) when there is no
// single separator.
func splitDot(s string) (string, string, bool) {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}
