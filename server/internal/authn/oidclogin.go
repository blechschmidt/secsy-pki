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
	// name identifies this provider among several configured ones (Task 212). It
	// appears in /auth/login?provider=<name>, is recorded in the login
	// transaction cookie so the callback is dispatched back to this provider, and
	// is carried into the login audit detail. Empty in a single-provider
	// deployment.
	name string
	// displayName is the label the console shows on its sign-in button.
	displayName string
	// isDefault marks this provider as the target of a bare GET /auth/login.
	// Declaration order decides presentation; this decides policy, so an operator
	// can list providers in whatever order reads best and still point the bare
	// login URL at one of them.
	isDefault bool
	// txKey signs the short-lived transaction cookie carrying the CSRF state,
	// nonce, PKCE verifier, and provider name across the redirect. It is random
	// per process and shared by every provider on the manager, because several
	// providers may share one callback URL — the callback has to be able to read
	// a cookie whichever provider wrote it before it knows which that was.
	txKey []byte
	now   func() time.Time
}

// OIDCLoginConfig configures the interactive login handler.
type OIDCLoginConfig struct {
	// Name identifies the provider when several are configured; it must be unique
	// on the manager. Leave empty for a lone provider.
	Name string
	// DisplayName is the console's sign-in button label (defaults to Name).
	DisplayName string
	// Default makes this the provider a bare GET /auth/login uses. At most one
	// provider on a manager may set it; absent any, the first added one is used.
	Default      bool
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
	display := cfg.DisplayName
	if display == "" {
		display = cfg.Name
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
		resolve:     cfg.Resolve,
		name:        cfg.Name,
		displayName: display,
		isDefault:   cfg.Default,
		txKey:       mgr.loginTxKey(),
		now:         time.Now,
	}, nil
}

// Name returns the provider's configured name ("" for a lone provider).
func (l *OIDCLogin) Name() string { return l.name }

// DisplayName returns the console's sign-in button label for this provider.
func (l *OIDCLogin) DisplayName() string { return l.displayName }

// RedirectURL returns the callback URL registered for this provider at its IdP.
func (l *OIDCLogin) RedirectURL() string { return l.oauth.RedirectURL }

// oidcTx is the state carried across the redirect in a signed cookie. Keeping it
// client-side (rather than in server memory) makes the flow stateless and
// resilient across replicas, while the HMAC signature and short TTL prevent
// tampering and replay.
type oidcTx struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Issued   int64  `json:"t"`
	// Provider names the login provider that began the flow. It is what lets
	// several IdPs share one registered redirect URI: the callback reads this to
	// decide which verifier, client credentials, and claim mapping to complete
	// the exchange with. It is inside the HMAC-signed payload, so a caller cannot
	// steer its own code exchange at a provider that did not issue the state.
	Provider string `json:"p,omitempty"`
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
		Provider: l.name,
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
	// The transaction must belong to THIS provider. The manager already dispatches
	// on tx.Provider, so this only fires when a provider's own callback path is hit
	// with another provider's transaction — which must not complete here, or a code
	// issued by one IdP would be exchanged with another's client credentials.
	if tx.Provider != l.name {
		l.fail(w, r, http.StatusBadRequest, "provider_mismatch",
			fmt.Sprintf("login transaction belongs to provider %q, not %q", tx.Provider, l.name))
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
	if user != nil && user.AuthProvider == "" {
		user.AuthProvider = l.name
	}

	sess := l.mgr.startSession(w, user, MethodOIDC)
	recordLoginMetric(MethodOIDC, true)
	l.mgr.record(r, user, audit.ActionAuthLogin, sess.ID, audit.ResultSuccess, "method=oidc"+l.auditProvider())
	http.Redirect(w, r, l.mgr.consoleRedirect, http.StatusFound)
}

// fail records a failed login (metric + audit) and returns an error response.
// For the redirect-based callback a browser lands here, so a compact JSON error
// is acceptable; the console's login page surfaces the reason on retry.
func (l *OIDCLogin) fail(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	recordLoginMetric(MethodOIDC, false)
	l.mgr.record(r, nil, audit.ActionAuthLoginFailed, "", audit.ResultDenied,
		"method=oidc"+l.auditProvider()+" reason="+code+" "+detail)
	writeJSON(w, status, map[string]string{"error": detail, "code": code})
}

// auditProvider renders the provider name for audit detail, so a federated
// deployment can tell which IdP a login (or a failed login) went through.
func (l *OIDCLogin) auditProvider() string {
	if l.name == "" {
		return ""
	}
	return " provider=" + l.name
}

// --- signed transaction cookie ---
//
// The cookie is owned by the Manager rather than by one provider: its name and
// signing key are shared, so the callback can read a transaction whichever
// provider began the flow and then dispatch on the provider name inside it. The
// per-provider accessors below exist because a provider still writes its own
// transaction and still verifies that what came back is its own.

func (l *OIDCLogin) txCookieName() string { return l.mgr.txCookieName() }

func (l *OIDCLogin) setTxCookie(w http.ResponseWriter, tx oidcTx) {
	l.mgr.setLoginTxCookie(w, tx, l.txKey)
}

func (l *OIDCLogin) clearTxCookie(w http.ResponseWriter) {
	clearCookie(w, l.txCookieName(), l.mgr.secure)
}

func (l *OIDCLogin) readTxCookie(r *http.Request) (oidcTx, error) {
	return readLoginTxCookie(r, l.txCookieName(), l.txKey, l.now())
}

// txCookieName is the name of the shared login transaction cookie.
func (m *Manager) txCookieName() string { return m.sessionCookie + oidcTxCookieSuffix }

// setLoginTxCookie seals tx into the short-lived transaction cookie.
func (m *Manager) setLoginTxCookie(w http.ResponseWriter, tx oidcTx, key []byte) {
	payload, _ := json.Marshal(tx)
	b := base64.RawURLEncoding.EncodeToString(payload)
	setCookie(w, m.txCookieName(), b+"."+signTx(key, b), 600, true, m.secure)
}

// readLoginTx recovers the in-flight login transaction from the request, so the
// callback can learn which provider to dispatch to before completing the flow.
func (m *Manager) readLoginTx(r *http.Request) (oidcTx, error) {
	return readLoginTxCookie(r, m.txCookieName(), m.loginTxKey(), time.Now())
}

// readLoginTxCookie verifies and decodes the transaction cookie. A bad signature,
// a malformed payload, or an age beyond the 10-minute window all fail closed —
// the login then restarts rather than completing against stale state.
func readLoginTxCookie(r *http.Request, cookieName string, key []byte, now time.Time) (oidcTx, error) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return oidcTx{}, err
	}
	b, sig, ok := splitDot(c.Value)
	if !ok || !hmac.Equal([]byte(signTx(key, b)), []byte(sig)) {
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
	if now.Unix()-tx.Issued > 600 {
		return oidcTx{}, errors.New("login transaction expired")
	}
	return tx, nil
}

// sign is the provider's view of the shared transaction MAC.
func (l *OIDCLogin) sign(b string) string { return signTx(l.txKey, b) }

func signTx(key []byte, b string) string {
	mac := hmac.New(sha256.New, key)
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
