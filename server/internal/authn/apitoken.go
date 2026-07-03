package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Native scoped API tokens / service accounts (Task 86).
//
// A token is an opaque, high-entropy bearer secret of the form
// "secsy_pat_<random>". It authenticates a machine caller as a principal bound
// to a set of RBAC roles and a tenant scope. Tokens are the native, revocable,
// long-lived alternative to the single built-in root basic credential or an
// external OIDC IdP.
//
// Security model:
//   - The secret is generated from 256 bits of CSPRNG entropy, so it is not
//     brute-forceable. It is returned to the operator exactly once, at creation.
//   - Only a one-way hash of the secret is stored (see HashToken); the plaintext
//     never touches persistent storage. A database disclosure therefore cannot
//     yield a usable credential.
//   - Verification is fail-closed: an unknown, malformed, expired, or revoked
//     token is rejected with no distinguishing detail leaked to the caller.
const (
	// TokenSecretPrefix namespaces the token so it is self-identifying on the
	// wire (a presented credential with this prefix is unambiguously a secsy PAT,
	// never an OIDC JWT) and so leaked secrets are greppable/scannable.
	TokenSecretPrefix = "secsy_pat_"

	// TokenAuthScheme is the distinct HTTP Authorization scheme carrying an API
	// token, deliberately separate from the OIDC "Bearer" scheme so the two
	// verification paths never conflate. Clients that can only send "Bearer" are
	// still accepted because the TokenSecretPrefix disambiguates the credential.
	TokenAuthScheme = "Token"

	// tokenEntropyBytes is the number of random bytes in a token secret.
	tokenEntropyBytes = 32
	// tokenPrefixDisplayLen is how many leading characters of the secret are kept
	// (non-secret) for display in listings so an operator can recognize a token.
	tokenPrefixDisplayLen = 18
)

// ErrTokenInvalid is the single, detail-free error every verification failure
// maps to, so the caller cannot distinguish "unknown" from "expired" from
// "revoked" (which would aid probing). The specific outcome is recorded in a
// metric instead.
var ErrTokenInvalid = errors.New("authn: invalid api token")

// GenerateToken mints a new token secret and returns it together with its
// at-rest hash and its (non-secret) display prefix. The secret is the only copy
// of the credential; the caller must return it to the operator once and persist
// only the hash and prefix.
func GenerateToken() (secret, hash, prefix string) {
	b := make([]byte, tokenEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		// A failing CSPRNG is unrecoverable; the same policy as randToken.
		panic("authn: crypto/rand failed: " + err.Error())
	}
	secret = TokenSecretPrefix + base64.RawURLEncoding.EncodeToString(b)
	hash = HashToken(secret)
	prefix = secret
	if len(prefix) > tokenPrefixDisplayLen {
		prefix = prefix[:tokenPrefixDisplayLen]
	}
	return secret, hash, prefix
}

// HashToken computes the at-rest hash of a token secret: hex(SHA-256(secret)).
//
// A fast cryptographic hash — not argon2/bcrypt/scrypt — is the correct choice
// here, and this is a deliberate security decision:
//   - The secret carries 256 bits of entropy, so it cannot be brute-forced
//     offline. Password-hardening KDFs exist to slow the guessing of LOW-entropy
//     human passwords, which does not apply to a random 256-bit token.
//   - A deterministic, unsalted hash is what makes O(1) indexed lookup on the
//     verify path possible; a per-record salted KDF would force a linear scan and
//     a slow hash of every stored token on every request.
//
// This matches the design used by GitHub/GitLab personal access tokens.
func HashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// ResolveTokenLifetimeDays validates a requested token expiry against a maximum
// lifetime policy and returns the effective lifetime in days (0 = never
// expires). It is the single source of truth for the lifetime policy, shared by
// the REST handler and the CLI:
//   - requested == nil (unspecified): defaults to the cap; with no cap this is 0
//     (never expires).
//   - with a positive cap: the request must be within [1, cap]; 0 or an
//     over-cap value is rejected so the deployment can forbid immortal tokens.
//   - with no cap: any non-negative request is honored (including 0 = never).
func ResolveTokenLifetimeDays(max time.Duration, requested *int) (int, error) {
	capDays := int(max / (24 * time.Hour))
	if requested == nil {
		return capDays, nil
	}
	days := *requested
	if days < 0 {
		return 0, errors.New("expires_in_days must not be negative")
	}
	if capDays > 0 && (days == 0 || days > capDays) {
		return 0, fmt.Errorf("expires_in_days must be between 1 and %d (the configured maximum lifetime)", capDays)
	}
	return days, nil
}

// LooksLikeToken reports whether a presented credential is a secsy API token by
// its self-identifying prefix. It performs no lookup and does not validate the
// secret — it only routes the credential to the token verification path.
func LooksLikeToken(cred string) bool {
	return strings.HasPrefix(cred, TokenSecretPrefix)
}

// TokenLookup is the read side of the API-token store the authenticator depends
// on. Declaring it as an interface (rather than importing the database package)
// keeps authn free of a storage dependency and makes verification unit-testable
// with a fake. *database.DB satisfies it structurally.
type TokenLookup interface {
	// GetAPITokenByHash returns the token whose stored hash matches, or (nil, nil)
	// when none does.
	GetAPITokenByHash(hash string) (*models.APIToken, error)
	// TouchAPIToken records a successful use (last-used time + client IP),
	// best-effort.
	TouchAPIToken(id string, at time.Time, ip string) error
}

// TokenAuthenticator verifies presented API tokens against the store and
// resolves them to request principals. It is installed on the auth middleware
// (both the HTTP and gRPC paths) alongside the other credential verifiers.
type TokenAuthenticator struct {
	store TokenLookup
	now   func() time.Time

	// last-used writes are throttled: updating on every single request would put
	// a write on the hot path of a busy service account. touchInterval bounds how
	// often a given token's last-used timestamp is persisted; lastTouch is the
	// process-local memo of the most recent persisted touch per token.
	touchInterval time.Duration
	mu            sync.Mutex
	lastTouch     map[string]time.Time
}

// NewTokenAuthenticator builds a verifier over the given store.
func NewTokenAuthenticator(store TokenLookup) *TokenAuthenticator {
	return &TokenAuthenticator{
		store:         store,
		now:           time.Now,
		touchInterval: time.Minute,
		lastTouch:     make(map[string]time.Time),
	}
}

// Verify resolves an opaque token secret to a request principal, or returns
// ErrTokenInvalid. It is fail-closed at every step: a non-token credential, a
// store error, an unknown hash, a revoked token, or an expired token all yield
// the same detail-free error, and the specific outcome is recorded as a metric.
// On success it records a throttled last-used touch and returns the principal
// carrying the token's roles and tenant scope.
func (t *TokenAuthenticator) Verify(secret, ip string) (*models.UserInfo, error) {
	if t == nil || !LooksLikeToken(secret) {
		metrics.RecordAuthTokenVerify(metrics.TokenVerifyUnknown)
		return nil, ErrTokenInvalid
	}
	rec, err := t.store.GetAPITokenByHash(HashToken(secret))
	if err != nil {
		// Do not leak the store error to the caller; treat it as a hard failure.
		metrics.RecordAuthTokenVerify(metrics.TokenVerifyError)
		return nil, ErrTokenInvalid
	}
	if rec == nil {
		metrics.RecordAuthTokenVerify(metrics.TokenVerifyUnknown)
		return nil, ErrTokenInvalid
	}
	now := t.now()
	if rec.Revoked() {
		metrics.RecordAuthTokenVerify(metrics.TokenVerifyRevoked)
		return nil, ErrTokenInvalid
	}
	if !rec.Active(now) {
		// Not revoked (checked above) and not active ⇒ expired.
		metrics.RecordAuthTokenVerify(metrics.TokenVerifyExpired)
		return nil, ErrTokenInvalid
	}
	metrics.RecordAuthTokenVerify(metrics.TokenVerifySuccess)
	t.touch(rec.ID, now, ip)
	return rec.Principal(), nil
}

// touch persists a last-used update at most once per touchInterval per token.
// It is best-effort: a storage failure is ignored, since losing an advisory
// last-used timestamp must never fail an otherwise-valid authentication.
func (t *TokenAuthenticator) touch(id string, now time.Time, ip string) {
	t.mu.Lock()
	if last, ok := t.lastTouch[id]; ok && now.Sub(last) < t.touchInterval {
		t.mu.Unlock()
		return
	}
	t.lastTouch[id] = now
	t.mu.Unlock()
	_ = t.store.TouchAPIToken(id, now, ip)
}
