package authn

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

type fakeTokenStore struct {
	byHash  map[string]*models.APIToken
	err     error
	touches int
	lastIP  string
}

func (f *fakeTokenStore) GetAPITokenByHash(hash string) (*models.APIToken, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.byHash[hash], nil
}

func (f *fakeTokenStore) TouchAPIToken(id string, at time.Time, ip string) error {
	f.touches++
	f.lastIP = ip
	return nil
}

func TestGenerateTokenFormat(t *testing.T) {
	secret, hash, prefix := GenerateToken()
	if !strings.HasPrefix(secret, TokenSecretPrefix) {
		t.Fatalf("secret %q missing prefix %q", secret, TokenSecretPrefix)
	}
	if !LooksLikeToken(secret) {
		t.Fatalf("LooksLikeToken(%q) = false", secret)
	}
	if hash != HashToken(secret) {
		t.Fatalf("returned hash != HashToken(secret)")
	}
	if len(hash) != 64 {
		t.Fatalf("hash length = %d, want 64 hex chars", len(hash))
	}
	if !strings.HasPrefix(secret, prefix) || len(prefix) != tokenPrefixDisplayLen {
		t.Fatalf("prefix %q is not the %d-char lead of secret", prefix, tokenPrefixDisplayLen)
	}
	// The secret must never equal its stored hash, and must be high-entropy: two
	// generations differ.
	s2, _, _ := GenerateToken()
	if secret == s2 {
		t.Fatalf("two generated tokens collided")
	}
}

func TestHashTokenDeterministic(t *testing.T) {
	const sample = "secsy_pat_abc"
	first, second := HashToken(sample), HashToken(sample)
	if first != second {
		t.Fatalf("HashToken is not deterministic")
	}
	if HashToken("a") == HashToken("b") {
		t.Fatalf("distinct inputs hashed equal")
	}
}

func mkToken(secret string, mut func(*models.APIToken)) (string, *models.APIToken) {
	hash := HashToken(secret)
	tok := &models.APIToken{
		ID:        "tok-1",
		TenantID:  "acme",
		Name:      "ci",
		Prefix:    secret[:tokenPrefixDisplayLen],
		TokenHash: hash,
		Roles:     []string{"issuer"},
		Scope:     models.TokenScopeTenant,
		CreatedAt: time.Now().Add(-time.Hour),
	}
	if mut != nil {
		mut(tok)
	}
	return hash, tok
}

func TestVerifySuccessTenantScoped(t *testing.T) {
	secret, _, _ := GenerateToken()
	hash, tok := mkToken(secret, nil)
	store := &fakeTokenStore{byHash: map[string]*models.APIToken{hash: tok}}
	ta := NewTokenAuthenticator(store)

	info, err := ta.Verify(secret, "203.0.113.7")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if info.Subject != "token:tok-1" || info.IsRoot {
		t.Fatalf("unexpected principal: %+v", info)
	}
	if len(info.Roles) != 0 {
		t.Fatalf("tenant-scoped token must not carry platform roles, got %v", info.Roles)
	}
	if got := info.TenantRoles["acme"]; len(got) != 1 || got[0] != "issuer" {
		t.Fatalf("tenant roles = %v, want issuer in acme", info.TenantRoles)
	}
	if store.touches != 1 || store.lastIP != "203.0.113.7" {
		t.Fatalf("expected a last-used touch with the client IP, got touches=%d ip=%q", store.touches, store.lastIP)
	}
}

func TestVerifySuccessPlatformScoped(t *testing.T) {
	secret, _, _ := GenerateToken()
	hash, tok := mkToken(secret, func(x *models.APIToken) {
		x.Scope = models.TokenScopePlatform
		x.Roles = []string{"admin"}
	})
	store := &fakeTokenStore{byHash: map[string]*models.APIToken{hash: tok}}
	ta := NewTokenAuthenticator(store)

	info, err := ta.Verify(secret, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(info.TenantRoles) != 0 {
		t.Fatalf("platform-scoped token must not carry tenant roles, got %v", info.TenantRoles)
	}
	if len(info.Roles) != 1 || info.Roles[0] != "admin" {
		t.Fatalf("platform roles = %v, want [admin]", info.Roles)
	}
}

func TestVerifyFailClosed(t *testing.T) {
	goodSecret, _, _ := GenerateToken()
	hash, tok := mkToken(goodSecret, nil)

	cases := []struct {
		name   string
		secret string
		mutate func(*models.APIToken)
		store  *fakeTokenStore
	}{
		{
			name:   "not a token",
			secret: "Bearer eyJhbGc",
			store:  &fakeTokenStore{byHash: map[string]*models.APIToken{hash: tok}},
		},
		{
			name:   "unknown hash",
			secret: TokenSecretPrefix + "unknownvalue",
			store:  &fakeTokenStore{byHash: map[string]*models.APIToken{hash: tok}},
		},
		{
			name:   "store error",
			secret: goodSecret,
			store:  &fakeTokenStore{err: errors.New("db down")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ta := NewTokenAuthenticator(tc.store)
			if _, err := ta.Verify(tc.secret, ""); !errors.Is(err, ErrTokenInvalid) {
				t.Fatalf("Verify(%s): err = %v, want ErrTokenInvalid", tc.name, err)
			}
		})
	}
}

func TestVerifyExpiredAndRevoked(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

	t.Run("expired", func(t *testing.T) {
		secret, _, _ := GenerateToken()
		past := now.Add(-time.Minute)
		hash, tok := mkToken(secret, func(x *models.APIToken) { x.ExpiresAt = &past })
		ta := NewTokenAuthenticator(&fakeTokenStore{byHash: map[string]*models.APIToken{hash: tok}})
		ta.now = func() time.Time { return now }
		if _, err := ta.Verify(secret, ""); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("expired token accepted: %v", err)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		secret, _, _ := GenerateToken()
		rev := now.Add(-time.Minute)
		future := now.Add(time.Hour)
		hash, tok := mkToken(secret, func(x *models.APIToken) {
			x.ExpiresAt = &future // not expired…
			x.RevokedAt = &rev    // …but revoked
		})
		ta := NewTokenAuthenticator(&fakeTokenStore{byHash: map[string]*models.APIToken{hash: tok}})
		ta.now = func() time.Time { return now }
		if _, err := ta.Verify(secret, ""); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("revoked token accepted: %v", err)
		}
	})
}

func TestTouchThrottle(t *testing.T) {
	secret, _, _ := GenerateToken()
	hash, tok := mkToken(secret, nil)
	store := &fakeTokenStore{byHash: map[string]*models.APIToken{hash: tok}}
	ta := NewTokenAuthenticator(store)
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	ta.now = func() time.Time { return base }

	for i := 0; i < 5; i++ {
		if _, err := ta.Verify(secret, ""); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
	if store.touches != 1 {
		t.Fatalf("within throttle window: touches = %d, want 1", store.touches)
	}
	// Advance past the throttle window: the next use persists again.
	ta.now = func() time.Time { return base.Add(2 * time.Minute) }
	if _, err := ta.Verify(secret, ""); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if store.touches != 2 {
		t.Fatalf("after throttle window: touches = %d, want 2", store.touches)
	}
}
