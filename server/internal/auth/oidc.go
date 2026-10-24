// Package auth provides operator authentication: OIDC SSO login and ID-token verification with claim-to-role mapping.
package auth

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

type OIDCProvider struct {
	provider  *oidc.Provider
	verifier  *oidc.IDTokenVerifier
	issuerURL string
	clientID  string
}

func NewOIDCProvider(issuerURL, clientID string) (*OIDCProvider, error) {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC provider: %w", err)
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	return &OIDCProvider{
		provider:  provider,
		verifier:  verifier,
		issuerURL: issuerURL,
		clientID:  clientID,
	}, nil
}

type Claims struct {
	Subject string `json:"sub"`
	Email   string `json:"email"`
	// EmailVerified reports whether the IdP has verified the email address.
	// RBAC role assignments keyed by email are only honored when this is true,
	// so an unverified (or user-settable) email cannot be used to claim another
	// principal's roles.
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`

	// Issuer and Audience are the verified `iss` / `aud` of the token, taken from
	// the parsed ID token rather than re-decoded, so they reflect what the
	// verifier actually accepted.
	Issuer   string   `json:"-"`
	Audience []string `json:"-"`
	// Provider names the configured OIDC provider that verified this token. With
	// several machine issuers federated (Task 212) it is what makes authorization
	// per-provider: a claim->role mapping declared for one issuer must not be
	// matched by a token from another that happens to carry the same subject.
	// Empty for a single-provider deployment that did not name its issuer.
	Provider string `json:"-"`
	// Raw carries every claim the token asserted, so the per-provider
	// claim -> role mapper can inspect groups, roles, or any other claim the IdP
	// uses to express entitlement without this struct having to enumerate them.
	Raw map[string]interface{} `json:"-"`
}

func (o *OIDCProvider) VerifyToken(ctx context.Context, rawToken string) (*Claims, error) {
	idToken, err := o.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("verifying token: %w", err)
	}

	var claims Claims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("parsing claims: %w", err)
	}
	// The raw claim set is decoded separately because a typed struct cannot carry
	// the arbitrary group/role claims an IdP uses to express entitlement, and
	// encoding/json has no way to capture the remaining keys. Its error is
	// deliberately not checked: the verifier above already parsed iss/aud/exp out
	// of this payload, so it is known to be a JSON object and cannot fail to
	// decode into a map. Only the typed decode above can fail, on a claim whose
	// JSON type is wrong — which it still rejects.
	var raw map[string]interface{}
	_ = idToken.Claims(&raw)
	claims.Raw = raw
	claims.Issuer = idToken.Issuer
	claims.Audience = idToken.Audience

	return &claims, nil
}

func (o *OIDCProvider) IssuerURL() string {
	return o.issuerURL
}

func (o *OIDCProvider) ClientID() string {
	return o.clientID
}

// Provider exposes the underlying go-oidc provider so the interactive-login
// handler (internal/authn) can reach the IdP's authorization/token endpoints
// without re-running OIDC discovery.
func (o *OIDCProvider) Provider() *oidc.Provider {
	return o.provider
}

// VerifierForClient builds an ID-token verifier bound to a specific client id.
// Interactive console login may use a different OAuth2 client than the API's
// bearer-token audience, so it needs its own verifier.
func (o *OIDCProvider) VerifierForClient(clientID string) *oidc.IDTokenVerifier {
	return o.provider.Verifier(&oidc.Config{ClientID: clientID})
}
