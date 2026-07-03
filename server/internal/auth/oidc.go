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
