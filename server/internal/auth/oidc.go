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
	Name    string `json:"name"`
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
