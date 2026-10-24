package auth

// Multi-issuer Bearer verification (Task 212).
//
// A deployment rarely has one identity provider. The CI pipeline that asks for an
// artifact signature authenticates through its forge's workload-identity issuer
// (GitHub Actions, GitLab, a Kubernetes projected service-account token); the
// humans who administer the PKI sign in through the corporate IdP; a partner's
// automation may arrive through a third. Each mints its own JWTs, under its own
// issuer, with its own audience and its own idea of what a subject string means.
//
// MultiProvider trusts several such issuers at once without letting them become
// interchangeable. Two properties make that safe:
//
//   - A token is routed to exactly one verifier, by its `iss` claim. Routing uses
//     the UNVERIFIED payload — that is sound because the selected verifier then
//     re-checks `iss` cryptographically, so a forged `iss` only picks a provider
//     that will reject the signature. An unknown issuer is rejected outright
//     rather than offered to every verifier in turn.
//   - Every provider is audience-bound. A provider with no accepted audience is
//     refused at construction: it would otherwise honor any token the IdP minted
//     for an unrelated relying party.
//
// The provider that verified a token is reported back on the claims, which is what
// lets authorization be per-provider — "this GitHub workflow may sign artifacts"
// cannot be claimed by a token from another issuer that happens to carry the same
// `sub`.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

// ErrUnknownIssuer is returned when a presented Bearer JWT names an issuer no
// configured provider serves. It is deliberately distinguishable from a
// verification failure: the two mean different things to an operator reading the
// log (a misdirected client versus a bad token).
var ErrUnknownIssuer = errors.New("no configured OIDC provider for the token's issuer")

// ProviderSpec declares one machine-token issuer to trust.
type ProviderSpec struct {
	// Name identifies the provider in logs, audit detail, and on verified claims.
	Name string
	// IssuerURL is the IdP's issuer, used for discovery and matched against `iss`.
	IssuerURL string
	// Audiences are the accepted `aud` values. At least one is required.
	Audiences []string
}

// entry is one discovered provider plus the policy applied to its tokens.
type entry struct {
	name      string
	provider  *OIDCProvider
	audiences []string
}

// MultiProvider verifies Bearer ID/access tokens against several OIDC issuers,
// routing each token to the provider that serves its issuer. It satisfies the
// middleware's TokenVerifier, so a single-provider deployment and a federated one
// take the same code path.
type MultiProvider struct {
	byIssuer map[string]*entry
	order    []*entry
}

// ProviderError reports that one provider could not be brought up (discovery
// failed, or it was misconfigured). It is returned per provider so one
// unreachable IdP does not take the others down with it.
type ProviderError struct {
	Name      string
	IssuerURL string
	Err       error
}

func (e ProviderError) Error() string {
	return fmt.Sprintf("oidc provider %q (%s): %v", e.Name, e.IssuerURL, e.Err)
}

func (e ProviderError) Unwrap() error { return e.Err }

// NewMultiProvider performs OIDC discovery for each spec and returns a verifier
// over those that came up, alongside one ProviderError per provider that did not.
//
// Partial success is the intended outcome, not a compromise: an IdP that is
// unreachable at boot must not prevent the other issuers — or the rest of the
// server — from working, and the caller logs the errors so the gap is visible.
// A nil MultiProvider is returned when no provider came up, so the caller can
// install a nil TokenVerifier rather than a non-nil interface wrapping nothing.
func NewMultiProvider(ctx context.Context, specs []ProviderSpec) (*MultiProvider, []ProviderError) {
	m := &MultiProvider{byIssuer: make(map[string]*entry, len(specs))}
	var errs []ProviderError
	for _, s := range specs {
		name := strings.TrimSpace(s.Name)
		if name == "" {
			name = "default"
		}
		issuer := strings.TrimSpace(s.IssuerURL)
		auds := dedupNonEmpty(s.Audiences)
		if issuer == "" {
			errs = append(errs, ProviderError{name, issuer, errors.New("no issuer_url configured")})
			continue
		}
		if len(auds) == 0 {
			// Fail closed rather than verify every audience: see the file comment.
			errs = append(errs, ProviderError{name, issuer, errors.New(
				"no accepted audience configured (set client_id or audiences); refusing to verify tokens minted for any relying party")})
			continue
		}
		if prev, dup := m.byIssuer[issuer]; dup {
			errs = append(errs, ProviderError{name, issuer, fmt.Errorf(
				"issuer is already served by provider %q", prev.name)})
			continue
		}
		p, err := newProviderWithAudiences(ctx, issuer, auds)
		if err != nil {
			errs = append(errs, ProviderError{name, issuer, err})
			continue
		}
		e := &entry{name: name, provider: p, audiences: auds}
		m.byIssuer[issuer] = e
		m.order = append(m.order, e)
	}
	if len(m.order) == 0 {
		return nil, errs
	}
	return m, errs
}

// newProviderWithAudiences discovers issuer and builds a verifier accepting any of
// auds. With a single audience go-oidc enforces it directly; with several it
// cannot, so the check is performed here after verification — and performed in
// both cases, so a token carrying no `aud` at all can never slip through.
func newProviderWithAudiences(ctx context.Context, issuer string, auds []string) (*OIDCProvider, error) {
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("creating OIDC provider: %w", err)
	}
	cfg := &oidc.Config{}
	if len(auds) == 1 {
		cfg.ClientID = auds[0]
	} else {
		cfg.SkipClientIDCheck = true
	}
	return &OIDCProvider{
		provider:  provider,
		verifier:  provider.Verifier(cfg),
		issuerURL: issuer,
		clientID:  auds[0],
	}, nil
}

// Providers returns the configured providers in declaration order.
func (m *MultiProvider) Providers() []ProviderInfo {
	if m == nil {
		return nil
	}
	out := make([]ProviderInfo, 0, len(m.order))
	for _, e := range m.order {
		out = append(out, ProviderInfo{
			Name:      e.name,
			IssuerURL: e.provider.IssuerURL(),
			Audiences: append([]string(nil), e.audiences...),
		})
	}
	return out
}

// ProviderInfo describes one configured machine-token issuer for discovery
// endpoints and diagnostics. It carries no secret: an issuer and the audiences it
// may mint for are public facts a client needs in order to request a usable token.
type ProviderInfo struct {
	Name      string   `json:"name"`
	IssuerURL string   `json:"issuer_url"`
	Audiences []string `json:"audiences,omitempty"`
}

// Primary returns the first configured provider, or nil when there is none. It
// exists so the single-issuer fields of the public auth-discovery document keep
// reporting something meaningful in the common one-provider deployment.
func (m *MultiProvider) Primary() *OIDCProvider {
	if m == nil || len(m.order) == 0 {
		return nil
	}
	return m.order[0].provider
}

// Lookup returns the provider serving issuer, or nil.
func (m *MultiProvider) Lookup(issuer string) *OIDCProvider {
	if m == nil {
		return nil
	}
	if e := m.byIssuer[strings.TrimSpace(issuer)]; e != nil {
		return e.provider
	}
	return nil
}

// VerifyToken routes rawToken to the provider serving its issuer and verifies it
// there, then enforces that provider's accepted audiences. The returned claims
// name the provider that vouched for them.
func (m *MultiProvider) VerifyToken(ctx context.Context, rawToken string) (*Claims, error) {
	if m == nil || len(m.order) == 0 {
		return nil, errors.New("no OIDC provider configured")
	}
	issuer, err := unverifiedIssuer(rawToken)
	if err != nil {
		return nil, err
	}
	e := m.byIssuer[issuer]
	if e == nil {
		// Naming the issuer is safe (it is the caller's own, unverified assertion)
		// and is the single most useful detail for diagnosing a misdirected client.
		return nil, fmt.Errorf("%w: %q", ErrUnknownIssuer, issuer)
	}
	claims, err := e.provider.VerifyToken(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("provider %q: %w", e.name, err)
	}
	if !audienceAccepted(claims.Audience, e.audiences) {
		return nil, fmt.Errorf("provider %q: token audience %v is not accepted (want one of %v)",
			e.name, claims.Audience, e.audiences)
	}
	claims.Provider = e.name
	return claims, nil
}

// unverifiedIssuer extracts the `iss` claim from a JWT without verifying it. The
// value is used ONLY to select which verifier gets the token; that verifier then
// checks the issuer cryptographically, so a forged value cannot grant anything.
func unverifiedIssuer(rawToken string) (string, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return "", errors.New("malformed bearer token: not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("malformed bearer token: %w", err)
	}
	var c struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("malformed bearer token claims: %w", err)
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return "", errors.New("bearer token carries no iss claim")
	}
	return strings.TrimSpace(c.Issuer), nil
}

// audienceAccepted reports whether the token's audience list intersects the
// provider's accepted audiences. An empty token audience never matches.
func audienceAccepted(tokenAud, accepted []string) bool {
	for _, a := range tokenAud {
		for _, want := range accepted {
			if a == want {
				return true
			}
		}
	}
	return false
}

func dedupNonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
