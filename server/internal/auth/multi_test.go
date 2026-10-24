// Hermetic tests for multi-issuer Bearer verification (multi.go, Task 212).
//
// Federating several identity providers onto one API moves a trust boundary: a
// token is no longer "valid or not" but "valid for which provider". The failure
// mode this guards against is provider confusion — a token minted by a low-trust
// issuer being accepted as, and authorized as, one from a high-trust issuer. The
// tests therefore assert both halves of the routing contract: a token reaches the
// verifier that serves its issuer, and it reaches no other.
//
// Two in-process fake IdPs (the harness from oidc_test.go) stand in for the
// real-world pairing this exists for: a CI forge's workload-identity issuer for
// automated signing, and a corporate IdP for everything else.
package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const (
	ciAudience   = "secsy-pki-signing"
	corpAudience = "api://secsy-pki"
)

// twoProviders brings up two fake IdPs and a verifier over both.
func twoProviders(t *testing.T) (ci, corp *fakeIDP, m *MultiProvider) {
	t.Helper()
	ci, corp = newFakeIDP(t), newFakeIDP(t)
	m, errs := NewMultiProvider(context.Background(), []ProviderSpec{
		{Name: "github", IssuerURL: ci.issuer, Audiences: []string{ciAudience}},
		{Name: "entra", IssuerURL: corp.issuer, Audiences: []string{corpAudience}},
	})
	if len(errs) != 0 {
		t.Fatalf("NewMultiProvider: %v", errs)
	}
	if m == nil {
		t.Fatal("NewMultiProvider returned no verifier")
	}
	return ci, corp, m
}

// TestMultiProviderRoutesByIssuer is the core property: each IdP's token verifies,
// and the claims name the provider that vouched for it — which is what lets
// authorization be per-provider.
func TestMultiProviderRoutesByIssuer(t *testing.T) {
	ci, corp, m := twoProviders(t)

	for _, tc := range []struct {
		idp      *fakeIDP
		aud      string
		wantName string
	}{
		{ci, ciAudience, "github"},
		{corp, corpAudience, "entra"},
	} {
		claims, err := m.VerifyToken(context.Background(), tc.idp.mint(t, tc.idp.baseClaims(tc.aud)))
		if err != nil {
			t.Fatalf("VerifyToken(%s): %v", tc.wantName, err)
		}
		if claims.Provider != tc.wantName {
			t.Errorf("Provider = %q, want %q", claims.Provider, tc.wantName)
		}
		if claims.Issuer != tc.idp.issuer {
			t.Errorf("Issuer = %q, want %q", claims.Issuer, tc.idp.issuer)
		}
		if len(claims.Audience) != 1 || claims.Audience[0] != tc.aud {
			t.Errorf("Audience = %v, want [%s]", claims.Audience, tc.aud)
		}
		if claims.Subject != "operator-123" {
			t.Errorf("Subject = %q, want operator-123", claims.Subject)
		}
	}
}

// TestMultiProviderRejectsCrossProviderAudience is the provider-confusion test: a
// token the CI issuer legitimately minted, but for the *corporate* audience, must
// not authenticate. Without the audience binding, a token obtained for any other
// relying party of the same IdP would work here.
func TestMultiProviderRejectsCrossProviderAudience(t *testing.T) {
	ci, _, m := twoProviders(t)

	if _, err := m.VerifyToken(context.Background(), ci.mint(t, ci.baseClaims(corpAudience))); err == nil {
		t.Fatal("a token minted for another provider's audience must be rejected")
	}
}

// TestMultiProviderRejectsUnknownIssuer asserts an issuer no provider serves is
// refused outright rather than being offered to every verifier in turn, and that
// the error is distinguishable from a verification failure.
func TestMultiProviderRejectsUnknownIssuer(t *testing.T) {
	_, _, m := twoProviders(t)
	stranger := newFakeIDP(t)

	_, err := m.VerifyToken(context.Background(), stranger.mint(t, stranger.baseClaims(ciAudience)))
	if err == nil {
		t.Fatal("a token from an unconfigured issuer must be rejected")
	}
	if !errors.Is(err, ErrUnknownIssuer) {
		t.Errorf("error = %v, want ErrUnknownIssuer", err)
	}
	if !strings.Contains(err.Error(), stranger.issuer) {
		t.Errorf("error %q should name the unknown issuer so a misdirected client is diagnosable", err)
	}
}

// TestMultiProviderForgedIssuerCannotRedirectVerification is the reason routing on
// an unverified claim is sound: a token signed by the CI IdP but *claiming* the
// corporate issuer is routed to the corporate verifier, which rejects it because
// the signature is not from its JWKS. Routing cannot be used to pick a lenient
// verifier, only an unhelpful one.
func TestMultiProviderForgedIssuerCannotRedirectVerification(t *testing.T) {
	ci, corp, m := twoProviders(t)

	// Signed by ci's key, but asserting corp's issuer and corp's audience.
	c := ci.baseClaims(corpAudience)
	c["iss"] = corp.issuer
	if _, err := m.VerifyToken(context.Background(), ci.mint(t, c)); err == nil {
		t.Fatal("a token claiming another issuer must fail that issuer's signature check")
	}

	// And the reverse: corp's key cannot mint a token that passes as ci's.
	c = corp.baseClaims(ciAudience)
	c["iss"] = ci.issuer
	if _, err := m.VerifyToken(context.Background(), corp.mint(t, c)); err == nil {
		t.Fatal("a cross-signed token must not verify at the issuer it names")
	}
}

// TestMultiProviderMultipleAudiences covers the several-audiences form, where
// go-oidc's own single-audience check cannot be used and the intersection is
// enforced here. Any configured audience is accepted; one that is not configured
// is not — and a token with no audience at all never is, which is the case the
// hand-rolled check exists to catch.
func TestMultiProviderMultipleAudiences(t *testing.T) {
	idp := newFakeIDP(t)
	m, errs := NewMultiProvider(context.Background(), []ProviderSpec{
		{Name: "forge", IssuerURL: idp.issuer, Audiences: []string{"aud-a", "aud-b"}},
	})
	if len(errs) != 0 || m == nil {
		t.Fatalf("NewMultiProvider: %v", errs)
	}

	for _, aud := range []string{"aud-a", "aud-b"} {
		if _, err := m.VerifyToken(context.Background(), idp.mint(t, idp.baseClaims(aud))); err != nil {
			t.Errorf("VerifyToken(aud=%s): %v", aud, err)
		}
	}
	if _, err := m.VerifyToken(context.Background(), idp.mint(t, idp.baseClaims("aud-c"))); err == nil {
		t.Error("an unconfigured audience must be rejected")
	}

	// A multi-value aud claim is accepted when it intersects the configured set.
	c := idp.baseClaims("")
	c["aud"] = []string{"someone-else", "aud-b"}
	if _, err := m.VerifyToken(context.Background(), idp.mint(t, c)); err != nil {
		t.Errorf("a token whose audience list includes a configured audience must verify: %v", err)
	}

	// No audience at all: go-oidc is in SkipClientIDCheck mode here, so this is
	// exactly the token the local intersection check has to stop.
	c = idp.baseClaims("")
	delete(c, "aud")
	if _, err := m.VerifyToken(context.Background(), idp.mint(t, c)); err == nil {
		t.Error("a token carrying no audience must be rejected")
	}
}

// TestNewMultiProviderRejectsAudiencelessProvider asserts the fail-closed
// construction rule: a provider that accepts any audience is refused rather than
// brought up, because it would honor tokens the IdP minted for other services.
func TestNewMultiProviderRejectsAudiencelessProvider(t *testing.T) {
	idp := newFakeIDP(t)
	m, errs := NewMultiProvider(context.Background(), []ProviderSpec{
		{Name: "no-aud", IssuerURL: idp.issuer},
	})
	if m != nil {
		t.Error("a provider with no accepted audience must not be brought up")
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "audience") {
		t.Fatalf("errors = %v, want one audience complaint", errs)
	}
	if errs[0].Name != "no-aud" {
		t.Errorf("ProviderError.Name = %q, want no-aud", errs[0].Name)
	}
}

// TestNewMultiProviderPartialFailure asserts an unreachable IdP is reported but
// does not take the working providers down with it — the behavior that keeps one
// IdP outage from being a server outage.
func TestNewMultiProviderPartialFailure(t *testing.T) {
	good := newFakeIDP(t)
	m, errs := NewMultiProvider(context.Background(), []ProviderSpec{
		{Name: "down", IssuerURL: "http://127.0.0.1:1/not-an-idp", Audiences: []string{"x"}},
		{Name: "up", IssuerURL: good.issuer, Audiences: []string{ciAudience}},
	})
	if len(errs) != 1 || errs[0].Name != "down" {
		t.Fatalf("errors = %v, want exactly the unreachable provider", errs)
	}
	if m == nil {
		t.Fatal("the reachable provider must still be usable")
	}
	if got := m.Providers(); len(got) != 1 || got[0].Name != "up" {
		t.Fatalf("Providers() = %+v, want only \"up\"", got)
	}
	if _, err := m.VerifyToken(context.Background(), good.mint(t, good.baseClaims(ciAudience))); err != nil {
		t.Errorf("VerifyToken through the surviving provider: %v", err)
	}
}

// TestNewMultiProviderRejectsDuplicateIssuer asserts one issuer cannot be served
// by two providers: routing is by issuer, so a duplicate would make which
// provider's audience set and role mapping applies depend on declaration order.
func TestNewMultiProviderRejectsDuplicateIssuer(t *testing.T) {
	idp := newFakeIDP(t)
	m, errs := NewMultiProvider(context.Background(), []ProviderSpec{
		{Name: "first", IssuerURL: idp.issuer, Audiences: []string{"a"}},
		{Name: "second", IssuerURL: idp.issuer, Audiences: []string{"b"}},
	})
	if m == nil || len(m.Providers()) != 1 {
		t.Fatalf("the first declaration should survive alone, got %+v", m.Providers())
	}
	if len(errs) != 1 || errs[0].Name != "second" || !strings.Contains(errs[0].Error(), "already served") {
		t.Fatalf("errors = %v, want the second declaration rejected", errs)
	}
	// Confirm the surviving provider is the first one, by its audience.
	if _, err := m.VerifyToken(context.Background(), idp.mint(t, idp.baseClaims("b"))); err == nil {
		t.Error("the rejected provider's audience must not be accepted")
	}
}

// TestMultiProviderMalformedTokens asserts the routing pre-parse fails closed on
// anything that is not a JWT carrying an issuer, rather than panicking or falling
// through to a provider.
func TestMultiProviderMalformedTokens(t *testing.T) {
	_, _, m := twoProviders(t)

	for name, token := range map[string]string{
		"empty":         "",
		"not a jwt":     "secsy_pat_deadbeef",
		"two segments":  "aaaa.bbbb",
		"bad base64":    "aaaa.!!!!.cccc",
		"not json":      "aaaa." + encodeSegment([]byte("not json")) + ".cccc",
		"no iss":        "aaaa." + encodeSegment([]byte(`{"sub":"x"}`)) + ".cccc",
		"empty iss":     "aaaa." + encodeSegment([]byte(`{"iss":"  "}`)) + ".cccc",
		"iss not a str": "aaaa." + encodeSegment([]byte(`{"iss":42}`)) + ".cccc",
	} {
		if _, err := m.VerifyToken(context.Background(), token); err == nil {
			t.Errorf("VerifyToken(%s) succeeded, want an error", name)
		}
	}
}

// TestMultiProviderNilAndEmpty asserts the zero cases are inert: a deployment
// with no OIDC configured must get a nil verifier (so the middleware installs a
// nil interface), and calling through nothing must error rather than panic.
func TestMultiProviderNilAndEmpty(t *testing.T) {
	m, errs := NewMultiProvider(context.Background(), nil)
	if m != nil || len(errs) != 0 {
		t.Fatalf("NewMultiProvider(nil) = (%v, %v), want (nil, no errors)", m, errs)
	}

	var nilProvider *MultiProvider
	if _, err := nilProvider.VerifyToken(context.Background(), "x.y.z"); err == nil {
		t.Error("VerifyToken on a nil provider must error")
	}
	if nilProvider.Primary() != nil || nilProvider.Lookup("https://idp") != nil || nilProvider.Providers() != nil {
		t.Error("accessors on a nil provider must be inert")
	}
}

// TestMultiProviderPrimaryAndLookup covers the accessors the public auth-discovery
// document and the console-login wiring depend on.
func TestMultiProviderPrimaryAndLookup(t *testing.T) {
	ci, corp, m := twoProviders(t)

	if got := m.Primary(); got == nil || got.IssuerURL() != ci.issuer {
		t.Errorf("Primary() issuer = %v, want the first declared provider %q", got, ci.issuer)
	}
	if got := m.Lookup(corp.issuer); got == nil || got.IssuerURL() != corp.issuer {
		t.Errorf("Lookup(%q) did not find the second provider", corp.issuer)
	}
	if m.Lookup("https://unconfigured.example.com") != nil {
		t.Error("Lookup of an unconfigured issuer must be nil")
	}
	infos := m.Providers()
	if len(infos) != 2 || infos[0].Name != "github" || infos[1].Name != "entra" {
		t.Fatalf("Providers() = %+v, want declaration order", infos)
	}
	if len(infos[0].Audiences) != 1 || infos[0].Audiences[0] != ciAudience {
		t.Errorf("Providers()[0].Audiences = %v, want [%s]", infos[0].Audiences, ciAudience)
	}
}

// TestMultiProviderCarriesRawClaims asserts the full claim set reaches the caller:
// the per-provider claim -> role mapping is driven off arbitrary claims (groups,
// roles, a forge's repository fields), which the typed Claims struct cannot name.
func TestMultiProviderCarriesRawClaims(t *testing.T) {
	ci, _, m := twoProviders(t)

	c := ci.baseClaims(ciAudience)
	c["groups"] = []string{"pki-signers", "everyone"}
	c["repository_owner"] = "example-org"

	claims, err := m.VerifyToken(context.Background(), ci.mint(t, c))
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.Raw == nil {
		t.Fatal("Raw claims must be populated for the claim -> role mapper")
	}
	if got, _ := claims.Raw["repository_owner"].(string); got != "example-org" {
		t.Errorf("Raw[repository_owner] = %q, want example-org", got)
	}
	groups, ok := claims.Raw["groups"].([]interface{})
	if !ok || len(groups) != 2 {
		t.Fatalf("Raw[groups] = %#v, want a 2-element list", claims.Raw["groups"])
	}
}

// TestDedupNonEmpty covers the audience normalizer: blank and repeated entries
// must not survive into the accepted set.
func TestDedupNonEmpty(t *testing.T) {
	got := dedupNonEmpty([]string{" a ", "a", "", "   ", "b", "a"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("dedupNonEmpty = %v, want [a b]", got)
	}
}

// TestNewMultiProviderRejectsIssuerlessProvider covers the remaining
// construction guard: a provider with no issuer cannot be routed to (routing is
// by `iss`), so it is reported rather than silently brought up. It also pins the
// fallback name used when a spec carries none, which is what the error message
// has to say to be actionable.
func TestNewMultiProviderRejectsIssuerlessProvider(t *testing.T) {
	m, errs := NewMultiProvider(context.Background(), []ProviderSpec{
		{Name: "", Audiences: []string{"a"}},
	})
	if m != nil {
		t.Error("a provider with no issuer must not be brought up")
	}
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "no issuer_url configured") {
		t.Fatalf("errors = %v, want one missing-issuer complaint", errs)
	}
	if errs[0].Name != "default" {
		t.Errorf("ProviderError.Name = %q, want the \"default\" fallback for an unnamed spec", errs[0].Name)
	}
}

// TestProviderErrorWraps asserts a ProviderError stays inspectable with
// errors.Is/As, so a caller can distinguish (say) an unreachable IdP from a
// misconfigured one without string matching.
func TestProviderErrorWraps(t *testing.T) {
	sentinel := errors.New("discovery exploded")
	err := error(ProviderError{Name: "entra", IssuerURL: "https://idp.example.com", Err: sentinel})

	if !errors.Is(err, sentinel) {
		t.Error("ProviderError must unwrap to the underlying cause")
	}
	var pe ProviderError
	if !errors.As(err, &pe) || pe.Name != "entra" {
		t.Errorf("errors.As did not recover the provider: %+v", pe)
	}
	for _, want := range []string{"entra", "https://idp.example.com", "discovery exploded"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q should mention %q", err, want)
		}
	}
}
