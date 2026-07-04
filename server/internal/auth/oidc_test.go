// Hermetic unit tests for the OIDC operator-authentication trust boundary
// (oidc.go). ID-token verification is security-critical: it is the point at
// which a bearer token minted by the identity provider is trusted to name an
// operator principal. A verification bug here (accepting a forged signature, an
// expired token, or a token minted for a different audience/issuer) would let an
// attacker impersonate an operator, so every failure mode is covered.
//
// The tests stand up an in-process fake OpenID Connect issuer: an httptest
// server serving discovery (/.well-known/openid-configuration) and a JWKS, plus
// a locally-held RSA key used to sign ID tokens. No HSM and no network are
// required, so these run under a plain `go test ./internal/auth/...`.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	jose "github.com/go-jose/go-jose/v4"
)

const testClientID = "secsy-api"

// fakeIDP is an in-process OpenID Connect issuer for hermetic tests. It serves
// discovery and a JWKS advertising a single RSA signing key ("k1"), and mints
// ID tokens signed with the locally-held private key.
type fakeIDP struct {
	srv    *httptest.Server
	issuer string
	priv   *rsa.PrivateKey
	signer jose.Signer
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	priv := testRSAKey(t)
	idp := &fakeIDP{priv: priv, signer: newRSASigner(t, priv, "k1")}

	mux := http.NewServeMux()
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	idp.issuer = idp.srv.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                idp.issuer,
			"authorization_endpoint":                idp.issuer + "/authorize",
			"token_endpoint":                        idp.issuer + "/token",
			"jwks_uri":                              idp.issuer + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: priv.Public(), KeyID: "k1", Algorithm: "RS256", Use: "sig",
		}}})
	})
	return idp
}

// baseClaims returns a fully valid ID-token claim set aimed at aud, which
// individual tests mutate to exercise a single defect at a time.
func (f *fakeIDP) baseClaims(aud string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":            f.issuer,
		"aud":            aud,
		"sub":            "operator-123",
		"exp":            now.Add(time.Hour).Unix(),
		"iat":            now.Add(-time.Minute).Unix(),
		"email":          "op@example.com",
		"email_verified": true,
		"name":           "Op Erator",
	}
}

// mint signs claims with the IdP's published key (kid "k1").
func (f *fakeIDP) mint(t *testing.T, claims map[string]any) string {
	return signClaims(t, f.signer, claims)
}

func TestVerifyTokenSuccess(t *testing.T) {
	idp := newFakeIDP(t)
	op, err := NewOIDCProvider(idp.issuer, testClientID)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	raw := idp.mint(t, idp.baseClaims(testClientID))
	claims, err := op.VerifyToken(context.Background(), raw)
	if err != nil {
		t.Fatalf("VerifyToken on a valid token: %v", err)
	}
	if claims.Subject != "operator-123" {
		t.Errorf("Subject = %q, want operator-123", claims.Subject)
	}
	if claims.Email != "op@example.com" {
		t.Errorf("Email = %q, want op@example.com", claims.Email)
	}
	if !claims.EmailVerified {
		t.Errorf("EmailVerified = false, want true")
	}
	if claims.Name != "Op Erator" {
		t.Errorf("Name = %q, want Op Erator", claims.Name)
	}
}

// TestVerifyTokenEmailVerifiedFalse confirms the unverified-email signal is
// carried through faithfully — the RBAC layer refuses to honor email-keyed role
// assignments when this is false, so it must not silently default to true.
func TestVerifyTokenEmailVerifiedFalse(t *testing.T) {
	idp := newFakeIDP(t)
	op, err := NewOIDCProvider(idp.issuer, testClientID)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	c := idp.baseClaims(testClientID)
	c["email_verified"] = false
	claims, err := op.VerifyToken(context.Background(), idp.mint(t, c))
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.EmailVerified {
		t.Errorf("EmailVerified = true, want false")
	}
}

// TestVerifyTokenMalformedClaimType ensures a signature-valid token whose claim
// has an unexpected JSON type (here, a numeric "email" where a string is
// expected) is rejected during claim extraction rather than panicking or
// silently yielding a zero-valued principal. go-oidc verifies the registered
// claims and signature but does not type-check application claims, so this
// exercises VerifyToken's own claim-parsing guard.
func TestVerifyTokenMalformedClaimType(t *testing.T) {
	idp := newFakeIDP(t)
	op, err := NewOIDCProvider(idp.issuer, testClientID)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	c := idp.baseClaims(testClientID)
	c["email"] = 12345 // not a string
	claims, err := op.VerifyToken(context.Background(), idp.mint(t, c))
	if err == nil {
		t.Fatalf("VerifyToken accepted a token with a malformed email claim; claims=%+v", claims)
	}
	if claims != nil {
		t.Errorf("claims = %+v, want nil on parse failure", claims)
	}
	if !strings.Contains(err.Error(), "parsing claims") {
		t.Errorf("error %q is not the claim-parsing guard", err)
	}
}

// TestVerifyTokenRejects covers the security-relevant failure modes: a token
// must be rejected unless it is signed by the issuer's advertised key, not
// expired, minted for this audience, and issued by the discovered issuer.
func TestVerifyTokenRejects(t *testing.T) {
	idp := newFakeIDP(t)
	op, err := NewOIDCProvider(idp.issuer, testClientID)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	// A key the IdP never published: tokens it signs must not verify.
	foreign := testRSAKey(t)
	foreignSigner := newRSASigner(t, foreign, "k1") // reuse the published kid → the
	// verifier selects the genuine k1 public key and the signature check fails.

	now := time.Now()

	cases := []struct {
		name  string
		token string
	}{
		{
			name: "forged signature (foreign signing key)",
			// Otherwise-perfect claims, signed by a key absent from the JWKS.
			token: signClaims(t, foreignSigner, idp.baseClaims(testClientID)),
		},
		{
			name: "tampered payload",
			token: func() string {
				// Flip the subject in the payload of a validly-signed token; the
				// signature no longer covers the altered bytes.
				valid := idp.mint(t, idp.baseClaims(testClientID))
				return tamperSubject(t, valid, "attacker")
			}(),
		},
		{
			name: "expired token",
			token: idp.mint(t, mutate(idp.baseClaims(testClientID), func(c map[string]any) {
				c["exp"] = now.Add(-time.Minute).Unix()
			})),
		},
		{
			name: "wrong audience",
			token: idp.mint(t, mutate(idp.baseClaims(testClientID), func(c map[string]any) {
				c["aud"] = "some-other-client"
			})),
		},
		{
			name: "wrong issuer",
			token: idp.mint(t, mutate(idp.baseClaims(testClientID), func(c map[string]any) {
				c["iss"] = "https://evil.example.com"
			})),
		},
		// --- missing / empty required claims ---
		{
			name: "missing audience claim",
			token: idp.mint(t, mutate(idp.baseClaims(testClientID), func(c map[string]any) {
				delete(c, "aud")
			})),
		},
		{
			name: "missing expiry claim",
			token: idp.mint(t, mutate(idp.baseClaims(testClientID), func(c map[string]any) {
				delete(c, "exp")
			})),
		},
		{
			name: "missing issuer claim",
			token: idp.mint(t, mutate(idp.baseClaims(testClientID), func(c map[string]any) {
				delete(c, "iss")
			})),
		},
		{
			name:  "not a JWT",
			token: "this.is.not-a-valid-jwt",
		},
		{
			name:  "empty token",
			token: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := op.VerifyToken(context.Background(), tc.token)
			if err == nil {
				t.Fatalf("VerifyToken accepted an invalid token (%s); claims=%+v", tc.name, claims)
			}
			if claims != nil {
				t.Errorf("VerifyToken returned claims %+v alongside an error; must be nil on failure", claims)
			}
			// The error must originate from this package's verification wrapper.
			if !strings.Contains(err.Error(), "verifying token") {
				t.Errorf("error %q not wrapped by VerifyToken", err)
			}
		})
	}
}

// TestVerifierForClientAudienceIsolation proves a token minted for one client id
// is rejected by a verifier bound to a different client id — the interactive
// console login and the API bearer path may use distinct audiences, and one
// must not accept the other's tokens.
func TestVerifierForClientAudienceIsolation(t *testing.T) {
	idp := newFakeIDP(t)
	op, err := NewOIDCProvider(idp.issuer, testClientID)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	consoleToken := idp.mint(t, idp.baseClaims("secsy-console"))

	// The API-audience verifier (testClientID) must reject the console token.
	if _, err := op.VerifyToken(context.Background(), consoleToken); err == nil {
		t.Errorf("API verifier accepted a token minted for the console audience")
	}
	// A verifier bound to the console client id must accept it.
	consoleVerifier := op.VerifierForClient("secsy-console")
	if _, err := consoleVerifier.Verify(context.Background(), consoleToken); err != nil {
		t.Errorf("console verifier rejected its own audience: %v", err)
	}
}

// TestNewOIDCProviderDiscoveryFailure ensures construction fails closed when the
// issuer does not serve a valid discovery document, rather than yielding a
// provider that silently verifies nothing.
func TestNewOIDCProviderDiscoveryFailure(t *testing.T) {
	// A server that 404s the discovery endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	if _, err := NewOIDCProvider(srv.URL, testClientID); err == nil {
		t.Fatalf("NewOIDCProvider succeeded against an issuer with no discovery document")
	}
}

// TestOIDCProviderAccessors covers the small accessors used by the login wiring.
func TestOIDCProviderAccessors(t *testing.T) {
	idp := newFakeIDP(t)
	op, err := NewOIDCProvider(idp.issuer, testClientID)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}
	if op.IssuerURL() != idp.issuer {
		t.Errorf("IssuerURL() = %q, want %q", op.IssuerURL(), idp.issuer)
	}
	if op.ClientID() != testClientID {
		t.Errorf("ClientID() = %q, want %q", op.ClientID(), testClientID)
	}
	if op.Provider() == nil {
		t.Errorf("Provider() = nil, want the discovered provider")
	}
	if op.VerifierForClient("x") == nil {
		t.Errorf("VerifierForClient returned nil")
	}
}

// TestClaimToRoleMappingWiredThroughAuthn exercises the full operator-login
// trust chain at the unit level: a token verified by internal/auth surfaces its
// claims, and internal/authn's ClaimMapper (the configurable IdP-group -> RBAC
// bridge) turns them into roles. It also asserts the fail-closed behavior a
// deployment relies on: a verified identity carrying no role-granting group is
// denied when zero-role logins are forbidden.
func TestClaimToRoleMappingWiredThroughAuthn(t *testing.T) {
	idp := newFakeIDP(t)
	op, err := NewOIDCProvider(idp.issuer, testClientID)
	if err != nil {
		t.Fatalf("NewOIDCProvider: %v", err)
	}

	// The claim->role config: IdP group "pki-admins" grants the admin role.
	mapper := authn.NewClaimMapper("groups", []authn.ClaimMapping{
		{Value: "pki-admins", Roles: []rbac.Role{rbac.RoleAdmin}},
		{Value: "acme-issuers", Tenant: "acme", Roles: []rbac.Role{rbac.RoleIssuer}},
	})

	// resolve mirrors buildPrincipalResolver's fail-closed rule: no platform or
	// tenant role, and zero-role logins forbidden, denies the login.
	resolve := func(claims map[string]any) ([]rbac.Role, map[string][]rbac.Role, error) {
		platform, tenant := mapper.Resolve(claims)
		if len(platform) == 0 && len(tenant) == 0 {
			return nil, nil, errNoRole
		}
		return platform, tenant, nil
	}

	// verifiedClaims runs a minted token through the real verifier and returns
	// the raw claim map, exactly as the login callback does before mapping.
	verifiedClaims := func(t *testing.T, tokenClaims map[string]any) map[string]any {
		t.Helper()
		verifier := op.VerifierForClient(testClientID)
		idToken, err := verifier.Verify(context.Background(), idp.mint(t, tokenClaims))
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		var claims map[string]any
		if err := idToken.Claims(&claims); err != nil {
			t.Fatalf("extract claims: %v", err)
		}
		return claims
	}

	t.Run("group claim maps to platform role", func(t *testing.T) {
		c := idp.baseClaims(testClientID)
		c["groups"] = []string{"pki-admins"}
		platform, tenant, err := resolve(verifiedClaims(t, c))
		if err != nil {
			t.Fatalf("resolve denied a mapped operator: %v", err)
		}
		if len(platform) != 1 || platform[0] != rbac.RoleAdmin {
			t.Errorf("platform roles = %v, want [admin]", platform)
		}
		if len(tenant) != 0 {
			t.Errorf("unexpected tenant roles: %v", tenant)
		}
	})

	t.Run("group claim maps to tenant-scoped role", func(t *testing.T) {
		c := idp.baseClaims(testClientID)
		c["groups"] = []string{"acme-issuers"}
		platform, tenant, err := resolve(verifiedClaims(t, c))
		if err != nil {
			t.Fatalf("resolve denied a mapped operator: %v", err)
		}
		if len(platform) != 0 {
			t.Errorf("unexpected platform roles: %v", platform)
		}
		if got := tenant["acme"]; len(got) != 1 || got[0] != rbac.RoleIssuer {
			t.Errorf("tenant roles = %v, want issuer in acme", tenant)
		}
	})

	// Fail-closed: a verified identity whose required role-granting claim is
	// absent or empty is denied when zero-role logins are forbidden.
	for _, tc := range []struct {
		name   string
		groups any
	}{
		{"missing groups claim", nil},
		{"empty groups list", []string{}},
		{"unrelated group only", []string{"finance"}},
	} {
		t.Run("denied: "+tc.name, func(t *testing.T) {
			c := idp.baseClaims(testClientID)
			if tc.groups != nil {
				c["groups"] = tc.groups
			}
			if _, _, err := resolve(verifiedClaims(t, c)); err == nil {
				t.Fatalf("resolve accepted an operator with no mapped role (%s)", tc.name)
			}
		})
	}
}

// --- test helpers ---

var errNoRole = &roleError{"no RBAC role is assigned to this account"}

type roleError struct{ s string }

func (e *roleError) Error() string { return e.s }

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	return k
}

func newRSASigner(t *testing.T, key *rsa.PrivateKey, kid string) jose.Signer {
	t.Helper()
	s, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("jose signer: %v", err)
	}
	return s
}

func signClaims(t *testing.T, signer jose.Signer, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	compact, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return compact
}

// mutate applies f to a copy-in-place of claims and returns it, so table entries
// can express a single defect inline.
func mutate(claims map[string]any, f func(map[string]any)) map[string]any {
	f(claims)
	return claims
}

// tamperSubject rewrites the "sub" claim in the (base64url) payload segment of a
// compact JWS without re-signing, producing a token whose signature no longer
// matches its contents.
func tamperSubject(t *testing.T, token, newSub string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a 3-part compact JWS, got %d parts", len(parts))
	}
	payload := decodeSegment(t, parts[1])
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	claims["sub"] = newSub
	reencoded, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal tampered payload: %v", err)
	}
	parts[1] = encodeSegment(reencoded)
	return strings.Join(parts, ".")
}

// writeJSON serializes v as a JSON response body. Encoding a plain map/struct
// does not fail in practice; the error is ignored to match the surrounding test
// IdP handlers, which run in the httptest server's own goroutine.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// decodeSegment / encodeSegment handle the base64url-without-padding encoding
// used for the three segments of a compact JWS.
func decodeSegment(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("decode JWS segment: %v", err)
	}
	return b
}

func encodeSegment(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
