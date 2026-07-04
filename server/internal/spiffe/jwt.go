package spiffe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
	"github.com/go-jose/go-jose/v4/jwt"
)

// jwtSVIDType is the JOSE "typ" header carried by a JWT-SVID. The SPIFFE
// JWT-SVID specification permits the typ header to be absent, but requires it to
// be exactly "JWT" or "JOSE" when present; we always set "JWT" for clarity.
const jwtSVIDType = "JWT"

// jwtSVIDLeeway is the default clock-skew tolerance applied when validating a
// JWT-SVID's time claims (exp/nbf), matching the philosophy of the X.509
// clock-skew backdate: a verifier whose clock lags slightly still accepts a
// freshly minted token, and one whose clock leads slightly still rejects an
// expired one within the window.
const jwtSVIDLeeway = time.Minute

// allowedJWTSVIDAlgs is the closed set of JWS signature algorithms a JWT-SVID
// may use. It deliberately excludes the "none" algorithm (which is simply not
// present here, so jwt.ParseSigned rejects it) — the SPIFFE JWT-SVID spec
// forbids unsigned tokens. Passing this allowlist to jwt.ParseSigned is what
// enforces algorithm agility safely: an attacker cannot downgrade the token to
// an unexpected or absent algorithm.
var allowedJWTSVIDAlgs = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512,
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.EdDSA,
}

// KeyID derives the stable JWT-SVID key identifier (kid) for a public key: the
// RFC 7638 JWK SHA-256 thumbprint, base64url-encoded without padding. It is
// computed identically at signing time (from the HSM signer's public key) and
// when the JWKS trust bundle is assembled (from the CA certificate's public
// key), so a token's kid header always matches its verification key in the
// bundle. The thumbprint is a canonical function of the key material alone, so
// the two derivations agree regardless of how each side obtained the key.
func KeyID(pub crypto.PublicKey) (string, error) {
	if pub == nil {
		return "", fmt.Errorf("cannot derive a key id from a nil public key")
	}
	jwk := jose.JSONWebKey{Key: pub}
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("computing JWK thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(thumb), nil
}

// signatureAlgorithm selects the JWS signature algorithm for a signing key,
// following the SPIFFE/JWA conventions: ECDSA is bound to the curve-matched ES*
// family, RSA to RS256, and Ed25519 to EdDSA. It rejects any key type a JWT-SVID
// cannot be signed with.
func signatureAlgorithm(pub crypto.PublicKey) (jose.SignatureAlgorithm, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve for a JWT-SVID: %s", k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		return jose.RS256, nil
	case ed25519.PublicKey:
		return jose.EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported key type for a JWT-SVID: %T", pub)
	}
}

// SignatureAlgorithm returns the JWS "alg" a JWT-SVID signed by the given public
// key's private half will carry (e.g. "ES256"), for diagnostics and API
// responses. It errors for a key type that cannot sign a JWT-SVID.
func SignatureAlgorithm(pub crypto.PublicKey) (string, error) {
	alg, err := signatureAlgorithm(pub)
	if err != nil {
		return "", err
	}
	return string(alg), nil
}

// JWTSVIDParams describes a JWT-SVID to sign. The signer is any crypto.Signer —
// crucially an HSM-backed keyprovider.Signer, whose private key never leaves the
// token — wrapped as an opaque JOSE signer so the signing happens on the device.
type JWTSVIDParams struct {
	// SPIFFEID is the workload identity, carried verbatim in the "sub" claim. It
	// must be a valid spiffe:// URI.
	SPIFFEID string
	// Audience is the intended audience set ("aud"). At least one non-empty value
	// is required by the JWT-SVID spec.
	Audience []string
	// IssuedAt populates "iat"; zero omits it (discouraged).
	IssuedAt time.Time
	// Expiry populates the required "exp" claim.
	Expiry time.Time
	// NotBefore, when non-zero, populates "nbf".
	NotBefore time.Time
	// KeyID overrides the "kid" header. Empty derives it from the signer's public
	// key via KeyID, which is the normal path (it then matches the JWKS bundle).
	KeyID string
}

// SignJWTSVID mints and signs a SPIFFE JWT-SVID. The subject is the spiffe:// ID,
// the audience and expiry are required, and the kid header is the RFC 7638
// thumbprint of the signing key so a relying party can locate the verification
// key in the trust bundle. Signing is delegated to the crypto.Signer (an HSM key
// in production) through go-jose's opaque-signer bridge, so no private key
// material is handled in process.
func SignJWTSVID(signer crypto.Signer, p JWTSVIDParams) (string, error) {
	if signer == nil {
		return "", fmt.Errorf("JWT-SVID signing requires a signer")
	}
	id := strings.TrimSpace(p.SPIFFEID)
	if id == "" {
		return "", fmt.Errorf("JWT-SVID requires a spiffe:// subject")
	}
	if _, err := ParseID(id); err != nil {
		return "", fmt.Errorf("invalid JWT-SVID subject: %w", err)
	}
	auds := normalizeAudience(p.Audience)
	if len(auds) == 0 {
		return "", fmt.Errorf("JWT-SVID requires at least one audience")
	}
	if p.Expiry.IsZero() {
		return "", fmt.Errorf("JWT-SVID requires an expiry")
	}
	alg, err := signatureAlgorithm(signer.Public())
	if err != nil {
		return "", err
	}
	kid := p.KeyID
	if kid == "" {
		if kid, err = KeyID(signer.Public()); err != nil {
			return "", err
		}
	}

	opts := (&jose.SignerOptions{}).
		WithType(jwtSVIDType).
		WithHeader(jose.HeaderKey("kid"), kid)
	joseSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: alg,
		Key:       cryptosigner.Opaque(signer),
	}, opts)
	if err != nil {
		return "", fmt.Errorf("constructing JWT-SVID signer: %w", err)
	}

	claims := jwt.Claims{
		Subject:  id,
		Audience: jwt.Audience(auds),
		Expiry:   jwt.NewNumericDate(p.Expiry),
	}
	if !p.IssuedAt.IsZero() {
		claims.IssuedAt = jwt.NewNumericDate(p.IssuedAt)
	}
	if !p.NotBefore.IsZero() {
		claims.NotBefore = jwt.NewNumericDate(p.NotBefore)
	}
	token, err := jwt.Signed(joseSigner).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("signing JWT-SVID: %w", err)
	}
	return token, nil
}

// JWTValidationOptions parameterizes JWT-SVID validation.
type JWTValidationOptions struct {
	// Audience, when non-empty, must appear in the token's "aud" set; this is the
	// relying party's own identity. The SPIFFE spec requires a JWT-SVID to be
	// rejected unless the validator's audience is present.
	Audience string
	// TrustDomains, when non-empty, is the allowlist the token's trust domain (the
	// authority of its "sub") must belong to. Empty accepts any syntactically
	// valid SPIFFE trust domain (the caller has opted out of allowlisting).
	TrustDomains []string
	// Now overrides the validation clock (zero uses time.Now); tests inject it.
	Now time.Time
	// Leeway overrides the clock-skew tolerance for exp/nbf (<=0 uses the default).
	Leeway time.Duration
}

// JWTSVIDValidationResult is the verified content of a JWT-SVID.
type JWTSVIDValidationResult struct {
	SPIFFEID    string
	TrustDomain string
	Path        string
	Audience    []string
	KeyID       string
	Algorithm   string
	IssuedAt    time.Time
	Expiry      time.Time
}

// ValidateJWTSVID verifies a compact JWT-SVID against a SPIFFE JWKS trust bundle
// and the supplied policy. It performs, in order and fail-closed:
//
//  1. structural parse restricted to the allowed signature algorithms (never
//     "none"),
//  2. lookup of the header kid among the bundle's jwt-svid keys,
//  3. cryptographic signature verification against that key,
//  4. validation that the subject is a well-formed SPIFFE ID whose trust domain
//     is on the allowlist (the same allowlist that gates issuance),
//  5. validation that the required audience claim is present and, if the relying
//     party named one, contains it, and that the token is unexpired / already
//     valid (exp/nbf within leeway).
//
// Any failure returns a descriptive error and a nil result.
func ValidateJWTSVID(token string, jwks []byte, opts JWTValidationOptions) (*JWTSVIDValidationResult, error) {
	keys, err := ParseJWTBundleKeys(jwks)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT trust bundle: %w", err)
	}

	parsed, err := jwt.ParseSigned(strings.TrimSpace(token), allowedJWTSVIDAlgs)
	if err != nil {
		return nil, fmt.Errorf("parsing JWT-SVID: %w", err)
	}
	if len(parsed.Headers) == 0 {
		return nil, fmt.Errorf("JWT-SVID has no protected header")
	}
	hdr := parsed.Headers[0]
	if hdr.KeyID == "" {
		return nil, fmt.Errorf("JWT-SVID header is missing the key id (kid)")
	}
	pub, ok := keys[hdr.KeyID]
	if !ok {
		return nil, fmt.Errorf("JWT-SVID is signed by an unknown key %q (not in the trust bundle)", hdr.KeyID)
	}

	var claims jwt.Claims
	if err := parsed.Claims(pub, &claims); err != nil {
		return nil, fmt.Errorf("JWT-SVID signature verification failed: %w", err)
	}

	sub, err := ParseID(claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("JWT-SVID subject %q is not a valid SPIFFE ID: %w", claims.Subject, err)
	}
	if len(opts.TrustDomains) > 0 && !trustDomainAllowed(opts.TrustDomains, sub.TrustDomain()) {
		return nil, fmt.Errorf("JWT-SVID trust domain %q is not permitted", sub.TrustDomain())
	}
	if len(claims.Audience) == 0 {
		return nil, fmt.Errorf("JWT-SVID is missing the required audience (aud) claim")
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	leeway := opts.Leeway
	if leeway <= 0 {
		leeway = jwtSVIDLeeway
	}
	expected := jwt.Expected{Time: now}
	if opts.Audience != "" {
		expected.AnyAudience = jwt.Audience{opts.Audience}
	}
	if err := claims.ValidateWithLeeway(expected, leeway); err != nil {
		return nil, fmt.Errorf("JWT-SVID claim validation failed: %w", err)
	}

	res := &JWTSVIDValidationResult{
		SPIFFEID:    sub.String(),
		TrustDomain: sub.TrustDomain(),
		Path:        sub.Path(),
		Audience:    []string(claims.Audience),
		KeyID:       hdr.KeyID,
		Algorithm:   hdr.Algorithm,
	}
	if claims.IssuedAt != nil {
		res.IssuedAt = claims.IssuedAt.Time()
	}
	if claims.Expiry != nil {
		res.Expiry = claims.Expiry.Time()
	}
	return res, nil
}

// normalizeAudience trims, drops empties, and de-duplicates an audience list
// while preserving first-seen order.
func normalizeAudience(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, a := range in {
		a = strings.TrimSpace(a)
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

// trustDomainAllowed reports whether td is present in the allowlist, comparing
// case-insensitively (trust domains are lowercase-canonical).
func trustDomainAllowed(allowlist []string, td string) bool {
	for _, a := range allowlist {
		if strings.EqualFold(strings.TrimSpace(a), td) {
			return true
		}
	}
	return false
}
