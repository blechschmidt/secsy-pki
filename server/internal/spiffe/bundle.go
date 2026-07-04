package spiffe

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// x509SVIDUse is the JWK "use" value that marks an X.509 authority (a CA
// certificate that anchors X.509-SVIDs) in a SPIFFE trust bundle.
const x509SVIDUse = "x509-svid"

// jwtSVIDUse is the JWK "use" value that marks a JWT-SVID signing/verification
// key in a SPIFFE trust bundle. Unlike an x509-svid entry (a full certificate in
// x5c), a jwt-svid entry is a bare public key with a "kid" a token's header
// references.
const jwtSVIDUse = "jwt-svid"

// Bundle is the JSON encoding of a SPIFFE trust bundle in the JWKS-style format
// defined by the SPIFFE Trust Domain and Bundle specification and emitted by
// SPIRE. Each X.509 trust anchor is a JWK carrying the certificate in "x5c" and
// "use":"x509-svid"; go-spiffe and SPIRE clients consume this directly.
//
// The optional top-level members give consumers cache guidance:
//
//   - spiffe_refresh_hint: seconds a consumer should wait before re-fetching.
//   - spiffe_sequence:     a monotonically increasing bundle version.
type Bundle struct {
	Keys        []json.RawMessage `json:"keys"`
	RefreshHint *int64            `json:"spiffe_refresh_hint,omitempty"`
	Sequence    *int64            `json:"spiffe_sequence,omitempty"`
}

// BuildBundle assembles a SPIFFE trust bundle from the trust domain's X.509
// authorities (its root, and any intermediates/overlapping keys that anchor
// current SVIDs). Every certificate is emitted twice: once as an x509-svid JWK
// (the full certificate, anchoring X.509-SVIDs) and once as a jwt-svid JWK (the
// bare public key with a kid, verifying JWT-SVIDs signed by that authority's
// HSM-backed key). refreshHint (if positive) and sequence (if positive) populate
// the cache-guidance members.
//
// Emitting the whole authority set as jwt-svid keys — not just the single active
// issuer that signs today — mirrors the x509-svid trust-anchor model: a token
// signed by any key still inside the CA's rollover-overlap window continues to
// verify without a bundle swap. Since only the active issuer ever signs a
// JWT-SVID, this is a superset that widens verification, never signing.
//
// Only CA certificates should be passed; a caller that hands in a leaf produces
// a technically valid but semantically wrong bundle, so BuildBundle rejects any
// certificate that is not a CA to keep the trust anchor set honest.
func BuildBundle(authorities []*x509.Certificate, refreshHint time.Duration, sequence int64) ([]byte, error) {
	if len(authorities) == 0 {
		return nil, fmt.Errorf("trust bundle requires at least one CA certificate")
	}
	b := Bundle{Keys: make([]json.RawMessage, 0, len(authorities)*2)}
	for _, cert := range authorities {
		if cert == nil {
			continue
		}
		if !cert.IsCA {
			return nil, fmt.Errorf("trust bundle authority %q is not a CA certificate", cert.Subject)
		}
		x509JWK := jose.JSONWebKey{
			Key:          cert.PublicKey,
			Certificates: []*x509.Certificate{cert},
			Use:          x509SVIDUse,
		}
		raw, err := x509JWK.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("encoding trust anchor %q as JWK: %w", cert.Subject, err)
		}
		b.Keys = append(b.Keys, json.RawMessage(raw))

		kid, err := KeyID(cert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("deriving JWT key id for %q: %w", cert.Subject, err)
		}
		jwtJWK := jose.JSONWebKey{
			Key:   cert.PublicKey,
			KeyID: kid,
			Use:   jwtSVIDUse,
		}
		jraw, err := jwtJWK.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("encoding JWT-SVID key for %q as JWK: %w", cert.Subject, err)
		}
		b.Keys = append(b.Keys, json.RawMessage(jraw))
	}
	if len(b.Keys) == 0 {
		return nil, fmt.Errorf("trust bundle contains no usable CA certificates")
	}
	if refreshHint > 0 {
		secs := int64(refreshHint / time.Second)
		if secs < 1 {
			secs = 1
		}
		b.RefreshHint = &secs
	}
	if sequence > 0 {
		b.Sequence = &sequence
	}
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding trust bundle: %w", err)
	}
	return out, nil
}

// ParseBundle decodes a SPIFFE trust bundle back into the set of X.509
// authorities it advertises. It is the inverse of BuildBundle and is used by
// tests (and any in-process consumer) to verify a bundle's contents without
// pulling in the full go-spiffe dependency.
func ParseBundle(data []byte) ([]*x509.Certificate, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("decoding trust bundle: %w", err)
	}
	var out []*x509.Certificate
	for i, raw := range b.Keys {
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(raw); err != nil {
			return nil, fmt.Errorf("decoding bundle key %d: %w", i, err)
		}
		if jwk.Use != x509SVIDUse {
			continue
		}
		if len(jwk.Certificates) == 0 {
			return nil, fmt.Errorf("bundle key %d marked %q but carries no certificate", i, x509SVIDUse)
		}
		out = append(out, jwk.Certificates[0])
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("trust bundle contains no x509-svid authorities")
	}
	return out, nil
}

// ParseJWTBundleKeys extracts the JWT-SVID verification keys from a SPIFFE trust
// bundle, keyed by their kid. It is the JWT counterpart of ParseBundle and backs
// JWT-SVID validation: a token's header kid selects the key its signature is
// checked against. x509-svid entries are ignored. It errors if the bundle
// advertises no jwt-svid key or a jwt-svid entry lacks a kid (which would make
// it unreferenceable).
func ParseJWTBundleKeys(data []byte) (map[string]crypto.PublicKey, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("decoding trust bundle: %w", err)
	}
	out := make(map[string]crypto.PublicKey)
	for i, raw := range b.Keys {
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(raw); err != nil {
			return nil, fmt.Errorf("decoding bundle key %d: %w", i, err)
		}
		if jwk.Use != jwtSVIDUse {
			continue
		}
		if jwk.KeyID == "" {
			return nil, fmt.Errorf("bundle jwt-svid key %d is missing a kid", i)
		}
		if jwk.Key == nil {
			return nil, fmt.Errorf("bundle jwt-svid key %d (kid %q) carries no key material", i, jwk.KeyID)
		}
		out[jwk.KeyID] = jwk.Key
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("trust bundle contains no jwt-svid keys")
	}
	return out, nil
}
