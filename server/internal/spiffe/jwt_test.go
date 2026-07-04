package spiffe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

// caFromKey builds a minimal self-signed CA certificate wrapping pub, so a
// signing key can be published in a trust bundle exactly as a real CA cert is.
func caFromKey(t *testing.T, cn string, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// issueAndBundle signs a JWT-SVID with signer and returns the token plus a trust
// bundle that publishes the signer's key (via a self-signed CA cert).
func issueAndBundle(t *testing.T, signer crypto.Signer, p JWTSVIDParams) (string, []byte) {
	t.Helper()
	token, err := SignJWTSVID(signer, p)
	if err != nil {
		t.Fatalf("SignJWTSVID: %v", err)
	}
	ca := caFromKey(t, "Test SVID CA", signer.Public(), signer)
	bundle, err := BuildBundle([]*x509.Certificate{ca}, 0, 0)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	return token, bundle
}

func mustECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestJWTSVIDRoundTrip proves the happy path across every supported key type:
// sign a JWT-SVID, publish the signer in a bundle, and validate it back — the
// subject, audience, trust domain, and kid all round-trip, and the kid in the
// token header matches the bundle entry.
func TestJWTSVIDRoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name    string
		signer  crypto.Signer
		wantAlg string
	}{
		{"ecdsa-p256", mustECKey(t), "ES256"},
		{"ecdsa-p384", ecKey384, "ES384"},
		{"rsa-2048", rsaKey, "RS256"},
		{"ed25519", edKey, "EdDSA"},
	}

	const id = "spiffe://prod.example.org/ns/prod/sa/web"
	now := time.Now()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, bundle := issueAndBundle(t, tc.signer, JWTSVIDParams{
				SPIFFEID: id,
				Audience: []string{"spiffe://prod.example.org/ns/prod/sa/db"},
				IssuedAt: now,
				Expiry:   now.Add(time.Hour),
			})
			res, err := ValidateJWTSVID(token, bundle, JWTValidationOptions{
				Audience:     "spiffe://prod.example.org/ns/prod/sa/db",
				TrustDomains: []string{"prod.example.org"},
				Now:          now,
			})
			if err != nil {
				t.Fatalf("ValidateJWTSVID: %v", err)
			}
			if res.SPIFFEID != id {
				t.Errorf("sub = %q, want %q", res.SPIFFEID, id)
			}
			if res.TrustDomain != "prod.example.org" {
				t.Errorf("trust domain = %q, want prod.example.org", res.TrustDomain)
			}
			if res.Algorithm != tc.wantAlg {
				t.Errorf("alg = %q, want %q", res.Algorithm, tc.wantAlg)
			}
			// The kid in the token header must be the RFC 7638 thumbprint and match
			// the bundle key.
			wantKID, err := KeyID(tc.signer.Public())
			if err != nil {
				t.Fatal(err)
			}
			if res.KeyID != wantKID {
				t.Errorf("kid = %q, want %q", res.KeyID, wantKID)
			}
			keys, err := ParseJWTBundleKeys(bundle)
			if err != nil {
				t.Fatalf("ParseJWTBundleKeys: %v", err)
			}
			if _, ok := keys[wantKID]; !ok {
				t.Errorf("bundle has no jwt-svid key for kid %q", wantKID)
			}
		})
	}
}

// TestJWTSVIDWrongAudience proves a token minted for one audience is rejected
// when the relying party expects a different one.
func TestJWTSVIDWrongAudience(t *testing.T) {
	key := mustECKey(t)
	now := time.Now()
	token, bundle := issueAndBundle(t, key, JWTSVIDParams{
		SPIFFEID: "spiffe://example.org/workload",
		Audience: []string{"spiffe://example.org/server-a"},
		IssuedAt: now,
		Expiry:   now.Add(time.Hour),
	})
	if _, err := ValidateJWTSVID(token, bundle, JWTValidationOptions{
		Audience:     "spiffe://example.org/server-b", // not the token's audience
		TrustDomains: []string{"example.org"},
		Now:          now,
	}); err == nil {
		t.Fatal("validation should reject a token with the wrong audience")
	}
	// The same token validates for its actual audience.
	if _, err := ValidateJWTSVID(token, bundle, JWTValidationOptions{
		Audience:     "spiffe://example.org/server-a",
		TrustDomains: []string{"example.org"},
		Now:          now,
	}); err != nil {
		t.Fatalf("validation should accept the correct audience: %v", err)
	}
}

// TestJWTSVIDExpired proves an expired token is rejected even accounting for the
// clock-skew leeway.
func TestJWTSVIDExpired(t *testing.T) {
	key := mustECKey(t)
	past := time.Now().Add(-2 * time.Hour)
	token, bundle := issueAndBundle(t, key, JWTSVIDParams{
		SPIFFEID: "spiffe://example.org/workload",
		Audience: []string{"aud"},
		IssuedAt: past,
		Expiry:   past.Add(time.Hour), // expired an hour ago
	})
	if _, err := ValidateJWTSVID(token, bundle, JWTValidationOptions{
		Audience:     "aud",
		TrustDomains: []string{"example.org"},
	}); err == nil {
		t.Fatal("validation should reject an expired token")
	}
}

// TestJWTSVIDNotYetValid proves a token whose nbf is in the future is rejected.
func TestJWTSVIDNotYetValid(t *testing.T) {
	key := mustECKey(t)
	now := time.Now()
	future := now.Add(time.Hour)
	token, bundle := issueAndBundle(t, key, JWTSVIDParams{
		SPIFFEID:  "spiffe://example.org/workload",
		Audience:  []string{"aud"},
		IssuedAt:  future,
		NotBefore: future,
		Expiry:    future.Add(time.Hour),
	})
	if _, err := ValidateJWTSVID(token, bundle, JWTValidationOptions{
		Audience:     "aud",
		TrustDomains: []string{"example.org"},
		Now:          now,
	}); err == nil {
		t.Fatal("validation should reject a not-yet-valid token")
	}
}

// TestJWTSVIDForeignTrustDomain proves a token whose subject is in a trust
// domain outside the allowlist is rejected — even though its signature verifies.
func TestJWTSVIDForeignTrustDomain(t *testing.T) {
	key := mustECKey(t)
	now := time.Now()
	token, bundle := issueAndBundle(t, key, JWTSVIDParams{
		SPIFFEID: "spiffe://evil.example.net/workload",
		Audience: []string{"aud"},
		IssuedAt: now,
		Expiry:   now.Add(time.Hour),
	})
	if _, err := ValidateJWTSVID(token, bundle, JWTValidationOptions{
		Audience:     "aud",
		TrustDomains: []string{"prod.example.org"}, // does not include evil.example.net
		Now:          now,
	}); err == nil {
		t.Fatal("validation should reject a foreign trust domain")
	}
	// With the allowlist opened (empty), the same token validates — proving it was
	// the allowlist, not a signature failure, that rejected it above.
	if _, err := ValidateJWTSVID(token, bundle, JWTValidationOptions{
		Audience: "aud",
		Now:      now,
	}); err != nil {
		t.Fatalf("validation should accept the token with no allowlist: %v", err)
	}
}

// TestJWTSVIDUnknownKey proves a token signed by a key that is not in the bundle
// is rejected (the kid does not resolve).
func TestJWTSVIDUnknownKey(t *testing.T) {
	signKey := mustECKey(t)
	now := time.Now()
	token, err := SignJWTSVID(signKey, JWTSVIDParams{
		SPIFFEID: "spiffe://example.org/workload",
		Audience: []string{"aud"},
		IssuedAt: now,
		Expiry:   now.Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	// Build a bundle from a DIFFERENT key.
	otherKey := mustECKey(t)
	otherCA := caFromKey(t, "Other CA", otherKey.Public(), otherKey)
	bundle, err := BuildBundle([]*x509.Certificate{otherCA}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateJWTSVID(token, bundle, JWTValidationOptions{Audience: "aud", Now: now}); err == nil {
		t.Fatal("validation should reject a token whose kid is not in the bundle")
	}
}

// TestJWTSVIDTamperedSignature proves that mutating the payload (which changes
// the signed content) is detected.
func TestJWTSVIDTamperedSignature(t *testing.T) {
	key := mustECKey(t)
	now := time.Now()
	token, bundle := issueAndBundle(t, key, JWTSVIDParams{
		SPIFFEID: "spiffe://example.org/workload",
		Audience: []string{"aud"},
		IssuedAt: now,
		Expiry:   now.Add(time.Hour),
	})
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS should have 3 parts, got %d", len(parts))
	}
	// Forge the payload: change the subject to a different SPIFFE ID.
	forged, err := json.Marshal(map[string]any{
		"sub": "spiffe://example.org/attacker",
		"aud": "aud",
		"exp": now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	parts[1] = base64.RawURLEncoding.EncodeToString(forged)
	tampered := strings.Join(parts, ".")
	if _, err := ValidateJWTSVID(tampered, bundle, JWTValidationOptions{Audience: "aud", Now: now}); err == nil {
		t.Fatal("validation should reject a token with a tampered payload")
	}
}

// TestJWTSVIDRejectsNoneAlg proves the "none" algorithm is refused at parse time
// (the allowlist passed to jwt.ParseSigned excludes it).
func TestJWTSVIDRejectsNoneAlg(t *testing.T) {
	key := mustECKey(t)
	ca := caFromKey(t, "CA", key.Public(), key)
	bundle, err := BuildBundle([]*x509.Certificate{ca}, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := KeyID(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	// Hand-craft an unsigned ("alg":"none") token with an empty signature.
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"` + kid + `","typ":"JWT"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"spiffe://example.org/w","aud":"aud","exp":9999999999}`))
	unsigned := hdr + "." + pl + "."
	if _, err := ValidateJWTSVID(unsigned, bundle, JWTValidationOptions{Audience: "aud"}); err == nil {
		t.Fatal("validation must reject an alg=none token")
	}
}

// TestSignJWTSVIDValidation covers the input guards on the signing path.
func TestSignJWTSVIDValidation(t *testing.T) {
	key := mustECKey(t)
	now := time.Now()
	cases := []struct {
		name string
		p    JWTSVIDParams
	}{
		{"empty subject", JWTSVIDParams{Audience: []string{"a"}, Expiry: now.Add(time.Hour)}},
		{"bad subject", JWTSVIDParams{SPIFFEID: "http://example.org/x", Audience: []string{"a"}, Expiry: now.Add(time.Hour)}},
		{"no audience", JWTSVIDParams{SPIFFEID: "spiffe://example.org/w", Expiry: now.Add(time.Hour)}},
		{"no expiry", JWTSVIDParams{SPIFFEID: "spiffe://example.org/w", Audience: []string{"a"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := SignJWTSVID(key, tc.p); err == nil {
				t.Errorf("SignJWTSVID(%s) should have failed", tc.name)
			}
		})
	}
	if _, err := SignJWTSVID(nil, JWTSVIDParams{SPIFFEID: "spiffe://example.org/w", Audience: []string{"a"}, Expiry: now.Add(time.Hour)}); err == nil {
		t.Error("SignJWTSVID(nil signer) should have failed")
	}
}

// TestKeyIDStable proves the kid derivation is a deterministic function of the
// key material: the same key always yields the same kid, and distinct keys yield
// distinct kids.
func TestKeyIDStable(t *testing.T) {
	k1 := mustECKey(t)
	k2 := mustECKey(t)
	a, err := KeyID(k1.Public())
	if err != nil {
		t.Fatal(err)
	}
	b, err := KeyID(k1.Public())
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("kid is not stable for the same key: %q vs %q", a, b)
	}
	c, err := KeyID(k2.Public())
	if err != nil {
		t.Fatal(err)
	}
	if a == c {
		t.Error("distinct keys produced the same kid")
	}
}
