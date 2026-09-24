//go:build sqlite

package acme

// Coverage for publicKeyMatches, the sole authorization check on the
// certificate-key ("jwk") branch of revocation (RFC 8555 §7.6). A false positive
// there lets anybody revoke anybody's certificate, so the matrix below pins down
// that keys of the same type and size, the same family on a different curve, and
// different families are all distinguished — and that every degenerate input
// fails closed rather than open.

import (
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
	"net/http"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	xacme "golang.org/x/crypto/acme"
)

// certWithKey returns a certificate carrying pub as its public key. Only the
// public key is read by publicKeyMatches, so a synthetic certificate keeps the
// matrix exact and fast; TestPublicKeyMatchesRealCertificate below repeats the
// positive case against a genuinely parsed DER certificate.
func certWithKey(pub any) *x509.Certificate { return &x509.Certificate{PublicKey: pub} }

func jwkOf(pub any) *jose.JSONWebKey { return &jose.JSONWebKey{Key: pub} }

func TestPublicKeyMatches(t *testing.T) {
	ec256a := newP256(t)
	ec256b := newP256(t)
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-384: %v", err)
	}
	rsaA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA-2048: %v", err)
	}
	rsaB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA-2048 (second): %v", err)
	}
	rsa3072, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("generate RSA-3072: %v", err)
	}
	edPubA, edPrivA, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519: %v", err)
	}
	edPubB, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 (second): %v", err)
	}
	// An RSA key sharing rsaA's modulus but a different public exponent: the
	// modulus alone must not be treated as the key's identity.
	rsaSameN := &rsa.PublicKey{N: rsaA.N, E: 3}

	cases := []struct {
		name string
		jwk  *jose.JSONWebKey
		cert *x509.Certificate
		want bool
	}{
		{"ecdsa-p256-same-key", jwkOf(&ec256a.PublicKey), certWithKey(&ec256a.PublicKey), true},
		{"rsa-2048-same-key", jwkOf(&rsaA.PublicKey), certWithKey(&rsaA.PublicKey), true},
		{"ed25519-same-key", jwkOf(edPubA), certWithKey(edPubA), true},

		// Same type, same size, different key — the case a naive "is it an ECDSA
		// P-256 key?" check would wave through.
		{"ecdsa-p256-different-keys", jwkOf(&ec256a.PublicKey), certWithKey(&ec256b.PublicKey), false},
		{"rsa-2048-different-keys", jwkOf(&rsaA.PublicKey), certWithKey(&rsaB.PublicKey), false},
		{"ed25519-different-keys", jwkOf(edPubA), certWithKey(edPubB), false},

		// Same family, different curve / size.
		{"ecdsa-p256-vs-p384", jwkOf(&ec256a.PublicKey), certWithKey(&ec384.PublicKey), false},
		{"ecdsa-p384-vs-p256", jwkOf(&ec384.PublicKey), certWithKey(&ec256a.PublicKey), false},
		{"rsa-2048-vs-3072", jwkOf(&rsaA.PublicKey), certWithKey(&rsa3072.PublicKey), false},

		// Different families entirely.
		{"ecdsa-vs-rsa", jwkOf(&ec256a.PublicKey), certWithKey(&rsaA.PublicKey), false},
		{"rsa-vs-ecdsa", jwkOf(&rsaA.PublicKey), certWithKey(&ec256a.PublicKey), false},
		{"ed25519-vs-ecdsa", jwkOf(edPubA), certWithKey(&ec256a.PublicKey), false},
		{"rsa-vs-ed25519", jwkOf(&rsaA.PublicKey), certWithKey(edPubA), false},

		// Same modulus, different exponent.
		{"rsa-same-modulus-different-exponent", jwkOf(rsaSameN), certWithKey(&rsaA.PublicKey), false},

		// Degenerate inputs must fail closed, never open.
		{"nil-jwk", nil, certWithKey(&ec256a.PublicKey), false},
		{"jwk-with-nil-key", jwkOf(nil), certWithKey(&ec256a.PublicKey), false},
		{"jwk-with-zero-value-key", &jose.JSONWebKey{}, certWithKey(&ec256a.PublicKey), false},
		{"cert-with-nil-public-key", jwkOf(&ec256a.PublicKey), certWithKey(nil), false},
		{"both-nil-key-material", jwkOf(nil), certWithKey(nil), false},
		{"jwk-with-unsupported-key-type", jwkOf([]byte("an-hmac-secret")), certWithKey(&ec256a.PublicKey), false},
		// A private JWK is refused before it can match: the JWS layer already
		// rejects non-public embedded keys, and this must not be a second way in.
		{"jwk-holds-a-private-key", jwkOf(ec256a), certWithKey(&ec256a.PublicKey), false},
		{"jwk-holds-a-private-ed25519-key", jwkOf(edPrivA), certWithKey(edPubA), false},
		// A zero/empty ECDSA public key must not match a real one.
		{"jwk-zero-ecdsa-point", jwkOf(&ecdsa.PublicKey{Curve: elliptic.P256(),
			X: big.NewInt(0), Y: big.NewInt(0)}), certWithKey(&ec256a.PublicKey), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := publicKeyMatches(tc.jwk, tc.cert); got != tc.want {
				t.Errorf("publicKeyMatches() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPublicKeyMatchesRealCertificate repeats the positive and negative cases
// against a certificate that went through DER encode/parse, confirming the match
// is not an artefact of comparing in-memory structs.
func TestPublicKeyMatchesRealCertificate(t *testing.T) {
	key := newP256(t)
	other := newP256(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "pubkey-match.example.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !publicKeyMatches(jwkOf(&key.PublicKey), cert) {
		t.Error("publicKeyMatches = false for the certificate's own key")
	}
	if publicKeyMatches(jwkOf(&other.PublicKey), cert) {
		t.Error("publicKeyMatches = true for a different key of the same type and curve")
	}
}

// ---- end-to-end: certificate-key revocation -------------------------------

// issueCertKeepingKey drives a full http-01 order to a certificate while
// retaining the certificate key pair, so the cert-key revocation branch of
// RFC 8555 §7.6 can be exercised.
func issueCertKeepingKey(t *testing.T, env *testEnv, domain string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	c := env.client(t)
	ctx := t.Context()
	order, err := c.AuthorizeOrder(ctx, xacme.DomainIDs(domain))
	if err != nil {
		t.Fatalf("AuthorizeOrder: %v", err)
	}
	env.solve(t, c, order, "http-01", domain)
	if _, err := c.WaitOrder(ctx, order.URI); err != nil {
		t.Fatalf("WaitOrder: %v", err)
	}
	certKey := newP256(t)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: domain},
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	der, _, err := c.CreateOrderCert(ctx, order.FinalizeURL, csrDER, true)
	if err != nil {
		t.Fatalf("CreateOrderCert: %v", err)
	}
	return certKey, der[0]
}

// revokeCertURL fetches the directory's advertised revokeCert resource.
func revokeCertURL(t *testing.T, dirURL string) string {
	t.Helper()
	resp, err := http.Get(dirURL)
	if err != nil {
		t.Fatalf("GET directory: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var dir struct {
		RevokeCert string `json:"revokeCert"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&dir); err != nil {
		t.Fatalf("decode directory: %v", err)
	}
	if dir.RevokeCert == "" {
		t.Fatal("directory does not advertise a revokeCert resource")
	}
	return dir.RevokeCert
}

// postRevoke signs a revocation request with signKey, embedding it as the JWS
// "jwk" — the certificate-key authentication mode of RFC 8555 §7.6.
func postRevoke(t *testing.T, env *testEnv, signKey *ecdsa.PrivateKey, der []byte) (*http.Response, []byte) {
	t.Helper()
	rc := newRawClient(t, env.dirURL)
	rc.key = signKey
	payload, err := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(der),
		"reason":      1, // keyCompromise
	})
	if err != nil {
		t.Fatalf("marshal revoke payload: %v", err)
	}
	return rc.post(revokeCertURL(t, env.dirURL), payload, true)
}

// TestACME_Revoke_WithCertificateKey confirms the holder of the certificate's own
// private key may revoke it without an account (RFC 8555 §7.6), i.e. the positive
// side of publicKeyMatches in the real handler.
func TestACME_Revoke_WithCertificateKey(t *testing.T) {
	env := newTestEnv(t)
	certKey, der := issueCertKeepingKey(t, env, "revoke-certkey.example.test")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	resp, body := postRevoke(t, env, certKey, der)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke with the certificate key = %d, want 200: %s", resp.StatusCode, body)
	}
	rev, err := env.db.GetRevokedCertificate(env.caID, cert.SerialNumber.String())
	if err != nil {
		t.Fatalf("GetRevokedCertificate: %v", err)
	}
	if rev == nil {
		t.Fatal("certificate was not recorded as revoked")
	}
}

// TestACME_Revoke_WithForeignKeyRejected is the authorization assertion: a JWS
// signed by a key that is not the certificate's must not revoke it, and the
// certificate must still be good afterwards. A publicKeyMatches that returned
// true too eagerly would turn this into an unauthenticated revocation DoS against
// every certificate the CA has issued.
func TestACME_Revoke_WithForeignKeyRejected(t *testing.T) {
	env := newTestEnv(t)
	_, der := issueCertKeepingKey(t, env, "revoke-foreign.example.test")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	foreign := newP256(t)
	resp, body := postRevoke(t, env, foreign, der)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoke with a foreign key = %d, want 401: %s", resp.StatusCode, body)
	}
	var prob Problem
	if err := json.Unmarshal(body, &prob); err != nil {
		t.Fatalf("response is not a problem document: %v (%s)", err, body)
	}
	if prob.Type != probUnauthorized {
		t.Errorf("problem type = %q, want %q: %s", prob.Type, probUnauthorized, body)
	}
	rev, err := env.db.GetRevokedCertificate(env.caID, cert.SerialNumber.String())
	if err != nil {
		t.Fatalf("GetRevokedCertificate: %v", err)
	}
	if rev != nil {
		t.Fatal("certificate was revoked by a key that does not belong to it")
	}
}

// TestACME_Revoke_WithForeignAccountKeyRejected covers the same bypass attempted
// from a *registered* account: an account that never ordered the certificate
// cannot revoke it, whether it authenticates by kid or presents its account key
// as the certificate key.
func TestACME_Revoke_WithForeignAccountKeyRejected(t *testing.T) {
	env := newTestEnv(t)
	_, der := issueCertKeepingKey(t, env, "revoke-foreign-acct.example.test")
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	stranger := newRawClient(t, env.dirURL)
	stranger.register()
	payload, err := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(der),
	})
	if err != nil {
		t.Fatalf("marshal revoke payload: %v", err)
	}
	revURL := revokeCertURL(t, env.dirURL)

	// kid mode: the account does not own the order.
	if resp, body := stranger.post(revURL, payload, false); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("kid-mode revoke by a stranger = %d, want 401: %s", resp.StatusCode, body)
	}
	// jwk mode: the account key is not the certificate key.
	if resp, body := stranger.post(revURL, payload, true); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("jwk-mode revoke by a stranger = %d, want 401: %s", resp.StatusCode, body)
	}
	if rev, _ := env.db.GetRevokedCertificate(env.caID, cert.SerialNumber.String()); rev != nil {
		t.Fatal("certificate was revoked by an unrelated account")
	}
}
