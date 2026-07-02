package acme

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
)

// maxJWSBytes bounds an inbound ACME request body.
const maxJWSBytes = 256 * 1024

// allowedAlgs is the set of JWS signature algorithms the server accepts. "none"
// is deliberately excluded, and only asymmetric algorithms are permitted so an
// account is always bound to a key pair (RFC 8555 §6.2).
var allowedAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// jwsData holds the parsed, nonce-validated fields of an ACME JWS request. The
// signature itself has NOT yet been verified — the caller resolves the correct
// verification key (embedded JWK or the account's stored key) and calls verify.
type jwsData struct {
	Alg   string
	Nonce string
	URL   string
	KID   string
	JWK   *jose.JSONWebKey
	jws   *jose.JSONWebSignature
}

// decodeJWS reads and structurally validates an ACME JWS request: it enforces
// the flattened-JSON encoding, a single signature, the required protected-header
// fields, the anti-replay nonce, and the url binding. It does not verify the
// signature (see verify).
func (s *Server) decodeJWS(r *http.Request) (*jwsData, *Problem) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxJWSBytes))
	if err != nil {
		return nil, newProblem(probMalformed, http.StatusBadRequest, "reading request body")
	}
	// RFC 8555 §6.2 requires the JWS to be sent using the flattened JSON
	// serialization; reject compact/other encodings.
	jws, err := jose.ParseSignedJSON(string(body), allowedAlgs)
	if err != nil {
		return nil, newProblem(probMalformed, http.StatusBadRequest, "parsing JWS: "+err.Error())
	}
	if len(jws.Signatures) != 1 {
		return nil, newProblem(probMalformed, http.StatusBadRequest, "JWS must carry exactly one signature")
	}

	prot := jws.Signatures[0].Protected
	d := &jwsData{
		Alg:   prot.Algorithm,
		Nonce: prot.Nonce,
		KID:   prot.KeyID,
		JWK:   prot.JSONWebKey,
		jws:   jws,
	}
	if u, ok := prot.ExtraHeaders[jose.HeaderKey("url")]; ok {
		if str, ok := u.(string); ok {
			d.URL = str
		}
	}

	// Exactly one of "jwk" (new account / cert-key auth) or "kid" (existing
	// account) must be present (RFC 8555 §6.2).
	if (d.JWK == nil) == (d.KID == "") {
		return nil, newProblem(probMalformed, http.StatusBadRequest, "JWS must contain exactly one of \"jwk\" or \"kid\"")
	}
	if d.JWK != nil && !d.JWK.IsPublic() {
		return nil, newProblem(probMalformed, http.StatusBadRequest, "embedded JWK must be a public key")
	}

	// The signed "url" header must match the URL the request was sent to; this
	// binds the signature to this exact endpoint (RFC 8555 §6.4).
	if d.URL == "" {
		return nil, newProblem(probMalformed, http.StatusBadRequest, "protected header is missing the \"url\" field")
	}
	if !strings.EqualFold(d.URL, s.requestURL(r)) {
		return nil, newProblem(probMalformed, http.StatusBadRequest, "JWS \"url\" header does not match the request URL")
	}

	// Consume the anti-replay nonce. A missing/expired/reused nonce is a
	// badNonce error, which conformant clients retry with a fresh nonce.
	if !s.nonces.Consume(d.Nonce) {
		return nil, newProblem(probBadNonce, http.StatusBadRequest, "the supplied anti-replay nonce is invalid or has expired")
	}

	return d, nil
}

// verify checks the JWS signature against the given key and returns the decoded
// payload. The payload is empty for POST-as-GET requests.
func (d *jwsData) verify(key interface{}) ([]byte, *Problem) {
	payload, err := d.jws.Verify(key)
	if err != nil {
		return nil, newProblem(probUnauthorized, http.StatusUnauthorized, "JWS signature verification failed")
	}
	return payload, nil
}

// jwkThumbprint returns the base64url-encoded RFC 7638 SHA-256 thumbprint of a
// public JWK. This is the stable account-key identity used for lookup and to
// construct key authorizations.
func jwkThumbprint(jwk *jose.JSONWebKey) (string, error) {
	tp, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// keyAuthorization builds the RFC 8555 §8.1 key authorization string that a
// challenge response must present: "<token>.<account-key-thumbprint>".
func keyAuthorization(token, thumbprint string) string {
	return token + "." + thumbprint
}

// newToken mints a fresh, high-entropy challenge token. RFC 8555 §8.1 requires
// at least 128 bits of entropy; we use 256.
func newToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand should never fail; if it does, fail loudly rather than
		// return a predictable token.
		panic("acme: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}
