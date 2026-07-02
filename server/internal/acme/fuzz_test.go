package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// buildSeedJWS produces a genuine flattened-JSON JWS with an embedded public
// JWK, matching the shape decodeJWS expects, for use as a fuzz seed.
func buildSeedJWS(tb testing.TB) []byte {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generating key: %v", err)
	}
	opts := (&jose.SignerOptions{}).
		WithHeader("url", "https://ca.example.com/acme/new-account").
		WithHeader("nonce", "seed-nonce")
	opts.EmbedJWK = true
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		tb.Fatalf("creating signer: %v", err)
	}
	obj, err := signer.Sign([]byte(`{"contact":["mailto:admin@example.com"],"termsOfServiceAgreed":true}`))
	if err != nil {
		tb.Fatalf("signing: %v", err)
	}
	return []byte(obj.FullSerialize())
}

// FuzzParseJWS drives the ACME JWS decode path (jose.ParseSignedJSON plus the
// protected-header extraction and JWK thumbprinting that decodeJWS performs).
// This is the very first thing every authenticated ACME request touches, on an
// unauthenticated endpoint, so it must survive arbitrary bodies without
// panicking, over-allocating, or dereferencing nil.
func FuzzParseJWS(f *testing.F) {
	f.Add(buildSeedJWS(f))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"protected":"","payload":"","signature":""}`))
	f.Add([]byte(`{"protected":"!!!","payload":"@@@","signature":"###"}`))
	f.Add([]byte(`{"signatures":[]}`))
	f.Add([]byte("not json at all"))
	f.Add([]byte(nil))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, body []byte) {
		jws, err := jose.ParseSignedJSON(string(body), allowedAlgs)
		if err != nil {
			return
		}
		if jws == nil {
			t.Fatal("ParseSignedJSON returned nil JWS with nil error")
		}
		if len(jws.Signatures) != 1 {
			return
		}
		// Mirror decodeJWS's structural access of the protected header. None of
		// these accesses may panic regardless of what the attacker supplied.
		prot := jws.Signatures[0].Protected
		d := &jwsData{
			Alg:   prot.Algorithm,
			Nonce: prot.Nonce,
			KID:   prot.KeyID,
			JWK:   prot.JSONWebKey,
			jws:   jws,
		}
		if u, ok := prot.ExtraHeaders[jose.HeaderKey("url")]; ok {
			if s, ok := u.(string); ok {
				d.URL = s
			}
		}
		if d.JWK != nil {
			_ = d.JWK.IsPublic()
			// jwkThumbprint is called on every new-account request.
			_, _ = jwkThumbprint(d.JWK)
		}
	})
}

// FuzzACMEPayloads drives the JSON payload deserializers that run on the
// verified-but-attacker-authored inner payload of ACME requests, including the
// base64url + x509 decode of CSRs (finalize) and certificates (revoke). A
// signature check proves the payload came from the account key, not that it is
// well-formed, so these parsers face fully adversarial content.
func FuzzACMEPayloads(f *testing.F) {
	f.Add([]byte(`{"contact":["mailto:x@y.com"],"termsOfServiceAgreed":true}`))
	f.Add([]byte(`{"identifiers":[{"type":"dns","value":"a.example.com"}],"notAfter":"2030-01-01T00:00:00Z"}`))
	f.Add([]byte(`{"status":"deactivated"}`))
	f.Add([]byte(`{"csr":"AAAA"}`))
	f.Add([]byte(`{"certificate":"AAAA","reason":1}`))
	f.Add([]byte(`{"account":"https://ca/acct/1","oldKey":{}}`))
	f.Add([]byte(`{`))
	f.Add([]byte(nil))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, payload []byte) {
		var na newAccountRequest
		_ = json.Unmarshal(payload, &na)

		var no newOrderRequest
		_ = json.Unmarshal(payload, &no)

		var au accountUpdateRequest
		_ = json.Unmarshal(payload, &au)

		var ki keyChangeInner
		_ = json.Unmarshal(payload, &ki)

		// Finalize: JSON -> base64url -> DER CSR, mirroring handleFinalize.
		var fr finalizeRequest
		if json.Unmarshal(payload, &fr) == nil && fr.CSR != "" {
			if der, err := base64.RawURLEncoding.DecodeString(fr.CSR); err == nil {
				if csr, err := x509.ParseCertificateRequest(der); err == nil && csr != nil {
					_ = csr.CheckSignature()
				}
			}
		}

		// Revoke: JSON -> base64url -> DER certificate, mirroring handleRevoke.
		var rr revokeRequest
		if json.Unmarshal(payload, &rr) == nil && rr.Certificate != "" {
			if der, err := base64.RawURLEncoding.DecodeString(rr.Certificate); err == nil {
				_, _ = x509.ParseCertificate(der)
			}
		}
	})
}

// FuzzParseCertID drives the ARI CertID parser (draft-ietf-acme-ari §4.1). The
// CertID arrives in the unauthenticated renewalInfo URL path and in the
// account-authored newOrder "replaces" field, so it must survive arbitrary input
// without panicking or mis-decoding. Well-formed CertIDs are additionally
// checked to round-trip.
func FuzzParseCertID(f *testing.F) {
	f.Add("aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE")
	f.Add("AAAA.AAAA")
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")
	f.Add("!!!.@@@")
	f.Add("onlyAKI.")
	f.Add(".onlySerial")

	f.Fuzz(func(t *testing.T, s string) {
		id, err := parseCertID(s)
		if err != nil {
			return
		}
		if id == nil || len(id.AKI) == 0 || id.Serial == nil {
			t.Fatalf("parseCertID(%q) returned a nil/empty result with no error", s)
		}
		// A successfully parsed CertID must re-encode to a value that parses back to
		// the same AKI and serial (canonical, stable round-trip).
		reencoded, err := certIDForCertificate(id.AKI, id.Serial)
		if err != nil {
			t.Fatalf("certIDForCertificate on parsed CertID %q failed: %v", s, err)
		}
		again, err := parseCertID(reencoded)
		if err != nil {
			t.Fatalf("re-encoded CertID %q does not parse: %v", reencoded, err)
		}
		if !bytesEqual(again.AKI, id.AKI) || again.Serial.Cmp(id.Serial) != 0 {
			t.Fatalf("CertID round-trip mismatch for %q", s)
		}
	})
}
