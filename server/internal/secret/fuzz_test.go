package secret

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// fuzzWrapper is a software implementation of the envelope-layer wrapper
// interface, backed by an in-memory RSA key. It mirrors the RSA-OAEP semantics
// of the production rsaOAEPWrapper (which delegates unwrap to an HSM) so the
// decrypt path — validate -> RSA-OAEP unwrap -> AES-GCM open — can be fuzzed
// with no HSM present, exactly as it runs in CI.
type fuzzWrapper struct{ priv *rsa.PrivateKey }

func (w *fuzzWrapper) Wrap(dek []byte) ([]byte, string, error) {
	h, err := algHash(AlgRSAOAEPSHA256)
	if err != nil {
		return nil, "", err
	}
	wrapped, err := rsa.EncryptOAEP(h.New(), rand.Reader, &w.priv.PublicKey, dek, nil)
	if err != nil {
		return nil, "", err
	}
	return wrapped, AlgRSAOAEPSHA256, nil
}

func (w *fuzzWrapper) Unwrap(wrapped []byte, alg string) ([]byte, error) {
	h, err := algHash(alg)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(h.New(), rand.Reader, w.priv, wrapped, nil)
}

func (w *fuzzWrapper) Label() string        { return "fuzz-kek" }
func (w *fuzzWrapper) URI() string          { return "software:fuzz-kek" }
func (w *fuzzWrapper) ProviderName() string { return "software" }
func (w *fuzzWrapper) Version() int         { return 1 }

func newFuzzWrapper(tb testing.TB) *fuzzWrapper {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("generating RSA key: %v", err)
	}
	return &fuzzWrapper{priv: key}
}

// FuzzEnvelopeUnmarshal drives the JSON envelope parser. A stored/transmitted
// envelope is untrusted input on the decrypt path; the parser rejects unknown
// fields, unsupported versions, and unsupported algorithms. This target asserts
// it never panics or returns a nil envelope with a nil error, and that any
// envelope it accepts round-trips back through Marshal (validate() is
// self-consistent).
func FuzzEnvelopeUnmarshal(f *testing.F) {
	w := newFuzzWrapper(f)
	if env, err := seal(w, []byte("hello world"), nil, nil); err == nil {
		if b, err := env.Marshal(); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`{"version":2,"kek_label":"x","wrap_alg":"RSA-OAEP-SHA256","data_alg":"AES-256-GCM","wrapped_dek":"AAAA","nonce":"AAAA","ciphertext":"AAAA"}`))
	f.Add([]byte(`{"version":1,"kek_label":"x","wrap_alg":"bogus","data_alg":"AES-256-GCM","wrapped_dek":"AAAA","nonce":"AAAA","ciphertext":"AAAA"}`))
	f.Add([]byte(`{"version":1,"kek_label":"x","wrap_alg":"RSA-OAEP-SHA256","data_alg":"AES-256-GCM","wrapped_dek":"AAAA","nonce":"AAAA","ciphertext":"AAAA","unknown_field":true}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(nil))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		env, err := Unmarshal(data)
		if err == nil && env == nil {
			t.Fatalf("Unmarshal returned a nil envelope with a nil error for %d bytes", len(data))
		}
		if err != nil {
			return
		}
		// Anything Unmarshal accepts has passed validate(); Marshal validates
		// again and must therefore succeed, proving the accepted state is
		// internally consistent.
		if _, err := env.Marshal(); err != nil {
			t.Fatalf("Marshal rejected an envelope that Unmarshal accepted: %v", err)
		}
	})
}

// FuzzEnvelopeOpen drives the full decrypt path — validate, RSA-OAEP unwrap of
// the DEK, and AES-GCM open — with adversarially chosen ciphertext material and
// encryption context. This is where corrupted or attacker-substituted envelope
// fields are cryptographically processed; it must never panic, over-allocate, or
// return a nil error together with unexpected state.
func FuzzEnvelopeOpen(f *testing.F) {
	w := newFuzzWrapper(f)

	// A genuine envelope's parts make a high-value seed (they steer the fuzzer
	// past validate() and OAEP unwrap into the GCM open).
	if env, err := seal(w, []byte("secret-data"), []byte("ctx"), nil); err == nil {
		f.Add(env.WrappedDEK, env.Nonce, env.Ciphertext, []byte("ctx"), true)
	}
	f.Add([]byte("short-wrap"), []byte("123456789012"), []byte("abc"), []byte(nil), false)
	f.Add([]byte(nil), []byte(nil), []byte(nil), []byte(nil), false)
	f.Add([]byte{0x00}, []byte{0x00}, []byte{0x00}, []byte{0x00}, true)

	f.Fuzz(func(t *testing.T, wrapped, nonce, ciphertext, context []byte, bound bool) {
		env := &Envelope{
			Version:      FormatVersion1,
			Provider:     "software",
			KEKLabel:     "fuzz-kek",
			WrapAlg:      AlgRSAOAEPSHA256,
			DataAlg:      AlgAES256GCM,
			WrappedDEK:   wrapped,
			Nonce:        nonce,
			Ciphertext:   ciphertext,
			ContextBound: bound,
		}
		pt, err := open(w, env, context)
		if err == nil && pt == nil {
			t.Fatal("open returned nil plaintext with a nil error")
		}
	})
}
