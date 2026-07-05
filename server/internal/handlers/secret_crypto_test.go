//go:build sqlite

package handlers

// Functional tests for the stateless crypto service (Task 138): data-key
// generation, keyed HMAC generate/verify, and CSPRNG random bytes, exercised
// end-to-end against a software KEK. Authorization/tenant-isolation is covered by
// the authz matrix; these tests prove the crypto actually round-trips.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

func newCryptoAPI(t *testing.T) *API {
	t.Helper()
	db, err := database.New("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	prov, err := keyprovider.NewSoftwareProvider(keyprovider.SoftwareSettings{KeystoreDir: t.TempDir()})
	if err != nil {
		t.Fatalf("NewSoftwareProvider: %v", err)
	}
	if _, err := secret.ProvisionKEK(context.Background(), prov, "crypto-kek", keyprovider.KeyTypeRSA2048); err != nil {
		t.Fatalf("ProvisionKEK: %v", err)
	}
	return NewAPI(db, keyprovider.Instrument(prov), nil, hsm.Config{}, true, "crypto-kek")
}

func doJSON(t *testing.T, h http.HandlerFunc, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, reqAs(http.MethodPost, path, rootUser(), "", body))
	return rec
}

// TestDataKeyRoundTrip: a minted data key is returned in the clear and its
// wrapped envelope decrypts back to the identical key via the existing
// /api/secret/decrypt path — the core "envelope encryption as a service" loop.
func TestDataKeyRoundTrip(t *testing.T) {
	api := newCryptoAPI(t)

	for _, bits := range []int{128, 256, 512} {
		rec := doJSON(t, api.GenerateDataKey, "/api/secret/datakey", `{"bits":`+itoa(bits)+`}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("datakey bits=%d = %d; body=%s", bits, rec.Code, rec.Body.String())
		}
		var dk dataKeyResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &dk); err != nil {
			t.Fatalf("decode datakey: %v", err)
		}
		key, err := base64.StdEncoding.DecodeString(dk.Plaintext)
		if err != nil {
			t.Fatalf("plaintext not base64: %v", err)
		}
		if len(key)*8 != bits {
			t.Errorf("bits=%d: key length = %d bits, want %d", bits, len(key)*8, bits)
		}
		if len(dk.Wrapped) == 0 {
			t.Fatalf("bits=%d: wrapped envelope missing", bits)
		}

		// Recover the same key by decrypting the wrapped envelope.
		decBody, _ := json.Marshal(map[string]json.RawMessage{"envelope": dk.Wrapped})
		drec := doJSON(t, api.DecryptSecret, "/api/secret/decrypt", string(decBody))
		if drec.Code != http.StatusOK {
			t.Fatalf("bits=%d: decrypt wrapped = %d; body=%s", bits, drec.Code, drec.Body.String())
		}
		var dr decryptResponse
		if err := json.Unmarshal(drec.Body.Bytes(), &dr); err != nil {
			t.Fatalf("decode decrypt: %v", err)
		}
		if dr.Plaintext != dk.Plaintext {
			t.Errorf("bits=%d: recovered key %q != minted key %q", bits, dr.Plaintext, dk.Plaintext)
		}
	}
}

// TestDataKeyWrappedOnly: wrapped_only omits the plaintext but still returns a
// decryptable envelope.
func TestDataKeyWrappedOnly(t *testing.T) {
	api := newCryptoAPI(t)
	rec := doJSON(t, api.GenerateDataKey, "/api/secret/datakey", `{"wrapped_only":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("datakey = %d; body=%s", rec.Code, rec.Body.String())
	}
	var dk dataKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &dk); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dk.Plaintext != "" {
		t.Errorf("wrapped_only returned plaintext %q, want empty", dk.Plaintext)
	}
	if len(dk.Wrapped) == 0 {
		t.Error("wrapped_only omitted the wrapped envelope too")
	}
	if dk.Bits != 256 {
		t.Errorf("default bits = %d, want 256", dk.Bits)
	}
}

// TestDataKeyBadBits rejects an off-size key strength.
func TestDataKeyBadBits(t *testing.T) {
	api := newCryptoAPI(t)
	rec := doJSON(t, api.GenerateDataKey, "/api/secret/datakey", `{"bits":200}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bits=200 = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// TestHMACGenerateVerify: a generated tag verifies; wrong data, a tampered tag,
// and a wrong version all fail closed; the same input verifies stably across
// calls (the MAC key is stable, not ephemeral).
func TestHMACGenerateVerify(t *testing.T) {
	api := newCryptoAPI(t)
	data := base64.StdEncoding.EncodeToString([]byte("authenticate me"))

	rec := doJSON(t, api.GenerateHMAC, "/api/secret/hmac", `{"data":"`+data+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("hmac generate = %d; body=%s", rec.Code, rec.Body.String())
	}
	var gen hmacResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &gen); err != nil {
		t.Fatalf("decode hmac: %v", err)
	}
	if gen.Version != 1 || gen.Algorithm != secret.HMACAlgSHA256 || gen.HMAC == "" {
		t.Fatalf("unexpected hmac response %+v", gen)
	}

	verify := func(dataB64, macB64 string, version int) hmacVerifyResponse {
		body, _ := json.Marshal(hmacVerifyRequest{Data: dataB64, HMAC: macB64, Version: version})
		vrec := doJSON(t, api.VerifyHMAC, "/api/secret/hmac/verify", string(body))
		if vrec.Code != http.StatusOK {
			t.Fatalf("hmac verify = %d; body=%s", vrec.Code, vrec.Body.String())
		}
		var vr hmacVerifyResponse
		if err := json.Unmarshal(vrec.Body.Bytes(), &vr); err != nil {
			t.Fatalf("decode verify: %v", err)
		}
		return vr
	}

	if vr := verify(data, gen.HMAC, gen.Version); !vr.Valid {
		t.Error("valid tag did not verify")
	}
	// Version 0 resolves to the active version and must also verify.
	if vr := verify(data, gen.HMAC, 0); !vr.Valid {
		t.Error("valid tag did not verify under active version (0)")
	}
	// Wrong data.
	otherData := base64.StdEncoding.EncodeToString([]byte("different"))
	if vr := verify(otherData, gen.HMAC, gen.Version); vr.Valid {
		t.Error("tag verified against different data")
	}
	// Tampered tag.
	tag, _ := base64.StdEncoding.DecodeString(gen.HMAC)
	tag[0] ^= 0xFF
	if vr := verify(data, base64.StdEncoding.EncodeToString(tag), gen.Version); vr.Valid {
		t.Error("tampered tag verified")
	}
	// Unknown version is valid=false, not an error.
	if vr := verify(data, gen.HMAC, 99); vr.Valid {
		t.Error("tag verified against a nonexistent key version")
	}

	// Regenerating over the same data yields the same tag (stable key).
	rec2 := doJSON(t, api.GenerateHMAC, "/api/secret/hmac", `{"data":"`+data+`"}`)
	var gen2 hmacResponse
	_ = json.Unmarshal(rec2.Body.Bytes(), &gen2)
	if gen2.HMAC != gen.HMAC || gen2.Version != gen.Version {
		t.Errorf("HMAC not stable: %+v vs %+v", gen2, gen)
	}
}

// TestRandomBytes: the RNG returns the requested length in the requested
// encoding, reports a source, and bounds/validates its input.
func TestRandomBytes(t *testing.T) {
	api := newCryptoAPI(t)

	rec := doJSON(t, api.GenerateRandom, "/api/secret/random", `{"bytes":32}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("random = %d; body=%s", rec.Code, rec.Body.String())
	}
	var r randomResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	b, err := base64.StdEncoding.DecodeString(r.Random)
	if err != nil {
		t.Fatalf("random not base64: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("got %d bytes, want 32", len(b))
	}
	// The software provider has no hardware RNG, so the source is the OS CSPRNG.
	if r.Source != randomSourceSoftware {
		t.Errorf("source = %q, want %q", r.Source, randomSourceSoftware)
	}

	// hex encoding.
	hrec := doJSON(t, api.GenerateRandom, "/api/secret/random", `{"bytes":8,"format":"hex"}`)
	var hr randomResponse
	_ = json.Unmarshal(hrec.Body.Bytes(), &hr)
	if hb, err := hex.DecodeString(hr.Random); err != nil || len(hb) != 8 {
		t.Errorf("hex random = %q (err=%v), want 8 bytes hex", hr.Random, err)
	}

	// Bounds and validation.
	if rec := doJSON(t, api.GenerateRandom, "/api/secret/random", `{"bytes":0}`); rec.Code != http.StatusBadRequest {
		t.Errorf("bytes=0 = %d, want 400", rec.Code)
	}
	if rec := doJSON(t, api.GenerateRandom, "/api/secret/random", `{"bytes":100000}`); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized = %d, want 400", rec.Code)
	}
	if rec := doJSON(t, api.GenerateRandom, "/api/secret/random", `{"bytes":8,"format":"octal"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("bad format = %d, want 400", rec.Code)
	}
}

// itoa avoids pulling strconv into the test for one use.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
