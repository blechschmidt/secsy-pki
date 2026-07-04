package keyprovider

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeVault is a hermetic, in-process stand-in for a HashiCorp Vault server with
// the Transit secrets engine and AppRole auth mounted. It implements just enough
// of the REST API for the vaultTransitBackend to exercise every code path —
// create/read/list keys, sign/verify, encrypt/decrypt (wrap/unwrap), token
// lookup, and AppRole login — using real Go-standard-library crypto. It requires
// no real Vault and no HSM, mirroring the in-memory KMS fake backend.
type fakeVault struct {
	server    *httptest.Server
	mount     string
	roleID    string
	secretID  string
	rootToken string

	mu     sync.Mutex
	keys   map[string]*fakeVaultKey // by transit key name
	tokens map[string]bool          // valid client tokens (besides rootToken)
	nextID int
}

type fakeVaultKey struct {
	transitType string
	signer      crypto.Signer // asymmetric keys
	aesKey      []byte        // symmetric wrapping keys
}

func startFakeVault(t *testing.T) *fakeVault {
	t.Helper()
	f := &fakeVault{
		mount:     "transit",
		roleID:    "test-role-id",
		secretID:  "test-secret-id",
		rootToken: "test-root-token",
		keys:      map[string]*fakeVaultKey{},
		tokens:    map[string]bool{},
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

// expireIssuedTokens invalidates every AppRole-issued token (but not the root
// token), simulating token-TTL expiry so the client's re-login-on-403 path runs.
func (f *fakeVault) expireIssuedTokens() {
	f.mu.Lock()
	f.tokens = map[string]bool{}
	f.mu.Unlock()
}

func (f *fakeVault) validToken(tok string) bool {
	if tok == f.rootToken {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens[tok]
}

func (f *fakeVault) handle(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	loginPath := "/v1/auth/approle/login"
	if r.Method == http.MethodPost && path == loginPath {
		f.handleLogin(w, r)
		return
	}
	// Every other endpoint requires a valid token.
	if !f.validToken(r.Header.Get("X-Vault-Token")) {
		writeVaultError(w, http.StatusForbidden, "permission denied")
		return
	}
	keysPrefix := "/v1/" + f.mount + "/keys/"
	switch {
	case path == "/v1/auth/token/lookup-self":
		writeVaultData(w, map[string]any{"id": r.Header.Get("X-Vault-Token")})
	case path == "/v1/"+f.mount+"/keys" && r.Method == http.MethodGet:
		f.handleList(w)
	case strings.HasPrefix(path, keysPrefix):
		f.handleKey(w, r, strings.TrimPrefix(path, keysPrefix))
	case strings.HasPrefix(path, "/v1/"+f.mount+"/sign/"):
		f.handleSign(w, r, strings.TrimPrefix(path, "/v1/"+f.mount+"/sign/"))
	case strings.HasPrefix(path, "/v1/"+f.mount+"/verify/"):
		f.handleVerify(w, r, strings.TrimPrefix(path, "/v1/"+f.mount+"/verify/"))
	case strings.HasPrefix(path, "/v1/"+f.mount+"/encrypt/"):
		f.handleEncrypt(w, r, strings.TrimPrefix(path, "/v1/"+f.mount+"/encrypt/"))
	case strings.HasPrefix(path, "/v1/"+f.mount+"/decrypt/"):
		f.handleDecrypt(w, r, strings.TrimPrefix(path, "/v1/"+f.mount+"/decrypt/"))
	default:
		writeVaultError(w, http.StatusNotFound, "unsupported path: "+path)
	}
}

func (f *fakeVault) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}
	if err := decodeVaultJSON(r, &body); err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.RoleID != f.roleID || body.SecretID != f.secretID {
		writeVaultError(w, http.StatusBadRequest, "invalid role or secret id")
		return
	}
	f.mu.Lock()
	f.nextID++
	tok := fmt.Sprintf("s.approle-%d", f.nextID)
	f.tokens[tok] = true
	f.mu.Unlock()
	writeVaultJSON(w, http.StatusOK, map[string]any{
		"auth": map[string]any{"client_token": tok, "lease_duration": 3600},
	})
}

func (f *fakeVault) handleList(w http.ResponseWriter) {
	f.mu.Lock()
	names := make([]string, 0, len(f.keys))
	for name := range f.keys {
		names = append(names, name)
	}
	f.mu.Unlock()
	if len(names) == 0 {
		// An empty Transit mount answers 404 to LIST.
		writeVaultError(w, http.StatusNotFound, "no keys")
		return
	}
	writeVaultData(w, map[string]any{"keys": names})
}

func (f *fakeVault) handleKey(w http.ResponseWriter, r *http.Request, name string) {
	switch r.Method {
	case http.MethodPost:
		f.createKey(w, r, name)
	case http.MethodGet:
		f.readKey(w, name)
	default:
		writeVaultError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (f *fakeVault) createKey(w http.ResponseWriter, r *http.Request, name string) {
	var body struct {
		Type string `json:"type"`
	}
	if err := decodeVaultJSON(r, &body); err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.keys[name]; ok {
		// Transit create is idempotent, but our backend checks existence first, so
		// this path is not normally reached; keep it faithful anyway.
		writeVaultData(w, map[string]any{"name": name})
		return
	}
	key, err := generateFakeVaultKey(body.Type)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.keys[name] = key
	writeVaultData(w, map[string]any{"name": name, "type": body.Type})
}

func (f *fakeVault) readKey(w http.ResponseWriter, name string) {
	f.mu.Lock()
	key, ok := f.keys[name]
	f.mu.Unlock()
	if !ok {
		writeVaultError(w, http.StatusNotFound, "no such key")
		return
	}
	versionEntry := map[string]any{"creation_time": "2026-01-01T00:00:00Z"}
	if key.signer != nil {
		der, err := x509.MarshalPKIXPublicKey(key.signer.Public())
		if err != nil {
			writeVaultError(w, http.StatusInternalServerError, err.Error())
			return
		}
		versionEntry["public_key"] = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	writeVaultData(w, map[string]any{
		"name":           name,
		"type":           key.transitType,
		"latest_version": 1,
		"keys":           map[string]any{"1": versionEntry},
	})
}

func (f *fakeVault) handleSign(w http.ResponseWriter, r *http.Request, name string) {
	key, req, ok := f.signKeyAndRequest(w, r, name)
	if !ok {
		return
	}
	digest, err := base64.StdEncoding.DecodeString(req.Input)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, "bad input encoding")
		return
	}
	sig, err := fakeVaultSign(key, req, digest)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeVaultData(w, map[string]any{"signature": "vault:v1:" + base64.StdEncoding.EncodeToString(sig)})
}

func (f *fakeVault) handleVerify(w http.ResponseWriter, r *http.Request, name string) {
	key, req, ok := f.signKeyAndRequest(w, r, name)
	if !ok {
		return
	}
	digest, err := base64.StdEncoding.DecodeString(req.Input)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, "bad input encoding")
		return
	}
	sig, err := decodeVaultPayload(req.Signature)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeVaultData(w, map[string]any{"valid": fakeVaultVerify(key, req, digest, sig)})
}

type fakeSignReq struct {
	Input               string `json:"input"`
	Signature           string `json:"signature"`
	HashAlgorithm       string `json:"hash_algorithm"`
	SignatureAlgorithm  string `json:"signature_algorithm"`
	MarshalingAlgorithm string `json:"marshaling_algorithm"`
	Prehashed           bool   `json:"prehashed"`
}

// signKeyAndRequest loads the named asymmetric key and parses a sign/verify body.
func (f *fakeVault) signKeyAndRequest(w http.ResponseWriter, r *http.Request, name string) (*fakeVaultKey, fakeSignReq, bool) {
	var req fakeSignReq
	if err := decodeVaultJSON(r, &req); err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return nil, req, false
	}
	f.mu.Lock()
	key, ok := f.keys[name]
	f.mu.Unlock()
	if !ok || key.signer == nil {
		writeVaultError(w, http.StatusNotFound, "no such signing key")
		return nil, req, false
	}
	if !req.Prehashed {
		writeVaultError(w, http.StatusBadRequest, "fake vault only supports prehashed input")
		return nil, req, false
	}
	return key, req, true
}

func (f *fakeVault) handleEncrypt(w http.ResponseWriter, r *http.Request, name string) {
	var body struct {
		Plaintext string `json:"plaintext"`
	}
	if err := decodeVaultJSON(r, &body); err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.mu.Lock()
	key, ok := f.keys[name]
	f.mu.Unlock()
	if !ok || key.aesKey == nil {
		writeVaultError(w, http.StatusNotFound, "no such encryption key")
		return
	}
	plaintext, err := base64.StdEncoding.DecodeString(body.Plaintext)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, "bad plaintext encoding")
		return
	}
	ct, err := fakeAESSeal(key.aesKey, plaintext)
	if err != nil {
		writeVaultError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeVaultData(w, map[string]any{"ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString(ct)})
}

func (f *fakeVault) handleDecrypt(w http.ResponseWriter, r *http.Request, name string) {
	var body struct {
		Ciphertext string `json:"ciphertext"`
	}
	if err := decodeVaultJSON(r, &body); err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	f.mu.Lock()
	key, ok := f.keys[name]
	f.mu.Unlock()
	if !ok || key.aesKey == nil {
		writeVaultError(w, http.StatusNotFound, "no such encryption key")
		return
	}
	raw, err := decodeVaultPayload(body.Ciphertext)
	if err != nil {
		writeVaultError(w, http.StatusBadRequest, err.Error())
		return
	}
	plaintext, err := fakeAESOpen(key.aesKey, raw)
	if err != nil {
		// Vault returns 400 for a ciphertext that does not decrypt.
		writeVaultError(w, http.StatusBadRequest, "decryption failed")
		return
	}
	writeVaultData(w, map[string]any{"plaintext": base64.StdEncoding.EncodeToString(plaintext)})
}

// --- fake crypto helpers -----------------------------------------------------

func generateFakeVaultKey(transitType string) (*fakeVaultKey, error) {
	switch transitType {
	case "ecdsa-p256":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return &fakeVaultKey{transitType: transitType, signer: k}, err
	case "ecdsa-p384":
		k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		return &fakeVaultKey{transitType: transitType, signer: k}, err
	case "ecdsa-p521":
		k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		return &fakeVaultKey{transitType: transitType, signer: k}, err
	case "rsa-2048":
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		return &fakeVaultKey{transitType: transitType, signer: k}, err
	case "rsa-4096":
		k, err := rsa.GenerateKey(rand.Reader, 4096)
		return &fakeVaultKey{transitType: transitType, signer: k}, err
	case vaultWrappingKeyType:
		aesKey := make([]byte, 32)
		if _, err := rand.Read(aesKey); err != nil {
			return nil, err
		}
		return &fakeVaultKey{transitType: transitType, aesKey: aesKey}, nil
	default:
		return nil, fmt.Errorf("unsupported transit key type %q", transitType)
	}
}

func fakeHashFromName(name string) (crypto.Hash, error) {
	switch name {
	case "sha2-256":
		return crypto.SHA256, nil
	case "sha2-384":
		return crypto.SHA384, nil
	case "sha2-512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash_algorithm %q", name)
	}
}

func fakeVaultSign(key *fakeVaultKey, req fakeSignReq, digest []byte) ([]byte, error) {
	switch signer := key.signer.(type) {
	case *ecdsa.PrivateKey:
		// marshaling_algorithm "asn1" → ASN.1 DER, matching the backend request.
		return ecdsa.SignASN1(rand.Reader, signer, digest)
	case *rsa.PrivateKey:
		hash, err := fakeHashFromName(req.HashAlgorithm)
		if err != nil {
			return nil, err
		}
		if req.SignatureAlgorithm == "pss" {
			return rsa.SignPSS(rand.Reader, signer, hash, digest, &rsa.PSSOptions{
				SaltLength: rsa.PSSSaltLengthEqualsHash,
				Hash:       hash,
			})
		}
		return rsa.SignPKCS1v15(rand.Reader, signer, hash, digest)
	default:
		return nil, fmt.Errorf("unsupported signer type %T", key.signer)
	}
}

func fakeVaultVerify(key *fakeVaultKey, req fakeSignReq, digest, sig []byte) bool {
	switch pub := key.signer.Public().(type) {
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(pub, digest, sig)
	case *rsa.PublicKey:
		hash, err := fakeHashFromName(req.HashAlgorithm)
		if err != nil {
			return false
		}
		if req.SignatureAlgorithm == "pss" {
			return rsa.VerifyPSS(pub, hash, digest, sig, nil) == nil
		}
		return rsa.VerifyPKCS1v15(pub, hash, digest, sig) == nil
	default:
		return false
	}
}

func fakeAESSeal(aesKey, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return append(nonce, gcm.Seal(nil, nonce, plaintext, nil)...), nil
}

func fakeAESOpen(aesKey, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

func decodeVaultJSON(r *http.Request, out any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	return json.Unmarshal(body, out)
}

func writeVaultJSON(w http.ResponseWriter, status int, payload map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeVaultData(w http.ResponseWriter, data map[string]any) {
	writeVaultJSON(w, http.StatusOK, map[string]any{"data": data})
}

func writeVaultError(w http.ResponseWriter, status int, msgs ...string) {
	writeVaultJSON(w, status, map[string]any{"errors": msgs})
}

// --- tests -------------------------------------------------------------------

// newTokenAuthVault wires a KMSProvider over the Vault Transit backend against a
// fake Vault authenticated with a static token.
func newTokenAuthVault(t *testing.T) (*fakeVault, *KMSProvider) {
	t.Helper()
	fv := startFakeVault(t)
	p, err := NewKMSProvider(KMSSettings{
		Backend:   KMSBackendVault,
		KeyPrefix: "secsy/",
		Vault:     VaultSettings{Address: fv.server.URL, Token: fv.rootToken},
	})
	if err != nil {
		t.Fatalf("NewKMSProvider(vault): %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return fv, p
}

// TestVaultGenerateResolveSign exercises the full signing surface for every
// supported key type: generate, resolve by label, export the public key, and sign
// a digest that verifies against the exported public half.
func TestVaultGenerateResolveSign(t *testing.T) {
	ctx := context.Background()
	for _, keyType := range []string{
		KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeECDSAP521, KeyTypeRSA2048, KeyTypeRSA4096,
	} {
		t.Run(keyType, func(t *testing.T) {
			_, p := newTokenAuthVault(t)
			label := "role-" + keyType

			gen, err := p.GenerateKey(ctx, KeySpec{Label: label, KeyType: keyType})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if gen.KeyType != keyType {
				t.Errorf("KeyType = %q, want %q", gen.KeyType, keyType)
			}
			if gen.PublicKey == nil {
				t.Fatal("nil public key")
			}
			if !strings.HasPrefix(gen.URI, "kms:vault:") {
				t.Errorf("URI = %q, want kms:vault: prefix", gen.URI)
			}

			found, err := p.FindKey(ctx, KeyRef{Label: label})
			if err != nil {
				t.Fatalf("FindKey: %v", err)
			}
			if found.URI != gen.URI {
				t.Errorf("FindKey URI = %q, want %q", found.URI, gen.URI)
			}

			signer, err := p.Signer(ctx, KeyRef{Label: label})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			defer signer.Close()

			hash := hashForKeyType(keyType)
			digest := digestFor(hash, []byte("hello vault transit"))
			sig, err := signer.Sign(rand.Reader, digest, hash)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			verifyDigestHash(t, gen.PublicKey, hash, digest, sig, false)
		})
	}
}

// TestVaultSignRSAPSS confirms RSA-PSS is selected when the caller passes
// *rsa.PSSOptions, exercising the pss branch through the Transit sign endpoint.
func TestVaultSignRSAPSS(t *testing.T) {
	ctx := context.Background()
	_, p := newTokenAuthVault(t)
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "pss", KeyType: KeyTypeRSA2048}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := p.Signer(ctx, KeyRef{Label: "pss"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	defer signer.Close()

	digest := sha256.Sum256([]byte("pss message"))
	sig, err := signer.Sign(rand.Reader, digest[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256,
	})
	if err != nil {
		t.Fatalf("Sign PSS: %v", err)
	}
	verifyDigest(t, signer.Public(), digest[:], sig, true)
}

// TestVaultVerifyEndpoint checks that Vault's own /transit/verify endpoint agrees
// with a locally-produced signature (the Sign/Verify interop the task requires).
func TestVaultVerifyEndpoint(t *testing.T) {
	ctx := context.Background()
	fv, p := newTokenAuthVault(t)
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "verify-key", KeyType: KeyTypeECDSAP256}); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	signer, err := p.Signer(ctx, KeyRef{Label: "verify-key"})
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	defer signer.Close()
	digest := sha256.Sum256([]byte("verify me"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	backend := newVaultBackend(t, fv)
	ok, err := backend.Verify(ctx, backend.keyName("verify-key"), KeyTypeECDSAP256, digest[:], sig, crypto.SHA256, false)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("vault verify reported a valid signature as invalid")
	}
	// A tampered signature must not verify.
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0xff
	if ok, _ := backend.Verify(ctx, backend.keyName("verify-key"), KeyTypeECDSAP256, digest[:], bad, crypto.SHA256, false); ok {
		t.Fatal("vault verify accepted a tampered signature")
	}
}

// TestVaultSignsX509Certificate is the end-to-end guarantee for the CA/TSA/OCSP
// roles: a certificate signed through the Vault signer verifies against the Vault
// public key using the real x509 signing path — the same guarantee openssl
// provides for the documented interop.
func TestVaultSignsX509Certificate(t *testing.T) {
	ctx := context.Background()
	for _, keyType := range []string{KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeRSA2048} {
		t.Run(keyType, func(t *testing.T) {
			_, p := newTokenAuthVault(t)
			if _, err := p.GenerateKey(ctx, KeySpec{Label: "ca", KeyType: keyType}); err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			signer, err := p.Signer(ctx, KeyRef{Label: "ca"})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			defer signer.Close()

			tmpl := &x509.Certificate{
				SerialNumber:          big.NewInt(1),
				Subject:               pkix.Name{CommonName: "Vault Transit Root CA"},
				NotBefore:             time.Now().Add(-time.Hour),
				NotAfter:              time.Now().Add(24 * time.Hour),
				IsCA:                  true,
				BasicConstraintsValid: true,
				KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
			if err != nil {
				t.Fatalf("CreateCertificate: %v", err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatalf("ParseCertificate: %v", err)
			}
			if err := cert.CheckSignatureFrom(cert); err != nil {
				t.Fatalf("self-signature verification failed: %v", err)
			}
		})
	}
}

// TestVaultWrapUnwrap exercises the KEK wrap/unwrap path (transit encrypt/decrypt):
// generate a symmetric KEK, wrap a DEK, unwrap it, and confirm the round-trip.
func TestVaultWrapUnwrap(t *testing.T) {
	ctx := context.Background()
	_, p := newTokenAuthVault(t)
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "kek", Usage: KeyUsageDecrypt}); err != nil {
		t.Fatalf("GenerateKey(KEK): %v", err)
	}
	ref := KeyRef{Label: "kek"}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := p.WrapKey(ctx, ref, dek)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if !strings.HasPrefix(string(ciphertext), "vault:v1:") {
		t.Errorf("ciphertext = %q, want vault:v1: prefix", ciphertext)
	}
	recovered, err := p.UnwrapKey(ctx, ref, ciphertext)
	if err != nil {
		t.Fatalf("UnwrapKey: %v", err)
	}
	if !subtleBytesEqual(recovered, dek) {
		t.Fatal("unwrapped DEK does not match the original")
	}

	// A tampered ciphertext must fail to unwrap.
	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := p.UnwrapKey(ctx, ref, tampered); err == nil {
		t.Fatal("expected unwrap of tampered ciphertext to fail")
	}
}

// TestVaultWrapUnsupportedBackend confirms non-Vault KMS backends report
// ErrWrapUnsupported rather than pretending to wrap.
func TestVaultWrapUnsupportedBackend(t *testing.T) {
	ctx := context.Background()
	p := newFakeKMSProvider(t)
	if _, err := p.WrapKey(ctx, KeyRef{Label: "x"}, []byte("dek")); err != ErrWrapUnsupported {
		t.Errorf("WrapKey err = %v, want ErrWrapUnsupported", err)
	}
	if _, err := p.UnwrapKey(ctx, KeyRef{Label: "x"}, []byte("ct")); err != ErrWrapUnsupported {
		t.Errorf("UnwrapKey err = %v, want ErrWrapUnsupported", err)
	}
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "kek", Usage: KeyUsageDecrypt}); err == nil {
		t.Error("expected fake KMS backend to reject a KEK (decrypt) key")
	}
}

// TestVaultInstrumentedWrap confirms the instrumented wrapper preserves the
// KeyWrapper capability (so metrics are recorded) and forwards Prober/KeyLister.
func TestVaultInstrumentedWrap(t *testing.T) {
	ctx := context.Background()
	_, p := newTokenAuthVault(t)
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "kek", Usage: KeyUsageDecrypt}); err != nil {
		t.Fatalf("GenerateKey(KEK): %v", err)
	}
	inst := Instrument(p)
	kw, ok := inst.(KeyWrapper)
	if !ok {
		t.Fatal("instrumented vault provider does not expose KeyWrapper")
	}
	ct, err := kw.WrapKey(ctx, KeyRef{Label: "kek"}, []byte("data-key-material"))
	if err != nil {
		t.Fatalf("instrumented WrapKey: %v", err)
	}
	pt, err := kw.UnwrapKey(ctx, KeyRef{Label: "kek"}, ct)
	if err != nil {
		t.Fatalf("instrumented UnwrapKey: %v", err)
	}
	if string(pt) != "data-key-material" {
		t.Errorf("round-trip = %q, want original", pt)
	}
	if _, ok := inst.(Prober); !ok {
		t.Error("instrumented vault provider lost Prober")
	}
	if _, ok := inst.(KeyLister); !ok {
		t.Error("instrumented vault provider lost KeyLister")
	}
}

// TestVaultListKeys checks the inventory surface reports Vault keys as
// non-extractable and sensitive — the Transit trust boundary.
func TestVaultListKeys(t *testing.T) {
	ctx := context.Background()
	_, p := newTokenAuthVault(t)
	for _, l := range []string{"ca", "tsa", "ocsp"} {
		if _, err := p.GenerateKey(ctx, KeySpec{Label: l, KeyType: KeyTypeECDSAP256}); err != nil {
			t.Fatalf("GenerateKey %s: %v", l, err)
		}
	}
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "kek", Usage: KeyUsageDecrypt}); err != nil {
		t.Fatalf("GenerateKey KEK: %v", err)
	}
	keys, err := p.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 4 {
		t.Fatalf("ListKeys returned %d keys, want 4", len(keys))
	}
	for _, k := range keys {
		if k.Extractable {
			t.Errorf("key %q reported Extractable=true; Vault Transit keys must be non-extractable", k.Label)
		}
		if !k.Sensitive {
			t.Errorf("key %q reported Sensitive=false", k.Label)
		}
	}
}

// TestVaultPing confirms the provider satisfies Prober and the probe reaches the
// fake Vault's token/lookup-self endpoint through the instrumented wrapper.
func TestVaultPing(t *testing.T) {
	ctx := context.Background()
	_, p := newTokenAuthVault(t)
	if err := p.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	prober, ok := Instrument(p).(Prober)
	if !ok {
		t.Fatal("instrumented vault provider does not expose Prober")
	}
	if err := prober.Ping(ctx); err != nil {
		t.Fatalf("instrumented Ping: %v", err)
	}
}

// TestVaultAppRoleAuthAndReLogin verifies AppRole login works and, crucially, that
// an expired client token transparently triggers a single re-login and retry.
func TestVaultAppRoleAuthAndReLogin(t *testing.T) {
	ctx := context.Background()
	fv := startFakeVault(t)
	p, err := NewKMSProvider(KMSSettings{
		Backend:   KMSBackendVault,
		KeyPrefix: "secsy/",
		Vault: VaultSettings{
			Address:    fv.server.URL,
			AuthMethod: vaultAuthAppRole,
			RoleID:     fv.roleID,
			SecretID:   fv.secretID,
		},
	})
	if err != nil {
		t.Fatalf("NewKMSProvider(approle): %v", err)
	}
	t.Cleanup(func() { p.Close() })

	if _, err := p.GenerateKey(ctx, KeySpec{Label: "approle-key", KeyType: KeyTypeECDSAP256}); err != nil {
		t.Fatalf("GenerateKey (initial login): %v", err)
	}
	// Simulate token TTL expiry: the cached client token is now rejected, so the
	// next operation must re-login via AppRole and succeed on retry.
	fv.expireIssuedTokens()
	if _, err := p.FindKey(ctx, KeyRef{Label: "approle-key"}); err != nil {
		t.Fatalf("FindKey after token expiry (expected transparent re-login): %v", err)
	}
}

// TestVaultDuplicateLabelRejected mirrors the provider contract: a second key with
// an existing label is an error.
func TestVaultDuplicateLabelRejected(t *testing.T) {
	ctx := context.Background()
	_, p := newTokenAuthVault(t)
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "dup", KeyType: KeyTypeECDSAP256}); err != nil {
		t.Fatalf("first GenerateKey: %v", err)
	}
	if _, err := p.GenerateKey(ctx, KeySpec{Label: "dup", KeyType: KeyTypeECDSAP256}); err == nil {
		t.Fatal("expected duplicate label to be rejected")
	}
}

// TestVaultRejectsUnsupportedKeyType confirms Ed25519 and PQC are rejected before
// any Vault call (the abstraction stays uniform with the other KMS backends).
func TestVaultRejectsUnsupportedKeyType(t *testing.T) {
	ctx := context.Background()
	_, p := newTokenAuthVault(t)
	for _, kt := range []string{KeyTypeEd25519, KeyTypeMLDSA65} {
		if _, err := p.GenerateKey(ctx, KeySpec{Label: "x-" + kt, KeyType: kt}); err == nil {
			t.Errorf("GenerateKey(%s) unexpectedly succeeded", kt)
		}
	}
}

// TestVaultFindNotFound checks the ErrKeyNotFound contract.
func TestVaultFindNotFound(t *testing.T) {
	ctx := context.Background()
	_, p := newTokenAuthVault(t)
	if _, err := p.FindKey(ctx, KeyRef{Label: "nope"}); err == nil {
		t.Fatal("expected error for missing key")
	}
}

// TestVaultAuthFailure confirms an invalid token surfaces as a probe failure.
func TestVaultAuthFailure(t *testing.T) {
	ctx := context.Background()
	fv := startFakeVault(t)
	p, err := NewKMSProvider(KMSSettings{
		Backend: KMSBackendVault,
		Vault:   VaultSettings{Address: fv.server.URL, Token: "wrong-token"},
	})
	if err != nil {
		t.Fatalf("NewKMSProvider: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	if err := p.Ping(ctx); err == nil {
		t.Fatal("expected Ping with an invalid token to fail")
	}
}

// TestVaultClientConfigErrors covers the construction-time validation.
func TestVaultClientConfigErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  VaultSettings
	}{
		{"no address", VaultSettings{Token: "t"}},
		{"token auth without token", VaultSettings{Address: "https://v:8200"}},
		{"approle without role", VaultSettings{Address: "https://v:8200", AuthMethod: "approle", SecretID: "s"}},
		{"unknown auth", VaultSettings{Address: "https://v:8200", AuthMethod: "ldap"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newVaultTransitBackend(KMSSettings{Vault: tc.cfg}); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// newVaultBackend returns the raw *vaultTransitBackend for a fake Vault, used by
// tests that call Vault-specific methods (Verify) not on the Provider interface.
func newVaultBackend(t *testing.T, fv *fakeVault) *vaultTransitBackend {
	t.Helper()
	b, err := newVaultTransitBackend(KMSSettings{
		KeyPrefix: "secsy/",
		Vault:     VaultSettings{Address: fv.server.URL, Token: fv.rootToken},
	})
	if err != nil {
		t.Fatalf("newVaultTransitBackend: %v", err)
	}
	return b.(*vaultTransitBackend)
}

// --- shared digest/verify helpers --------------------------------------------

func hashForKeyType(keyType string) crypto.Hash {
	switch keyType {
	case KeyTypeECDSAP384:
		return crypto.SHA384
	case KeyTypeECDSAP521:
		return crypto.SHA512
	default:
		return crypto.SHA256
	}
}

func digestFor(hash crypto.Hash, msg []byte) []byte {
	h := hash.New()
	h.Write(msg)
	return h.Sum(nil)
}

// verifyDigestHash is verifyDigest for an arbitrary hash (P-384/P-521 use
// SHA-384/512), dispatching by key family.
func verifyDigestHash(t *testing.T, pub crypto.PublicKey, hash crypto.Hash, digest, sig []byte, pss bool) {
	t.Helper()
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest, sig) {
			t.Fatal("ECDSA signature failed verification")
		}
	case *rsa.PublicKey:
		if pss {
			if err := rsa.VerifyPSS(key, hash, digest, sig, nil); err != nil {
				t.Fatalf("RSA-PSS verification failed: %v", err)
			}
		} else if err := rsa.VerifyPKCS1v15(key, hash, digest, sig); err != nil {
			t.Fatalf("RSA PKCS1v15 verification failed: %v", err)
		}
	default:
		t.Fatalf("unexpected public key type %T", pub)
	}
}

func subtleBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
