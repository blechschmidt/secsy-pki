//go:build sqlite

package chaos

// Scenario 3 — HSM authentication and crypto-parameter faults. Requires SoftHSM.
//
//   - TestChaosWrongPINFailsClosed points a provider at a valid token with the
//     wrong PIN and asserts every key operation fails cleanly: no key is created
//     (no partial state) and the correct-PIN path keeps working, so a bad
//     credential degrades to "no service" rather than "wrong service".
//
//   - TestChaosOAEPHashMismatchFailsClosed provisions an RSA KEK on the token
//     and asserts the fail-closed property of the envelope-unwrap path: an
//     OAEP ciphertext decrypted under the wrong hash never yields the original
//     plaintext (it errors or returns garbage), while the hash the token
//     actually supports round-trips exactly. This is the invariant the Task 7
//     secret layer's hash negotiation relies on (SoftHSM is RSA-OAEP SHA-1 only).

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 is the only OAEP hash SoftHSM supports; used deliberately.
	"crypto/sha256"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

func TestChaosWrongPINFailsClosed(t *testing.T) {
	module, pin, soPin := softHSMTokenTooling(t)

	label := "chaos-pin-" + randSuffix(t)
	initToken(t, label, pin, soPin)
	t.Cleanup(func() { deleteToken(label) })

	newProvider := func(usePin string) *keyprovider.PKCS11Provider {
		p, err := keyprovider.NewPKCS11Provider(keyprovider.PKCS11Settings{
			ModulePath:      module,
			Pin:             usePin,
			TokenLabel:      label,
			SessionPoolSize: 1, // one login attempt only — never risk locking the token
		})
		if err != nil {
			t.Fatalf("NewPKCS11Provider: %v", err)
		}
		t.Cleanup(func() { p.Close() })
		return p
	}

	ctx := context.Background()

	// The wrong PIN must fail closed. This runs FIRST, before any correct login
	// exists on this fresh token: SoftHSM's login state is per-application, so a
	// correct-PIN session opened earlier in the same process would mask a later
	// wrong-PIN login (it returns CKR_USER_ALREADY_LOGGED_IN). Attempting the bad
	// PIN on a token with no prior login exercises the genuine C_Login rejection.
	bad := newProvider("000000")
	victimLabel := "chaos-pin-victim-" + randSuffix(t)
	if _, err := bad.GenerateKey(ctx, keyprovider.KeySpec{
		Label:   victimLabel,
		KeyType: keyprovider.KeyTypeECDSAP256,
		Usage:   keyprovider.KeyUsageSign,
	}); err == nil {
		t.Fatal("GenerateKey with the wrong PIN succeeded; want a login failure")
	}
	bad.Close()

	// The token works with the correct PIN: a marker signing key is created, and
	// the victim key from the failed attempt must not exist (no partial state).
	good := newProvider(pin)
	markerLabel := "chaos-pin-marker-" + randSuffix(t)
	if _, err := good.GenerateKey(ctx, keyprovider.KeySpec{
		Label:   markerLabel,
		KeyType: keyprovider.KeyTypeECDSAP256,
		Usage:   keyprovider.KeyUsageSign,
	}); err != nil {
		t.Fatalf("GenerateKey (correct PIN): %v", err)
	}

	keys, err := good.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	for _, k := range keys {
		if k.Label == victimLabel {
			t.Fatalf("wrong-PIN GenerateKey left a key %q on the token (partial state)", victimLabel)
		}
	}

	// The correct-PIN path is unharmed by the failed attempt.
	signer, err := good.Signer(ctx, keyprovider.KeyRef{Label: markerLabel})
	if err != nil {
		t.Fatalf("Signer (correct PIN, post-fault): %v", err)
	}
	defer signer.Close()
	digest := sha256.Sum256([]byte("post-fault"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("Sign (correct PIN, post-fault): %v", err)
	}
}

func TestChaosOAEPHashMismatchFailsClosed(t *testing.T) {
	module, pin := softHSM(t)
	token := envOr("SECSY_TOKEN_LABEL", "")
	if token == "" {
		t.Skip("SECSY_TOKEN_LABEL not set")
	}

	pool, err := pki.NewSessionPool(pki.PKCS11Config{ModulePath: module, Pin: pin, TokenLabel: token}, 2)
	if err != nil {
		t.Fatalf("NewSessionPool: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })

	ctx := context.Background()
	label := "chaos-kek-" + randSuffix(t)
	if _, err := pool.GenerateRSAKEK(ctx, label, 2048); err != nil {
		t.Fatalf("GenerateRSAKEK: %v", err)
	}
	rawPub, _, _, err := pool.PublicKey(ctx, label)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	pub, ok := rawPub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("KEK public key type %T, want *rsa.PublicKey", rawPub)
	}

	probe := make([]byte, 32)
	if _, err := rand.Read(probe); err != nil {
		t.Fatal(err)
	}

	// oaep wraps the probe under the named OAEP hash on the host.
	oaep := func(h crypto.Hash) []byte {
		var (
			b   []byte
			err error
		)
		switch h {
		case crypto.SHA256:
			b, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, probe, nil)
		case crypto.SHA1:
			b, err = rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, probe, nil)
		default:
			t.Fatalf("unsupported test hash %v", h)
		}
		if err != nil {
			t.Fatalf("EncryptOAEP(%v): %v", h, err)
		}
		return b
	}

	// Find the hash the token actually supports by round-tripping each. On
	// SoftHSM this is SHA-1; on a richer HSM it may also be SHA-256.
	supported := crypto.Hash(0)
	for _, h := range []crypto.Hash{crypto.SHA256, crypto.SHA1} {
		out, derr := pool.Decrypt(ctx, label, oaep(h), &rsa.OAEPOptions{Hash: h})
		if derr == nil && string(out) == string(probe) {
			supported = h
			break
		}
	}
	if supported == 0 {
		t.Fatal("token could not RSA-OAEP unwrap with SHA-256 or SHA-1")
	}
	t.Logf("token supports RSA-OAEP with %v", supported)

	// Fail-closed invariant: decrypting a ciphertext wrapped under the supported
	// hash with the WRONG hash must never return the plaintext. It either errors
	// or yields garbage — but it must not silently succeed.
	wrong := crypto.SHA1
	if supported == crypto.SHA1 {
		wrong = crypto.SHA256
	}
	ct := oaep(supported)
	out, derr := pool.Decrypt(ctx, label, ct, &rsa.OAEPOptions{Hash: wrong})
	if derr == nil && string(out) == string(probe) {
		t.Fatalf("OAEP hash mismatch (%v ciphertext, %v opts) returned the plaintext; must fail closed", supported, wrong)
	}

	// And the supported hash still round-trips exactly (the negotiated path).
	out, derr = pool.Decrypt(ctx, label, ct, &rsa.OAEPOptions{Hash: supported})
	if derr != nil {
		t.Fatalf("Decrypt with supported hash %v: %v", supported, derr)
	}
	if string(out) != string(probe) {
		t.Fatalf("Decrypt with supported hash %v returned wrong plaintext", supported)
	}
}
