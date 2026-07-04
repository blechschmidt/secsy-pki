package keyprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// requireSoftHSM skips a test unless the ambient SoftHSM environment is available
// (the same one setup-softhsm.sh --export-env exports), returning the module path
// and PINs. It mirrors the guards in pkcs11_ha_softhsm_test.go.
func requireSoftHSM(t *testing.T) (module, pin, soPin string) {
	t.Helper()
	module = os.Getenv("SECSY_PKCS11_MODULE")
	if module == "" {
		t.Skip("SoftHSM not configured: set SECSY_PKCS11_MODULE (run: eval \"$(scripts/setup-softhsm.sh --export-env)\")")
	}
	if os.Getenv("SOFTHSM2_CONF") == "" {
		t.Skip("SOFTHSM2_CONF not set; cannot create test tokens (run setup-softhsm.sh --export-env)")
	}
	if _, err := exec.LookPath("softhsm2-util"); err != nil {
		t.Skip("softhsm2-util not found on PATH")
	}
	return module, envOr("SECSY_USER_PIN", "1234"), envOr("SECSY_SO_PIN", "5678")
}

// importKeyWithID imports a PKCS#8 EC key into a token under a chosen CKA_LABEL
// and CKA_ID (hex). softhsm2-util interprets --id as hex.
func importKeyWithID(t *testing.T, keyPath, tokenLabel, keyLabel, idHex, pin string) {
	t.Helper()
	cmd := exec.Command("softhsm2-util", "--import", keyPath,
		"--token", tokenLabel, "--label", keyLabel, "--id", idHex, "--pin", pin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("importing key (label %q id %q): %v\n%s", keyLabel, idHex, err, out)
	}
}

// writeECKey generates a P-256 key, writes it as a PKCS#8 PEM file, and returns
// the path and the public half for signature verification.
func writeECKey(t *testing.T) (path string, pub *ecdsa.PublicKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling PKCS#8: %v", err)
	}
	path = filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}
	return path, &priv.PublicKey
}

func signVerify(t *testing.T, p Provider, ref KeyRef, pub *ecdsa.PublicKey) error {
	t.Helper()
	ctx := context.Background()
	signer, err := p.Signer(ctx, ref)
	if err != nil {
		return err
	}
	defer signer.Close()
	// The signer's public key must be the imported key's public half.
	got, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || got.X.Cmp(pub.X) != 0 || got.Y.Cmp(pub.Y) != 0 {
		t.Fatalf("signer public key does not match the imported key")
	}
	digest := sha256.Sum256([]byte("secsy-pki rfc7512 resolution test"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatalf("signature failed verification")
	}
	return nil
}

// TestPKCS11URIResolutionSoftHSM is the SoftHSM-backed acceptance test for
// RFC 7512 key addressing: it imports one EC key under a known CKA_LABEL and
// CKA_ID, then resolves and uses it three ways — by object= label, by id= CKA_ID
// alone, and by the (object, id) pair — proving the keyprovider now honors CKA_ID
// addressing rather than only CKA_LABEL. It also confirms an id-addressed FindKey
// reports the real label, and that a wrong CKA_ID is a clean not-found.
func TestPKCS11URIResolutionSoftHSM(t *testing.T) {
	module, pin, soPin := requireSoftHSM(t)

	suffix := randSuffix(t)
	tokenLabel := "uri-tok-" + suffix
	keyLabel := "uri-key-" + suffix
	const idHex = "a1b2c3"

	initToken(t, tokenLabel, pin, soPin)
	t.Cleanup(func() { deleteToken(tokenLabel) })

	keyPath, pub := writeECKey(t)
	importKeyWithID(t, keyPath, tokenLabel, keyLabel, idHex, pin)

	p, err := NewPKCS11Provider(PKCS11Settings{ModulePath: module, Pin: pin, TokenLabel: tokenLabel})
	if err != nil {
		t.Fatalf("NewPKCS11Provider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	ctx := context.Background()

	// 1. By object= label (the historical addressing).
	labelRef, err := KeyRefFromURI("pkcs11:object=" + keyLabel + ";type=private")
	if err != nil {
		t.Fatalf("KeyRefFromURI(label): %v", err)
	}
	if err := signVerify(t, p, labelRef, pub); err != nil {
		t.Fatalf("resolution by label failed: %v", err)
	}

	// 2. By id= CKA_ID alone — the new capability.
	idRef, err := KeyRefFromURI("pkcs11:id=%a1%b2%c3;type=private")
	if err != nil {
		t.Fatalf("KeyRefFromURI(id): %v", err)
	}
	if idRef.Label != "" || idRef.ID != idHex {
		t.Fatalf("id ref = %+v, want ID=%s only", idRef, idHex)
	}
	if err := signVerify(t, p, idRef, pub); err != nil {
		t.Fatalf("resolution by CKA_ID failed: %v", err)
	}

	// An id-addressed FindKey reports the object's real label and id.
	info, err := p.FindKey(ctx, idRef)
	if err != nil {
		t.Fatalf("FindKey by id: %v", err)
	}
	if info.Label != keyLabel || info.ID != idHex {
		t.Errorf("FindKey by id = label %q id %q, want %q / %s", info.Label, info.ID, keyLabel, idHex)
	}

	// 3. By the (object, id) pair — both constraints must match the same object.
	pairRef, err := KeyRefFromURI("pkcs11:object=" + keyLabel + ";id=%a1%b2%c3;type=private")
	if err != nil {
		t.Fatalf("KeyRefFromURI(pair): %v", err)
	}
	if err := signVerify(t, p, pairRef, pub); err != nil {
		t.Fatalf("resolution by (label,id) failed: %v", err)
	}

	// A wrong CKA_ID is a clean not-found, not an opaque error.
	wrongRef, _ := KeyRefFromURI("pkcs11:id=%ff%ff%ff;type=private")
	if _, err := p.FindKey(ctx, wrongRef); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("FindKey with wrong id = %v, want ErrKeyNotFound", err)
	}
}

// TestPKCS11URITokenPinningSoftHSM proves RFC 7512 token addressing routes an
// operation to a specific token in a high-availability set: with the key present
// on only one of two tokens, pinning by that token's serial resolves the key,
// pinning by the other token's serial is a clean not-found (the operation was NOT
// allowed to fall through to the token that holds the key), and pinning by a
// serial no token has fails closed.
func TestPKCS11URITokenPinningSoftHSM(t *testing.T) {
	module, pin, soPin := requireSoftHSM(t)

	suffix := randSuffix(t)
	labelA := "pin-tokA-" + suffix
	labelB := "pin-tokB-" + suffix
	keyLabel := "pin-key-" + suffix

	initToken(t, labelA, pin, soPin)
	initToken(t, labelB, pin, soPin)
	t.Cleanup(func() { deleteToken(labelA) })
	t.Cleanup(func() { deleteToken(labelB) })

	// Import the key onto token B only; token A is a reachable but keyless token.
	keyPath, pub := writeECKey(t)
	importKeyWithID(t, keyPath, labelB, keyLabel, "b0", pin)

	p, err := NewPKCS11HAProvider(PKCS11Settings{
		ModulePath:       module,
		Pin:              pin,
		SelectionPolicy:  string(PolicyPrimaryBackup),
		FailureThreshold: 2,
		ProbeInterval:    time.Hour, // no background flapping during the test
		Tokens: []TokenSettings{
			{Name: "A", TokenLabel: labelA},
			{Name: "B", TokenLabel: labelB},
		},
	})
	if err != nil {
		t.Fatalf("NewPKCS11HAProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })

	ctx := context.Background()
	// Build every member's session pool so each token's actual serial is known,
	// making serial pinning exact rather than best-effort.
	_ = p.Ping(ctx)

	serialA := p.members[0].identity().serial
	serialB := p.members[1].identity().serial
	if serialA == "" || serialB == "" || serialA == serialB {
		t.Fatalf("token serials not distinct/known: A=%q B=%q", serialA, serialB)
	}

	// Pin to token B (which holds the key) by its serial → resolves and signs.
	refB := KeyRef{Label: keyLabel, Token: TokenSelector{Serial: serialB}}
	if err := signVerify(t, p, refB, pub); err != nil {
		t.Fatalf("pinning to the token holding the key failed: %v", err)
	}

	// Pin to token A (keyless) by its serial → not found. The operation must NOT
	// fall through to token B, proving the selector restricts routing.
	refA := KeyRef{Label: keyLabel, Token: TokenSelector{Serial: serialA}}
	if _, err := p.FindKey(ctx, refA); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("pinning to the keyless token = %v, want ErrKeyNotFound (no fall-through)", err)
	}

	// Pin to a serial no token has → fails closed with a clear error.
	refNone := KeyRef{Label: keyLabel, Token: TokenSelector{Serial: "no-such-serial"}}
	if _, err := p.FindKey(ctx, refNone); err == nil {
		t.Error("pinning to a nonexistent serial unexpectedly succeeded")
	}

	// Without a pin the key resolves via failover to whichever token holds it.
	if err := signVerify(t, p, KeyRef{Label: keyLabel}, pub); err != nil {
		t.Errorf("unpinned resolution failed: %v", err)
	}
}
