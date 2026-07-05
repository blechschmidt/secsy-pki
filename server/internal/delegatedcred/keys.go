package delegatedcred

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// equalKey is implemented by the standard-library public key types (Go 1.15+),
// giving a constant-time-ish structural comparison.
type equalKey interface {
	Equal(x crypto.PublicKey) bool
}

// publicKeyMatches reports whether two public keys are the same key, falling back
// to a DER SubjectPublicKeyInfo comparison when the Equal method is unavailable.
func publicKeyMatches(a, b crypto.PublicKey) error {
	if ek, ok := a.(equalKey); ok {
		if ek.Equal(b) {
			return nil
		}
		return errors.New("public keys differ")
	}
	ad, err1 := x509.MarshalPKIXPublicKey(a)
	bd, err2 := x509.MarshalPKIXPublicKey(b)
	if err1 != nil || err2 != nil || !bytes.Equal(ad, bd) {
		return errors.New("public keys differ")
	}
	return nil
}

// GenerateKey generates a fresh delegated-credential keypair of the named type.
// Supported types: ecdsa-p256 (default when empty), ecdsa-p384, ecdsa-p521,
// rsa-2048, rsa-3072, rsa-4096, ed25519. The returned signer's public key is a
// valid delegated key (its scheme is derivable by SchemeForKey).
func GenerateKey(keyType string) (crypto.Signer, error) {
	switch strings.ToLower(strings.TrimSpace(keyType)) {
	case "", "ecdsa-p256", "ecdsa", "p256":
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa-p384", "p384":
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ecdsa-p521", "p521":
		return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "rsa-2048", "rsa":
		return rsa.GenerateKey(rand.Reader, 2048)
	case "rsa-3072":
		return rsa.GenerateKey(rand.Reader, 3072)
	case "rsa-4096":
		return rsa.GenerateKey(rand.Reader, 4096)
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("delegatedcred: unsupported key type %q", keyType)
	}
}

// ParsePrivateKeyDER parses a private key from DER, trying PKCS#8 (the form the
// PKCS#12 escrow path stores), then SEC1 EC, then PKCS#1 RSA. The result is
// returned as a crypto.Signer; a non-signing key type is rejected.
func ParsePrivateKeyDER(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return asSigner(key)
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("delegatedcred: unrecognized private key DER (want PKCS#8, SEC1 EC, or PKCS#1)")
}

// ParsePrivateKeyPEM parses a PEM-encoded private key (PKCS#8 "PRIVATE KEY",
// SEC1 "EC PRIVATE KEY", or PKCS#1 "RSA PRIVATE KEY"). It is the loader the CLI
// uses for an operator-supplied leaf key.
func ParsePrivateKeyPEM(pemBytes []byte) (crypto.Signer, error) {
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if !strings.Contains(block.Type, "PRIVATE KEY") {
			continue
		}
		return ParsePrivateKeyDER(block.Bytes)
	}
	return nil, errors.New("delegatedcred: no private-key PEM block found")
}

// asSigner narrows a parsed key to crypto.Signer, rejecting types that cannot
// sign (e.g. an X25519 key).
func asSigner(key any) (crypto.Signer, error) {
	if s, ok := key.(crypto.Signer); ok {
		return s, nil
	}
	return nil, fmt.Errorf("delegatedcred: private key of type %T cannot sign", key)
}
