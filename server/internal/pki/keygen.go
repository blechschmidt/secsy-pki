package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

type KeyGenParams struct {
	KeyType string
	Bits    int
	Comment string
}

type GeneratedKey struct {
	PrivateKeyPEM string
	PublicKeySSH  string
}

func GenerateKey(params KeyGenParams) (*GeneratedKey, error) {
	switch params.KeyType {
	case "rsa":
		return generateRSA(params)
	case "ecdsa":
		return generateECDSA(params)
	case "ed25519":
		return generateEd25519(params)
	default:
		return nil, fmt.Errorf("unsupported key type: %s (supported: rsa, ecdsa, ed25519)", params.KeyType)
	}
}

func generateRSA(params KeyGenParams) (*GeneratedKey, error) {
	bits := params.Bits
	if bits == 0 {
		bits = 4096
	}
	// 2048 bits is the current minimum for RSA (NIST SP 800-57 / CA-Browser
	// Forum); 1024-bit keys are deprecated and rejected.
	if bits < 2048 {
		return nil, fmt.Errorf("RSA key size must be at least 2048 bits")
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generating RSA key: %w", err)
	}

	privPEM, err := ssh.MarshalPrivateKey(key, params.Comment)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("creating SSH public key: %w", err)
	}

	pubStr := string(ssh.MarshalAuthorizedKey(pub))
	if params.Comment != "" {
		pubStr = pubStr[:len(pubStr)-1] + " " + params.Comment + "\n"
	}

	return &GeneratedKey{
		PrivateKeyPEM: string(pem.EncodeToMemory(privPEM)),
		PublicKeySSH:  pubStr,
	}, nil
}

func generateECDSA(params KeyGenParams) (*GeneratedKey, error) {
	bits := params.Bits
	if bits == 0 {
		bits = 256
	}

	var curve elliptic.Curve
	switch bits {
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("ECDSA key size must be 256, 384, or 521")
	}

	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA key: %w", err)
	}

	privPEM, err := ssh.MarshalPrivateKey(key, params.Comment)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("creating SSH public key: %w", err)
	}

	pubStr := string(ssh.MarshalAuthorizedKey(pub))
	if params.Comment != "" {
		pubStr = pubStr[:len(pubStr)-1] + " " + params.Comment + "\n"
	}

	return &GeneratedKey{
		PrivateKeyPEM: string(pem.EncodeToMemory(privPEM)),
		PublicKeySSH:  pubStr,
	}, nil
}

func generateEd25519(params KeyGenParams) (*GeneratedKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating Ed25519 key: %w", err)
	}

	privPEM, err := ssh.MarshalPrivateKey(priv, params.Comment)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("creating SSH public key: %w", err)
	}

	pubStr := string(ssh.MarshalAuthorizedKey(sshPub))
	if params.Comment != "" {
		pubStr = pubStr[:len(pubStr)-1] + " " + params.Comment + "\n"
	}

	return &GeneratedKey{
		PrivateKeyPEM: string(pem.EncodeToMemory(privPEM)),
		PublicKeySSH:  pubStr,
	}, nil
}
