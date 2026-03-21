package pki

import (
	"strings"
	"testing"
)

func TestGenerateKeyEd25519(t *testing.T) {
	result, err := GenerateKey(KeyGenParams{KeyType: "ed25519", Comment: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.PublicKeySSH, "ssh-ed25519") {
		t.Errorf("public key should contain ssh-ed25519: %s", result.PublicKeySSH)
	}
	if !strings.Contains(result.PrivateKeyPEM, "BEGIN OPENSSH PRIVATE KEY") {
		t.Errorf("private key should be OpenSSH format: %s", result.PrivateKeyPEM[:50])
	}
	if !strings.Contains(result.PublicKeySSH, "test") {
		t.Errorf("public key should contain comment: %s", result.PublicKeySSH)
	}
}

func TestGenerateKeyECDSA(t *testing.T) {
	for _, bits := range []int{256, 384, 521} {
		t.Run(string(rune('0'+bits/100)), func(t *testing.T) {
			result, err := GenerateKey(KeyGenParams{KeyType: "ecdsa", Bits: bits})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(result.PublicKeySSH, "ecdsa-sha2-nistp") {
				t.Errorf("public key: %s", result.PublicKeySSH)
			}
		})
	}
}

func TestGenerateKeyRSA(t *testing.T) {
	result, err := GenerateKey(KeyGenParams{KeyType: "rsa", Bits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.PublicKeySSH, "ssh-rsa") {
		t.Errorf("public key: %s", result.PublicKeySSH)
	}
}

func TestGenerateKeyRSADefault(t *testing.T) {
	result, err := GenerateKey(KeyGenParams{KeyType: "rsa"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.PublicKeySSH, "ssh-rsa") {
		t.Errorf("public key: %s", result.PublicKeySSH)
	}
}

func TestGenerateKeyECDSADefault(t *testing.T) {
	result, err := GenerateKey(KeyGenParams{KeyType: "ecdsa"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result.PublicKeySSH, "nistp256") {
		t.Errorf("public key: %s", result.PublicKeySSH)
	}
}

func TestGenerateKeyUnsupported(t *testing.T) {
	_, err := GenerateKey(KeyGenParams{KeyType: "dsa"})
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

func TestGenerateKeyRSATooSmall(t *testing.T) {
	_, err := GenerateKey(KeyGenParams{KeyType: "rsa", Bits: 512})
	if err == nil {
		t.Fatal("expected error for small RSA key")
	}
}

func TestGenerateKeyECDSAInvalidBits(t *testing.T) {
	_, err := GenerateKey(KeyGenParams{KeyType: "ecdsa", Bits: 128})
	if err == nil {
		t.Fatal("expected error for invalid ECDSA bits")
	}
}
