package pki

// Reading an existing private key out of the files operators actually have
// (Task 194). Adopting a legacy CA, an SSH CA, or a signing key means taking
// key material that was generated somewhere else — years ago, by openssl, by
// ssh-keygen, by a vendor appliance — and moving it under this PKI's key
// provider. The formats that arrive are consequently varied, and getting one of
// them wrong is not a soft failure: the operator is holding the only copy of a
// root key.
//
// ParsePrivateKey therefore accepts every encoding this codebase can decode
// without a new dependency, distinguishes "wrong passphrase" from "unsupported
// format" from "this is not a private key at all", and never guesses: an
// encrypted container with no passphrase returns ErrPassphraseRequired so the
// caller can ask, rather than reporting a parse error the operator would chase
// in the wrong direction.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"software.sslmate.com/src/go-pkcs12"
)

// KeyFileFormat names the encoding a private key was read from. It is reported
// back to the operator so an import transcript records exactly what was parsed.
type KeyFileFormat string

const (
	// FormatPKCS8 is an unencrypted PKCS#8 "PRIVATE KEY" PEM block (RFC 5208).
	FormatPKCS8 KeyFileFormat = "pkcs8"
	// FormatPKCS8Encrypted is an "ENCRYPTED PRIVATE KEY" PEM block (RFC 5958),
	// the default of `openssl pkcs8 -topk8` and `openssl genpkey -aes256`.
	FormatPKCS8Encrypted KeyFileFormat = "pkcs8-encrypted"
	// FormatPKCS1 is a traditional "RSA PRIVATE KEY" PEM block.
	FormatPKCS1 KeyFileFormat = "pkcs1"
	// FormatSEC1 is a traditional "EC PRIVATE KEY" PEM block (RFC 5915).
	FormatSEC1 KeyFileFormat = "sec1"
	// FormatPEMEncrypted is a legacy OpenSSL PEM block encrypted in place with
	// a Proc-Type/DEK-Info header (pre-3.0 `openssl genrsa -aes256`).
	FormatPEMEncrypted KeyFileFormat = "pem-encrypted"
	// FormatOpenSSH is an "OPENSSH PRIVATE KEY" block, optionally bcrypt-encrypted.
	FormatOpenSSH KeyFileFormat = "openssh"
	// FormatPKCS12 is a PKCS#12 / PFX container, which also carries certificates.
	FormatPKCS12 KeyFileFormat = "pkcs12"
	// FormatDER is a bare (non-PEM) DER encoding of PKCS#8, PKCS#1, or SEC1.
	FormatDER KeyFileFormat = "der"
)

// ErrPassphraseRequired reports that the supplied file is an encrypted
// container and no passphrase was given. Callers distinguish it from a parse
// failure so they can prompt instead of reporting a corrupt file.
var ErrPassphraseRequired = errors.New("pki: private key is encrypted and no passphrase was supplied")

// ErrWrongPassphrase reports that a passphrase was supplied but did not decrypt
// the container. It is deliberately distinct from ErrPassphraseRequired: one
// means "ask", the other means "the answer was wrong".
var ErrWrongPassphrase = errors.New("pki: private key passphrase is incorrect")

// ParsedPrivateKey is the outcome of reading an operator-supplied key file.
type ParsedPrivateKey struct {
	// Key is the decoded private key: *rsa.PrivateKey, *ecdsa.PrivateKey, or
	// ed25519.PrivateKey. It is always a signer (crypto.Signer).
	Key crypto.PrivateKey
	// Format records which encoding the key was read from.
	Format KeyFileFormat
	// Encrypted reports whether the container was passphrase-protected.
	Encrypted bool
	// Certificate is the leaf/end-entity certificate carried alongside the key,
	// set only for PKCS#12 containers (which bundle key and certificate). It
	// lets `ca import` accept a single .p12 instead of a key and a cert file.
	Certificate *x509.Certificate
	// CACerts are the additional certificates in a PKCS#12 container (the chain
	// up to the trust anchor), in the order the container listed them.
	CACerts []*x509.Certificate
}

// Signer returns the parsed key as a crypto.Signer.
func (p *ParsedPrivateKey) Signer() (crypto.Signer, error) {
	s, ok := p.Key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("pki: parsed %T is not a signing key", p.Key)
	}
	return s, nil
}

// ParsePrivateKey decodes an operator-supplied private key file. It accepts, in
// this order of detection: PEM (PKCS#8 plain and encrypted, PKCS#1, SEC1,
// legacy DEK-Info-encrypted, OpenSSH), bare DER (PKCS#8/PKCS#1/SEC1), and
// PKCS#12/PFX. passphrase may be nil for unencrypted material.
//
// It returns ErrPassphraseRequired when the file is encrypted and no passphrase
// was given, and ErrWrongPassphrase when one was given but did not work, so a
// caller can tell "ask the operator" from "the operator answered wrong".
func ParsePrivateKey(data []byte, passphrase []byte) (*ParsedPrivateKey, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("pki: empty private key input")
	}
	if block, _ := pem.Decode(data); block != nil {
		return parsePEMPrivateKey(data, block, passphrase)
	}
	// Not PEM: either bare DER or a PKCS#12 container. PKCS#12 is also DER, so
	// try the plain key encodings first and fall back to the container.
	if key, err := parseDERPrivateKey(data); err == nil {
		return &ParsedPrivateKey{Key: key, Format: FormatDER}, nil
	}
	parsed, p12Err := parsePKCS12(data, passphrase)
	if p12Err == nil {
		return parsed, nil
	}
	if errors.Is(p12Err, ErrWrongPassphrase) || errors.Is(p12Err, ErrPassphraseRequired) {
		return nil, p12Err
	}
	return nil, fmt.Errorf("pki: unrecognized private key file: not PEM, not DER PKCS#8/PKCS#1/SEC1, and not a PKCS#12 container")
}

// parsePEMPrivateKey handles every PEM-armored form. It scans the whole input
// rather than only the first block, so a file that leads with certificates (a
// concatenated key+chain bundle, which is common) still yields its key.
func parsePEMPrivateKey(data []byte, first *pem.Block, passphrase []byte) (*ParsedPrivateKey, error) {
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch {
		case block.Type == "ENCRYPTED PRIVATE KEY":
			if len(passphrase) == 0 {
				return nil, ErrPassphraseRequired
			}
			der, err := DecryptPKCS8(block.Bytes, passphrase)
			if err != nil {
				return nil, err
			}
			key, err := x509.ParsePKCS8PrivateKey(der)
			if err != nil {
				return nil, fmt.Errorf("pki: parsing decrypted PKCS#8 key: %w", err)
			}
			return newParsed(key, FormatPKCS8Encrypted, true)

		case block.Type == "OPENSSH PRIVATE KEY":
			key, format, encrypted, err := parseOpenSSH(block, passphrase)
			if err != nil {
				return nil, err
			}
			return newParsed(key, format, encrypted)

		case isEncryptedPEMBlock(block):
			if len(passphrase) == 0 {
				return nil, ErrPassphraseRequired
			}
			der, err := decryptPEMBlock(block, passphrase)
			if err != nil {
				return nil, err
			}
			key, err := parseDERPrivateKey(der)
			if err != nil {
				// A legacy block decrypts to garbage under the wrong passphrase
				// far more often than it fails the cipher check, so an
				// unparseable plaintext means the passphrase, not the file.
				return nil, ErrWrongPassphrase
			}
			return newParsed(key, FormatPEMEncrypted, true)

		case block.Type == "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("pki: parsing PKCS#8 private key: %w", err)
			}
			return newParsed(key, FormatPKCS8, false)

		case block.Type == "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("pki: parsing PKCS#1 RSA private key: %w", err)
			}
			return newParsed(key, FormatPKCS1, false)

		case block.Type == "EC PRIVATE KEY":
			key, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("pki: parsing SEC1 EC private key: %w", err)
			}
			return newParsed(key, FormatSEC1, false)
		}
	}
	// Every encrypted form above returns from inside the loop, so reaching here
	// means no block in the file was a private key at all.
	return nil, fmt.Errorf("pki: no private key PEM block found (first block is %q; expected PRIVATE KEY, RSA PRIVATE KEY, EC PRIVATE KEY, ENCRYPTED PRIVATE KEY, or OPENSSH PRIVATE KEY)", first.Type)
}

// parseOpenSSH decodes an OpenSSH-format key, which carries its own bcrypt-KDF
// encryption rather than PEM headers.
func parseOpenSSH(block *pem.Block, passphrase []byte) (crypto.PrivateKey, KeyFileFormat, bool, error) {
	pemBytes := pem.EncodeToMemory(block)
	key, err := ssh.ParseRawPrivateKey(pemBytes)
	if err == nil {
		return normalizeOpenSSHKey(key), FormatOpenSSH, false, nil
	}
	var needsPass *ssh.PassphraseMissingError
	if !errors.As(err, &needsPass) {
		return nil, "", false, fmt.Errorf("pki: parsing OpenSSH private key: %w", err)
	}
	if len(passphrase) == 0 {
		return nil, "", true, ErrPassphraseRequired
	}
	key, err = ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
	if err != nil {
		if errors.Is(err, x509.IncorrectPasswordError) || strings.Contains(err.Error(), "decrypt") {
			return nil, "", true, ErrWrongPassphrase
		}
		return nil, "", true, fmt.Errorf("pki: decrypting OpenSSH private key: %w", err)
	}
	return normalizeOpenSSHKey(key), FormatOpenSSH, true, nil
}

// normalizeOpenSSHKey unwraps the pointer form x/crypto/ssh returns for Ed25519
// (*ed25519.PrivateKey) so every parse path yields the same value types.
func normalizeOpenSSHKey(key any) crypto.PrivateKey {
	if p, ok := key.(*ed25519.PrivateKey); ok && p != nil {
		return *p
	}
	return key
}

// parsePKCS12 decodes a .p12/.pfx container. Such a container is always
// password-protected in practice (an empty password is itself a password), so
// an unusable one is reported as a passphrase problem rather than a bad file.
func parsePKCS12(data []byte, passphrase []byte) (*ParsedPrivateKey, error) {
	key, cert, caCerts, err := pkcs12.DecodeChain(data, string(passphrase))
	if err != nil {
		if strings.Contains(err.Error(), "decryption password incorrect") ||
			strings.Contains(err.Error(), "invalid password") ||
			strings.Contains(err.Error(), "MAC verification failed") {
			if len(passphrase) == 0 {
				return nil, ErrPassphraseRequired
			}
			return nil, ErrWrongPassphrase
		}
		return nil, fmt.Errorf("pki: decoding PKCS#12 container: %w", err)
	}
	parsed, err := newParsed(key, FormatPKCS12, true)
	if err != nil {
		return nil, err
	}
	parsed.Certificate = cert
	parsed.CACerts = caCerts
	return parsed, nil
}

// parseDERPrivateKey tries the three bare-DER private key encodings.
func parseDERPrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("pki: DER is not a PKCS#8, PKCS#1, or SEC1 private key")
}

// newParsed validates that a decoded key is one this PKI can actually use and
// wraps it. Rejecting an unsupported algorithm here — rather than at the token
// — keeps the operator-facing error specific.
func newParsed(key crypto.PrivateKey, format KeyFileFormat, encrypted bool) (*ParsedPrivateKey, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if err := k.Validate(); err != nil {
			return nil, fmt.Errorf("pki: RSA private key is inconsistent: %w", err)
		}
	case *ecdsa.PrivateKey:
	case ed25519.PrivateKey:
		if len(k) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("pki: Ed25519 private key has length %d, expected %d", len(k), ed25519.PrivateKeySize)
		}
	default:
		return nil, fmt.Errorf("pki: unsupported private key type %T (supported: RSA, ECDSA P-256/384/521, Ed25519)", key)
	}
	return &ParsedPrivateKey{Key: key, Format: format, Encrypted: encrypted}, nil
}
