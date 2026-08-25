package pki

// Importing an existing private key onto a PKCS#11 token (Task 194).
//
// Generation is the normal path and stays the recommendation: a key that was
// born inside the HSM has never existed anywhere else, and the device says so
// under attestation. Import exists for the case generation cannot serve —
// adopting a CA that already issued certificates, whose key was created years
// ago in software and whose certificate is already in a thousand trust stores.
// Re-keying such a CA means re-distributing its root; moving the key into the
// HSM does not.
//
// The import applies exactly the least-privilege template generation applies
// (CKA_SENSITIVE, CKA_EXTRACTABLE=false, CKA_PRIVATE, single-purpose
// sign-or-decrypt), so an imported key is as locked-down on the token as a
// generated one — the difference is provenance, not protection, and provenance
// is what attestation reports.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"

	"github.com/miekg/pkcs11"
	"golang.org/x/crypto/ssh"
)

// ImportKeyUsage selects the least-privilege attribute set an imported key is
// created with, mirroring the split between GenerateSignKey and GenerateRSAKEK.
type ImportKeyUsage string

const (
	// ImportUsageSign creates a sign-only key (a CA, TSA, SSH-CA, or artifact
	// signing key).
	ImportUsageSign ImportKeyUsage = "sign"
	// ImportUsageDecrypt creates a decrypt-only RSA key-encryption key for the
	// envelope-encryption layer.
	ImportUsageDecrypt ImportKeyUsage = "decrypt"
)

// ImportedHSMKey describes a key that was placed on a token by import.
type ImportedHSMKey struct {
	// PKCS11URI addresses the key on the token (RFC 7512).
	PKCS11URI string
	// KeyType is the canonical key-type string derived from the key material.
	KeyType string
	// SSHPublicKey is the OpenSSH form of the public half, read back from the
	// token rather than computed from the input, so it reflects what the device
	// actually stored.
	SSHPublicKey string
}

// ImportKey places an existing private key on the token via a pooled session,
// creating the private and (where the module requires it) public key objects.
// It fails if a key with the same label already exists, matching the duplicate-
// label invariant GenerateSignKey enforces: two objects sharing a CKA_LABEL
// make every later lookup ambiguous.
func (p *SessionPool) ImportKey(ctx context.Context, label string, id []byte, priv crypto.PrivateKey, usage ImportKeyUsage) (*ImportedHSMKey, error) {
	s, release, err := p.borrow(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	return importKeyOnSession(p.ctx, s.handle, p.cfg, label, id, priv, usage)
}

// importKeyOnSession is the C_CreateObject core. The session must already be
// authenticated and read/write.
func importKeyOnSession(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, cfg PKCS11Config, label string, id []byte, priv crypto.PrivateKey, usage ImportKeyUsage) (*ImportedHSMKey, error) {
	if label == "" {
		return nil, fmt.Errorf("import: key label is required")
	}
	keyType, err := PrivateKeyType(priv)
	if err != nil {
		return nil, err
	}
	if usage == ImportUsageDecrypt {
		if _, ok := priv.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("import: a key-encryption key must be RSA, got %s", keyType)
		}
	}

	privAttrs, pubAttrs, err := importTemplates(priv, label, id, usage)
	if err != nil {
		return nil, err
	}

	if _, err := ctx.CreateObject(session, privAttrs); err != nil {
		return nil, fmt.Errorf("import: creating private key object on the token: %w", err)
	}

	// The public half is created as its own object because key lookup resolves
	// the public key from CKO_PUBLIC_KEY. Modules that synthesize the public
	// object from the private key (YubiHSM does) reject the create; that is not
	// an error as long as the key then resolves, which the read-back confirms.
	pubCreateErr := error(nil)
	if _, err := ctx.CreateObject(session, pubAttrs); err != nil {
		pubCreateErr = err
	}

	loc := KeyLocator{Label: label, ID: id}
	ko, err := findKeyObjects(ctx, session, loc)
	if err != nil {
		return nil, fmt.Errorf("import: the imported key %s could not be resolved on the token: %w", loc.Describe(), err)
	}
	if ko.pubKey == nil {
		if pubCreateErr != nil {
			return nil, fmt.Errorf("import: the token exposes no public key object for %s and rejected creating one: %w", loc.Describe(), pubCreateErr)
		}
		return nil, fmt.Errorf("import: the token exposes no public key object for %s", loc.Describe())
	}
	// The token is authoritative: compare what it stored against what we sent,
	// so a module that silently truncated or re-encoded the material is caught
	// here rather than by a verifier months later.
	if !publicKeysEqual(ko.pubKey, publicOf(priv)) {
		return nil, fmt.Errorf("import: the public key read back from the token does not match the imported private key")
	}

	sshPub, err := ssh.NewPublicKey(ko.pubKey)
	if err != nil {
		return nil, fmt.Errorf("import: encoding the imported public key: %w", err)
	}
	return &ImportedHSMKey{
		PKCS11URI:    BuildPKCS11URI(cfg, label),
		KeyType:      keyType,
		SSHPublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
	}, nil
}

// importTemplates builds the CKO_PRIVATE_KEY and CKO_PUBLIC_KEY attribute
// templates for one key. The private template is the same least-privilege set
// generation uses; see generateKeyPairOnSession and generateRSAKEKOnSession.
func importTemplates(priv crypto.PrivateKey, label string, id []byte, usage ImportKeyUsage) (privAttrs, pubAttrs []*pkcs11.Attribute, err error) {
	privAttrs = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		// An imported CA key must be no more exposed than a generated one:
		// CKA_SENSITIVE hides its value from attribute reads and
		// CKA_EXTRACTABLE=false forbids wrapping it back off the device, so the
		// copy that lands on the token cannot become a second copy elsewhere.
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	pubAttrs = []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	switch usage {
	case ImportUsageDecrypt:
		privAttrs = append(privAttrs,
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, false))
		pubAttrs = append(pubAttrs,
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, false))
	default:
		privAttrs = append(privAttrs,
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, false),
			pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, false))
		pubAttrs = append(pubAttrs,
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true))
	}
	if len(id) > 0 {
		privAttrs = append(privAttrs, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
		pubAttrs = append(pubAttrs, pkcs11.NewAttribute(pkcs11.CKA_ID, id))
	}

	switch k := priv.(type) {
	case *rsa.PrivateKey:
		// The CRT parameters are mandatory in a CKK_RSA private-key template;
		// Precompute fills them in for keys parsed from formats that omit them.
		k.Precompute()
		if len(k.Primes) != 2 || k.Precomputed.Dp == nil || k.Precomputed.Dq == nil || k.Precomputed.Qinv == nil {
			return nil, nil, fmt.Errorf("import: RSA key is missing the CRT parameters required by PKCS#11 (multi-prime keys are not supported)")
		}
		privAttrs = append(privAttrs,
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, k.N.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(k.E)).Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE_EXPONENT, k.D.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PRIME_1, k.Primes[0].Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PRIME_2, k.Primes[1].Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_1, k.Precomputed.Dp.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_EXPONENT_2, k.Precomputed.Dq.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_COEFFICIENT, k.Precomputed.Qinv.Bytes()))
		pubAttrs = append(pubAttrs,
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_RSA),
			pkcs11.NewAttribute(pkcs11.CKA_MODULUS, k.N.Bytes()),
			pkcs11.NewAttribute(pkcs11.CKA_PUBLIC_EXPONENT, big.NewInt(int64(k.E)).Bytes()))

	case *ecdsa.PrivateKey:
		ecParams, err := ecParamsForCurve(k.Curve)
		if err != nil {
			return nil, nil, err
		}
		// The private scalar is left-padded to the curve's field size: a token
		// that infers the curve from the value length would otherwise reject a
		// scalar that happens to have leading zero bytes.
		scalar := padScalar(k.D, (k.Curve.Params().BitSize+7)/8)
		point, err := asn1.Marshal(elliptic.Marshal(k.Curve, k.X, k.Y)) //nolint:staticcheck // SA1019: PKCS#11 CKA_EC_POINT is exactly this uncompressed encoding; crypto/ecdh cannot produce it from an ecdsa key.
		if err != nil {
			return nil, nil, fmt.Errorf("import: encoding EC point: %w", err)
		}
		privAttrs = append(privAttrs,
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, scalar))
		pubAttrs = append(pubAttrs,
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecParams),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, point))

	case ed25519.PrivateKey:
		// CKA_EC_PARAMS carries the PrintableString curve name, matching what
		// generation writes: YubiHSM requires it and SoftHSM accepts it, so an
		// imported key is byte-identical in shape to a generated one.
		edParams, err := asn1.Marshal("edwards25519")
		if err != nil {
			return nil, nil, fmt.Errorf("import: encoding Ed25519 curve parameters: %w", err)
		}
		point, err := asn1.Marshal([]byte(k.Public().(ed25519.PublicKey)))
		if err != nil {
			return nil, nil, fmt.Errorf("import: encoding Ed25519 public point: %w", err)
		}
		privAttrs = append(privAttrs,
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_EDWARDS),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, edParams),
			// Cryptoki stores the 32-byte Ed25519 seed, not Go's 64-byte
			// seed||public concatenation.
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, k.Seed()))
		pubAttrs = append(pubAttrs,
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, CKK_EC_EDWARDS),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, edParams),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, point))

	default:
		return nil, nil, fmt.Errorf("import: unsupported private key type %T", priv)
	}
	return privAttrs, pubAttrs, nil
}

// ecParamsForCurve returns the DER-encoded named-curve OID for CKA_EC_PARAMS.
func ecParamsForCurve(curve elliptic.Curve) ([]byte, error) {
	var oid asn1.ObjectIdentifier
	switch curve {
	case elliptic.P256():
		oid = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	case elliptic.P384():
		oid = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	case elliptic.P521():
		oid = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	default:
		return nil, fmt.Errorf("import: unsupported elliptic curve %s", curve.Params().Name)
	}
	der, err := asn1.Marshal(oid)
	if err != nil {
		return nil, fmt.Errorf("import: encoding curve OID: %w", err)
	}
	return der, nil
}

// padScalar left-pads a big-endian integer to a fixed width.
func padScalar(d *big.Int, size int) []byte {
	b := d.Bytes()
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// PrivateKeyType returns the canonical key-type identifier for an in-memory
// private key, using the same vocabulary as generated keys. RSA moduli below
// 2048 bits are refused outright: they are unusable for issuance under this
// PKI's own key-check gate, so accepting one onto a token would only move a
// dead key into expensive storage.
func PrivateKeyType(priv crypto.PrivateKey) (string, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		bits := k.N.BitLen()
		switch {
		case bits < 2048:
			return "", fmt.Errorf("import: RSA key is %d bits; the minimum is 2048", bits)
		case bits <= 2048:
			return "rsa-2048", nil
		case bits <= 3072:
			return "rsa-3072", nil
		default:
			return "rsa-4096", nil
		}
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return "ecdsa-sha2-nistp256", nil
		case elliptic.P384():
			return "ecdsa-sha2-nistp384", nil
		case elliptic.P521():
			return "ecdsa-sha2-nistp521", nil
		default:
			return "", fmt.Errorf("import: unsupported elliptic curve %s", k.Curve.Params().Name)
		}
	case ed25519.PrivateKey:
		return "ed25519", nil
	default:
		return "", fmt.Errorf("import: unsupported private key type %T", priv)
	}
}

// publicOf returns the public half of a private key.
func publicOf(priv crypto.PrivateKey) crypto.PublicKey {
	if s, ok := priv.(crypto.Signer); ok {
		return s.Public()
	}
	return nil
}

// publicKeysEqual compares two public keys structurally.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if a == nil || b == nil {
		return false
	}
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return false
}
