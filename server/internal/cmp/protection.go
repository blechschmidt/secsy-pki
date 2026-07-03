package cmp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
)

// errProtection is returned when message-protection verification fails. It is
// deliberately generic so it can be reported to clients as badMessageCheck
// without leaking which step failed.
var errProtection = errors.New("cmp: message protection verification failed")

// pbmParameter is the PBMParameter carried in a PasswordBasedMac protectionAlg
// (RFC 4210 §5.1.3.1).
type pbmParameter struct {
	Salt           []byte
	OWF            pkix.AlgorithmIdentifier
	IterationCount int
	MAC            pkix.AlgorithmIdentifier
}

// defaultPBM returns sensible PBM parameters for protecting a response: SHA-256
// as the one-way function and HMAC-SHA256 as the MAC, with a fresh salt.
func defaultPBM() (pbmParameter, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return pbmParameter{}, err
	}
	return pbmParameter{
		Salt:           salt,
		OWF:            pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue},
		IterationCount: 1024,
		MAC:            pkix.AlgorithmIdentifier{Algorithm: oidHMACSHA256, Parameters: asn1.NullRawValue},
	}, nil
}

// pbmProtectionAlg encodes a PasswordBasedMac AlgorithmIdentifier from PBM
// parameters.
func pbmProtectionAlg(p pbmParameter) (pkix.AlgorithmIdentifier, error) {
	paramDER, err := asn1.Marshal(p)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, err
	}
	return pkix.AlgorithmIdentifier{
		Algorithm:  oidPasswordBasedMac,
		Parameters: asn1.RawValue{FullBytes: paramDER},
	}, nil
}

// owfHash resolves a one-way-function algorithm identifier to a hash constructor.
func owfHash(oid asn1.ObjectIdentifier) (func() hash.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return sha256.New, nil
	case oid.Equal(oidSHA1):
		if fips.PolicyEnforced() {
			return nil, fmt.Errorf("cmp: PBM one-way function SHA-1 is %w", fips.ErrNotApproved)
		}
		return sha1.New, nil
	case oid.Equal(oidSHA384):
		return sha512.New384, nil
	case oid.Equal(oidSHA512):
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("cmp: unsupported PBM one-way function %v", oid)
	}
}

// macHash resolves an HMAC algorithm identifier to a hash constructor.
func macHash(oid asn1.ObjectIdentifier) (func() hash.Hash, error) {
	switch {
	case oid.Equal(oidHMACSHA256):
		return sha256.New, nil
	case oid.Equal(oidHMACSHA1):
		if fips.PolicyEnforced() {
			return nil, fmt.Errorf("cmp: PBM MAC HMAC-SHA1 is %w", fips.ErrNotApproved)
		}
		return sha1.New, nil
	case oid.Equal(oidHMACSHA384):
		return sha512.New384, nil
	case oid.Equal(oidHMACSHA512):
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("cmp: unsupported PBM MAC algorithm %v", oid)
	}
}

// computePBM derives the PBM key and computes the MAC over the protected part
// (RFC 4210 §5.1.3.1): the one-way function is applied iterationCount times,
// starting from secret||salt, to yield the HMAC key.
func computePBM(secret, protectedPart []byte, p pbmParameter) ([]byte, error) {
	if p.IterationCount <= 0 {
		return nil, fmt.Errorf("cmp: PBM iterationCount must be positive")
	}
	owf, err := owfHash(p.OWF.Algorithm)
	if err != nil {
		return nil, err
	}
	mac, err := macHash(p.MAC.Algorithm)
	if err != nil {
		return nil, err
	}
	key := append(append([]byte{}, secret...), p.Salt...)
	for i := 0; i < p.IterationCount; i++ {
		h := owf()
		h.Write(key)
		key = h.Sum(nil)
	}
	m := hmac.New(mac, key)
	m.Write(protectedPart)
	return m.Sum(nil), nil
}

// verifyPBM recomputes the MAC over the protected part and compares it to the
// received protection in constant time.
func verifyPBM(secret []byte, msg *message) error {
	if !msg.header.ProtectionAlg.Algorithm.Equal(oidPasswordBasedMac) {
		return fmt.Errorf("cmp: message is not PasswordBasedMac protected")
	}
	var p pbmParameter
	if _, err := asn1.Unmarshal(msg.header.ProtectionAlg.Parameters.FullBytes, &p); err != nil {
		return fmt.Errorf("cmp: decoding PBMParameter: %w", err)
	}
	want, err := computePBM(secret, msg.protectedPartDER, p)
	if err != nil {
		return err
	}
	if len(msg.protection) == 0 || subtle.ConstantTimeCompare(want, msg.protection) != 1 {
		return errProtection
	}
	return nil
}

// ---- signature-based protection -------------------------------------------

// hashForSignatureAlg maps a signature algorithm identifier to the hash used and
// whether the key is RSA/ECDSA/Ed25519. Ed25519 uses no external hash.
func hashForSignatureAlg(oid asn1.ObjectIdentifier) (crypto.Hash, bool, error) {
	switch {
	case oid.Equal(oidSHA256WithRSA), oid.Equal(oidECDSAWithSHA256):
		return crypto.SHA256, false, nil
	case oid.Equal(oidSHA384WithRSA), oid.Equal(oidECDSAWithSHA384):
		return crypto.SHA384, false, nil
	case oid.Equal(oidSHA512WithRSA), oid.Equal(oidECDSAWithSHA512):
		return crypto.SHA512, false, nil
	case oid.Equal(oidEd25519):
		return 0, true, nil
	default:
		return 0, false, fmt.Errorf("cmp: unsupported signature algorithm %v", oid)
	}
}

// signatureAlgForKey selects the protection signature algorithm identifier and
// hash for a signing key, using SHA-256 for RSA/ECDSA and pure Ed25519.
func signatureAlgForKey(pub crypto.PublicKey) (pkix.AlgorithmIdentifier, crypto.Hash, bool, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidSHA256WithRSA, Parameters: asn1.NullRawValue}, crypto.SHA256, false, nil
	case *ecdsa.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidECDSAWithSHA256}, crypto.SHA256, false, nil
	case ed25519.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidEd25519}, 0, true, nil
	default:
		return pkix.AlgorithmIdentifier{}, 0, false, fmt.Errorf("cmp: unsupported signing key type %T", pub)
	}
}

// signData signs data with a crypto.Signer using the given hash (or pure
// Ed25519 when eddsa is set), returning the raw signature bytes.
func signData(signer crypto.Signer, data []byte, h crypto.Hash, eddsa bool) ([]byte, error) {
	if eddsa {
		return signer.Sign(rand.Reader, data, crypto.Hash(0))
	}
	hh := h.New()
	hh.Write(data)
	return signer.Sign(rand.Reader, hh.Sum(nil), h)
}

// verifySignature verifies a signature over data against a public key using the
// algorithm identified by alg.
func verifySignature(pub crypto.PublicKey, alg pkix.AlgorithmIdentifier, data, sig []byte) error {
	h, eddsa, err := hashForSignatureAlg(alg.Algorithm)
	if err != nil {
		return err
	}
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if eddsa {
			return errProtection
		}
		digest := hashSum(h, data)
		if err := rsa.VerifyPKCS1v15(key, h, digest, sig); err != nil {
			return errProtection
		}
		return nil
	case *ecdsa.PublicKey:
		if eddsa {
			return errProtection
		}
		digest := hashSum(h, data)
		if !ecdsa.VerifyASN1(key, digest, sig) {
			return errProtection
		}
		return nil
	case ed25519.PublicKey:
		if !eddsa {
			return errProtection
		}
		if !ed25519.Verify(key, data, sig) {
			return errProtection
		}
		return nil
	default:
		return fmt.Errorf("cmp: unsupported verification key type %T", pub)
	}
}

func hashSum(h crypto.Hash, data []byte) []byte {
	hh := h.New()
	hh.Write(data)
	return hh.Sum(nil)
}

// verifySignatureProtection verifies a signature-protected message against the
// public key of the signer certificate (the first extraCert).
func verifySignatureProtection(signerCert *x509.Certificate, msg *message) error {
	if len(msg.protection) == 0 {
		return errProtection
	}
	return verifySignature(signerCert.PublicKey, msg.header.ProtectionAlg, msg.protectedPartDER, msg.protection)
}
