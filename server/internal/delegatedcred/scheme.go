package delegatedcred

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"io"
)

// SignatureScheme is a TLS 1.3 SignatureScheme code point (RFC 8446 §4.2.3). A
// delegated credential carries two of them: the outer algorithm, used to sign the
// credential with the end-entity certificate key, and expected_cert_verify_
// algorithm, the scheme the delegated key itself will use in the handshake
// CertificateVerify.
type SignatureScheme uint16

// The subset of TLS 1.3 signature schemes usable for delegated credentials.
// RFC 9345 §4.1.3 requires RSA signatures use RSASSA-PSS; PKCS#1 v1.5 schemes are
// deliberately excluded.
const (
	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	ECDSAWithP521AndSHA512 SignatureScheme = 0x0603
	RSAPSSWithSHA256       SignatureScheme = 0x0804
	RSAPSSWithSHA384       SignatureScheme = 0x0805
	RSAPSSWithSHA512       SignatureScheme = 0x0806
	Ed25519               SignatureScheme = 0x0807
)

// schemeNames maps the supported schemes to their IANA registry names.
var schemeNames = map[SignatureScheme]string{
	ECDSAWithP256AndSHA256: "ecdsa_secp256r1_sha256",
	ECDSAWithP384AndSHA384: "ecdsa_secp384r1_sha384",
	ECDSAWithP521AndSHA512: "ecdsa_secp521r1_sha512",
	RSAPSSWithSHA256:       "rsa_pss_rsae_sha256",
	RSAPSSWithSHA384:       "rsa_pss_rsae_sha384",
	RSAPSSWithSHA512:       "rsa_pss_rsae_sha512",
	Ed25519:               "ed25519",
}

// String renders the scheme by its IANA name, or as a hex code point when
// unknown, so error messages and JSON output are legible.
func (s SignatureScheme) String() string {
	if name, ok := schemeNames[s]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", uint16(s))
}

// SchemeFromName resolves an IANA signature-scheme name (case-insensitive is not
// applied; names are lowercase) to its code point. It also accepts a raw
// "0x0403" hex code point. It is used by the CLI/API to parse an operator's
// chosen scheme.
func SchemeFromName(name string) (SignatureScheme, error) {
	for s, n := range schemeNames {
		if n == name {
			return s, nil
		}
	}
	var v uint16
	if _, err := fmt.Sscanf(name, "0x%04x", &v); err == nil {
		s := SignatureScheme(v)
		if _, ok := schemeNames[s]; ok {
			return s, nil
		}
	}
	return 0, fmt.Errorf("unknown or unsupported signature scheme %q", name)
}

// hash returns the crypto.Hash a scheme prehashes with, or 0 for Ed25519 (which
// is pure EdDSA over the whole message).
func (s SignatureScheme) hash() crypto.Hash {
	switch s {
	case ECDSAWithP256AndSHA256, RSAPSSWithSHA256:
		return crypto.SHA256
	case ECDSAWithP384AndSHA384, RSAPSSWithSHA384:
		return crypto.SHA384
	case ECDSAWithP521AndSHA512, RSAPSSWithSHA512:
		return crypto.SHA512
	default:
		return 0
	}
}

// SchemeForKey returns the TLS signature scheme a public key signs/verifies with,
// validating an optional operator override against the key type. A zero override
// selects the natural default for the key (RSA defaults to rsa_pss_rsae_sha256).
func SchemeForKey(pub crypto.PublicKey, override SignatureScheme) (SignatureScheme, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		var want SignatureScheme
		switch k.Curve {
		case elliptic.P256():
			want = ECDSAWithP256AndSHA256
		case elliptic.P384():
			want = ECDSAWithP384AndSHA384
		case elliptic.P521():
			want = ECDSAWithP521AndSHA512
		default:
			return 0, fmt.Errorf("unsupported ECDSA curve %q", k.Curve.Params().Name)
		}
		if override != 0 && override != want {
			return 0, fmt.Errorf("signature scheme %s does not match an ECDSA %s key (expected %s)", override, k.Curve.Params().Name, want)
		}
		return want, nil
	case *rsa.PublicKey:
		if override != 0 {
			switch override {
			case RSAPSSWithSHA256, RSAPSSWithSHA384, RSAPSSWithSHA512:
				return override, nil
			default:
				return 0, fmt.Errorf("signature scheme %s is not valid for an RSA key (RFC 9345 §4.1.3 requires RSASSA-PSS)", override)
			}
		}
		return RSAPSSWithSHA256, nil
	case ed25519.PublicKey:
		if override != 0 && override != Ed25519 {
			return 0, fmt.Errorf("signature scheme %s does not match an Ed25519 key", override)
		}
		return Ed25519, nil
	default:
		return 0, fmt.Errorf("unsupported public key type %T", pub)
	}
}

// signMessage signs msg with the given key under the given scheme, producing the
// TLS wire signature (ECDSA is DER-encoded ECDSA-Sig-Value; RSA is RSASSA-PSS).
func signMessage(rnd io.Reader, key crypto.Signer, scheme SignatureScheme, msg []byte) ([]byte, error) {
	if got, err := SchemeForKey(key.Public(), scheme); err != nil {
		return nil, err
	} else if got != scheme {
		return nil, fmt.Errorf("signature scheme %s incompatible with signing key", scheme)
	}
	switch scheme {
	case ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512:
		h := scheme.hash()
		return key.Sign(rnd, digest(h, msg), h)
	case RSAPSSWithSHA256, RSAPSSWithSHA384, RSAPSSWithSHA512:
		h := scheme.hash()
		return key.Sign(rnd, digest(h, msg), &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
	case Ed25519:
		return key.Sign(rnd, msg, crypto.Hash(0))
	default:
		return nil, fmt.Errorf("unsupported signature scheme %s", scheme)
	}
}

// verifyMessage checks a signature over msg produced under the given scheme.
func verifyMessage(pub crypto.PublicKey, scheme SignatureScheme, msg, sig []byte) error {
	switch scheme {
	case ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512:
		pk, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("scheme %s requires an ECDSA public key, got %T", scheme, pub)
		}
		if got, err := SchemeForKey(pk, scheme); err != nil || got != scheme {
			return fmt.Errorf("scheme %s does not match the certificate key", scheme)
		}
		if !ecdsa.VerifyASN1(pk, digest(scheme.hash(), msg), sig) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil
	case RSAPSSWithSHA256, RSAPSSWithSHA384, RSAPSSWithSHA512:
		pk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("scheme %s requires an RSA public key, got %T", scheme, pub)
		}
		h := scheme.hash()
		return rsa.VerifyPSS(pk, h, digest(h, msg), sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h})
	case Ed25519:
		pk, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("scheme %s requires an Ed25519 public key, got %T", scheme, pub)
		}
		if !ed25519.Verify(pk, msg, sig) {
			return fmt.Errorf("Ed25519 signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported signature scheme %s", scheme)
	}
}

// digest hashes msg under h. h must be a registered, linked hash.
func digest(h crypto.Hash, msg []byte) []byte {
	d := h.New()
	d.Write(msg)
	return d.Sum(nil)
}
