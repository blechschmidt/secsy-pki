package pqc

import (
	"crypto"
	"crypto/sha1"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// pkixAlgorithmIdentifier mirrors the X.509 AlgorithmIdentifier. For ML-DSA the
// parameters field is absent (per draft-ietf-lamps-dilithium-certificates), so
// only the OID is encoded.
type pkixAlgorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
}

// subjectPublicKeyInfo mirrors the X.509 SubjectPublicKeyInfo structure.
type subjectPublicKeyInfo struct {
	Algorithm        pkixAlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// pkcs8 mirrors the PKCS#8 PrivateKeyInfo structure. The privateKey OCTET
// STRING carries the CIRCL binary encoding of the ML-DSA private key. This is an
// internal-at-rest format for the software keystore; it round-trips within this
// system and is not claimed to interoperate with other PKCS#8 ML-DSA encoders.
type pkcs8 struct {
	Version    int
	Algorithm  pkixAlgorithmIdentifier
	PrivateKey []byte
}

// MarshalPKIXPublicKey encodes an ML-DSA public key as a DER SubjectPublicKeyInfo,
// analogous to x509.MarshalPKIXPublicKey for classical keys.
func MarshalPKIXPublicKey(pub crypto.PublicKey) ([]byte, error) {
	a, ok := algorithmForPublicKey(pub)
	if !ok {
		return nil, fmt.Errorf("pqc: not an ML-DSA public key (%T)", pub)
	}
	raw, err := pub.(sign.PublicKey).MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("pqc: marshaling public key: %w", err)
	}
	spki := subjectPublicKeyInfo{
		Algorithm:        pkixAlgorithmIdentifier{Algorithm: a.oid},
		SubjectPublicKey: asn1.BitString{Bytes: raw, BitLength: len(raw) * 8},
	}
	der, err := asn1.Marshal(spki)
	if err != nil {
		return nil, fmt.Errorf("pqc: encoding SubjectPublicKeyInfo: %w", err)
	}
	return der, nil
}

// ParsePKIXPublicKey decodes a DER SubjectPublicKeyInfo carrying an ML-DSA public
// key. It returns an error (that IsUnsupportedAlgorithm reports true for) when
// the SPKI is well-formed but does not name a known ML-DSA algorithm, so callers
// can fall back to x509.ParsePKIXPublicKey for classical keys.
func ParsePKIXPublicKey(der []byte) (crypto.PublicKey, string, error) {
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &spki)
	if err != nil {
		return nil, "", fmt.Errorf("pqc: parsing SubjectPublicKeyInfo: %w", err)
	}
	if len(rest) != 0 {
		return nil, "", fmt.Errorf("pqc: trailing data after SubjectPublicKeyInfo")
	}
	a, ok := algorithmByOID(spki.Algorithm.Algorithm)
	if !ok {
		return nil, "", errUnsupportedAlgorithm{spki.Algorithm.Algorithm}
	}
	if a.scheme == nil {
		return nil, "", fmt.Errorf("pqc: ML-DSA scheme for %s is unavailable in this build", a.keyType)
	}
	pub, err := a.scheme.UnmarshalBinaryPublicKey(spki.SubjectPublicKey.RightAlign())
	if err != nil {
		return nil, "", fmt.Errorf("pqc: decoding %s public key: %w", a.keyType, err)
	}
	return pub, a.keyType, nil
}

// MarshalPKCS8PrivateKey encodes an ML-DSA private key as DER PKCS#8, for the
// software keystore. See the note on the pkcs8 type about interoperability.
func MarshalPKCS8PrivateKey(priv crypto.PrivateKey) ([]byte, error) {
	sk, ok := priv.(sign.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("pqc: not an ML-DSA private key (%T)", priv)
	}
	a, ok := algorithmForPublicKey(sk.Public())
	if !ok {
		return nil, fmt.Errorf("pqc: unsupported ML-DSA private key (%T)", priv)
	}
	raw, err := sk.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("pqc: marshaling private key: %w", err)
	}
	der, err := asn1.Marshal(pkcs8{
		Version:    0,
		Algorithm:  pkixAlgorithmIdentifier{Algorithm: a.oid},
		PrivateKey: raw,
	})
	if err != nil {
		return nil, fmt.Errorf("pqc: encoding PKCS#8: %w", err)
	}
	return der, nil
}

// ParsePKCS8PrivateKey decodes a DER PKCS#8 ML-DSA private key produced by
// MarshalPKCS8PrivateKey. It returns the key, its canonical key type, and an
// error (reporting IsUnsupportedAlgorithm) when the OID is not a known ML-DSA
// algorithm, so the software keystore can fall back to the classical parser.
func ParsePKCS8PrivateKey(der []byte) (sign.PrivateKey, string, error) {
	var p pkcs8
	if _, err := asn1.Unmarshal(der, &p); err != nil {
		return nil, "", fmt.Errorf("pqc: parsing PKCS#8: %w", err)
	}
	a, ok := algorithmByOID(p.Algorithm.Algorithm)
	if !ok {
		return nil, "", errUnsupportedAlgorithm{p.Algorithm.Algorithm}
	}
	if a.scheme == nil {
		return nil, "", fmt.Errorf("pqc: ML-DSA scheme for %s is unavailable in this build", a.keyType)
	}
	sk, err := a.scheme.UnmarshalBinaryPrivateKey(p.PrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("pqc: decoding %s private key: %w", a.keyType, err)
	}
	return sk, a.keyType, nil
}

// SubjectKeyID derives an RFC 5280 §4.2.1.2 (method 1) subject key identifier for
// an ML-DSA public key: the SHA-1 hash of the SubjectPublicKeyInfo's public-key
// BIT STRING. It matches the identifier crypto/x509 derives for classical keys,
// so ML-DSA and classical certificates chain by AKI/SKI uniformly.
func SubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	// Re-parse to isolate the BIT STRING content, mirroring the classical path.
	var spki subjectPublicKeyInfo
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, err
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return sum[:], nil
}

// errUnsupportedAlgorithm marks a well-formed structure whose algorithm OID is
// not a known ML-DSA algorithm. Callers use IsUnsupportedAlgorithm to decide
// whether to retry with a classical parser.
type errUnsupportedAlgorithm struct {
	oid asn1.ObjectIdentifier
}

func (e errUnsupportedAlgorithm) Error() string {
	return fmt.Sprintf("pqc: unsupported algorithm %v (not an ML-DSA key)", e.oid)
}

// IsUnsupportedAlgorithm reports whether err indicates a well-formed key/CSR/cert
// whose algorithm is simply not ML-DSA (as opposed to a malformed encoding).
func IsUnsupportedAlgorithm(err error) bool {
	var u errUnsupportedAlgorithm
	return errors.As(err, &u)
}

// algorithmIdentifierDER encodes a bare AlgorithmIdentifier (OID, no parameters)
// for the given ML-DSA key type, used as the certificate/CSR signatureAlgorithm
// and as the altSignatureAlgorithm extension value.
func algorithmIdentifierDER(keyType string) ([]byte, error) {
	a, ok := algorithmByKeyType(keyType)
	if !ok {
		return nil, fmt.Errorf("pqc: unsupported ML-DSA key type %q", keyType)
	}
	return asn1.Marshal(pkixAlgorithmIdentifier{Algorithm: a.oid})
}

// readElement returns the raw DER (tag+length+content) of the next ASN.1 element
// in s, advancing s past it. It is a small helper for the certificate surgery in
// hybrid verification.
func readElement(s *cryptobyte.String) ([]byte, error) {
	var elem cryptobyte.String
	var tag cryptobyte_asn1.Tag
	if !s.ReadAnyASN1Element(&elem, &tag) {
		return nil, fmt.Errorf("pqc: malformed ASN.1 element")
	}
	return []byte(elem), nil
}
