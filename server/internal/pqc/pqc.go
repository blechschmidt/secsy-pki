// Package pqc adds post-quantum and hybrid signature support to the PKI on top
// of ML-DSA (FIPS 204, formerly CRYSTALS-Dilithium).
//
// Go's standard crypto/x509 does not (as of this writing) understand ML-DSA
// keys or signatures, so this package hand-assembles the small amount of ASN.1
// the standard library will not: the SubjectPublicKeyInfo and PKCS#8 wrappers
// for ML-DSA keys, and the TBSCertificate/CertificationRequest signing envelope
// for pure-PQC certificates. Everything that Go *can* encode (names, validity,
// the standard v3 extensions) is produced by crypto/x509 and reused verbatim, so
// this package stays a thin, auditable shim rather than a second X.509 encoder.
//
// Two issuance modes are supported:
//
//   - Pure PQC: the subject key and the issuer signature are both ML-DSA. The
//     resulting certificate is post-quantum end to end but is only understood by
//     PQC-aware verifiers (see VerifyChain and docs/certificates/pqc.md for trust-store
//     caveats).
//   - Hybrid ("catalyst", per the ITU-T X.509 / draft-ietf-lamps-x509-alt
//     alternative-signature extensions): the primary key and signature are
//     classical (ECDSA/RSA) so any existing verifier accepts the certificate,
//     while a parallel ML-DSA public key and signature are carried in the
//     subjectAltPublicKeyInfo / altSignatureAlgorithm / altSignatureValue
//     extensions for PQC-aware verifiers. See hybrid.go.
//
// The underlying ML-DSA implementation is Cloudflare CIRCL. Keys are ordinary
// crypto.Signer values, so an HSM that natively supports ML-DSA could supply
// them instead; SoftHSM does not, so the software key provider is the fallback
// for PQC keys (see keyprovider).
package pqc

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/schemes"
)

// Canonical ML-DSA key-type identifiers. They follow the lowercase,
// hyphenated convention already used by the keyprovider for classical keys.
const (
	KeyTypeMLDSA44 = "ml-dsa-44"
	KeyTypeMLDSA65 = "ml-dsa-65"
	KeyTypeMLDSA87 = "ml-dsa-87"
)

// NIST FIPS 204 object identifiers for the ML-DSA parameter sets, from the
// NIST Computer Security Objects Register (arc 2.16.840.1.101.3.4.3).
var (
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

// algorithm binds a canonical key type to its CIRCL scheme and OID.
type algorithm struct {
	keyType string
	oid     asn1.ObjectIdentifier
	scheme  sign.Scheme
}

// algorithms is the registry of supported ML-DSA parameter sets. CIRCL scheme
// names are the FIPS 204 names ("ML-DSA-44" etc.).
var algorithms = []algorithm{
	{KeyTypeMLDSA44, oidMLDSA44, schemes.ByName("ML-DSA-44")},
	{KeyTypeMLDSA65, oidMLDSA65, schemes.ByName("ML-DSA-65")},
	{KeyTypeMLDSA87, oidMLDSA87, schemes.ByName("ML-DSA-87")},
}

func algorithmByKeyType(keyType string) (algorithm, bool) {
	for _, a := range algorithms {
		if a.keyType == keyType {
			return a, true
		}
	}
	return algorithm{}, false
}

func algorithmByOID(oid asn1.ObjectIdentifier) (algorithm, bool) {
	for _, a := range algorithms {
		if a.oid.Equal(oid) {
			return a, true
		}
	}
	return algorithm{}, false
}

func algorithmForPublicKey(pub crypto.PublicKey) (algorithm, bool) {
	pk, ok := pub.(sign.PublicKey)
	if !ok {
		return algorithm{}, false
	}
	name := pk.Scheme().Name()
	for _, a := range algorithms {
		if a.scheme != nil && a.scheme.Name() == name {
			return a, true
		}
	}
	return algorithm{}, false
}

// IsPQC reports whether keyType names a supported post-quantum key algorithm.
func IsPQC(keyType string) bool {
	_, ok := algorithmByKeyType(keyType)
	return ok
}

// IsPQCPublicKey reports whether pub is a supported ML-DSA public key.
func IsPQCPublicKey(pub crypto.PublicKey) bool {
	_, ok := algorithmForPublicKey(pub)
	return ok
}

// KeyTypeOf returns the canonical key type for an ML-DSA public key.
func KeyTypeOf(pub crypto.PublicKey) (string, error) {
	a, ok := algorithmForPublicKey(pub)
	if !ok {
		return "", fmt.Errorf("pqc: not an ML-DSA public key (%T)", pub)
	}
	return a.keyType, nil
}

// NormalizeKeyType maps user-supplied ML-DSA key-type strings (including common
// aliases) to a canonical KeyType* constant. It returns an error for strings it
// does not recognize; callers fall back to their classical normalizer.
func NormalizeKeyType(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ml-dsa-44", "mldsa44", "mldsa-44", "dilithium2":
		return KeyTypeMLDSA44, nil
	case "ml-dsa-65", "mldsa65", "mldsa-65", "dilithium3":
		return KeyTypeMLDSA65, nil
	case "ml-dsa-87", "mldsa87", "mldsa-87", "dilithium5":
		return KeyTypeMLDSA87, nil
	default:
		return "", fmt.Errorf("pqc: unsupported ML-DSA key type %q", s)
	}
}

// VerifyMessage verifies an ML-DSA signature over msg using pub, whose parameter
// set is given by keyType. It is a thin wrapper over the scheme's Verify used for
// raw message signatures (e.g. HSM-style crypto.Signer output).
func VerifyMessage(keyType string, pub crypto.PublicKey, msg, sig []byte) bool {
	a, ok := algorithmByKeyType(keyType)
	if !ok || a.scheme == nil {
		return false
	}
	p, ok := pub.(sign.PublicKey)
	if !ok {
		return false
	}
	return a.scheme.Verify(p, msg, sig, nil)
}

// GenerateKey creates a new ML-DSA key pair of the given canonical key type. The
// returned private key implements crypto.Signer (its Sign method signs the
// supplied message directly — ML-DSA is not pre-hashed — with an empty context).
func GenerateKey(keyType string) (sign.PrivateKey, error) {
	a, ok := algorithmByKeyType(keyType)
	if !ok {
		return nil, fmt.Errorf("pqc: unsupported ML-DSA key type %q", keyType)
	}
	if a.scheme == nil {
		return nil, fmt.Errorf("pqc: ML-DSA scheme for %q is unavailable in this build", keyType)
	}
	_, priv, err := a.scheme.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("pqc: generating %s key: %w", keyType, err)
	}
	return priv, nil
}
