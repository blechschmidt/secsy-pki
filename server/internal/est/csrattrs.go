package est

// This file implements the RFC 7030 §4.5 CSR Attributes advertisement:
//
//	CsrAttrs  ::= SEQUENCE SIZE (0..MAX) OF AttrOrOID
//	AttrOrOID ::= CHOICE { oid OBJECT IDENTIFIER, attribute Attribute }
//	Attribute ::= SEQUENCE { type OBJECT IDENTIFIER,
//	                         values SET SIZE(1..MAX) OF ANY }
//
// A bare OID tells the client to include an attribute/extension of that type in
// its CSR (choosing the value itself — e.g. challengePassword, a signature
// algorithm, or an attestation statement). A full Attribute (type + values)
// tells the client to include the attribute/extension with those exact values
// (e.g. id-ecPublicKey with a named curve, or extKeyUsage with specific
// purposes). Because AttrOrOID is a CHOICE between an OBJECT IDENTIFIER (tag
// 0x06) and a SEQUENCE (tag 0x30), the two forms are unambiguous on the wire.
//
// The advertised set is derived from the resolved issuance profile so a client
// learns, before generating a key, what shape the certificate will take: the
// expected subject public-key algorithm/curve, the key usages and extended key
// usages the CA will stamp, and — for attestation-required profiles — that the
// CSR must carry a hardware key-attestation statement. An operator may instead
// declare an explicit per-profile attribute list (see Config.CSRAttrs), which is
// advertised verbatim in place of the derived set.

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// OIDs referenced by the CSR-attributes advertisement.
var (
	oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
	oidExtensionRequest  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}
	oidECPublicKey       = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidRSAEncryption     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidKeyUsage          = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 37}
	// oidAttestationBundle mirrors internal/attestation's private extension OID
	// under which a client bundles a hardware key-attestation certificate chain
	// inside its CSR (Task 49). Advertising it as a bare OID tells the client an
	// attestation statement is required for this profile.
	oidAttestationBundle = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 58270, 1, 1}

	// Named-curve OIDs used as the value of the id-ecPublicKey key-type hint.
	oidCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	// FIPS 204 ML-DSA parameter-set OIDs, advertised as the subject public-key
	// hint for pure post-quantum profiles.
	oidMLDSA44 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	oidMLDSA65 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}
	oidMLDSA87 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}
)

// ekuOIDByName maps a profile's extended-key-usage identifier to its KeyPurposeId
// OID. The keys mirror pki.X509ExtKeyUsageFromString so any EKU a profile can
// declare is advertisable.
var ekuOIDByName = map[string]asn1.ObjectIdentifier{
	"serverAuth":      {1, 3, 6, 1, 5, 5, 7, 3, 1},
	"clientAuth":      {1, 3, 6, 1, 5, 5, 7, 3, 2},
	"codeSigning":     {1, 3, 6, 1, 5, 5, 7, 3, 3},
	"emailProtection": {1, 3, 6, 1, 5, 5, 7, 3, 4},
	"timeStamping":    {1, 3, 6, 1, 5, 5, 7, 3, 8},
	"ocspSigning":     {1, 3, 6, 1, 5, 5, 7, 3, 9},
}

// attrOrOID is one element of the CsrAttrs SEQUENCE. When values is nil it
// encodes as a bare OBJECT IDENTIFIER; otherwise as an Attribute SEQUENCE whose
// SET OF value carries each pre-encoded DER element in values.
type attrOrOID struct {
	oid    asn1.ObjectIdentifier
	values [][]byte
}

// bareOID advertises an OID alone: the client must include an attribute or
// extension of this type, supplying the value itself.
func bareOID(oid asn1.ObjectIdentifier) attrOrOID { return attrOrOID{oid: oid} }

// attribute advertises an Attribute { type, SET OF values } with at least one
// pre-encoded DER value element.
func attribute(oid asn1.ObjectIdentifier, values ...[]byte) attrOrOID {
	return attrOrOID{oid: oid, values: values}
}

// CSRAttr is one operator-declared /csrattrs entry used to override the derived
// advertisement for a profile. An entry with no Values encodes as a bare OID
// (e.g. OID "1.2.840.113549.1.9.7" advertises a required challengePassword); an
// entry with Values encodes as an Attribute whose SET OF value holds each OID
// (e.g. OID "1.2.840.10045.2.1" with Values ["1.3.132.0.34"] requests an EC key
// on P-384). All values are OBJECT IDENTIFIERs, which covers the attributes EST
// clients act on (curves, key-purpose OIDs, signature algorithms, extension
// types); profiles needing a richer value should rely on the derived defaults.
type CSRAttr struct {
	OID    string
	Values []string
}

// encodeCsrAttrs DER-encodes the CsrAttrs SEQUENCE. SET OF value elements are
// sorted into canonical DER order so the output is deterministic and standards
// compliant regardless of the order values were supplied.
func encodeCsrAttrs(attrs []attrOrOID) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, a := range attrs {
			if a.values == nil {
				b.AddASN1ObjectIdentifier(a.oid)
				continue
			}
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(a.oid)
				sorted := append([][]byte(nil), a.values...)
				sort.Slice(sorted, func(i, j int) bool {
					return bytes.Compare(sorted[i], sorted[j]) < 0
				})
				b.AddASN1(cryptobyte_asn1.SET, func(b *cryptobyte.Builder) {
					for _, v := range sorted {
						b.AddBytes(v)
					}
				})
			})
		}
	})
	return b.Bytes()
}

// deriveCsrAttrs builds the advertised attribute set from a resolved profile.
// attestRequired reflects the profile's EST attestation mode (ModeRequire);
// curve is the named curve advertised with an id-ecPublicKey key-type hint.
func deriveCsrAttrs(p ca.Profile, attestRequired bool, curve asn1.ObjectIdentifier) ([]attrOrOID, error) {
	var attrs []attrOrOID

	// (1) Subject public-key algorithm hint. A pure-PQC profile mandates ML-DSA;
	// a profile whose key usages require key transport (keyEncipherment) mandates
	// RSA; everything else advises the modern default of an EC key on curve.
	switch {
	case p.Algorithm == ca.AlgPQC:
		// PQCKeyType is the exported parameter-set field; an empty value maps to
		// the ml-dsa-65 default inside mlDSAKeyOID.
		if oid, ok := mlDSAKeyOID(p.PQCKeyType); ok {
			attrs = append(attrs, bareOID(oid))
		}
	case profileNeedsRSA(p):
		attrs = append(attrs, bareOID(oidRSAEncryption))
	default:
		cv, err := oidValue(curve)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attribute(oidECPublicKey, cv))
	}

	// (2) keyUsage the profile stamps, as the exact BIT STRING the leaf will bear.
	if len(p.KeyUsages) > 0 {
		ku, err := keyUsageMask(p)
		if err != nil {
			return nil, err
		}
		val, err := pki.KeyUsageBitString(ku)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attribute(oidKeyUsage, val))
	}

	// (3) extKeyUsage purposes the profile stamps.
	if len(p.ExtKeyUsages) > 0 {
		vals, err := ekuValues(p.ExtKeyUsages)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attribute(oidExtKeyUsage, vals...))
	}

	// (4) A profile that requires hardware key attestation advertises the
	// attestation-bundle OID so the client knows to carry an attestation
	// statement — without it the enrollment fails closed.
	if attestRequired {
		attrs = append(attrs, bareOID(oidAttestationBundle))
	}

	return attrs, nil
}

// ValidateCSRAttrConfig checks the /csrattrs configuration at startup so a bad
// curve name or malformed override OID fails fast rather than at first request.
func ValidateCSRAttrConfig(ecCurve string, overrides map[string][]CSRAttr) error {
	if _, err := resolveECCurve(ecCurve); err != nil {
		return err
	}
	for profile, specs := range overrides {
		attrs, err := buildOverrideAttrs(specs)
		if err != nil {
			return fmt.Errorf("profile %q: %w", profile, err)
		}
		// Encode to catch OIDs that parse syntactically but are not valid DER
		// object identifiers (e.g. a first arc > 2) before the first request.
		if _, err := encodeCsrAttrs(attrs); err != nil {
			return fmt.Errorf("profile %q: %w", profile, err)
		}
	}
	return nil
}

// buildOverrideAttrs translates an operator-declared per-profile attribute list
// into the encodable form.
func buildOverrideAttrs(specs []CSRAttr) ([]attrOrOID, error) {
	attrs := make([]attrOrOID, 0, len(specs))
	for _, s := range specs {
		oid, err := parseOID(s.OID)
		if err != nil {
			return nil, fmt.Errorf("est csrattrs override: %w", err)
		}
		if len(s.Values) == 0 {
			attrs = append(attrs, bareOID(oid))
			continue
		}
		vals := make([][]byte, 0, len(s.Values))
		for _, v := range s.Values {
			void, err := parseOID(v)
			if err != nil {
				return nil, fmt.Errorf("est csrattrs override %s: %w", s.OID, err)
			}
			dv, err := oidValue(void)
			if err != nil {
				return nil, err
			}
			vals = append(vals, dv)
		}
		attrs = append(attrs, attribute(oid, vals...))
	}
	return attrs, nil
}

// oidValue returns the DER encoding of an OBJECT IDENTIFIER for use as an
// Attribute value.
func oidValue(oid asn1.ObjectIdentifier) ([]byte, error) {
	return asn1.Marshal(oid)
}

// keyUsageMask recomputes a profile's x509.KeyUsage bitmask from its identifiers.
func keyUsageMask(p ca.Profile) (x509.KeyUsage, error) {
	var ku x509.KeyUsage
	for _, s := range p.KeyUsages {
		v, ok := pki.X509KeyUsageFromString[s]
		if !ok {
			return 0, fmt.Errorf("est csrattrs: profile %q references unknown key usage %q", p.Name, s)
		}
		ku |= v
	}
	return ku, nil
}

// ekuValues encodes a profile's extended-key-usage identifiers as DER OID values.
func ekuValues(names []string) ([][]byte, error) {
	out := make([][]byte, 0, len(names))
	for _, n := range names {
		oid, ok := ekuOIDByName[n]
		if !ok {
			return nil, fmt.Errorf("est csrattrs: unknown extended key usage %q", n)
		}
		v, err := oidValue(oid)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// profileNeedsRSA reports whether the profile's key usages require an RSA subject
// key (key transport), which an EC key cannot satisfy.
func profileNeedsRSA(p ca.Profile) bool {
	for _, ku := range p.KeyUsages {
		if ku == "keyEncipherment" || ku == "dataEncipherment" {
			return true
		}
	}
	return false
}

// mlDSAKeyOID maps an ML-DSA parameter-set name to its FIPS 204 OID.
func mlDSAKeyOID(paramSet string) (asn1.ObjectIdentifier, bool) {
	switch strings.ToLower(strings.TrimSpace(paramSet)) {
	case "", "ml-dsa-65", "mldsa65":
		return oidMLDSA65, true
	case "ml-dsa-44", "mldsa44":
		return oidMLDSA44, true
	case "ml-dsa-87", "mldsa87":
		return oidMLDSA87, true
	default:
		return nil, false
	}
}

// resolveECCurve maps a configured curve name to the OID advertised with the
// id-ecPublicKey hint. An empty name defaults to P-256.
func resolveECCurve(name string) (asn1.ObjectIdentifier, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "p-256", "p256", "prime256v1", "secp256r1":
		return oidCurveP256, nil
	case "p-384", "p384", "secp384r1":
		return oidCurveP384, nil
	case "p-521", "p521", "secp521r1":
		return oidCurveP521, nil
	default:
		return nil, fmt.Errorf("est csrattrs: unknown ec_curve %q (want p-256, p-384, or p-521)", name)
	}
}

// parseOID parses a dotted-decimal object identifier.
func parseOID(s string) (asn1.ObjectIdentifier, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty OID")
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OID %q: need at least two arcs", s)
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid OID %q", s)
		}
		oid[i] = n
	}
	return oid, nil
}
