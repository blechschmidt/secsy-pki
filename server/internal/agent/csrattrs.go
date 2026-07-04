package agent

// Client-side handling of the EST CSR Attributes advertisement (RFC 7030 §4.5).
// The agent fetches GET /csrattrs before enrolling and honors the advertised
// attributes when building its CSR: it adopts the advertised subject public-key
// type/curve (when the spec leaves key_type as "auto") and reflects the
// advertised extended key usages into the request. Attributes it cannot satisfy
// locally (e.g. a hardware attestation statement) are surfaced in logs so an
// operator can see why an enrollment may be rejected.

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// OIDs the agent recognizes in a /csrattrs advertisement.
var (
	oidChallengePasswordC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}
	oidECPublicKeyC       = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidRSAEncryptionC     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidExtKeyUsageC       = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidAttestationBundleC = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 58270, 1, 1}
	oidCurveP256C         = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidCurveP384C         = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

// csrAttr is one parsed AttrOrOID from a /csrattrs response. bare is true for a
// standalone OID; otherwise values holds the OBJECT IDENTIFIER members of the
// attribute's SET (non-OID values, e.g. a keyUsage BIT STRING, are not captured
// because the agent does not act on them).
type csrAttr struct {
	oid    asn1.ObjectIdentifier
	bare   bool
	values []asn1.ObjectIdentifier
}

// parseCSRAttrs decodes a DER CsrAttrs (SEQUENCE OF AttrOrOID). AttrOrOID is a
// CHOICE, distinguished on the wire by tag: an OBJECT IDENTIFIER is a bare OID,
// a SEQUENCE is an Attribute { type, SET OF value }.
func parseCSRAttrs(der []byte) ([]csrAttr, error) {
	input := cryptobyte.String(der)
	var seq cryptobyte.String
	if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("csrattrs: malformed outer SEQUENCE")
	}
	var out []csrAttr
	for !seq.Empty() {
		if seq.PeekASN1Tag(cryptobyte_asn1.OBJECT_IDENTIFIER) {
			var oid asn1.ObjectIdentifier
			if !seq.ReadASN1ObjectIdentifier(&oid) {
				return nil, fmt.Errorf("csrattrs: malformed OID element")
			}
			out = append(out, csrAttr{oid: oid, bare: true})
			continue
		}
		var attr cryptobyte.String
		if !seq.ReadASN1(&attr, cryptobyte_asn1.SEQUENCE) {
			return nil, fmt.Errorf("csrattrs: malformed attribute")
		}
		var typ asn1.ObjectIdentifier
		if !attr.ReadASN1ObjectIdentifier(&typ) {
			return nil, fmt.Errorf("csrattrs: malformed attribute type")
		}
		var set cryptobyte.String
		if !attr.ReadASN1(&set, cryptobyte_asn1.SET) {
			return nil, fmt.Errorf("csrattrs: malformed attribute values")
		}
		a := csrAttr{oid: typ}
		for !set.Empty() {
			if set.PeekASN1Tag(cryptobyte_asn1.OBJECT_IDENTIFIER) {
				var v asn1.ObjectIdentifier
				if !set.ReadASN1ObjectIdentifier(&v) {
					return nil, fmt.Errorf("csrattrs: malformed attribute value OID")
				}
				a.values = append(a.values, v)
				continue
			}
			// Skip a value type the agent does not act on (e.g. a BIT STRING).
			var skip cryptobyte.String
			var tag cryptobyte_asn1.Tag
			if !set.ReadAnyASN1(&skip, &tag) {
				return nil, fmt.Errorf("csrattrs: malformed attribute value")
			}
		}
		out = append(out, a)
	}
	return out, nil
}

// keyTypeFromCSRAttrs maps the advertised subject public-key algorithm to an
// agent key_type. It returns "" when nothing applies (or the advertised
// algorithm is one the software agent cannot generate locally, e.g. ML-DSA).
func keyTypeFromCSRAttrs(attrs []csrAttr) string {
	for _, a := range attrs {
		if a.bare && a.oid.Equal(oidRSAEncryptionC) {
			return "rsa-2048"
		}
		if a.oid.Equal(oidECPublicKeyC) {
			for _, v := range a.values {
				switch {
				case v.Equal(oidCurveP256C):
					return "ecdsa-p256"
				case v.Equal(oidCurveP384C):
					return "ecdsa-p384"
				}
			}
			// id-ecPublicKey with no (or an unsupported) curve: default EC.
			return "ecdsa-p256"
		}
	}
	return ""
}

// ekuOIDsFromCSRAttrs returns the extended-key-usage purpose OIDs the server
// advertised, if any.
func ekuOIDsFromCSRAttrs(attrs []csrAttr) []asn1.ObjectIdentifier {
	for _, a := range attrs {
		if a.oid.Equal(oidExtKeyUsageC) {
			return a.values
		}
	}
	return nil
}

// csrExtensionsFromCSRAttrs builds the CSR extensions that reflect the advertised
// attributes: currently the extended key usage. The issuing CA sets these
// authoritatively from the profile, so this makes the request self-describing
// rather than changing the outcome.
func csrExtensionsFromCSRAttrs(attrs []csrAttr) ([]pkix.Extension, error) {
	var exts []pkix.Extension
	if ekus := ekuOIDsFromCSRAttrs(attrs); len(ekus) > 0 {
		val, err := asn1.Marshal(ekus)
		if err != nil {
			return nil, fmt.Errorf("encoding advertised extKeyUsage: %w", err)
		}
		exts = append(exts, pkix.Extension{Id: oidExtKeyUsageC, Value: val})
	}
	return exts, nil
}

// requiresAttestation reports whether the advertisement demands a hardware
// key-attestation statement the software agent cannot produce.
func requiresAttestation(attrs []csrAttr) bool {
	for _, a := range attrs {
		if a.bare && a.oid.Equal(oidAttestationBundleC) {
			return true
		}
	}
	return false
}

// summarizeCSRAttrs renders the advertised attributes for a log line.
func summarizeCSRAttrs(attrs []csrAttr) string {
	parts := make([]string, 0, len(attrs))
	for _, a := range attrs {
		switch {
		case a.bare && a.oid.Equal(oidChallengePasswordC):
			parts = append(parts, "challengePassword")
		case a.bare && a.oid.Equal(oidAttestationBundleC):
			parts = append(parts, "attestation")
		case a.bare && a.oid.Equal(oidRSAEncryptionC):
			parts = append(parts, "rsaEncryption")
		case a.oid.Equal(oidECPublicKeyC):
			parts = append(parts, "ecPublicKey")
		case a.oid.Equal(oidExtKeyUsageC):
			parts = append(parts, "extKeyUsage")
		default:
			parts = append(parts, a.oid.String())
		}
	}
	return strings.Join(parts, ",")
}
