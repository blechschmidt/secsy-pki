// Package nameconstraints implements RFC 5280 §4.2.1.10 X.509 Name Constraints
// (extension 2.5.29.30): building the extension for a CA certificate, parsing it
// back from an issuer certificate, and evaluating a leaf's identity (its subject
// alternative names and subject distinguished name) against the permitted and
// excluded name subtrees.
//
// Go's crypto/x509 encoder only emits DNS, IP, e-mail, and URI subtrees and
// cannot emit or parse directoryName subtrees, so this package hand-rolls the
// ASN.1 for all five general-name forms the enterprise CA supports. The evaluator
// mirrors the matching rules a conforming path validator (e.g. OpenSSL, which
// enforces name constraints during `openssl verify`) applies, so a leaf accepted
// by the pre-issuance gate also validates against the constrained chain.
package nameconstraints

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
)

// oidNameConstraints is the object identifier of the Name Constraints extension.
var oidNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}

// OID returns the Name Constraints extension OID (2.5.29.30).
func OID() asn1.ObjectIdentifier { return oidNameConstraints }

// Subtrees groups the name subtrees of one polarity (permitted or excluded),
// partitioned by general-name form. Every field is optional; an empty field
// leaves that name form unconstrained for this polarity.
type Subtrees struct {
	// DNS subtrees. A value "example.com" matches that name and any subdomain
	// (host.example.com); an empty string matches every DNS name.
	DNS []string
	// IP subtrees, each a CIDR network. A leaf IP matches when the network
	// contains it.
	IP []*net.IPNet
	// Email subtrees. A value containing "@" matches that exact mailbox; a bare
	// host "example.com" matches any mailbox on that host; a value beginning "."
	// (".example.com") matches any mailbox in that domain.
	Email []string
	// URI subtrees, matched against the host component of a leaf URI using the
	// same domain rules as DNS.
	URI []string
	// DirNames are directoryName subtrees. A leaf subject matches when the
	// subtree's relative distinguished names are all present in the subject
	// (organization/geography scoping).
	DirNames []pkix.Name
}

// isEmpty reports whether the subtree set constrains nothing.
func (s Subtrees) isEmpty() bool {
	return len(s.DNS) == 0 && len(s.IP) == 0 && len(s.Email) == 0 &&
		len(s.URI) == 0 && len(s.DirNames) == 0
}

// Constraints is a parsed or to-be-built Name Constraints extension.
type Constraints struct {
	Permitted Subtrees
	Excluded  Subtrees
	// Critical marks the emitted extension critical. RFC 5280 requires name
	// constraints to be critical; the enterprise CA defaults to true.
	Critical bool
}

// IsZero reports whether the constraints impose nothing (no extension needed).
func (c Constraints) IsZero() bool {
	return c.Permitted.isEmpty() && c.Excluded.isEmpty()
}

// generalName tags within a GeneralName CHOICE (RFC 5280 §4.2.1.6).
const (
	tagRFC822Name = 1
	tagDNSName    = 2
	tagDirName    = 4
	tagURI        = 6
	tagIPAddress  = 7
)

// generalSubtree is a single GeneralSubtree: the minimum/maximum BaseDistance
// fields are always absent (RFC 5280 mandates minimum=0 and no maximum), so only
// the base GeneralName is encoded.
type generalSubtree struct {
	Base asn1.RawValue
}

// Extension builds the DER-encoded Name Constraints pkix.Extension. It returns a
// zero Extension and false when the constraints are empty (nothing to emit).
func (c Constraints) Extension() (pkix.Extension, bool, error) {
	if c.IsZero() {
		return pkix.Extension{}, false, nil
	}
	permitted, err := encodeSubtrees(0, c.Permitted)
	if err != nil {
		return pkix.Extension{}, false, fmt.Errorf("encoding permitted subtrees: %w", err)
	}
	excluded, err := encodeSubtrees(1, c.Excluded)
	if err != nil {
		return pkix.Extension{}, false, fmt.Errorf("encoding excluded subtrees: %w", err)
	}
	var seq []byte
	seq = append(seq, permitted...)
	seq = append(seq, excluded...)
	value, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      seq,
	})
	if err != nil {
		return pkix.Extension{}, false, fmt.Errorf("encoding name constraints: %w", err)
	}
	return pkix.Extension{Id: oidNameConstraints, Critical: c.Critical, Value: value}, true, nil
}

// encodeSubtrees encodes one polarity's subtrees into the context-tagged
// [tag] GeneralSubtrees element, or nil when the polarity is empty.
func encodeSubtrees(tag int, s Subtrees) ([]byte, error) {
	var subtrees [][]byte

	appendGN := func(gn asn1.RawValue) error {
		der, err := asn1.Marshal(generalSubtree{Base: gn})
		if err != nil {
			return err
		}
		subtrees = append(subtrees, der)
		return nil
	}

	for _, d := range s.DNS {
		if err := appendGN(ia5GeneralName(tagDNSName, d)); err != nil {
			return nil, err
		}
	}
	for _, e := range s.Email {
		if err := appendGN(ia5GeneralName(tagRFC822Name, e)); err != nil {
			return nil, err
		}
	}
	for _, u := range s.URI {
		if err := appendGN(ia5GeneralName(tagURI, u)); err != nil {
			return nil, err
		}
	}
	for _, ipnet := range s.IP {
		gn, err := ipGeneralName(ipnet)
		if err != nil {
			return nil, err
		}
		if err := appendGN(gn); err != nil {
			return nil, err
		}
	}
	for _, dn := range s.DirNames {
		gn, err := dirGeneralName(dn)
		if err != nil {
			return nil, err
		}
		if err := appendGN(gn); err != nil {
			return nil, err
		}
	}

	if len(subtrees) == 0 {
		return nil, nil
	}
	var content []byte
	for _, st := range subtrees {
		content = append(content, st...)
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tag,
		IsCompound: true,
		Bytes:      content,
	})
}

// ia5GeneralName builds a primitive context-tagged IA5String GeneralName
// (dNSName, rfc822Name, or uniformResourceIdentifier).
func ia5GeneralName(tag int, value string) asn1.RawValue {
	return asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   tag,
		Bytes: []byte(value),
	}
}

// ipGeneralName builds an iPAddress GeneralName for a name-constraint subtree:
// per RFC 5280 the OCTET STRING carries the network address followed by the
// subnet mask (8 bytes for IPv4, 32 for IPv6).
func ipGeneralName(ipnet *net.IPNet) (asn1.RawValue, error) {
	ip := ipnet.IP
	mask := ipnet.Mask
	if v4 := ip.To4(); v4 != nil && len(mask) == net.IPv4len {
		ip = v4
	}
	if len(ip) != len(mask) {
		return asn1.RawValue{}, fmt.Errorf("IP subtree %s: address/mask length mismatch", ipnet)
	}
	octets := make([]byte, 0, len(ip)+len(mask))
	octets = append(octets, ip...)
	octets = append(octets, mask...)
	return asn1.RawValue{
		Class: asn1.ClassContextSpecific,
		Tag:   tagIPAddress,
		Bytes: octets,
	}, nil
}

// dirGeneralName builds a directoryName GeneralName. directoryName is [4]
// EXPLICIT because Name is itself a CHOICE, so the context tag wraps the DER of
// the RDNSequence.
func dirGeneralName(dn pkix.Name) (asn1.RawValue, error) {
	rdnDER, err := asn1.Marshal(dn.ToRDNSequence())
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("encoding directoryName %q: %w", dn.String(), err)
	}
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        tagDirName,
		IsCompound: true,
		Bytes:      rdnDER,
	}, nil
}
