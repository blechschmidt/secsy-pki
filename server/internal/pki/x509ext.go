package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
	"strings"
)

// This file carries the DER encoders for the X.509 v3 extensions crypto/x509
// cannot emit from its certificate template. They are the building blocks of the
// full CA-certificate extension set (see internal/caext): each one takes already
// validated Go values and returns a complete pkix.Extension, ready to hand to
// x509.CreateCertificate through ExtraExtensions — which takes precedence over
// anything crypto/x509 would have generated for the same OID.
//
// Everything here encodes; nothing here decides policy. Criticality is an
// argument rather than a constant wherever RFC 5280 leaves the choice to the
// issuer, and the few extensions whose criticality the RFC fixes say so in their
// doc comment and ignore the caller.
//
// id-pkix-ocsp-nocheck already has an encoder next to the OCSP responder
// (OCSPNoCheckExtension in ocsp.go); it is reused rather than repeated here.

var (
	// OIDSubjectDirectoryAttributes is id-ce-subjectDirectoryAttributes
	// (RFC 5280 §4.2.1.8, { id-ce 9 }): non-identifying directory attributes of
	// the subject, such as a date of birth or place of residence. Always
	// non-critical.
	OIDSubjectDirectoryAttributes = asn1.ObjectIdentifier{2, 5, 29, 9}
	// OIDIssuerAltName is id-ce-issuerAltName (RFC 5280 §4.2.1.7, { id-ce 18 }):
	// alternative names for the certificate issuer. SHOULD be non-critical.
	OIDIssuerAltName = asn1.ObjectIdentifier{2, 5, 29, 18}
	// OIDFreshestCRL is id-ce-freshestCRL (RFC 5280 §4.2.1.15, { id-ce 46 }),
	// also called the delta-CRL distribution point. Same syntax as
	// cRLDistributionPoints; MUST be non-critical.
	OIDFreshestCRL = asn1.ObjectIdentifier{2, 5, 29, 46}
	// OIDInhibitAnyPolicy is id-ce-inhibitAnyPolicy (RFC 5280 §4.2.1.14,
	// { id-ce 54 }): the number of further certificates in the path for which
	// anyPolicy is still honoured. MUST be critical.
	OIDInhibitAnyPolicy = asn1.ObjectIdentifier{2, 5, 29, 54}
	// OIDSubjectInfoAccess is id-pe-subjectInfoAccess (RFC 5280 §4.2.2.2):
	// how to reach services offered by the subject — for a CA, its certificate
	// repository. MUST be non-critical.
	OIDSubjectInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 11}
	// OIDAuthorityInfoAccess is id-pe-authorityInfoAccess (RFC 5280 §4.2.2.1).
	OIDAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}

	// OIDAccessMethodOCSP is id-ad-ocsp: an OCSP responder for the issuer.
	OIDAccessMethodOCSP = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	// OIDAccessMethodCAIssuers is id-ad-caIssuers: where the issuer's own
	// certificate can be fetched (AIA chain building).
	OIDAccessMethodCAIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
	// OIDAccessMethodTimeStamping is id-ad-timeStamping: an RFC 3161 TSA offered
	// by the subject (SIA).
	OIDAccessMethodTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 3}
	// OIDAccessMethodCARepository is id-ad-caRepository: the repository in which
	// the subject CA publishes the certificates it issues (SIA).
	OIDAccessMethodCARepository = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 5}

	// OIDNetscapeCertType is the legacy Netscape certificate-type extension
	// (2.16.840.1.113730.1.1), a BIT STRING of intended uses. Obsoleted by
	// keyUsage/extKeyUsage but still read by some old devices.
	OIDNetscapeCertType = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 1}
	// OIDNetscapeComment is the legacy Netscape comment extension
	// (2.16.840.1.113730.1.13): an IA5String some tools display to users.
	OIDNetscapeComment = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 1, 13}
)

// OtherName is one RFC 5280 GeneralName otherName entry: a type identifier and
// the DER of its value. Value is the complete encoding of the inner value (the
// content of the [0] EXPLICIT wrapper), so a caller can carry any ASN.1 type the
// type-id defines.
type OtherName struct {
	TypeID asn1.ObjectIdentifier
	Value  []byte
}

// GeneralNames is an encodable RFC 5280 GeneralNames: the union of every
// GeneralName CHOICE alternative this PKI emits. The x400Address [3] and
// ediPartyName [5] alternatives are deliberately absent — no modern relying
// party consumes them, and OtherNames is the escape hatch for anything else.
//
// Entries are encoded in the order of the fields below, which is the
// conventional order readers expect (otherName first, as smartcard-logon
// certificates place the UPN).
type GeneralNames struct {
	OtherNames []OtherName
	Emails     []string // rfc822Name [1]
	DNSNames   []string // dNSName [2]
	// DirNames are directoryName [4] entries as ordered RDN sequences. The
	// sequence form rather than pkix.Name is deliberate: pkix.Name groups
	// attributes by kind and so cannot represent the order an operator wrote,
	// and a directoryName is compared as an ordered sequence.
	DirNames      []pkix.RDNSequence
	URIs          []string // uniformResourceIdentifier [6]
	IPs           []net.IP // iPAddress [7]
	RegisteredIDs []asn1.ObjectIdentifier
}

// IsEmpty reports whether the set would encode an empty SEQUENCE, which RFC 5280
// forbids (GeneralNames has a lower bound of one).
func (g GeneralNames) IsEmpty() bool {
	return len(g.OtherNames) == 0 && len(g.Emails) == 0 && len(g.DNSNames) == 0 &&
		len(g.DirNames) == 0 && len(g.URIs) == 0 && len(g.IPs) == 0 &&
		len(g.RegisteredIDs) == 0
}

// OtherNameUTF8 builds an otherName whose value is a UTF8String, the shape most
// otherName type-ids (including id-ms-UPN) use.
func OtherNameUTF8(typeID asn1.ObjectIdentifier, value string) (OtherName, error) {
	der, err := asn1.MarshalWithParams(value, "utf8")
	if err != nil {
		return OtherName{}, fmt.Errorf("encoding otherName %s value: %w", typeID, err)
	}
	return OtherName{TypeID: typeID, Value: der}, nil
}

// encode serializes the GeneralNames entries as the concatenated DER of their
// GeneralName CHOICE alternatives (without the enclosing SEQUENCE).
func (g GeneralNames) encode() ([]byte, error) {
	var out []byte
	appendRaw := func(rv asn1.RawValue) error {
		b, err := asn1.Marshal(rv)
		if err != nil {
			return err
		}
		out = append(out, b...)
		return nil
	}
	// ctx builds a primitive context-specific GeneralName alternative; the
	// IA5String/OCTET STRING content is carried verbatim because the [n] tag is
	// IMPLICIT and replaces the universal tag.
	ctx := func(tag int, content []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: content}
	}

	for _, o := range g.OtherNames {
		if len(o.TypeID) == 0 {
			return nil, fmt.Errorf("otherName requires a type-id OID")
		}
		if len(o.Value) == 0 {
			return nil, fmt.Errorf("otherName %s requires a value", o.TypeID)
		}
		// OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }.
		// The [0] GeneralName tag is IMPLICIT, so it replaces the SEQUENCE tag;
		// the inner value tag is EXPLICIT and wraps the value's own DER.
		explicitValue, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      o.Value,
		})
		if err != nil {
			return nil, fmt.Errorf("encoding otherName %s value: %w", o.TypeID, err)
		}
		oidDER, err := asn1.Marshal(o.TypeID)
		if err != nil {
			return nil, fmt.Errorf("encoding otherName type-id %s: %w", o.TypeID, err)
		}
		inner := make([]byte, 0, len(oidDER)+len(explicitValue))
		inner = append(inner, oidDER...)
		inner = append(inner, explicitValue...)
		if err := appendRaw(asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner,
		}); err != nil {
			return nil, err
		}
	}
	for _, e := range g.Emails {
		if err := appendRaw(ctx(1, []byte(e))); err != nil {
			return nil, err
		}
	}
	for _, d := range g.DNSNames {
		if err := appendRaw(ctx(2, []byte(d))); err != nil {
			return nil, err
		}
	}
	for _, dn := range g.DirNames {
		// directoryName [4] Name — Name is itself a CHOICE, so the tag is
		// EXPLICIT (constructed) and wraps the RDNSequence SEQUENCE.
		rdnDER, err := asn1.Marshal(dn)
		if err != nil {
			return nil, fmt.Errorf("encoding directoryName %q: %w", dn.String(), err)
		}
		if err := appendRaw(asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: rdnDER,
		}); err != nil {
			return nil, err
		}
	}
	for _, u := range g.URIs {
		if err := appendRaw(ctx(6, []byte(u))); err != nil {
			return nil, err
		}
	}
	for _, ip := range g.IPs {
		b := ip
		if v4 := ip.To4(); v4 != nil {
			b = v4
		}
		if len(b) != net.IPv4len && len(b) != net.IPv6len {
			return nil, fmt.Errorf("iPAddress %q is neither 4 nor 16 bytes", ip)
		}
		if err := appendRaw(ctx(7, b)); err != nil {
			return nil, err
		}
	}
	for _, oid := range g.RegisteredIDs {
		// registeredID [8] OBJECT IDENTIFIER — IMPLICIT, so only the OID's
		// content octets travel under the [8] tag.
		der, err := asn1.Marshal(oid)
		if err != nil {
			return nil, fmt.Errorf("encoding registeredID %s: %w", oid, err)
		}
		// Strip the universal OID tag+length, keeping the content octets.
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(der, &raw); err != nil {
			return nil, fmt.Errorf("encoding registeredID %s: %w", oid, err)
		}
		if err := appendRaw(ctx(8, raw.Bytes)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// GeneralNamesExtension builds an extension whose value is a GeneralNames
// SEQUENCE — subjectAltName (2.5.29.17) and issuerAltName (2.5.29.18) share this
// syntax. It rejects an empty set, which would encode a SEQUENCE RFC 5280
// forbids.
func GeneralNamesExtension(oid asn1.ObjectIdentifier, critical bool, g GeneralNames) (pkix.Extension, error) {
	if g.IsEmpty() {
		return pkix.Extension{}, fmt.Errorf("extension %s requires at least one general name", oid)
	}
	names, err := g.encode()
	if err != nil {
		return pkix.Extension{}, err
	}
	value, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      names,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding %s: %w", oid, err)
	}
	return pkix.Extension{Id: oid, Critical: critical, Value: value}, nil
}

// AccessDescription is one RFC 5280 AccessDescription: an access method and the
// URI at which that service is reachable. Both authorityInfoAccess and
// subjectInfoAccess are SEQUENCEs of these.
type AccessDescription struct {
	Method asn1.ObjectIdentifier
	URI    string
}

// accessDescription mirrors the ASN.1 structure with a uniformResourceIdentifier
// accessLocation, which is the only GeneralName form relying parties consume here.
type accessDescription struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue
}

// AccessSyntaxExtension builds an authorityInfoAccess or subjectInfoAccess
// extension from a list of method/URI pairs. RFC 5280 requires both to be
// non-critical, so criticality is not a parameter.
func AccessSyntaxExtension(oid asn1.ObjectIdentifier, descs []AccessDescription) (pkix.Extension, error) {
	if len(descs) == 0 {
		return pkix.Extension{}, fmt.Errorf("extension %s requires at least one access description", oid)
	}
	out := make([]accessDescription, 0, len(descs))
	for _, d := range descs {
		if len(d.Method) == 0 {
			return pkix.Extension{}, fmt.Errorf("extension %s: access description requires a method OID", oid)
		}
		if strings.TrimSpace(d.URI) == "" {
			return pkix.Extension{}, fmt.Errorf("extension %s: access method %s requires a URI", oid, d.Method)
		}
		out = append(out, accessDescription{
			Method: d.Method,
			// accessLocation is a GeneralName; [6] uniformResourceIdentifier is
			// IMPLICIT IA5String, so the URI bytes travel under the [6] tag.
			Location: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(d.URI)},
		})
	}
	value, err := asn1.Marshal(out)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding %s: %w", oid, err)
	}
	return pkix.Extension{Id: oid, Value: value}, nil
}

// distributionPoint mirrors the RFC 5280 DistributionPoint structure for the
// full-name URI form crypto/x509 also emits.
type distributionPoint struct {
	DistributionPoint distributionPointName `asn1:"optional,tag:0"`
}

type distributionPointName struct {
	FullName []asn1.RawValue `asn1:"optional,tag:0"`
}

// DistributionPointsExtension builds a cRLDistributionPoints-syntax extension
// (RFC 5280 §4.2.1.13) from a list of URIs — used here for id-ce-freshestCRL
// (2.5.29.46), the delta-CRL pointer, which crypto/x509 cannot emit. Each URI
// becomes its own DistributionPoint with a single
// uniformResourceIdentifier fullName, matching what crypto/x509 produces for
// cRLDistributionPoints so readers see a familiar shape. The extension MUST be
// non-critical.
func DistributionPointsExtension(oid asn1.ObjectIdentifier, urls []string) (pkix.Extension, error) {
	if len(urls) == 0 {
		return pkix.Extension{}, fmt.Errorf("extension %s requires at least one URI", oid)
	}
	points := make([]distributionPoint, 0, len(urls))
	for _, u := range urls {
		if strings.TrimSpace(u) == "" {
			return pkix.Extension{}, fmt.Errorf("extension %s: empty distribution point URI", oid)
		}
		points = append(points, distributionPoint{
			DistributionPoint: distributionPointName{
				FullName: []asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(u)}},
			},
		})
	}
	value, err := asn1.Marshal(points)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding %s: %w", oid, err)
	}
	return pkix.Extension{Id: oid, Value: value}, nil
}

// InhibitAnyPolicyExtension builds id-ce-inhibitAnyPolicy (2.5.29.54): the
// number of certificates that may still appear in the path before the anyPolicy
// OID stops being accepted as a match for a specific policy. RFC 5280 §4.2.1.14
// requires the extension to be critical, so criticality is not a parameter.
func InhibitAnyPolicyExtension(skipCerts int) (pkix.Extension, error) {
	if skipCerts < 0 {
		return pkix.Extension{}, fmt.Errorf("inhibitAnyPolicy skipCerts must not be negative (got %d)", skipCerts)
	}
	value, err := asn1.Marshal(skipCerts)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding inhibitAnyPolicy: %w", err)
	}
	return pkix.Extension{Id: OIDInhibitAnyPolicy, Critical: true, Value: value}, nil
}

// DirectoryAttribute is one entry of id-ce-subjectDirectoryAttributes: an
// attribute type and its values, each value carried as complete DER.
type DirectoryAttribute struct {
	Type   asn1.ObjectIdentifier
	Values [][]byte
}

// attributeTypeAndValues mirrors the X.501 Attribute structure
// (type + SET OF AttributeValue) subjectDirectoryAttributes is a SEQUENCE of.
type attributeTypeAndValues struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue
}

// SubjectDirectoryAttributesExtension builds id-ce-subjectDirectoryAttributes
// (2.5.29.9), a SEQUENCE of attribute type/value sets carrying non-identifying
// directory information about the subject (country of citizenship, date of
// birth, place of birth and the like). RFC 5280 §4.2.1.8 requires it to be
// non-critical.
func SubjectDirectoryAttributesExtension(attrs []DirectoryAttribute) (pkix.Extension, error) {
	if len(attrs) == 0 {
		return pkix.Extension{}, fmt.Errorf("subjectDirectoryAttributes requires at least one attribute")
	}
	out := make([]attributeTypeAndValues, 0, len(attrs))
	for _, a := range attrs {
		if len(a.Type) == 0 {
			return pkix.Extension{}, fmt.Errorf("subjectDirectoryAttributes: attribute requires a type OID")
		}
		if len(a.Values) == 0 {
			return pkix.Extension{}, fmt.Errorf("subjectDirectoryAttributes: attribute %s requires at least one value", a.Type)
		}
		var content []byte
		for _, v := range a.Values {
			if len(v) == 0 {
				return pkix.Extension{}, fmt.Errorf("subjectDirectoryAttributes: attribute %s has an empty value", a.Type)
			}
			content = append(content, v...)
		}
		out = append(out, attributeTypeAndValues{
			Type:   a.Type,
			Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: content},
		})
	}
	value, err := asn1.Marshal(out)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding subjectDirectoryAttributes: %w", err)
	}
	return pkix.Extension{Id: OIDSubjectDirectoryAttributes, Value: value}, nil
}

// NetscapeCommentExtension builds the legacy Netscape comment extension
// (2.16.840.1.113730.1.13), an IA5String. Non-critical by definition.
func NetscapeCommentExtension(comment string) (pkix.Extension, error) {
	if strings.TrimSpace(comment) == "" {
		return pkix.Extension{}, fmt.Errorf("netscape comment must not be empty")
	}
	value, err := asn1.MarshalWithParams(comment, "ia5")
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding netscape comment: %w", err)
	}
	return pkix.Extension{Id: OIDNetscapeComment, Value: value}, nil
}

// NetscapeCertType bit positions in the legacy certificate-type BIT STRING.
const (
	NetscapeCertTypeSSLClient = 0
	NetscapeCertTypeSSLServer = 1
	NetscapeCertTypeSMIME     = 2
	NetscapeCertTypeObject    = 3
	NetscapeCertTypeSSLCA     = 5
	NetscapeCertTypeSMIMECA   = 6
	NetscapeCertTypeObjectCA  = 7
)

// NetscapeCertTypeFromString resolves the operator-facing name of a legacy
// Netscape certificate-type bit.
var NetscapeCertTypeFromString = map[string]int{
	"sslClient": NetscapeCertTypeSSLClient,
	"sslServer": NetscapeCertTypeSSLServer,
	"sslCA":     NetscapeCertTypeSSLCA,
	"smime":     NetscapeCertTypeSMIME,
	"smimeCA":   NetscapeCertTypeSMIMECA,
	"objsign":   NetscapeCertTypeObject,
	"objCA":     NetscapeCertTypeObjectCA,
}

// NetscapeCertTypeExtension builds the legacy Netscape certificate-type
// extension (2.16.840.1.113730.1.1) from a set of bit positions. keyUsage and
// extKeyUsage supersede it; it exists for old hardware that still reads it.
// Non-critical.
func NetscapeCertTypeExtension(bits []int) (pkix.Extension, error) {
	if len(bits) == 0 {
		return pkix.Extension{}, fmt.Errorf("netscape cert type requires at least one bit")
	}
	highest := 0
	for _, b := range bits {
		if b < 0 || b > 7 {
			return pkix.Extension{}, fmt.Errorf("netscape cert type bit %d is out of range (0-7)", b)
		}
		if b > highest {
			highest = b
		}
	}
	// A single octet holds bits 0-7; bit 0 is the most significant bit.
	var octet byte
	for _, b := range bits {
		octet |= 0x80 >> uint(b)
	}
	bs := asn1.BitString{Bytes: []byte{octet}, BitLength: highest + 1}
	value, err := asn1.Marshal(bs)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding netscape cert type: %w", err)
	}
	return pkix.Extension{Id: OIDNetscapeCertType, Value: value}, nil
}
