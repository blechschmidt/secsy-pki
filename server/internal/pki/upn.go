package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"net"
)

// Object identifiers for Microsoft smartcard-logon / Kerberos PKINIT client-
// authentication certificates.
var (
	// OIDSubjectAltName is the X.509 subjectAltName extension (RFC 5280 §4.2.1.6).
	OIDSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

	// OIDUserPrincipalName is the Microsoft id-ms-UPN otherName type-id
	// (1.3.6.1.4.1.311.20.2.3). Its value is a UTF8String "user@REALM" carried in
	// a subjectAltName otherName; Active Directory matches it against a user's
	// userPrincipalName attribute to authenticate a smartcard logon.
	OIDUserPrincipalName = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

	// OIDExtKeyUsageMSSmartcardLogon is id-ms-smartcardLogon
	// (1.3.6.1.4.1.311.20.2.2), the Microsoft smartcard-logon extended key usage.
	OIDExtKeyUsageMSSmartcardLogon = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
	// OIDExtKeyUsagePKINITClientAuth is id-pkinit-KPClientAuth (1.3.6.1.5.2.3.4,
	// RFC 4556 §3.2.2), the Kerberos PKINIT client-authentication extended key
	// usage.
	OIDExtKeyUsagePKINITClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 4}
)

// X509ExtKeyUsageOIDFromString resolves the extended-key-usage string
// identifiers that crypto/x509 has no enum constant for — the Microsoft
// smartcard-logon and Kerberos PKINIT client-auth EKUs — to their OIDs. A
// profile referencing these carries them as UnknownExtKeyUsage entries, which
// x509.CreateCertificate folds into the same extKeyUsage extension as the known
// usages.
var X509ExtKeyUsageOIDFromString = map[string]asn1.ObjectIdentifier{
	"msSmartcardLogon": OIDExtKeyUsageMSSmartcardLogon,
	"pkinitClientAuth": OIDExtKeyUsagePKINITClientAuth,
}

// upnOtherName encodes a single UPN as a GeneralName otherName (RFC 5280
// §4.2.1.6):
//
//	otherName [0] IMPLICIT OtherName
//	OtherName ::= SEQUENCE { type-id OBJECT IDENTIFIER,
//	                        value [0] EXPLICIT ANY DEFINED BY type-id }
//
// The [0] GeneralName tag is IMPLICIT (it replaces the SEQUENCE tag), while the
// inner value tag is EXPLICIT. For a UPN the type-id is id-ms-UPN and the value
// is a UTF8String — the exact encoding Windows expects.
func upnOtherName(value string) (asn1.RawValue, error) {
	// The value: a UTF8String, wrapped in the [0] EXPLICIT value tag.
	utf8DER, err := asn1.MarshalWithParams(value, "utf8")
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("encoding UPN value: %w", err)
	}
	explicitDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      utf8DER,
	})
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("encoding UPN explicit value: %w", err)
	}
	oidDER, err := asn1.Marshal(OIDUserPrincipalName)
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("encoding UPN type-id: %w", err)
	}
	// OtherName SEQUENCE content = type-id || [0] EXPLICIT value; the whole
	// SEQUENCE is IMPLICITly tagged [0] (context-specific, constructed).
	inner := make([]byte, 0, len(oidDER)+len(explicitDER))
	inner = append(inner, oidDER...)
	inner = append(inner, explicitDER...)
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      inner,
	}, nil
}

// SubjectAltNameExtension builds a complete subjectAltName extension (OID
// 2.5.29.17) merging the standard GeneralName types with id-ms-UPN otherNames.
// It is used when a leaf carries at least one UPN, because crypto/x509 cannot
// emit an otherName SAN itself — the whole extension is hand-rolled and supplied
// via ExtraExtensions. UPN otherNames are emitted first (the conventional order
// for smartcard-logon certificates), followed by rfc822Name, dNSName,
// uniformResourceIdentifier, and iPAddress entries.
//
// critical mirrors crypto/x509's own rule: the SAN extension is critical only
// when the subject DN is empty (RFC 5280 §4.2.1.6).
func SubjectAltNameExtension(dns []string, ips []net.IP, emails, uris, upns []string, critical bool) (pkix.Extension, error) {
	var names []byte
	appendGN := func(rv asn1.RawValue) error {
		b, err := asn1.Marshal(rv)
		if err != nil {
			return err
		}
		names = append(names, b...)
		return nil
	}
	ctx := func(tag int, content []byte) asn1.RawValue {
		return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: content}
	}

	for _, u := range upns {
		rv, err := upnOtherName(u)
		if err != nil {
			return pkix.Extension{}, err
		}
		if err := appendGN(rv); err != nil {
			return pkix.Extension{}, err
		}
	}
	for _, e := range emails { // rfc822Name [1]
		if err := appendGN(ctx(1, []byte(e))); err != nil {
			return pkix.Extension{}, err
		}
	}
	for _, d := range dns { // dNSName [2]
		if err := appendGN(ctx(2, []byte(d))); err != nil {
			return pkix.Extension{}, err
		}
	}
	for _, u := range uris { // uniformResourceIdentifier [6]
		if err := appendGN(ctx(6, []byte(u))); err != nil {
			return pkix.Extension{}, err
		}
	}
	for _, ip := range ips { // iPAddress [7]
		b := ip
		if v4 := ip.To4(); v4 != nil {
			b = v4
		}
		if err := appendGN(ctx(7, b)); err != nil {
			return pkix.Extension{}, err
		}
	}

	value, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      names,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding subjectAltName: %w", err)
	}
	return pkix.Extension{Id: OIDSubjectAltName, Critical: critical, Value: value}, nil
}

// UPNsFromSANValue extracts the id-ms-UPN otherName values from a subjectAltName
// extension value (a DER-encoded GeneralNames SEQUENCE). It tolerates and skips
// every other GeneralName type. Malformed input yields an error so a caller can
// distinguish "no UPNs" from "unparseable".
func UPNsFromSANValue(extnValue []byte) ([]string, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(extnValue, &seq); err != nil {
		return nil, fmt.Errorf("decoding subjectAltName: %w", err)
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return nil, fmt.Errorf("subjectAltName is not a SEQUENCE")
	}
	var upns []string
	rest := seq.Bytes
	for len(rest) > 0 {
		var gn asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &gn)
		if err != nil {
			return nil, fmt.Errorf("decoding GeneralName: %w", err)
		}
		// otherName is [0] constructed.
		if gn.Class != asn1.ClassContextSpecific || gn.Tag != 0 || !gn.IsCompound {
			continue
		}
		if v, ok := parseUPNOtherName(gn.Bytes); ok {
			upns = append(upns, v)
		}
	}
	return upns, nil
}

// parseUPNOtherName decodes an OtherName SEQUENCE body (type-id || [0] EXPLICIT
// value) and returns the UTF8String value when the type-id is id-ms-UPN.
func parseUPNOtherName(body []byte) (string, bool) {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(body, &oid)
	if err != nil || !oid.Equal(OIDUserPrincipalName) {
		return "", false
	}
	var explicit asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &explicit); err != nil {
		return "", false
	}
	if explicit.Class != asn1.ClassContextSpecific || explicit.Tag != 0 || !explicit.IsCompound {
		return "", false
	}
	var value string
	if _, err := asn1.UnmarshalWithParams(explicit.Bytes, &value, "utf8"); err != nil {
		return "", false
	}
	return value, true
}

// UPNsFromCertificate returns the id-ms-UPN otherName values carried in a parsed
// certificate's subjectAltName extension. crypto/x509 does not surface otherName
// SANs on any typed field, so it is recovered from the raw extension.
func UPNsFromCertificate(cert *x509.Certificate) []string {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDSubjectAltName) {
			continue
		}
		if upns, err := UPNsFromSANValue(ext.Value); err == nil {
			return upns
		}
	}
	return nil
}

// UPNsFromCSR returns the id-ms-UPN otherName values carried in a PKCS#10
// certificate-request's subjectAltName extension. It lets the EST/SCEP
// enrollment paths honor a UPN a device placed in its CSR, which crypto/x509
// otherwise discards.
func UPNsFromCSR(csr *x509.CertificateRequest) []string {
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(OIDSubjectAltName) {
			continue
		}
		if upns, err := UPNsFromSANValue(ext.Value); err == nil {
			return upns
		}
	}
	return nil
}
