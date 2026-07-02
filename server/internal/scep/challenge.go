package scep

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
)

// oidChallengePassword is the PKCS#9 challengePassword attribute (RFC 2985),
// the field SCEP clients carry the enrollment shared secret in.
var oidChallengePassword = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 7}

// challengePasswordFromCSR extracts the PKCS#9 challengePassword attribute from
// a CSR, returning "" when absent. Go's x509 parser does not surface CRI
// attributes directly, so the CertificationRequestInfo attributes are re-parsed
// from the raw DER.
func challengePasswordFromCSR(csr *x509.CertificateRequest) string {
	type certReqInfo struct {
		Raw        asn1.RawContent
		Version    int
		Subject    asn1.RawValue
		PublicKey  asn1.RawValue
		Attributes []attributeTypeAndValueSet `asn1:"tag:0"`
	}
	type certReq struct {
		Raw       asn1.RawContent
		Info      certReqInfo
		SigAlg    pkix.AlgorithmIdentifier
		Signature asn1.BitString
	}

	var cr certReq
	if _, err := asn1.Unmarshal(csr.Raw, &cr); err != nil {
		return ""
	}
	for _, attr := range cr.Info.Attributes {
		if !attr.Type.Equal(oidChallengePassword) {
			continue
		}
		for _, v := range attr.Values {
			if s := directoryString(v); s != "" {
				return s
			}
		}
	}
	return ""
}

// attributeTypeAndValueSet mirrors the CRI attribute shape: an OID and a SET OF
// (SET OF) value. The nested slices accommodate the SET OF AttributeValue
// wrapper without assuming a single value.
type attributeTypeAndValueSet struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// directoryString decodes a PrintableString / UTF8String / IA5String value to a
// Go string, returning "" for anything else.
func directoryString(v asn1.RawValue) string {
	switch v.Tag {
	case asn1.TagPrintableString, asn1.TagUTF8String, asn1.TagIA5String, asn1.TagT61String:
		return string(v.Bytes)
	default:
		return ""
	}
}
