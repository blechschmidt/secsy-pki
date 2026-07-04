package pki

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// OIDTLSFeature identifies the RFC 7633 id-pe-tlsfeature extension
// ({ id-pe 24 } = 1.3.6.1.5.5.7.1.24). Its value is a DER SEQUENCE OF INTEGER
// listing the TLS extension-type values (per the IANA "TLS ExtensionType"
// registry, RFC 6066) a certificate commits its server to including in the TLS
// handshake. A relying party that finds a feature listed here but not honored in
// the handshake must abort the connection.
var OIDTLSFeature = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

// TLSFeatureStatusRequest is the TLS status_request extension type (RFC 6066 §8,
// value 5). Listing it in a TLS Feature extension is the "OCSP Must-Staple"
// commitment (RFC 7633): a conforming TLS client must abort a handshake in which
// the server does not staple a valid OCSP response for the certificate.
const TLSFeatureStatusRequest = 5

// TLSFeatureExtension builds a non-critical id-pe-tlsfeature extension whose
// value is the DER SEQUENCE OF INTEGER of the given TLS feature (extension-type)
// values. At least one feature is required. RFC 7633 §6 requires the extension
// be non-critical so that clients which do not understand it still process the
// certificate (and simply do not enforce the feature).
func TLSFeatureExtension(features ...int) (pkix.Extension, error) {
	if len(features) == 0 {
		return pkix.Extension{}, fmt.Errorf("tls feature extension requires at least one feature")
	}
	val, err := asn1.Marshal(features)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding tls feature extension: %w", err)
	}
	return pkix.Extension{Id: OIDTLSFeature, Critical: false, Value: val}, nil
}

// MustStapleExtension returns the id-pe-tlsfeature extension carrying only the
// status_request feature — the RFC 7633 OCSP Must-Staple commitment. Its encoded
// value is the five bytes 30 03 02 01 05 (SEQUENCE { INTEGER 5 }).
func MustStapleExtension() pkix.Extension {
	// TLSFeatureExtension cannot fail for a fixed, non-empty feature list.
	ext, _ := TLSFeatureExtension(TLSFeatureStatusRequest)
	return ext
}

// ParseTLSFeature decodes the DER value of an id-pe-tlsfeature extension into its
// list of TLS feature (extension-type) values. It returns an error when the
// value is not a well-formed SEQUENCE OF INTEGER, so callers can distinguish a
// recognized-but-malformed extension from a valid one.
func ParseTLSFeature(value []byte) ([]int, error) {
	var features []int
	rest, err := asn1.Unmarshal(value, &features)
	if err != nil {
		return nil, fmt.Errorf("decoding tls feature extension: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("tls feature extension has %d trailing byte(s)", len(rest))
	}
	return features, nil
}

// TLSFeatureListed reports whether the given feature value appears in a parsed
// TLS feature list.
func TLSFeatureListed(features []int, feature int) bool {
	for _, f := range features {
		if f == feature {
			return true
		}
	}
	return false
}
