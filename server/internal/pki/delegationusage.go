package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// OIDDelegationUsage identifies the RFC 9345 id-ce-delegationUsage certificate
// extension (1.3.6.1.4.1.44363.44). Its presence on a TLS end-entity certificate
// marks the certificate as eligible to authorize TLS Delegated Credentials
// (RFC 9345): the certified key may sign short-lived DelegatedCredential
// structures that in turn authenticate TLS 1.3 handshakes on its behalf, so a
// front end can be given a delegated credential without holding the long-lived
// certificate private key.
var OIDDelegationUsage = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 44}

// DelegationUsageExtension builds the non-critical RFC 9345 id-ce-delegationUsage
// extension. RFC 9345 §4.2 defines DelegationUsage as an ASN.1 NULL, so the
// encoded value is the two bytes 05 00, and mandates the extension be
// non-critical: a relying party that does not understand it must still accept the
// certificate (it simply will not accept delegated credentials from it).
//
// RFC 9345 §4.2 forbids combining this extension with the RFC 7633 TLS Feature /
// OCSP Must-Staple commitment. The issuance path enforces that mutual exclusion
// fail-closed; see applyDelegationUsage in the ca package.
func DelegationUsageExtension() pkix.Extension {
	return pkix.Extension{
		Id:       OIDDelegationUsage,
		Critical: false,
		// DelegationUsage ::= NULL. asn1.NullBytes is its DER encoding {0x05, 0x00};
		// copy it so the returned extension never aliases the package-level slice.
		Value: append([]byte(nil), asn1.NullBytes...),
	}
}

// ParseDelegationUsage validates the DER value of an id-ce-delegationUsage
// extension. RFC 9345 defines DelegationUsage as an ASN.1 NULL, so the canonical
// value is the two-byte NULL encoding (05 00). A zero-length value is also
// tolerated: some early subcerts implementations emitted an empty value, and the
// extension is a pure presence marker either way. Any other content is rejected
// so a recognized-but-malformed extension is distinguishable from a valid one.
func ParseDelegationUsage(value []byte) error {
	if len(value) == 0 {
		return nil
	}
	var null asn1.RawValue
	rest, err := asn1.Unmarshal(value, &null)
	if err != nil {
		return fmt.Errorf("decoding delegation usage extension: %w", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("delegation usage extension has %d trailing byte(s)", len(rest))
	}
	if null.Class != asn1.ClassUniversal || null.Tag != asn1.TagNull || len(null.Bytes) != 0 {
		return fmt.Errorf("delegation usage extension value is not ASN.1 NULL")
	}
	return nil
}

// HasDelegationUsage reports whether a parsed certificate carries a well-formed
// RFC 9345 id-ce-delegationUsage extension, marking it eligible to authorize TLS
// Delegated Credentials.
func HasDelegationUsage(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(OIDDelegationUsage) {
			return ParseDelegationUsage(ext.Value) == nil
		}
	}
	return false
}
