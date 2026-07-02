// Package ct implements the client side of RFC 6962 Certificate Transparency:
// building precertificates, submitting them to CT logs, collecting Signed
// Certificate Timestamps (SCTs), and embedding an SCT list back into the final
// certificate before it is signed.
//
// The issuance path uses this package as follows:
//
//  1. Build a precertificate — the certificate template plus the critical
//     "poison" extension (OID 1.3.6.1.4.1.11129.2.4.3) — and sign it on the HSM.
//     The poison marks the object as un-usable as a real certificate.
//  2. Submit the precertificate (with its issuer chain) to one or more CT logs
//     via the add-pre-chain endpoint. Each log returns an SCT.
//  3. Serialise the collected SCTs into a SignedCertificateTimestampList and
//     embed it as the SCT list extension (OID 1.3.6.1.4.1.11129.2.4.2).
//  4. Re-sign the certificate template — identical to the precertificate except
//     the poison extension is replaced by the SCT list extension — on the HSM.
//
// Because the precertificate and final certificate differ only in that single
// trailing extension, the TBSCertificate a CT log signs over (precertificate
// TBS with the poison removed) is byte-for-byte identical to what a relying
// party reconstructs from the final certificate (final TBS with the SCT list
// removed), so the embedded SCTs verify.
package ct

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

// RFC 6962 object identifiers.
var (
	// OIDSCTList identifies the signed-certificate-timestamp-list extension that
	// carries embedded SCTs in a final certificate (RFC 6962 §3.3).
	OIDSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
	// OIDPoison identifies the precertificate poison extension (RFC 6962 §3.1).
	// It is always critical and its value is an ASN.1 NULL.
	OIDPoison = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}
	// OIDPrecertSigningEKU identifies the precertificate-signing extended key
	// usage (RFC 6962 §3.1). Defined for completeness; this implementation signs
	// precertificates directly with the CA key rather than a delegated signer.
	OIDPrecertSigningEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 4}
)

// PoisonExtension returns the critical precertificate poison extension. Its
// presence makes an object a precertificate that no relying party will accept
// as an end-entity certificate.
func PoisonExtension() pkix.Extension {
	return pkix.Extension{
		Id:       OIDPoison,
		Critical: true,
		Value:    []byte{0x05, 0x00}, // DER encoding of ASN.1 NULL
	}
}

// SCT is a decoded Signed Certificate Timestamp as returned by a CT log's
// add-pre-chain endpoint (RFC 6962 §3.2 / §4.2).
type SCT struct {
	// Version is the sct_version enum; only v1 (0) is defined by RFC 6962.
	Version uint8
	// LogID is the SHA-256 hash of the log's public key (DER SubjectPublicKeyInfo).
	LogID [32]byte
	// Timestamp is the log's assertion time in milliseconds since the Unix epoch.
	Timestamp uint64
	// Extensions carries opaque CT extensions (usually empty).
	Extensions []byte
	// Signature is the raw TLS digitally-signed structure over the log entry:
	// a SignatureAndHashAlgorithm (2 bytes) followed by an opaque<0..2^16-1>
	// signature. It is stored verbatim so it can be re-serialised into the SCT
	// list without re-encoding.
	Signature []byte
}
