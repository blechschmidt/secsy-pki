// Package cms implements the minimal subset of the Cryptographic Message Syntax
// (PKCS#7 / RFC 5652) needed by the SCEP (RFC 8894) and EST (RFC 7030)
// enrollment protocols:
//
//   - parsing and signature-verifying a SignedData (the SCEP pkiMessage wrapper),
//   - parsing and decrypting a KeyTrans EnvelopedData (the SCEP request payload),
//   - building an EnvelopedData encrypted to a recipient certificate,
//   - building a SignedData signed by a CA key,
//   - building a "degenerate" certificates-only SignedData (SCEP CertRep payload
//     and the EST cacerts / enrollment response bodies).
//
// The implementation deliberately keeps the CA private key on its provider: all
// asymmetric operations flow through crypto.Signer / crypto.Decrypter, so an
// HSM-resident key is never exported. Symmetric content keys are ephemeral and
// handled in-process.
//
// Only what the enrollment protocols actually require is implemented. RSA
// key-transport recipients (rsaEncryption, PKCS#1 v1.5) and CBC content
// encryption (AES-128/192/256-CBC and DES-EDE3-CBC) are supported, matching the
// capabilities SCEP clients negotiate through GetCACaps.
package cms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
)

// Object identifiers used across CMS structures and SCEP attributes.
var (
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}

	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}

	// Authenticated-attribute types (RFC 5652 §11).
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// Digest algorithms.
	oidDigestSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidDigestSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidDigestSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidDigestSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// Content-encryption algorithms.
	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
)

// contentInfo is the top-level ContentInfo (RFC 5652 §3). The content is an
// EXPLICIT [0] wrapper around the type-specific structure.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signedData is the SignedData structure (RFC 5652 §5.1).
type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo      encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

// encapContentInfo is the encapsulated content (RFC 5652 §5.2). For SCEP the
// eContentType is data and eContent carries the DER of the inner message
// (an EnvelopedData for requests, a degenerate SignedData for responses).
type encapContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signerInfo is a SignerInfo (RFC 5652 §5.3).
type signerInfo struct {
	Version                   int
	IssuerAndSerialNumber     issuerAndSerial
	DigestAlgorithm           pkix.AlgorithmIdentifier
	AuthenticatedAttributes   []attribute `asn1:"optional,tag:0"`
	DigestEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedDigest           []byte
	UnauthenticatedAttributes []attribute `asn1:"optional,tag:1"`
}

// issuerAndSerial identifies a certificate by issuer DN and serial number.
type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

// attribute is an Attribute (RFC 5652 §5.3): an OID plus a SET OF values.
type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// envelopedData is the EnvelopedData structure (RFC 5652 §6.1).
type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

// recipientInfo is a KeyTransRecipientInfo (RFC 5652 §6.2.1). Only issuer-and-
// serial recipient identification (version 0) is used by SCEP.
type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

// encryptedContentInfo is the EncryptedContentInfo (RFC 5652 §6.1). The
// encryptedContent is an IMPLICIT [0] OCTET STRING.
type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"optional,tag:0"`
}
