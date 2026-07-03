package cms

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"
)

// Attribute is an authenticated attribute to embed in a SignedData SignerInfo.
// Value is DER-encoded via encoding/asn1, so a Go string becomes a
// PrintableString, a []byte becomes an OCTET STRING, and an int becomes an
// INTEGER — matching the SCEP attribute value types (RFC 8894 §3.2).
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

// DegenerateCertsOnly builds a "certs-only" degenerate SignedData (RFC 5652
// §5.1 with no signerInfos), the wire form used by SCEP GetCACert (multi-cert)
// and by every EST cacerts / enrollment response. It returns a complete
// ContentInfo DER.
func DegenerateCertsOnly(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("cms: DegenerateCertsOnly requires at least one certificate")
	}
	sd := signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{},
		ContentInfo:      encapContentInfo{ContentType: oidData},
		Certificates:     marshalCerts(certs),
		SignerInfos:      []signerInfo{},
	}
	return wrapContentInfo(oidSignedData, sd)
}

// SignedDataOpts parameterizes BuildSignedData.
type SignedDataOpts struct {
	// Content is the eContent to encapsulate and sign (attached signature). For a
	// detached signature it is the external content the messageDigest attribute
	// covers; it may then be nil when ContentDigest is supplied instead.
	Content []byte
	// ContentDigest, when set, is the precomputed Digest-hash of the content and
	// is used verbatim as the messageDigest attribute. It allows signing very
	// large artifacts by digest without streaming them through the builder. It is
	// only valid for a Detached signature (an attached signature must embed the
	// content itself) and must be exactly Digest.Size() bytes.
	ContentDigest []byte
	// Detached omits the eContent from the encapsulated content info (RFC 5652
	// §5.2: an "external signature"). The signature still covers the content via
	// the mandatory messageDigest authenticated attribute; verifiers are handed
	// the content (or its digest) out of band.
	Detached bool
	// ContentType is the eContentType (default: data).
	ContentType asn1.ObjectIdentifier
	// SignerCert / Signer produce the single SignerInfo. Signer is typically an
	// HSM-backed crypto.Signer holding an RSA or ECDSA key.
	SignerCert *x509.Certificate
	Signer     crypto.Signer
	// Digest selects the message-digest / signature hash (default: SHA-256).
	Digest crypto.Hash
	// Certificates are embedded in the message (should include SignerCert and any
	// chain the recipient needs). When empty, SignerCert alone is embedded unless
	// OmitCertificates is set.
	Certificates []*x509.Certificate
	// OmitCertificates suppresses the embedded CertificateSet entirely, even the
	// signer certificate. RFC 3161 §2.4.1 requires this when a TimeStampReq did
	// not request the TSA certificate (certReq = FALSE).
	OmitCertificates bool
	// ExtraAttrs are additional authenticated attributes (e.g. the SCEP
	// transaction attributes) added alongside the mandatory contentType and
	// messageDigest.
	ExtraAttrs []Attribute
	// UnauthAttrsFunc, when non-nil, is invoked with the computed SignerInfo
	// signature value and returns unauthenticated (unsigned) attributes to embed
	// alongside it. This is how an RFC 3161 timestamp countersignature — a token
	// over the signature value — is attached (id-aa-timeStampToken, RFC 3161
	// Appendix A): the token can only be obtained after the signature exists.
	UnauthAttrsFunc func(signature []byte) ([]Attribute, error)
}

// BuildSignedData builds an attached-signature SignedData with a single
// SignerInfo carrying authenticated attributes. The CA private key stays in its
// provider: only Signer.Sign is invoked. It returns a complete ContentInfo DER.
func BuildSignedData(opts SignedDataOpts) ([]byte, error) {
	if opts.SignerCert == nil || opts.Signer == nil {
		return nil, errors.New("cms: BuildSignedData requires a signer certificate and signer")
	}
	hash := opts.Digest
	if hash == 0 {
		hash = crypto.SHA256
	}
	digestOID, err := digestAlgOID(hash)
	if err != nil {
		return nil, err
	}
	contentType := opts.ContentType
	if contentType == nil {
		contentType = oidData
	}

	// Mandatory authenticated attributes: contentType and messageDigest.
	var msgDigest []byte
	switch {
	case opts.ContentDigest != nil:
		if !opts.Detached {
			return nil, errors.New("cms: ContentDigest requires a detached signature (attached signatures must embed the content)")
		}
		if len(opts.ContentDigest) != hash.Size() {
			return nil, fmt.Errorf("cms: ContentDigest length %d does not match %v output size %d",
				len(opts.ContentDigest), hash, hash.Size())
		}
		msgDigest = opts.ContentDigest
	default:
		h := hash.New()
		h.Write(opts.Content)
		msgDigest = h.Sum(nil)
	}

	attrList := []Attribute{
		{Type: oidAttrContentType, Value: contentType},
		{Type: oidAttrMessageDigest, Value: msgDigest},
	}
	attrList = append(attrList, opts.ExtraAttrs...)

	attrs := make([]attribute, 0, len(attrList))
	for _, a := range attrList {
		enc, err := buildAttribute(a)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, enc)
	}
	// DER requires the SET OF authenticated attributes to be sorted by their
	// encoding. Sort the stored order to match, so the attributes transmitted in
	// the SignerInfo's IMPLICIT [0] field are byte-identical (modulo tag) to the
	// SET the signature is computed over — satisfying strict verifiers.
	if err := sortAttributes(attrs); err != nil {
		return nil, err
	}

	sigAlg, err := signatureAlgorithm(opts.Signer.Public(), hash)
	if err != nil {
		return nil, err
	}

	signedBytes, err := marshalAuthAttrsForSigning(attrs)
	if err != nil {
		return nil, err
	}
	dh := hash.New()
	dh.Write(signedBytes)
	sig, err := opts.Signer.Sign(rand.Reader, dh.Sum(nil), hash)
	if err != nil {
		return nil, fmt.Errorf("cms: signing authenticated attributes: %w", err)
	}

	// Unauthenticated attributes are outside the signature, so they can be
	// derived from it (the RFC 3161 timestamp-countersignature pattern).
	var unauthAttrs []attribute
	if opts.UnauthAttrsFunc != nil {
		extra, err := opts.UnauthAttrsFunc(sig)
		if err != nil {
			return nil, fmt.Errorf("cms: building unauthenticated attributes: %w", err)
		}
		for _, a := range extra {
			enc, err := buildAttribute(a)
			if err != nil {
				return nil, err
			}
			unauthAttrs = append(unauthAttrs, enc)
		}
		if err := sortAttributes(unauthAttrs); err != nil {
			return nil, err
		}
	}

	certs := opts.Certificates
	if len(certs) == 0 && !opts.OmitCertificates {
		certs = []*x509.Certificate{opts.SignerCert}
	}

	si := signerInfo{
		Version: 1,
		IssuerAndSerialNumber: issuerAndSerial{
			IssuerName:   asn1.RawValue{FullBytes: opts.SignerCert.RawIssuer},
			SerialNumber: opts.SignerCert.SerialNumber,
		},
		DigestAlgorithm:           pkix.AlgorithmIdentifier{Algorithm: digestOID, Parameters: asn1.NullRawValue},
		AuthenticatedAttributes:   attrs,
		DigestEncryptionAlgorithm: sigAlg,
		EncryptedDigest:           sig,
		UnauthenticatedAttributes: unauthAttrs,
	}

	eContent := encapContentInfo{ContentType: contentType}
	if !opts.Detached {
		eContent.Content = asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustMarshalOctet(opts.Content)}
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: digestOID, Parameters: asn1.NullRawValue}},
		ContentInfo:      eContent,
		Certificates:     marshalCerts(certs),
		SignerInfos:      []signerInfo{si},
	}
	return wrapContentInfo(oidSignedData, sd)
}

// signatureAlgorithm selects the SignerInfo signatureAlgorithm for the signer's
// key type. RSA keeps the historical rsaEncryption identifier (PKCS#1 v1.5, the
// form SCEP/EST/TSA verifiers including openssl expect); ECDSA uses the
// digest-specific ecdsa-with-SHA* identifier with absent parameters (RFC 5758
// §3.2).
func signatureAlgorithm(pub crypto.PublicKey, hash crypto.Hash) (pkix.AlgorithmIdentifier, error) {
	switch pub.(type) {
	case *rsa.PublicKey:
		return pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue}, nil
	case *ecdsa.PublicKey:
		var oid asn1.ObjectIdentifier
		switch hash {
		case crypto.SHA256:
			oid = oidECDSAWithSHA256
		case crypto.SHA384:
			oid = oidECDSAWithSHA384
		case crypto.SHA512:
			oid = oidECDSAWithSHA512
		case crypto.SHA1:
			oid = oidECDSAWithSHA1
		default:
			return pkix.AlgorithmIdentifier{}, fmt.Errorf("cms: no ECDSA signature algorithm for digest %v", hash)
		}
		return pkix.AlgorithmIdentifier{Algorithm: oid}, nil
	default:
		return pkix.AlgorithmIdentifier{}, fmt.Errorf("cms: unsupported signer key type %T (RSA and ECDSA are supported)", pub)
	}
}

// BuildEnvelopedData encrypts plaintext to a single recipient certificate using
// AES-256-CBC content encryption with an RSA (PKCS#1 v1.5) key-transport
// recipient info. It returns a complete ContentInfo DER. The recipient must
// hold an RSA public key.
func BuildEnvelopedData(plaintext []byte, recipient *x509.Certificate) ([]byte, error) {
	rsaPub, ok := recipient.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cms: recipient key is %T, only RSA recipients are supported", recipient.PublicKey)
	}

	// Fresh 256-bit content-encryption key and 128-bit IV.
	cek := make([]byte, 32)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(cek); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	encKey, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, cek)
	if err != nil {
		return nil, fmt.Errorf("cms: wrapping content-encryption key: %w", err)
	}

	ivParam, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}

	ed := envelopedData{
		Version: 0,
		RecipientInfos: []recipientInfo{{
			Version: 0,
			IssuerAndSerialNumber: issuerAndSerial{
				IssuerName:   asn1.RawValue{FullBytes: recipient.RawIssuer},
				SerialNumber: recipient.SerialNumber,
			},
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption, Parameters: asn1.NullRawValue},
			EncryptedKey:           encKey,
		}},
		EncryptedContentInfo: encryptedContentInfo{
			ContentType: oidData,
			ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  oidAES256CBC,
				Parameters: asn1.RawValue{FullBytes: ivParam},
			},
			EncryptedContent: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: false, Bytes: ciphertext},
		},
	}
	return wrapContentInfo(oidEnvelopedData, ed)
}

// OIDSigningCertificateV2 (id-aa-signingCertificateV2) is the ESS signed
// attribute binding a SignerInfo to the signing certificate (RFC 5035).
var OIDSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

// essCertIDv2 is RFC 5035 ESSCertIDv2 with the default (id-sha256) hash
// algorithm and no issuerSerial, so it encodes as SEQUENCE { certHash }.
type essCertIDv2 struct {
	CertHash []byte
}

// signingCertificateV2 is RFC 5035 SigningCertificateV2 with no policies.
type signingCertificateV2 struct {
	Certs []essCertIDv2
}

// SigningCertificateV2Attribute builds the id-aa-signingCertificateV2
// authenticated attribute over the given certificates (RFC 5035). Only the
// leaf (the signing certificate) is required; including the whole chain lets
// strict verifiers bind every certificate. Used by both the RFC 3161 TSA and
// the artifact-signing service.
func SigningCertificateV2Attribute(chain []*x509.Certificate) (Attribute, error) {
	if len(chain) == 0 {
		return Attribute{}, errors.New("cms: signing-certificate attribute requires at least the signer certificate")
	}
	certs := make([]essCertIDv2, 0, len(chain))
	for _, c := range chain {
		sum := sha256.Sum256(c.Raw)
		certs = append(certs, essCertIDv2{CertHash: sum[:]})
	}
	return Attribute{Type: OIDSigningCertificateV2, Value: signingCertificateV2{Certs: certs}}, nil
}

// ---- encoding helpers -----------------------------------------------------

// wrapContentInfo marshals inner and wraps it in a ContentInfo of the given type.
func wrapContentInfo(contentType asn1.ObjectIdentifier, inner interface{}) ([]byte, error) {
	innerDER, err := asn1.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("cms: marshaling %v content: %w", contentType, err)
	}
	ci := contentInfo{
		ContentType: contentType,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: innerDER},
	}
	return asn1.Marshal(ci)
}

// marshalCerts concatenates certificate DER and wraps it in the [0] IMPLICIT
// CertificateSet used by SignedData. With no certificates it returns the zero
// RawValue so the optional field is omitted entirely (an empty [0] set would
// otherwise be transmitted, which RFC 3161 forbids for a certReq=FALSE token).
func marshalCerts(certs []*x509.Certificate) asn1.RawValue {
	if len(certs) == 0 {
		return asn1.RawValue{}
	}
	var buf []byte
	for _, c := range certs {
		buf = append(buf, c.Raw...)
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: buf}
}

// sortAttributes orders attributes by their DER encoding, the canonical DER
// ordering for a SET OF. This mirrors how encoding/asn1 sorts a `set`-tagged
// slice, so the transmitted and signed encodings agree.
func sortAttributes(attrs []attribute) error {
	type enc struct {
		attr attribute
		der  []byte
	}
	encs := make([]enc, len(attrs))
	for i, a := range attrs {
		der, err := asn1.Marshal(a)
		if err != nil {
			return fmt.Errorf("cms: encoding attribute for sort: %w", err)
		}
		encs[i] = enc{attr: a, der: der}
	}
	sort.Slice(encs, func(i, j int) bool { return bytes.Compare(encs[i].der, encs[j].der) < 0 })
	for i := range encs {
		attrs[i] = encs[i].attr
	}
	return nil
}

// buildAttribute encodes an Attribute into the wire attribute structure, wrapping
// the value in a SET OF as required.
func buildAttribute(a Attribute) (attribute, error) {
	valDER, err := asn1.Marshal(a.Value)
	if err != nil {
		return attribute{}, fmt.Errorf("cms: encoding attribute %v value: %w", a.Type, err)
	}
	return attribute{
		Type:   a.Type,
		Values: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: valDER},
	}, nil
}

// mustMarshalOctet marshals content as an OCTET STRING and returns its full DER,
// used as the eContent inside the EXPLICIT [0] wrapper.
func mustMarshalOctet(content []byte) []byte {
	b, _ := asn1.Marshal(content)
	return b
}

// pkcs7Pad applies PKCS#7 block padding.
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// digestAlgOID maps a crypto.Hash to its digest-algorithm OID.
func digestAlgOID(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA256:
		return oidDigestSHA256, nil
	case crypto.SHA1:
		return oidDigestSHA1, nil
	case crypto.SHA384:
		return oidDigestSHA384, nil
	case crypto.SHA512:
		return oidDigestSHA512, nil
	default:
		return nil, fmt.Errorf("cms: unsupported digest %v", h)
	}
}
