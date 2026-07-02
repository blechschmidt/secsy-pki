package cms

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// ParsedSignedData is a decoded and (optionally) verified SignedData message.
type ParsedSignedData struct {
	sd           signedData
	Certificates []*x509.Certificate
	// Content is the encapsulated eContent (the DER of the inner message). It is
	// empty for a degenerate certificates-only structure.
	Content []byte

	signer     *signerInfo
	signerCert *x509.Certificate
	authAttrs  []attribute
}

// ParseSignedData decodes a top-level ContentInfo wrapping a SignedData.
func ParseSignedData(der []byte) (*ParsedSignedData, error) {
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("cms: parsing ContentInfo: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("cms: trailing data after ContentInfo")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("cms: content type is %v, want signedData", ci.ContentType)
	}

	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("cms: parsing SignedData: %w", err)
	}

	p := &ParsedSignedData{sd: sd}
	if len(sd.ContentInfo.Content.Bytes) > 0 {
		// eContent is [0] EXPLICIT OCTET STRING; the RawValue captured the
		// wrapper, so unwrap the inner OCTET STRING to get the encapsulated bytes.
		var oct []byte
		if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &oct); err != nil {
			return nil, fmt.Errorf("cms: parsing encapsulated content: %w", err)
		}
		p.Content = oct
	}
	if len(sd.Certificates.Bytes) > 0 {
		certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cms: parsing embedded certificates: %w", err)
		}
		p.Certificates = certs
	}
	return p, nil
}

// SignerCertificate returns the certificate that signed the message, resolved
// during Verify. It is nil for a degenerate (unsigned) structure.
func (p *ParsedSignedData) SignerCertificate() *x509.Certificate { return p.signerCert }

// Verify checks the single SignerInfo's signature against its embedded signer
// certificate and (when present) the authenticated attributes' message digest.
// It does NOT establish trust in the signer certificate — SCEP self-signs the
// initial request, so the caller decides how to authorize the enrollment.
func (p *ParsedSignedData) Verify() error {
	if len(p.sd.SignerInfos) != 1 {
		return fmt.Errorf("cms: expected exactly one SignerInfo, got %d", len(p.sd.SignerInfos))
	}
	si := p.sd.SignerInfos[0]
	p.signer = &si

	cert := p.findCert(si.IssuerAndSerialNumber)
	if cert == nil {
		return errors.New("cms: no embedded certificate matches the SignerInfo")
	}
	p.signerCert = cert

	hash, err := hashForDigestAlg(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}

	var signedBytes []byte
	if len(si.AuthenticatedAttributes) > 0 {
		p.authAttrs = si.AuthenticatedAttributes

		// The eContent digest must appear in the messageDigest attribute
		// (RFC 5652 §5.4).
		h := hash.New()
		h.Write(p.Content)
		wantDigest := h.Sum(nil)

		mdRaw, ok := firstAttrValue(p.authAttrs, oidAttrMessageDigest)
		if !ok {
			return errors.New("cms: authenticated attributes lack a messageDigest")
		}
		var md []byte
		if _, err := asn1.Unmarshal(mdRaw.FullBytes, &md); err != nil {
			return fmt.Errorf("cms: parsing messageDigest attribute: %w", err)
		}
		if !bytes.Equal(md, wantDigest) {
			return errors.New("cms: messageDigest attribute does not match the content")
		}

		// The signature is computed over the DER SET OF authenticated attributes
		// (with the universal SET tag, not the transmitted IMPLICIT [0] tag).
		signedBytes, err = marshalAuthAttrsForSigning(p.authAttrs)
		if err != nil {
			return err
		}
	} else {
		// No authenticated attributes: the signature is over the content itself.
		signedBytes = p.Content
	}

	return verifySignature(cert, hash, signedBytes, si.EncryptedDigest)
}

// AuthenticatedAttribute returns the raw DER value of the first authenticated
// attribute with the given type, and whether it was present. Verify must have
// been called first.
func (p *ParsedSignedData) AuthenticatedAttribute(oid asn1.ObjectIdentifier) (asn1.RawValue, bool) {
	return firstAttrValue(p.authAttrs, oid)
}

// findCert resolves an embedded certificate by issuer DN and serial number.
func (p *ParsedSignedData) findCert(ias issuerAndSerial) *x509.Certificate {
	for _, c := range p.Certificates {
		if ias.SerialNumber != nil && c.SerialNumber.Cmp(ias.SerialNumber) == 0 &&
			bytes.Equal(c.RawIssuer, ias.IssuerName.FullBytes) {
			return c
		}
	}
	return nil
}

// marshalAuthAttrsForSigning encodes the authenticated attributes as a DER
// SET OF Attribute (universal SET tag), which is what a SignerInfo signature is
// computed over. Go's asn1 marshaller sorts SET OF members canonically, so this
// reproduces the exact bytes any DER-conforming SCEP client signed.
func marshalAuthAttrsForSigning(attrs []attribute) ([]byte, error) {
	// asn1.Marshal of a struct wrapper yields SEQUENCE{ SET{...} }; unwrap the
	// outer SEQUENCE so we return just the SET TLV.
	wrapped, err := asn1.Marshal(struct {
		Attrs []attribute `asn1:"set"`
	}{Attrs: attrs})
	if err != nil {
		return nil, fmt.Errorf("cms: encoding authenticated attributes: %w", err)
	}
	var inner asn1.RawValue
	if _, err := asn1.Unmarshal(wrapped, &inner); err != nil {
		return nil, fmt.Errorf("cms: unwrapping authenticated attributes: %w", err)
	}
	return inner.Bytes, nil
}

// firstAttrValue returns the first value of the attribute with the given type.
func firstAttrValue(attrs []attribute, oid asn1.ObjectIdentifier) (asn1.RawValue, bool) {
	for _, a := range attrs {
		if a.Type.Equal(oid) {
			// a.Values holds the SET OF value(s); take the first element.
			var vals []asn1.RawValue
			buf := append([]byte(nil), a.Values.FullBytes...)
			if len(buf) > 0 {
				buf[0] = 0x30
			}
			if _, err := asn1.Unmarshal(buf, &vals); err != nil || len(vals) == 0 {
				return asn1.RawValue{}, false
			}
			return vals[0], true
		}
	}
	return asn1.RawValue{}, false
}

// verifySignature checks an RSA (PKCS#1 v1.5) signature over signedBytes.
func verifySignature(cert *x509.Certificate, hash crypto.Hash, signedBytes, sig []byte) error {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("cms: signer key is %T, only RSA signers are supported", cert.PublicKey)
	}
	h := hash.New()
	h.Write(signedBytes)
	if err := rsa.VerifyPKCS1v15(pub, hash, h.Sum(nil), sig); err != nil {
		return fmt.Errorf("cms: signature verification failed: %w", err)
	}
	return nil
}

// hashForDigestAlg maps a digest AlgorithmIdentifier OID to a crypto.Hash.
func hashForDigestAlg(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidDigestSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidDigestSHA1):
		return crypto.SHA1, nil
	case oid.Equal(oidDigestSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidDigestSHA512):
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("cms: unsupported digest algorithm %v", oid)
	}
}
