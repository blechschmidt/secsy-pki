package tsa

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
)

// Accuracy bounds how far a token's genTime may deviate from the true time
// (RFC 3161 §2.4.2). A zero Accuracy (all fields 0) is omitted from the token.
// Millis and Micros are constrained to 1..999 by the ASN.1 module.
type Accuracy struct {
	Seconds int
	Millis  int
	Micros  int
}

// IsZero reports whether the accuracy carries no information.
func (a Accuracy) IsZero() bool { return a.Seconds == 0 && a.Millis == 0 && a.Micros == 0 }

// rawAccuracy is the DER layout of RFC 3161 Accuracy. millis/micros are
// [0]/[1] IMPLICIT and, like seconds, omitted when zero.
type rawAccuracy struct {
	Seconds int `asn1:"optional,default:0"`
	Millis  int `asn1:"optional,default:0,tag:0"`
	Micros  int `asn1:"optional,default:0,tag:1"`
}

// marshal encodes the accuracy as a RawValue for embedding, reporting ok=false
// when the accuracy is zero (so the field is omitted from the TSTInfo).
func (a Accuracy) marshal() (asn1.RawValue, bool, error) {
	if a.IsZero() {
		return asn1.RawValue{}, false, nil
	}
	der, err := asn1.Marshal(rawAccuracy{Seconds: a.Seconds, Millis: a.Millis, Micros: a.Micros})
	if err != nil {
		return asn1.RawValue{}, false, fmt.Errorf("tsa: marshaling accuracy: %w", err)
	}
	return asn1.RawValue{FullBytes: der}, true, nil
}

// tstInfoParams carries the TSA-controlled inputs for a single TSTInfo, distinct
// from the client-supplied Request fields that are echoed back.
type tstInfoParams struct {
	Policy       asn1.ObjectIdentifier
	SerialNumber *big.Int
	GenTime      time.Time
	Accuracy     Accuracy
	Ordering     bool
	// TSAName, when non-nil, is embedded as the informational tsa GeneralName
	// (RFC 3161 §2.4.2); it is the DER of the signing certificate's subject Name.
	TSAName []byte
}

// rawTSTInfo is the RFC 3161 TSTInfo, laid out for DER marshaling. Accuracy and
// the tsa GeneralName are pre-encoded RawValues so they are omitted cleanly when
// absent; ordering is omitted when false (DER DEFAULT). GenTime is a
// GeneralizedTime (RFC 3161 §2.4.2) and must be UTC so it ends in "Z".
type rawTSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       asn1.RawValue    `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"optional"`
	Extensions     []pkix.Extension `asn1:"optional,tag:1"`
}

// buildTSTInfo constructs and DER-encodes the TSTInfo binding the request's
// message imprint (and nonce, when present) to the TSA's asserted time.
func buildTSTInfo(req *Request, p tstInfoParams) ([]byte, error) {
	if _, ok := oidForDigest(req.Hash); !ok {
		return nil, fmt.Errorf("tsa: no OID for hash %v", req.Hash)
	}
	info := rawTSTInfo{
		Version: 1,
		Policy:  p.Policy,
		// Echo the client's exact AlgorithmIdentifier (including parameters) so the
		// message imprint is byte-identical to the request's.
		MessageImprint: messageImprint{
			HashAlgorithm: req.hashAlgorithm,
			HashedMessage: req.Digest,
		},
		SerialNumber: p.SerialNumber,
		// GeneralizedTime has one-second resolution here; the (optional) Accuracy
		// field advertises the bound on how far genTime may drift from real time.
		GenTime:  p.GenTime.UTC().Truncate(time.Second),
		Ordering: p.Ordering,
		Nonce:    req.Nonce,
	}

	if acc, ok, err := p.Accuracy.marshal(); err != nil {
		return nil, err
	} else if ok {
		info.Accuracy = acc
	}
	if len(p.TSAName) > 0 {
		info.TSA = generalNameDirectory(p.TSAName)
	}

	der, err := asn1.Marshal(info)
	if err != nil {
		return nil, fmt.Errorf("tsa: marshaling TSTInfo: %w", err)
	}
	return der, nil
}

// generalNameDirectory wraps a subject Name DER as an explicit-[0] GeneralName
// of the directoryName ([4]) choice, the form TSTInfo's tsa field takes. Because
// GeneralName is an ASN.1 CHOICE, the outer [0] is EXPLICIT.
func generalNameDirectory(subjectDER []byte) asn1.RawValue {
	dirName := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: subjectDER}
	inner, err := asn1.Marshal(dirName)
	if err != nil {
		return asn1.RawValue{}
	}
	return asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}
}

// buildToken signs a TSTInfo into a TimeStampToken: a CMS SignedData whose
// eContentType is id-ct-TSTInfo and whose sole SignerInfo carries the ESS
// signing-certificate-v2 attribute (RFC 3161 §2.4.2, RFC 5035). The signature is
// produced on the key provider; for an HSM the private key never leaves it.
//
// When includeCerts is true (the client set certReq) the TSA certificate and its
// issuer chain are embedded; otherwise no certificates are embedded.
func buildToken(signer keyprovider.Signer, tsaCert *x509.Certificate, chain []*x509.Certificate,
	digest crypto.Hash, tstInfoDER []byte, includeCerts bool) ([]byte, error) {

	scv2, err := signingCertificateV2Attr(chainOrSelf(tsaCert, chain))
	if err != nil {
		return nil, err
	}

	opts := cms.SignedDataOpts{
		Content:     tstInfoDER,
		ContentType: OIDTSTInfo,
		SignerCert:  tsaCert,
		Signer:      signer,
		Digest:      digest,
		ExtraAttrs:  []cms.Attribute{scv2},
	}
	if includeCerts {
		opts.Certificates = chainOrSelf(tsaCert, chain)
	} else {
		opts.OmitCertificates = true
	}
	return cms.BuildSignedData(opts)
}

// chainOrSelf returns the full chain when it already begins with the TSA
// certificate, otherwise the TSA certificate alone.
func chainOrSelf(tsaCert *x509.Certificate, chain []*x509.Certificate) []*x509.Certificate {
	if len(chain) > 0 {
		return chain
	}
	return []*x509.Certificate{tsaCert}
}

// signingCertificateV2Attr builds the id-aa-signingCertificateV2 authenticated
// attribute. Only the leaf (the TSA certificate) is required by RFC 5035, but
// including the whole chain lets strict verifiers bind every certificate.
func signingCertificateV2Attr(chain []*x509.Certificate) (cms.Attribute, error) {
	if len(chain) == 0 {
		return cms.Attribute{}, fmt.Errorf("tsa: signing-certificate attribute requires at least the TSA certificate")
	}
	certs := make([]essCertIDv2, 0, len(chain))
	for _, c := range chain {
		sum := sha256.Sum256(c.Raw)
		certs = append(certs, essCertIDv2{CertHash: sum[:]})
	}
	return cms.Attribute{Type: OIDSigningCertificateV2, Value: signingCertificateV2{Certs: certs}}, nil
}

// essCertIDv2 is RFC 5035 ESSCertIDv2 with the default (id-sha256) hash
// algorithm and no issuerSerial, so it encodes as SEQUENCE { certHash }.
type essCertIDv2 struct {
	CertHash []byte
}

// signingCertificateV2 is RFC 5035 SigningCertificateV2 with no policies.
type signingCertificateV2 struct {
	Certs []essCertIDv2
}

// ---- TimeStampResp construction -------------------------------------------

// pkiStatusGranted is a PKIStatusInfo carrying only a granted status.
type pkiStatusGranted struct {
	Status int
}

// pkiStatusRejection is a PKIStatusInfo with a human-readable statusString and a
// machine-readable failInfo bit string.
type pkiStatusRejection struct {
	Status       int
	StatusString asn1.RawValue // PKIFreeText: SEQUENCE OF UTF8String
	FailInfo     asn1.BitString
}

// timeStampRespGranted is a TimeStampResp with a token; timeStampRespRejected
// omits it. RFC 3161 requires the token be absent on any non-granted status.
type timeStampRespGranted struct {
	Status asn1.RawValue // PKIStatusInfo
	Token  asn1.RawValue // TimeStampToken (a CMS ContentInfo)
}

type timeStampRespRejected struct {
	Status asn1.RawValue // PKIStatusInfo
}

// grantedResponse wraps a signed TimeStampToken in a granted TimeStampResp.
func grantedResponse(tokenDER []byte) ([]byte, error) {
	statusDER, err := asn1.Marshal(pkiStatusGranted{Status: StatusGranted})
	if err != nil {
		return nil, fmt.Errorf("tsa: marshaling granted status: %w", err)
	}
	return asn1.Marshal(timeStampRespGranted{
		Status: asn1.RawValue{FullBytes: statusDER},
		Token:  asn1.RawValue{FullBytes: tokenDER},
	})
}

// rejectionResponse builds a token-less TimeStampResp reporting a validation
// failure with the given PKIFailureInfo bit and message.
func rejectionResponse(failure int, message string) ([]byte, error) {
	freeText, err := marshalFreeText(message)
	if err != nil {
		return nil, err
	}
	statusDER, err := asn1.Marshal(pkiStatusRejection{
		Status:       StatusRejection,
		StatusString: freeText,
		FailInfo:     failInfoBitString(failure),
	})
	if err != nil {
		return nil, fmt.Errorf("tsa: marshaling rejection status: %w", err)
	}
	return asn1.Marshal(timeStampRespRejected{Status: asn1.RawValue{FullBytes: statusDER}})
}

// marshalFreeText encodes a single-line PKIFreeText (SEQUENCE OF UTF8String).
func marshalFreeText(s string) (asn1.RawValue, error) {
	utf8DER, err := asn1.MarshalWithParams(s, "utf8")
	if err != nil {
		return asn1.RawValue{}, fmt.Errorf("tsa: marshaling statusString: %w", err)
	}
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: utf8DER}, nil
}

// failInfoBitString returns a BIT STRING with the single named PKIFailureInfo
// bit set, trimmed to the minimal length (bit numbering is big-endian per X.680).
func failInfoBitString(bit int) asn1.BitString {
	n := bit + 1
	b := make([]byte, (n+7)/8)
	b[bit/8] |= 0x80 >> uint(bit%8)
	return asn1.BitString{Bytes: b, BitLength: n}
}
