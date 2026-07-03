package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	// Imported for their side effect of linking the hash implementations used by
	// the OCSP certID (SHA-1 by default) and response signatures into the binary.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	"golang.org/x/crypto/ocsp"
)

// OCSP status codes re-exported so callers need not import the ocsp package.
const (
	OCSPGood    = ocsp.Good
	OCSPRevoked = ocsp.Revoked
	OCSPUnknown = ocsp.Unknown
)

// Pre-serialized OCSP error responses re-exported so HTTP handlers need not
// import the ocsp package (RFC 6960 §4.2.1). These are the definite,
// unsigned responses a responder returns when it cannot produce a signed
// answer.
var (
	// OCSPMalformedResponse is returned for a request that cannot be parsed.
	OCSPMalformedResponse = ocsp.MalformedRequestErrorResponse
	// OCSPInternalErrorResponse is returned when the responder hit an
	// unexpected internal error.
	OCSPInternalErrorResponse = ocsp.InternalErrorErrorResponse
	// OCSPTryLaterResponse tells the client the responder is transiently
	// unable to answer (e.g. the signing backend is momentarily unavailable or
	// shedding load); the client should retry.
	OCSPTryLaterResponse = ocsp.TryLaterErrorResponse
	// OCSPUnauthorizedResponse is returned when the responder is not
	// authoritative for the requested certificate (unknown issuer / CA).
	OCSPUnauthorizedResponse = ocsp.UnauthorizedErrorResponse
	// OCSPSigRequiredResponse is returned when the responder requires a signed
	// request but received an unsigned one.
	OCSPSigRequiredResponse = ocsp.SigRequredErrorResponse
)

// OCSP extension object identifiers (RFC 6960 / RFC 8954).
var (
	// OIDNonce is id-pkix-ocsp-nonce (1.3.6.1.5.5.7.48.1.2). It appears in the
	// requestExtensions of a request and, echoed, in the responseExtensions of
	// the signed response to bind a specific request to its response and defeat
	// replay of pre-computed responses.
	OIDNonce = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}
	// OIDOCSPNoCheck is id-pkix-ocsp-nocheck (1.3.6.1.5.5.7.48.1.5). A CA places
	// it in a delegated OCSP-signing certificate to tell relying parties they
	// need not obtain revocation status for that short-lived certificate.
	OIDOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}
)

// Nonce length bounds (RFC 8954 §2.1). A conforming responder accepts nonces of
// 1..32 octets; anything outside that range is treated as a malformed request so
// an attacker cannot force large allocations or smuggle oversized data through
// the extension.
const (
	MinNonceLength = 1
	MaxNonceLength = 32
)

// ParseOCSPRequest parses a DER-encoded OCSP request.
func ParseOCSPRequest(der []byte) (*ocsp.Request, error) {
	return ocsp.ParseRequest(der)
}

// BuildOCSPRequest constructs a DER-encoded OCSP request asking about cert,
// issued by issuer. It is a thin wrapper over the ocsp package used by tests and
// benchmarks (and available to clients) so they need not import ocsp directly.
func BuildOCSPRequest(cert, issuer *x509.Certificate) ([]byte, error) {
	return ocsp.CreateRequest(cert, issuer, nil)
}

// BuildOCSPRequestForSerial constructs the canonical DER-encoded OCSP request
// asking about one serial under issuer: SHA-1 certID (the RFC 6960 default and
// what RFC 5019 lightweight clients send) and no extensions. Because the
// encoding is fully determined by (issuer, serial), it is usable as a stable
// lookup key: the static artifact publisher stores each pre-signed response
// under the base64url form of this encoding so a CDN can map RFC 6960 A.1 GET
// requests onto static objects.
func BuildOCSPRequestForSerial(issuer *x509.Certificate, serial *big.Int) ([]byte, error) {
	if issuer == nil {
		return nil, fmt.Errorf("OCSP request requires an issuing CA certificate")
	}
	if serial == nil {
		return nil, fmt.Errorf("OCSP request requires a serial number")
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("parsing issuer public key: %w", err)
	}
	h := crypto.SHA1.New()
	h.Write(spki.SubjectPublicKey.RightAlign())
	keyHash := h.Sum(nil)
	h.Reset()
	h.Write(issuer.RawSubject)
	nameHash := h.Sum(nil)

	req := ocsp.Request{
		HashAlgorithm:  crypto.SHA1,
		IssuerNameHash: nameHash,
		IssuerKeyHash:  keyHash,
		SerialNumber:   serial,
	}
	return req.Marshal()
}

// BuildOCSPRequestWithNonce builds the canonical request for a serial under
// issuer (as BuildOCSPRequestForSerial) carrying an RFC 8954 nonce request
// extension. golang.org/x/crypto/ocsp cannot marshal request extensions, so
// the TBSRequest is assembled directly.
func BuildOCSPRequestWithNonce(issuer *x509.Certificate, serial *big.Int, nonce []byte) ([]byte, error) {
	base, err := BuildOCSPRequestForSerial(issuer, serial)
	if err != nil {
		return nil, err
	}
	if len(nonce) == 0 {
		return base, nil
	}
	var req ocspRequestASN1
	if _, err := asn1.Unmarshal(base, &req); err != nil {
		return nil, fmt.Errorf("re-parsing canonical request: %w", err)
	}
	ext, err := nonceExtension(nonce)
	if err != nil {
		return nil, err
	}
	type tbs struct {
		RequestList []asn1.RawValue
		Extensions  []pkix.Extension `asn1:"explicit,tag:2,optional"`
	}
	out, err := asn1.Marshal(struct{ TBS tbs }{TBS: tbs{
		RequestList: req.TBSRequest.RequestList,
		Extensions:  []pkix.Extension{ext},
	}})
	if err != nil {
		return nil, fmt.Errorf("marshaling nonce-bearing request: %w", err)
	}
	return out, nil
}

// OCSPResponseNextUpdate parses a signed OCSP response (without verifying its
// signature) and returns its NextUpdate. It is used by the TLS stapler to decide
// when to refresh a staple. It reports false if the response cannot be parsed or
// carries no NextUpdate.
func OCSPResponseNextUpdate(der []byte) (time.Time, bool) {
	resp, err := ocsp.ParseResponse(der, nil)
	if err != nil || resp.NextUpdate.IsZero() {
		return time.Time{}, false
	}
	return resp.NextUpdate, true
}

// OCSPResponseNonce returns the nonce echoed in a signed OCSP response's
// response-level responseExtensions (RFC 6960 §4.4.1), or nil if none is
// present. It is the response-side counterpart of ExtractOCSPNonce and lets a
// client confirm the responder bound the response to its request nonce. The
// golang.org/x/crypto/ocsp parser does not surface these extensions, so this
// decodes the response structure directly. It does not verify the signature.
func OCSPResponseNonce(der []byte) ([]byte, error) {
	var outer ocspResponseASN1
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, fmt.Errorf("parsing OCSP response: %w", err)
	}
	if !outer.Response.ResponseType.Equal(oidPKIXOCSPBasic) {
		return nil, fmt.Errorf("not a basic OCSP response")
	}
	var basic basicResponseASN1
	if _, err := asn1.Unmarshal(outer.Response.Response, &basic); err != nil {
		return nil, fmt.Errorf("parsing OCSP basicResponse: %w", err)
	}
	var tbs responseDataASN1
	if _, err := asn1.Unmarshal(basic.TBSResponseData.FullBytes, &tbs); err != nil {
		return nil, fmt.Errorf("parsing OCSP responseData: %w", err)
	}
	for _, ext := range tbs.ResponseExtensions {
		if !ext.Id.Equal(OIDNonce) {
			continue
		}
		var inner []byte
		if rest, err := asn1.Unmarshal(ext.Value, &inner); err == nil && len(rest) == 0 {
			return inner, nil
		}
		return ext.Value, nil
	}
	return nil, nil
}

// OCSPRequestSerial extracts the requested certificate serial (base-10) from a
// DER-encoded OCSP request, for use as a response-cache key. It reports false if
// the request cannot be parsed, so callers fall back to signing freshly rather
// than caching under a wrong or empty key.
func OCSPRequestSerial(der []byte) (string, bool) {
	req, err := ocsp.ParseRequest(der)
	if err != nil || req.SerialNumber == nil {
		return "", false
	}
	return req.SerialNumber.String(), true
}

// -----------------------------------------------------------------------------
// Nonce extraction
// -----------------------------------------------------------------------------

// ASN.1 shapes for the TBSRequest, sufficient to reach the requestExtensions
// field that golang.org/x/crypto/ocsp does not surface. Only the pieces needed
// to locate the nonce are modeled; the request body itself is parsed by the
// ocsp package.
type ocspRequestASN1 struct {
	Raw        asn1.RawContent
	TBSRequest tbsRequestASN1
	// The optional signature is not modeled; asn1.Unmarshal tolerates trailing
	// SEQUENCE members it is not told about only via the RawValue below.
	OptionalSignature asn1.RawValue `asn1:"optional,tag:0"`
}

type tbsRequestASN1 struct {
	Version       int              `asn1:"explicit,tag:0,default:0,optional"`
	RequestorName asn1.RawValue    `asn1:"explicit,tag:1,optional"`
	RequestList   []asn1.RawValue  // opaque; the ocsp package parses the bodies
	Extensions    []pkix.Extension `asn1:"explicit,tag:2,optional"`
}

// ExtractOCSPNonce returns the raw nonce value carried by the id-pkix-ocsp-nonce
// request extension, or nil if the request carries no nonce.
//
// It returns ErrNonceTooLong / ErrNonceTooShort (wrapped) if a nonce is present
// but violates the RFC 8954 length bounds, so the caller can answer "malformed".
// The returned bytes are the extension value's inner OCTET STRING contents
// (RFC 8954 encodes the nonce as an OCTET STRING inside the extnValue).
func ExtractOCSPNonce(der []byte) ([]byte, error) {
	var req ocspRequestASN1
	if _, err := asn1.Unmarshal(der, &req); err != nil {
		return nil, fmt.Errorf("parsing OCSP request for nonce: %w", err)
	}
	for _, ext := range req.TBSRequest.Extensions {
		if !ext.Id.Equal(OIDNonce) {
			continue
		}
		nonce := ext.Value
		// RFC 8954 wraps the nonce in an OCTET STRING inside extnValue. Older
		// clients (and RFC 6960's under-specified form) sometimes place the raw
		// bytes directly. Accept either: try to peel one OCTET STRING layer, and
		// fall back to the raw value if that does not parse cleanly.
		var inner []byte
		if rest, err := asn1.Unmarshal(ext.Value, &inner); err == nil && len(rest) == 0 {
			nonce = inner
		}
		if len(nonce) > MaxNonceLength {
			return nil, fmt.Errorf("OCSP nonce is %d octets, exceeds max %d: %w", len(nonce), MaxNonceLength, ErrNonceTooLong)
		}
		if len(nonce) < MinNonceLength {
			return nil, fmt.Errorf("OCSP nonce is empty: %w", ErrNonceTooShort)
		}
		return nonce, nil
	}
	return nil, nil
}

// Sentinel errors for nonce length violations.
var (
	ErrNonceTooLong  = fmt.Errorf("OCSP nonce exceeds maximum length")
	ErrNonceTooShort = fmt.Errorf("OCSP nonce below minimum length")
)

// nonceExtension builds the id-pkix-ocsp-nonce extension for a response,
// re-wrapping the nonce value in an OCTET STRING as RFC 8954 specifies.
func nonceExtension(nonce []byte) (pkix.Extension, error) {
	wrapped, err := asn1.Marshal(nonce)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding nonce: %w", err)
	}
	return pkix.Extension{Id: OIDNonce, Critical: false, Value: wrapped}, nil
}

// OCSPNoCheckExtension returns the id-pkix-ocsp-nocheck extension (value: an
// explicit DER NULL) to place in a delegated OCSP-signing certificate so relying
// parties do not attempt to check that certificate's own revocation status.
func OCSPNoCheckExtension() pkix.Extension {
	// RFC 6960 §4.2.2.2.1: the extension value is DER-encoded NULL.
	return pkix.Extension{Id: OIDOCSPNoCheck, Critical: false, Value: []byte{0x05, 0x00}}
}

// -----------------------------------------------------------------------------
// Response construction
// -----------------------------------------------------------------------------

// OCSPResponseSpec describes the status of a single certificate to attest to in
// an OCSP response.
type OCSPResponseSpec struct {
	// Serial is the serial number the request asked about.
	Serial *big.Int
	// Status is one of OCSPGood, OCSPRevoked, OCSPUnknown.
	Status int
	// RevokedAt and RevocationReason are only meaningful when Status is
	// OCSPRevoked.
	RevokedAt        time.Time
	RevocationReason int
	// ThisUpdate / NextUpdate bound the validity of the response. If NextUpdate
	// is zero the response has no explicit expiry.
	ThisUpdate time.Time
	NextUpdate time.Time

	// IssuerHash selects the hash used to compute the certID IssuerNameHash and
	// IssuerKeyHash. Zero means SHA-1 (the RFC 6960 default). When answering a
	// request, set it to the request's HashAlgorithm so the response certID
	// matches what the client asked about.
	IssuerHash crypto.Hash

	// Nonce, when non-empty, is echoed as the id-pkix-ocsp-nonce response
	// extension (RFC 8954), binding this response to the request that carried it.
	Nonce []byte

	// Responder, when non-nil, is a delegated OCSP-signing certificate. Its
	// subject becomes the responder ID and it is embedded in the response so a
	// relying party can build the path issuer -> responder -> response. When nil,
	// the issuing CA is its own responder (responder ID = issuer, no embedded
	// certificate).
	Responder *x509.Certificate
}

// CreateOCSPResponse builds and signs an OCSP response attesting to the status
// of a single certificate.
//
// issuer is the CA certificate that issued the certificate in question. signer
// is the key producing the signature: for a CA signing its own responses that is
// the CA key (and spec.Responder is nil); for a delegated responder it is the
// short-lived OCSP-signing key whose certificate is spec.Responder. For an
// HSM-backed provider the signature is produced on the device.
//
// Unlike golang.org/x/crypto/ocsp.CreateResponse, this builder can place the
// nonce in the response-level responseExtensions (where RFC 6960 requires it and
// where openssl and other clients look for it), which the upstream package does
// not support. OCSP signing supports RSA and ECDSA keys; Ed25519 is not
// supported by the OCSP encoding and yields an error.
func CreateOCSPResponse(signer crypto.Signer, issuer *x509.Certificate, spec OCSPResponseSpec) ([]byte, error) {
	if issuer == nil {
		return nil, fmt.Errorf("OCSP response requires an issuing CA certificate")
	}
	if signer == nil {
		return nil, fmt.Errorf("OCSP response requires a signer")
	}
	if spec.Serial == nil {
		return nil, fmt.Errorf("OCSP response requires a serial number")
	}

	issuerHash := spec.IssuerHash
	if issuerHash == 0 {
		issuerHash = crypto.SHA1
	}
	if !issuerHash.Available() {
		return nil, fmt.Errorf("OCSP issuer hash %v not linked into binary", issuerHash)
	}
	hashOID, err := hashToOID(issuerHash)
	if err != nil {
		return nil, err
	}

	// IssuerNameHash / IssuerKeyHash over the issuing CA, per RFC 6960. Recomputing
	// them from the issuer with the request's hash yields the same bytes the
	// client put in the request certID.
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, fmt.Errorf("parsing issuer public key: %w", err)
	}
	h := issuerHash.New()
	h.Write(spki.SubjectPublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)
	h.Reset()
	h.Write(issuer.RawSubject)
	issuerNameHash := h.Sum(nil)

	// Responder identity + the certificate (if delegated) to embed.
	responderCert := issuer
	if spec.Responder != nil {
		responderCert = spec.Responder
	}

	sigHash, sigAlgID, err := ocspSigningParams(signer.Public())
	if err != nil {
		return nil, err
	}

	single := singleResponseASN1{
		CertID: certIDASN1{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  hashOID,
				Parameters: asn1.RawValue{Tag: 5}, // ASN.1 NULL
			},
			NameHash:      issuerNameHash,
			IssuerKeyHash: issuerKeyHash,
			SerialNumber:  spec.Serial,
		},
		ThisUpdate: spec.ThisUpdate.UTC(),
		NextUpdate: spec.NextUpdate.UTC(),
	}
	switch spec.Status {
	case ocsp.Good:
		single.Good = true
	case ocsp.Unknown:
		single.Unknown = true
	case ocsp.Revoked:
		single.Revoked = revokedInfoASN1{
			RevocationTime: spec.RevokedAt.UTC(),
			Reason:         asn1.Enumerated(spec.RevocationReason),
		}
	default:
		return nil, fmt.Errorf("invalid OCSP status %d", spec.Status)
	}

	var responseExts []pkix.Extension
	if len(spec.Nonce) > 0 {
		ext, err := nonceExtension(spec.Nonce)
		if err != nil {
			return nil, err
		}
		responseExts = append(responseExts, ext)
	}

	tbs := responseDataASN1{
		Version: 0,
		RawResponderID: asn1.RawValue{
			Class:      2, // context-specific
			Tag:        1, // byName [1] Name
			IsCompound: true,
			Bytes:      responderCert.RawSubject,
		},
		ProducedAt:         time.Now().Truncate(time.Minute).UTC(),
		Responses:          []singleResponseASN1{single},
		ResponseExtensions: responseExts,
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("encoding OCSP responseData: %w", err)
	}

	digest := sigHash.New()
	digest.Write(tbsDER)
	sig, err := signer.Sign(rand.Reader, digest.Sum(nil), sigHash)
	if err != nil {
		return nil, fmt.Errorf("signing OCSP response: %w", err)
	}

	basic := basicResponseASN1{
		TBSResponseData:    asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: sigAlgID,
		Signature:          asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)},
	}
	if spec.Responder != nil {
		basic.Certificates = []asn1.RawValue{{FullBytes: spec.Responder.Raw}}
	}
	basicDER, err := asn1.Marshal(basic)
	if err != nil {
		return nil, fmt.Errorf("encoding OCSP basicResponse: %w", err)
	}

	return asn1.Marshal(ocspResponseASN1{
		Status: asn1.Enumerated(ocsp.Success),
		Response: responseBytesASN1{
			ResponseType: oidPKIXOCSPBasic,
			Response:     basicDER,
		},
	})
}

// -----------------------------------------------------------------------------
// ASN.1 wire structures for the OCSP response (RFC 6960 §4.2.1). These mirror
// the private types in golang.org/x/crypto/ocsp but add the response-level
// responseExtensions field so a nonce can be echoed where the RFC requires it.
// -----------------------------------------------------------------------------

var oidPKIXOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

type ocspResponseASN1 struct {
	Status   asn1.Enumerated
	Response responseBytesASN1 `asn1:"explicit,tag:0,optional"`
}

type responseBytesASN1 struct {
	ResponseType asn1.ObjectIdentifier
	Response     []byte
}

type basicResponseASN1 struct {
	TBSResponseData    asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          asn1.BitString
	Certificates       []asn1.RawValue `asn1:"explicit,tag:0,optional"`
}

type responseDataASN1 struct {
	Version            int `asn1:"optional,default:0,explicit,tag:0"`
	RawResponderID     asn1.RawValue
	ProducedAt         time.Time `asn1:"generalized"`
	Responses          []singleResponseASN1
	ResponseExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type singleResponseASN1 struct {
	CertID           certIDASN1
	Good             asn1.Flag        `asn1:"tag:0,optional"`
	Revoked          revokedInfoASN1  `asn1:"tag:1,optional"`
	Unknown          asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate       time.Time        `asn1:"generalized"`
	NextUpdate       time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	SingleExtensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

type certIDASN1 struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	NameHash      []byte
	IssuerKeyHash []byte
	SerialNumber  *big.Int
}

type revokedInfoASN1 struct {
	RevocationTime time.Time       `asn1:"generalized"`
	Reason         asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}

// -----------------------------------------------------------------------------
// Signature / hash algorithm helpers
// -----------------------------------------------------------------------------

// Hash algorithm OIDs for the certID.
var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

func hashToOID(h crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch h {
	case crypto.SHA1:
		return oidSHA1, nil
	case crypto.SHA256:
		return oidSHA256, nil
	case crypto.SHA384:
		return oidSHA384, nil
	case crypto.SHA512:
		return oidSHA512, nil
	default:
		return nil, fmt.Errorf("unsupported OCSP certID hash %v", h)
	}
}

// Signature algorithm OIDs for the response signature.
var (
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// ocspSigningParams returns the digest to hash the responseData with and the
// AlgorithmIdentifier to record, for the responder's public key. It mirrors the
// choices golang.org/x/crypto/ocsp makes: SHA-256 for RSA, and a curve-matched
// SHA for ECDSA.
func ocspSigningParams(pub crypto.PublicKey) (crypto.Hash, pkix.AlgorithmIdentifier, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return crypto.SHA256, pkix.AlgorithmIdentifier{
			Algorithm:  oidSignatureSHA256WithRSA,
			Parameters: asn1.RawValue{Tag: 5}, // NULL, required for RSA
		}, nil
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return crypto.SHA256, pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWithSHA256}, nil
		case elliptic.P384():
			return crypto.SHA384, pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWithSHA384}, nil
		case elliptic.P521():
			return crypto.SHA512, pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWithSHA512}, nil
		default:
			return 0, pkix.AlgorithmIdentifier{}, fmt.Errorf("unsupported ECDSA curve for OCSP signing")
		}
	default:
		return 0, pkix.AlgorithmIdentifier{}, fmt.Errorf("OCSP signing requires an RSA or ECDSA key, got %T", pub)
	}
}
