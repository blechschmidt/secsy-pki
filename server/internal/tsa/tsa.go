// Package tsa implements an RFC 3161 Time-Stamp Authority (TSA).
//
// A TSA answers a TimeStampReq (a hash of some data, an optional nonce, and an
// optional policy) with a TimeStampResp carrying a TimeStampToken: a CMS
// SignedData that binds the submitted hash to a trusted time, signed by a
// dedicated TSA key. The signing key lives in the configured key provider (an
// HSM via PKCS#11, or the software keystore) and is used exclusively through
// crypto.Signer, so private key material never leaves the device.
//
// The TSA signing certificate MUST carry the id-kp-timeStamping extended key
// usage as its sole EKU (RFC 3161 §2.3) and, for openssl `ts -verify` interop,
// the key MUST be RSA: the CMS SignedData builder shared with the SCEP/EST
// enrollment code signs with RSA PKCS#1 v1.5. The certificate is provisioned
// offline with the `secsy-ca tsa-key` command and referenced from configuration.
//
// This file holds the wire structures, the request parser, and validation. The
// token/response construction lives in build.go and the HTTP authority in
// authority.go.
package tsa

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	// Register the hash implementations referenced by DigestForOID so a plain
	// import of this package guarantees they are linked in.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

// Object identifiers used by RFC 3161 / RFC 5652.
var (
	// OIDTSTInfo (id-ct-TSTInfo) is the eContentType of the TimeStampToken's
	// encapsulated content (RFC 3161 §2.4.2).
	OIDTSTInfo = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	// OIDSigningCertificateV2 (id-aa-signingCertificateV2) is the ESS signed
	// attribute that binds the SignerInfo to the TSA certificate (RFC 5035). A
	// conforming verifier (openssl included) checks it against the signer cert.
	OIDSigningCertificateV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	// OIDExtKeyUsageTimeStamping (id-kp-timeStamping) is the sole EKU a TSA
	// signing certificate may carry (RFC 3161 §2.3).
	OIDExtKeyUsageTimeStamping = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}

	// Digest-algorithm OIDs accepted in a MessageImprint.
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// DefaultPolicyOID is the TSA policy asserted when the operator does not
// configure one. It lives under the ITU-T "example" arc (2.999) so it can never
// collide with a real, registered policy; production deployments should set an
// owned policy OID in configuration.
var DefaultPolicyOID = asn1.ObjectIdentifier{2, 999, 1, 1}

// PKIStatus values (RFC 3161 §2.4.2, RFC 2510).
const (
	StatusGranted        = 0
	StatusGrantedWithMod = 1
	StatusRejection      = 2
)

// PKIFailureInfo bit positions (RFC 3161 §2.4.2). They are carried in a BIT
// STRING; only the machine-readable failure reason is conveyed here.
const (
	FailureBadAlg           = 0  // unrecognized or unsupported algorithm identifier
	FailureBadRequest       = 2  // transaction not permitted or supported
	FailureBadDataFormat    = 5  // the data submitted has the wrong format
	FailureTimeNotAvailable = 14 // the TSA's time source is not available
	FailureUnacceptedPolicy = 15 // the requested TSA policy is not supported
	FailureUnacceptedExtn   = 16 // the requested extension is not supported
	FailureAddInfoNotAvail  = 17 // additional information requested is not available
	FailureSystemFailure    = 25 // the request cannot be handled due to system failure
)

// messageImprint is the RFC 3161 MessageImprint: the hash algorithm and the
// resulting digest of the data being time-stamped. The same value is copied
// verbatim into the TSTInfo so a verifier can confirm the token covers its data.
type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// timeStampReq is the RFC 3161 TimeStampReq.
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"optional,tag:0"`
}

// Request is a parsed, validated TimeStampReq.
type Request struct {
	// Hash is the message-imprint digest algorithm.
	Hash crypto.Hash
	// hashAlgorithm is the exact AlgorithmIdentifier from the request, re-emitted
	// verbatim into the TSTInfo's messageImprint.
	hashAlgorithm pkix.AlgorithmIdentifier
	// Digest is the hashed message (its length equals Hash's output size).
	Digest []byte
	// ReqPolicy is the policy OID the client asked the TSA to assert, or nil.
	ReqPolicy asn1.ObjectIdentifier
	// Nonce echoes the client's large random nonce, or nil when absent. When
	// present it MUST be copied into the response with the same value.
	Nonce *big.Int
	// CertReq requests that the TSA include its signing certificate (and chain)
	// in the response (RFC 3161 §2.4.1).
	CertReq bool
}

// RequestError is a validation failure that maps to an RFC 3161 PKIFailureInfo,
// so the HTTP layer can return a signed-free rejection TimeStampResp instead of
// an opaque transport error.
type RequestError struct {
	Failure int    // one of the Failure* bit positions
	Message string // human-readable detail for statusString and logs
}

func (e *RequestError) Error() string { return e.Message }

func badRequest(failure int, format string, args ...any) *RequestError {
	return &RequestError{Failure: failure, Message: fmt.Sprintf(format, args...)}
}

// ParseRequest decodes and validates a DER-encoded TimeStampReq. On a
// well-formed but unacceptable request (unknown hash algorithm, wrong digest
// length) it returns a *RequestError carrying the appropriate PKIFailureInfo.
func ParseRequest(der []byte) (*Request, error) {
	var raw timeStampReq
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, badRequest(FailureBadDataFormat, "malformed TimeStampReq: %v", err)
	}
	if len(rest) != 0 {
		return nil, badRequest(FailureBadDataFormat, "trailing data after TimeStampReq")
	}
	// RFC 3161 defines only version 1.
	if raw.Version != 1 {
		return nil, badRequest(FailureBadRequest, "unsupported TimeStampReq version %d", raw.Version)
	}

	hash, ok := digestForOID(raw.MessageImprint.HashAlgorithm.Algorithm)
	if !ok {
		return nil, badRequest(FailureBadAlg, "unsupported message-imprint hash algorithm %v",
			raw.MessageImprint.HashAlgorithm.Algorithm)
	}
	if !hash.Available() {
		return nil, badRequest(FailureBadAlg, "hash algorithm %v is not linked into the binary", hash)
	}
	if got, want := len(raw.MessageImprint.HashedMessage), hash.Size(); got != want {
		return nil, badRequest(FailureBadDataFormat,
			"message-imprint digest length %d does not match %v output size %d", got, hash, want)
	}

	return &Request{
		Hash:          hash,
		hashAlgorithm: raw.MessageImprint.HashAlgorithm,
		Digest:        raw.MessageImprint.HashedMessage,
		ReqPolicy:     raw.ReqPolicy,
		Nonce:         raw.Nonce,
		CertReq:       raw.CertReq,
	}, nil
}

// digestForOID maps a digest-algorithm OID to its crypto.Hash. It reports false
// for an OID the TSA does not accept in a message imprint.
func digestForOID(oid asn1.ObjectIdentifier) (crypto.Hash, bool) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, true
	case oid.Equal(oidSHA384):
		return crypto.SHA384, true
	case oid.Equal(oidSHA512):
		return crypto.SHA512, true
	case oid.Equal(oidSHA1):
		return crypto.SHA1, true
	default:
		return 0, false
	}
}

// RequestOptions parameterize MakeRequest.
type RequestOptions struct {
	// Nonce, when set, is a large random value the TSA must echo back; it binds
	// a specific request to its response, defeating replay.
	Nonce *big.Int
	// Policy, when set, asks the TSA to assert exactly this policy OID.
	Policy asn1.ObjectIdentifier
	// CertReq asks the TSA to include its signing certificate in the response.
	CertReq bool
}

// MakeRequest builds a DER-encoded RFC 3161 TimeStampReq over a precomputed
// message-imprint digest. It is the client-side counterpart of ParseRequest and
// is used by callers (and tests) that need to construct a request without the
// openssl `ts` tool. digest must be the output of hash over the data to stamp.
func MakeRequest(hash crypto.Hash, digest []byte, opts *RequestOptions) ([]byte, error) {
	oid, ok := oidForDigest(hash)
	if !ok {
		return nil, fmt.Errorf("tsa: unsupported message-imprint hash %v", hash)
	}
	if len(digest) != hash.Size() {
		return nil, fmt.Errorf("tsa: digest length %d does not match %v size %d", len(digest), hash, hash.Size())
	}
	req := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oid, Parameters: asn1.NullRawValue},
			HashedMessage: digest,
		},
	}
	if opts != nil {
		req.ReqPolicy = opts.Policy
		req.Nonce = opts.Nonce
		req.CertReq = opts.CertReq
	}
	return asn1.Marshal(req)
}

// oidForDigest is the inverse of digestForOID, used when building a MessageImprint.
func oidForDigest(h crypto.Hash) (asn1.ObjectIdentifier, bool) {
	switch h {
	case crypto.SHA256:
		return oidSHA256, true
	case crypto.SHA384:
		return oidSHA384, true
	case crypto.SHA512:
		return oidSHA512, true
	case crypto.SHA1:
		return oidSHA1, true
	default:
		return nil, false
	}
}
