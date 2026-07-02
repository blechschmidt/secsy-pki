package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSP status codes re-exported so callers need not import the ocsp package.
const (
	OCSPGood    = ocsp.Good
	OCSPRevoked = ocsp.Revoked
	OCSPUnknown = ocsp.Unknown
)

// Pre-serialized OCSP error responses re-exported so HTTP handlers need not
// import the ocsp package (RFC 6960 §4.2.1).
var (
	OCSPMalformedResponse     = ocsp.MalformedRequestErrorResponse
	OCSPInternalErrorResponse = ocsp.InternalErrorErrorResponse
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
}

// CreateOCSPResponse builds and signs an OCSP response attesting to the status
// of a single certificate. issuer is the CA certificate that issued the
// certificate in question and signer is the CA key (the CA signs its own OCSP
// responses here, so the responder certificate is the issuer itself). For an
// HSM-backed provider the signature is produced on the device.
//
// OCSP signing supports RSA and ECDSA CA keys; Ed25519 is not supported by the
// underlying encoder and yields an error.
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
	switch signer.Public().(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
	default:
		return nil, fmt.Errorf("OCSP signing requires an RSA or ECDSA CA key")
	}

	tmpl := ocsp.Response{
		Status:       spec.Status,
		SerialNumber: spec.Serial,
		ThisUpdate:   spec.ThisUpdate,
		NextUpdate:   spec.NextUpdate,
	}
	if spec.Status == ocsp.Revoked {
		tmpl.RevokedAt = spec.RevokedAt
		tmpl.RevocationReason = spec.RevocationReason
	}

	// The CA is its own OCSP responder.
	return ocsp.CreateResponse(issuer, issuer, tmpl, signer)
}
