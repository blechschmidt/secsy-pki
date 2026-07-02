package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// RevokedEntry describes one revoked certificate for inclusion in a CRL.
type RevokedEntry struct {
	// Serial is the revoked certificate's serial number.
	Serial *big.Int
	// RevokedAt is when the certificate was revoked.
	RevokedAt time.Time
	// Reason is an RFC 5280 CRL reason code (0 = unspecified).
	Reason int
}

// CRLRequest describes a certificate revocation list to build.
type CRLRequest struct {
	// Number is the monotonically increasing CRL number for this issuer. Each
	// CRL an issuer publishes must carry a strictly greater number than the
	// previous one; callers should obtain it from a safe allocator.
	Number *big.Int
	// ThisUpdate / NextUpdate bound the validity of the CRL.
	ThisUpdate time.Time
	NextUpdate time.Time
	// Revoked is the full list of certificates currently revoked by the issuer.
	Revoked []RevokedEntry
}

// CreateCRL builds and signs an X.509 v2 certificate revocation list.
//
// issuer is the CA certificate whose key (signer) signs the list; for an
// HSM-backed provider the signature is produced on the device. The returned
// bytes are the DER encoding of the CRL.
func CreateCRL(signer crypto.Signer, issuer *x509.Certificate, req CRLRequest) ([]byte, error) {
	if issuer == nil {
		return nil, fmt.Errorf("CRL requires an issuing CA certificate")
	}
	if signer == nil {
		return nil, fmt.Errorf("CRL requires a signer")
	}
	if req.Number == nil || req.Number.Sign() < 0 {
		return nil, fmt.Errorf("CRL number must be a non-negative integer")
	}
	if !req.NextUpdate.After(req.ThisUpdate) {
		return nil, fmt.Errorf("CRL next_update (%s) must be after this_update (%s)", req.NextUpdate, req.ThisUpdate)
	}

	revoked := make([]x509.RevocationListEntry, 0, len(req.Revoked))
	for _, e := range req.Revoked {
		if e.Serial == nil {
			return nil, fmt.Errorf("revoked entry is missing a serial number")
		}
		revoked = append(revoked, x509.RevocationListEntry{
			SerialNumber:   e.Serial,
			RevocationTime: e.RevokedAt,
			ReasonCode:     e.Reason,
		})
	}

	template := &x509.RevocationList{
		Number:                    req.Number,
		ThisUpdate:                req.ThisUpdate,
		NextUpdate:                req.NextUpdate,
		RevokedCertificateEntries: revoked,
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, issuer, signer)
	if err != nil {
		return nil, fmt.Errorf("creating revocation list: %w", err)
	}
	return der, nil
}

// EncodeCRLPEM wraps a DER CRL in a PEM block.
func EncodeCRLPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

// RFC 5280 §5.3.1 CRL reason codes.
const (
	RevocationReasonUnspecified          = 0
	RevocationReasonKeyCompromise        = 1
	RevocationReasonCACompromise         = 2
	RevocationReasonAffiliationChanged   = 3
	RevocationReasonSuperseded           = 4
	RevocationReasonCessationOfOperation = 5
	RevocationReasonCertificateHold      = 6
	RevocationReasonPrivilegeWithdrawn   = 9
	RevocationReasonAACompromise         = 10
)

// revocationReasonNames maps RFC 5280 reason names to their numeric codes.
var revocationReasonNames = map[string]int{
	"unspecified":          RevocationReasonUnspecified,
	"keycompromise":        RevocationReasonKeyCompromise,
	"cacompromise":         RevocationReasonCACompromise,
	"affiliationchanged":   RevocationReasonAffiliationChanged,
	"superseded":           RevocationReasonSuperseded,
	"cessationofoperation": RevocationReasonCessationOfOperation,
	"certificatehold":      RevocationReasonCertificateHold,
	"privilegewithdrawn":   RevocationReasonPrivilegeWithdrawn,
	"aacompromise":         RevocationReasonAACompromise,
}

// ParseRevocationReason maps a reason name (case-insensitive, e.g.
// "keyCompromise") to its RFC 5280 numeric code. An empty string maps to
// "unspecified". Unknown names are rejected.
func ParseRevocationReason(name string) (int, error) {
	if name == "" {
		return RevocationReasonUnspecified, nil
	}
	code, ok := revocationReasonNames[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return 0, fmt.Errorf("unknown revocation reason %q", name)
	}
	return code, nil
}
