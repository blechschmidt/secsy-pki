package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// RFC 5280 CRL-extension object identifiers used for delta CRLs and partitioning.
var (
	// oidDeltaCRLIndicator (2.5.29.27) marks a CRL as a delta CRL relative to a
	// base CRL identified by its CRLNumber. It is always critical (§5.2.4).
	oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}
	// oidIssuingDistributionPoint (2.5.29.28) scopes a CRL to a distribution
	// point / certificate subset. It is always critical (§5.2.5).
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	// oidFreshestCRL (2.5.29.46) identifies where the delta CRL for a base CRL
	// can be obtained. It is always non-critical (§5.2.6).
	oidFreshestCRL = asn1.ObjectIdentifier{2, 5, 29, 46}
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

// IssuingDistributionPoint describes the RFC 5280 §5.2.5 issuing-distribution-
// point scope of a CRL. It is used to bind a (base or delta) CRL to the
// distribution-point URL stamped into the certificates it covers, which is how a
// relying party knows a partitioned CRL is the authoritative one for a given
// certificate (the cert's CRLDistributionPoints must name the same URL).
type IssuingDistributionPoint struct {
	// DistributionPointURLs are the URIs of this CRL's distribution point. They
	// must match the CRLDistributionPoints stamped into the covered certificates.
	DistributionPointURLs []string
	// OnlyContainsUserCerts sets the onlyContainsUserCerts flag: the CRL covers
	// only end-entity certificates (partitioned leaf CRLs always do).
	OnlyContainsUserCerts bool
}

// CRLRequest describes a certificate revocation list to build.
type CRLRequest struct {
	// Number is the monotonically increasing CRL number for this issuer/scope.
	// Each CRL a scope publishes — base or delta — must carry a strictly greater
	// number than the previous one; callers should obtain it from a safe
	// allocator (RFC 5280 §5.2.3).
	Number *big.Int
	// ThisUpdate / NextUpdate bound the validity of the CRL.
	ThisUpdate time.Time
	NextUpdate time.Time
	// Revoked is the list of certificates in scope. For a base (complete) CRL it
	// is the full revocation list; for a delta CRL it is the entries revoked
	// since the referenced base CRL.
	Revoked []RevokedEntry

	// BaseCRLNumber, when non-nil, makes this a delta CRL: it carries the
	// (critical) Delta CRL Indicator extension referencing the base CRL whose
	// CRLNumber this equals. It must be strictly less than Number.
	BaseCRLNumber *big.Int
	// FreshestCRLURLs, when non-empty, adds the (non-critical) Freshest CRL
	// extension pointing relying parties at the delta CRL for this scope. It is
	// set on base CRLs, not on delta CRLs.
	FreshestCRLURLs []string
	// IDP, when non-nil, adds the (critical) Issuing Distribution Point extension
	// scoping the CRL to a partition. Partitioned (sharded) CRLs set it so the
	// covered certificates' CRLDistributionPoints match this CRL.
	IDP *IssuingDistributionPoint
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

	if req.BaseCRLNumber != nil {
		if req.BaseCRLNumber.Sign() < 0 {
			return nil, fmt.Errorf("delta CRL base number must be non-negative")
		}
		if req.BaseCRLNumber.Cmp(req.Number) >= 0 {
			return nil, fmt.Errorf("delta CRL base number (%s) must be less than the delta CRL number (%s)", req.BaseCRLNumber, req.Number)
		}
	}

	exts, err := crlExtraExtensions(req)
	if err != nil {
		return nil, err
	}

	template := &x509.RevocationList{
		Number:                    req.Number,
		ThisUpdate:                req.ThisUpdate,
		NextUpdate:                req.NextUpdate,
		RevokedCertificateEntries: revoked,
		ExtraExtensions:           exts,
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, issuer, signer)
	if err != nil {
		return nil, fmt.Errorf("creating revocation list: %w", err)
	}
	return der, nil
}

// crlExtraExtensions builds the RFC 5280 delta/partitioning extensions requested
// in req, hand-encoding the DER because crypto/x509 does not natively emit the
// Delta CRL Indicator, Issuing Distribution Point, or Freshest CRL extensions.
func crlExtraExtensions(req CRLRequest) ([]pkix.Extension, error) {
	var exts []pkix.Extension

	// Issuing Distribution Point (critical) — emitted first so a partitioned
	// CRL's scope is declared up front.
	if req.IDP != nil {
		val, err := marshalIssuingDistributionPoint(*req.IDP)
		if err != nil {
			return nil, fmt.Errorf("encoding issuing distribution point: %w", err)
		}
		exts = append(exts, pkix.Extension{Id: oidIssuingDistributionPoint, Critical: true, Value: val})
	}

	// Delta CRL Indicator (critical) — presence makes this a delta CRL.
	if req.BaseCRLNumber != nil {
		val, err := asn1.Marshal(req.BaseCRLNumber)
		if err != nil {
			return nil, fmt.Errorf("encoding delta CRL indicator: %w", err)
		}
		exts = append(exts, pkix.Extension{Id: oidDeltaCRLIndicator, Critical: true, Value: val})
	}

	// Freshest CRL (non-critical) — where to fetch the delta for a base CRL. Its
	// value uses the same syntax as a certificate's CRLDistributionPoints.
	if len(req.FreshestCRLURLs) > 0 {
		val, err := marshalCRLDistributionPoints(req.FreshestCRLURLs)
		if err != nil {
			return nil, fmt.Errorf("encoding freshest CRL: %w", err)
		}
		exts = append(exts, pkix.Extension{Id: oidFreshestCRL, Critical: false, Value: val})
	}

	return exts, nil
}

// generalNamesURIs encodes a run of GeneralName uniformResourceIdentifier [6]
// IA5String values (no enclosing SEQUENCE), for use inside a DistributionPointName.
func generalNamesURIs(uris []string) ([]byte, error) {
	var out []byte
	for _, u := range uris {
		raw := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 6, Bytes: []byte(u)}
		enc, err := asn1.Marshal(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, enc...)
	}
	return out, nil
}

// distributionPointField encodes the shared "distributionPoint [0]
// DistributionPointName { fullName [0] GeneralNames }" element (A0 { A0 { 86… } })
// used by both CRLDistributionPoints/Freshest CRL and IssuingDistributionPoint.
func distributionPointField(uris []string) ([]byte, error) {
	names, err := generalNamesURIs(uris)
	if err != nil {
		return nil, err
	}
	// fullName [0] GeneralNames (implicit) — context [0] constructed.
	fullName := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: names}
	fullNameDER, err := asn1.Marshal(fullName)
	if err != nil {
		return nil, err
	}
	// distributionPoint [0] DistributionPointName — context [0] constructed.
	dp := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: fullNameDER}
	return asn1.Marshal(dp)
}

// marshalCRLDistributionPoints encodes a CRLDistributionPoints value:
// SEQUENCE OF DistributionPoint, each a SEQUENCE holding one distributionPoint [0].
func marshalCRLDistributionPoints(uris []string) ([]byte, error) {
	field, err := distributionPointField(uris)
	if err != nil {
		return nil, err
	}
	dp := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: field}
	dpDER, err := asn1.Marshal(dp)
	if err != nil {
		return nil, err
	}
	outer := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: dpDER}
	return asn1.Marshal(outer)
}

// marshalIssuingDistributionPoint encodes an IssuingDistributionPoint value:
// SEQUENCE { distributionPoint [0] …, onlyContainsUserCerts [1] BOOLEAN }.
func marshalIssuingDistributionPoint(idp IssuingDistributionPoint) ([]byte, error) {
	if len(idp.DistributionPointURLs) == 0 && !idp.OnlyContainsUserCerts {
		return nil, fmt.Errorf("issuing distribution point requires a distribution point URL or a scope flag")
	}
	var content []byte
	if len(idp.DistributionPointURLs) > 0 {
		field, err := distributionPointField(idp.DistributionPointURLs)
		if err != nil {
			return nil, err
		}
		content = append(content, field...)
	}
	if idp.OnlyContainsUserCerts {
		// onlyContainsUserCerts [1] BOOLEAN (implicit) TRUE.
		content = append(content, 0x81, 0x01, 0xFF)
	}
	seq := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content}
	return asn1.Marshal(seq)
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
