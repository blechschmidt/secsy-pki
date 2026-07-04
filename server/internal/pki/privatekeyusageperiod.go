package pki

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"
)

// OIDPrivateKeyUsagePeriod identifies the RFC 5280 §4.2.1 (originally X.509)
// id-ce-privateKeyUsagePeriod extension ({ id-ce 16 } = 2.5.29.16). Its value is
//
//	PrivateKeyUsagePeriod ::= SEQUENCE {
//	     notBefore       [0]     GeneralizedTime OPTIONAL,
//	     notAfter        [1]     GeneralizedTime OPTIONAL }
//	     -- either notBefore or notAfter shall be present
//
// It constrains the period during which the certified private key may be used to
// *produce* signatures — a window that can be narrower than the certificate's own
// validity, so a signing key can be retired before the certificate expires while
// signatures it already made remain verifiable. RFC 5280 deprecates its use in
// the Internet PKI but it is still expected on some eIDAS / qualified signing
// certificates and legacy deployments. The extension MUST be non-critical.
var OIDPrivateKeyUsagePeriod = asn1.ObjectIdentifier{2, 5, 29, 16}

// generalizedTimeLayout is the DER GeneralizedTime profile RFC 5280 §4.1.2.5.2
// requires: a four-digit year, seconds always present, no fractional seconds, and
// the 'Z' (UTC) zone designator. The times this package emits are formatted with
// it, and the parser accepts it (the only form a conforming issuer produces).
const generalizedTimeLayout = "20060102150405Z"

// PrivateKeyUsagePeriod is the decoded content of an id-ce-privateKeyUsagePeriod
// extension. Either bound may be absent (the zero time.Time), but at least one
// must be present for a valid extension. Times are handled in UTC and to
// one-second resolution (GeneralizedTime carries no sub-second precision here).
type PrivateKeyUsagePeriod struct {
	// NotBefore is the earliest instant the private key may be used to sign. The
	// zero value omits the [0] field.
	NotBefore time.Time
	// NotAfter is the latest instant the private key may be used to sign. The zero
	// value omits the [1] field.
	NotAfter time.Time
}

// IsZero reports whether neither bound is set (the extension would encode
// nothing, which is not a valid PrivateKeyUsagePeriod).
func (p PrivateKeyUsagePeriod) IsZero() bool {
	return p.NotBefore.IsZero() && p.NotAfter.IsZero()
}

// Extension builds the complete id-ce-privateKeyUsagePeriod extension (OID
// 2.5.29.16), a non-critical SEQUENCE of the optional [0]/[1] IMPLICIT
// GeneralizedTime bounds. At least one bound is required, and when both are set
// notBefore must not fall after notAfter.
//
// crypto/x509 cannot encode this extension, so — like the smartcard/UPN otherName
// SAN and the ETSI QCStatements — it is hand-rolled and supplied via
// ExtraExtensions. The caller appends it before any Certificate-Transparency
// poison/SCT-list extension so that trailing CT extension stays last (keeping the
// precertificate and final certificate TBSCertificates aligned for SCT
// verification).
func (p PrivateKeyUsagePeriod) Extension() (pkix.Extension, error) {
	if p.IsZero() {
		return pkix.Extension{}, fmt.Errorf("privateKeyUsagePeriod: at least one of notBefore/notAfter is required")
	}
	if !p.NotBefore.IsZero() && !p.NotAfter.IsZero() && p.NotAfter.Before(p.NotBefore) {
		return pkix.Extension{}, fmt.Errorf("privateKeyUsagePeriod: notAfter (%s) precedes notBefore (%s)",
			p.NotAfter.UTC().Format(time.RFC3339), p.NotBefore.UTC().Format(time.RFC3339))
	}

	var body []byte
	// Each bound is a context-specific, IMPLICITly-tagged GeneralizedTime: the [0]
	// / [1] tag replaces the UNIVERSAL GeneralizedTime tag, so the content octets
	// are exactly the ASCII of the (UTC, second-resolution, Z-terminated) time.
	appendBound := func(tag int, t time.Time) error {
		der, err := asn1.Marshal(asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        tag,
			IsCompound: false,
			Bytes:      []byte(t.UTC().Truncate(time.Second).Format(generalizedTimeLayout)),
		})
		if err != nil {
			return fmt.Errorf("encoding privateKeyUsagePeriod bound [%d]: %w", tag, err)
		}
		body = append(body, der...)
		return nil
	}
	if !p.NotBefore.IsZero() {
		if err := appendBound(0, p.NotBefore); err != nil {
			return pkix.Extension{}, err
		}
	}
	if !p.NotAfter.IsZero() {
		if err := appendBound(1, p.NotAfter); err != nil {
			return pkix.Extension{}, err
		}
	}

	value, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      body,
	})
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("encoding privateKeyUsagePeriod: %w", err)
	}
	// RFC 5280 §4.2.1: the extension is non-critical.
	return pkix.Extension{Id: OIDPrivateKeyUsagePeriod, Critical: false, Value: value}, nil
}

// ParsePrivateKeyUsagePeriod decodes an id-ce-privateKeyUsagePeriod extension
// value back into a PrivateKeyUsagePeriod. It fully validates the structure — a
// SEQUENCE of at most one [0] and one [1] context-specific GeneralizedTime, in
// that order, at least one present, and notBefore not after notAfter — so a
// structurally malformed value yields an error, which is how the pre-issuance
// lint gate recognizes-but-rejects a corrupt extension.
func ParsePrivateKeyUsagePeriod(value []byte) (PrivateKeyUsagePeriod, error) {
	var out PrivateKeyUsagePeriod
	var seq asn1.RawValue
	rest, err := asn1.Unmarshal(value, &seq)
	if err != nil {
		return out, fmt.Errorf("decoding privateKeyUsagePeriod: %w", err)
	}
	if len(rest) != 0 {
		return out, fmt.Errorf("privateKeyUsagePeriod has %d trailing byte(s)", len(rest))
	}
	if seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence || !seq.IsCompound {
		return out, fmt.Errorf("privateKeyUsagePeriod is not a SEQUENCE")
	}

	sawNotBefore, sawNotAfter := false, false
	body := seq.Bytes
	for len(body) > 0 {
		var field asn1.RawValue
		body, err = asn1.Unmarshal(body, &field)
		if err != nil {
			return out, fmt.Errorf("decoding privateKeyUsagePeriod bound: %w", err)
		}
		if field.Class != asn1.ClassContextSpecific || field.IsCompound {
			return out, fmt.Errorf("privateKeyUsagePeriod bound has unexpected tag class")
		}
		t, terr := parseDERGeneralizedTime(field.Bytes)
		if terr != nil {
			return out, fmt.Errorf("decoding privateKeyUsagePeriod GeneralizedTime: %w", terr)
		}
		switch field.Tag {
		case 0:
			if sawNotBefore {
				return out, fmt.Errorf("privateKeyUsagePeriod has a duplicate notBefore")
			}
			if sawNotAfter {
				return out, fmt.Errorf("privateKeyUsagePeriod notBefore must precede notAfter")
			}
			out.NotBefore = t
			sawNotBefore = true
		case 1:
			if sawNotAfter {
				return out, fmt.Errorf("privateKeyUsagePeriod has a duplicate notAfter")
			}
			out.NotAfter = t
			sawNotAfter = true
		default:
			return out, fmt.Errorf("privateKeyUsagePeriod has an unexpected bound [%d]", field.Tag)
		}
	}
	if out.IsZero() {
		return out, fmt.Errorf("privateKeyUsagePeriod has neither notBefore nor notAfter")
	}
	if sawNotBefore && sawNotAfter && out.NotAfter.Before(out.NotBefore) {
		return out, fmt.Errorf("privateKeyUsagePeriod notAfter precedes notBefore")
	}
	return out, nil
}

// parseDERGeneralizedTime parses the raw content octets of an IMPLICITly-tagged
// GeneralizedTime in the strict RFC 5280 profile (YYYYMMDDHHMMSSZ). It rejects
// any other form (fractional seconds, a non-Z zone, a two-digit year) so a
// non-conforming encoding surfaces as a malformed extension.
func parseDERGeneralizedTime(raw []byte) (time.Time, error) {
	s := string(raw)
	t, err := time.Parse(generalizedTimeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q is not a conforming GeneralizedTime (want YYYYMMDDHHMMSSZ)", s)
	}
	return t.UTC(), nil
}

// PrivateKeyUsagePeriodFromCertificate returns the decoded
// id-ce-privateKeyUsagePeriod content a parsed certificate carries, reporting
// present=false when the extension is absent. A present-but-malformed extension
// yields an error.
func PrivateKeyUsagePeriodFromCertificate(cert *x509.Certificate) (p PrivateKeyUsagePeriod, present bool, err error) {
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(OIDPrivateKeyUsagePeriod) {
			continue
		}
		p, err = ParsePrivateKeyUsagePeriod(ext.Value)
		return p, true, err
	}
	return PrivateKeyUsagePeriod{}, false, nil
}
