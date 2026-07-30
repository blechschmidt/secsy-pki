package cms

// This file adds the CMS-level building blocks for CAdES (ETSI EN 319 122)
// long-term-validation material, used by the artifact-signing service to raise a
// signature to CAdES-LT:
//
//   - populating the SignedData `crls` field (RFC 5652 §5.1 / §10.2.1
//     RevocationInfoChoices) with X.509 CRLs, so generic CMS tools (openssl cms)
//     see the revocation material, and
//   - the ETSI `id-aa-ets-revocationValues` unsigned attribute (ETSI TS 101 733
//     / RFC 5126 §6.3.4), the canonical CAdES container carrying both CRLs and
//     OCSP BasicOCSPResponses so a CAdES-aware verifier can validate the chain
//     offline after the signer certificate expires.
//
// Everything here stays within encoding/asn1 and the standard library — the cms
// package deliberately does not import the pki/ca packages.

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// OIDRevocationValues (id-aa-ets-revocationValues) is the CAdES unsigned
// attribute carrying the CRLs and OCSP responses proving the signer chain was
// not revoked (ETSI TS 101 733 / RFC 5126 §6.3.4).
var OIDRevocationValues = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 24}

// oidPKIXOCSPBasic (id-pkix-ocsp-basic) types the BasicOCSPResponse inside an
// OCSPResponse (RFC 6960 §4.2.1).
var oidPKIXOCSPBasic = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}

// RevocationValuesAttribute builds the id-aa-ets-revocationValues unsigned
// attribute from DER CRLs (CertificateList) and DER OCSP responses (each a
// complete OCSPResponse, as produced by the OCSP responder). The OCSP responses
// are unwrapped to their BasicOCSPResponse, which is what RevocationValues
// carries (ETSI TS 101 733):
//
//	RevocationValues ::= SEQUENCE {
//	    crlVals      [0] SEQUENCE OF CertificateList     OPTIONAL,
//	    ocspVals     [1] SEQUENCE OF BasicOCSPResponse   OPTIONAL,
//	    otherRevVals [2] OtherRevVals                    OPTIONAL }
//
// The [0]/[1] tags are EXPLICIT, matching the reference implementations
// (BouncyCastle, ETSI DSS). At least one of crls/ocspResponses must be non-empty.
func RevocationValuesAttribute(crls [][]byte, ocspResponses [][]byte) (Attribute, error) {
	if len(crls) == 0 && len(ocspResponses) == 0 {
		return Attribute{}, errors.New("cms: revocation-values attribute requires at least one CRL or OCSP response")
	}

	var body []byte
	if len(crls) > 0 {
		seq, err := sequenceOf(crls)
		if err != nil {
			return Attribute{}, fmt.Errorf("cms: encoding revocation-values crlVals: %w", err)
		}
		tagged, err := explicitContext(0, seq)
		if err != nil {
			return Attribute{}, err
		}
		body = append(body, tagged...)
	}
	if len(ocspResponses) > 0 {
		basics := make([][]byte, 0, len(ocspResponses))
		for _, resp := range ocspResponses {
			basic, err := BasicOCSPResponse(resp)
			if err != nil {
				return Attribute{}, err
			}
			basics = append(basics, basic)
		}
		seq, err := sequenceOf(basics)
		if err != nil {
			return Attribute{}, fmt.Errorf("cms: encoding revocation-values ocspVals: %w", err)
		}
		tagged, err := explicitContext(1, seq)
		if err != nil {
			return Attribute{}, err
		}
		body = append(body, tagged...)
	}

	rvDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	if err != nil {
		return Attribute{}, fmt.Errorf("cms: encoding RevocationValues: %w", err)
	}
	return Attribute{Type: OIDRevocationValues, Value: asn1.RawValue{FullBytes: rvDER}}, nil
}

// RevocationValues is the decoded content of an id-aa-ets-revocationValues
// attribute: the raw DER of each embedded CRL (CertificateList) and each OCSP
// BasicOCSPResponse.
type RevocationValues struct {
	CRLs               [][]byte // DER CertificateList
	BasicOCSPResponses [][]byte // DER BasicOCSPResponse
}

// ParseRevocationValues decodes an id-aa-ets-revocationValues attribute value.
// The [0]/[1] members are EXPLICIT-tagged SEQUENCE OFs; unmarshaling them into
// typed slices lets encoding/asn1 unwrap the explicit tag and split the elements.
func ParseRevocationValues(der []byte) (*RevocationValues, error) {
	var rv struct {
		CRLVals  []asn1.RawValue `asn1:"explicit,tag:0,optional"`
		OCSPVals []asn1.RawValue `asn1:"explicit,tag:1,optional"`
		// otherRevVals [2] is tolerated but not consumed.
		Other asn1.RawValue `asn1:"explicit,tag:2,optional"`
	}
	if _, err := asn1.Unmarshal(der, &rv); err != nil {
		return nil, fmt.Errorf("cms: parsing RevocationValues: %w", err)
	}
	out := &RevocationValues{}
	for _, c := range rv.CRLVals {
		out.CRLs = append(out.CRLs, c.FullBytes)
	}
	for _, o := range rv.OCSPVals {
		out.BasicOCSPResponses = append(out.BasicOCSPResponses, o.FullBytes)
	}
	return out, nil
}

// BasicOCSPResponse extracts the DER BasicOCSPResponse from a complete DER
// OCSPResponse (RFC 6960 §4.2.1). It requires a successful response carrying an
// id-pkix-ocsp-basic BasicOCSPResponse.
func BasicOCSPResponse(ocspResponseDER []byte) ([]byte, error) {
	var outer struct {
		Status   asn1.Enumerated
		Response struct {
			ResponseType asn1.ObjectIdentifier
			Response     []byte
		} `asn1:"explicit,tag:0,optional"`
	}
	if _, err := asn1.Unmarshal(ocspResponseDER, &outer); err != nil {
		return nil, fmt.Errorf("cms: parsing OCSP response: %w", err)
	}
	if !outer.Response.ResponseType.Equal(oidPKIXOCSPBasic) {
		return nil, fmt.Errorf("cms: OCSP response type is %v, want id-pkix-ocsp-basic", outer.Response.ResponseType)
	}
	if len(outer.Response.Response) == 0 {
		return nil, errors.New("cms: OCSP response carries no BasicOCSPResponse")
	}
	return outer.Response.Response, nil
}

// WrapBasicOCSPResponse re-wraps a BasicOCSPResponse (as carried in a CAdES
// revocation-values attribute) into a complete, successful OCSPResponse, so a
// standard OCSP parser — which expects the outer OCSPResponse — can consume it.
func WrapBasicOCSPResponse(basic []byte) ([]byte, error) {
	type responseBytes struct {
		ResponseType asn1.ObjectIdentifier
		Response     []byte
	}
	type ocspResponse struct {
		Status   asn1.Enumerated
		Response responseBytes `asn1:"explicit,tag:0,optional"`
	}
	der, err := asn1.Marshal(ocspResponse{
		Status:   0, // successful
		Response: responseBytes{ResponseType: oidPKIXOCSPBasic, Response: basic},
	})
	if err != nil {
		return nil, fmt.Errorf("cms: wrapping BasicOCSPResponse: %w", err)
	}
	return der, nil
}

// ---- low-level DER helpers ------------------------------------------------

// sequenceOf concatenates the DER elements and wraps them in a universal
// SEQUENCE OF. SEQUENCE OF (unlike SET OF) imposes no ordering, so the input
// order is preserved.
func sequenceOf(items [][]byte) ([]byte, error) {
	var body []byte
	for _, it := range items {
		body = append(body, it...)
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
}

// explicitContext wraps a complete DER TLV in an EXPLICIT context-specific tag.
func explicitContext(tag int, inner []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner})
}

// splitSequenceOf breaks the body of a SEQUENCE OF / SET OF into the raw DER of
// each top-level element.
func splitSequenceOf(body []byte) [][]byte {
	var out [][]byte
	rest := body
	for len(rest) > 0 {
		var elem asn1.RawValue
		next, err := asn1.Unmarshal(rest, &elem)
		if err != nil {
			break
		}
		out = append(out, elem.FullBytes)
		rest = next
	}
	return out
}
