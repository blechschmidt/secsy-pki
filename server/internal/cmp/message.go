// Package cmp implements a Lightweight CMP (RFC 9483, profiling RFC 4210/4211)
// server endpoint on top of the HSM-backed ca.Manager issuance layer. It handles
// the core PKIMessage flows — initialization request (ir), certification request
// (cr), key update request (kur), and revocation request (rr) — with message
// protection by either a shared secret (Password-Based MAC, RFC 4210 §5.1.3.1)
// or a signature from a certificate this CA previously issued.
//
// The CA signing key never leaves its provider: leaf certificates and
// signature-protected responses are produced through crypto.Signer instances
// opened on the key provider (an HSM via PKCS#11, or the software keystore).
package cmp

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"
)

// PKIMessage body tag numbers (RFC 4210 §5.1.2). Only the flows this endpoint
// implements are enumerated.
const (
	bodyIR    = 0  // initialization request
	bodyIP    = 1  // initialization response
	bodyCR    = 2  // certification request
	bodyCP    = 3  // certification response
	bodyKUR   = 7  // key update request
	bodyKUP   = 8  // key update response
	bodyRR    = 11 // revocation request
	bodyRP    = 12 // revocation response
	bodyError = 23 // error message
)

// PKIStatus values (RFC 4210 §5.2.3).
const (
	statusAccepted        = 0
	statusGrantedWithMods = 1
	statusRejection       = 2
)

// PKIFailureInfo bit positions (RFC 4210 Appendix F) used in error responses.
const (
	failBadAlg           = 0
	failBadMessageCheck  = 1
	failBadRequest       = 2
	failSignerNotTrusted = 18
	failNotAuthorized    = 23
	failSystemUnavail    = 24
	failSystemFailure    = 25
)

// pvnoCMP2000 is the protocol version used by the Lightweight CMP profile.
const pvnoCMP2000 = 2

// rawPKIMessage is the on-the-wire PKIMessage decoded positionally. The header
// and body are captured as raw values so the protected part (SEQUENCE { header,
// body }) can be reconstructed byte-for-byte for MAC/signature verification.
type rawPKIMessage struct {
	Header     asn1.RawValue
	Body       asn1.RawValue
	Protection asn1.BitString `asn1:"optional,explicit,tag:0"`
	ExtraCerts asn1.RawValue  `asn1:"optional,explicit,tag:1"`
}

// pkiHeader is the PKIHeader (RFC 4210 §5.1.1). The module uses EXPLICIT tags,
// so every context-tagged optional wraps its universal type.
type pkiHeader struct {
	Pvno          int
	Sender        asn1.RawValue
	Recipient     asn1.RawValue
	MessageTime   asn1.RawValue            `asn1:"optional,explicit,tag:0"`
	ProtectionAlg pkix.AlgorithmIdentifier `asn1:"optional,explicit,tag:1"`
	SenderKID     []byte                   `asn1:"optional,explicit,tag:2"`
	RecipKID      asn1.RawValue            `asn1:"optional,explicit,tag:3"`
	TransactionID []byte                   `asn1:"optional,explicit,tag:4"`
	SenderNonce   []byte                   `asn1:"optional,explicit,tag:5"`
	RecipNonce    []byte                   `asn1:"optional,explicit,tag:6"`
	FreeText      asn1.RawValue            `asn1:"optional,explicit,tag:7"`
	GeneralInfo   asn1.RawValue            `asn1:"optional,explicit,tag:8"`
}

// infoTypeAndValue is a generalInfo entry (RFC 4210 §5.3.19).
type infoTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue `asn1:"optional"`
}

// message is a parsed PKIMessage with the pieces the flows need.
type message struct {
	header           pkiHeader
	bodyTag          int
	bodyContent      []byte // DER of the body's inner value (the explicit wrapper stripped)
	protectedPartDER []byte // DER of SEQUENCE { header, body } for protection checks
	protection       []byte // raw protection bits (MAC output or signature)
	extraCerts       []*x509.Certificate
}

// parseMessage decodes a PKIMessage and reconstructs its protected part.
func parseMessage(der []byte) (*message, error) {
	var raw rawPKIMessage
	rest, err := asn1.Unmarshal(der, &raw)
	if err != nil {
		return nil, fmt.Errorf("decoding PKIMessage: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after PKIMessage")
	}

	var hdr pkiHeader
	if _, err := asn1.Unmarshal(raw.Header.FullBytes, &hdr); err != nil {
		return nil, fmt.Errorf("decoding PKIHeader: %w", err)
	}
	if raw.Body.Class != asn1.ClassContextSpecific {
		return nil, fmt.Errorf("PKIBody is not a context-tagged CHOICE")
	}

	// The protected part is the DER of SEQUENCE { header, body }, using the exact
	// bytes as received (RFC 4210 §5.1.3).
	pp := wrapSequence(concat(raw.Header.FullBytes, raw.Body.FullBytes))

	certs, err := parseExtraCerts(raw.ExtraCerts)
	if err != nil {
		return nil, err
	}

	return &message{
		header:           hdr,
		bodyTag:          raw.Body.Tag,
		bodyContent:      raw.Body.Bytes,
		protectedPartDER: pp,
		protection:       raw.Protection.RightAlign(),
		extraCerts:       certs,
	}, nil
}

// parseExtraCerts decodes the optional extraCerts field ([1] SEQUENCE OF
// CMPCertificate). CMPCertificate is a CHOICE whose sole alternative is a plain
// X.509 Certificate, so each element is parsed directly.
func parseExtraCerts(field asn1.RawValue) ([]*x509.Certificate, error) {
	if len(field.Bytes) == 0 {
		return nil, nil
	}
	elems, err := seqElements(field.Bytes)
	if err != nil {
		return nil, fmt.Errorf("decoding extraCerts: %w", err)
	}
	certs := make([]*x509.Certificate, 0, len(elems))
	for _, el := range elems {
		cert, err := x509.ParseCertificate(el.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing extraCert: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// ---- header construction --------------------------------------------------

// headerFields carries the values placed into a response PKIHeader.
type headerFields struct {
	Pvno            int
	Sender          asn1.RawValue // a GeneralName ([n] ...) full TLV
	Recipient       asn1.RawValue
	MessageTime     time.Time
	ProtectionAlg   *pkix.AlgorithmIdentifier
	SenderKID       []byte
	TransactionID   []byte
	SenderNonce     []byte
	RecipNonce      []byte
	ImplicitConfirm bool
}

// buildHeaderDER encodes a PKIHeader. Fields are emitted in ascending tag order
// so the result is valid DER; absent optionals are simply skipped.
func buildHeaderDER(f headerFields) ([]byte, error) {
	pvno := f.Pvno
	if pvno == 0 {
		pvno = pvnoCMP2000
	}
	pvnoDER, err := asn1.Marshal(pvno)
	if err != nil {
		return nil, err
	}
	parts := [][]byte{pvnoDER, f.Sender.FullBytes, f.Recipient.FullBytes}

	if !f.MessageTime.IsZero() {
		parts = append(parts, explicitTLV(0, marshalGeneralizedTime(f.MessageTime)))
	}
	if f.ProtectionAlg != nil {
		algDER, err := asn1.Marshal(*f.ProtectionAlg)
		if err != nil {
			return nil, err
		}
		parts = append(parts, explicitTLV(1, algDER))
	}
	if len(f.SenderKID) > 0 {
		kidDER, err := asn1.Marshal(f.SenderKID)
		if err != nil {
			return nil, err
		}
		parts = append(parts, explicitTLV(2, kidDER))
	}
	if len(f.TransactionID) > 0 {
		txDER, err := asn1.Marshal(f.TransactionID)
		if err != nil {
			return nil, err
		}
		parts = append(parts, explicitTLV(4, txDER))
	}
	if len(f.SenderNonce) > 0 {
		snDER, err := asn1.Marshal(f.SenderNonce)
		if err != nil {
			return nil, err
		}
		parts = append(parts, explicitTLV(5, snDER))
	}
	if len(f.RecipNonce) > 0 {
		rnDER, err := asn1.Marshal(f.RecipNonce)
		if err != nil {
			return nil, err
		}
		parts = append(parts, explicitTLV(6, rnDER))
	}
	if f.ImplicitConfirm {
		itav := infoTypeAndValue{Type: oidImplicitConfirm, Value: asn1.RawValue{FullBytes: []byte{0x05, 0x00}}}
		seq, err := asn1.Marshal([]infoTypeAndValue{itav})
		if err != nil {
			return nil, err
		}
		parts = append(parts, explicitTLV(8, seq))
	}
	return wrapSequence(concat(parts...)), nil
}

// ---- ASN.1 low-level helpers ----------------------------------------------

// explicitTLV wraps inner in a context-specific, constructed [tag] element.
func explicitTLV(tag int, inner []byte) []byte {
	rv := asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner}
	out, err := asn1.Marshal(rv)
	if err != nil { // asn1.Marshal of a RawValue with explicit bytes cannot fail
		panic(err)
	}
	return out
}

// wrapSequence wraps inner content in a universal SEQUENCE.
func wrapSequence(inner []byte) []byte {
	rv := asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: inner}
	out, err := asn1.Marshal(rv)
	if err != nil {
		panic(err)
	}
	return out
}

// concat joins byte slices into a fresh slice.
func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// seqElements decodes a single SEQUENCE (or SEQUENCE OF) TLV and returns its
// member elements. Use it when handed a whole SEQUENCE TLV — e.g. the inner
// value carried by an EXPLICIT context tag — rather than a SEQUENCE's content.
func seqElements(fullSeqTLV []byte) ([]asn1.RawValue, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(fullSeqTLV, &seq); err != nil {
		return nil, err
	}
	return walkSequence(seq.Bytes)
}

// walkSequence returns the top-level TLV elements inside a SEQUENCE body.
func walkSequence(seqContent []byte) ([]asn1.RawValue, error) {
	var out []asn1.RawValue
	rest := seqContent
	for len(rest) > 0 {
		var rv asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &rv)
		if err != nil {
			return nil, err
		}
		out = append(out, rv)
	}
	return out, nil
}

// marshalGeneralizedTime encodes a time as an ASN.1 GeneralizedTime TLV in UTC.
// CMP requires GeneralizedTime (not UTCTime) for messageTime.
func marshalGeneralizedTime(t time.Time) []byte {
	s := t.UTC().Format("20060102150405Z")
	return append([]byte{0x18, byte(len(s))}, []byte(s)...)
}

// generalNameDirectory builds a GeneralName of the directoryName ([4]) form from
// a distinguished name. Name is a CHOICE, so the [4] tag is explicit.
func generalNameDirectory(name pkix.Name) asn1.RawValue {
	rdn := name.ToRDNSequence()
	der, err := asn1.Marshal(rdn)
	if err != nil {
		panic(err)
	}
	return asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        4,
		IsCompound: true,
		Bytes:      der,
		FullBytes:  explicitTLV(4, der),
	}
}
