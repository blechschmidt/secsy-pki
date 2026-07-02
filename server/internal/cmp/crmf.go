package cmp

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
)

// oidSubjectAltName is the X.509 subjectAltName extension.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// certRequest is a parsed CRMF CertRequest (RFC 4211 §5) with the fields the
// issuance flows consume.
type certRequest struct {
	certReqID   int
	rawCertReq  []byte // DER of the whole CertRequest, for POP verification
	subject     pkix.Name
	publicKey   crypto.PublicKey
	serial      *big.Int
	issuer      pkix.Name
	hasIssuer   bool
	dnsNames    []string
	ipAddresses []net.IP
	emails      []string
	uris        []string
}

// certReqMsg is a parsed CertReqMsg: its CertRequest plus an optional signature
// proof of possession over that request.
type certReqMsg struct {
	req    certRequest
	popSig *popSignature
}

// popSignature is a signature-form ProofOfPossession (RFC 4211 §4.1): a
// signature (with an algorithm identifier) computed over the DER of the
// CertRequest, proving the requester controls the requested private key.
type popSignature struct {
	alg pkix.AlgorithmIdentifier
	sig []byte
}

// parseCertReqMessages decodes the CertReqMessages carried by an ir/cr/kur body.
func parseCertReqMessages(bodyContent []byte) ([]certReqMsg, error) {
	elems, err := seqElements(bodyContent)
	if err != nil {
		return nil, fmt.Errorf("decoding CertReqMessages: %w", err)
	}
	if len(elems) == 0 {
		return nil, fmt.Errorf("no CertReqMsg in request")
	}
	out := make([]certReqMsg, 0, len(elems))
	for _, el := range elems {
		msg, err := parseCertReqMsg(el.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, msg)
	}
	return out, nil
}

// parseCertReqMsg decodes one CertReqMsg (RFC 4211 §3): the CertRequest, an
// optional ProofOfPossession, and optional regInfo (ignored).
func parseCertReqMsg(content []byte) (certReqMsg, error) {
	fields, err := walkSequence(content)
	if err != nil {
		return certReqMsg{}, fmt.Errorf("decoding CertReqMsg: %w", err)
	}
	if len(fields) == 0 {
		return certReqMsg{}, fmt.Errorf("empty CertReqMsg")
	}
	req, err := parseCertRequest(fields[0].FullBytes)
	if err != nil {
		return certReqMsg{}, err
	}
	msg := certReqMsg{req: req}
	// The optional ProofOfPossession is the next context-tagged field. Only the
	// signature form ([1]) is verified; raVerified/keyEncipherment forms are
	// accepted by presence but not cryptographically checked here.
	for _, f := range fields[1:] {
		if f.Class == asn1.ClassContextSpecific && f.Tag == 1 {
			pop, err := parsePOPSignature(f.Bytes)
			if err != nil {
				return certReqMsg{}, err
			}
			msg.popSig = pop
		}
	}
	return msg, nil
}

// parseCertRequest decodes a CRMF CertRequest and its CertTemplate.
func parseCertRequest(fullDER []byte) (certRequest, error) {
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(fullDER, &raw); err != nil {
		return certRequest{}, fmt.Errorf("decoding CertRequest: %w", err)
	}
	fields, err := walkSequence(raw.Bytes)
	if err != nil {
		return certRequest{}, fmt.Errorf("decoding CertRequest fields: %w", err)
	}
	if len(fields) < 2 {
		return certRequest{}, fmt.Errorf("CertRequest missing certReqId or certTemplate")
	}
	req := certRequest{rawCertReq: append([]byte(nil), fullDER...)}
	if _, err := asn1.Unmarshal(fields[0].FullBytes, &req.certReqID); err != nil {
		return certRequest{}, fmt.Errorf("decoding certReqId: %w", err)
	}
	if err := parseCertTemplate(fields[1].Bytes, &req); err != nil {
		return certRequest{}, err
	}
	return req, nil
}

// parseCertTemplate walks a CRMF CertTemplate (RFC 4211 §5) and fills the
// requested subject, public key, serial, issuer, and SANs. The CRMF module uses
// IMPLICIT tags, except that the Name CHOICE fields (issuer/subject) are
// effectively EXPLICIT.
func parseCertTemplate(templateContent []byte, req *certRequest) error {
	elems, err := walkSequence(templateContent)
	if err != nil {
		return fmt.Errorf("decoding CertTemplate: %w", err)
	}
	for _, el := range elems {
		if el.Class != asn1.ClassContextSpecific {
			continue
		}
		switch el.Tag {
		case 1: // serialNumber, IMPLICIT INTEGER
			// Certificate serials are positive; interpret the (implicit-tagged)
			// INTEGER content as an unsigned big-endian magnitude, which matches the
			// value regardless of any DER sign-padding byte.
			req.serial = new(big.Int).SetBytes(el.Bytes)
		case 3: // issuer, Name (EXPLICIT)
			name, err := parseName(el.Bytes)
			if err != nil {
				return fmt.Errorf("decoding template issuer: %w", err)
			}
			req.issuer = name
			req.hasIssuer = true
		case 5: // subject, Name (EXPLICIT)
			name, err := parseName(el.Bytes)
			if err != nil {
				return fmt.Errorf("decoding template subject: %w", err)
			}
			req.subject = name
		case 6: // publicKey, IMPLICIT SubjectPublicKeyInfo
			spkiDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: el.Bytes})
			if err != nil {
				return err
			}
			pub, err := x509.ParsePKIXPublicKey(spkiDER)
			if err != nil {
				return fmt.Errorf("decoding template public key: %w", err)
			}
			req.publicKey = pub
		case 9: // extensions, IMPLICIT Extensions
			if err := parseTemplateExtensions(el.Bytes, req); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseName decodes an RDNSequence DER into a pkix.Name.
func parseName(der []byte) (pkix.Name, error) {
	var rdn pkix.RDNSequence
	if _, err := asn1.Unmarshal(der, &rdn); err != nil {
		return pkix.Name{}, err
	}
	var name pkix.Name
	name.FillFromRDNSequence(&rdn)
	return name, nil
}

// extension is an X.509 Extension (RFC 5280 §4.1).
type extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    []byte
}

// parseTemplateExtensions extracts SANs from the template extensions.
func parseTemplateExtensions(extsContent []byte, req *certRequest) error {
	elems, err := walkSequence(extsContent)
	if err != nil {
		return fmt.Errorf("decoding template extensions: %w", err)
	}
	for _, el := range elems {
		var ext extension
		if _, err := asn1.Unmarshal(el.FullBytes, &ext); err != nil {
			return fmt.Errorf("decoding extension: %w", err)
		}
		if ext.ID.Equal(oidSubjectAltName) {
			dns, ips, emails, uris, err := parseSAN(ext.Value)
			if err != nil {
				return err
			}
			req.dnsNames = dns
			req.ipAddresses = ips
			req.emails = emails
			req.uris = uris
		}
	}
	return nil
}

// parseSAN decodes a subjectAltName extension value (GeneralNames) into the SAN
// component slices.
func parseSAN(extnValue []byte) (dns []string, ips []net.IP, emails, uris []string, err error) {
	var seq asn1.RawValue
	if _, err = asn1.Unmarshal(extnValue, &seq); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("decoding subjectAltName: %w", err)
	}
	names, err := walkSequence(seq.Bytes)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, gn := range names {
		if gn.Class != asn1.ClassContextSpecific {
			continue
		}
		switch gn.Tag {
		case 1: // rfc822Name
			emails = append(emails, string(gn.Bytes))
		case 2: // dNSName
			dns = append(dns, string(gn.Bytes))
		case 6: // uniformResourceIdentifier
			uris = append(uris, string(gn.Bytes))
		case 7: // iPAddress
			ips = append(ips, net.IP(append([]byte(nil), gn.Bytes...)))
		}
	}
	return dns, ips, emails, uris, nil
}

// parsePOPSignature decodes a POPOSigningKey body (the IMPLICIT [1] content of a
// ProofOfPossession): an optional poposkInput, an algorithm identifier, and the
// signature BIT STRING.
func parsePOPSignature(poskContent []byte) (*popSignature, error) {
	elems, err := walkSequence(poskContent)
	if err != nil {
		return nil, fmt.Errorf("decoding POPOSigningKey: %w", err)
	}
	// Skip an optional poposkInput ([0]); the remaining fields are the algorithm
	// identifier (SEQUENCE) and the signature (BIT STRING).
	var algDER, sigDER []byte
	for _, el := range elems {
		if el.Class == asn1.ClassContextSpecific && el.Tag == 0 {
			continue // poposkInput: not supported, signature is over certReq
		}
		if el.Class == asn1.ClassUniversal && el.Tag == asn1.TagSequence && algDER == nil {
			algDER = el.FullBytes
			continue
		}
		if el.Class == asn1.ClassUniversal && el.Tag == asn1.TagBitString {
			sigDER = el.FullBytes
		}
	}
	if algDER == nil || sigDER == nil {
		return nil, fmt.Errorf("POPOSigningKey missing algorithm or signature")
	}
	var alg pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(algDER, &alg); err != nil {
		return nil, fmt.Errorf("decoding POP algorithm: %w", err)
	}
	var sig asn1.BitString
	if _, err := asn1.Unmarshal(sigDER, &sig); err != nil {
		return nil, fmt.Errorf("decoding POP signature: %w", err)
	}
	return &popSignature{alg: alg, sig: sig.RightAlign()}, nil
}

// ---- request construction (client side) -----------------------------------

// templateParams describes a CertTemplate to build for an ir/cr/kur request.
type templateParams struct {
	subject   pkix.Name
	publicKey crypto.PublicKey
	dnsNames  []string
	ips       []net.IP
	emails    []string
	uris      []string
}

// buildCertTemplate encodes a CRMF CertTemplate with subject, public key, and
// (when present) a subjectAltName extension.
func buildCertTemplate(p templateParams) ([]byte, error) {
	var parts [][]byte

	if len(p.subject.ToRDNSequence()) > 0 || p.subject.CommonName != "" {
		rdnDER, err := asn1.Marshal(p.subject.ToRDNSequence())
		if err != nil {
			return nil, err
		}
		parts = append(parts, explicitTLV(5, rdnDER))
	}

	spkiDER, err := x509.MarshalPKIXPublicKey(p.publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling template public key: %w", err)
	}
	var spki asn1.RawValue
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return nil, err
	}
	parts = append(parts, explicitTLV(6, spki.Bytes)) // IMPLICIT [6]

	if len(p.dnsNames)+len(p.ips)+len(p.emails)+len(p.uris) > 0 {
		extDER, err := buildSANExtensions(p.dnsNames, p.ips, p.emails, p.uris)
		if err != nil {
			return nil, err
		}
		parts = append(parts, explicitTLV(9, extDER)) // IMPLICIT [9] Extensions
	}
	return wrapSequence(concat(parts...)), nil
}

// buildRevTemplate encodes a CertTemplate that identifies a certificate to
// revoke by issuer and serial number (RFC 4211 CertTemplate; RFC 4210 rr).
func buildRevTemplate(issuer pkix.Name, serial *big.Int) ([]byte, error) {
	serialDER, err := asn1.Marshal(serial)
	if err != nil {
		return nil, err
	}
	var iv asn1.RawValue
	if _, err := asn1.Unmarshal(serialDER, &iv); err != nil {
		return nil, err
	}
	serialField, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: iv.Bytes})
	if err != nil {
		return nil, err
	}
	rdnDER, err := asn1.Marshal(issuer.ToRDNSequence())
	if err != nil {
		return nil, err
	}
	issuerField := explicitTLV(3, rdnDER)
	return wrapSequence(concat(serialField, issuerField)), nil
}

// buildSANExtensions encodes a single-extension Extensions SEQUENCE carrying a
// subjectAltName built from the supplied SAN components.
func buildSANExtensions(dns []string, ips []net.IP, emails, uris []string) ([]byte, error) {
	var gns [][]byte
	appendGN := func(tag int, content []byte) {
		gn, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, Bytes: content})
		if err != nil {
			panic(err)
		}
		gns = append(gns, gn)
	}
	for _, d := range dns {
		appendGN(2, []byte(d))
	}
	for _, e := range emails {
		appendGN(1, []byte(e))
	}
	for _, u := range uris {
		appendGN(6, []byte(u))
	}
	for _, ip := range ips {
		b := ip
		if v4 := ip.To4(); v4 != nil {
			b = v4
		}
		appendGN(7, b)
	}
	gnSeq := wrapSequence(concat(gns...))
	// extension.Value is a []byte, which asn1 encodes as the extnValue OCTET
	// STRING wrapping the GeneralNames SEQUENCE.
	ext := extension{ID: oidSubjectAltName, Value: gnSeq}
	extDER, err := asn1.Marshal(ext)
	if err != nil {
		return nil, err
	}
	return extDER, nil
}
