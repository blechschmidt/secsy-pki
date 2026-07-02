package pqc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/cloudflare/circl/sign"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// CreatePQCCSR builds a pure post-quantum PKCS#10 certificate signing request:
// the subject public key and the request self-signature are both ML-DSA. As with
// CreateCertificate, the CertificationRequestInfo structure (subject, requested
// SAN attributes) is produced by crypto/x509 and reused verbatim; only the
// SubjectPublicKeyInfo and the signature are ML-DSA. The returned bytes are DER.
func CreatePQCCSR(tmpl *x509.CertificateRequest, priv crypto.Signer) ([]byte, error) {
	if tmpl == nil {
		return nil, fmt.Errorf("pqc: CSR template is required")
	}
	a, ok := algorithmForPublicKey(priv.Public())
	if !ok {
		return nil, fmt.Errorf("pqc: CSR key is not an ML-DSA key (%T)", priv.Public())
	}

	// Throwaway build so crypto/x509 encodes the subject and requested-extension
	// attributes; its SPKI and signature are discarded.
	throwPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pqc: generating throwaway key: %w", err)
	}
	throwDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, throwPriv)
	if err != nil {
		return nil, fmt.Errorf("pqc: building CSR skeleton: %w", err)
	}

	criFields, err := criFields(throwDER)
	if err != nil {
		return nil, err
	}
	if len(criFields) != 4 {
		return nil, fmt.Errorf("pqc: unexpected CertificationRequestInfo shape (%d fields)", len(criFields))
	}

	spkiDER, err := MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}
	sigAlgDER, err := algorithmIdentifierDER(a.keyType)
	if err != nil {
		return nil, err
	}

	// CertificationRequestInfo: version, subject, subjectPKInfo, attributes[0].
	var cb cryptobyte.Builder
	cb.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(criFields[0]) // version
		b.AddBytes(criFields[1]) // subject
		b.AddBytes(spkiDER)      // subjectPKInfo
		b.AddBytes(criFields[3]) // attributes [0]
	})
	cri, err := cb.Bytes()
	if err != nil {
		return nil, fmt.Errorf("pqc: encoding CertificationRequestInfo: %w", err)
	}

	sig, err := priv.Sign(rand.Reader, cri, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("pqc: signing CSR: %w", err)
	}
	return assembleSigned(cri, sigAlgDER, sig)
}

// PQCCSR is a parsed and verified pure-PQC certificate signing request.
type PQCCSR struct {
	Subject   pkix.Name
	PublicKey crypto.PublicKey
	KeyType   string
	Raw       []byte
	// Parsed is the standard-library view of the request, for its Subject and
	// SAN fields. Its PublicKey is nil (ML-DSA is unknown to crypto/x509).
	Parsed *x509.CertificateRequest
}

// ParsePQCCSR parses a DER PKCS#10 request whose subject key is ML-DSA and
// verifies its self-signature. It returns an error (reporting
// IsUnsupportedAlgorithm) when the request's key is not ML-DSA, so callers can
// fall back to x509.ParseCertificateRequest.
func ParsePQCCSR(der []byte) (*PQCCSR, error) {
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("pqc: parsing CSR structure: %w", err)
	}
	pub, keyType, err := ParsePKIXPublicKey(parsed.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, err // propagates IsUnsupportedAlgorithm for classical CSRs
	}

	// Verify the self-signature: CertificationRequestInfo (first element) signed
	// by the subject key.
	cri, sigOID, sig, err := csrParts(der)
	if err != nil {
		return nil, err
	}
	a, ok := algorithmByOID(sigOID)
	if !ok {
		return nil, fmt.Errorf("pqc: CSR is not ML-DSA signed (%v)", sigOID)
	}
	if a.keyType != keyType {
		return nil, fmt.Errorf("pqc: CSR signature algorithm %s does not match key type %s", a.keyType, keyType)
	}
	if !a.scheme.Verify(pub.(sign.PublicKey), cri, sig, nil) {
		return nil, fmt.Errorf("pqc: CSR self-signature verification failed")
	}

	return &PQCCSR{
		Subject:   parsed.Subject,
		PublicKey: pub,
		KeyType:   keyType,
		Raw:       der,
		Parsed:    parsed,
	}, nil
}

// CreateHybridCSR builds a classical PKCS#10 request that also carries an ML-DSA
// alternative public key (subjectAltPublicKeyInfo) and an alternative
// self-signature (altSignatureAlgorithm/altSignatureValue) over the request,
// mirroring the hybrid certificate design. classicalPriv proves possession of the
// primary key; altPriv proves possession of the ML-DSA key.
func CreateHybridCSR(tmpl *x509.CertificateRequest, classicalPriv, altPriv crypto.Signer) ([]byte, error) {
	if tmpl == nil {
		return nil, fmt.Errorf("pqc: CSR template is required")
	}
	altAlg, ok := algorithmForPublicKey(altPriv.Public())
	if !ok {
		return nil, fmt.Errorf("pqc: alternative CSR key is not ML-DSA (%T)", altPriv.Public())
	}
	preExts, err := hybridPreExtensions(altPriv.Public(), altAlg.keyType)
	if err != nil {
		return nil, err
	}

	// Pass A: classical CSR with the two pre-extensions as requested extensions.
	tmplA := *tmpl
	tmplA.ExtraExtensions = appendExts(tmpl.ExtraExtensions, preExts...)
	csrA, err := x509.CreateCertificateRequest(rand.Reader, &tmplA, classicalPriv)
	if err != nil {
		return nil, fmt.Errorf("pqc: building hybrid CSR pre-image: %w", err)
	}
	preCRI, err := csrCRI(csrA)
	if err != nil {
		return nil, err
	}
	altSig, err := altPriv.Sign(rand.Reader, preCRI, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("pqc: producing alternative CSR signature: %w", err)
	}
	altSigDER, err := asn1.Marshal(asn1.BitString{Bytes: altSig, BitLength: len(altSig) * 8})
	if err != nil {
		return nil, err
	}

	// Pass B: same CSR with altSignatureValue appended last.
	tmplB := *tmpl
	tmplB.ExtraExtensions = appendExts(tmpl.ExtraExtensions, append(preExts,
		pkix.Extension{Id: oidAltSignatureValue, Critical: false, Value: altSigDER})...)
	csrB, err := x509.CreateCertificateRequest(rand.Reader, &tmplB, classicalPriv)
	if err != nil {
		return nil, fmt.Errorf("pqc: building hybrid CSR: %w", err)
	}
	return csrB, nil
}

// HybridCSR is a parsed hybrid CSR with both proofs of possession verified.
type HybridCSR struct {
	Parsed     *x509.CertificateRequest
	PrimaryKey crypto.PublicKey
	AltKey     crypto.PublicKey
	AltKeyType string
	Raw        []byte
}

// ParseHybridCSR parses a hybrid CSR, verifying the classical self-signature and
// the alternative ML-DSA self-signature (proof of possession of both keys).
func ParseHybridCSR(der []byte) (*HybridCSR, error) {
	parsed, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("pqc: parsing hybrid CSR: %w", err)
	}
	if err := parsed.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pqc: classical CSR signature verification failed: %w", err)
	}

	var sapki, altSig pkix.Extension
	var haveSAPKI, haveAltSig bool
	for _, e := range parsed.Extensions {
		switch {
		case e.Id.Equal(oidSubjectAltPublicKeyInfo):
			sapki, haveSAPKI = e, true
		case e.Id.Equal(oidAltSignatureValue):
			altSig, haveAltSig = e, true
		}
	}
	if !haveSAPKI || !haveAltSig {
		return nil, fmt.Errorf("pqc: CSR is not hybrid (missing alternative-key/signature extensions)")
	}
	altPub, altKeyType, err := ParsePKIXPublicKey(sapki.Value)
	if err != nil {
		return nil, err
	}
	var altSigBits asn1.BitString
	if _, err := asn1.Unmarshal(altSig.Value, &altSigBits); err != nil {
		return nil, fmt.Errorf("pqc: decoding CSR altSignatureValue: %w", err)
	}

	preimage, lastOID, err := stripLastExtensionCRI(der)
	if err != nil {
		return nil, err
	}
	if !lastOID.Equal(oidAltSignatureValue) {
		return nil, fmt.Errorf("pqc: CSR altSignatureValue is not the final requested extension")
	}
	a, ok := algorithmByKeyType(altKeyType)
	if !ok {
		return nil, fmt.Errorf("pqc: unsupported CSR alternative key type %s", altKeyType)
	}
	if !a.scheme.Verify(altPub.(sign.PublicKey), preimage, altSigBits.RightAlign(), nil) {
		return nil, fmt.Errorf("pqc: CSR alternative (ML-DSA) signature verification failed")
	}

	return &HybridCSR{
		Parsed:     parsed,
		PrimaryKey: parsed.PublicKey,
		AltKey:     altPub,
		AltKeyType: altKeyType,
		Raw:        der,
	}, nil
}

// criFields extracts the raw DER of each CertificationRequestInfo field from a
// DER CSR.
func criFields(csrDER []byte) ([][]byte, error) {
	cri, err := csrCRI(csrDER)
	if err != nil {
		return nil, err
	}
	return sequenceFields(cri)
}

// csrCRI returns the raw CertificationRequestInfo DER (the first element) of a
// DER CSR.
func csrCRI(csrDER []byte) ([]byte, error) {
	outer := cryptobyte.String(csrDER)
	var csr cryptobyte.String
	if !outer.ReadASN1(&csr, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("pqc: malformed CSR")
	}
	return readElement(&csr)
}

// csrParts returns the CertificationRequestInfo DER, the signatureAlgorithm OID,
// and the signature bytes of a DER CSR.
func csrParts(csrDER []byte) ([]byte, asn1.ObjectIdentifier, []byte, error) {
	outer := cryptobyte.String(csrDER)
	var csr cryptobyte.String
	if !outer.ReadASN1(&csr, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, nil, fmt.Errorf("pqc: malformed CSR")
	}
	cri, err := readElement(&csr)
	if err != nil {
		return nil, nil, nil, err
	}
	var algSeq cryptobyte.String
	if !csr.ReadASN1(&algSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, nil, fmt.Errorf("pqc: malformed CSR signatureAlgorithm")
	}
	var oid asn1.ObjectIdentifier
	if !algSeq.ReadASN1ObjectIdentifier(&oid) {
		return nil, nil, nil, fmt.Errorf("pqc: malformed CSR signatureAlgorithm OID")
	}
	var sig []byte
	if !csr.ReadASN1BitStringAsBytes(&sig) {
		return nil, nil, nil, fmt.Errorf("pqc: malformed CSR signature")
	}
	return cri, oid, sig, nil
}

// stripLastExtensionCRI reconstructs the CertificationRequestInfo with the final
// requested extension removed, for hybrid CSR alt-signature verification. The
// requested extensions live inside the attributes ([0]) field as an
// extensionRequest attribute; this removes the last Extension from that inner
// SEQUENCE and returns the rebuilt CRI plus the removed OID.
func stripLastExtensionCRI(csrDER []byte) ([]byte, asn1.ObjectIdentifier, error) {
	fields, err := criFields(csrDER)
	if err != nil {
		return nil, nil, err
	}
	if len(fields) != 4 {
		return nil, nil, fmt.Errorf("pqc: unexpected CertificationRequestInfo shape (%d fields)", len(fields))
	}
	newAttrs, lastOID, err := stripLastRequestedExtension(fields[3])
	if err != nil {
		return nil, nil, err
	}
	var cb cryptobyte.Builder
	cb.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(fields[0])
		b.AddBytes(fields[1])
		b.AddBytes(fields[2])
		b.AddBytes(newAttrs)
	})
	cri, err := cb.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return cri, lastOID, nil
}

// stripLastRequestedExtension takes the attributes ([0]) field of a CSR and
// rebuilds it with the last requested extension (inside the pkcs-9
// extensionRequest attribute) removed. It returns the rebuilt [0] field and the
// removed extension's OID.
func stripLastRequestedExtension(attrsField []byte) ([]byte, asn1.ObjectIdentifier, error) {
	// attributes ::= [0] IMPLICIT SET OF Attribute
	s := cryptobyte.String(attrsField)
	var set cryptobyte.String
	if !s.ReadASN1(&set, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return nil, nil, fmt.Errorf("pqc: malformed CSR attributes")
	}

	var lastOID asn1.ObjectIdentifier
	// Rebuild the SET OF Attribute, transforming only the extensionRequest one.
	var outer cryptobyte.Builder
	outer.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
		for !set.Empty() {
			attr, err := readElement(&set)
			if err != nil {
				b.SetError(err)
				return
			}
			rebuilt, oid, isExtReq, err := maybeStripExtReq(attr)
			if err != nil {
				b.SetError(err)
				return
			}
			if isExtReq {
				lastOID = oid
			}
			b.AddBytes(rebuilt)
		}
	})
	out, err := outer.Bytes()
	if err != nil {
		return nil, nil, err
	}
	if lastOID == nil {
		return nil, nil, fmt.Errorf("pqc: CSR has no extensionRequest attribute")
	}
	return out, lastOID, nil
}

// oidExtensionRequest is the PKCS#9 extensionRequest attribute type.
var oidExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

// maybeStripExtReq inspects one CSR Attribute. If it is the extensionRequest
// attribute, it returns the attribute rebuilt with the last requested extension
// removed, that extension's OID, and true. Otherwise it returns the attribute
// verbatim and false.
func maybeStripExtReq(attrDER []byte) ([]byte, asn1.ObjectIdentifier, bool, error) {
	// Attribute ::= SEQUENCE { type OID, values SET OF ANY }
	s := cryptobyte.String(attrDER)
	var attr cryptobyte.String
	if !s.ReadASN1(&attr, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, false, fmt.Errorf("pqc: malformed CSR attribute")
	}
	var typ asn1.ObjectIdentifier
	if !attr.ReadASN1ObjectIdentifier(&typ) {
		return nil, nil, false, fmt.Errorf("pqc: malformed CSR attribute type")
	}
	if !typ.Equal(oidExtensionRequest) {
		return attrDER, nil, false, nil
	}
	var valueSet cryptobyte.String
	if !attr.ReadASN1(&valueSet, cryptobyte_asn1.SET) {
		return nil, nil, false, fmt.Errorf("pqc: malformed extensionRequest values")
	}
	var extSeq cryptobyte.String
	if !valueSet.ReadASN1(&extSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, false, fmt.Errorf("pqc: malformed extensionRequest SEQUENCE")
	}
	var elems [][]byte
	for !extSeq.Empty() {
		e, err := readElement(&extSeq)
		if err != nil {
			return nil, nil, false, err
		}
		elems = append(elems, e)
	}
	if len(elems) == 0 {
		return nil, nil, false, fmt.Errorf("pqc: empty extensionRequest")
	}
	last := elems[len(elems)-1]
	oid, err := extensionOID(last)
	if err != nil {
		return nil, nil, false, err
	}
	kept := elems[:len(elems)-1]

	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidExtensionRequest)
		b.AddASN1(cryptobyte_asn1.SET, func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				for _, e := range kept {
					b.AddBytes(e)
				}
			})
		})
	})
	rebuilt, err := b.Bytes()
	if err != nil {
		return nil, nil, false, err
	}
	return rebuilt, oid, true, nil
}
