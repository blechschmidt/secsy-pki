package pqc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// CreateCertificate builds and signs a pure post-quantum X.509 certificate: the
// subject public key is ML-DSA and the issuer signature is ML-DSA. It mirrors the
// call shape of crypto/x509.CreateCertificate.
//
// tmpl carries the certificate fields (subject, validity, key usages, SANs,
// basic constraints, …) exactly as for the standard library. subjectPub is the
// subject's ML-DSA public key. When parent is nil the certificate is self-signed
// (a root); otherwise parent is the issuing CA certificate. issuerSigner is the
// issuer's ML-DSA key (which for an HSM-backed provider would perform the
// signature on the device — SoftHSM has no ML-DSA, so the software provider is
// the fallback).
//
// The standard v3 extensions are encoded by crypto/x509 (via a throwaway build)
// and reused verbatim, so only the ML-DSA-specific fields — the signature
// AlgorithmIdentifier, the issuer name substitution, and the SubjectPublicKeyInfo
// — are assembled here. The returned bytes are the DER certificate.
func CreateCertificate(tmpl, parent *x509.Certificate, subjectPub crypto.PublicKey, issuerSigner crypto.Signer) ([]byte, error) {
	if tmpl == nil {
		return nil, fmt.Errorf("pqc: certificate template is required")
	}
	if tmpl.SerialNumber == nil || tmpl.SerialNumber.Sign() <= 0 {
		return nil, fmt.Errorf("pqc: certificate serial must be a positive integer")
	}
	if !IsPQCPublicKey(subjectPub) {
		return nil, fmt.Errorf("pqc: subject public key is not ML-DSA (%T)", subjectPub)
	}
	if issuerSigner == nil {
		return nil, fmt.Errorf("pqc: issuer signer is required")
	}
	issAlg, ok := algorithmForPublicKey(issuerSigner.Public())
	if !ok {
		return nil, fmt.Errorf("pqc: issuer signer is not an ML-DSA key (%T)", issuerSigner.Public())
	}

	ski, err := SubjectKeyID(subjectPub)
	if err != nil {
		return nil, err
	}

	// Work on a copy so the caller's template is not mutated. Force the SKI (and,
	// for a self-signed root, the AKI) to the ML-DSA subject key's identifier;
	// otherwise the throwaway ECDSA key below would drive them.
	t := *tmpl
	if t.SubjectKeyId == nil {
		t.SubjectKeyId = ski
	}
	var issuerNameDER []byte
	if parent == nil {
		if t.AuthorityKeyId == nil {
			t.AuthorityKeyId = t.SubjectKeyId
		}
	} else {
		if t.AuthorityKeyId == nil {
			t.AuthorityKeyId = parent.SubjectKeyId
		}
		issuerNameDER = parent.RawSubject
	}

	// Throwaway self-signed build: crypto/x509 emits the correct standard
	// extensions (key usage, EKU, basic constraints, SKI, AKI, SANs) with our
	// explicit SKI/AKI. Its signature and SPKI are discarded.
	throwPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pqc: generating throwaway key: %w", err)
	}
	throwDER, err := x509.CreateCertificate(rand.Reader, &t, &t, throwPriv.Public(), throwPriv)
	if err != nil {
		return nil, fmt.Errorf("pqc: building certificate skeleton: %w", err)
	}

	fields, err := tbsFields(throwDER)
	if err != nil {
		return nil, err
	}
	if len(fields) != 8 {
		return nil, fmt.Errorf("pqc: unexpected TBSCertificate shape (%d fields)", len(fields))
	}

	sigAlgDER, err := algorithmIdentifierDER(issAlg.keyType)
	if err != nil {
		return nil, err
	}
	spkiDER, err := MarshalPKIXPublicKey(subjectPub)
	if err != nil {
		return nil, err
	}
	if issuerNameDER == nil {
		issuerNameDER = fields[3] // self-signed: keep the throwaway's issuer (== subject)
	}

	// Reassemble the TBSCertificate: version, serial, signature(ML-DSA),
	// issuer, validity, subject, SPKI(ML-DSA), extensions.
	var tb cryptobyte.Builder
	tb.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(fields[0]) // version [0]
		b.AddBytes(fields[1]) // serialNumber
		b.AddBytes(sigAlgDER) // signature
		b.AddBytes(issuerNameDER)
		b.AddBytes(fields[4]) // validity
		b.AddBytes(fields[5]) // subject
		b.AddBytes(spkiDER)   // subjectPublicKeyInfo
		b.AddBytes(fields[7]) // extensions [3]
	})
	tbs, err := tb.Bytes()
	if err != nil {
		return nil, fmt.Errorf("pqc: encoding TBSCertificate: %w", err)
	}

	sig, err := issuerSigner.Sign(rand.Reader, tbs, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("pqc: signing certificate: %w", err)
	}

	return assembleSigned(tbs, sigAlgDER, sig)
}

// assembleSigned wraps a TBS structure, its signatureAlgorithm, and the signature
// bit string into the outer SEQUENCE shared by Certificate and
// CertificationRequest.
func assembleSigned(tbs, sigAlgDER, sig []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbs)
		b.AddBytes(sigAlgDER)
		b.AddASN1BitString(sig)
	})
	der, err := b.Bytes()
	if err != nil {
		return nil, fmt.Errorf("pqc: encoding signed structure: %w", err)
	}
	return der, nil
}

// tbsFields extracts and returns, in order, the raw DER of each field of the
// TBSCertificate contained in a DER certificate.
func tbsFields(certDER []byte) ([][]byte, error) {
	outer := cryptobyte.String(certDER)
	var cert cryptobyte.String
	if !outer.ReadASN1(&cert, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("pqc: malformed certificate")
	}
	tbsRaw, err := readElement(&cert)
	if err != nil {
		return nil, fmt.Errorf("pqc: reading TBSCertificate: %w", err)
	}
	return sequenceFields(tbsRaw)
}

// sequenceFields splits the content of a DER SEQUENCE into its top-level element
// DERs (each including its own tag and length).
func sequenceFields(seqDER []byte) ([][]byte, error) {
	s := cryptobyte.String(seqDER)
	var body cryptobyte.String
	if !s.ReadASN1(&body, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("pqc: not a SEQUENCE")
	}
	var out [][]byte
	for !body.Empty() {
		elem, err := readElement(&body)
		if err != nil {
			return nil, err
		}
		out = append(out, elem)
	}
	return out, nil
}

// certTBS returns the raw TBSCertificate DER of a DER certificate.
func certTBS(certDER []byte) ([]byte, error) {
	outer := cryptobyte.String(certDER)
	var cert cryptobyte.String
	if !outer.ReadASN1(&cert, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("pqc: malformed certificate")
	}
	return readElement(&cert)
}

// certSignature returns the signatureAlgorithm OID and signature bytes of a DER
// certificate.
func certSignature(certDER []byte) (asn1.ObjectIdentifier, []byte, error) {
	outer := cryptobyte.String(certDER)
	var cert cryptobyte.String
	if !outer.ReadASN1(&cert, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("pqc: malformed certificate")
	}
	if _, err := readElement(&cert); err != nil { // skip TBS
		return nil, nil, err
	}
	var algSeq cryptobyte.String
	if !cert.ReadASN1(&algSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("pqc: malformed signatureAlgorithm")
	}
	var oid asn1.ObjectIdentifier
	if !algSeq.ReadASN1ObjectIdentifier(&oid) {
		return nil, nil, fmt.Errorf("pqc: malformed signatureAlgorithm OID")
	}
	var sig []byte
	if !cert.ReadASN1BitStringAsBytes(&sig) {
		return nil, nil, fmt.Errorf("pqc: malformed signature")
	}
	return oid, sig, nil
}
