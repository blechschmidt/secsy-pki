package pqc

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Alternative-signature extension OIDs from ITU-T X.509 (2019) clause 9.8 /
// IETF draft-ietf-lamps-x509-alt. A "catalyst" hybrid certificate carries a
// classical primary key and signature (so any verifier accepts it) plus a
// parallel ML-DSA public key and signature in these extensions for PQC-aware
// verifiers.
var (
	oidSubjectAltPublicKeyInfo = asn1.ObjectIdentifier{2, 5, 29, 72}
	oidAltSignatureAlgorithm   = asn1.ObjectIdentifier{2, 5, 29, 73}
	oidAltSignatureValue       = asn1.ObjectIdentifier{2, 5, 29, 74}
)

// HybridExtensions returns the subjectAltPublicKeyInfo and altSignatureAlgorithm
// extensions for a certificate whose alternative (PQC) key is altPub and whose
// alternative signature will be produced by an issuer holding altIssuerKeyType.
// They are appended (in this order) to a certificate template before the primary
// signature is computed; altSignatureValue is added afterwards (see
// CreateHybridCertificate).
func hybridPreExtensions(altPub crypto.PublicKey, altIssuerKeyType string) ([]pkix.Extension, error) {
	sapki, err := MarshalPKIXPublicKey(altPub)
	if err != nil {
		return nil, err
	}
	algID, err := algorithmIdentifierDER(altIssuerKeyType)
	if err != nil {
		return nil, err
	}
	return []pkix.Extension{
		{Id: oidSubjectAltPublicKeyInfo, Critical: false, Value: sapki},
		{Id: oidAltSignatureAlgorithm, Critical: false, Value: algID},
	}, nil
}

// CreateHybridCertificate builds a hybrid (catalyst) certificate.
//
// The primary key/signature are classical: tmpl and primarySubjectPub describe
// the standard certificate and primaryIssuerSigner (the CA's classical key)
// produces the ordinary X.509 signature. In parallel, altSubjectPub (an ML-DSA
// key belonging to the subject) is embedded as subjectAltPublicKeyInfo, and
// altIssuerSigner (the CA's ML-DSA key) signs the pre-certificate to produce the
// altSignatureValue extension. When parent is nil the certificate is self-signed.
//
// The alternative signature is computed over the DER of the TBSCertificate with
// the subjectAltPublicKeyInfo and altSignatureAlgorithm extensions present but
// the altSignatureValue extension absent — the standard reconstruction used by
// VerifyHybridChain.
func CreateHybridCertificate(tmpl, parent *x509.Certificate, primarySubjectPub, altSubjectPub crypto.PublicKey, primaryIssuerSigner, altIssuerSigner crypto.Signer) ([]byte, error) {
	if tmpl == nil {
		return nil, fmt.Errorf("pqc: certificate template is required")
	}
	if !IsPQCPublicKey(altSubjectPub) {
		return nil, fmt.Errorf("pqc: alternative subject key is not ML-DSA (%T)", altSubjectPub)
	}
	altIssAlg, ok := algorithmForPublicKey(altIssuerSigner.Public())
	if !ok {
		return nil, fmt.Errorf("pqc: alternative issuer signer is not ML-DSA (%T)", altIssuerSigner.Public())
	}

	preExts, err := hybridPreExtensions(altSubjectPub, altIssAlg.keyType)
	if err != nil {
		return nil, err
	}

	// Pass A: classical certificate carrying the two pre-extensions. Its
	// TBSCertificate is the pre-image the alternative signature covers.
	tmplA := *tmpl
	tmplA.ExtraExtensions = appendExts(tmpl.ExtraExtensions, preExts...)
	issuerA := parent
	if issuerA == nil {
		issuerA = &tmplA
	}
	certA, err := x509.CreateCertificate(rand.Reader, &tmplA, issuerA, primarySubjectPub, primaryIssuerSigner)
	if err != nil {
		return nil, fmt.Errorf("pqc: building hybrid pre-certificate: %w", err)
	}
	preTBS, err := certTBS(certA)
	if err != nil {
		return nil, err
	}

	altSig, err := altIssuerSigner.Sign(rand.Reader, preTBS, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("pqc: producing alternative signature: %w", err)
	}
	altSigDER, err := asn1.Marshal(asn1.BitString{Bytes: altSig, BitLength: len(altSig) * 8})
	if err != nil {
		return nil, fmt.Errorf("pqc: encoding alternative signature: %w", err)
	}

	// Pass B: the same certificate with altSignatureValue appended last.
	tmplB := *tmpl
	tmplB.ExtraExtensions = appendExts(tmpl.ExtraExtensions, append(preExts,
		pkix.Extension{Id: oidAltSignatureValue, Critical: false, Value: altSigDER})...)
	issuerB := parent
	if issuerB == nil {
		issuerB = &tmplB
	}
	certB, err := x509.CreateCertificate(rand.Reader, &tmplB, issuerB, primarySubjectPub, primaryIssuerSigner)
	if err != nil {
		return nil, fmt.Errorf("pqc: building hybrid certificate: %w", err)
	}
	return certB, nil
}

// appendExts returns base with extra appended, without mutating base.
func appendExts(base []pkix.Extension, extra ...pkix.Extension) []pkix.Extension {
	out := make([]pkix.Extension, 0, len(base)+len(extra))
	out = append(out, base...)
	out = append(out, extra...)
	return out
}

// IsHybridCertificate reports whether cert carries the alternative-signature
// extensions of a catalyst hybrid certificate.
func IsHybridCertificate(cert *x509.Certificate) bool {
	_, ok := findExtension(cert, oidAltSignatureValue)
	return ok
}

// AltPublicKey returns the ML-DSA public key carried in a certificate's
// subjectAltPublicKeyInfo extension.
func AltPublicKey(cert *x509.Certificate) (crypto.PublicKey, string, error) {
	ext, ok := findExtension(cert, oidSubjectAltPublicKeyInfo)
	if !ok {
		return nil, "", fmt.Errorf("pqc: certificate has no subjectAltPublicKeyInfo extension")
	}
	return ParsePKIXPublicKey(ext.Value)
}

// VerifyHybridAltSignature verifies the alternative (ML-DSA) signature of a
// hybrid certificate against issuerAltPub. It reconstructs the signed pre-image
// by removing the altSignatureValue extension from the TBSCertificate.
func VerifyHybridAltSignature(certDER []byte, issuerAltPub crypto.PublicKey) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("pqc: parsing certificate: %w", err)
	}
	valExt, ok := findExtension(cert, oidAltSignatureValue)
	if !ok {
		return fmt.Errorf("pqc: certificate has no altSignatureValue extension")
	}
	var altSigBits asn1.BitString
	if _, err := asn1.Unmarshal(valExt.Value, &altSigBits); err != nil {
		return fmt.Errorf("pqc: decoding altSignatureValue: %w", err)
	}

	preimage, lastOID, err := stripLastExtensionTBS(certDER)
	if err != nil {
		return err
	}
	if !lastOID.Equal(oidAltSignatureValue) {
		return fmt.Errorf("pqc: altSignatureValue is not the final extension (found %v)", lastOID)
	}

	a, ok := algorithmForPublicKey(issuerAltPub)
	if !ok {
		return fmt.Errorf("pqc: issuer alternative key is not ML-DSA (%T)", issuerAltPub)
	}
	pub := issuerAltPub.(sign.PublicKey)
	if !a.scheme.Verify(pub, preimage, altSigBits.RightAlign(), nil) {
		return fmt.Errorf("pqc: alternative (ML-DSA) signature verification failed")
	}
	return nil
}

// VerifyHybridChain verifies BOTH signature dimensions of an ordered hybrid
// chain [leaf, …, root]: the classical primary signatures (via the standard
// library) and the alternative ML-DSA signatures (each link against the alt key
// in its issuer's subjectAltPublicKeyInfo). A chain that verifies here is
// trusted by both classical and PQC-aware relying parties.
func VerifyHybridChain(chainDER [][]byte, opts VerifyOptions) error {
	if len(chainDER) == 0 {
		return fmt.Errorf("pqc: empty chain")
	}
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	certs := make([]*x509.Certificate, len(chainDER))
	for i, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("pqc: parsing chain certificate %d: %w", i, err)
		}
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return fmt.Errorf("pqc: certificate %d (%s) is not valid at %s", i, c.Subject, now)
		}
		certs[i] = c
	}

	verifyLink := func(childDER []byte, child, issuer *x509.Certificate) error {
		if err := child.CheckSignatureFrom(issuer); err != nil {
			return fmt.Errorf("classical signature: %w", err)
		}
		altPub, _, err := AltPublicKey(issuer)
		if err != nil {
			return fmt.Errorf("issuer alternative key: %w", err)
		}
		if err := VerifyHybridAltSignature(childDER, altPub); err != nil {
			return err
		}
		return nil
	}

	for i := 0; i+1 < len(certs); i++ {
		if err := verifyLink(chainDER[i], certs[i], certs[i+1]); err != nil {
			return fmt.Errorf("pqc: verifying hybrid certificate %d: %w", i, err)
		}
	}
	last := len(certs) - 1
	if err := verifyLink(chainDER[last], certs[last], certs[last]); err != nil {
		return fmt.Errorf("pqc: verifying self-signed hybrid root: %w", err)
	}
	return nil
}

// findExtension returns the extension with the given OID.
func findExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, e := range cert.Extensions {
		if e.Id.Equal(oid) {
			return e, true
		}
	}
	return pkix.Extension{}, false
}

// stripLastExtensionTBS reconstructs the TBSCertificate DER with its final
// extension removed, returning that pre-image and the removed extension's OID. It
// is the canonical alt-signature pre-image reconstruction.
func stripLastExtensionTBS(certDER []byte) ([]byte, asn1.ObjectIdentifier, error) {
	fields, err := tbsFields(certDER)
	if err != nil {
		return nil, nil, err
	}
	if len(fields) != 8 {
		return nil, nil, fmt.Errorf("pqc: unexpected TBSCertificate shape (%d fields)", len(fields))
	}

	// fields[7] is the extensions field: [3] EXPLICIT SEQUENCE OF Extension.
	exts := cryptobyte.String(fields[7])
	var inner cryptobyte.String
	if !exts.ReadASN1(&inner, cryptobyte_asn1.Tag(3).Constructed().ContextSpecific()) {
		return nil, nil, fmt.Errorf("pqc: malformed extensions field")
	}
	var seq cryptobyte.String
	if !inner.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, fmt.Errorf("pqc: malformed extensions SEQUENCE")
	}
	var elems [][]byte
	for !seq.Empty() {
		e, err := readElement(&seq)
		if err != nil {
			return nil, nil, err
		}
		elems = append(elems, e)
	}
	if len(elems) == 0 {
		return nil, nil, fmt.Errorf("pqc: certificate has no extensions")
	}
	last := elems[len(elems)-1]
	lastOID, err := extensionOID(last)
	if err != nil {
		return nil, nil, err
	}
	kept := elems[:len(elems)-1]

	// Rebuild extensions field and TBSCertificate with DER-minimal lengths.
	var eb cryptobyte.Builder
	eb.AddASN1(cryptobyte_asn1.Tag(3).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for _, e := range kept {
				b.AddBytes(e)
			}
		})
	})
	newExts, err := eb.Bytes()
	if err != nil {
		return nil, nil, err
	}

	var tb cryptobyte.Builder
	tb.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for i := 0; i < 7; i++ {
			b.AddBytes(fields[i])
		}
		b.AddBytes(newExts)
	})
	preimage, err := tb.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return preimage, lastOID, nil
}

// extensionOID returns the OID of a single DER-encoded Extension element.
func extensionOID(extDER []byte) (asn1.ObjectIdentifier, error) {
	s := cryptobyte.String(extDER)
	var ext cryptobyte.String
	if !s.ReadASN1(&ext, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("pqc: malformed extension")
	}
	var oid asn1.ObjectIdentifier
	if !ext.ReadASN1ObjectIdentifier(&oid) {
		return nil, fmt.Errorf("pqc: malformed extension OID")
	}
	return oid, nil
}
