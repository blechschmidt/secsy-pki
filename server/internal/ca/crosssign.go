package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Cross-signing (Task 47): a second issuer signs a certificate for a subject key
// that another issuer already certifies.
//
// Cross-signing does NOT create a new key — it certifies an *existing* public
// key under a different issuer. The resulting certificate carries the subject
// CA's exact distinguished name and public key (so it is byte-compatible as an
// issuer), but is signed by the cross-signing CA's HSM-backed key. This yields
// two (or more) valid certificates for the same subordinate key, so a relying
// party can be served whichever chain it trusts:
//
//   - Bridge CA: two enterprise PKIs cross-certify each other's roots so leaves
//     in one domain validate under the other's trust anchor.
//   - Root transition: a new root is cross-signed by the old root, so relying
//     parties that only trust the old root still build a chain to the new one
//     until they have distributed the new anchor.
//
// The subject key may come from a CA already in this deployment (its HSM key is
// untouched — only its public half is re-certified), from an externally supplied
// certificate, or from a CSR. The alternate chains are published alongside the
// native chain (Task 24's overlap bundle), and selection is by Subject Key
// Identifier: every certificate for the same subject key shares one SKI.

// CrossSignSpec parameterizes a cross-signing operation. Exactly one of
// SubjectCAID, CertPEM, or CSRPEM identifies the subject key to cross-sign.
type CrossSignSpec struct {
	// IssuerCAID is the local CA whose HSM-backed key signs the cross-certificate.
	// If it is part of a rollover lineage, the active key is used.
	IssuerCAID string
	// SubjectCAID cross-signs a CA held in this deployment (by id). Its private key
	// is never touched; only its certificate's subject and public key are reused.
	SubjectCAID string
	// CertPEM cross-signs an externally supplied certificate (PEM or DER-in-PEM).
	CertPEM []byte
	// CSRPEM cross-signs an externally supplied certificate signing request.
	CSRPEM []byte
	// Validity bounds the cross-signed certificate. Zero reuses the subject
	// certificate's original span (required to be set for a CSR subject). The
	// result is always clamped to the issuer's own expiry.
	Validity time.Duration
	// MaxPathLen overrides the path-length constraint. Nil preserves the subject
	// certificate's constraint (or leaves a CSR subject unconstrained).
	MaxPathLen *int
	// RequestedBy records who initiated the cross-sign (for audit/labelling).
	RequestedBy string
}

// CrossSignResult is the outcome of a successful cross-sign.
type CrossSignResult struct {
	// CrossSign is the persisted cross-sign record.
	CrossSign *models.CrossSign
	// CertificatePEM is the freshly signed cross-certificate (PEM).
	CertificatePEM []byte
	// ChainPEM is the alternate chain a relying party would use: the
	// cross-certificate followed by the issuer's own chain to its root.
	ChainPEM []byte
}

// crossSubject holds the material extracted from a cross-sign subject source.
type crossSubject struct {
	rawSubject   []byte
	subjectDN    string
	publicKey    crypto.PublicKey
	subjectKeyID []byte
	maxPathLen   *int
	extraExts    []pkix.Extension
	source       string
	// localCAID is set when the subject is a CA held in this deployment.
	localCAID string
	// originalSpan is the subject certificate's original validity, used to default
	// the cross-sign lifetime when Validity is unset (zero for a CSR subject).
	originalSpan time.Duration
}

// CrossSign issues a cross-certificate: the issuer CA's HSM key signs a CA
// certificate carrying the subject's exact DN and public key. The subject's
// private key is never involved. The relationship is persisted and the alternate
// chain returned.
func (m *Manager) CrossSign(ctx context.Context, spec CrossSignSpec) (*CrossSignResult, error) {
	if spec.IssuerCAID == "" {
		return nil, fmt.Errorf("issuer CA id is required")
	}
	if err := validateCrossSignSources(spec); err != nil {
		return nil, err
	}

	// Sign under the currently active key in the issuer's rollover lineage.
	activeIssuerID, err := m.ActiveIssuerID(spec.IssuerCAID)
	if err != nil {
		return nil, err
	}
	issuerCA, issuerCert, err := m.loadIssuer(activeIssuerID)
	if err != nil {
		return nil, fmt.Errorf("loading issuer CA: %w", err)
	}
	if err := m.checkPathLen(issuerCA, issuerCert); err != nil {
		return nil, err
	}

	subject, err := m.resolveCrossSubject(spec)
	if err != nil {
		return nil, err
	}

	// A CA must not cross-sign itself: it would produce a spurious self-issued
	// certificate under a different serial with no trust benefit.
	if subject.localCAID != "" && subject.localCAID == issuerCA.ID {
		return nil, fmt.Errorf("issuer and subject are the same CA %q; cross-signing requires distinct issuer and subject", issuerCA.Label)
	}

	// Determine validity: reuse the subject's original span unless overridden, and
	// always clamp to the issuer's expiry so the cross-cert never outlives it.
	now := time.Now()
	validity := spec.Validity
	if validity <= 0 {
		validity = subject.originalSpan
	}
	if validity <= 0 {
		return nil, fmt.Errorf("validity is required when cross-signing a CSR (the subject carries no validity to reuse)")
	}
	notAfter := now.Add(validity)
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
	}

	maxPathLen := subject.maxPathLen
	if spec.MaxPathLen != nil {
		maxPathLen = spec.MaxPathLen
	}

	serial, err := m.db.AllocateSerial(issuerCA.ID)
	if err != nil {
		return nil, fmt.Errorf("allocating serial from issuer CA: %w", err)
	}

	issuerSigner, err := m.provider.Signer(ctx, keyRefForCA(issuerCA))
	if err != nil {
		return nil, fmt.Errorf("opening issuer CA signer: %w", err)
	}
	defer issuerSigner.Close()

	req := pki.CACertRequest{
		RawSubject:      subject.rawSubject,
		SubjectKeyID:    subject.subjectKeyID,
		PublicKey:       subject.publicKey,
		Serial:          big.NewInt(serial),
		NotBefore:       now.Add(-clockSkew),
		NotAfter:        notAfter,
		MaxPathLen:      maxPathLen,
		ExtraExtensions: subject.extraExts,
	}
	der, err := pki.CreateCACertificate(issuerSigner, issuerCert, req)
	if err != nil {
		return nil, fmt.Errorf("creating cross-signed certificate: %w", err)
	}
	certPEM := pki.EncodeCertificatePEM(der)

	// Re-parse the signed certificate so the persisted SKI/subject reflect exactly
	// what was emitted (the encoder may derive the SKI when we did not supply one).
	crossCert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing cross-signed certificate: %w", err)
	}
	skiHex := hex.EncodeToString(crossCert.SubjectKeyId)

	var subjectCAID *string
	if subject.localCAID != "" {
		id := subject.localCAID
		subjectCAID = &id
	}

	cs := &models.CrossSign{
		ID:           uuid.New().String(),
		TenantID:     issuerCA.TenantID,
		IssuerCAID:   issuerCA.ID,
		SubjectCAID:  subjectCAID,
		SubjectKeyID: skiHex,
		Subject:      crossCert.Subject.String(),
		Serial:       req.Serial.String(),
		Certificate:  string(certPEM),
		NotBefore:    crossCert.NotBefore,
		NotAfter:     crossCert.NotAfter,
		Source:       subject.source,
		Status:       models.CrossSignStatusActive,
		RequestedBy:  spec.RequestedBy,
	}
	if err := m.db.CreateCrossSign(cs); err != nil {
		return nil, fmt.Errorf("persisting cross-sign: %w", err)
	}

	chain, err := m.crossSignChainPEM(cs, issuerCA.ID)
	if err != nil {
		return nil, err
	}

	return &CrossSignResult{
		CrossSign:      cs,
		CertificatePEM: certPEM,
		ChainPEM:       chain,
	}, nil
}

// validateCrossSignSources enforces that exactly one subject source is supplied.
func validateCrossSignSources(spec CrossSignSpec) error {
	n := 0
	if spec.SubjectCAID != "" {
		n++
	}
	if len(spec.CertPEM) > 0 {
		n++
	}
	if len(spec.CSRPEM) > 0 {
		n++
	}
	switch {
	case n == 0:
		return fmt.Errorf("a cross-sign subject is required: set exactly one of subject CA, certificate, or CSR")
	case n > 1:
		return fmt.Errorf("only one cross-sign subject may be given (subject CA, certificate, or CSR)")
	}
	return nil
}

// resolveCrossSubject extracts the subject DN, public key, SKI, path-length
// constraint, and preserved CA extensions from the configured subject source.
func (m *Manager) resolveCrossSubject(spec CrossSignSpec) (*crossSubject, error) {
	switch {
	case spec.SubjectCAID != "":
		return m.crossSubjectFromLocalCA(spec.SubjectCAID)
	case len(spec.CertPEM) > 0:
		return crossSubjectFromCertificate(spec.CertPEM)
	default:
		return crossSubjectFromCSR(spec.CSRPEM)
	}
}

// crossSubjectFromLocalCA builds the subject material from a CA held in this
// deployment. The CA's certificate supplies the exact DN, public key, SKI, and
// preserved Name Constraints / policy extensions.
func (m *Manager) crossSubjectFromLocalCA(caID string) (*crossSubject, error) {
	ca, err := m.db.GetCA(caID)
	if err != nil {
		return nil, fmt.Errorf("looking up subject CA: %w", err)
	}
	if ca == nil {
		return nil, fmt.Errorf("subject CA %q not found", caID)
	}
	if ca.Certificate == "" {
		return nil, fmt.Errorf("subject CA %q is not an X.509 CA (no certificate)", ca.Label)
	}
	cert, err := pki.ParseCertificatePEM([]byte(ca.Certificate))
	if err != nil {
		return nil, fmt.Errorf("parsing subject CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("subject CA %q certificate is not a CA certificate", ca.Label)
	}
	return &crossSubject{
		rawSubject:   cert.RawSubject,
		subjectDN:    cert.Subject.String(),
		publicKey:    cert.PublicKey,
		subjectKeyID: cert.SubjectKeyId,
		maxPathLen:   maxPathLenOf(cert),
		extraExts:    preservedCAExtensions(cert),
		source:       models.CrossSignSourceLocalCA,
		localCAID:    ca.ID,
		originalSpan: cert.NotAfter.Sub(cert.NotBefore),
	}, nil
}

// crossSubjectFromCertificate builds the subject material from an externally
// supplied certificate. It must be a CA certificate. A self-signed certificate's
// signature is verified as a sanity check; a certificate already signed by
// another issuer is accepted as-is (that is the bridge case).
func crossSubjectFromCertificate(certPEM []byte) (*crossSubject, error) {
	cert, err := pki.ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing subject certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("subject certificate is not a CA certificate (basic constraints cA=false); only CA keys may be cross-signed")
	}
	// If the certificate presents itself as self-signed (issuer == subject),
	// confirm it actually verifies under its own key — a corrupted trust anchor
	// must be rejected before we re-certify its key. A certificate already issued
	// by a different CA (issuer != subject) is accepted as-is: re-certifying a
	// foreign-issued key is exactly the bridge case.
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		if err := cert.CheckSignatureFrom(cert); err != nil {
			return nil, fmt.Errorf("subject certificate is self-issued but its signature does not verify: %w", err)
		}
	}
	ski := cert.SubjectKeyId
	if len(ski) == 0 {
		ski = deriveSKI(cert.PublicKey)
	}
	return &crossSubject{
		rawSubject:   cert.RawSubject,
		subjectDN:    cert.Subject.String(),
		publicKey:    cert.PublicKey,
		subjectKeyID: ski,
		maxPathLen:   maxPathLenOf(cert),
		extraExts:    preservedCAExtensions(cert),
		source:       models.CrossSignSourceCertificate,
		originalSpan: cert.NotAfter.Sub(cert.NotBefore),
	}, nil
}

// crossSubjectFromCSR builds the subject material from a CSR. The CSR's
// self-signature is verified (proof the requester holds the private key). A CSR
// carries no validity, so the caller must supply one.
func crossSubjectFromCSR(csrPEM []byte) (*crossSubject, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid PEM: expected CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing subject CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("subject CSR signature verification failed: %w", err)
	}
	return &crossSubject{
		rawSubject:   csr.RawSubject,
		subjectDN:    csr.Subject.String(),
		publicKey:    csr.PublicKey,
		subjectKeyID: deriveSKI(csr.PublicKey),
		source:       models.CrossSignSourceCSR,
	}, nil
}

// maxPathLenOf returns a certificate's basic-constraints path-length constraint
// as an optional int: 0 when explicitly zero, the value when set, or nil when
// the certificate leaves the path length unconstrained.
func maxPathLenOf(cert *x509.Certificate) *int {
	if cert.MaxPathLenZero {
		zero := 0
		return &zero
	}
	if cert.MaxPathLen > 0 {
		v := cert.MaxPathLen
		return &v
	}
	return nil
}

// deriveSKI computes the RFC 5280 §4.2.1.2 method-1 Subject Key Identifier
// (SHA-1 of the subject public key BIT STRING) for a public key, matching how
// crypto/x509 derives an omitted SKI so native and cross-signed certificates for
// the same key share one identifier.
func deriveSKI(pub crypto.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return sum[:]
}
