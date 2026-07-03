package ca

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/pqc"
)

// altKeyLabel derives the provider label under which a hybrid CA's ML-DSA
// alternative key is stored, alongside its classical primary key. A hybrid CA
// therefore holds two keys in the provider: <label> (classical) and
// <label>+altKeySuffix (ML-DSA). The alternative public key is also embedded in
// the CA certificate (subjectAltPublicKeyInfo) so chains are self-contained.
const altKeySuffix = "-altpqc"

func altKeyLabel(label string) string { return label + altKeySuffix }

// decodeCSRPEM extracts the DER of a PEM-encoded PKCS#10 request, for the
// ML-DSA-aware CSR parsers (which operate on DER).
func decodeCSRPEM(csrPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid PEM: expected CERTIFICATE REQUEST block")
	}
	return block.Bytes, nil
}

// leafTemplateFromRequest converts a pki.LeafCertRequest into the crypto/x509
// template used by the pqc builders. It mirrors the template that
// pki.CreateLeafCertificate assembles for classical leaves, minus the fields the
// pqc builders derive themselves (subject key identifier).
func leafTemplateFromRequest(req pki.LeafCertRequest) (*x509.Certificate, error) {
	uris := make([]*url.URL, 0, len(req.URIs))
	for _, raw := range req.URIs {
		u, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid URI SAN %q: %w", raw, err)
		}
		uris = append(uris, u)
	}
	t := &x509.Certificate{
		SerialNumber:          req.Serial,
		Subject:               req.Subject,
		NotBefore:             req.NotBefore,
		NotAfter:              req.NotAfter,
		KeyUsage:              req.KeyUsage,
		ExtKeyUsage:           req.ExtKeyUsage,
		BasicConstraintsValid: true,
		DNSNames:              req.DNSNames,
		IPAddresses:           req.IPAddresses,
		EmailAddresses:        req.EmailAddresses,
		URIs:                  uris,
		CRLDistributionPoints: req.CRLDistributionPoints,
		OCSPServer:            req.OCSPServer,
		ExtraExtensions:       req.ExtraExtensions,
	}
	if req.IsCA {
		t.IsCA = true
		if req.MaxPathLen != nil {
			t.MaxPathLen = *req.MaxPathLen
			t.MaxPathLenZero = *req.MaxPathLen == 0
		}
	}
	return t, nil
}

// caTemplateFromRequest converts a pki.CACertRequest into a crypto/x509 CA
// template for the pqc builders, mirroring pki.CreateCACertificate.
func caTemplateFromRequest(req pki.CACertRequest) *x509.Certificate {
	t := &x509.Certificate{
		SerialNumber:          req.Serial,
		Subject:               req.Subject,
		NotBefore:             req.NotBefore,
		NotAfter:              req.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions:       req.ExtraExtensions,
	}
	if req.MaxPathLen != nil {
		t.MaxPathLen = *req.MaxPathLen
		t.MaxPathLenZero = *req.MaxPathLen == 0
	}
	return t
}

// buildAndSignCACert generates the CA key material and produces the signed CA
// certificate DER for the requested algorithm. For a root CA parent/parentCert
// are nil (the certificate is self-signed); for an intermediate they identify the
// issuing parent. It returns the primary key's KeyInfo, which the caller persists
// as the CA record's key.
//
//   - classical: one key; signed by crypto/x509.
//   - pqc: one ML-DSA key; signed with ML-DSA (the parent's, or its own for a root).
//   - hybrid: a classical primary key plus an ML-DSA alternative key (stored under
//     altKeyLabel); signed with both the primary and alternative issuer keys.
func (m *Manager) buildAndSignCACert(ctx context.Context, algorithm CertAlgorithm, label, keyType, altKeyType string, req pki.CACertRequest, parent *models.CA, parentCert *x509.Certificate) (*keyprovider.KeyInfo, []byte, error) {
	switch algorithm {
	case AlgPQC:
		return m.buildPQCCACert(ctx, label, keyType, req, parent, parentCert)
	case AlgHybrid:
		return m.buildHybridCACert(ctx, label, keyType, altKeyType, req, parent, parentCert)
	case AlgClassical:
		return m.buildClassicalCACert(ctx, label, keyType, req, parent, parentCert)
	default:
		return nil, nil, fmt.Errorf("unknown CA algorithm %q (want classical, pqc, or hybrid)", algorithm)
	}
}

// issuerPrimaryRef resolves the key reference for the signing (primary) key: the
// new CA's own key for a self-signed root, or the parent's key otherwise.
func issuerPrimaryRef(newLabel string, parent *models.CA) keyprovider.KeyRef {
	if parent == nil {
		return keyprovider.KeyRef{Label: newLabel}
	}
	return keyRefForCA(parent)
}

// issuerAltRef resolves the key reference for the ML-DSA alternative signing key
// of a hybrid CA: the new CA's own alt key for a root, or the parent's alt key.
func issuerAltRef(newLabel string, parent *models.CA) keyprovider.KeyRef {
	if parent == nil {
		return keyprovider.KeyRef{Label: altKeyLabel(newLabel)}
	}
	return keyprovider.KeyRef{Label: altKeyLabel(parent.Label)}
}

func (m *Manager) buildClassicalCACert(ctx context.Context, label, keyType string, req pki.CACertRequest, parent *models.CA, parentCert *x509.Certificate) (*keyprovider.KeyInfo, []byte, error) {
	keyInfo, err := m.provider.GenerateKey(ctx, keyprovider.KeySpec{Label: label, KeyType: keyType})
	if err != nil {
		return nil, nil, fmt.Errorf("generating CA key: %w", err)
	}
	signer, err := m.provider.Signer(ctx, issuerPrimaryRef(label, parent))
	if err != nil {
		return nil, nil, fmt.Errorf("opening CA signer: %w", err)
	}
	defer signer.Close()
	req.PublicKey = keyInfo.PublicKey
	der, err := pki.CreateCACertificate(signer, parentCert, req)
	if err != nil {
		return nil, nil, err
	}
	return keyInfo, der, nil
}

func (m *Manager) buildPQCCACert(ctx context.Context, label, keyType string, req pki.CACertRequest, parent *models.CA, parentCert *x509.Certificate) (*keyprovider.KeyInfo, []byte, error) {
	if !pqc.IsPQC(keyType) {
		return nil, nil, fmt.Errorf("a post-quantum CA requires an ML-DSA key type, got %q", keyType)
	}
	keyInfo, err := m.provider.GenerateKey(ctx, keyprovider.KeySpec{Label: label, KeyType: keyType})
	if err != nil {
		return nil, nil, fmt.Errorf("generating ML-DSA CA key: %w", err)
	}
	signer, err := m.provider.Signer(ctx, issuerPrimaryRef(label, parent))
	if err != nil {
		return nil, nil, fmt.Errorf("opening ML-DSA CA signer: %w", err)
	}
	defer signer.Close()
	if !pqc.IsPQCPublicKey(signer.Public()) {
		return nil, nil, fmt.Errorf("a post-quantum intermediate must be issued under a post-quantum (ML-DSA) parent CA")
	}
	tmpl := caTemplateFromRequest(req)
	der, err := pqc.CreateCertificate(tmpl, parentCert, keyInfo.PublicKey, signer)
	if err != nil {
		return nil, nil, err
	}
	return keyInfo, der, nil
}

func (m *Manager) buildHybridCACert(ctx context.Context, label, keyType, altKeyType string, req pki.CACertRequest, parent *models.CA, parentCert *x509.Certificate) (*keyprovider.KeyInfo, []byte, error) {
	if pqc.IsPQC(keyType) {
		return nil, nil, fmt.Errorf("a hybrid CA's primary key must be classical (ECDSA/RSA), got %q", keyType)
	}
	if altKeyType == "" {
		altKeyType = defaultPQCKeyType
	}
	if !pqc.IsPQC(altKeyType) {
		return nil, nil, fmt.Errorf("a hybrid CA's alternative key must be ML-DSA, got %q", altKeyType)
	}

	// Generate the classical primary key (persisted as the CA record's key) and
	// the ML-DSA alternative key stored alongside it under altKeyLabel.
	keyInfo, err := m.provider.GenerateKey(ctx, keyprovider.KeySpec{Label: label, KeyType: keyType})
	if err != nil {
		return nil, nil, fmt.Errorf("generating hybrid CA primary key: %w", err)
	}
	altInfo, err := m.provider.GenerateKey(ctx, keyprovider.KeySpec{Label: altKeyLabel(label), KeyType: altKeyType})
	if err != nil {
		return nil, nil, fmt.Errorf("generating hybrid CA alternative (ML-DSA) key: %w", err)
	}

	primarySigner, err := m.provider.Signer(ctx, issuerPrimaryRef(label, parent))
	if err != nil {
		return nil, nil, fmt.Errorf("opening hybrid CA primary signer: %w", err)
	}
	defer primarySigner.Close()
	altSigner, err := m.provider.Signer(ctx, issuerAltRef(label, parent))
	if err != nil {
		return nil, nil, fmt.Errorf("opening hybrid CA alternative signer: %w", err)
	}
	defer altSigner.Close()
	if !pqc.IsPQCPublicKey(altSigner.Public()) {
		return nil, nil, fmt.Errorf("a hybrid intermediate must be issued under a hybrid parent CA (missing ML-DSA parent key)")
	}

	tmpl := caTemplateFromRequest(req)
	der, err := pqc.CreateHybridCertificate(tmpl, parentCert, keyInfo.PublicKey, altInfo.PublicKey, primarySigner, altSigner)
	if err != nil {
		return nil, nil, err
	}
	return keyInfo, der, nil
}

// issuePQCLeaf issues a pure post-quantum end-entity certificate: the subject key
// (from a PQC CSR) and the issuer signature are both ML-DSA. Certificate
// Transparency does not apply (these are not submitted to public CT logs), but
// the pre-issuance lint gate still runs.
func (m *Manager) issuePQCLeaf(ctx context.Context, spec IssueSpec, issuerCA *models.CA, issuerCert *x509.Certificate, profile Profile) (_ *IssueResult, err error) {
	// Fail-closed FIPS gate: ML-DSA comes from CIRCL, software outside the
	// validated module boundary (see internal/fips).
	if fips.PolicyEnforced() {
		return nil, fmt.Errorf("profile %q issues pure post-quantum certificates, which are %w", profile.Name, fips.ErrNotApproved)
	}
	// Same tenant lifecycle + quota gate as the classical issueLeaf path.
	gateDone, err := m.gateTenantIssuance(ctx, issuerCA, spec.RequestedBy)
	if err != nil {
		return nil, err
	}
	defer func() { gateDone(err) }()

	csrDER, err := decodeCSRPEM(spec.CSRPEM)
	if err != nil {
		return nil, err
	}
	csr, err := pqc.ParsePQCCSR(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parsing post-quantum CSR: %w", err)
	}

	base, err := m.leafBaseFromCSR(csr.PublicKey, csr.Parsed, spec, profile, issuerCert)
	if err != nil {
		return nil, err
	}
	// Same S/MIME mailbox gate as the classical buildLeaf path (normalization
	// must precede linting so the lint checks see the final SAN values).
	if base, err = m.applySMIMEPolicy(base, profile, issuerCA, spec.RequestedBy); err != nil {
		return nil, err
	}
	if err := m.lintLeaf(base, profile, issuerCA, spec.RequestedBy); err != nil {
		return nil, err
	}

	signer, err := m.provider.Signer(ctx, keyRefForCA(issuerCA))
	if err != nil {
		return nil, fmt.Errorf("opening issuer signer: %w", err)
	}
	defer signer.Close()
	if !pqc.IsPQCPublicKey(signer.Public()) {
		return nil, fmt.Errorf("profile %q requires a post-quantum (ML-DSA) issuing CA, but CA %q has a %s key",
			profile.Name, issuerCA.Label, issuerCA.KeyType)
	}

	tmpl, err := leafTemplateFromRequest(base)
	if err != nil {
		return nil, err
	}
	der, err := pqc.CreateCertificate(tmpl, issuerCert, csr.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("creating post-quantum certificate: %w", err)
	}
	return m.recordLeaf(issuerCA, der, base.Serial, profile, spec.RequestedBy, spec.Marker)
}

// issueHybridLeaf issues a catalyst hybrid end-entity certificate from a hybrid
// CSR: a classical primary signature plus a parallel ML-DSA alternative
// signature. It requires a hybrid issuing CA (classical primary key plus an
// ML-DSA alternative key stored under altKeyLabel).
func (m *Manager) issueHybridLeaf(ctx context.Context, spec IssueSpec, issuerCA *models.CA, issuerCert *x509.Certificate, profile Profile) (_ *IssueResult, err error) {
	// Fail-closed FIPS gate: the ML-DSA alternative signature comes from CIRCL,
	// software outside the validated module boundary (see internal/fips).
	if fips.PolicyEnforced() {
		return nil, fmt.Errorf("profile %q issues hybrid (catalyst) certificates, which are %w", profile.Name, fips.ErrNotApproved)
	}
	// Same tenant lifecycle + quota gate as the classical issueLeaf path.
	gateDone, err := m.gateTenantIssuance(ctx, issuerCA, spec.RequestedBy)
	if err != nil {
		return nil, err
	}
	defer func() { gateDone(err) }()

	csrDER, err := decodeCSRPEM(spec.CSRPEM)
	if err != nil {
		return nil, err
	}
	csr, err := pqc.ParseHybridCSR(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parsing hybrid CSR: %w", err)
	}

	base, err := m.leafBaseFromCSR(csr.PrimaryKey, csr.Parsed, spec, profile, issuerCert)
	if err != nil {
		return nil, err
	}
	// Same S/MIME mailbox gate as the classical buildLeaf path (normalization
	// must precede linting so the lint checks see the final SAN values).
	if base, err = m.applySMIMEPolicy(base, profile, issuerCA, spec.RequestedBy); err != nil {
		return nil, err
	}
	if err := m.lintLeaf(base, profile, issuerCA, spec.RequestedBy); err != nil {
		return nil, err
	}

	primarySigner, err := m.provider.Signer(ctx, keyRefForCA(issuerCA))
	if err != nil {
		return nil, fmt.Errorf("opening issuer primary signer: %w", err)
	}
	defer primarySigner.Close()

	altSigner, err := m.provider.Signer(ctx, keyprovider.KeyRef{Label: altKeyLabel(issuerCA.Label)})
	if err != nil {
		return nil, fmt.Errorf("opening issuer alternative (ML-DSA) signer for hybrid CA %q "+
			"(expected an ML-DSA key labeled %q): %w", issuerCA.Label, altKeyLabel(issuerCA.Label), err)
	}
	defer altSigner.Close()

	tmpl, err := leafTemplateFromRequest(base)
	if err != nil {
		return nil, err
	}
	der, err := pqc.CreateHybridCertificate(tmpl, issuerCert, csr.PrimaryKey, csr.AltKey, primarySigner, altSigner)
	if err != nil {
		return nil, fmt.Errorf("creating hybrid certificate: %w", err)
	}
	return m.recordLeaf(issuerCA, der, base.Serial, profile, spec.RequestedBy, spec.Marker)
}

// leafBaseFromCSR builds the shared LeafCertRequest for a PQC/hybrid leaf from a
// parsed CSR's subject, public key, and SANs, applying the profile's usages and
// clamped validity and a fresh random serial.
func (m *Manager) leafBaseFromCSR(publicKey any, parsed *x509.CertificateRequest, spec IssueSpec, profile Profile, issuerCert *x509.Certificate) (pki.LeafCertRequest, error) {
	keyUsage, err := profile.keyUsage()
	if err != nil {
		return pki.LeafCertRequest{}, err
	}
	extKeyUsage, err := profile.extKeyUsage()
	if err != nil {
		return pki.LeafCertRequest{}, err
	}
	now := time.Now()
	validity := profile.resolveValidity(spec.Validity)
	notAfter := now.Add(validity)
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
	}
	serial, err := newSerial()
	if err != nil {
		return pki.LeafCertRequest{}, err
	}
	uris := make([]string, len(parsed.URIs))
	for i, u := range parsed.URIs {
		uris[i] = u.String()
	}
	return pki.LeafCertRequest{
		Subject:        parsed.Subject,
		PublicKey:      publicKey,
		Serial:         serial,
		NotBefore:      now.Add(-clockSkew),
		NotAfter:       notAfter,
		KeyUsage:       keyUsage,
		ExtKeyUsage:    extKeyUsage,
		DNSNames:       parsed.DNSNames,
		IPAddresses:    parsed.IPAddresses,
		EmailAddresses: parsed.EmailAddresses,
		URIs:           uris,
	}, nil
}

// recordLeaf parses a freshly issued PQC/hybrid leaf, persists its bookkeeping
// record, and assembles the IssueResult. CT does not apply, so the record's CT
// status is "none".
func (m *Manager) recordLeaf(issuerCA *models.CA, der []byte, serial *big.Int, profile Profile, requestedBy, marker string) (*IssueResult, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing issued certificate: %w", err)
	}
	leafPEM := pki.EncodeCertificatePEM(der)
	chainPEM := append(append([]byte{}, leafPEM...), []byte(issuerCA.Certificate)...)

	record := &models.IssuedCertificate{
		ID:          uuid.New().String(),
		CAID:        issuerCA.ID,
		Serial:      serial.String(),
		Subject:     cert.Subject.String(),
		CommonName:  cert.Subject.CommonName,
		SANs:        sanStrings(cert),
		Profile:     profile.Name,
		Certificate: string(leafPEM),
		NotBefore:   cert.NotBefore,
		NotAfter:    cert.NotAfter,
		Status:      models.CertStatusValid,
		RequestedBy: requestedBy,
		Marker:      marker,
	}
	applyCTToRecord(record, nil)
	if err := m.db.RecordIssuedCertificate(record); err != nil {
		return nil, fmt.Errorf("recording issued certificate: %w", err)
	}
	return &IssueResult{
		Certificate: cert,
		PEM:         leafPEM,
		ChainPEM:    chainPEM,
		Serial:      serial,
		Profile:     profile.Name,
		Record:      record,
		CT:          &CTStatus{Enabled: false},
	}, nil
}
