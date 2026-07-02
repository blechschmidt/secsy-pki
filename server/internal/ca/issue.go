package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// defaultCRLValidity is how long a generated CRL is valid before a fresh one
// should be published.
const defaultCRLValidity = 7 * 24 * time.Hour

// defaultOCSPValidity bounds how long an OCSP response may be cached.
const defaultOCSPValidity = 24 * time.Hour

// IssueSpec describes an end-entity certificate to issue under a CA.
type IssueSpec struct {
	// CAID identifies the issuing CA. It must be an X.509 CA (have a cert).
	CAID string
	// CSRPEM is a PEM-encoded PKCS#10 certificate signing request. The subject,
	// public key, and SANs are taken from it.
	CSRPEM []byte
	// Profile is the certificate profile name (empty = default profile).
	Profile string
	// Validity overrides the profile's default validity. Zero uses the default;
	// it is always clamped to the profile's maximum and the CA's own expiry.
	Validity time.Duration
	// RequestedBy records who requested the certificate (for audit).
	RequestedBy string
}

// IssueResult is the outcome of issuing an end-entity certificate.
type IssueResult struct {
	Certificate *x509.Certificate
	PEM         []byte
	ChainPEM    []byte
	Serial      *big.Int
	Profile     string
	Record      *models.IssuedCertificate
	// CT summarises Certificate Transparency handling for this issuance. It is
	// always non-nil; CT.Enabled is false when the profile did not request CT.
	CT *CTStatus
}

// applyCTToRecord folds a CT status into the stored certificate record.
func applyCTToRecord(record *models.IssuedCertificate, status *CTStatus) {
	if status == nil || !status.Enabled {
		record.CTStatus = models.CTStatusNone
		return
	}
	record.SCTCount = status.SCTCount
	record.CTLogs = status.succeededLogNames()
	switch {
	case status.Embedded:
		record.CTStatus = models.CTStatusSubmitted
	case status.FailedOpen:
		record.CTStatus = models.CTStatusFailedOpen
	default:
		record.CTStatus = models.CTStatusNone
	}
}

// IssueCertificate signs a CSR into an end-entity certificate under the given
// CA and profile. The serial number is allocated atomically (safe under
// concurrent issuance), the leaf is signed on the provider (HSM), and a copy is
// recorded for renewal and revocation.
func (m *Manager) IssueCertificate(ctx context.Context, spec IssueSpec) (*IssueResult, error) {
	// Follow any key-rotation lineage so new certificates are always minted under
	// the current (newest) signing key. Issuing against a superseded CA id/label
	// transparently uses its active successor; an un-rotated CA resolves to itself.
	activeID, err := m.ActiveIssuerID(spec.CAID)
	if err != nil {
		return nil, err
	}
	issuerCA, issuerCert, err := m.loadIssuer(activeID)
	if err != nil {
		return nil, err
	}

	profile, err := LookupProfile(spec.Profile)
	if err != nil {
		return nil, err
	}

	// Post-quantum and hybrid profiles take dedicated issuance paths: their CSRs
	// carry ML-DSA keys crypto/x509 cannot parse, and their certificates are
	// signed (wholly, or in addition to the classical signature) with ML-DSA.
	switch profile.Algorithm {
	case AlgPQC:
		spec.CAID = activeID
		return m.issuePQCLeaf(ctx, spec, issuerCA, issuerCert, profile)
	case AlgHybrid:
		spec.CAID = activeID
		return m.issueHybridLeaf(ctx, spec, issuerCA, issuerCert, profile)
	}

	csr, err := parseAndVerifyCSR(spec.CSRPEM)
	if err != nil {
		return nil, err
	}

	uris := make([]string, len(csr.URIs))
	for i, u := range csr.URIs {
		uris[i] = u.String()
	}

	return m.issueLeaf(ctx, issuerCA, issuerCert, profile, leafParts{
		Subject:        csr.Subject,
		PublicKey:      csr.PublicKey,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           uris,
	}, spec.Validity, spec.RequestedBy)
}

// TemplateIssueSpec describes an end-entity certificate to issue from a parsed
// subject/public-key template rather than a PKCS#10 CSR. It is used by the CMP
// (RFC 9483) endpoint, whose CertTemplate is not a self-signed CSR; proof of
// possession is verified by the protocol layer before this is called.
type TemplateIssueSpec struct {
	// CAID identifies the issuing CA. It must be an X.509 CA (have a cert).
	CAID string
	// Subject, PublicKey and the SAN fields are taken from the CMP CertTemplate.
	Subject        pkix.Name
	PublicKey      crypto.PublicKey
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []string
	// Profile is the certificate profile name (empty = default profile).
	Profile string
	// Validity overrides the profile default; clamped as in CSR issuance.
	Validity time.Duration
	// RequestedBy records who requested the certificate (for audit).
	RequestedBy string
}

// IssueCertificateFromTemplate signs a subject/public-key template into an
// end-entity certificate. It shares the full HSM-backed issuance path with
// IssueCertificate (serial allocation, pre-issuance lint/CAA gates, CT, and the
// recorded copy for renewal/revocation); only the front end differs. Post-
// quantum and hybrid profiles are rejected here, since their public keys arrive
// via dedicated CSR-based paths.
func (m *Manager) IssueCertificateFromTemplate(ctx context.Context, spec TemplateIssueSpec) (*IssueResult, error) {
	activeID, err := m.ActiveIssuerID(spec.CAID)
	if err != nil {
		return nil, err
	}
	issuerCA, issuerCert, err := m.loadIssuer(activeID)
	if err != nil {
		return nil, err
	}
	profile, err := LookupProfile(spec.Profile)
	if err != nil {
		return nil, err
	}
	if profile.Algorithm != AlgClassical {
		return nil, fmt.Errorf("profile %q is %s; template-based issuance supports classical algorithms only", profile.Name, profile.Algorithm)
	}
	if spec.PublicKey == nil {
		return nil, fmt.Errorf("certificate template has no public key")
	}
	if spec.Subject.CommonName == "" && len(spec.DNSNames) == 0 &&
		len(spec.IPAddresses) == 0 && len(spec.EmailAddresses) == 0 && len(spec.URIs) == 0 {
		return nil, fmt.Errorf("certificate template must contain a subject common name or at least one SAN")
	}
	return m.issueLeaf(ctx, issuerCA, issuerCert, profile, leafParts{
		Subject:        spec.Subject,
		PublicKey:      spec.PublicKey,
		DNSNames:       spec.DNSNames,
		IPAddresses:    spec.IPAddresses,
		EmailAddresses: spec.EmailAddresses,
		URIs:           spec.URIs,
	}, spec.Validity, spec.RequestedBy)
}

// leafParts carries the subject, public key, and SANs of a leaf certificate,
// abstracting over whether they were sourced from a PKCS#10 CSR or a CMP
// CertTemplate so both share one issuance path.
type leafParts struct {
	Subject        pkix.Name
	PublicKey      crypto.PublicKey
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []string
}

// issueLeaf is the shared classical end-entity issuance path: it resolves the
// validity window, allocates a random serial, signs the leaf on the provider
// (HSM) through buildLeaf (which applies the pre-issuance lint/CAA gates and CT
// embedding), and records a copy for renewal/revocation. Both CSR-based and
// template-based issuance funnel through it so the security-sensitive logic
// lives in one place.
func (m *Manager) issueLeaf(ctx context.Context, issuerCA *models.CA, issuerCert *x509.Certificate, profile Profile, parts leafParts, validityOverride time.Duration, requestedBy string) (*IssueResult, error) {
	keyUsage, err := profile.keyUsage()
	if err != nil {
		return nil, err
	}
	extKeyUsage, err := profile.extKeyUsage()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	validity := profile.resolveValidity(validityOverride)
	notBefore := now.Add(-clockSkew)
	notAfter := now.Add(validity)
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
	}

	// Generate an unpredictable serial with 128 bits of entropy (RFC 5280 /
	// CA-Browser-Forum Baseline Requirements: >= 64 bits of entropy so serials
	// cannot be predicted and to add defense-in-depth against hash-collision
	// forgery). Uniqueness per CA is assured in practice by the entropy.
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	signer, err := m.provider.Signer(ctx, keyRefForCA(issuerCA))
	if err != nil {
		return nil, fmt.Errorf("opening issuer signer: %w", err)
	}
	defer signer.Close()

	der, ctStatus, err := m.buildLeaf(ctx, signer, issuerCA, issuerCert, pki.LeafCertRequest{
		Subject:               parts.Subject,
		PublicKey:             parts.PublicKey,
		Serial:                serial,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		DNSNames:              parts.DNSNames,
		IPAddresses:           parts.IPAddresses,
		EmailAddresses:        parts.EmailAddresses,
		URIs:                  parts.URIs,
		CRLDistributionPoints: leafCRLDistributionPoints(issuerCA.ID, serial),
	}, profile, requestedBy)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}

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
	}
	applyCTToRecord(record, ctStatus)
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
		CT:          ctStatus,
	}, nil
}

// RenewSpec describes a renewal of a previously issued certificate.
type RenewSpec struct {
	CAID string
	// Serial identifies the certificate to renew (the certificate the authority
	// previously issued).
	Serial string
	// CSRPEM optionally rekeys the certificate. When empty the original public
	// key and subject are reused.
	CSRPEM []byte
	// Validity overrides the profile default; clamped as in issuance.
	Validity    time.Duration
	RequestedBy string
}

// RenewCertificate reissues a previously issued certificate with a new serial
// and validity window, reusing the original subject/SANs/profile (and public
// key, unless a fresh CSR is supplied). The original certificate is left intact;
// callers may revoke it separately.
func (m *Manager) RenewCertificate(ctx context.Context, spec RenewSpec) (*IssueResult, error) {
	issuerCA, issuerCert, err := m.loadIssuer(spec.CAID)
	if err != nil {
		return nil, err
	}
	if spec.Serial == "" {
		return nil, fmt.Errorf("serial is required to renew a certificate")
	}
	prior, err := m.db.GetIssuedCertificate(issuerCA.ID, spec.Serial)
	if err != nil {
		return nil, fmt.Errorf("looking up certificate to renew: %w", err)
	}
	if prior == nil {
		return nil, fmt.Errorf("no certificate with serial %q issued by this CA", spec.Serial)
	}
	// SECURITY: never renew a revoked certificate. Renewal reuses the prior
	// subject, SANs, and (absent a rekey CSR) public key, so renewing a
	// revoked cert would silently resurrect a credential that was withdrawn —
	// e.g. after key compromise. The revocation store is authoritative; the
	// cached status field is checked too as defense-in-depth.
	if revoked, err := m.db.GetRevokedCertificate(issuerCA.ID, spec.Serial); err != nil {
		return nil, fmt.Errorf("checking revocation status: %w", err)
	} else if revoked != nil || prior.Status == models.CertStatusRevoked {
		return nil, fmt.Errorf("certificate with serial %q is revoked and cannot be renewed; issue a new certificate instead", spec.Serial)
	}
	priorCert, err := pki.ParseCertificatePEM([]byte(prior.Certificate))
	if err != nil {
		return nil, fmt.Errorf("parsing prior certificate: %w", err)
	}

	profile, err := LookupProfile(prior.Profile)
	if err != nil {
		return nil, err
	}
	// Renewal reuses the prior certificate's parsed public key, which crypto/x509
	// cannot recover for ML-DSA subjects. Post-quantum and hybrid certificates are
	// therefore re-issued from a fresh CSR rather than renewed in place.
	if profile.Algorithm != AlgClassical {
		return nil, fmt.Errorf("profile %q is %s; renew-in-place is not supported for post-quantum/hybrid certificates — issue a new certificate from a fresh CSR instead", profile.Name, profile.Algorithm)
	}
	keyUsage, err := profile.keyUsage()
	if err != nil {
		return nil, err
	}
	extKeyUsage, err := profile.extKeyUsage()
	if err != nil {
		return nil, err
	}

	// Determine the subject/public key/SANs to carry forward.
	subject := priorCert.Subject
	publicKey := priorCert.PublicKey
	dnsNames := priorCert.DNSNames
	ipAddresses := priorCert.IPAddresses
	emails := priorCert.EmailAddresses
	var uris []string
	for _, u := range priorCert.URIs {
		uris = append(uris, u.String())
	}
	if len(spec.CSRPEM) > 0 {
		csr, err := parseAndVerifyCSR(spec.CSRPEM)
		if err != nil {
			return nil, err
		}
		subject = csr.Subject
		publicKey = csr.PublicKey
		dnsNames = csr.DNSNames
		ipAddresses = csr.IPAddresses
		emails = csr.EmailAddresses
		uris = uris[:0]
		for _, u := range csr.URIs {
			uris = append(uris, u.String())
		}
	}

	now := time.Now()
	validity := profile.resolveValidity(spec.Validity)
	notAfter := now.Add(validity)
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
	}

	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	signer, err := m.provider.Signer(ctx, keyRefForCA(issuerCA))
	if err != nil {
		return nil, fmt.Errorf("opening issuer signer: %w", err)
	}
	defer signer.Close()

	der, ctStatus, err := m.buildLeaf(ctx, signer, issuerCA, issuerCert, pki.LeafCertRequest{
		Subject:               subject,
		PublicKey:             publicKey,
		Serial:                serial,
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		EmailAddresses:        emails,
		URIs:                  uris,
		CRLDistributionPoints: leafCRLDistributionPoints(issuerCA.ID, serial),
	}, profile, spec.RequestedBy)
	if err != nil {
		return nil, fmt.Errorf("creating renewed certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing renewed certificate: %w", err)
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
		RequestedBy: spec.RequestedBy,
	}
	applyCTToRecord(record, ctStatus)
	if err := m.db.RecordIssuedCertificate(record); err != nil {
		return nil, fmt.Errorf("recording renewed certificate: %w", err)
	}

	return &IssueResult{
		Certificate: cert,
		PEM:         leafPEM,
		ChainPEM:    chainPEM,
		Serial:      serial,
		Profile:     profile.Name,
		Record:      record,
		CT:          ctStatus,
	}, nil
}

// RevokeCertificate records the revocation of a certificate (by serial) issued
// by the given CA. reasonName is an RFC 5280 reason name (empty = unspecified).
// It returns whether the revocation was newly applied.
func (m *Manager) RevokeCertificate(ctx context.Context, caID, serial, reasonName string) (bool, error) {
	if _, _, err := m.loadIssuer(caID); err != nil {
		return false, err
	}
	if _, ok := new(big.Int).SetString(serial, 10); !ok {
		return false, fmt.Errorf("serial %q is not a valid decimal integer", serial)
	}
	reason, err := pki.ParseRevocationReason(reasonName)
	if err != nil {
		return false, err
	}
	return m.db.RevokeCertificate(caID, serial, reason, time.Now())
}

// GenerateCRL builds and signs a fresh CRL for the CA covering all recorded
// revocations. The CRL is signed on the provider (HSM). The returned bytes are
// DER-encoded.
func (m *Manager) GenerateCRL(ctx context.Context, caID string) ([]byte, error) {
	issuerCA, issuerCert, err := m.loadIssuer(caID)
	if err != nil {
		return nil, err
	}

	revoked, err := m.db.ListRevokedCertificates(caID)
	if err != nil {
		return nil, fmt.Errorf("listing revoked certificates: %w", err)
	}
	entries := make([]pki.RevokedEntry, 0, len(revoked))
	for _, rc := range revoked {
		serial, ok := new(big.Int).SetString(rc.Serial, 10)
		if !ok {
			return nil, fmt.Errorf("stored revoked serial %q is not a valid integer", rc.Serial)
		}
		entries = append(entries, pki.RevokedEntry{
			Serial:    serial,
			RevokedAt: rc.RevokedAt,
			Reason:    rc.Reason,
		})
	}

	number, err := m.db.NextCRLNumber(caID)
	if err != nil {
		return nil, fmt.Errorf("allocating CRL number: %w", err)
	}

	signer, err := m.provider.Signer(ctx, keyRefForCA(issuerCA))
	if err != nil {
		return nil, fmt.Errorf("opening issuer signer: %w", err)
	}
	defer signer.Close()

	now := time.Now()
	der, err := pki.CreateCRL(signer, issuerCert, pki.CRLRequest{
		Number:     big.NewInt(number),
		ThisUpdate: now.Add(-clockSkew),
		NextUpdate: now.Add(defaultCRLValidity),
		Revoked:    entries,
	})
	if err != nil {
		return nil, fmt.Errorf("creating CRL: %w", err)
	}
	return der, nil
}

// loadIssuer fetches a CA and its parsed certificate, ensuring it is a usable
// X.509 issuer (has a certificate and is not path-length-0 for leaf issuance is
// not enforced here — leaves are always allowed by any CA).
func (m *Manager) loadIssuer(caID string) (*models.CA, *x509.Certificate, error) {
	if caID == "" {
		return nil, nil, fmt.Errorf("CA id is required")
	}
	issuerCA, err := m.db.GetCA(caID)
	if err != nil {
		return nil, nil, fmt.Errorf("looking up CA: %w", err)
	}
	if issuerCA == nil {
		return nil, nil, fmt.Errorf("CA %q not found", caID)
	}
	if issuerCA.Certificate == "" {
		return nil, nil, fmt.Errorf("CA %q is not an X.509 CA (no certificate)", issuerCA.Label)
	}
	issuerCert, err := pki.ParseCertificatePEM([]byte(issuerCA.Certificate))
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA certificate: %w", err)
	}
	return issuerCA, issuerCert, nil
}

// parseAndVerifyCSR decodes a PEM CSR and verifies its self-signature.
func parseAndVerifyCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid PEM: expected CERTIFICATE REQUEST block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}
	if csr.Subject.CommonName == "" && len(csr.DNSNames) == 0 &&
		len(csr.IPAddresses) == 0 && len(csr.EmailAddresses) == 0 && len(csr.URIs) == 0 {
		return nil, fmt.Errorf("CSR must contain a subject common name or at least one SAN")
	}
	return csr, nil
}

// newSerial returns a cryptographically random, positive certificate serial
// number carrying 128 bits of entropy. Random serials are unpredictable and
// effectively unique per CA, satisfying RFC 5280 §4.1.2.2 and CA/Browser Forum
// guidance (>= 64 bits of entropy) and providing defense-in-depth against
// chosen-prefix hash-collision certificate forgery.
func newSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, fmt.Errorf("generating serial: %w", err)
		}
		if n.Sign() > 0 { // reject the astronomically unlikely zero serial
			return n, nil
		}
	}
}

// sanStrings renders a certificate's subject alternative names as a flat list of
// human-readable strings for storage/audit.
func sanStrings(cert *x509.Certificate) []string {
	var out []string
	out = append(out, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	out = append(out, cert.EmailAddresses...)
	for _, u := range cert.URIs {
		out = append(out, u.String())
	}
	return out
}
