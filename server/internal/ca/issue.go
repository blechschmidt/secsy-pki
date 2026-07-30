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
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/caa"
	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
	"go.opentelemetry.io/otel/attribute"
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
	// Marker tags the stored record as synthetic (e.g. models.CertMarkerCanary)
	// so monitoring and reports can exclude it. It is internal plumbing for
	// system probes and is never settable through the API layers.
	Marker string

	// ACMEAccountURI and ValidationMethods carry the RFC 8657 CAA-binding facts of
	// an ACME-driven issuance, threaded into the pre-issuance CAA gate. They are
	// set only by the ACME finalize path (see internal/acme); every other caller
	// leaves them empty, and an empty value makes a record's accounturi/
	// validationmethods parameter unsatisfiable (blocking under CAA enforce mode).
	//
	// ACMEAccountURI is the requesting ACME account's URL. ValidationMethods maps a
	// normalized DNS identifier (lowercased, trailing dot and "*." stripped) to the
	// validation method (challenge type: "http-01", "dns-01", "tls-alpn-01") that
	// satisfied it.
	ACMEAccountURI    string
	ValidationMethods map[string]string

	// MustStaple optionally overrides the profile's RFC 7633 OCSP Must-Staple
	// default for this one certificate. It is honored only when the profile sets
	// allow_must_staple_override; nil (the common case) uses the profile default.
	// Set by the REST/gRPC issue paths from an optional per-request field.
	MustStaple *bool

	// UPNs are Microsoft/Kerberos User Principal Names ("user@REALM") to emit as
	// id-ms-UPN otherName SANs (Task 122). They are honored only under a profile
	// that declares UPN support (smartcard-logon / pkinit-client / a custom UPN
	// profile) and are validated and realm-allowlist-checked before signing.
	UPNs []string

	// PSD2 optionally supplies the ETSI TS 119 495 PSD2 authorization (roles +
	// NCA) for the eIDAS QCStatements extension (Task 128). It is honored only
	// under a profile whose qcstatements block enables PSD2 overrides
	// (allow_psd2_override); on any other profile it is a hard error. Set by the
	// REST/gRPC/CLI issue paths from an optional per-request field.
	PSD2 *models.PSD2QCStatement

	// PrivateKeyUsagePeriod optionally overrides the profile's RFC 5280
	// id-ce-privateKeyUsagePeriod window (Task 132) for this one certificate. It is
	// honored only under a profile whose private_key_usage_period block permits
	// overrides (allow_override); on any other profile it is a hard error. Set by
	// the REST/gRPC/CLI issue paths from an optional per-request field.
	PrivateKeyUsagePeriod *models.PrivateKeyUsagePeriod
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

// applyCTToRecord folds a CT status into the stored certificate record. When the
// SCT policy failed open (a fail-open profile whose policy was not fully met) the
// record is marked failed_open even if some SCTs were still embedded — the
// fail-open is the operationally important signal (e.g. SCTs obtained but from
// too few distinct operators to satisfy min_distinct_operators), and inclusion
// monitoring keys off sct_count rather than this status, so surfacing the
// shortfall here costs no monitoring coverage.
func applyCTToRecord(record *models.IssuedCertificate, status *CTStatus) {
	if status == nil || !status.Enabled {
		record.CTStatus = models.CTStatusNone
		return
	}
	record.SCTCount = status.SCTCount
	record.CTLogs = status.succeededLogNames()
	switch {
	case status.FailedOpen:
		record.CTStatus = models.CTStatusFailedOpen
	case status.Embedded:
		record.CTStatus = models.CTStatusSubmitted
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

	// User Principal Name SANs (smartcard-logon / PKINIT) are a classical-only
	// feature: the dedicated ML-DSA paths below build their own leaf and would
	// silently drop a requested UPN, so reject the misconfiguration up front.
	if len(spec.UPNs) > 0 && profile.Algorithm != AlgClassical {
		return nil, fmt.Errorf("profile %q is %s; User Principal Name SANs are supported on classical profiles only", profile.Name, profile.Algorithm)
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
		UPNs:           spec.UPNs,
		psd2:           spec.PSD2,
		pkup:           spec.PrivateKeyUsagePeriod,
		Marker:         spec.Marker,
		caaContext: caa.RequestContext{
			AccountURI:        spec.ACMEAccountURI,
			ValidationMethods: spec.ValidationMethods,
		},
		mustStaple: spec.MustStaple,
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
	// MustStaple optionally overrides the profile's RFC 7633 Must-Staple default
	// (honored only when the profile permits per-request overrides). Nil uses the
	// profile default.
	MustStaple *bool
	// UPNs are User Principal Name otherName SANs to emit (Task 122), honored only
	// under a UPN-enabled profile.
	UPNs []string
	// PSD2 optionally supplies the ETSI TS 119 495 PSD2 authorization for the
	// eIDAS QCStatements extension (Task 128), honored only under a QC-enabled
	// profile that permits per-request PSD2 overrides.
	PSD2 *models.PSD2QCStatement
	// PrivateKeyUsagePeriod optionally overrides the profile's RFC 5280
	// id-ce-privateKeyUsagePeriod window (Task 132), honored only under a profile
	// whose private_key_usage_period block permits per-request overrides.
	PrivateKeyUsagePeriod *models.PrivateKeyUsagePeriod
	// Marker tags the stored record as synthetic (e.g. models.CertMarkerServingTLS
	// for the self-managed serving-TLS certificate) so monitoring and reports can
	// exclude it. It is internal plumbing; the REST/gRPC layers never set it.
	Marker string
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
		UPNs:           spec.UPNs,
		psd2:           spec.PSD2,
		pkup:           spec.PrivateKeyUsagePeriod,
		Marker:         spec.Marker,
		mustStaple:     spec.MustStaple,
	}, spec.Validity, spec.RequestedBy)
}

// leafParts carries the subject, public key, and SANs of a leaf certificate,
// abstracting over whether they were sourced from a PKCS#10 CSR or a CMP
// CertTemplate so both share one issuance path. Marker rides along for the
// stored record only; it never affects certificate contents.
type leafParts struct {
	Subject        pkix.Name
	PublicKey      crypto.PublicKey
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []string
	// UPNs are Microsoft/Kerberos User Principal Name otherName SANs (Task 122).
	UPNs []string
	// psd2 is the per-request ETSI TS 119 495 PSD2 authorization override for the
	// eIDAS QCStatements extension (Task 128), if any.
	psd2 *models.PSD2QCStatement
	// pkup is the per-request RFC 5280 private-key usage period override
	// (id-ce-privateKeyUsagePeriod, Task 132), if any.
	pkup   *models.PrivateKeyUsagePeriod
	Marker string
	// caaContext carries the RFC 8657 CAA-binding facts of the request (ACME
	// account URI and per-identifier validation method) into buildLeaf's CAA gate.
	// It is the zero value for every non-ACME issuance path.
	caaContext caa.RequestContext
	// mustStaple optionally overrides the profile's RFC 7633 Must-Staple default
	// (honored only when the profile permits per-request overrides). Nil uses the
	// profile default.
	mustStaple *bool
}

// issueLeaf is the shared classical end-entity issuance path: it resolves the
// validity window, allocates a random serial, signs the leaf on the provider
// (HSM) through buildLeaf (which applies the pre-issuance lint/CAA gates and CT
// embedding), and records a copy for renewal/revocation. Both CSR-based and
// template-based issuance funnel through it so the security-sensitive logic
// lives in one place.
func (m *Manager) issueLeaf(ctx context.Context, issuerCA *models.CA, issuerCert *x509.Certificate, profile Profile, parts leafParts, validityOverride time.Duration, requestedBy string) (_ *IssueResult, err error) {
	ctx, span := tracing.Start(ctx, "ca.issue_leaf",
		attribute.String("ca.id", issuerCA.ID),
		attribute.String("ca.profile", profile.Name))
	defer func() { tracing.End(span, err) }()

	// Tenant lifecycle + quota gate (fail-closed), before any HSM work. The
	// reservation it takes is committed or released by the final issuance error.
	gateDone, err := m.gateTenantIssuance(ctx, issuerCA, requestedBy)
	if err != nil {
		return nil, err
	}
	defer func() { gateDone(err) }()

	keyUsage, err := profile.keyUsage()
	if err != nil {
		return nil, err
	}
	extKeyUsage, unknownEKU, err := profile.extKeyUsage()
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

	base := pki.LeafCertRequest{
		Subject:               parts.Subject,
		PublicKey:             parts.PublicKey,
		Serial:                serial,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		UnknownExtKeyUsage:    unknownEKU,
		DNSNames:              parts.DNSNames,
		IPAddresses:           parts.IPAddresses,
		EmailAddresses:        parts.EmailAddresses,
		URIs:                  parts.URIs,
		UPNs:                  parts.UPNs,
		CRLDistributionPoints: leafCRLDistributionPoints(issuerCA.ID, serial),
	}

	// Stamp the eIDAS QCStatements extension (ETSI EN 319 412-5, Task 128) when
	// the profile is QC-enabled, merging any per-request PSD2 override. Applied
	// before buildLeaf so it is present for the pre-issuance lint gate and, being
	// part of base.ExtraExtensions, is carried identically by the precertificate
	// and the final certificate (keeping the TBSCertificates aligned for CT).
	base, err = applyQCStatements(base, profile, parts.psd2)
	if err != nil {
		return nil, err
	}

	// Stamp the RFC 5280 private-key usage period (id-ce-privateKeyUsagePeriod,
	// Task 132) when the profile configures one, merging any per-request override.
	// Resolved against this leaf's validity window (base.NotBefore/NotAfter) so a
	// duration/fraction is computed from the actual window, and applied here — like
	// QCStatements — so it is present for the pre-issuance lint gate and carried
	// identically by the precertificate and the final certificate.
	base, err = applyPrivateKeyUsagePeriod(base, profile, parts.pkup)
	if err != nil {
		return nil, err
	}

	der, ctStatus, err := m.buildLeaf(ctx, signer, issuerCA, issuerCert, base,
		profile, requestedBy, parts.caaContext, profile.resolveMustStaple(parts.mustStaple))
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
		ID:                   uuid.New().String(),
		CAID:                 issuerCA.ID,
		Serial:               serial.String(),
		Subject:              cert.Subject.String(),
		CommonName:           cert.Subject.CommonName,
		SANs:                 sanStrings(cert),
		Profile:              profile.Name,
		Certificate:          string(leafPEM),
		NotBefore:            cert.NotBefore,
		NotAfter:             cert.NotAfter,
		Status:               models.CertStatusValid,
		RequestedBy:          requestedBy,
		Marker:               parts.Marker,
		PublicKeyFingerprint: subjectKeyFingerprint(cert.PublicKey),
	}
	applyCTToRecord(record, ctStatus)
	span.SetAttributes(attribute.String("cert.serial", serial.String()))
	if err := traceStore(ctx, "store.record_issued_certificate", func() error {
		return m.db.RecordIssuedCertificate(record)
	}); err != nil {
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
func (m *Manager) RenewCertificate(ctx context.Context, spec RenewSpec) (_ *IssueResult, err error) {
	issuerCA, issuerCert, err := m.loadIssuer(spec.CAID)
	if err != nil {
		return nil, err
	}
	// Renewal mints a new certificate, so it passes the same tenant lifecycle +
	// quota gate as first-time issuance (fail-closed, reservation released on
	// any later failure).
	gateDone, err := m.gateTenantIssuance(ctx, issuerCA, spec.RequestedBy)
	if err != nil {
		return nil, err
	}
	defer func() { gateDone(err) }()
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
	extKeyUsage, unknownEKU, err := profile.extKeyUsage()
	if err != nil {
		return nil, err
	}

	// Determine the subject/public key/SANs to carry forward. The prior UPN
	// otherName SANs are recovered from the raw subjectAltName extension (crypto/
	// x509 surfaces no typed field for otherName) so a renewed smartcard-logon
	// certificate keeps its User Principal Name.
	subject := priorCert.Subject
	publicKey := priorCert.PublicKey
	dnsNames := priorCert.DNSNames
	ipAddresses := priorCert.IPAddresses
	emails := priorCert.EmailAddresses
	upns := pki.UPNsFromCertificate(priorCert)
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
		upns = pki.UPNsFromCSR(csr)
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

	// Preserve the RFC 7633 Must-Staple commitment across renewal: stamp it when
	// the profile now requires it OR the certificate being renewed already carried
	// it (e.g. via a per-request override at first issuance). Renewal never drops a
	// Must-Staple commitment the subscriber already relies on.
	mustStaple := profile.MustStaple || certHasMustStaple(priorCert)

	renewBase := pki.LeafCertRequest{
		Subject:               subject,
		PublicKey:             publicKey,
		Serial:                serial,
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		UnknownExtKeyUsage:    unknownEKU,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		EmailAddresses:        emails,
		URIs:                  uris,
		UPNs:                  upns,
		CRLDistributionPoints: leafCRLDistributionPoints(issuerCA.ID, serial),
	}
	// Re-apply the profile's RFC 5280 private-key usage period (Task 132) on
	// renewal, recomputed against the new validity window (a duration/fraction must
	// be measured from the fresh notBefore/notAfter, so copying the prior cert's
	// absolute bounds would be wrong). Renewal takes no per-request override.
	renewBase, err = applyPrivateKeyUsagePeriod(renewBase, profile, nil)
	if err != nil {
		return nil, fmt.Errorf("applying private-key usage period: %w", err)
	}

	der, ctStatus, err := m.buildLeaf(ctx, signer, issuerCA, issuerCert, renewBase,
		profile, spec.RequestedBy, caa.RequestContext{}, mustStaple)
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
		// A renewal of a synthetic certificate is itself synthetic.
		Marker:               prior.Marker,
		PublicKeyFingerprint: subjectKeyFingerprint(cert.PublicKey),
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
	applied, err := m.db.RevokeCertificate(caID, serial, reason, time.Now())
	if err == nil && applied {
		// Usage accounting only — revocation is never quota-gated, and a
		// suspended tenant's certificates must remain revocable.
		m.accountTenantRevocation(caID)
	}
	return applied, err
}

// GenerateCRL builds and signs a fresh CRL for the CA covering all recorded
// revocations. The CRL is signed on the provider (HSM). The returned bytes are
// DER-encoded.
func (m *Manager) GenerateCRL(ctx context.Context, caID string) (_ []byte, err error) {
	ctx, span := tracing.Start(ctx, "ca.generate_crl", attribute.String("ca.id", caID))
	defer func() { tracing.End(span, err) }()

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

	span.SetAttributes(attribute.Int("crl.revoked_count", len(entries)))
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

// traceStore runs a persistence-store call inside a span so Postgres/SQLite
// queries on the issuance path are visible in the trace and their latency is
// attributable. It records a store error on the span. The DB methods do not take
// a context, so the span parent is threaded from the caller's issuance context.
func traceStore(ctx context.Context, name string, fn func() error) error {
	_, span := tracing.Start(ctx, name, attribute.String("db.operation", name))
	defer span.End()
	err := fn()
	if err != nil {
		span.RecordError(err)
	}
	return err
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

// decodeAndVerifyCSR decodes a PEM CSR and verifies its self-signature, without
// requiring it to carry any subject or SAN. It is the shared front half of
// parseAndVerifyCSR, used directly by SVID issuance where the identity comes from
// the request (the spiffe:// URI) rather than the CSR — so a bare public-key CSR
// is valid.
func decodeAndVerifyCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
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
	return csr, nil
}

// parseAndVerifyCSR decodes a PEM CSR, verifies its self-signature, and requires
// it to carry a subject common name or at least one SAN (so the issued
// certificate has an identity). SVID issuance uses decodeAndVerifyCSR instead.
func parseAndVerifyCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	csr, err := decodeAndVerifyCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	if csr.Subject.CommonName == "" && len(csr.DNSNames) == 0 &&
		len(csr.IPAddresses) == 0 && len(csr.EmailAddresses) == 0 && len(csr.URIs) == 0 {
		return nil, fmt.Errorf("CSR must contain a subject common name or at least one SAN")
	}
	return csr, nil
}

// CSRIdentity is the subject and SANs extracted from a verified PKCS#10 CSR.
// The per-profile issuance-approval gate (Task 84) uses it to validate a request
// up front and to describe and fingerprint it while it is parked for approval.
type CSRIdentity struct {
	// Subject is the RFC 2253 string form of the CSR subject DN.
	Subject string
	// SANs are the CSR's DNS, IP, e-mail, and URI subject alternative names as
	// flat strings, sorted so the fingerprint is stable regardless of ordering.
	SANs []string
}

// InspectCSRForIssue decodes and verifies a PEM PKCS#10 CSR exactly as the leaf
// issuance path does (valid self-signature and at least one identity), returning
// its subject and SANs. It lets the operator/API issuance-approval gate reject
// malformed requests before parking them and derive a stable request
// fingerprint, without duplicating the CSR-validation rules.
func InspectCSRForIssue(csrPEM []byte) (CSRIdentity, error) {
	csr, err := parseAndVerifyCSR(csrPEM)
	if err != nil {
		return CSRIdentity{}, err
	}
	var sans []string
	sans = append(sans, csr.DNSNames...)
	for _, ip := range csr.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, csr.EmailAddresses...)
	for _, u := range csr.URIs {
		sans = append(sans, u.String())
	}
	sort.Strings(sans)
	return CSRIdentity{Subject: csr.Subject.String(), SANs: sans}, nil
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

// subjectKeyFingerprint returns the "SHA256:<base64>" SubjectPublicKeyInfo
// fingerprint of a certified public key for the inventory record, or "" when the
// key cannot be marshaled (e.g. an ML-DSA subject on a PQC path). It is the key by
// which the pre-issuance gate detects a reused subject key and by which a
// compromised key can be located across the inventory.
func subjectKeyFingerprint(pub crypto.PublicKey) string {
	fp, err := keycheck.Fingerprint(pub)
	if err != nil {
		return ""
	}
	return fp
}

// sanStrings renders a certificate's subject alternative names as a flat list of
// human-readable strings for storage/audit. UPN otherName SANs (which crypto/
// x509 surfaces on no typed field) are recovered from the raw extension and
// rendered "upn:user@REALM" so the inventory and audit trail record them.
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
	for _, u := range pki.UPNsFromCertificate(cert) {
		out = append(out, "upn:"+u)
	}
	return out
}
