package ca

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
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
}

// IssueCertificate signs a CSR into an end-entity certificate under the given
// CA and profile. The serial number is allocated atomically (safe under
// concurrent issuance), the leaf is signed on the provider (HSM), and a copy is
// recorded for renewal and revocation.
func (m *Manager) IssueCertificate(ctx context.Context, spec IssueSpec) (*IssueResult, error) {
	issuerCA, issuerCert, err := m.loadIssuer(spec.CAID)
	if err != nil {
		return nil, err
	}

	profile, err := LookupProfile(spec.Profile)
	if err != nil {
		return nil, err
	}

	csr, err := parseAndVerifyCSR(spec.CSRPEM)
	if err != nil {
		return nil, err
	}

	keyUsage, err := profile.keyUsage()
	if err != nil {
		return nil, err
	}
	extKeyUsage, err := profile.extKeyUsage()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	validity := profile.resolveValidity(spec.Validity)
	notBefore := now.Add(-clockSkew)
	notAfter := now.Add(validity)
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
	}

	// Allocate the serial only once all validation has passed, so a failed
	// request does not burn a serial number.
	serialN, err := m.db.AllocateSerial(issuerCA.ID)
	if err != nil {
		return nil, fmt.Errorf("allocating serial: %w", err)
	}
	serial := big.NewInt(serialN)

	signer, err := m.provider.Signer(ctx, keyRefForCA(issuerCA))
	if err != nil {
		return nil, fmt.Errorf("opening issuer signer: %w", err)
	}
	defer signer.Close()

	uris := make([]string, len(csr.URIs))
	for i, u := range csr.URIs {
		uris[i] = u.String()
	}

	der, err := pki.CreateLeafCertificate(signer, issuerCert, pki.LeafCertRequest{
		Subject:        csr.Subject,
		PublicKey:      csr.PublicKey,
		Serial:         serial,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
		KeyUsage:       keyUsage,
		ExtKeyUsage:    extKeyUsage,
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           uris,
	})
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
		RequestedBy: spec.RequestedBy,
	}
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
	priorCert, err := pki.ParseCertificatePEM([]byte(prior.Certificate))
	if err != nil {
		return nil, fmt.Errorf("parsing prior certificate: %w", err)
	}

	profile, err := LookupProfile(prior.Profile)
	if err != nil {
		return nil, err
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

	serialN, err := m.db.AllocateSerial(issuerCA.ID)
	if err != nil {
		return nil, fmt.Errorf("allocating serial: %w", err)
	}
	serial := big.NewInt(serialN)

	signer, err := m.provider.Signer(ctx, keyRefForCA(issuerCA))
	if err != nil {
		return nil, fmt.Errorf("opening issuer signer: %w", err)
	}
	defer signer.Close()

	der, err := pki.CreateLeafCertificate(signer, issuerCert, pki.LeafCertRequest{
		Subject:        subject,
		PublicKey:      publicKey,
		Serial:         serial,
		NotBefore:      now.Add(-clockSkew),
		NotAfter:       notAfter,
		KeyUsage:       keyUsage,
		ExtKeyUsage:    extKeyUsage,
		DNSNames:       dnsNames,
		IPAddresses:    ipAddresses,
		EmailAddresses: emails,
		URIs:           uris,
	})
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

// OCSPRespond answers an OCSP request (DER) about a certificate issued by the
// given CA. The response is signed on the provider (HSM). The returned bytes are
// a DER-encoded OCSP response.
func (m *Manager) OCSPRespond(ctx context.Context, caID string, reqDER []byte) ([]byte, error) {
	issuerCA, issuerCert, err := m.loadIssuer(caID)
	if err != nil {
		return nil, err
	}

	req, err := pki.ParseOCSPRequest(reqDER)
	if err != nil {
		return nil, fmt.Errorf("parsing OCSP request: %w", err)
	}

	spec := pki.OCSPResponseSpec{
		Serial:     req.SerialNumber,
		ThisUpdate: time.Now().Add(-clockSkew),
		NextUpdate: time.Now().Add(defaultOCSPValidity),
	}

	serialStr := req.SerialNumber.String()
	revoked, err := m.db.GetRevokedCertificate(caID, serialStr)
	if err != nil {
		return nil, fmt.Errorf("looking up revocation: %w", err)
	}
	switch {
	case revoked != nil:
		spec.Status = pki.OCSPRevoked
		spec.RevokedAt = revoked.RevokedAt
		spec.RevocationReason = revoked.Reason
	default:
		// Distinguish a certificate we know we issued (Good) from one we have no
		// record of (Unknown).
		issued, err := m.db.GetIssuedCertificate(caID, serialStr)
		if err != nil {
			return nil, fmt.Errorf("looking up issued certificate: %w", err)
		}
		if issued == nil {
			spec.Status = pki.OCSPUnknown
		} else {
			spec.Status = pki.OCSPGood
		}
	}

	signer, err := m.provider.Signer(ctx, keyRefForCA(issuerCA))
	if err != nil {
		return nil, fmt.Errorf("opening issuer signer: %w", err)
	}
	defer signer.Close()

	return pki.CreateOCSPResponse(signer, issuerCert, spec)
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
