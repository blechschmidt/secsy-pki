// Package ca implements certificate-authority lifecycle operations backed by a
// key provider (HSM via PKCS#11, or the software keystore).
//
// A CA's private key is generated inside the provider and never leaves it: the
// self-signed root certificate and every intermediate certificate are signed by
// the provider (i.e. on the HSM). Certificates and their metadata — subject,
// serial, validity, path-length constraint — are persisted to the database, and
// each CA gets a monotonic serial counter for the certificates it issues.
package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// clockSkew backdates NotBefore slightly so freshly issued certificates are
// valid on verifiers whose clocks lag a little behind.
const clockSkew = 5 * time.Minute

// Manager performs CA operations against a key provider and a database.
type Manager struct {
	db       *database.DB
	provider keyprovider.Provider
}

// NewManager constructs a CA manager.
func NewManager(db *database.DB, provider keyprovider.Provider) *Manager {
	return &Manager{db: db, provider: provider}
}

// ProviderName returns the human-readable name of the underlying key provider
// (e.g. "pkcs11" or "software"), for transcripts and diagnostics.
func (m *Manager) ProviderName() string {
	return m.provider.Name()
}

// RootSpec describes a root CA to initialize.
type RootSpec struct {
	Label      string
	KeyType    string
	Subject    pkix.Name
	Validity   time.Duration
	MaxPathLen *int // nil = unconstrained
}

// IntermediateSpec describes an intermediate CA to issue under an existing CA.
type IntermediateSpec struct {
	ParentID   string
	Label      string
	KeyType    string
	Subject    pkix.Name
	Validity   time.Duration
	MaxPathLen *int // nil = unconstrained
}

// PKIXName converts an API/CLI subject into a pkix.Name.
func PKIXName(s models.CASubject) pkix.Name {
	name := pkix.Name{CommonName: s.CommonName}
	if s.Organization != "" {
		name.Organization = []string{s.Organization}
	}
	if s.OrganizationalUnit != "" {
		name.OrganizationalUnit = []string{s.OrganizationalUnit}
	}
	if s.Country != "" {
		name.Country = []string{s.Country}
	}
	if s.Province != "" {
		name.Province = []string{s.Province}
	}
	if s.Locality != "" {
		name.Locality = []string{s.Locality}
	}
	return name
}

// InitRoot generates a key inside the provider and creates a self-signed root
// CA certificate signed by that key. The resulting CA is persisted and returned.
func (m *Manager) InitRoot(ctx context.Context, spec RootSpec) (*models.CA, error) {
	if err := m.validateSpec(spec.Label, spec.KeyType, spec.Subject, spec.Validity); err != nil {
		return nil, err
	}

	keyInfo, err := m.provider.GenerateKey(ctx, keyprovider.KeySpec{Label: spec.Label, KeyType: spec.KeyType})
	if err != nil {
		return nil, fmt.Errorf("generating root CA key: %w", err)
	}

	signer, err := m.provider.Signer(ctx, keyprovider.KeyRef{Label: spec.Label})
	if err != nil {
		return nil, fmt.Errorf("opening root CA signer: %w", err)
	}
	defer signer.Close()

	now := time.Now()
	req := pki.CACertRequest{
		Subject:    spec.Subject,
		PublicKey:  keyInfo.PublicKey,
		Serial:     big.NewInt(1), // a root's self-signed certificate is serial 1
		NotBefore:  now.Add(-clockSkew),
		NotAfter:   now.Add(spec.Validity),
		MaxPathLen: spec.MaxPathLen,
	}
	der, err := pki.CreateCACertificate(signer, nil, req)
	if err != nil {
		return nil, fmt.Errorf("creating root CA certificate: %w", err)
	}

	return m.persistCA(nil, spec.Label, keyInfo, der, req)
}

// IssueIntermediate generates a key inside the provider and creates an
// intermediate CA certificate signed by the parent CA (on the HSM). The parent
// must already be an X.509 CA (have a certificate).
func (m *Manager) IssueIntermediate(ctx context.Context, spec IntermediateSpec) (*models.CA, error) {
	if spec.ParentID == "" {
		return nil, fmt.Errorf("parent CA is required")
	}
	if err := m.validateSpec(spec.Label, spec.KeyType, spec.Subject, spec.Validity); err != nil {
		return nil, err
	}

	parent, err := m.db.GetCA(spec.ParentID)
	if err != nil {
		return nil, fmt.Errorf("looking up parent CA: %w", err)
	}
	if parent == nil {
		return nil, fmt.Errorf("parent CA %q not found", spec.ParentID)
	}
	if parent.Certificate == "" {
		return nil, fmt.Errorf("parent CA %q is not an X.509 CA (no certificate)", parent.Label)
	}
	parentCert, err := pki.ParseCertificatePEM([]byte(parent.Certificate))
	if err != nil {
		return nil, fmt.Errorf("parsing parent CA certificate: %w", err)
	}
	if err := m.checkPathLen(parent, parentCert); err != nil {
		return nil, err
	}

	// Allocate the intermediate's serial from the parent's counter.
	serial, err := m.db.AllocateSerial(parent.ID)
	if err != nil {
		return nil, fmt.Errorf("allocating serial from parent CA: %w", err)
	}

	keyInfo, err := m.provider.GenerateKey(ctx, keyprovider.KeySpec{Label: spec.Label, KeyType: spec.KeyType})
	if err != nil {
		return nil, fmt.Errorf("generating intermediate CA key: %w", err)
	}

	parentSigner, err := m.provider.Signer(ctx, keyRefForCA(parent))
	if err != nil {
		return nil, fmt.Errorf("opening parent CA signer: %w", err)
	}
	defer parentSigner.Close()

	// The intermediate's validity is clamped to the parent's expiry.
	now := time.Now()
	notAfter := now.Add(spec.Validity)
	if notAfter.After(parentCert.NotAfter) {
		notAfter = parentCert.NotAfter
	}
	req := pki.CACertRequest{
		Subject:    spec.Subject,
		PublicKey:  keyInfo.PublicKey,
		Serial:     big.NewInt(serial),
		NotBefore:  now.Add(-clockSkew),
		NotAfter:   notAfter,
		MaxPathLen: spec.MaxPathLen,
	}
	der, err := pki.CreateCACertificate(parentSigner, parentCert, req)
	if err != nil {
		return nil, fmt.Errorf("creating intermediate CA certificate: %w", err)
	}

	return m.persistCA(&parent.ID, spec.Label, keyInfo, der, req)
}

// validateSpec performs shared request validation, including key-type
// normalization and a label-uniqueness check against the database.
func (m *Manager) validateSpec(label, keyType string, subject pkix.Name, validity time.Duration) error {
	if label == "" {
		return fmt.Errorf("CA label is required")
	}
	if subject.CommonName == "" {
		return fmt.Errorf("subject common name (CN) is required")
	}
	if validity <= 0 {
		return fmt.Errorf("validity must be positive")
	}
	if _, err := keyprovider.NormalizeKeyType(keyType); err != nil {
		return err
	}
	existing, err := m.db.GetCAByLabel(label)
	if err != nil {
		return fmt.Errorf("checking for existing CA: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("a CA with label %q already exists", label)
	}
	return nil
}

// checkPathLen rejects issuing an intermediate when the parent's basic
// constraints forbid a subordinate CA below it.
func (m *Manager) checkPathLen(parent *models.CA, parentCert *x509.Certificate) error {
	// MaxPathLenZero means the parent may not have any CA beneath it.
	if parentCert.MaxPathLenZero {
		return fmt.Errorf("parent CA %q has a path-length constraint of 0 and cannot issue intermediate CAs", parent.Label)
	}
	return nil
}

// persistCA parses the freshly signed certificate, records its metadata, and
// stores the CA. It sets deny-all default restriction sets so a new CA cannot
// sign anything until an operator configures it (issuance is handled elsewhere).
func (m *Manager) persistCA(parentID *string, label string, keyInfo *keyprovider.KeyInfo, der []byte, req pki.CACertRequest) (*models.CA, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing signed certificate: %w", err)
	}
	pemBytes := pki.EncodeCertificatePEM(der)

	notBefore := cert.NotBefore
	notAfter := cert.NotAfter
	denySSH := database.BuiltinDenyAllSSH
	denyX509 := database.BuiltinDenyAllX509

	ca := &models.CA{
		ID:                          uuid.New().String(),
		ParentID:                    parentID,
		Label:                       label,
		PKCS11URI:                   keyInfo.URI,
		KeyType:                     keyInfo.KeyType,
		PublicKey:                   keyInfo.SSHPublicKey,
		DefaultSSHRestrictionSetID:  &denySSH,
		DefaultX509RestrictionSetID: &denyX509,
		Certificate:                 string(pemBytes),
		Subject:                     cert.Subject.String(),
		Serial:                      req.Serial.String(),
		NotBefore:                   &notBefore,
		NotAfter:                    &notAfter,
		MaxPathLen:                  req.MaxPathLen,
		Status:                      models.CAStatusActive,
	}
	if err := m.db.CreateCA(ca); err != nil {
		return nil, fmt.Errorf("persisting CA: %w", err)
	}
	return ca, nil
}

// keyRefForCA resolves the provider key reference for a CA, preferring the
// object= label embedded in its PKCS#11 URI and falling back to its label.
func keyRefForCA(ca *models.CA) keyprovider.KeyRef {
	label := pki.ExtractKeyLabel(ca.PKCS11URI)
	if label == "" {
		label = ca.Label
	}
	return keyprovider.KeyRef{Label: label}
}
