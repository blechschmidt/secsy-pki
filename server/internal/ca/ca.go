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
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/certpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/nameconstraints"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/pqc"
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
	// TenantID is the tenant that will own this root and its entire issuance
	// subtree. Empty defaults to the built-in default tenant.
	TenantID   string
	Label      string
	KeyType    string
	Subject    pkix.Name
	Validity   time.Duration
	MaxPathLen *int // nil = unconstrained
	// Algorithm selects the CA's signature scheme: classical (default), pure
	// post-quantum (ML-DSA), or hybrid (classical primary + ML-DSA alternative).
	Algorithm CertAlgorithm
	// AltKeyType is the ML-DSA parameter set for a hybrid CA's alternative key
	// (empty defaults to ml-dsa-65). Ignored for non-hybrid CAs.
	AltKeyType string
	// NameConstraints, when non-empty, emits an RFC 5280 Name Constraints
	// extension (2.5.29.30) restricting the identities certificates below this CA
	// may assert. Typically set on intermediates rather than a root.
	NameConstraints nameconstraints.Constraints
	// Policies, when non-empty, emits the certificate-policy family of extensions
	// (certificatePolicies / policyMappings / policyConstraints) on the CA cert.
	Policies certpolicy.Policies
}

// IntermediateSpec describes an intermediate CA to issue under an existing CA.
type IntermediateSpec struct {
	ParentID   string
	Label      string
	KeyType    string
	Subject    pkix.Name
	Validity   time.Duration
	MaxPathLen *int // nil = unconstrained
	// Algorithm and AltKeyType select the intermediate's signature scheme, as in
	// RootSpec. A pqc/hybrid intermediate must be issued under a matching parent.
	Algorithm  CertAlgorithm
	AltKeyType string
	// NameConstraints and Policies configure the intermediate's RFC 5280 Name
	// Constraints and certificate-policy extensions, as in RootSpec. Constraining
	// an intermediate is the common enterprise pattern (delegating a scoped subtree
	// to a subordinate CA).
	NameConstraints nameconstraints.Constraints
	Policies        certpolicy.Policies
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

	extraExts, err := caPolicyExtensions(spec.NameConstraints, spec.Policies)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	req := pki.CACertRequest{
		Subject:         spec.Subject,
		Serial:          big.NewInt(1), // a root's self-signed certificate is serial 1
		NotBefore:       now.Add(-clockSkew),
		NotAfter:        now.Add(spec.Validity),
		MaxPathLen:      spec.MaxPathLen,
		ExtraExtensions: extraExts,
	}
	keyInfo, der, err := m.buildAndSignCACert(ctx, spec.Algorithm, spec.Label, spec.KeyType, spec.AltKeyType, req, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("creating root CA certificate: %w", err)
	}

	tenantID := spec.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	return m.persistCA(tenantID, nil, spec.Label, keyInfo, der, req)
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

	// The intermediate's validity is clamped to the parent's expiry.
	now := time.Now()
	notAfter := now.Add(spec.Validity)
	if notAfter.After(parentCert.NotAfter) {
		notAfter = parentCert.NotAfter
	}
	extraExts, err := caPolicyExtensions(spec.NameConstraints, spec.Policies)
	if err != nil {
		return nil, err
	}
	req := pki.CACertRequest{
		Subject:         spec.Subject,
		Serial:          big.NewInt(serial),
		NotBefore:       now.Add(-clockSkew),
		NotAfter:        notAfter,
		MaxPathLen:      spec.MaxPathLen,
		ExtraExtensions: extraExts,
	}
	keyInfo, der, err := m.buildAndSignCACert(ctx, spec.Algorithm, spec.Label, spec.KeyType, spec.AltKeyType, req, parent, parentCert)
	if err != nil {
		return nil, fmt.Errorf("creating intermediate CA certificate: %w", err)
	}

	// A subordinate CA always inherits its parent's tenant, so an intermediate can
	// never cross the isolation boundary.
	return m.persistCA(parent.TenantID, &parent.ID, spec.Label, keyInfo, der, req)
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
func (m *Manager) persistCA(tenantID string, parentID *string, label string, keyInfo *keyprovider.KeyInfo, der []byte, req pki.CACertRequest) (*models.CA, error) {
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parsing signed certificate: %w", err)
	}
	pemBytes := pki.EncodeCertificatePEM(der)

	notBefore := cert.NotBefore
	notAfter := cert.NotAfter
	denySSH := database.BuiltinDenyAllSSH
	denyX509 := database.BuiltinDenyAllX509

	// ML-DSA keys have no OpenSSH representation, so the software provider returns
	// an empty SSHPublicKey for them. Store the DER SubjectPublicKeyInfo (PEM) as
	// the CA's public key so the non-null column always carries the real key.
	publicKey := keyInfo.SSHPublicKey
	if publicKey == "" {
		if der, err := pqc.MarshalPKIXPublicKey(keyInfo.PublicKey); err == nil {
			publicKey = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
		} else {
			publicKey = keyInfo.KeyType // last-resort non-null marker
		}
	}

	ca := &models.CA{
		ID:                          uuid.New().String(),
		TenantID:                    tenantID,
		ParentID:                    parentID,
		Label:                       label,
		PKCS11URI:                   keyInfo.URI,
		KeyType:                     keyInfo.KeyType,
		PublicKey:                   publicKey,
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
