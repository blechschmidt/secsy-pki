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
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/caext"
	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/certpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/nameconstraints"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/pqc"
	"github.com/blechschmidt/secsy-pki/server/internal/signpolicy"
)

// clockSkew backdates NotBefore slightly so freshly issued certificates are
// valid on verifiers whose clocks lag a little behind.
const clockSkew = 5 * time.Minute

// Manager performs CA operations against a key provider and a database.
type Manager struct {
	db       *database.DB
	provider keyprovider.Provider
	// signPolicy is the CEL *signing*-restriction gate (Task 224). The manager's
	// certificate gate reads the rule table directly (checkCELPolicy); this one
	// governs the single credential the manager mints with a CA key that is not a
	// certificate: a SPIFFE JWT-SVID. It is built from the same store, so every
	// caller of NewManager gets it without wiring.
	signPolicy celpolicy.SigningChecker
}

// NewManager constructs a CA manager.
func NewManager(db *database.DB, provider keyprovider.Provider) *Manager {
	m := &Manager{db: db, provider: provider}
	if db != nil {
		m.signPolicy = signpolicy.NewGate(db, db)
	}
	return m
}

// SetSigningPolicyGate replaces the signing-restriction gate. It exists for a
// test that wants to drive the gate directly; production wiring happens in
// NewManager. A nil gate disables the check.
func (m *Manager) SetSigningPolicyGate(gate celpolicy.SigningChecker) { m.signPolicy = gate }

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
	// Extensions is the rest of the CA certificate's X.509 v3 extension set:
	// key usage, EKU chaining constraints, subject/issuer alternative names, the
	// AIA/SIA/CRL pointers, inhibitAnyPolicy, the private-key usage period and
	// anything else an operator configures — including arbitrary extensions by
	// OID. The zero value asks for the defaults.
	Extensions *caext.Config
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
	// Extensions is the intermediate's wider X.509 v3 extension set, as in
	// RootSpec. Constraining an issuing CA here — an extKeyUsage of serverAuth
	// only, a narrow private-key usage period, its parent's CRL and OCSP
	// pointers — is where most of this configuration earns its keep.
	Extensions *caext.Config
}

// PKIXName converts an API/CLI subject into a pkix.Name, mapping every field
// that cannot fail to validate. CASubject.ExtraNames needs its attribute types
// resolved and so may be rejected; PKIXNameStrict is the variant that handles it
// and returns an error. Callers that accept an operator-supplied subject should
// prefer PKIXNameStrict — this function exists for the many internal call sites
// that build a subject from a literal.
func PKIXName(s models.CASubject) pkix.Name {
	name, _ := pkixName(s, false)
	return name
}

// PKIXNameStrict converts an API/CLI subject into a pkix.Name including
// CASubject.ExtraNames, rejecting an attribute type it cannot resolve rather
// than silently dropping it — a dropped DN attribute would produce a CA whose
// subject is not the one the operator asked for, which is not something to
// discover after the key exists.
func PKIXNameStrict(s models.CASubject) (pkix.Name, error) {
	return pkixName(s, true)
}

func pkixName(s models.CASubject, strict bool) (pkix.Name, error) {
	name := pkix.Name{
		CommonName:   s.CommonName,
		SerialNumber: s.SerialNumber,
	}
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
	if s.Street != "" {
		name.StreetAddress = []string{s.Street}
	}
	if s.PostalCode != "" {
		name.PostalCode = []string{s.PostalCode}
	}
	// pkix.Name has no field for domainComponent or emailAddress, so they go
	// through ExtraNames — which pkix emits after the modelled attributes, in
	// the order given. Both are defined as IA5String.
	for _, dc := range s.DomainComponents {
		if dc = strings.TrimSpace(dc); dc != "" {
			name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
				Type: oidDomainComponent, Value: ia5Value(dc),
			})
		}
	}
	if email := strings.TrimSpace(s.EmailAddress); email != "" {
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
			Type: oidEmailAddress, Value: ia5Value(email),
		})
	}
	for _, attr := range s.ExtraNames {
		oid, err := parseSubjectAttributeType(attr.Type)
		if err != nil {
			if strict {
				return pkix.Name{}, err
			}
			continue
		}
		if strings.TrimSpace(attr.Value) == "" {
			if strict {
				return pkix.Name{}, fmt.Errorf("distinguished-name attribute %q has no value", attr.Type)
			}
			continue
		}
		var value any = attr.Value
		// The two IA5String-defined attributes keep that encoding when supplied
		// through the generic path too.
		if oid.Equal(oidEmailAddress) || oid.Equal(oidDomainComponent) {
			value = ia5Value(attr.Value)
		}
		name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{Type: oid, Value: value})
	}
	return name, nil
}

// InitRoot generates a key inside the provider and creates a self-signed root
// CA certificate signed by that key. The resulting CA is persisted and returned.
func (m *Manager) InitRoot(ctx context.Context, spec RootSpec) (*models.CA, error) {
	if err := m.validateSpec(spec.Label, spec.KeyType, spec.Subject, spec.Validity); err != nil {
		return nil, err
	}

	now := time.Now()
	req := pki.CACertRequest{
		Subject:    spec.Subject,
		Serial:     big.NewInt(1), // a root's self-signed certificate is serial 1
		NotBefore:  now.Add(-clockSkew),
		NotAfter:   now.Add(spec.Validity),
		MaxPathLen: spec.MaxPathLen,
	}
	if err := applyCAExtensions(&req, spec.NameConstraints, spec.Policies, spec.Extensions); err != nil {
		return nil, err
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
	req := pki.CACertRequest{
		Subject:    spec.Subject,
		Serial:     big.NewInt(serial),
		NotBefore:  now.Add(-clockSkew),
		NotAfter:   notAfter,
		MaxPathLen: spec.MaxPathLen,
	}
	if err := applyCAExtensions(&req, spec.NameConstraints, spec.Policies, spec.Extensions); err != nil {
		return nil, err
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

	ca := &models.CA{
		ID:                          uuid.New().String(),
		TenantID:                    tenantID,
		ParentID:                    parentID,
		Label:                       label,
		PKCS11URI:                   keyInfo.URI,
		KeyType:                     keyInfo.KeyType,
		PublicKey:                   caPublicKeyString(keyInfo),
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

// caPublicKeyString renders a generated key's public half for the CA record's
// non-null public_key column: the OpenSSH form when available, else the DER
// SubjectPublicKeyInfo as PEM (ML-DSA keys have no OpenSSH representation).
func caPublicKeyString(keyInfo *keyprovider.KeyInfo) string {
	if keyInfo.SSHPublicKey != "" {
		return keyInfo.SSHPublicKey
	}
	if der, err := pqc.MarshalPKIXPublicKey(keyInfo.PublicKey); err == nil {
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	return keyInfo.KeyType // last-resort non-null marker
}

// keyRefForCA resolves the provider key reference for a CA from its stored
// PKCS#11 URI, honoring the full RFC 7512 addressing: the object= / id= object
// selectors and the token / serial / slot-id token selectors (so a CA key on a
// specific replica in an HA set is addressed unambiguously). It falls back to the
// CA label when the URI is a bare label, a software: URI without a label, or a
// pkcs11: URI that names no object.
func keyRefForCA(ca *models.CA) keyprovider.KeyRef {
	ref, err := keyprovider.KeyRefFromURI(ca.PKCS11URI)
	if err != nil || (ref.Label == "" && ref.ID == "") {
		return keyprovider.KeyRef{Label: ca.Label}
	}
	return ref
}

// KeyRefForCA exposes the provider key reference the manager uses for a CA's
// signing key, so out-of-package diagnostics (`secsy-ca doctor`) address
// exactly the key the issuance path would use rather than re-deriving it.
func KeyRefForCA(ca *models.CA) keyprovider.KeyRef { return keyRefForCA(ca) }
