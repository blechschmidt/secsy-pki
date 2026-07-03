package sshca

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	// Aliased because Sign's local variable for the CA record is named "ca".
	capkg "github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// DefaultCAKeyType is the key type used when an SSH CA is initialized without
// naming one. Ed25519 is the modern OpenSSH default and is supported by the
// software keystore, SoftHSM (CKM_EDDSA), and YubiHSM; HSMs lacking an EdDSA
// mechanism should use ecdsa-p256 instead.
const DefaultCAKeyType = "ed25519"

// clockSkewBackdate is subtracted from a certificate's ValidAfter so a
// freshly signed certificate is immediately usable on hosts whose clocks lag
// slightly, matching the X.509 issuance path's habit.
const clockSkewBackdate = 5 * time.Minute

// Authority signs OpenSSH certificates with CA keys held by the configured key
// provider. The private key never leaves the backend: signing goes through
// crypto.Signer (ssh.NewSignerFromSigner), so a PKCS#11 HSM performs the raw
// signature operation.
type Authority struct {
	db       *database.DB
	provider keyprovider.Provider
	// now is the time source, overridable in tests.
	now func() time.Time
}

// NewAuthority builds an SSH certificate authority over the shared store and
// key provider.
func NewAuthority(db *database.DB, provider keyprovider.Provider) *Authority {
	return &Authority{db: db, provider: provider, now: time.Now}
}

// CASpec describes a new SSH certificate authority.
type CASpec struct {
	// TenantID is the owning tenant; empty means the default tenant.
	TenantID string
	// Label is the CA's unique label; it doubles as the provider key label.
	Label string
	// KeyType is a keyprovider key type (ed25519, ecdsa-p256, rsa-2048, …);
	// empty defaults to DefaultCAKeyType.
	KeyType string
}

// InitCA generates a new CA key pair inside the key provider and persists the
// CA record. The returned CA's PublicKey field is the authorized_keys line
// relying hosts pin as TrustedUserCAKeys (user certs) or as a @cert-authority
// known_hosts entry (host certs).
func (a *Authority) InitCA(ctx context.Context, spec CASpec) (*models.CA, error) {
	label := strings.TrimSpace(spec.Label)
	if label == "" {
		return nil, fmt.Errorf("a CA label is required")
	}
	keyType := spec.KeyType
	if keyType == "" {
		keyType = DefaultCAKeyType
	}
	normalized, err := keyprovider.NormalizeKeyType(keyType)
	if err != nil {
		return nil, err
	}

	tenantID := spec.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	tenant, err := a.db.GetTenant(tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant lookup failed: %w", err)
	}
	if tenant == nil {
		return nil, fmt.Errorf("unknown tenant %q", tenantID)
	}

	if existing, err := a.db.GetCAByLabel(label); err != nil {
		return nil, fmt.Errorf("checking for existing CA: %w", err)
	} else if existing != nil {
		return nil, fmt.Errorf("a CA labeled %q already exists", label)
	}

	info, err := a.provider.GenerateKey(ctx, keyprovider.KeySpec{Label: label, KeyType: normalized})
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}
	if info.SSHPublicKey == "" {
		return nil, fmt.Errorf("key type %q has no OpenSSH representation and cannot back an SSH CA", normalized)
	}

	// New SSH CAs default to the built-in deny-all restriction sets, matching
	// the legacy key-creation path: the legacy per-key signing endpoint stays
	// closed until an operator explicitly opens it. The profile-driven signing
	// path is governed by RBAC and profiles, not by these defaults.
	denySSH := database.BuiltinDenyAllSSH
	denyX509 := database.BuiltinDenyAllX509
	ca := &models.CA{
		ID:                          uuid.New().String(),
		TenantID:                    tenantID,
		Label:                       label,
		PKCS11URI:                   info.URI,
		KeyType:                     info.KeyType,
		PublicKey:                   info.SSHPublicKey,
		DefaultSSHRestrictionSetID:  &denySSH,
		DefaultX509RestrictionSetID: &denyX509,
		Status:                      models.CAStatusActive,
	}
	if err := a.db.CreateCA(ca); err != nil {
		return nil, fmt.Errorf("persisting CA: %w", err)
	}
	return ca, nil
}

// SignRequest asks a CA to sign an OpenSSH public key into a certificate.
type SignRequest struct {
	// CAID identifies the signing CA (its store ID).
	CAID string
	// CertType is "user" (default) or "host".
	CertType string
	// PublicKey is the authorized_keys line of the key to certify.
	PublicKey string
	// KeyID is the certificate's key ID, recorded in host auth logs. Empty
	// defaults to RequestedBy, then the first principal.
	KeyID string
	// Principals are the user names (user certs) or host names (host certs)
	// the certificate is valid for.
	Principals []string
	// Profile names the signing profile; empty selects the built-in default for
	// the certificate type.
	Profile string
	// Validity is the requested lifetime; zero applies the profile default, and
	// values beyond the profile maximum are clamped.
	Validity time.Duration
	// Extensions/CriticalOptions replace the profile defaults when non-empty;
	// every key must be permitted by the profile.
	Extensions      map[string]string
	CriticalOptions map[string]string
	// RequestedBy is the requesting subject, recorded in the inventory.
	RequestedBy string
}

// SignResult is a signed OpenSSH certificate plus its inventory record.
type SignResult struct {
	// Certificate is the parsed signed certificate.
	Certificate *ssh.Certificate
	// AuthorizedKey is the single-line authorized_keys encoding (what OpenSSH
	// expects in an -cert.pub file).
	AuthorizedKey []byte
	// Record is the stored inventory row.
	Record *models.SSHCertificate
	// CA is the signing CA.
	CA *models.CA
}

// Sign validates a request against its profile, allocates the next serial from
// the CA's monotonic counter, and signs the certificate with the CA's
// HSM-held key.
func (a *Authority) Sign(ctx context.Context, req SignRequest) (_ *SignResult, err error) {
	ca, err := a.db.GetCA(req.CAID)
	if err != nil {
		return nil, fmt.Errorf("loading CA: %w", err)
	}
	if ca == nil {
		return nil, fmt.Errorf("CA %q not found", req.CAID)
	}
	if ca.Status != "" && ca.Status != models.CAStatusActive {
		return nil, fmt.Errorf("CA %q is %s and no longer signs certificates", ca.Label, ca.Status)
	}
	// SSH certificates mint from the same tenant-owned CA records as X.509, so
	// they pass the same tenant lifecycle + daily-quota gate (Task 61).
	gateDone, err := capkg.GateTenantIssuance(a.db, ca, req.RequestedBy)
	if err != nil {
		return nil, err
	}
	defer func() { gateDone(err) }()

	certType := req.CertType
	if certType == "" {
		certType = CertTypeUser
	}
	var sshCertType uint32
	switch certType {
	case CertTypeUser:
		sshCertType = ssh.UserCert
	case CertTypeHost:
		sshCertType = ssh.HostCert
	default:
		return nil, fmt.Errorf("invalid cert type %q (must be %q or %q)", certType, CertTypeUser, CertTypeHost)
	}

	profileName := req.Profile
	if profileName == "" {
		profileName = DefaultProfileName(certType)
	}
	profile, err := LookupProfile(profileName)
	if err != nil {
		return nil, err
	}
	if profile.CertType != certType {
		return nil, fmt.Errorf("profile %q signs %s certificates, not %s", profile.Name, profile.CertType, certType)
	}

	if strings.TrimSpace(req.PublicKey) == "" {
		return nil, fmt.Errorf("a public key is required")
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		return nil, fmt.Errorf("the supplied key is already a certificate; supply the plain public key")
	}

	principals := make([]string, 0, len(req.Principals))
	for _, p := range req.Principals {
		principals = append(principals, strings.TrimSpace(p))
	}
	if err := profile.checkPrincipals(principals); err != nil {
		return nil, err
	}
	// Host certificates carry neither extensions nor critical options; refuse
	// them explicitly rather than silently dropping what the caller asked for.
	if certType == CertTypeHost && (len(req.Extensions) > 0 || len(req.CriticalOptions) > 0) {
		return nil, fmt.Errorf("host certificates cannot carry extensions or critical options")
	}
	extensions, criticalOptions, err := profile.resolvePermissions(req.Extensions, req.CriticalOptions)
	if err != nil {
		return nil, err
	}

	keyID := strings.TrimSpace(req.KeyID)
	if keyID == "" {
		keyID = strings.TrimSpace(req.RequestedBy)
	}
	if keyID == "" && len(principals) > 0 {
		keyID = principals[0]
	}
	if keyID == "" {
		return nil, fmt.Errorf("a key ID is required")
	}

	validity := profile.resolveValidity(req.Validity)
	now := a.now()
	validAfter := now.Add(-clockSkewBackdate)
	validBefore := now.Add(validity)

	serial, err := a.db.AllocateSerial(ca.ID)
	if err != nil {
		return nil, fmt.Errorf("allocating serial: %w", err)
	}

	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          uint64(serial),
		CertType:        sshCertType,
		KeyId:           keyID,
		ValidPrincipals: principals,
		ValidAfter:      uint64(validAfter.Unix()),
		ValidBefore:     uint64(validBefore.Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: criticalOptions,
			Extensions:      extensions,
		},
	}

	signer, err := a.provider.Signer(ctx, keyRefForCA(ca))
	if err != nil {
		return nil, fmt.Errorf("opening CA signer: %w", err)
	}
	defer signer.Close()
	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("wrapping CA signer: %w", err)
	}
	if err := cert.SignCert(rand.Reader, sshSigner); err != nil {
		return nil, fmt.Errorf("signing certificate: %w", err)
	}

	record := &models.SSHCertificate{
		CAID:                 ca.ID,
		TenantID:             ca.TenantID,
		Serial:               strconv.FormatUint(cert.Serial, 10),
		CertType:             certType,
		KeyID:                keyID,
		Principals:           principals,
		Profile:              profile.Name,
		PublicKeyFingerprint: ssh.FingerprintSHA256(pub),
		Certificate:          strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert))),
		ValidAfter:           validAfter,
		ValidBefore:          validBefore,
		Status:               models.CertStatusValid,
		IssuedBy:             req.RequestedBy,
	}
	if err := a.db.RecordSSHCertificate(record); err != nil {
		return nil, fmt.Errorf("recording certificate: %w", err)
	}

	return &SignResult{
		Certificate:   cert,
		AuthorizedKey: ssh.MarshalAuthorizedKey(cert),
		Record:        record,
		CA:            ca,
	}, nil
}

// RevokeRequest revokes a certificate serial, or every certificate bearing a
// key ID, under a CA. Exactly one of Serial and KeyID must be set.
type RevokeRequest struct {
	CAID      string
	Serial    string
	KeyID     string
	Reason    string
	RevokedBy string
}

// Revoke records an SSH revocation. It returns the stored record and whether
// the revocation is newly effective (false when the target was already
// revoked; the reason/time are updated either way).
func (a *Authority) Revoke(ctx context.Context, req RevokeRequest) (*models.SSHRevocation, bool, error) {
	ca, err := a.db.GetCA(req.CAID)
	if err != nil {
		return nil, false, fmt.Errorf("loading CA: %w", err)
	}
	if ca == nil {
		return nil, false, fmt.Errorf("CA %q not found", req.CAID)
	}

	serial := strings.TrimSpace(req.Serial)
	keyID := strings.TrimSpace(req.KeyID)
	if (serial == "") == (keyID == "") {
		return nil, false, fmt.Errorf("exactly one of serial and key_id must be given")
	}
	if serial != "" {
		if _, err := strconv.ParseUint(serial, 10, 64); err != nil {
			return nil, false, fmt.Errorf("invalid serial %q: must be a decimal certificate serial", req.Serial)
		}
	}

	rev := &models.SSHRevocation{
		CAID:      ca.ID,
		Serial:    serial,
		KeyID:     keyID,
		Reason:    strings.TrimSpace(req.Reason),
		RevokedBy: req.RevokedBy,
		RevokedAt: a.now().UTC(),
	}
	newly, err := a.db.RevokeSSHCertificate(rev)
	if err != nil {
		return nil, false, fmt.Errorf("recording revocation: %w", err)
	}
	return rev, newly, nil
}

// BuildKRL generates the CA's OpenSSH Key Revocation List from the revocation
// store. The KRL version is the number of recorded revocations — monotonic,
// since revocations are only ever added — so relying hosts can order updates.
func (a *Authority) BuildKRL(ctx context.Context, caID, comment string) ([]byte, error) {
	ca, err := a.db.GetCA(caID)
	if err != nil {
		return nil, fmt.Errorf("loading CA: %w", err)
	}
	if ca == nil {
		return nil, fmt.Errorf("CA %q not found", caID)
	}
	caKey, err := caPublicKey(ca)
	if err != nil {
		return nil, err
	}

	revs, err := a.db.ListSSHRevocations(ca.ID)
	if err != nil {
		return nil, fmt.Errorf("listing revocations: %w", err)
	}
	content := &KRLContent{
		Version:     uint64(len(revs)),
		GeneratedAt: a.now(),
		Comment:     comment,
		CAKey:       caKey,
	}
	for _, rev := range revs {
		if rev.Serial != "" {
			serial, err := strconv.ParseUint(rev.Serial, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("stored revocation has invalid serial %q", rev.Serial)
			}
			content.Serials = append(content.Serials, serial)
		} else if rev.KeyID != "" {
			content.KeyIDs = append(content.KeyIDs, rev.KeyID)
		}
	}
	return MarshalKRL(content)
}

// VerifyCertificate checks a certificate the way a relying host would: it must
// be signed by this CA, currently within its validity window (at the given
// time), name the principal (when one is given), and not be revoked — by
// serial or by key ID. It returns the parsed certificate on success.
func (a *Authority) VerifyCertificate(ctx context.Context, caID string, authorizedKey []byte, principal string, at time.Time) (*ssh.Certificate, error) {
	ca, err := a.db.GetCA(caID)
	if err != nil {
		return nil, fmt.Errorf("loading CA: %w", err)
	}
	if ca == nil {
		return nil, fmt.Errorf("CA %q not found", caID)
	}
	caKey, err := caPublicKey(ca)
	if err != nil {
		return nil, err
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(authorizedKey)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("not a certificate")
	}

	// The certificate must chain to THIS CA; CheckCert verifies the signature
	// against cert.SignatureKey but trusting that key is the caller's job.
	if cert.SignatureKey == nil || !bytes.Equal(cert.SignatureKey.Marshal(), caKey.Marshal()) {
		return nil, fmt.Errorf("certificate was not signed by CA %q", ca.Label)
	}

	var revoked bool
	var revErr error
	checker := &ssh.CertChecker{
		Clock: func() time.Time { return at },
		IsRevoked: func(c *ssh.Certificate) bool {
			r, err := a.isRevoked(ca.ID, c)
			if err != nil {
				revErr = err
				return true // fail closed on a store error
			}
			revoked = r
			return r
		},
	}
	// We are checking issuance validity, not enforcing login policy: accept the
	// certificate's own critical options as supported.
	for opt := range cert.CriticalOptions {
		checker.SupportedCriticalOptions = append(checker.SupportedCriticalOptions, opt)
	}
	if err := checker.CheckCert(principal, cert); err != nil {
		if revErr != nil {
			return nil, fmt.Errorf("revocation check failed: %w", revErr)
		}
		if revoked {
			return nil, fmt.Errorf("certificate serial %d is revoked", cert.Serial)
		}
		return nil, err
	}
	return cert, nil
}

// isRevoked reports whether a certificate is revoked by serial or key ID.
func (a *Authority) isRevoked(caID string, cert *ssh.Certificate) (bool, error) {
	return a.db.IsSSHCertificateRevoked(caID, strconv.FormatUint(cert.Serial, 10), cert.KeyId)
}

// caPublicKey parses a CA's stored OpenSSH public key.
func caPublicKey(ca *models.CA) (ssh.PublicKey, error) {
	if strings.TrimSpace(ca.PublicKey) == "" {
		return nil, fmt.Errorf("CA %q has no OpenSSH public key", ca.Label)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("CA %q public key is not a valid OpenSSH key: %w", ca.Label, err)
	}
	return key, nil
}

// keyRefForCA resolves the provider key reference for a CA, preferring the
// object label embedded in its stored key URI.
func keyRefForCA(ca *models.CA) keyprovider.KeyRef {
	label := pki.ExtractKeyLabel(ca.PKCS11URI)
	if label == "" {
		label = ca.Label
	}
	return keyprovider.KeyRef{Label: label}
}
