package ca

// Adopting an existing certificate authority (Task 194).
//
// The migration case this exists for: an organization already runs a CA. Its
// root certificate is in laptops, phones, switches, and a build system nobody
// remembers configuring; its key is a file on a server, or in a token this PKI
// does not drive. Re-keying is not an option — that means redistributing the
// trust anchor to everything that has it. What *is* an option is moving the key
// into a real key provider and running the rest of its life properly: HSM-held,
// audited, monitored, with CRLs and OCSP that work.
//
// ImportCA is that move. It takes the existing key and the existing certificate
// and produces an ordinary CA record — one that issues, revokes, rotates, and
// publishes exactly like a CA created here, because after the import there is no
// difference except provenance.
//
// It is deliberately strict about the pairing. Binding a CA record to a key that
// does not match its certificate produces an authority that appears to work and
// signs certificates nothing can verify, discovered at the worst moment. So the
// key must match the certificate, the certificate must be a currently valid CA
// certificate, a self-signed one must actually verify under its own key, the key
// must pass the same weak/compromised-key gate subject keys pass, and the
// backend must demonstrably be able to sign with it before anything is persisted.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// ImportCASpec describes an existing CA to adopt.
type ImportCASpec struct {
	// TenantID is the tenant that will own the adopted CA and its issuance
	// subtree. Empty defaults to the built-in default tenant.
	TenantID string
	// Label is the key label / CA name to record it under. It must be unused.
	Label string
	// PrivateKey is the CA's existing private key, to be imported into the key
	// provider. Leave nil when the key is already in the provider and name it
	// with ExistingKeyLabel instead.
	PrivateKey crypto.PrivateKey
	// ExistingKeyLabel adopts a key already present in the provider — one put
	// there out of band by a vendor migration tool, a wrapped restore, or an
	// earlier `key import`. Nothing is written to the backend in that case; the
	// key is only verified to match the certificate and to be usable.
	ExistingKeyLabel string
	// CertificatePEM is the CA's existing certificate. Trailing certificates in
	// the same PEM are treated as chain material.
	CertificatePEM []byte
	// ChainPEM optionally supplies the issuing chain of a subordinate CA whose
	// parent is not (or not yet) in this PKI, so the served chain reaches the
	// external trust anchor.
	ChainPEM []byte
	// ParentID optionally links the adopted CA to a CA already in this PKI, for
	// the case where the parent was adopted first. When empty the parent is
	// discovered automatically: a CA in the same tenant whose certificate
	// verifies this one is linked, otherwise the supplied chain is recorded as
	// external chain material.
	ParentID string
}

// ImportCAResult is the outcome of adopting a CA.
type ImportCAResult struct {
	// CA is the persisted, active CA record.
	CA *models.CA
	// Warnings lists non-fatal findings an operator should review. The import
	// succeeded despite them.
	Warnings []string
	// ChainPEM is the chain now served for the CA.
	ChainPEM []byte
	// KeyImported reports whether key material was written into the provider
	// (false when an already-present key was adopted by label).
	KeyImported bool
	// KeyFingerprint is the SPKI SHA-256 fingerprint of the adopted key, the
	// same identifier the inventory and key-compromise search use.
	KeyFingerprint string
	// SelfSigned reports whether the adopted CA is a root.
	SelfSigned bool
}

// ImportCA adopts an existing CA: it imports the CA's private key into the key
// provider (or adopts one already there), validates the certificate against it,
// and persists an active CA record that issues like any other.
func (m *Manager) ImportCA(ctx context.Context, spec ImportCASpec) (*ImportCAResult, error) {
	if spec.Label == "" {
		return nil, fmt.Errorf("CA label is required")
	}
	if (spec.PrivateKey == nil) == (spec.ExistingKeyLabel == "") {
		return nil, fmt.Errorf("supply exactly one of a private key to import or the label of a key already in the provider")
	}
	if existing, err := m.db.GetCAByLabel(spec.Label); err != nil {
		return nil, fmt.Errorf("checking for existing CA: %w", err)
	} else if existing != nil {
		return nil, fmt.Errorf("a CA with label %q already exists", spec.Label)
	}

	cert, chainCerts, err := parseImportedCACertificate(spec.CertificatePEM, spec.ChainPEM)
	if err != nil {
		return nil, err
	}
	warnings, err := validateCACertificateForImport(cert)
	if err != nil {
		return nil, err
	}

	// The key-quality gate that guards subject keys guards this one too: a CA
	// key that is ROCA-vulnerable or on the compromised-key blocklist must not
	// be given a longer life inside an HSM — the HSM cannot un-factor it.
	fingerprint, err := m.checkImportedKeyQuality(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	keyInfo, imported, err := m.resolveImportKey(ctx, spec, cert)
	if err != nil {
		return nil, err
	}

	// Prove the provider can actually sign with the adopted key before a CA
	// record starts pointing at it.
	if err := keyprovider.VerifyKeyUsable(ctx, m.provider, keyprovider.KeyRef{Label: keyInfo.Label, ID: keyInfo.ID}, cert.PublicKey); err != nil {
		return nil, fmt.Errorf("the adopted key is not usable for signing: %w", err)
	}

	selfSigned := bytes.Equal(cert.RawIssuer, cert.RawSubject)
	parentID, chainWarnings, externalChain, err := m.resolveImportParent(spec, cert, chainCerts, selfSigned)
	if err != nil {
		return nil, err
	}
	warnings = append(warnings, chainWarnings...)
	if !imported {
		warnings = append(warnings, fmt.Sprintf("adopted the key already present in the provider as %q; no key material was written", keyInfo.Label))
	}
	if m.provider.Name() == string(keyprovider.ProviderSoftware) {
		warnings = append(warnings, "the key provider is the software keystore: the adopted key remains a file on disk and is copyable. Move it to an HSM before this CA issues in production")
	}
	// Serials for end-entity certificates are random 128-bit values, so they
	// cannot collide with what the legacy CA already issued. Subordinate-CA
	// serials come from a per-CA counter that starts fresh here, which can
	// collide with an intermediate the legacy CA issued from a low counter.
	warnings = append(warnings, "subordinate-CA serial numbers restart at 2 for this CA; if the legacy deployment issued intermediates with small sequential serials, revoke or retire them before issuing new ones")

	tenantID := spec.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	denySSH := database.BuiltinDenyAllSSH
	denyX509 := database.BuiltinDenyAllX509
	notBefore, notAfter := cert.NotBefore, cert.NotAfter
	caRec := &models.CA{
		ID:                          uuid.New().String(),
		TenantID:                    tenantID,
		ParentID:                    parentID,
		Label:                       spec.Label,
		PKCS11URI:                   keyInfo.URI,
		KeyType:                     keyInfo.KeyType,
		PublicKey:                   caPublicKeyString(keyInfo),
		DefaultSSHRestrictionSetID:  &denySSH,
		DefaultX509RestrictionSetID: &denyX509,
		Certificate:                 string(pki.EncodeCertificatePEM(cert.Raw)),
		Subject:                     cert.Subject.String(),
		Serial:                      cert.SerialNumber.String(),
		NotBefore:                   &notBefore,
		NotAfter:                    &notAfter,
		MaxPathLen:                  maxPathLenOf(cert),
		Status:                      models.CAStatusActive,
		ExternalChain:               string(externalChain),
	}
	if err := m.db.CreateCA(caRec); err != nil {
		return nil, fmt.Errorf("persisting adopted CA: %w", err)
	}

	chain, err := m.CombinedChainPEM(caRec.ID)
	if err != nil {
		return nil, err
	}
	return &ImportCAResult{
		CA:             caRec,
		Warnings:       warnings,
		ChainPEM:       chain,
		KeyImported:    imported,
		KeyFingerprint: fingerprint,
		SelfSigned:     selfSigned,
	}, nil
}

// parseImportedCACertificate splits the supplied PEM into the CA certificate
// and its chain material.
func parseImportedCACertificate(certPEM, chainPEM []byte) (*x509.Certificate, []*x509.Certificate, error) {
	if len(bytes.TrimSpace(certPEM)) == 0 {
		return nil, nil, fmt.Errorf("the CA certificate is required")
	}
	certs, err := pki.ParseCertificateChainPEM(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing CA certificate: %w", err)
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no CERTIFICATE block found in the supplied PEM")
	}
	chain := certs[1:]
	if len(chainPEM) > 0 {
		extra, err := pki.ParseCertificateChainPEM(chainPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing chain: %w", err)
		}
		chain = append(chain, extra...)
	}
	return certs[0], chain, nil
}

// validateCACertificateForImport applies the fail-closed checks an adopted CA
// certificate must pass, returning the non-fatal findings as warnings.
func validateCACertificateForImport(cert *x509.Certificate) ([]string, error) {
	var warnings []string

	if !cert.BasicConstraintsValid {
		return nil, fmt.Errorf("certificate has no basic-constraints extension; a CA certificate must carry basicConstraints cA=TRUE")
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA certificate (basicConstraints cA=FALSE); only a CA certificate can be adopted as a CA")
	}
	if cert.KeyUsage == 0 {
		warnings = append(warnings, "certificate has no keyUsage extension (RFC 5280 requires keyCertSign on CA certificates); strict verifiers may reject chains")
	} else {
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, fmt.Errorf("certificate keyUsage lacks keyCertSign; certificates issued under this CA would not verify")
		}
		if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
			warnings = append(warnings, "certificate keyUsage lacks cRLSign; CRLs signed by this CA will not verify")
		}
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			warnings = append(warnings, "certificate keyUsage lacks digitalSignature; OCSP responses signed directly by the CA key will not verify (use a delegated responder)")
		}
	}

	now := time.Now()
	if !cert.NotAfter.After(cert.NotBefore) {
		return nil, fmt.Errorf("certificate validity is inverted (notAfter %s is not after notBefore %s)",
			cert.NotAfter.Format(time.RFC3339), cert.NotBefore.Format(time.RFC3339))
	}
	if !cert.NotAfter.After(now) {
		return nil, fmt.Errorf("certificate expired at %s; an expired CA cannot issue — re-certify the key first (ca csr / ca import-cert) or import a current certificate",
			cert.NotAfter.Format(time.RFC3339))
	}
	if cert.NotBefore.After(now.Add(clockSkew)) {
		return nil, fmt.Errorf("certificate is not valid until %s", cert.NotBefore.Format(time.RFC3339))
	}
	if remaining := time.Until(cert.NotAfter); remaining < 90*24*time.Hour {
		warnings = append(warnings, fmt.Sprintf("certificate expires in %d days; plan re-certification of the adopted key", int(remaining.Hours()/24)))
	}

	// A self-signed certificate must verify under its own key. This catches a
	// truncated or mispasted root before it becomes a trust anchor nothing can
	// build a path through.
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		if err := cert.CheckSignatureFrom(cert); err != nil {
			return nil, fmt.Errorf("self-signed certificate does not verify under its own key: %w", err)
		}
	}
	return warnings, nil
}

// checkImportedKeyQuality runs the weak/compromised-key checks against the CA's
// own public key and returns its SPKI fingerprint. It fails closed, including on
// a blocklist read error.
func (m *Manager) checkImportedKeyQuality(pub crypto.PublicKey) (string, error) {
	res := keycheck.Inspect(pub, keycheck.DefaultPolicy(weakKeyBlocklist))
	if res.Fingerprint != "" {
		blocked, err := m.db.IsKeyBlocked(res.Fingerprint)
		if err != nil {
			return "", fmt.Errorf("consulting the compromised-key blocklist: %w", err)
		}
		if blocked {
			res.Add(keycheck.CodeBlockedKey, "the CA key is on the operator-managed compromised-key blocklist")
		}
	}
	if !res.OK() {
		return "", fmt.Errorf("the CA key fails the key-quality gate and must not be adopted: %s", res.Summary())
	}
	return res.Fingerprint, nil
}

// resolveImportKey either imports the supplied private key into the provider or
// adopts one already present, and in both cases proves it matches the
// certificate. The match is checked before anything is written, so a mismatched
// pairing never leaves an orphan key behind on the token.
func (m *Manager) resolveImportKey(ctx context.Context, spec ImportCASpec, cert *x509.Certificate) (*keyprovider.KeyInfo, bool, error) {
	if spec.ExistingKeyLabel != "" {
		info, err := m.provider.FindKey(ctx, keyprovider.KeyRef{Label: spec.ExistingKeyLabel})
		if err != nil {
			if errors.Is(err, keyprovider.ErrKeyNotFound) {
				return nil, false, fmt.Errorf("no key labeled %q in the %s key provider", spec.ExistingKeyLabel, m.provider.Name())
			}
			return nil, false, fmt.Errorf("looking up key %q: %w", spec.ExistingKeyLabel, err)
		}
		if !publicKeysEqual(info.PublicKey, cert.PublicKey) {
			return nil, false, fmt.Errorf("the key labeled %q does not match the certificate's public key", spec.ExistingKeyLabel)
		}
		return info, false, nil
	}

	signer, ok := spec.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, false, fmt.Errorf("the supplied private key of type %T cannot sign", spec.PrivateKey)
	}
	if !publicKeysEqual(signer.Public(), cert.PublicKey) {
		return nil, false, fmt.Errorf("the supplied private key does not match the certificate's public key — they are not a pair")
	}
	info, err := keyprovider.ImportKey(ctx, m.provider, keyprovider.ImportSpec{
		Label:      spec.Label,
		Usage:      keyprovider.KeyUsageSign,
		PrivateKey: spec.PrivateKey,
	})
	if err != nil {
		return nil, false, fmt.Errorf("importing the CA key: %w", err)
	}
	return info, true, nil
}

// resolveImportParent decides how the adopted CA's issuer is recorded: linked to
// a CA already in this PKI, or served as external chain material.
func (m *Manager) resolveImportParent(spec ImportCASpec, cert *x509.Certificate, chainCerts []*x509.Certificate, selfSigned bool) (*string, []string, []byte, error) {
	if selfSigned {
		if len(chainCerts) > 0 {
			return nil, []string{"the certificate is self-signed (a root); the supplied chain material was ignored"}, nil, nil
		}
		return nil, nil, nil, nil
	}

	if spec.ParentID != "" {
		parent, err := m.db.GetCA(spec.ParentID)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("looking up parent CA: %w", err)
		}
		if parent == nil {
			return nil, nil, nil, fmt.Errorf("parent CA %q not found", spec.ParentID)
		}
		if err := verifyIssuedBy(cert, parent); err != nil {
			return nil, nil, nil, err
		}
		id := parent.ID
		return &id, nil, nil, nil
	}

	// Auto-discovery: a parent already adopted into this PKI is the better
	// linkage, because it makes chain serving, rotation, and revocation walk the
	// real tree instead of a pasted bundle.
	if parent, err := m.findIssuingCA(cert); err != nil {
		return nil, nil, nil, err
	} else if parent != nil {
		id := parent.ID
		return &id, []string{fmt.Sprintf("linked to the CA %q already in this PKI, which issued this certificate", parent.Label)}, nil, nil
	}

	externalChain, chainWarnings, err := resolveExternalChain(cert, chainCerts, time.Now())
	if err != nil {
		return nil, nil, nil, err
	}
	return nil, chainWarnings, externalChain, nil
}

// findIssuingCA looks for a CA in this PKI whose certificate issued cert.
func (m *Manager) findIssuingCA(cert *x509.Certificate) (*models.CA, error) {
	cas, err := m.db.ListCAs()
	if err != nil {
		return nil, fmt.Errorf("listing CAs: %w", err)
	}
	for i := range cas {
		candidate := &cas[i]
		if candidate.Certificate == "" {
			continue
		}
		candidateCert, err := pki.ParseCertificatePEM([]byte(candidate.Certificate))
		if err != nil {
			continue
		}
		if !bytes.Equal(candidateCert.RawSubject, cert.RawIssuer) {
			continue
		}
		if cert.CheckSignatureFrom(candidateCert) == nil {
			return candidate, nil
		}
	}
	return nil, nil
}

// verifyIssuedBy confirms an explicitly named parent really issued cert.
func verifyIssuedBy(cert *x509.Certificate, parent *models.CA) error {
	if parent.Certificate == "" {
		return fmt.Errorf("parent CA %q has no certificate", parent.Label)
	}
	parentCert, err := pki.ParseCertificatePEM([]byte(parent.Certificate))
	if err != nil {
		return fmt.Errorf("parsing parent CA certificate: %w", err)
	}
	if !bytes.Equal(parentCert.RawSubject, cert.RawIssuer) {
		return fmt.Errorf("the certificate's issuer (%s) is not the subject of parent CA %q (%s)",
			cert.Issuer.String(), parent.Label, parentCert.Subject.String())
	}
	if err := cert.CheckSignatureFrom(parentCert); err != nil {
		return fmt.Errorf("the certificate does not verify under parent CA %q: %w", parent.Label, err)
	}
	return nil
}

// publicKeysEqual compares two public keys structurally.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if a == nil || b == nil {
		return false
	}
	e, ok := a.(equaler)
	return ok && e.Equal(b)
}
