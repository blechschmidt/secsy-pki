package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/pqc"
)

// Externally-signed subordinate CA support (Task 69): the common enterprise
// topology where the subordinate's key lives in our HSM but the parent is
// external — an offline corporate root or a public/bridge CA we do not operate.
//
// The flow has two halves:
//
//  1. GenerateExternalCACSR creates the HSM-backed key and emits a PKCS#10 CSR
//     carrying CA basicConstraints/keyUsage attributes. The CA record is
//     persisted in the "pending" state (no certificate) so the key and its
//     paperwork survive the out-of-band signing ceremony, which may take days.
//
//  2. ImportExternalCACertificate validates and installs the certificate the
//     external parent produced — the public key must match the HSM key, the
//     certificate must actually be a currently valid CA certificate — plus the
//     optional external chain (the offline parents up to the external root) so
//     chain serving can hand relying parties the full path to the external
//     trust anchor. The CA then issues and rotates subordinates normally.
//
// The external parent never sees a private key: only the CSR travels out and
// only certificates travel back.

// ExternalCACSRSpec describes an externally-signed subordinate CA to prepare:
// an HSM-backed key plus the PKCS#10 CSR to hand to the external parent.
type ExternalCACSRSpec struct {
	// TenantID is the tenant that will own this CA and its issuance subtree.
	// Empty defaults to the built-in default tenant.
	TenantID string
	Label    string
	KeyType  string
	Subject  pkix.Name
	// MaxPathLen is the path-length constraint requested in the CSR. The
	// external parent may override it; the issued certificate is authoritative.
	MaxPathLen *int
}

// ExternalCACSRResult is the outcome of preparing an externally-signed CA.
type ExternalCACSRResult struct {
	// CA is the persisted pending CA record (status "pending", no certificate).
	CA *models.CA
	// CSRPEM is the PKCS#10 request to submit to the external parent.
	CSRPEM []byte
}

// GenerateExternalCACSR generates a CA key inside the provider and emits a
// PKCS#10 CSR (CA basicConstraints and keyUsage in its extensionRequest
// attribute) for signature by an external parent. The CA is persisted in the
// "pending" state; it cannot issue anything until the externally signed
// certificate is installed with ImportExternalCACertificate.
func (m *Manager) GenerateExternalCACSR(ctx context.Context, spec ExternalCACSRSpec) (*ExternalCACSRResult, error) {
	if spec.Label == "" {
		return nil, fmt.Errorf("CA label is required")
	}
	if spec.Subject.CommonName == "" {
		return nil, fmt.Errorf("subject common name (CN) is required")
	}
	keyType, err := keyprovider.NormalizeKeyType(spec.KeyType)
	if err != nil {
		return nil, err
	}
	// The external parent signs with classical tooling (openssl, a commercial
	// CA); ML-DSA subjects would need a PQC-aware parent and a PQC CSR encoding.
	if pqc.IsPQC(keyType) {
		return nil, fmt.Errorf("post-quantum key type %q is not supported for externally-signed CAs; use a classical key type", keyType)
	}
	if existing, err := m.db.GetCAByLabel(spec.Label); err != nil {
		return nil, fmt.Errorf("checking for existing CA: %w", err)
	} else if existing != nil {
		return nil, fmt.Errorf("a CA with label %q already exists", spec.Label)
	}

	keyInfo, err := m.provider.GenerateKey(ctx, keyprovider.KeySpec{Label: spec.Label, KeyType: keyType})
	if err != nil {
		return nil, fmt.Errorf("generating CA key: %w", err)
	}
	signer, err := m.provider.Signer(ctx, keyprovider.KeyRef{Label: spec.Label})
	if err != nil {
		return nil, fmt.Errorf("opening CA signer: %w", err)
	}
	defer signer.Close()

	der, err := pki.CreateCACSR(signer, pki.CACSRRequest{
		Subject:    spec.Subject,
		MaxPathLen: spec.MaxPathLen,
	})
	if err != nil {
		return nil, err
	}
	csrPEM := pki.EncodeCSRPEM(der)

	tenantID := spec.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	denySSH := database.BuiltinDenyAllSSH
	denyX509 := database.BuiltinDenyAllX509
	caRec := &models.CA{
		ID:                          uuid.New().String(),
		TenantID:                    tenantID,
		Label:                       spec.Label,
		PKCS11URI:                   keyInfo.URI,
		KeyType:                     keyInfo.KeyType,
		PublicKey:                   caPublicKeyString(keyInfo),
		DefaultSSHRestrictionSetID:  &denySSH,
		DefaultX509RestrictionSetID: &denyX509,
		// Subject is recorded from the request so listings show what was asked
		// for; the imported certificate's subject replaces it and is authoritative.
		Subject:    spec.Subject.String(),
		MaxPathLen: spec.MaxPathLen,
		Status:     models.CAStatusPending,
		CSR:        string(csrPEM),
	}
	if err := m.db.CreateCA(caRec); err != nil {
		return nil, fmt.Errorf("persisting pending CA: %w", err)
	}
	return &ExternalCACSRResult{CA: caRec, CSRPEM: csrPEM}, nil
}

// ExternalCACSR returns the stored PKCS#10 CSR for a CA created with
// GenerateExternalCACSR, so an operator can re-download it while the external
// signing ceremony is in flight — or later, to have the same key re-certified
// when the external certificate approaches expiry.
func (m *Manager) ExternalCACSR(caID string) ([]byte, error) {
	ca, err := m.db.GetCA(caID)
	if err != nil {
		return nil, fmt.Errorf("looking up CA: %w", err)
	}
	if ca == nil {
		return nil, fmt.Errorf("CA %q not found", caID)
	}
	if ca.CSR == "" {
		return nil, fmt.Errorf("CA %q has no stored CSR (it was not created for external signing)", ca.Label)
	}
	return []byte(ca.CSR), nil
}

// ImportExternalCACertSpec parameterizes installing an externally signed CA
// certificate onto a pending CA.
type ImportExternalCACertSpec struct {
	// CAID identifies the pending CA whose key the certificate certifies.
	CAID string
	// CertificatePEM is the externally signed certificate. It may be a bundle;
	// the first certificate is installed and the rest are treated as chain.
	CertificatePEM []byte
	// ChainPEM optionally supplies the external issuing chain (intermediates
	// and root) used to verify the certificate and to serve the full path to
	// the external trust anchor. Without it the certificate is installed as-is
	// and served without external parents.
	ChainPEM []byte
	// Replace permits re-importing onto an externally-signed CA that is already
	// active: installing a renewed certificate for the same HSM key, or adding
	// the external chain after the fact. Without it only a pending CA accepts an
	// import, so an active CA's certificate cannot be overwritten accidentally.
	Replace bool
}

// ImportExternalCACertResult is the outcome of a successful import.
type ImportExternalCACertResult struct {
	// CA is the reloaded, now-active CA record.
	CA *models.CA
	// Warnings lists non-fatal findings an operator should review (missing
	// cRLSign key usage, DN rewritten by the external parent, no chain
	// supplied, ...). The import succeeded despite them.
	Warnings []string
	// ChainPEM is the combined chain now served for the CA: its own certificate
	// followed by the imported external parents up to the external root.
	ChainPEM []byte
}

// ImportExternalCACertificate validates and installs the certificate an
// external parent issued for a pending CA's HSM-backed key.
//
// Fail-closed checks: the certificate's public key must equal the CA's key in
// the provider, it must be a CA certificate (basicConstraints cA=TRUE), its
// keyUsage — when present — must include keyCertSign, it must be currently
// valid (neither expired nor not-yet-valid), it must not be self-signed, and
// when an external chain is supplied the certificate must verify against it.
// Deviations that do not break issuance (missing cRLSign, a DN rewritten by the
// parent, a path-length constraint different from the requested one) are
// reported as warnings.
func (m *Manager) ImportExternalCACertificate(ctx context.Context, spec ImportExternalCACertSpec) (*ImportExternalCACertResult, error) {
	if spec.CAID == "" {
		return nil, fmt.Errorf("CA id is required")
	}
	ca, err := m.db.GetCA(spec.CAID)
	if err != nil {
		return nil, fmt.Errorf("looking up CA: %w", err)
	}
	if ca == nil {
		return nil, fmt.Errorf("CA %q not found", spec.CAID)
	}
	if err := checkImportTarget(ca, spec.Replace); err != nil {
		return nil, err
	}

	certs, err := pki.ParseCertificateChainPEM(spec.CertificatePEM)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE block found in the supplied PEM")
	}
	cert := certs[0]
	// Trailing certificates in the file are chain material — external CAs
	// commonly return the issued certificate bundled with their own chain.
	chainCerts := certs[1:]
	if len(spec.ChainPEM) > 0 {
		extra, err := pki.ParseCertificateChainPEM(spec.ChainPEM)
		if err != nil {
			return nil, fmt.Errorf("parsing external chain: %w", err)
		}
		chainCerts = append(chainCerts, extra...)
	}

	var warnings []string

	// The certificate must certify exactly the key held in the provider — an
	// import must never bind a CA record to a key it cannot use.
	if err := m.checkKeyMatchesProvider(ctx, ca, cert.PublicKey); err != nil {
		return nil, err
	}

	// A self-signed certificate is not an externally signed subordinate; a
	// corrupted or mispasted root would otherwise slip in here.
	if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return nil, fmt.Errorf("certificate is self-signed (issuer equals subject); expected a certificate issued by the external parent — a self-signed root is created with init-root")
	}

	if !cert.BasicConstraintsValid {
		return nil, fmt.Errorf("certificate has no basic-constraints extension; a CA certificate must carry basicConstraints cA=TRUE")
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA certificate (basicConstraints cA=FALSE); the external parent must sign the CSR as a CA")
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
		return nil, fmt.Errorf("certificate expired at %s", cert.NotAfter.Format(time.RFC3339))
	}
	if cert.NotBefore.After(now.Add(clockSkew)) {
		return nil, fmt.Errorf("certificate is not valid until %s (check the external CA's clock)", cert.NotBefore.Format(time.RFC3339))
	}

	// A replace-import that supplies no chain falls back to the previously
	// imported one — but never blindly: the (possibly renewed) certificate is
	// re-verified against it below, so a stale chain forces the operator to
	// supply the current one rather than silently publishing a broken bundle.
	if len(chainCerts) == 0 && ca.ExternalChain != "" {
		retained, perr := pki.ParseCertificateChainPEM([]byte(ca.ExternalChain))
		if perr == nil && len(retained) > 0 {
			chainCerts = retained
			warnings = append(warnings, "no external chain supplied; revalidated and kept the previously imported chain")
		}
	}

	// When chain material is supplied the certificate must verify against it —
	// installing a certificate together with a chain it does not chain to would
	// publish a bundle relying parties can never build a path through.
	externalChainPEM, chainWarnings, err := resolveExternalChain(cert, chainCerts, now)
	if err != nil {
		return nil, err
	}
	warnings = append(warnings, chainWarnings...)

	// Requested-versus-issued drift is normal (the parent decides) but worth
	// surfacing: the parent may have rewritten the DN or tightened pathlen.
	if ca.CSR != "" {
		if csr, err := pki.ParseCSRPEM([]byte(ca.CSR)); err == nil && !bytes.Equal(csr.RawSubject, cert.RawSubject) {
			warnings = append(warnings, fmt.Sprintf("certificate subject %q differs from the CSR subject %q (the external parent rewrote the DN)",
				cert.Subject.String(), csr.Subject.String()))
		}
	}
	issuedPathLen := maxPathLenOf(cert)
	if ca.Status == models.CAStatusPending && !equalPathLen(ca.MaxPathLen, issuedPathLen) {
		warnings = append(warnings, fmt.Sprintf("issued path-length constraint (%s) differs from the requested one (%s)",
			pathLenString(issuedPathLen), pathLenString(ca.MaxPathLen)))
	}

	certPEM := pki.EncodeCertificatePEM(cert.Raw)
	if err := m.db.InstallCACertificate(ca.ID, string(certPEM), cert.Subject.String(), cert.SerialNumber.String(),
		cert.NotBefore, cert.NotAfter, issuedPathLen, string(externalChainPEM), models.CAStatusActive); err != nil {
		return nil, fmt.Errorf("installing CA certificate: %w", err)
	}

	installed, err := m.db.GetCA(ca.ID)
	if err != nil {
		return nil, fmt.Errorf("reloading CA: %w", err)
	}
	chain, err := m.CombinedChainPEM(ca.ID)
	if err != nil {
		return nil, err
	}
	return &ImportExternalCACertResult{CA: installed, Warnings: warnings, ChainPEM: chain}, nil
}

// checkImportTarget decides whether a CA may receive an imported certificate:
// a pending CA always may; an active externally-signed CA (it has a stored CSR
// and no local parent) may only with Replace, supporting external renewal and
// late chain import without risking accidental overwrites.
func checkImportTarget(ca *models.CA, replace bool) error {
	switch {
	case ca.Status == models.CAStatusPending:
		return nil
	case ca.Certificate == "":
		return fmt.Errorf("CA %q is not awaiting an external certificate (create one with \"ca csr\" first)", ca.Label)
	case ca.CSR == "" || ca.ParentID != nil:
		return fmt.Errorf("CA %q was not created for external signing; its certificate cannot be replaced by import", ca.Label)
	case ca.Status != models.CAStatusActive:
		return fmt.Errorf("CA %q is %s and cannot receive a certificate import", ca.Label, ca.Status)
	case !replace:
		return fmt.Errorf("CA %q already has an externally signed certificate; pass replace to install a renewed one for the same key", ca.Label)
	default:
		return nil
	}
}

// checkKeyMatchesProvider verifies the certificate's public key equals the CA's
// key as held by the key provider (the HSM is authoritative, not the stored
// record).
func (m *Manager) checkKeyMatchesProvider(ctx context.Context, ca *models.CA, certPub crypto.PublicKey) error {
	providerPub, err := m.provider.PublicKey(ctx, keyRefForCA(ca))
	if err != nil {
		return fmt.Errorf("loading CA public key from the key provider: %w", err)
	}
	eq, ok := providerPub.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return fmt.Errorf("cannot compare provider key of type %T", providerPub)
	}
	if !eq.Equal(certPub) {
		return fmt.Errorf("certificate public key does not match the CA key held by the provider (key label %q); the external parent signed a different key or the wrong CSR", ca.Label)
	}
	return nil
}

// resolveExternalChain verifies the imported certificate against the supplied
// external chain material and returns the chain to persist, ordered leaf-side
// first and excluding the imported certificate itself. With no chain material
// it returns nothing and a warning.
func resolveExternalChain(cert *x509.Certificate, chainCerts []*x509.Certificate, now time.Time) ([]byte, []string, error) {
	if len(chainCerts) == 0 {
		return nil, []string{"no external chain supplied; the served chain will not include the external parent (re-import with the chain to add it)"}, nil
	}

	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	rootCount := 0
	for _, c := range chainCerts {
		if bytes.Equal(c.RawIssuer, c.RawSubject) {
			roots.AddCert(c)
			rootCount++
		} else {
			intermediates.AddCert(c)
		}
	}
	// A chain without a self-signed anchor can still be useful (the operator
	// distributes the root separately); verify what we can by treating the
	// topmost supplied certificate as the anchor.
	if rootCount == 0 {
		for _, c := range chainCerts {
			roots.AddCert(c)
		}
	}

	chains, err := cert.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		// The CA certificate is not an end-entity: EKU chain rules do not apply.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("certificate does not verify against the supplied external chain: %w", err)
	}

	// Persist the verified path (excluding the imported certificate itself), so
	// the stored chain is normalized: leaf-side first, no unrelated certificates.
	var out []byte
	for _, c := range chains[0][1:] {
		out = append(out, pki.EncodeCertificatePEM(c.Raw)...)
	}
	var warnings []string
	if rootCount == 0 {
		warnings = append(warnings, "external chain has no self-signed root; relying parties must obtain the external trust anchor separately")
	}
	return out, warnings, nil
}

// equalPathLen compares two optional path-length constraints.
func equalPathLen(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// pathLenString renders an optional path-length constraint for messages.
func pathLenString(v *int) string {
	if v == nil {
		return "unconstrained"
	}
	return fmt.Sprintf("%d", *v)
}
