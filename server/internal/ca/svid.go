package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// SVIDProfileName is the built-in issuance profile that mints SPIFFE X.509-SVIDs.
const SVIDProfileName = "spiffe-svid"

// spiffeScheme is the URI scheme of a SPIFFE ID.
const spiffeScheme = "spiffe://"

// SVIDSpec describes a SPIFFE X.509-SVID to issue. The workload supplies a CSR
// for its freshly generated key; only the public key is taken from it — the
// SPIFFE identity is fixed by the caller (already trust-domain-authorized) and
// carried as the sole URI SAN, never derived from the CSR's own subject or SANs.
type SVIDSpec struct {
	// CAID identifies the issuing CA. It must be an X.509 CA (have a cert).
	CAID string
	// CSRPEM is a PEM-encoded PKCS#10 CSR whose public key becomes the SVID's.
	// Its subject and SANs are ignored: the SVID identity is SPIFFEID alone.
	CSRPEM []byte
	// SPIFFEID is the validated spiffe:// URI that becomes the sole URI SAN.
	SPIFFEID string
	// Profile is the SVID profile name; empty uses the built-in spiffe-svid.
	Profile string
	// Validity overrides the profile default (clamped to the profile maximum and
	// the issuer's expiry). Zero uses the profile's short default.
	Validity time.Duration
	// DNSNames are optional additional SANs. The SPIFFE X.509-SVID spec permits
	// extra SANs but discourages them; they are empty by default.
	DNSNames []string
	// RequestedBy records who requested the SVID (for audit).
	RequestedBy string
}

// IssueSVID mints a SPIFFE X.509-SVID under the given CA. The certificate has a
// single spiffe:// URI SAN as its identity, an empty subject (no CN reliance,
// per the SPIFFE X.509-SVID spec), CA:false, and the profile's key usage
// (digitalSignature) and EKUs. It shares the full HSM-backed issuance path with
// ordinary leaves (serial allocation, the pre-issuance lint gate — which
// enforces CA:false and the leaf key-usage rules — and the recorded copy for
// renewal/revocation).
func (m *Manager) IssueSVID(ctx context.Context, spec SVIDSpec) (*IssueResult, error) {
	id := strings.TrimSpace(spec.SPIFFEID)
	if id == "" {
		return nil, fmt.Errorf("SVID requires a spiffe:// identity")
	}
	if !strings.HasPrefix(id, spiffeScheme) || len(id) == len(spiffeScheme) {
		return nil, fmt.Errorf("invalid SPIFFE id %q: must be a spiffe:// URI", id)
	}

	profileName := spec.Profile
	if profileName == "" {
		profileName = SVIDProfileName
	}
	profile, err := LookupProfile(profileName)
	if err != nil {
		return nil, err
	}
	if profile.Algorithm != AlgClassical {
		return nil, fmt.Errorf("profile %q is %s; SPIFFE SVIDs are issued from classical CSRs only", profile.Name, profile.Algorithm)
	}

	// The CSR supplies only the workload public key; its subject/SANs are ignored,
	// so a bare public-key CSR (no subject, no SAN) is valid — the SVID identity is
	// the spiffe:// URI alone.
	csr, err := decodeAndVerifyCSR(spec.CSRPEM)
	if err != nil {
		return nil, err
	}

	activeID, err := m.ActiveIssuerID(spec.CAID)
	if err != nil {
		return nil, err
	}
	issuerCA, issuerCert, err := m.loadIssuer(activeID)
	if err != nil {
		return nil, err
	}

	// The identity is the URI SAN alone: an empty subject (no CN), the single
	// spiffe:// URI, and — only if explicitly requested — extra DNS SANs. IP and
	// e-mail SANs are never carried on an SVID.
	return m.issueLeaf(ctx, issuerCA, issuerCert, profile, leafParts{
		Subject:   pkix.Name{},
		PublicKey: csr.PublicKey,
		DNSNames:  spec.DNSNames,
		URIs:      []string{id},
	}, spec.Validity, spec.RequestedBy)
}

// TrustBundleAuthorities returns the CA certificates that anchor SVIDs issued by
// caID: the CA's combined overlap chain (the active issuer, any overlapping
// rollover siblings, and the ancestors up to the root). These are the X.509
// authorities a SPIFFE trust bundle advertises. The list is de-duplicated and
// ordered issuer-first (root last).
func (m *Manager) TrustBundleAuthorities(caID string) ([]*x509.Certificate, error) {
	chainPEM, err := m.CombinedChainPEM(caID)
	if err != nil {
		return nil, err
	}
	certs, err := pki.ParseCertificateChainPEM(chainPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing CA chain for trust bundle: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("CA %q has no certificate to anchor a trust bundle", caID)
	}
	return certs, nil
}
