package ca

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/spiffe"
)

// SVIDProfileName is the built-in issuance profile that mints SPIFFE X.509-SVIDs.
const SVIDProfileName = "spiffe-svid"

// spiffeScheme is the URI scheme of a SPIFFE ID.
const spiffeScheme = "spiffe://"

// JWT-SVID validity bounds. A JWT-SVID is a short-lived bearer credential minted
// from the CA's HSM-backed signing key; JWTSVIDDefaultTTL applies when a request
// omits a TTL, and JWTSVIDMaxTTL is a hard ceiling clamped regardless of the
// requested or configured value, so a JWT-SVID can never outlive a sensible
// bearer-token window.
const (
	JWTSVIDDefaultTTL = time.Hour
	JWTSVIDMaxTTL     = 24 * time.Hour
)

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

// JWTSVIDSpec describes a SPIFFE JWT-SVID to mint. Unlike an X.509-SVID there is
// no CSR and no leaf certificate: the CA's HSM-backed signing key signs a compact
// JWS whose subject is the SPIFFE ID and whose kid resolves to the CA's key in
// the trust bundle.
type JWTSVIDSpec struct {
	// CAID identifies the issuing CA. Its active issuer key signs the token.
	CAID string
	// SPIFFEID is the validated spiffe:// URI carried in the "sub" claim.
	SPIFFEID string
	// Audience is the token's "aud" set; at least one value is required.
	Audience []string
	// TTL is the token lifetime. Zero uses JWTSVIDDefaultTTL; any value is clamped
	// to JWTSVIDMaxTTL.
	TTL time.Duration
	// RequestedBy records who requested the token (for audit).
	RequestedBy string
}

// JWTSVIDResult is a freshly minted JWT-SVID and its metadata.
type JWTSVIDResult struct {
	// Token is the compact-serialized, signed JWT-SVID.
	Token string
	// SPIFFEID is the subject identity the token asserts.
	SPIFFEID string
	// TrustDomain is the trust domain of SPIFFEID.
	TrustDomain string
	// Audience is the normalized audience set embedded in the token.
	Audience []string
	// KeyID is the token's kid header — the RFC 7638 thumbprint of the signing key,
	// which resolves to the CA's jwt-svid entry in the trust bundle.
	KeyID string
	// Algorithm is the JWS "alg" (e.g. "ES256").
	Algorithm string
	// IssuedAt and Expiry are the token's iat/exp instants.
	IssuedAt time.Time
	Expiry   time.Time
}

// IssueJWTSVID mints a SPIFFE JWT-SVID under the given CA. The token is signed on
// the HSM by the CA's active issuer key (via the key provider) — the private key
// never leaves the token — with the SPIFFE ID in "sub", the required audience in
// "aud", short-lived iat/exp, and a kid that matches the CA's key in the JWKS
// trust bundle. The trust-domain authorization is the caller's responsibility
// (the handler/CLI enforce the same allowlist as X.509-SVID before calling this);
// here we validate the identity, resolve the signer, and sign.
func (m *Manager) IssueJWTSVID(ctx context.Context, spec JWTSVIDSpec) (*JWTSVIDResult, error) {
	sid, err := spiffe.ParseID(spec.SPIFFEID)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE id: %w", err)
	}
	auds := normalizeAudience(spec.Audience)
	if len(auds) == 0 {
		return nil, fmt.Errorf("a JWT-SVID requires at least one audience")
	}

	ttl := spec.TTL
	if ttl <= 0 {
		ttl = JWTSVIDDefaultTTL
	}
	if ttl > JWTSVIDMaxTTL {
		ttl = JWTSVIDMaxTTL
	}

	// Sign with the CA's active issuer key, so a token minted just before a
	// key rollover still verifies against the overlap chain the bundle publishes.
	activeID, err := m.ActiveIssuerID(spec.CAID)
	if err != nil {
		return nil, err
	}
	issuerCA, _, err := m.loadIssuer(activeID)
	if err != nil {
		return nil, err
	}

	// Respect tenant lifecycle: a suspended tenant is frozen for all new identity
	// issuance, exactly as the X.509-SVID path is via the tenant gate. A JWT-SVID
	// is an ephemeral bearer token, not an inventory certificate, so it does not
	// consume the daily/active certificate quota — only the suspension state gates
	// it.
	if err := m.ensureTenantActive(issuerCA); err != nil {
		return nil, err
	}

	signer, err := m.provider.Signer(ctx, keyRefForCA(issuerCA))
	if err != nil {
		return nil, fmt.Errorf("opening issuer signer: %w", err)
	}
	defer signer.Close()

	alg, err := spiffe.SignatureAlgorithm(signer.Public())
	if err != nil {
		return nil, err
	}
	kid, err := spiffe.KeyID(signer.Public())
	if err != nil {
		return nil, err
	}

	// Backdate nbf by the shared clock-skew allowance so a verifier whose clock
	// lags slightly still accepts a freshly minted token, matching the X.509 leaf
	// backdating philosophy.
	now := time.Now()
	iat := now
	nbf := now.Add(-clockSkew)
	exp := now.Add(ttl)

	token, err := spiffe.SignJWTSVID(signer, spiffe.JWTSVIDParams{
		SPIFFEID:  sid.String(),
		Audience:  auds,
		IssuedAt:  iat,
		NotBefore: nbf,
		Expiry:    exp,
		KeyID:     kid,
	})
	if err != nil {
		return nil, err
	}

	return &JWTSVIDResult{
		Token:       token,
		SPIFFEID:    sid.String(),
		TrustDomain: sid.TrustDomain(),
		Audience:    auds,
		KeyID:       kid,
		Algorithm:   alg,
		IssuedAt:    iat,
		Expiry:      exp,
	}, nil
}

// normalizeAudience trims, de-duplicates, and drops empty audience values while
// preserving order.
func normalizeAudience(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, a := range in {
		a = strings.TrimSpace(a)
		if a == "" || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
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
