// Package pkcs12 implements server-side key generation and PKCS#12 (.p12/.pfx)
// bundle export for end-entity certificates.
//
// The flow is a single, self-contained issuance path: a fresh subject keypair is
// generated in software, a PKCS#10 CSR is built and self-signed from it (proof
// of possession), the leaf is issued through the CA manager (which signs on the
// HSM), and the freshly-generated subject key, the leaf, and the full issuer
// chain are packed into a password-protected PKCS#12 using a vetted encoder
// (software.sslmate.com/src/go-pkcs12).
//
// CRITICAL invariant: only the freshly-generated subject key is ever bundled.
// The CA's signing key lives in the HSM and is used solely as a crypto.Signer
// during issuance — it never leaves the device and is never marshaled here.
// This makes PKCS#12 export safe for S/MIME (Task 66) and device-enrollment key
// delivery, where the subscriber legitimately needs its own private key.
package pkcs12

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/fips"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	sslpkcs12 "software.sslmate.com/src/go-pkcs12"
)

// MinPasswordLen is the shortest export password accepted. PKCS#12 confidentiality
// rests entirely on the password (even the "modern" encoder uses a modest 2048
// KDF iterations), so a trivially short one is refused; operators are encouraged
// to use a high-entropy password (e.g. `openssl rand -hex 16`).
const MinPasswordLen = 6

// Encoder names accepted by GenerateAndBundle / EncoderFor. The default is
// "modern" (PBES2 with PBKDF2-HMAC-SHA-256 and AES-256-CBC, HMAC-SHA-256 MAC),
// readable by OpenSSL 1.1.1+, Java 12+, and Windows Server 2019+. The legacy
// encoders trade security for reach with very old software.
const (
	EncoderModern    = "modern"    // Modern2023: PBES2 / AES-256-CBC / HMAC-SHA-256
	EncoderLegacyDES = "legacy"    // LegacyDES: 3DES + SHA-1 (broad compatibility)
	EncoderLegacyRC2 = "legacyrc2" // LegacyRC2: RC2/3DES + SHA-1 (oldest software)

	// DefaultKeyType and default sizes for server-side generation. ECDSA P-256 is
	// the default: small, fast, and universally supported for S/MIME and TLS.
	DefaultKeyType = "ecdsa"

	defaultRSABits    = 3072 // FIPS-approved, comfortably above the 2048 floor
	defaultECDSAField = 256  // P-256
)

// KeySpec describes the subject keypair to generate server-side.
type KeySpec struct {
	// Type is "ecdsa" (default) or "rsa". Ed25519 is intentionally unsupported:
	// PKCS#12 with Ed25519 keys interoperates poorly across common consumers.
	Type string
	// Bits is the RSA modulus size (default 3072, minimum 2048) or the ECDSA
	// curve field size (256, 384, or 521; default 256). Zero selects the default.
	Bits int
}

// BundleRequest is a full server-side-keygen + issue + bundle request.
type BundleRequest struct {
	// CAID identifies the issuing CA (must be an X.509 CA).
	CAID string
	// Profile is the certificate profile name (empty = the CA manager's default).
	Profile string
	// Subject is the leaf distinguished name.
	Subject pkix.Name
	// Subject Alternative Names. Any combination may be set; the profile still
	// governs which are permitted.
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []*url.URL
	// Key selects the subject keypair to generate.
	Key KeySpec
	// Validity overrides the profile default (0 = profile default), clamped by the
	// CA manager to the profile maximum and the CA's own expiry.
	Validity time.Duration
	// Password protects the PKCS#12 bundle. Required, at least MinPasswordLen.
	Password string
	// Encoder selects the PKCS#12 encoding (see the Encoder* constants). Empty =
	// EncoderModern.
	Encoder string
	// RequestedBy records who requested the certificate (for audit/renewal).
	RequestedBy string
}

// BundleResult is the outcome of a server-side-keygen PKCS#12 export.
type BundleResult struct {
	// PKCS12 is the password-protected DER-encoded PKCS#12 bundle: the subject
	// key, the leaf, and the full issuer chain.
	PKCS12 []byte
	// Leaf is the issued end-entity certificate.
	Leaf *x509.Certificate
	// Serial is the leaf serial number.
	Serial *big.Int
	// Profile is the profile the leaf was issued under.
	Profile string
	// ChainPEM is the full chain for display/AIA: leaf followed by every issuer up
	// to the root. It carries certificates only, never keys.
	ChainPEM []byte
	// CACerts are the issuer chain certificates (intermediates up to the root) that
	// were bundled alongside the leaf, in order.
	CACerts []*x509.Certificate
	// PrivateKeyPKCS8 is the freshly-generated subject private key in PKCS#8 DER.
	// It is provided so a caller may optionally escrow it (Task 33). Callers MUST
	// zeroize it once done; it is never persisted by this package.
	PrivateKeyPKCS8 []byte
	// KeyType is the resolved subject key description (e.g. "ecdsa-p256",
	// "rsa-3072").
	KeyType string
	// Encoder is the resolved encoder name used.
	Encoder string
	// CT summarizes Certificate Transparency handling for the issuance (nil-safe:
	// see ca.IssueResult.CT).
	CT *ca.CTStatus
}

// GenerateAndBundle generates a subject keypair, issues a leaf certificate
// through the CA manager, and returns a password-protected PKCS#12 bundle
// containing the subject key, the leaf, and the full issuer chain.
//
// The CA signing key never leaves the HSM: mgr.IssueCertificate uses it only as
// a crypto.Signer. Only the software-generated subject key is placed in the
// bundle.
func GenerateAndBundle(ctx context.Context, mgr *ca.Manager, req BundleRequest) (*BundleResult, error) {
	if mgr == nil {
		return nil, fmt.Errorf("pkcs12: nil CA manager")
	}
	if req.CAID == "" {
		return nil, fmt.Errorf("pkcs12: issuing CA is required")
	}
	if len(req.Password) < MinPasswordLen {
		return nil, fmt.Errorf("pkcs12: password must be at least %d characters", MinPasswordLen)
	}
	if req.Subject.CommonName == "" && len(req.DNSNames) == 0 && len(req.EmailAddresses) == 0 &&
		len(req.IPAddresses) == 0 && len(req.URIs) == 0 {
		return nil, fmt.Errorf("pkcs12: a subject common name or at least one SAN is required")
	}

	enc, encName, err := EncoderFor(req.Encoder)
	if err != nil {
		return nil, err
	}

	// Generate the subject keypair in software. This is the ONLY private key that
	// will be bundled.
	key, keyType, err := generateSubjectKey(req.Key)
	if err != nil {
		return nil, err
	}
	// Refuse a non-FIPS-approved subject key when the FIPS policy is enforced,
	// consistent with the rest of the issuance stack.
	if err := fips.CheckPublicKey(key.Public()); err != nil {
		return nil, fmt.Errorf("pkcs12: %w", err)
	}

	// Build and self-sign a CSR carrying the requested subject and SANs. The CA
	// takes the subject/public-key/SANs from it, and the self-signature proves
	// possession of the freshly-generated key.
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:        req.Subject,
		DNSNames:       req.DNSNames,
		IPAddresses:    req.IPAddresses,
		EmailAddresses: req.EmailAddresses,
		URIs:           req.URIs,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: building CSR: %w", err)
	}
	csrPEM := pki.EncodeCSRPEM(csrDER)

	result, err := mgr.IssueCertificate(ctx, ca.IssueSpec{
		CAID:        req.CAID,
		CSRPEM:      csrPEM,
		Profile:     req.Profile,
		Validity:    req.Validity,
		RequestedBy: req.RequestedBy,
	})
	if err != nil {
		return nil, err
	}

	// Assemble the issuer chain (intermediates up to the root, plus any external
	// parent chain). CombinedChainPEM never includes the leaf, so every parsed
	// certificate here is a CA certificate suitable for the PKCS#12 caCerts.
	caChainPEM, err := mgr.CombinedChainPEM(req.CAID)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: assembling issuer chain: %w", err)
	}
	caCerts, err := parseCertsPEM(caChainPEM)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: parsing issuer chain: %w", err)
	}

	pfx, err := enc.Encode(key, result.Certificate, caCerts, req.Password)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: encoding bundle: %w", err)
	}

	// Marshal the subject key to PKCS#8 for optional escrow by the caller. This is
	// the same key already sealed (encrypted) inside the bundle; returning it lets
	// a caller additionally escrow it under the M-of-N policy.
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pkcs12: marshaling subject key: %w", err)
	}

	// Full chain for display: leaf followed by the issuer chain.
	fullChain := make([]byte, 0, len(result.PEM)+len(caChainPEM))
	fullChain = append(fullChain, result.PEM...)
	fullChain = append(fullChain, caChainPEM...)

	return &BundleResult{
		PKCS12:          pfx,
		Leaf:            result.Certificate,
		Serial:          result.Serial,
		Profile:         result.Profile,
		ChainPEM:        fullChain,
		CACerts:         caCerts,
		PrivateKeyPKCS8: pkcs8,
		KeyType:         keyType,
		Encoder:         encName,
		CT:              result.CT,
	}, nil
}

// EscrowContext derives the encryption context bound into a PKCS#12 subject
// key's escrow envelope. Binding it to the certificate serial ties the escrowed
// key to the certificate it belongs to; the same value must be supplied verbatim
// at recovery time (`secsy-secret recover -context`).
func EscrowContext(serial string) string { return "pkcs12/" + serial }

// EncoderFor resolves an encoder name to a go-pkcs12 Encoder and its canonical
// name. An empty name selects EncoderModern. When the FIPS policy is enforced,
// the legacy encoders (which rely on 3DES/RC2 and SHA-1) are refused; only the
// modern PBES2/AES-256/HMAC-SHA-256 encoder is FIPS-appropriate.
func EncoderFor(name string) (*sslpkcs12.Encoder, string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", EncoderModern, "modern2023":
		return sslpkcs12.Modern2023, EncoderModern, nil
	case EncoderLegacyDES, "legacydes", "des":
		if fips.PolicyEnforced() {
			return nil, "", fmt.Errorf("pkcs12: legacy encoder is not permitted in FIPS mode (uses 3DES/SHA-1); use %q", EncoderModern)
		}
		return sslpkcs12.LegacyDES, EncoderLegacyDES, nil
	case EncoderLegacyRC2, "rc2":
		if fips.PolicyEnforced() {
			return nil, "", fmt.Errorf("pkcs12: legacy encoder is not permitted in FIPS mode (uses RC2/SHA-1); use %q", EncoderModern)
		}
		return sslpkcs12.LegacyRC2, EncoderLegacyRC2, nil
	default:
		return nil, "", fmt.Errorf("pkcs12: unknown encoder %q (want %q, %q, or %q)", name, EncoderModern, EncoderLegacyDES, EncoderLegacyRC2)
	}
}

// generateSubjectKey generates the subject keypair per the spec and returns it
// as a crypto.Signer together with a human-readable key-type description.
func generateSubjectKey(spec KeySpec) (crypto.Signer, string, error) {
	switch strings.ToLower(strings.TrimSpace(spec.Type)) {
	case "", DefaultKeyType:
		bits := spec.Bits
		if bits == 0 {
			bits = defaultECDSAField
		}
		var curve elliptic.Curve
		switch bits {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, "", fmt.Errorf("pkcs12: ECDSA curve size must be 256, 384, or 521 (got %d)", bits)
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, "", fmt.Errorf("pkcs12: generating ECDSA key: %w", err)
		}
		return key, fmt.Sprintf("ecdsa-p%d", bits), nil
	case "rsa":
		bits := spec.Bits
		if bits == 0 {
			bits = defaultRSABits
		}
		if bits < 2048 {
			return nil, "", fmt.Errorf("pkcs12: RSA key size must be at least 2048 bits (got %d)", bits)
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return nil, "", fmt.Errorf("pkcs12: generating RSA key: %w", err)
		}
		return key, fmt.Sprintf("rsa-%d", bits), nil
	default:
		return nil, "", fmt.Errorf("pkcs12: unsupported key type %q (want %q or %q)", spec.Type, DefaultKeyType, "rsa")
	}
}

// parseCertsPEM decodes every CERTIFICATE block in a PEM bundle, preserving
// order. It skips non-certificate blocks defensively.
func parseCertsPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
