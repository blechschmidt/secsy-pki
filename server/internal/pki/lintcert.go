package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sync"
)

// LintCertificateDER builds a "linting certificate": the exact leaf template
// that CreateLeafCertificate would sign, signed with a freshly generated,
// process-local throwaway key whose signature algorithm matches the issuer's.
// It exists so a structural linter (notably zlint, which parses DER) can inspect
// the certificate that WOULD be issued — with its subject, SANs, validity,
// serial, key usage, EKU, basic constraints, subject/authority key identifiers,
// CRL distribution points, AIA, and policy/CT extensions all faithfully encoded
// — WITHOUT invoking the HSM or consuming a real signature.
//
// The signature bytes are NOT cryptographically valid and the returned DER must
// never be persisted, published, or served: it is a lint artifact only.
// Structural lints do not verify the signature, and matching the issuer's key
// algorithm keeps signature-algorithm lints faithful. This mirrors the
// pre-issuance "linting certificate" technique used by production CA software.
func LintCertificateDER(issuer *x509.Certificate, req LeafCertRequest) ([]byte, error) {
	if issuer == nil {
		return nil, fmt.Errorf("linting certificate requires an issuing CA certificate")
	}
	template, err := leafTemplate(req)
	if err != nil {
		return nil, err
	}
	signer, err := ephemeralSignerFor(issuer.PublicKey)
	if err != nil {
		return nil, err
	}

	// crypto/x509.CreateCertificate refuses to sign when the signing key does not
	// match the parent certificate's public key. Since we sign with a throwaway
	// key, the parent must be a synthetic "linting issuer" that carries the
	// throwaway public key but the REAL issuer's distinguished name and subject
	// key identifier — so the resulting leaf's issuer field and authority key
	// identifier are faithful to what the real CA would emit.
	lintIssuer := &x509.Certificate{
		RawSubject:            issuer.RawSubject,
		Subject:               issuer.Subject,
		SubjectKeyId:          issuer.SubjectKeyId,
		PublicKey:             signer.Public(),
		NotBefore:             issuer.NotBefore,
		NotAfter:              issuer.NotAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, lintIssuer, req.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("creating linting certificate: %w", err)
	}
	return der, nil
}

// Throwaway signing keys are generated once per algorithm and reused for the
// lifetime of the process. They only ever produce cryptographically meaningless
// signatures on lint artifacts, so reuse is safe and avoids per-issuance key
// generation latency on the pre-issuance lint path.
var (
	lintRSAOnce sync.Once
	lintRSAKey  *rsa.PrivateKey
	lintRSAErr  error

	lintEd25519Once sync.Once
	lintEd25519Key  ed25519.PrivateKey
	lintEd25519Err  error

	lintECDSAKeys sync.Map // elliptic.Curve -> ecdsaKeyResult
)

type ecdsaKeyResult struct {
	key *ecdsa.PrivateKey
	err error
}

// ephemeralSignerFor returns a throwaway crypto.Signer whose key algorithm
// matches issuerPub, so the linting certificate's signatureAlgorithm equals the
// one the real issuer would use. Only classical CA key algorithms are supported;
// a post-quantum issuer (ML-DSA) cannot be reproduced with crypto/x509 and
// returns an error so the caller skips DER-based linting for that certificate.
func ephemeralSignerFor(issuerPub crypto.PublicKey) (crypto.Signer, error) {
	switch pub := issuerPub.(type) {
	case *rsa.PublicKey:
		lintRSAOnce.Do(func() {
			// 2048 bits is the smallest FIPS-approved RSA size and yields the same
			// SHA-256-with-RSA signature algorithm crypto/x509 selects for larger RSA
			// issuers, so it is a faithful, fast stand-in regardless of the real key size.
			lintRSAKey, lintRSAErr = rsa.GenerateKey(rand.Reader, 2048)
		})
		return lintRSAKey, lintRSAErr
	case *ecdsa.PublicKey:
		curve := pub.Curve
		if v, ok := lintECDSAKeys.Load(curve); ok {
			r := v.(ecdsaKeyResult)
			return r.key, r.err
		}
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		lintECDSAKeys.Store(curve, ecdsaKeyResult{key: key, err: err})
		return key, err
	case ed25519.PublicKey:
		lintEd25519Once.Do(func() {
			_, lintEd25519Key, lintEd25519Err = ed25519.GenerateKey(rand.Reader)
		})
		return lintEd25519Key, lintEd25519Err
	default:
		return nil, fmt.Errorf("cannot build a linting certificate for a %T issuing key", issuerPub)
	}
}
