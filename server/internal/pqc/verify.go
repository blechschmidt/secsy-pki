package pqc

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/cloudflare/circl/sign"
)

// PublicKeyFromCert returns the subject public key of a certificate, decoding
// ML-DSA keys (which crypto/x509 leaves as a nil PublicKey) from the raw
// SubjectPublicKeyInfo. For classical certificates it returns cert.PublicKey.
// The boolean reports whether the key is post-quantum.
func PublicKeyFromCert(cert *x509.Certificate) (crypto.PublicKey, bool, error) {
	if cert.PublicKey != nil {
		return cert.PublicKey, IsPQCPublicKey(cert.PublicKey), nil
	}
	pub, _, err := ParsePKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		if IsUnsupportedAlgorithm(err) {
			return nil, false, fmt.Errorf("pqc: certificate has an unsupported public key algorithm")
		}
		return nil, false, err
	}
	return pub, true, nil
}

// VerifyMLDSASignature verifies that certDER's ML-DSA signature was produced by
// issuerPub (an ML-DSA public key). It checks the certificate's own
// signatureAlgorithm against issuerPub's scheme.
func VerifyMLDSASignature(certDER []byte, issuerPub crypto.PublicKey) error {
	pub, ok := issuerPub.(sign.PublicKey)
	if !ok {
		return fmt.Errorf("pqc: issuer key is not an ML-DSA public key (%T)", issuerPub)
	}
	oid, sig, err := certSignature(certDER)
	if err != nil {
		return err
	}
	a, ok := algorithmByOID(oid)
	if !ok {
		return fmt.Errorf("pqc: certificate is not ML-DSA signed (%v)", oid)
	}
	if a.scheme == nil || a.scheme.Name() != pub.Scheme().Name() {
		return fmt.Errorf("pqc: issuer key algorithm does not match certificate signature algorithm")
	}
	tbs, err := certTBS(certDER)
	if err != nil {
		return err
	}
	if !a.scheme.Verify(pub, tbs, sig, nil) {
		return fmt.Errorf("pqc: ML-DSA signature verification failed")
	}
	return nil
}

// VerifyOptions bounds a chain verification.
type VerifyOptions struct {
	// CurrentTime is the instant validity is checked at (zero means time.Now).
	CurrentTime time.Time
}

// VerifyChain verifies an ordered certificate chain [leaf, …, root] where each
// certificate is signed by the next and the last is a self-signed root. Each link
// may independently be classical or pure ML-DSA, so it verifies fully
// post-quantum chains as well as mixed ones. It checks the issuer/subject name
// linkage, validity windows, and CA basic constraints on issuers.
//
// It is deliberately a focused verifier for internally issued chains, not a
// general path builder: it does not consult a system trust store, handle name
// constraints, or process revocation (see the CRL/OCSP paths for that).
func VerifyChain(chainDER [][]byte, opts VerifyOptions) error {
	if len(chainDER) == 0 {
		return fmt.Errorf("pqc: empty chain")
	}
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}

	certs := make([]*x509.Certificate, len(chainDER))
	for i, der := range chainDER {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("pqc: parsing chain certificate %d: %w", i, err)
		}
		certs[i] = c
	}

	for i, c := range certs {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return fmt.Errorf("pqc: certificate %d (%s) is not valid at %s", i, c.Subject, now)
		}
	}

	// Each non-root link: certs[i] must be issued by certs[i+1].
	for i := 0; i+1 < len(certs); i++ {
		if err := verifyIssued(chainDER[i], certs[i], certs[i+1], true); err != nil {
			return fmt.Errorf("pqc: verifying certificate %d against issuer %d: %w", i, i+1, err)
		}
	}

	// Root must be self-signed.
	root := certs[len(certs)-1]
	if err := verifyIssued(chainDER[len(certs)-1], root, root, false); err != nil {
		return fmt.Errorf("pqc: verifying self-signed root: %w", err)
	}
	return nil
}

// verifyIssued verifies that child (childDER/childCert) was issued by issuer.
// When requireCA is true the issuer must be a CA authorized to sign certificates.
func verifyIssued(childDER []byte, child, issuer *x509.Certificate, requireCA bool) error {
	if !bytes.Equal(child.RawIssuer, issuer.RawSubject) {
		return fmt.Errorf("issuer name mismatch")
	}
	issuerPub, issuerPQC, err := PublicKeyFromCert(issuer)
	if err != nil {
		return err
	}
	if requireCA {
		if !issuer.IsCA {
			return fmt.Errorf("issuer is not a CA")
		}
		if issuer.KeyUsage != 0 && issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("issuer key usage does not permit certificate signing")
		}
	}
	if issuerPQC {
		return VerifyMLDSASignature(childDER, issuerPub)
	}
	// Classical issuer: delegate to the standard library, which verifies the
	// child's signature against the issuer's public key (and re-checks the
	// issuer's CA basic constraints and certificate-signing key usage).
	_ = issuerPub
	return child.CheckSignatureFrom(issuer)
}
