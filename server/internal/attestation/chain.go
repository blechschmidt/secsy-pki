package attestation

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
)

// constantTimeEqual reports byte-equality in constant time, used for nonce and
// digest comparisons where a timing side-channel should be avoided.
func constantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// verifyChain establishes that leaf chains to one of the Verifier's trusted
// manufacturer roots, using extra (the intermediates carried alongside the
// attestation) plus any configured intermediates. It returns the verified chain
// on success.
//
// KeyUsages is set to ExtKeyUsageAny because attestation certificates carry a
// grab-bag of vendor-specific EKUs (e.g. the TCG AIK EKU 2.23.133.8.3, or none
// at all for YubiKey PIV attestation leaves); pinning a specific EKU would
// reject legitimate hardware. Trust is established purely by chaining to a
// configured manufacturer root — the operator's explicit trust decision.
func (v *Verifier) verifyChain(leaf *x509.Certificate, extra []*x509.Certificate) ([]*x509.Certificate, error) {
	if v.roots == nil || len(v.roots.Subjects()) == 0 { //nolint:staticcheck
		return nil, errors.New("no trusted manufacturer roots configured")
	}
	// Build a fresh per-request intermediate pool from the configured
	// intermediates plus any intermediates carried alongside the attestation.
	inter := x509.NewCertPool()
	for _, c := range v.intermediates {
		inter.AddCert(c)
	}
	for _, c := range extra {
		if c != nil && !bytes.Equal(c.Raw, leaf.Raw) {
			inter.AddCert(c)
		}
	}

	opts := x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: inter,
		CurrentTime:   v.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	chains, err := leaf.Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("chain does not reach a trusted manufacturer root: %w", err)
	}
	// Return the first (shortest) valid chain.
	return chains[0], nil
}

// publicKeysEqual reports whether two public keys are the same key, by comparing
// their PKIX (SubjectPublicKeyInfo) DER encodings. This binds an attested key to
// an enrolled key across type boundaries (RSA/ECDSA/Ed25519) without
// type-specific comparisons.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	ab, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bb, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return bytes.Equal(ab, bb)
}
