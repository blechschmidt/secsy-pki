package attestation

import (
	"crypto/x509"
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/cms"
)

// VerifyEnrollment is the EST/SCEP-facing entry point. It inspects a CSR for an
// attestation-certificate bundle, verifies it against the trusted manufacturer
// roots, binds the attested key to the CSR's public key, and applies the
// profile's enforcement mode — returning a Decision the caller audits and acts
// on.
//
// The attestation is carried in a PKCS#10 extension (oidAttestationBundle) whose
// value is a certs-only CMS (SignedData) holding the attestation leaf first,
// then any manufacturer intermediates. The attestation leaf certifies the
// enrolled key: its subject public key MUST equal the CSR's public key (the
// YubiKey PIV attestation model, and the general "accompanying attestation cert
// chain" case), which is what proves the *enrolled* key — not some other key —
// is the hardware-resident one.
func (v *Verifier) VerifyEnrollment(profile string, csr *x509.CertificateRequest) Decision {
	if v.Mode(profile) == ModeOff {
		return v.decide(profile, nil, nil)
	}
	res, err := v.verifyPKCS10(csr)
	return v.decide(profile, res, err)
}

// verifyPKCS10 extracts and verifies the attestation bundle from a CSR. It
// returns ErrNoAttestation when the CSR carries no bundle, or a populated
// (Verified=false) Result plus an error when a bundle is present but invalid.
func (v *Verifier) verifyPKCS10(csr *x509.CertificateRequest) (*Result, error) {
	chain, err := attestationBundleFromCSR(csr)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, ErrNoAttestation
	}
	return v.verifyAttestationChain(chain, csr.PublicKey)
}

// verifyAttestationChain verifies an attestation certificate chain (leaf first)
// against the trusted roots and binds the leaf's subject public key to
// enrolledKey. It is shared by the CSR path and any other cert-chain-based
// attestation. enrolledKey may be nil to skip the binding check (e.g. when the
// binding is proven by a separate attestation statement).
func (v *Verifier) verifyAttestationChain(chain []*x509.Certificate, enrolledKey interface{}) (*Result, error) {
	leaf := chain[0]
	res := &Result{}
	describeAttestationCert(leaf, res)

	if _, err := v.verifyChain(leaf, chain[1:]); err != nil {
		res.Reason = err.Error()
		return res, fmt.Errorf("attestation certificate chain is untrusted: %w", err)
	}

	// Bind the attested key to the enrolled key. The attestation leaf certifies
	// the hardware key; if that key is not the one being enrolled, the
	// attestation proves nothing about the enrolled key.
	if enrolledKey != nil {
		if !publicKeysEqual(leaf.PublicKey, enrolledKey) {
			res.Reason = "attested key does not match the enrolled (CSR) public key"
			return res, fmt.Errorf("attestation key binding failed: %s", res.Reason)
		}
		res.AttestedKey = leaf.PublicKey
	}

	res.Verified = true
	res.HardwareResident = true
	res.NonExportable = true
	if res.Reason == "" {
		res.Reason = "hardware attestation verified"
	}
	return res, nil
}

// attestationBundleFromCSR extracts the attestation certificate chain from a
// CSR's oidAttestationBundle extension, if present. The extension value is a
// certs-only CMS structure; the returned slice is leaf-first (as embedded).
func attestationBundleFromCSR(csr *x509.CertificateRequest) ([]*x509.Certificate, error) {
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal(oidAttestationBundle) {
			continue
		}
		parsed, err := cms.ParseSignedData(ext.Value)
		if err != nil {
			return nil, fmt.Errorf("parsing attestation bundle: %w", err)
		}
		if len(parsed.Certificates) == 0 {
			return nil, fmt.Errorf("attestation bundle carries no certificates")
		}
		return parsed.Certificates, nil
	}
	// x509 also surfaces requested extensions via ExtraExtensions on some paths;
	// check the extensionRequest attribute copy exposed as Extensions above is the
	// canonical location, so absence there means no bundle.
	return nil, nil
}

// BuildCSRAttestationExtension packages an attestation certificate chain
// (leaf first) into the PKCS#10 extension a client adds to its CSR so the
// EST/SCEP server can verify it. It is exported for use by test clients and the
// enrollment tooling.
func BuildCSRAttestationExtension(chain []*x509.Certificate) (oid []int, value []byte, err error) {
	der, err := cms.DegenerateCertsOnly(chain)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding attestation bundle: %w", err)
	}
	return oidAttestationBundle, der, nil
}
