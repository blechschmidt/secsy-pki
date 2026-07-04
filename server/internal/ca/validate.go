package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/blechschmidt/secsy-pki/server/internal/certvalidate"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// Certificate chain/path validation support (Task 123). These read-only,
// HSM-independent helpers let the REST/gRPC/CLI validation surfaces resolve a
// CA's configured trust anchors and each certificate's live revocation status —
// the two pieces of state the pure internal/certvalidate engine cannot compute on
// its own — while every gate (path building, name constraints, certificate
// policy, expiry, key usage, weak key/signature) stays in the engine.

// TrustAnchorsFor resolves the trust anchors and bridging intermediates for
// validating certificates issued under caID. The roots are the self-signed
// anchor(s) of the CA's combined overlap chain (the active issuer, any rollover
// siblings, and the ancestors up to the root); the intermediates are the
// remaining CA certificates that bridge a leaf to those anchors. When the bundle
// contains no self-signed root — an externally-signed subordinate CA whose
// offline/third-party root was not imported — the topmost available certificate
// is promoted to the anchor position (best effort), so validation still resolves
// against the highest authority this deployment holds.
func (m *Manager) TrustAnchorsFor(caID string) (roots, intermediates []*x509.Certificate, err error) {
	authorities, err := m.TrustBundleAuthorities(caID)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range authorities {
		if bytes.Equal(c.RawSubject, c.RawIssuer) {
			roots = append(roots, c)
		} else {
			intermediates = append(intermediates, c)
		}
	}
	if len(roots) == 0 && len(authorities) > 0 {
		top := authorities[len(authorities)-1]
		roots = []*x509.Certificate{top}
		intermediates = intermediates[:0]
		for _, c := range authorities {
			if c != top {
				intermediates = append(intermediates, c)
			}
		}
	}
	return roots, intermediates, nil
}

// LiveRevocationStatus returns the current revocation status of the certificate
// with the given serial as issued by caID, consulting the same revocation store
// that backs OCSP and the CRL — including the reversible on-hold state (RFC 5280
// certificateHold), which is reported distinctly from a permanent revocation.
func (m *Manager) LiveRevocationStatus(caID string, serial *big.Int) (certvalidate.RevocationStatus, error) {
	const source = "internal revocation store (CRL/OCSP)"
	status, revokedAt, reason, err := m.certStatus(caID, serial)
	if err != nil {
		return certvalidate.RevocationStatus{}, err
	}
	switch status {
	case pki.OCSPRevoked:
		st := certvalidate.RevocationStatus{
			RevokedAt:  revokedAt,
			Reason:     reason,
			ReasonText: pki.RevocationReasonName(reason),
			Source:     source,
		}
		if reason == pki.RevocationReasonCertificateHold {
			st.State = certvalidate.RevocationHeld
		} else {
			st.State = certvalidate.RevocationRevoked
		}
		return st, nil
	case pki.OCSPGood:
		return certvalidate.RevocationStatus{State: certvalidate.RevocationGood, Source: source}, nil
	default:
		return certvalidate.RevocationStatus{State: certvalidate.RevocationUnknown, Source: source}, nil
	}
}

// chainRevocationResolver implements certvalidate.RevocationResolver by mapping a
// chain certificate's issuer (the next certificate up the resolved path) to the
// managed CA that issued it — matched by the issuer certificate's exact DER
// fingerprint, which correctly distinguishes rollover siblings that share a
// subject — and then looking up the child serial's live status under that CA.
type chainRevocationResolver struct {
	mgr      *Manager
	byIssuer map[string]string // sha256(issuer DER) -> caID
}

// NewChainRevocationResolver builds a revocation resolver over the supplied CA
// records (typically every CA in the validating tenant). A certificate whose
// issuer is not one of these CAs is reported "unknown" rather than erroring: this
// PKI holds no revocation authority over an issuer it does not manage.
func (m *Manager) NewChainRevocationResolver(cas []models.CA) certvalidate.RevocationResolver {
	idx := make(map[string]string, len(cas))
	for _, c := range cas {
		if c.Certificate == "" {
			continue
		}
		cert, err := pki.ParseCertificatePEM([]byte(c.Certificate))
		if err != nil {
			continue
		}
		idx[certFingerprint(cert.Raw)] = c.ID
	}
	return &chainRevocationResolver{mgr: m, byIssuer: idx}
}

// Revocation resolves the live status of cert, issued by issuer.
func (r *chainRevocationResolver) Revocation(cert, issuer *x509.Certificate) (certvalidate.RevocationStatus, error) {
	if issuer == nil || cert == nil || cert.SerialNumber == nil {
		return certvalidate.RevocationStatus{State: certvalidate.RevocationUnknown}, nil
	}
	caID, ok := r.byIssuer[certFingerprint(issuer.Raw)]
	if !ok {
		return certvalidate.RevocationStatus{
			State:  certvalidate.RevocationUnknown,
			Source: fmt.Sprintf("issuer %q is not a CA managed by this PKI", issuer.Subject.CommonName),
		}, nil
	}
	return r.mgr.LiveRevocationStatus(caID, cert.SerialNumber)
}

func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return string(sum[:])
}
