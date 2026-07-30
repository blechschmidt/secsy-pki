package ca

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
	"go.opentelemetry.io/otel/attribute"
)

// CollectRevocation gathers long-term-validation (LTV) revocation evidence for a
// certificate chain, implementing the signing.RevocationSource interface used by
// the artifact-signing service to raise a signature to CAdES-LT. For every
// non-self-signed certificate in the chain whose issuer is a CA known to this
// deployment it produces:
//
//   - a fresh, HSM-signed OCSP response — only when the certificate is a recorded
//     issued leaf (so the responder can answer good/revoked rather than unknown);
//     this gives verifiers a precise status for the signer certificate, and
//   - the issuing CA's current base CRL (one per issuer, de-duplicated), which
//     proves the certificate is not revoked by its absence and covers
//     intermediate CA certificates that OCSP cannot definitively answer for.
//
// The result therefore embeds an OCSP "good" for the signer leaf plus the CRLs
// of every CA in its chain — enough to validate the chain offline after the
// certificates expire. It is best-effort: certificates whose issuer is not a
// known CA (a self-signed root, or an externally issued parent) are skipped, and
// a transient failure producing one object does not abort the others.
//
// All returned bytes are DER: OCSP responses are complete OCSPResponse
// structures; CRLs are CertificateLists.
func (m *Manager) CollectRevocation(ctx context.Context, chain []*x509.Certificate) (ocspResponses [][]byte, crls [][]byte, err error) {
	ctx, span := tracing.Start(ctx, "ca.collect_revocation", attribute.Int("chain.len", len(chain)))
	defer func() { tracing.End(span, err) }()

	issuerIndex, err := m.caSubjectIndex()
	if err != nil {
		return nil, nil, err
	}

	crlDone := map[string]bool{} // issuing CA id → CRL already gathered
	for _, cert := range chain {
		// A self-signed certificate (a root) has no issuer to attest to it.
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			continue
		}
		issuerCA := issuerIndex[string(cert.RawIssuer)]
		if issuerCA == nil {
			// Issuer is not a CA of this deployment (e.g. an external parent). We
			// cannot produce authoritative revocation material for it; skip.
			continue
		}

		// OCSP only for recorded leaves — for an unknown serial the responder would
		// answer "unknown", which carries no long-term value.
		if status, _, _, sErr := m.certStatus(issuerCA.ID, cert.SerialNumber); sErr == nil && status != pki.OCSPUnknown {
			if der, oErr := m.OCSPStapleForCertificate(ctx, issuerCA.ID, cert, OCSPRespondOptions{}); oErr == nil {
				ocspResponses = append(ocspResponses, der)
			}
		}

		// One complete CRL per issuing CA covers every certificate it issued.
		if !crlDone[issuerCA.ID] {
			crlDone[issuerCA.ID] = true
			if der, cErr := m.GetBaseCRL(ctx, issuerCA.ID, FullScope); cErr == nil {
				crls = append(crls, der)
			}
		}
	}
	return ocspResponses, crls, nil
}

// caSubjectIndex maps each X.509 CA's certificate subject DN (raw DER) to the CA
// record, so a chain certificate's issuer can be resolved to the CA that issued
// it. Subjects are unique across a deployment's CAs in practice; on a collision
// the first wins, which is acceptable for best-effort revocation gathering.
func (m *Manager) caSubjectIndex() (map[string]*models.CA, error) {
	cas, err := m.db.ListCAs()
	if err != nil {
		return nil, fmt.Errorf("ca: listing CAs for revocation lookup: %w", err)
	}
	index := make(map[string]*models.CA, len(cas))
	for i := range cas {
		if cas[i].Certificate == "" {
			continue
		}
		cert, err := pki.ParseCertificatePEM([]byte(cas[i].Certificate))
		if err != nil {
			continue // a single unparsable CA record must not break gathering
		}
		key := string(cert.RawSubject)
		if _, exists := index[key]; !exists {
			index[key] = &cas[i]
		}
	}
	return index, nil
}
