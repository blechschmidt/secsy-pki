package ca

import (
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// AlternateChain is one publishable trust path for a subject CA. The native
// chain is the one rooted at the subject's own parent lineage; each cross-sign
// yields a further chain rooted at a different issuer's trust anchor. Operators
// select whichever chain a relying party trusts.
type AlternateChain struct {
	// CrossSignID identifies the cross-sign this chain derives from; empty for the
	// native chain (the subject's own parent lineage).
	CrossSignID string `json:"cross_sign_id,omitempty"`
	// IssuerCAID is the CA at the top of this chain's trust path (the subject's
	// parent for the native chain, or the cross-signing CA otherwise).
	IssuerCAID string `json:"issuer_ca_id"`
	// IssuerLabel is the issuer CA's human-readable label.
	IssuerLabel string `json:"issuer_label"`
	// Native reports whether this is the subject's own parent-lineage chain.
	Native bool `json:"native"`
	// PEM is the chain bundle: the subject (as certified by this issuer) followed
	// by the issuer's chain to its trust anchor.
	PEM string `json:"pem"`
}

// AlternateChains returns every publishable chain for a subject CA: its native
// parent-lineage chain plus one chain per active cross-sign of its key. A relying
// party is served whichever chain terminates at a trust anchor it holds.
//
// caID identifies the subject CA (any id in its rollover lineage). Chains are
// returned native-first, then by cross-sign creation order.
func (m *Manager) AlternateChains(caID string) ([]AlternateChain, error) {
	subject, err := m.db.GetCA(caID)
	if err != nil {
		return nil, fmt.Errorf("looking up CA: %w", err)
	}
	if subject == nil {
		return nil, fmt.Errorf("CA %q not found", caID)
	}

	var chains []AlternateChain

	// Native chain: the subject's own overlap bundle up to its root. A root CA has
	// no parent lineage to publish, so only its cross-signs are alternate chains.
	if subject.ParentID != nil {
		nativePEM, err := m.CombinedChainPEM(subject.ID)
		if err != nil {
			return nil, err
		}
		parentLabel := ""
		if parent, err := m.db.GetCA(*subject.ParentID); err == nil && parent != nil {
			parentLabel = parent.Label
		}
		chains = append(chains, AlternateChain{
			IssuerCAID:  *subject.ParentID,
			IssuerLabel: parentLabel,
			Native:      true,
			PEM:         string(nativePEM),
		})
	}

	// Cross-signed chains: gather every active cross-sign whose subject is this CA.
	// Match both by explicit subject-CA linkage and by Subject Key Identifier so a
	// cross-sign of an imported copy of the same key is still surfaced.
	crossSigns, err := m.crossSignsForSubject(subject)
	if err != nil {
		return nil, err
	}
	for i := range crossSigns {
		cs := crossSigns[i]
		if cs.Status != models.CrossSignStatusActive {
			continue
		}
		chainPEM, err := m.crossSignChainPEM(&cs, cs.IssuerCAID)
		if err != nil {
			return nil, err
		}
		issuerLabel := ""
		if issuer, err := m.db.GetCA(cs.IssuerCAID); err == nil && issuer != nil {
			issuerLabel = issuer.Label
		}
		chains = append(chains, AlternateChain{
			CrossSignID: cs.ID,
			IssuerCAID:  cs.IssuerCAID,
			IssuerLabel: issuerLabel,
			Native:      false,
			PEM:         string(chainPEM),
		})
	}

	return chains, nil
}

// crossSignsForSubject returns the cross-signs certifying a subject CA's key,
// de-duplicated by id. It joins on both the explicit subject-CA link and the
// subject's Subject Key Identifier so alternate chains are found regardless of
// how the cross-sign subject was originally supplied.
func (m *Manager) crossSignsForSubject(subject *models.CA) ([]models.CrossSign, error) {
	seen := map[string]bool{}
	var out []models.CrossSign

	byCA, err := m.db.ListCrossSignsBySubjectCA(subject.ID)
	if err != nil {
		return nil, fmt.Errorf("listing cross-signs for subject CA: %w", err)
	}
	for _, cs := range byCA {
		if !seen[cs.ID] {
			seen[cs.ID] = true
			out = append(out, cs)
		}
	}

	// Also match by SKI, covering cross-signs imported as a foreign certificate/CSR
	// that happen to carry this CA's key, and rollover siblings sharing the key.
	if ski := m.subjectKeyIDHex(subject); ski != "" {
		byKey, err := m.db.ListCrossSignsForSubjectKey(ski)
		if err != nil {
			return nil, fmt.Errorf("listing cross-signs for subject key: %w", err)
		}
		for _, cs := range byKey {
			if !seen[cs.ID] {
				seen[cs.ID] = true
				out = append(out, cs)
			}
		}
	}
	return out, nil
}

// subjectKeyIDHex returns the hex Subject Key Identifier of a CA's certificate,
// or "" when it has no parseable certificate/SKI.
func (m *Manager) subjectKeyIDHex(ca *models.CA) string {
	if ca.Certificate == "" {
		return ""
	}
	cert, err := pki.ParseCertificatePEM([]byte(ca.Certificate))
	if err != nil {
		return ""
	}
	if len(cert.SubjectKeyId) == 0 {
		return ""
	}
	return hex.EncodeToString(cert.SubjectKeyId)
}

// splitPEMCerts splits a PEM bundle into its individual CERTIFICATE blocks, each
// re-encoded as a canonical PEM string, so a chain can be concatenated without
// duplicating certificates.
func splitPEMCerts(bundle []byte) []string {
	var out []string
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		out = append(out, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes})))
	}
	return out
}

// crossSignChainPEM builds the alternate chain for a cross-sign: the
// cross-certificate followed by the issuer's own overlap chain to its trust
// anchor, so a relying party holding the issuer's anchor can build a full path.
func (m *Manager) crossSignChainPEM(cs *models.CrossSign, issuerCAID string) ([]byte, error) {
	out := []byte(cs.Certificate)
	issuerChain, err := m.CombinedChainPEM(issuerCAID)
	if err != nil {
		return nil, fmt.Errorf("building issuer chain for cross-sign: %w", err)
	}
	// Avoid duplicating the cross-cert if it somehow appears in the issuer chain.
	added := map[string]bool{cs.Certificate: true}
	for _, c := range splitPEMCerts(issuerChain) {
		if added[c] {
			continue
		}
		added[c] = true
		out = append(out, []byte(c)...)
	}
	return out, nil
}

// CrossSignChainPEM returns the alternate chain for a single cross-sign by id:
// the cross-certificate followed by the issuer's chain to its trust anchor.
func (m *Manager) CrossSignChainPEM(crossSignID string) ([]byte, error) {
	cs, err := m.db.GetCrossSign(crossSignID)
	if err != nil {
		return nil, fmt.Errorf("looking up cross-sign: %w", err)
	}
	if cs == nil {
		return nil, fmt.Errorf("cross-sign %q not found", crossSignID)
	}
	return m.crossSignChainPEM(cs, cs.IssuerCAID)
}

// ListCrossSigns returns the cross-signs related to a CA, both those it issued
// and those certifying its key, de-duplicated by id.
func (m *Manager) ListCrossSigns(caID string) ([]models.CrossSign, error) {
	ca, err := m.db.GetCA(caID)
	if err != nil {
		return nil, fmt.Errorf("looking up CA: %w", err)
	}
	if ca == nil {
		return nil, fmt.Errorf("CA %q not found", caID)
	}
	seen := map[string]bool{}
	var out []models.CrossSign

	issued, err := m.db.ListCrossSignsByIssuer(ca.ID)
	if err != nil {
		return nil, fmt.Errorf("listing cross-signs issued by CA: %w", err)
	}
	for _, cs := range issued {
		if !seen[cs.ID] {
			seen[cs.ID] = true
			out = append(out, cs)
		}
	}
	asSubject, err := m.crossSignsForSubject(ca)
	if err != nil {
		return nil, err
	}
	for _, cs := range asSubject {
		if !seen[cs.ID] {
			seen[cs.ID] = true
			out = append(out, cs)
		}
	}
	return out, nil
}
