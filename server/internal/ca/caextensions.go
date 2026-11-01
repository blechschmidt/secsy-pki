package ca

import (
	"crypto/x509/pkix"
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/caext"
	"github.com/blechschmidt/secsy-pki/server/internal/certpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/nameconstraints"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// applyCAExtensions stamps the complete extension set a CA certificate should
// carry onto an otherwise-finished pki.CACertRequest: the Name Constraints and
// certificate-policy extensions from their own packages, plus everything
// internal/caext compiles from the operator's configuration.
//
// It must be called after the request's validity window is final, because the
// private-key usage period is resolved relative to it, and before the key is
// generated, so a rejected configuration costs nothing. The caller's existing
// req.ExtraExtensions (the cross-signing and rotation paths pre-seed extensions
// to carry forward) are preserved and take precedence: a configured extension
// that would duplicate one of them is an error rather than a second copy.
func applyCAExtensions(req *pki.CACertRequest, nc nameconstraints.Constraints, pol certpolicy.Policies, cfg *caext.Config) error {
	policyExts, err := caPolicyExtensions(nc, pol)
	if err != nil {
		return err
	}

	built, err := cfg.Build()
	if err != nil {
		return fmt.Errorf("invalid CA extension set: %w", err)
	}
	if err := built.ApplyValidity(req.NotBefore, req.NotAfter); err != nil {
		return fmt.Errorf("invalid CA extension set: %w", err)
	}

	req.KeyUsage = built.KeyUsage
	req.CRLDistributionPoints = built.CRLDistributionPoints
	req.OCSPServer = built.OCSPServers
	req.IssuingCertificateURL = built.CAIssuers
	// An explicit subject key identifier only applies when the caller has not
	// already pinned one (cross-signing reproduces the original CA's SKI, which
	// is the whole point of that path and must win).
	if len(req.SubjectKeyID) == 0 && len(built.SubjectKeyID) > 0 {
		req.SubjectKeyID = built.SubjectKeyID
	}

	merged := make([]pkix.Extension, 0, len(req.ExtraExtensions)+len(policyExts)+len(built.Extensions))
	merged = append(merged, req.ExtraExtensions...)
	merged = append(merged, policyExts...)
	merged = append(merged, built.Extensions...)
	if err := rejectDuplicateExtensions(merged); err != nil {
		return err
	}
	req.ExtraExtensions = merged
	return nil
}

// caCSRExtensions compiles the operator-configured extension set for a
// subordinate-CA PKCS#10 request, so an external parent can see (and reproduce)
// the extensions the CA was asked to carry. Extensions whose content depends on
// a validity window the parent has not chosen yet — the private-key usage
// period — are left out: only the issuer can resolve them.
func caCSRExtensions(nc nameconstraints.Constraints, pol certpolicy.Policies, cfg *caext.Config) (pki.CACSRRequest, error) {
	var out pki.CACSRRequest
	policyExts, err := caPolicyExtensions(nc, pol)
	if err != nil {
		return out, err
	}
	built, err := cfg.Build()
	if err != nil {
		return out, fmt.Errorf("invalid CA extension set: %w", err)
	}
	exts := make([]pkix.Extension, 0, len(policyExts)+len(built.Extensions))
	exts = append(exts, policyExts...)
	exts = append(exts, built.Extensions...)
	if err := rejectDuplicateExtensions(exts); err != nil {
		return out, err
	}
	out.KeyUsage = built.KeyUsage
	out.ExtraExtensions = exts
	return out, nil
}

// rejectDuplicateExtensions fails when two extensions share an OID. RFC 5280
// §4.2 forbids it, crypto/x509 would happily emit both, and the likely cause is
// an operator using the custom escape hatch for an extension the request already
// configures the proper way — worth saying out loud.
func rejectDuplicateExtensions(exts []pkix.Extension) error {
	seen := map[string]bool{}
	for _, e := range exts {
		key := e.Id.String()
		if seen[key] {
			return fmt.Errorf("extension %s is configured twice (RFC 5280 permits one of each)", key)
		}
		seen[key] = true
	}
	return nil
}
