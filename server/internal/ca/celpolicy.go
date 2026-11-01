package ca

import (
	"context"
	"crypto/x509"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/celpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// The CEL issuance-restriction gate (Task 223).
//
// It is the last of the pre-issuance gates and the only one whose logic the
// operator writes. Where the lint gate encodes the CA/Browser Forum's rules, the
// CAA gate the domain owner's, and the Name Constraints gate the issuing CA's
// own, this gate encodes *the deployment's* — the rules an enterprise invents
// that no fixed configuration field anticipated.
//
// It sits in buildLeaf alongside the others, which is deliberate: every issuance
// surface (REST, gRPC, ACME, EST, SCEP, CMP, MS-WSTEP, bulk, PKCS#12, SVID, the
// CLI) converges on that function, so a rule cannot be bypassed by asking over a
// different protocol. The facts a rule sees are derived from the to-be-signed
// template rather than from each surface's own request shape, so a rule is true
// of the certificate or of nothing.
//
// Fail-closed throughout: a rule set that cannot be loaded, a rule that cannot
// be compiled, and a rule that errors at evaluation all refuse the issuance
// (unless the operator marked that rule fail-open), because a restriction engine
// that permits what it could not check is not a restriction engine.

// checkCELPolicy is the fail-closed gate. It returns a *celpolicy.DenyError when
// an enforcing rule refused the request, whose message carries the operator's own
// wording — that message travels up through IssueCertificate to the API layer and
// reaches the requester, which is the whole point of the engine.
func (m *Manager) checkCELPolicy(ctx context.Context, base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, issuerCert *x509.Certificate, requestedBy string) error {
	rules, err := m.db.ActiveCELPolicyRules(issuerCA.TenantID)
	if err != nil {
		metrics.CertificatePolicyChecks.Inc("error")
		// Fail closed: without the rule set we cannot prove the request is
		// permitted, and the store being unreachable is not the requester's
		// licence to be certified.
		return fmt.Errorf("pre-issuance policy check failed: loading restriction rules: %w", err)
	}
	if len(rules) == 0 {
		return nil
	}

	in := celpolicy.FromContext(ctx).Input(
		celPolicyRequest(base, profile, issuerCA, issuerCert, requestedBy, celpolicy.OpIssue))
	decision := celpolicy.Shared().Evaluate(rules, in)
	m.recordCELPolicyOutcome(in, decision, profile, issuerCA, requestedBy)
	if decision.Allowed {
		return nil
	}
	return &celpolicy.DenyError{Decision: decision}
}

// EvaluateCELPolicy evaluates the restriction rules against a candidate leaf
// WITHOUT recording metrics or audit events, for the dry-run surfaces: the
// pre-issuance preview (Task 113) and the console/CLI rule testers. Sharing the
// evaluation with the gate is what keeps a preview honest — a dry-run that ran
// different code could promise an issuance the gate then refuses.
func (m *Manager) EvaluateCELPolicy(ctx context.Context, base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, issuerCert *x509.Certificate, requestedBy string, op string) (celpolicy.Decision, error) {
	rules, err := m.db.ActiveCELPolicyRules(issuerCA.TenantID)
	if err != nil {
		return celpolicy.Decision{}, fmt.Errorf("loading restriction rules: %w", err)
	}
	if len(rules) == 0 {
		return celpolicy.Decision{Allowed: true}, nil
	}
	in := celpolicy.FromContext(ctx).Input(
		celPolicyRequest(base, profile, issuerCA, issuerCert, requestedBy, op))
	return celpolicy.Shared().Evaluate(rules, in), nil
}

// celPolicyRequest assembles the certificate-side facts: the template's own
// names, validity and key, plus the profile and issuing-CA context a rule needs
// to tell one authority's requests from another's.
func celPolicyRequest(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, issuerCert *x509.Certificate, requestedBy, op string) celpolicy.CertRequest {
	req := celpolicy.FromLeafRequest(base)
	req.Operation = op
	req.Profile = profile.Name
	req.Algorithm = profileAlgorithmName(profile)
	req.MustStaple = hasMustStapleExtension(base)
	req.RequestedBy = requestedBy
	if issuerCA != nil {
		req.CA = celpolicy.CAInfo{
			ID:     issuerCA.ID,
			Label:  issuerCA.Label,
			Tenant: issuerCA.TenantID,
		}
	}
	if issuerCert != nil {
		req.CA.Subject = issuerCert.Subject.String()
		req.CA.NotAfter = issuerCert.NotAfter.UTC()
	}
	return req
}

// profileAlgorithmName names the profile's signature-scheme family for a rule.
func profileAlgorithmName(p Profile) string {
	switch p.Algorithm {
	case AlgPQC:
		return "pqc"
	case AlgHybrid:
		return "hybrid"
	default:
		return "classical"
	}
}

// hasMustStapleExtension reports whether the resolved template already carries
// the RFC 7633 TLS Feature extension. The gate runs after applyMustStaple, so
// reading the template is what makes `request.must_staple` reflect the
// certificate rather than the request's wish.
func hasMustStapleExtension(base pki.LeafCertRequest) bool {
	for _, e := range base.ExtraExtensions {
		if e.Id.Equal(pki.OIDTLSFeature) {
			return true
		}
	}
	return false
}

// recordCELPolicyOutcome publishes metrics for every evaluation and appends an
// audit event whenever a rule produced a finding — blocking or not. A monitor-mode
// finding that never reaches a requester is only useful if it is written down.
func (m *Manager) recordCELPolicyOutcome(in celpolicy.Input, d celpolicy.Decision, profile Profile, issuerCA *models.CA, requestedBy string) {
	switch {
	case !d.Allowed:
		metrics.CertificatePolicyChecks.Inc("deny")
	case len(d.Violations) > 0:
		metrics.CertificatePolicyChecks.Inc("monitor")
	default:
		metrics.CertificatePolicyChecks.Inc("pass")
	}
	for _, v := range d.Violations {
		metrics.CertificatePolicyViolations.Inc(v.Rule, string(v.Mode))
		if v.Error != "" {
			metrics.CertificatePolicyRuleErrors.Inc(v.Rule)
		}
	}
	if len(d.Violations) == 0 {
		return
	}
	m.recordCELPolicyEvent(in, d, profile, issuerCA, requestedBy)
}

// recordCELPolicyEvent appends a tamper-evident audit event for a policy finding.
func (m *Manager) recordCELPolicyEvent(in celpolicy.Input, d celpolicy.Decision, profile Profile, issuerCA *models.CA, requestedBy string) {
	actor := requestedBy
	if actor == "" {
		actor = "system"
	}
	target, targetName := "", ""
	if issuerCA != nil {
		target, targetName = issuerCA.ID, issuerCA.Label
	}
	if cn := in.Request.Subject.CommonName; cn != "" {
		targetName = cn
	}
	result := audit.ResultError
	if d.Allowed {
		// Monitor-mode findings only: the certificate was issued.
		result = audit.ResultSuccess
	}
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		Action:     audit.ActionCertPolicy,
		Target:     target,
		TargetName: targetName,
		Result:     result,
		Detail:     celPolicyDetail(in, d, profile),
	}
	if err := m.db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append cert.policy audit event: %v", err)
	}
}

// celPolicyDetail renders the audit detail: the surface, the profile, and every
// finding with its rule name and mode — the same text the requester received, so
// the log answers "why was this refused" on its own.
func celPolicyDetail(in celpolicy.Input, d celpolicy.Decision, profile Profile) string {
	parts := []string{
		"source=" + in.Request.Source,
		"profile=" + profile.Name,
		fmt.Sprintf("rules_evaluated=%d", d.Evaluated),
	}
	for _, v := range d.Violations {
		detail := fmt.Sprintf("%s[%s]: %s", v.Rule, v.Mode, v.Message)
		if v.Error != "" {
			detail += " (" + v.Error + ")"
		}
		parts = append(parts, detail)
	}
	return strings.Join(parts, " ")
}

// PolicyFactsFromCSR resolves the request facts a rule would see for a would-be
// issuance, without signing, persisting, or allocating anything. It is what the
// console's and CLI's rule tester seeds a dry-run with: facts derived by the same
// code the gate uses, so a rule tried against a real CSR behaves the way it will
// behave when that CSR is actually submitted.
//
// It reuses the preview's own template resolution (subject, SANs, usages,
// validity clamping, Must-Staple, the policy extensions), so the facts cannot
// drift from the issuance path.
func (m *Manager) PolicyFactsFromCSR(spec PreviewSpec) (celpolicy.CertRequest, error) {
	activeID, err := m.ActiveIssuerID(spec.CAID)
	if err != nil {
		return celpolicy.CertRequest{}, err
	}
	issuerCA, issuerCert, err := m.loadIssuer(activeID)
	if err != nil {
		return celpolicy.CertRequest{}, err
	}
	profile, err := LookupProfile(spec.Profile)
	if err != nil {
		return celpolicy.CertRequest{}, err
	}
	base, err := m.policyTemplateForPreview(spec, profile, issuerCert)
	if err != nil {
		return celpolicy.CertRequest{}, err
	}
	return celPolicyRequest(base, profile, issuerCA, issuerCert, spec.RequestedBy, celpolicy.OpPreview), nil
}

// policyTemplateForPreview builds the to-be-signed template for a dry-run,
// mirroring PreviewIssuance's own resolution: the subject/SANs/key from the CSR
// (or a synthesized key when none was given), the profile's usages, and the
// validity clamped to the profile maximum and the CA's own expiry.
func (m *Manager) policyTemplateForPreview(spec PreviewSpec, profile Profile, issuerCert *x509.Certificate) (pki.LeafCertRequest, error) {
	parts, _, err := previewLeafParts(spec)
	if err != nil {
		return pki.LeafCertRequest{}, err
	}
	keyUsage, err := profile.keyUsage()
	if err != nil {
		return pki.LeafCertRequest{}, err
	}
	extKeyUsage, unknownEKU, err := profile.extKeyUsage()
	if err != nil {
		return pki.LeafCertRequest{}, err
	}
	now := time.Now()
	notBefore := now.Add(-clockSkew)
	notAfter := now.Add(profile.resolveValidity(spec.Validity))
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
	}
	base := pki.LeafCertRequest{
		Subject:            parts.Subject,
		PublicKey:          parts.PublicKey,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		KeyUsage:           keyUsage,
		ExtKeyUsage:        extKeyUsage,
		UnknownExtKeyUsage: unknownEKU,
		DNSNames:           parts.DNSNames,
		IPAddresses:        parts.IPAddresses,
		EmailAddresses:     parts.EmailAddresses,
		URIs:               parts.URIs,
		UPNs:               parts.UPNs,
		IsCA:               profile.IsCA,
		MaxPathLen:         profile.MaxPathLen,
	}
	return applyMustStaple(base, profile.resolveMustStaple(spec.MustStaple)), nil
}
