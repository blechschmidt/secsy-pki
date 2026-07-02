package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ct"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
	"go.opentelemetry.io/otel/attribute"
)

// CTConfig is a profile's Certificate Transparency policy. When Enabled and a
// submitter is installed, issuance builds an RFC 6962 precertificate, submits it
// to the selected logs, and embeds the returned SCTs into the final certificate.
type CTConfig struct {
	// Enabled turns CT submission on for the profile.
	Enabled bool `json:"enabled"`
	// Logs names the CT logs (from the global registry) to submit to. Empty
	// submits to every registered log.
	Logs []string `json:"logs,omitempty"`
	// MinSCTs is the minimum number of SCTs the policy requires. Zero defaults to
	// one. When fewer are obtained, FailOpen decides whether issuance proceeds.
	MinSCTs int `json:"min_scts,omitempty"`
	// FailOpen selects the failure mode. False (fail-closed, the default) makes
	// issuance fail when the minimum SCT count is not met. True (fail-open) lets
	// issuance proceed, embedding whatever SCTs were obtained (possibly none).
	FailOpen bool `json:"fail_open,omitempty"`
	// TimeoutSeconds bounds each individual log submission attempt. Zero uses a
	// built-in default.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
	// Retries is the number of extra attempts per log after the first.
	Retries int `json:"retries,omitempty"`
}

// defaultCTTimeout bounds a single log attempt when the profile does not set one.
const defaultCTTimeout = 10 * time.Second

// minSCTs resolves the effective minimum SCT count.
func (c *CTConfig) minSCTs() int {
	if c.MinSCTs > 0 {
		return c.MinSCTs
	}
	return 1
}

func (c *CTConfig) timeout() time.Duration {
	if c.TimeoutSeconds > 0 {
		return time.Duration(c.TimeoutSeconds) * time.Second
	}
	return defaultCTTimeout
}

// ctSubmitter is the process-wide CT submitter installed at startup. It is set
// once before serving, so reads need no locking. Nil disables CT regardless of
// per-profile settings.
var ctSubmitter *ct.Submitter

// SetCTSubmitter installs the Certificate Transparency submitter used by all
// CT-enabled profiles. Passing nil disables CT.
func SetCTSubmitter(s *ct.Submitter) {
	ctSubmitter = s
}

// CTStatus summarises what Certificate Transparency did for one issuance. It is
// surfaced in the issuance response, persisted with the certificate, and folded
// into the audit trail.
type CTStatus struct {
	// Enabled reports whether the profile requested CT for this issuance.
	Enabled bool `json:"enabled"`
	// Embedded reports whether an SCT list extension was embedded.
	Embedded bool `json:"embedded"`
	// SCTCount is the number of SCTs embedded.
	SCTCount int `json:"sct_count"`
	// Logs is the per-log submission outcome.
	Logs []ct.LogResult `json:"logs,omitempty"`
	// FailedOpen reports that the SCT policy was not met but issuance proceeded
	// because the profile is configured fail-open.
	FailedOpen bool `json:"failed_open,omitempty"`
}

// Summary renders a compact human/audit-friendly description of CT handling,
// suitable for inclusion in an audit event detail.
func (s *CTStatus) Summary() string {
	if s == nil || !s.Enabled {
		return "ct=disabled"
	}
	ok := 0
	for _, r := range s.Logs {
		if r.OK {
			ok++
		}
	}
	str := fmt.Sprintf("ct=enabled scts=%d logs=%d/%d", s.SCTCount, ok, len(s.Logs))
	if s.FailedOpen {
		str += " fail_open=applied"
	}
	return str
}

// succeededLogNames returns the names of logs that returned a usable SCT.
func (s *CTStatus) succeededLogNames() []string {
	if s == nil {
		return nil
	}
	var out []string
	for _, r := range s.Logs {
		if r.OK {
			out = append(out, r.Log)
		}
	}
	return out
}

// buildLeaf signs an end-entity certificate for the given template, applying the
// profile's Certificate Transparency policy when enabled. It returns the DER
// certificate and a CTStatus describing what CT did (nil-safe when disabled).
//
// With CT enabled it: (1) builds and HSM-signs a precertificate carrying the
// poison extension, (2) submits it to the configured logs, (3) enforces the
// min-SCT / fail-open policy, and (4) HSM-signs the final certificate with the
// SCT list extension in place of the poison.
func (m *Manager) buildLeaf(ctx context.Context, signer crypto.Signer, issuerCA *models.CA, issuerCert *x509.Certificate, base pki.LeafCertRequest, profile Profile, requestedBy string) ([]byte, *CTStatus, error) {
	ctx, span := tracing.Start(ctx, "ca.build_leaf",
		attribute.String("ca.id", issuerCA.ID),
		attribute.String("ca.profile", profile.Name))
	defer span.End()

	// Fail-closed pre-issuance lint gate: run CA/Browser-Forum Baseline
	// Requirements checks on the to-be-signed template BEFORE any HSM signature.
	// A violating template is rejected here — neither the precertificate nor the
	// final certificate is ever signed. Each pre-issuance gate is its own span so
	// a rejection (and its latency) is attributable in the trace.
	if err := traceGate(ctx, "ca.gate.lint", func() error {
		return m.lintLeaf(base, profile, issuerCA, requestedBy)
	}); err != nil {
		return nil, nil, err
	}

	// Fail-closed pre-issuance CAA gate (RFC 8659): resolve and evaluate the
	// Certification Authority Authorization RRset for the certificate's DNS names.
	// Under enforce mode a CAA set that does not authorize this CA rejects the
	// request here, before any HSM signature.
	if err := traceGate(ctx, "ca.gate.caa", func() error {
		return m.checkCAA(ctx, base, profile, issuerCA, requestedBy)
	}); err != nil {
		return nil, nil, err
	}

	// Fail-closed pre-issuance Name Constraints gate (RFC 5280 §4.2.1.10): a leaf
	// whose subject or SAN falls outside the issuing CA's permitted subtrees (or
	// inside an excluded subtree) is rejected here, before any HSM signature.
	if err := traceGate(ctx, "ca.gate.name_constraints", func() error {
		return m.checkNameConstraints(base, profile, issuerCA, issuerCert, requestedBy)
	}); err != nil {
		return nil, nil, err
	}

	// Assign the profile's certificate-policy OIDs to the leaf. These are appended
	// to the base template so they participate identically in the precertificate
	// and the final certificate (keeping the TBSCertificate aligned for SCT).
	policyExts, err := profile.policyExtensions()
	if err != nil {
		return nil, nil, err
	}
	if len(policyExts) > 0 {
		base.ExtraExtensions = appendExts(base.ExtraExtensions, policyExts)
	}

	cfg := profile.CT
	if cfg == nil || !cfg.Enabled || ctSubmitter == nil {
		der, err := m.signLeaf(ctx, signer, issuerCert, base, "final")
		if err != nil {
			return nil, nil, err
		}
		return der, &CTStatus{Enabled: false}, nil
	}

	status := &CTStatus{Enabled: true}

	// (1) Precertificate: template + critical poison extension, HSM-signed.
	precertReq := base
	precertReq.ExtraExtensions = appendExt(base.ExtraExtensions, ct.PoisonExtension())
	precertDER, err := m.signLeaf(ctx, signer, issuerCert, precertReq, "precert")
	if err != nil {
		return nil, nil, fmt.Errorf("building precertificate: %w", err)
	}

	// (2) Submit to the configured logs.
	chainDER, err := m.issuerChainDER(issuerCA, issuerCert)
	if err != nil {
		return nil, nil, fmt.Errorf("assembling issuer chain for CT: %w", err)
	}
	submitCtx, ctSpan := tracing.Start(ctx, "ca.ct.submit",
		attribute.Int("ca.ct.log_count", len(cfg.Logs)))
	sub, err := ctSubmitter.Submit(submitCtx, ct.SubmitRequest{
		Logs:           cfg.Logs,
		PrecertDER:     precertDER,
		Issuer:         issuerCert,
		IssuerChainDER: chainDER,
		Timeout:        cfg.timeout(),
		Retries:        cfg.Retries,
	})
	if err != nil {
		tracing.RecordError(submitCtx, err)
		ctSpan.End()
		// A misconfigured submission (e.g. unknown log name) is always fatal:
		// fail-open covers log unavailability, not operator misconfiguration.
		return nil, nil, fmt.Errorf("certificate transparency submission: %w", err)
	}
	ctSpan.SetAttributes(attribute.Int("ca.ct.sct_count", len(sub.SCTs)))
	ctSpan.End()
	status.Logs = sub.Results
	status.SCTCount = len(sub.SCTs)

	// (3) Enforce the min-SCT / fail-open policy.
	if len(sub.SCTs) < cfg.minSCTs() {
		if !cfg.FailOpen {
			return nil, nil, fmt.Errorf(
				"certificate transparency: obtained %d SCT(s), profile %q requires %d (%s)",
				len(sub.SCTs), profile.Name, cfg.minSCTs(), ctResultsSummary(sub.Results))
		}
		status.FailedOpen = true
	}

	// (4) Final certificate: embed the SCT list (if any) and HSM-sign.
	finalReq := base
	if len(sub.SCTs) > 0 {
		ext, err := ct.SCTListExtension(sub.SCTs)
		if err != nil {
			return nil, nil, fmt.Errorf("building SCT list extension: %w", err)
		}
		finalReq.ExtraExtensions = appendExt(base.ExtraExtensions, ext)
		status.Embedded = true
	}
	der, err := m.signLeaf(ctx, signer, issuerCert, finalReq, "final")
	if err != nil {
		return nil, nil, fmt.Errorf("building final certificate: %w", err)
	}
	return der, status, nil
}

// signLeaf wraps pki.CreateLeafCertificate in a span so the HSM-signed
// certificate construction (precertificate or final certificate) is a
// first-class, timed step in the issuance trace. The child HSM-signing span
// (hsm.sign) nests under it, and the "kind" attribute distinguishes the
// precertificate from the final certificate on a CT-enabled profile.
func (m *Manager) signLeaf(ctx context.Context, signer crypto.Signer, issuerCert *x509.Certificate, req pki.LeafCertRequest, kind string) ([]byte, error) {
	ctx, span := tracing.Start(ctx, "ca.sign_certificate",
		attribute.String("ca.cert.kind", kind))
	defer span.End()
	der, err := pki.CreateLeafCertificate(signer, issuerCert, req)
	tracing.RecordError(ctx, err)
	return der, err
}

// traceGate runs a fail-closed pre-issuance gate (lint/CAA/name-constraints)
// inside its own span, recording a rejection as a span error so the reason a
// request was refused is visible in the trace.
func traceGate(ctx context.Context, name string, fn func() error) error {
	_, span := tracing.Start(ctx, name)
	defer span.End()
	err := fn()
	if err != nil {
		span.RecordError(err)
	}
	return err
}

// issuerChainDER returns the issuer certificate chain in DER, issuer first up to
// the root, for inclusion in an add-pre-chain submission.
func (m *Manager) issuerChainDER(issuerCA *models.CA, issuerCert *x509.Certificate) ([][]byte, error) {
	chain := [][]byte{issuerCert.Raw}
	cur := issuerCA
	seen := map[string]bool{cur.ID: true}
	for cur.ParentID != nil && *cur.ParentID != "" && !seen[*cur.ParentID] {
		parent, err := m.db.GetCA(*cur.ParentID)
		if err != nil {
			return nil, err
		}
		if parent == nil || parent.Certificate == "" {
			break
		}
		pc, err := pki.ParseCertificatePEM([]byte(parent.Certificate))
		if err != nil {
			return nil, err
		}
		chain = append(chain, pc.Raw)
		seen[parent.ID] = true
		cur = parent
	}
	return chain, nil
}

// appendExt returns a fresh slice with ext appended, never mutating base.
func appendExt(base []pkix.Extension, ext pkix.Extension) []pkix.Extension {
	out := make([]pkix.Extension, 0, len(base)+1)
	out = append(out, base...)
	out = append(out, ext)
	return out
}

// appendExts returns a fresh slice with exts appended, never mutating base.
func appendExts(base []pkix.Extension, exts []pkix.Extension) []pkix.Extension {
	out := make([]pkix.Extension, 0, len(base)+len(exts))
	out = append(out, base...)
	out = append(out, exts...)
	return out
}

// ctResultsSummary renders per-log errors for a policy-failure message.
func ctResultsSummary(results []ct.LogResult) string {
	msg := ""
	for _, r := range results {
		if r.OK {
			continue
		}
		if msg != "" {
			msg += "; "
		}
		msg += r.Log + ": " + r.Error
	}
	if msg == "" {
		return "no log errors reported"
	}
	return msg
}
