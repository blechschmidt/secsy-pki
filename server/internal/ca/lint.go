package ca

import (
	"fmt"
	"log"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/certlint"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// LintConfig is a profile's pre-issuance lint policy. Linting runs on every
// to-be-signed certificate as a fail-closed gate: an enforce-mode check that
// fails blocks issuance before the HSM signs. The default (a nil *LintConfig, or
// an all-zero value) runs the baseline checks in enforce mode without the
// public-trust name rules, which suits an internal PKI.
type LintConfig struct {
	// Disabled turns the lint gate off for the profile. Discouraged; disabling it
	// removes the CA/Browser Forum Baseline Requirements safety net.
	Disabled bool `json:"disabled,omitempty"`
	// Mode is the default enforcement mode for every check: "enforce" (default,
	// blocks issuance) or "warn" (reports only).
	Mode string `json:"mode,omitempty"`
	// Public applies CA/Browser-Forum public-trust rules (SAN required, CN in
	// SAN, no internal names / reserved IPs, 398-day TLS cap). Off by default.
	Public bool `json:"public,omitempty"`
	// Overrides sets the mode ("enforce"|"warn") for individual checks by code,
	// overriding Mode.
	Overrides map[string]string `json:"overrides,omitempty"`
}

// LintPolicy resolves the profile's effective certlint.Policy, folding in the
// profile's maximum validity as the validity cap and, for S/MIME profiles, the
// CA/B Forum S/MIME Baseline Requirements rule set.
func (p Profile) LintPolicy() certlint.Policy {
	pol := certlint.Policy{MaxValidity: p.MaxValidity}
	if p.SMIME != nil {
		pol.SMIME = &certlint.SMIMEPolicy{Class: p.SMIME.class(), Variant: p.SMIME.variant()}
	}
	if p.Lint != nil {
		pol.Public = p.Lint.Public
		if p.Lint.Mode != "" {
			pol.Mode = certlint.Mode(p.Lint.Mode)
		}
		if len(p.Lint.Overrides) > 0 {
			pol.Overrides = make(map[string]certlint.Mode, len(p.Lint.Overrides))
			for code, mode := range p.Lint.Overrides {
				pol.Overrides[code] = certlint.Mode(mode)
			}
		}
	}
	return pol
}

// lintEnabled reports whether the pre-issuance lint gate runs for the profile.
func (p Profile) lintEnabled() bool {
	return p.Lint == nil || !p.Lint.Disabled
}

// lintLeaf runs the pre-issuance lint gate on the to-be-signed template. It
// records metrics for every run and, when there are findings, an audit event.
// It returns a non-nil error (fail-closed) when an enforce-mode check fails, so
// the caller aborts before the HSM signs anything. Warnings never block.
func (m *Manager) lintLeaf(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, requestedBy string) error {
	if !profile.lintEnabled() {
		return nil
	}

	tbs, err := certlint.CertificateFromLeaf(base)
	if err != nil {
		return fmt.Errorf("building certificate for linting: %w", err)
	}
	res := certlint.Lint(tbs, profile.LintPolicy())

	// Metrics: one outcome per run, plus one per finding for fine-grained alerts.
	switch {
	case res.HasErrors():
		metrics.CertificateLints.Inc("fail")
	case !res.OK():
		metrics.CertificateLints.Inc("warn")
	default:
		metrics.CertificateLints.Inc("pass")
	}
	for _, f := range res.Findings {
		metrics.CertificateLintFindings.Inc(f.Code, string(f.Mode))
	}

	// Audit only when there is something to report (findings), to avoid doubling
	// the audit volume of the accompanying cert.issue/cert.renew event.
	if !res.OK() {
		m.recordLintEvent(base, profile, issuerCA, requestedBy, res)
	}

	if res.HasErrors() {
		return fmt.Errorf("pre-issuance lint failed for profile %q: %s", profile.Name, res.Err())
	}
	return nil
}

// recordLintEvent appends a tamper-evident audit event describing a lint result
// with findings. A failing gate is ResultError; warnings-only is ResultSuccess.
func (m *Manager) recordLintEvent(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, requestedBy string, res certlint.Result) {
	actor := requestedBy
	if actor == "" {
		actor = "system"
	}
	result := audit.ResultSuccess
	if res.HasErrors() {
		result = audit.ResultError
	}
	serial := ""
	if base.Serial != nil {
		serial = base.Serial.String()
	}
	target := issuerCA.ID
	targetName := issuerCA.Label
	detail := "profile=" + profile.Name + " " + res.Summary()
	if serial != "" {
		detail += " serial=" + serial
	}
	if cn := base.Subject.CommonName; cn != "" {
		targetName = cn
	}
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		Action:     audit.ActionCertLint,
		Target:     target,
		TargetName: targetName,
		Result:     result,
		Detail:     detail,
	}
	if err := m.db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append cert.lint audit event: %v", err)
	}
}
