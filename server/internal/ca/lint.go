package ca

import (
	"crypto/x509"
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
	// RequireMustStaple flags a serverAuth certificate issued under this profile
	// that omits the RFC 7633 OCSP Must-Staple TLS feature (status_request). It is
	// advisory (warn) by default; pair it with the profile's must_staple knob to
	// satisfy the check, or escalate it to enforce via Mode/Overrides.
	RequireMustStaple bool `json:"require_must_staple,omitempty"`
	// Overrides sets the mode ("enforce"|"warn") for individual checks by code,
	// overriding Mode.
	Overrides map[string]string `json:"overrides,omitempty"`
	// ZLint optionally enables the industry-standard github.com/zmap/zlint
	// backend alongside the hand-rolled checks. It is only effective in a binary
	// built with the "zlint" build tag; otherwise it is ignored (a warning is
	// logged at startup). Nil leaves zlint disabled.
	ZLint *ZLintConfig `json:"zlint,omitempty"`
}

// ZLintConfig is a profile's optional zlint backend configuration. It maps the
// zlint severity levels (error/warn/notice) onto this package's enforce/warn/
// ignore dispositions and optionally restricts which lints run.
type ZLintConfig struct {
	// Enabled turns the zlint backend on for the profile. When false the rest of
	// this struct is ignored.
	Enabled bool `json:"enabled,omitempty"`
	// ErrorMode / WarnMode / NoticeMode map the corresponding zlint severity
	// levels to "enforce", "warn", or "ignore". Empty uses the defaults: error →
	// enforce, warn → warn, notice → ignore.
	ErrorMode  string `json:"error_mode,omitempty"`
	WarnMode   string `json:"warn_mode,omitempty"`
	NoticeMode string `json:"notice_mode,omitempty"`
	// IncludeSources / ExcludeSources restrict the lint registry by source
	// (e.g. "CABF_BR", "RFC5280", "CABF_SMIME_BR", "Mozilla").
	IncludeSources []string `json:"include_sources,omitempty"`
	ExcludeSources []string `json:"exclude_sources,omitempty"`
	// IncludeNames / ExcludeNames restrict the registry to / from individual lint
	// names.
	IncludeNames []string `json:"include_names,omitempty"`
	ExcludeNames []string `json:"exclude_names,omitempty"`
	// Overrides sets the disposition ("enforce"|"warn"|"ignore") for an
	// individual lint by name, overriding the level mapping.
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
		pol.RequireMustStaple = p.Lint.RequireMustStaple
		if p.Lint.Mode != "" {
			pol.Mode = certlint.Mode(p.Lint.Mode)
		}
		if len(p.Lint.Overrides) > 0 {
			pol.Overrides = make(map[string]certlint.Mode, len(p.Lint.Overrides))
			for code, mode := range p.Lint.Overrides {
				pol.Overrides[code] = certlint.Mode(mode)
			}
		}
		if z := p.Lint.ZLint; z != nil && z.Enabled {
			pol.ZLint = zlintPolicy(z)
		}
	}
	return pol
}

// zlintPolicy translates a profile's ZLintConfig into the certlint.ZLintPolicy
// consumed by the linter.
func zlintPolicy(z *ZLintConfig) *certlint.ZLintPolicy {
	pol := &certlint.ZLintPolicy{
		ErrorMode:      certlint.Mode(z.ErrorMode),
		WarnMode:       certlint.Mode(z.WarnMode),
		NoticeMode:     certlint.Mode(z.NoticeMode),
		IncludeSources: z.IncludeSources,
		ExcludeSources: z.ExcludeSources,
		IncludeNames:   z.IncludeNames,
		ExcludeNames:   z.ExcludeNames,
	}
	if len(z.Overrides) > 0 {
		pol.Overrides = make(map[string]certlint.Mode, len(z.Overrides))
		for name, mode := range z.Overrides {
			pol.Overrides[name] = certlint.Mode(mode)
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
//
// issuerCert is the parsed issuing CA certificate; it is used only when the
// optional zlint backend is enabled and compiled in, to synthesize a faithful
// DER encoding of the to-be-signed leaf (a throwaway "linting certificate")
// without invoking the HSM.
func (m *Manager) lintLeaf(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, issuerCert *x509.Certificate, requestedBy string) error {
	if !profile.lintEnabled() {
		return nil
	}

	policy := profile.LintPolicy()
	tbs, err := certlint.CertificateFromLeaf(base)
	if err != nil {
		return fmt.Errorf("building certificate for linting: %w", err)
	}
	res := certlint.Lint(tbs, policy)

	// Optional zlint backend on the to-be-signed template. The template carries no
	// DER (nothing is signed yet), so synthesize a faithful linting certificate —
	// same TBSCertificate, throwaway signature — and lint its DER. Only classical
	// profiles are supported (zlint does not understand ML-DSA); a synthesis
	// failure is logged and skipped rather than blocking issuance, since it is an
	// infrastructure fault, not a certificate-policy violation. When the backend
	// is not compiled in, ZLintAvailable is false and this block is skipped (the
	// startup profile check warns the operator once).
	if policy.ZLint != nil && certlint.ZLintAvailable() && profile.Algorithm == AlgClassical && issuerCert != nil {
		if der, serr := pki.LintCertificateDER(issuerCert, base); serr != nil {
			log.Printf("WARNING: zlint enabled for profile %q but linting certificate could not be synthesized (skipping zlint): %v", profile.Name, serr)
		} else {
			res.Findings = append(res.Findings, certlint.ZLintFindings(der, *policy.ZLint)...)
		}
	}

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
