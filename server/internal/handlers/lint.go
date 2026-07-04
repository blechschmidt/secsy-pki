package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/certlint"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// LintRequest asks for an ad-hoc lint of an existing certificate against a
// profile's policy — the REST counterpart of `secsy-ca lint`, giving the
// console the same diagnostic. Nothing is issued or stored.
type LintRequest struct {
	// Certificate is the PEM-encoded certificate to lint.
	Certificate string `json:"certificate"`
	// Profile applies the named profile's lint policy; empty lints against the
	// baseline rules.
	Profile string `json:"profile,omitempty"`
	// Public applies the CA/Browser-Forum public-trust rules regardless of the
	// profile's setting.
	Public bool `json:"public,omitempty"`
	// Mode overrides the enforcement mode of every check: "enforce" or "warn".
	Mode string `json:"mode,omitempty"`
	// MaxValidityDays caps the permitted validity period (0 = from profile).
	MaxValidityDays int `json:"max_validity_days,omitempty"`
	// ZLint additionally runs the industry-standard zlint backend (effective only
	// when the server was built with -tags zlint; see ZLintAvailable in the
	// response).
	ZLint bool `json:"zlint,omitempty"`
}

// LintResponse reports the lint verdict and its findings.
type LintResponse struct {
	Subject  string `json:"subject"`
	Serial   string `json:"serial"`
	NotAfter string `json:"not_after"`
	// Mode and Public echo the effective policy applied.
	Mode   string `json:"mode"`
	Public bool   `json:"public"`
	// ZLint reports whether the zlint backend was requested, and ZLintAvailable
	// whether it is compiled into this server binary. When ZLint is true but
	// ZLintAvailable is false, only the hand-rolled checks ran.
	ZLint          bool `json:"zlint"`
	ZLintAvailable bool `json:"zlint_available"`
	// Pass is true when no findings were raised at all.
	Pass     bool               `json:"pass"`
	Errors   int                `json:"errors"`
	Warnings int                `json:"warnings"`
	Summary  string             `json:"summary"`
	Findings []certlint.Finding `json:"findings,omitempty"`
}

// LintCertificate handles POST /api/lint: parse a PEM certificate and lint it
// under a profile's policy. Read-gated (any assigned role) — linting is a
// diagnostic over material the caller already holds.
func (a *API) LintCertificate(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.canRead(user) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}

	var req LintRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Certificate == "" {
		writeError(w, http.StatusBadRequest, "certificate is required")
		return
	}
	cert, err := pki.ParseCertificatePEM([]byte(req.Certificate))
	if err != nil {
		writeError(w, http.StatusBadRequest, "parsing certificate: %v", err)
		return
	}

	var policy certlint.Policy
	if req.Profile != "" {
		prof, err := ca.LookupProfile(req.Profile)
		if err != nil {
			writeError(w, http.StatusBadRequest, "%v", err)
			return
		}
		policy = prof.LintPolicy()
	}
	if req.Public {
		policy.Public = true
	}
	if req.Mode != "" {
		if req.Mode != string(certlint.ModeEnforce) && req.Mode != string(certlint.ModeWarn) {
			writeError(w, http.StatusBadRequest, "invalid mode %q (want enforce or warn)", req.Mode)
			return
		}
		policy.Mode = certlint.Mode(req.Mode)
	}
	if req.MaxValidityDays > 0 {
		policy.MaxValidity = time.Duration(req.MaxValidityDays) * 24 * time.Hour
	}
	if req.ZLint && policy.ZLint == nil {
		policy.ZLint = &certlint.ZLintPolicy{}
	}

	res := certlint.Lint(cert, policy)
	effMode := policy.Mode
	if effMode == "" {
		effMode = certlint.ModeEnforce
	}
	writeJSON(w, http.StatusOK, LintResponse{
		Subject:        cert.Subject.String(),
		Serial:         cert.SerialNumber.String(),
		NotAfter:       cert.NotAfter.UTC().Format(time.RFC3339),
		Mode:           string(effMode),
		Public:         policy.Public,
		ZLint:          policy.ZLint != nil,
		ZLintAvailable: certlint.ZLintAvailable(),
		Pass:           res.OK(),
		Errors:         len(res.Errors()),
		Warnings:       len(res.Warnings()),
		Summary:        res.Summary(),
		Findings:       res.Findings,
	})
}
