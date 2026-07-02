package ca

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/caa"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// caaResolver is the process-wide DNS resolver used by the CAA pre-issuance
// gate. It is nil until installed at startup via SetCAAResolver; a profile that
// enables CAA while it is nil fails closed under enforce mode (authorization
// cannot be established) — see checkCAA. Set once before serving, so no locking
// is required for reads. Tests replace it directly.
var caaResolver caa.Resolver

// SetCAAResolver installs the DNS resolver used by every profile's CAA gate.
// Pass a caching resolver (see caa.NewCachingResolver) in production.
func SetCAAResolver(r caa.Resolver) {
	caaResolver = r
}

// CAAConfig is a profile's DNS Certification Authority Authorization policy
// (RFC 8659). The gate runs on every certificate that carries DNS-name SANs,
// before any HSM signature: under enforce mode a CAA set that forbids this CA
// blocks issuance (fail-closed). A nil *CAAConfig disables the gate, matching
// the historical behavior for profiles that predate CAA support.
type CAAConfig struct {
	// Mode selects "enforce" (block on a forbidding CAA set or an undetermined
	// lookup), "permissive" (evaluate and audit but never block), or "off"
	// (disable). Empty defaults to "off" so enabling CAA is always explicit.
	Mode string `json:"mode,omitempty"`
	// Identifier is the CA's own CAA domain identifier — the value a domain owner
	// publishes in an `issue "ca.example.com"` record to authorize this CA.
	// Required when Mode is "enforce"; enforcement without it authorizes nothing.
	Identifier string `json:"identifier,omitempty"`
	// TimeoutSeconds bounds all DNS lookups for a single certificate's names.
	// Zero uses the resolver/context default.
	TimeoutSeconds int `json:"timeout_seconds,omitempty"`
}

// caaEnabled reports whether the CAA gate runs for the profile.
func (p Profile) caaEnabled() bool {
	return p.CAA != nil && caa.Mode(strings.ToLower(p.CAA.Mode)) != caa.ModeOff && p.CAA.Mode != ""
}

// CAAPolicy resolves the profile's effective caa.Policy.
func (p Profile) CAAPolicy() caa.Policy {
	pol := caa.Policy{Mode: caa.ModeEnforce}
	if p.CAA != nil {
		if m := caa.Mode(strings.ToLower(p.CAA.Mode)); m != "" {
			pol.Mode = m
		}
		pol.Identifier = p.CAA.Identifier
		if p.CAA.TimeoutSeconds > 0 {
			pol.Timeout = time.Duration(p.CAA.TimeoutSeconds) * time.Second
		}
	}
	return pol
}

// checkCAA runs the pre-issuance CAA gate on the certificate's DNS names before
// any HSM signature. It records a metric for every run and, when the check
// forbids issuance, an audit event. Under enforce mode a forbidding CAA set (or
// a lookup that leaves authorization undetermined) returns a non-nil error so
// the caller aborts before signing (fail-closed); under permissive mode the same
// is audited but never blocks. Certificates with no DNS-name SANs (e.g. IP-only)
// skip the check.
func (m *Manager) checkCAA(ctx context.Context, base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, requestedBy string) error {
	if !profile.caaEnabled() {
		return nil
	}
	if len(base.DNSNames) == 0 {
		metrics.CertificateCAAChecks.Inc("skip")
		return nil
	}

	policy := profile.CAAPolicy()

	// A resolver is mandatory once CAA is enabled. Missing one leaves every name
	// undetermined: fail closed under enforce, warn-and-continue under permissive.
	if caaResolver == nil {
		metrics.CertificateCAAChecks.Inc("error")
		res := caa.Result{Findings: []caa.Finding{{Reason: caa.ReasonLookupError, Detail: "no CAA resolver configured"}}}
		m.recordCAAEvent(base, profile, issuerCA, requestedBy, res, policy.Mode == caa.ModeEnforce)
		if policy.Mode == caa.ModeEnforce {
			return fmt.Errorf("pre-issuance CAA check failed for profile %q: no DNS resolver configured", profile.Name)
		}
		log.Printf("WARNING: CAA permissive gate for profile %q has no resolver; allowing issuance", profile.Name)
		return nil
	}

	res := policy.Check(ctx, caaResolver, base.DNSNames)

	switch {
	case res.Forbidden():
		metrics.CertificateCAAChecks.Inc("fail")
	default:
		metrics.CertificateCAAChecks.Inc("pass")
	}
	for _, f := range res.Findings {
		metrics.CertificateCAAFindings.Inc(string(f.Reason))
	}

	// Audit only when there is something to report, mirroring the lint gate.
	blocking := res.Forbidden() && policy.Mode == caa.ModeEnforce
	if res.Forbidden() {
		m.recordCAAEvent(base, profile, issuerCA, requestedBy, res, blocking)
	}

	if blocking {
		return fmt.Errorf("pre-issuance CAA check failed for profile %q: %s", profile.Name, res.Summary())
	}
	return nil
}

// recordCAAEvent appends a tamper-evident audit event describing a CAA check
// that produced findings. A blocking (enforce) result is ResultError; a
// permissive-mode finding is ResultSuccess.
func (m *Manager) recordCAAEvent(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, requestedBy string, res caa.Result, blocking bool) {
	actor := requestedBy
	if actor == "" {
		actor = "system"
	}
	result := audit.ResultSuccess
	if blocking {
		result = audit.ResultError
	}
	targetName := issuerCA.Label
	if cn := base.Subject.CommonName; cn != "" {
		targetName = cn
	}
	detail := "profile=" + profile.Name + " " + res.Summary()
	if len(res.Iodef) > 0 {
		detail += " iodef=[" + strings.Join(res.Iodef, " ") + "]"
	}
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		Action:     audit.ActionCertCAA,
		Target:     issuerCA.ID,
		TargetName: targetName,
		Result:     result,
		Detail:     detail,
	}
	if err := m.db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append cert.caa audit event: %v", err)
	}
}
