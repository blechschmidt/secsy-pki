package ca

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/certpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/nameconstraints"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// caPolicyExtensions builds the CA-level RFC 5280 extensions requested by a CA
// spec: Name Constraints (2.5.29.30) and the certificate-policy family
// (certificatePolicies / policyMappings / policyConstraints). They are appended
// to the CA certificate template so a subordinate chain is bound by them and
// path validators (and the pre-issuance gate) enforce them on every leaf.
func caPolicyExtensions(nc nameconstraints.Constraints, pol certpolicy.Policies) ([]pkix.Extension, error) {
	var exts []pkix.Extension
	if !nc.IsZero() {
		ext, ok, err := nc.Extension()
		if err != nil {
			return nil, fmt.Errorf("building name constraints: %w", err)
		}
		if ok {
			exts = append(exts, ext)
		}
	}
	if !pol.IsZero() {
		polExts, err := pol.Extensions()
		if err != nil {
			return nil, fmt.Errorf("building certificate policies: %w", err)
		}
		exts = append(exts, polExts...)
	}
	return exts, nil
}

// preservedCAExtensionOIDs are the CA-scoped policy/constraint extensions carried
// forward verbatim when an intermediate CA's signing key is rotated, so the
// replacement certificate stays a drop-in issuer for the same constraints.
var preservedCAExtensionOIDs = map[string]bool{
	"2.5.29.30": true, // name constraints
	"2.5.29.32": true, // certificate policies
	"2.5.29.33": true, // policy mappings
	"2.5.29.36": true, // policy constraints
}

// preservedCAExtensions extracts the Name Constraints and certificate-policy
// extensions from an existing CA certificate so a rotation can re-emit them
// unchanged. crypto/x509 surfaces every extension (including the directoryName
// subtrees it cannot model) in cert.Extensions, so copying them verbatim
// preserves the exact encoded constraints.
func preservedCAExtensions(cert *x509.Certificate) []pkix.Extension {
	var out []pkix.Extension
	for _, e := range cert.Extensions {
		if preservedCAExtensionOIDs[e.Id.String()] {
			out = append(out, e)
		}
	}
	return out
}

// checkNameConstraints is the fail-closed pre-issuance Name Constraints gate. It
// enforces the issuing CA's own RFC 5280 §4.2.1.10 constraints on the candidate
// leaf's subject and subject alternative names, mirroring the CAA gate: a leaf
// whose name falls outside a permitted subtree or inside an excluded subtree is
// rejected before any HSM signature. Enforcement is unconditional whenever the
// issuer carries name constraints — a CA cannot opt out of honoring the limits
// encoded in its own certificate.
func (m *Manager) checkNameConstraints(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, issuerCert *x509.Certificate, requestedBy string) error {
	ev := m.evaluateNameConstraints(base, issuerCert)
	if ev.parseErr != nil {
		// The issuer's own extension failed to parse. Fail closed: we cannot prove
		// the leaf is in scope, so refuse rather than mis-issue.
		metrics.CertificateNameConstraintChecks.Inc("error")
		return fmt.Errorf("pre-issuance name-constraint check failed for CA %q: %w", issuerCA.Label, ev.parseErr)
	}
	if !ev.applicable {
		// Issuer imposes no name constraints; nothing to enforce.
		return nil
	}
	if ev.res.Permitted() {
		metrics.CertificateNameConstraintChecks.Inc("pass")
		return nil
	}

	metrics.CertificateNameConstraintChecks.Inc("fail")
	for _, v := range ev.res.Violations {
		metrics.CertificateNameConstraintViolations.Inc(v.Type + ":" + v.Reason)
	}
	m.recordNameConstraintEvent(base, profile, issuerCA, requestedBy, ev.res)
	return fmt.Errorf("pre-issuance name-constraint check failed for CA %q: %s", issuerCA.Label, ev.res.Summary())
}

// nameConstraintEvaluation is the side-effect-free outcome of the Name
// Constraints gate: whether the issuer imposes constraints, the validation
// result, or a parse error on the issuer's own extension (which fails closed).
type nameConstraintEvaluation struct {
	// applicable is true when the issuing CA certificate carries name constraints.
	applicable bool
	// res is the validation of the candidate leaf's names against them (valid only
	// when applicable and parseErr is nil).
	res nameconstraints.Result
	// parseErr is non-nil when the issuer's own name-constraint extension could
	// not be parsed; the gate then fails closed.
	parseErr error
}

// evaluateNameConstraints is the pure core of the pre-issuance Name Constraints
// gate: it validates the candidate leaf's subject and SANs against the issuing
// CA's RFC 5280 §4.2.1.10 constraints, WITHOUT recording metrics or audit
// events. checkNameConstraints wraps it for the issuance path; PreviewIssuance
// consumes the verdict directly.
func (m *Manager) evaluateNameConstraints(base pki.LeafCertRequest, issuerCert *x509.Certificate) nameConstraintEvaluation {
	constraints, ok, err := nameconstraints.FromExtensions(issuerCert.Extensions)
	if err != nil {
		return nameConstraintEvaluation{applicable: true, parseErr: err}
	}
	if !ok {
		return nameConstraintEvaluation{applicable: false}
	}
	id := nameconstraints.Identity{
		DNSNames: base.DNSNames,
		IPs:      base.IPAddresses,
		Emails:   base.EmailAddresses,
		URIs:     base.URIs,
		Subject:  base.Subject,
	}
	return nameConstraintEvaluation{applicable: true, res: constraints.Validate(id)}
}

// recordNameConstraintEvent appends a tamper-evident audit event for a leaf
// blocked by the issuing CA's name constraints.
func (m *Manager) recordNameConstraintEvent(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, requestedBy string, res nameconstraints.Result) {
	actor := requestedBy
	if actor == "" {
		actor = "system"
	}
	targetName := issuerCA.Label
	if cn := base.Subject.CommonName; cn != "" {
		targetName = cn
	}
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		Action:     audit.ActionCertNameConstraint,
		Target:     issuerCA.ID,
		TargetName: targetName,
		Result:     audit.ResultError,
		Detail:     "profile=" + profile.Name + " " + res.Summary(),
	}
	if err := m.db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append cert.nameconstraint audit event: %v", err)
	}
}
