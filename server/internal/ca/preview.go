package ca

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/caa"
	"github.com/blechschmidt/secsy-pki/server/internal/certlint"
	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/nameconstraints"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/tracing"
	"go.opentelemetry.io/otel/attribute"
)

// Single-request pre-issuance dry-run / validation preview (Task 113).
//
// PreviewIssuance validates one would-be issuance through the full fail-closed
// pre-issuance gate stack WITHOUT signing anything, allocating a durable serial,
// persisting a record, appending an audit event, or taking a tenant/rate-limit
// reservation. It resolves the profile, assembles the exact leaf TBSCertificate
// the real path would sign (KU/EKU/SAN/AKI/SKI/certificatePolicies/validity), and
// runs every gate — S/MIME policy, certificate policies, OCSP Must-Staple,
// certlint (and the optional zlint backend), CAA, Name Constraints, validity
// caps, and the manual-approval "would-park" signal — collecting each gate's
// pass/fail/reason. It lets an operator or CI validate a request before a real,
// HSM-consuming issuance.
//
// It reuses the same pure gate evaluators (evaluateSMIMEPolicy, lintResult,
// evaluateCAA, evaluateNameConstraints) that back the issuance path, so a
// preview verdict cannot drift from what buildLeaf would actually enforce. The
// only pieces it necessarily approximates are the attestation gate (an
// enrollment-protocol concern layered above ca — added by the serving layer) and
// the manual-approval engine state (added/refined by the serving layer, which
// owns the four-eyes engine); the ca-layer preview reports the profile's own
// require_approval intent.

// GateStatus is the disposition of one pre-issuance gate in a preview.
type GateStatus string

const (
	// GatePass: the gate ran and the request satisfied it.
	GatePass GateStatus = "pass"
	// GateFail: the gate ran and would reject the request (fail-closed). A single
	// failing gate makes the whole preview a "reject".
	GateFail GateStatus = "fail"
	// GateWarn: the gate produced findings that do not block issuance (warn-mode
	// lint findings, a permissive CAA denial, an approval hold, …).
	GateWarn GateStatus = "warn"
	// GateSkipped: the gate did not apply to this request (feature disabled for
	// the profile, or nothing for it to check).
	GateSkipped GateStatus = "skipped"
)

// Gate names, stable identifiers shared by every transport rendering a preview.
const (
	GateSMIME           = "smime"
	GateUPN             = "upn"
	GateCertPolicy      = "certificate_policy"
	GateMustStaple      = "must_staple"
	GateQCStatements    = "qcstatements"
	GateLint            = "lint"
	GateCAA             = "caa"
	GateNameConstraints = "name_constraints"
	GateKeyCheck        = "keycheck"
	GateValidity        = "validity"
	GateApproval        = "approval"
	// GateAttestation is populated by the serving layer (handlers), which owns the
	// enrollment attestation verifier; ca does not import it. Defined here so both
	// layers agree on the name.
	GateAttestation = "attestation"
)

// GateVerdict is one pre-issuance gate's outcome in a preview.
type GateVerdict struct {
	// Name is the gate identifier (one of the Gate* constants).
	Name string `json:"name"`
	// Status is the gate disposition.
	Status GateStatus `json:"status"`
	// Reason is a human-readable explanation of the disposition.
	Reason string `json:"reason,omitempty"`
	// Findings carries per-check detail (e.g. individual lint codes or
	// name-constraint violations) when the gate produced several.
	Findings []string `json:"findings,omitempty"`
}

// PreviewExtension describes one X.509 extension the leaf would carry, resolved
// from a faithful (throwaway-signed) synthesis of the to-be-signed certificate.
type PreviewExtension struct {
	// OID is the dotted extension object identifier.
	OID string `json:"oid"`
	// Name is a human-readable name for well-known extensions (empty if unknown).
	Name string `json:"name,omitempty"`
	// Critical reports whether the extension is marked critical.
	Critical bool `json:"critical"`
}

// PreviewSpec describes a would-be issuance to validate without signing. Either
// CSRPEM is set (subject/public key/SANs are taken from the verified CSR) or the
// explicit Subject/SAN fields are set (a throwaway subject key is synthesized so
// the extension layout can be resolved). Every other field mirrors IssueSpec.
type PreviewSpec struct {
	CAID string
	// CSRPEM, when set, is a PEM PKCS#10 CSR whose subject, public key, and SANs
	// are previewed exactly as issuance would take them.
	CSRPEM []byte
	// Subject and the SAN fields are used when CSRPEM is empty.
	Subject        pkix.Name
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string
	URIs           []string
	// UPNs are Microsoft/Kerberos User Principal Name otherName SANs (Task 122),
	// previewed through the same UPN gate the issuance path enforces.
	UPNs []string
	// Profile is the certificate profile name (empty = default profile).
	Profile string
	// Validity is the requested validity (0 = profile default). The validity gate
	// reports whether it exceeds the profile maximum or the CA's own expiry.
	Validity time.Duration
	// RequestedBy is the requesting principal (used only for context; the preview
	// records nothing).
	RequestedBy string
	// MustStaple optionally overrides the profile's RFC 7633 default (honored only
	// where the profile permits per-request overrides).
	MustStaple *bool
	// PSD2 optionally supplies the ETSI TS 119 495 PSD2 authorization for the eIDAS
	// QCStatements extension (Task 128), previewed through the same QC resolution
	// the issuance path enforces (honored only under a QC-enabled profile that
	// permits per-request PSD2 overrides).
	PSD2 *models.PSD2QCStatement
	// ACMEAccountURI / ValidationMethods carry the RFC 8657 CAA-binding facts of an
	// ACME-driven request into the CAA gate; the zero value on every other path.
	ACMEAccountURI    string
	ValidationMethods map[string]string
}

// PreviewResult is the outcome of a non-mutating issuance preview.
type PreviewResult struct {
	CAID    string `json:"ca_id"`
	CALabel string `json:"ca_label"`
	Profile string `json:"profile"`
	// Decision is the overall outcome: "accept" (would issue immediately), "park"
	// (would be held for four-eyes approval), or "reject" (a fail-closed gate would
	// refuse it).
	Decision string `json:"decision"`
	// WouldIssue is true when no gate would reject the request (Decision is accept
	// or park).
	WouldIssue bool `json:"would_issue"`
	// WouldPark is true when a real operator/API issuance would be held for manual
	// approval instead of issued immediately. Set by the serving layer, which owns
	// the four-eyes engine state.
	WouldPark bool `json:"would_park"`
	// RequiresApproval reports the profile's require_approval intent.
	RequiresApproval bool `json:"requires_approval"`

	// Resolved leaf fields (what the certificate would carry).
	Subject               string    `json:"subject"`
	SANs                  []string  `json:"sans,omitempty"`
	KeyUsages             []string  `json:"key_usages,omitempty"`
	ExtKeyUsages          []string  `json:"ext_key_usages,omitempty"`
	NotBefore             time.Time `json:"not_before"`
	NotAfter              time.Time `json:"not_after"`
	ValidityDays          int       `json:"validity_days"`
	RequestedValidityDays int       `json:"requested_validity_days"`
	MaxValidityDays       int       `json:"max_validity_days"`
	SubjectKeyID          string    `json:"subject_key_id,omitempty"`
	AuthorityKeyID        string    `json:"authority_key_id,omitempty"`
	// SubjectKeyProvided reports whether a real subject public key was supplied (via
	// a CSR). When false the subject key identifier above is derived from a
	// throwaway key synthesized only to resolve the extension layout, and is
	// indicative rather than the value a real certificate would carry.
	SubjectKeyProvided bool               `json:"subject_key_provided"`
	MustStaple         bool               `json:"must_staple"`
	Extensions         []PreviewExtension `json:"extensions,omitempty"`

	// Gates carries every gate's verdict, in evaluation order.
	Gates []GateVerdict `json:"gates"`
}

// SetGate replaces the verdict for a named gate (appending it when absent). It
// lets the serving layer refine the approval verdict with the four-eyes engine
// state and add the attestation verdict without the ca layer importing either.
func (r *PreviewResult) SetGate(v GateVerdict) {
	for i := range r.Gates {
		if r.Gates[i].Name == v.Name {
			r.Gates[i] = v
			return
		}
	}
	r.Gates = append(r.Gates, v)
}

// Recompute derives WouldIssue and Decision from the current gate verdicts and
// WouldPark. It is called by PreviewIssuance and again by the serving layer after
// it refines the approval/attestation verdicts. A single failing gate rejects.
func (r *PreviewResult) Recompute() {
	failed := false
	for _, g := range r.Gates {
		if g.Status == GateFail {
			failed = true
			break
		}
	}
	r.WouldIssue = !failed
	switch {
	case failed:
		r.Decision = "reject"
	case r.WouldPark:
		r.Decision = "park"
	default:
		r.Decision = "accept"
	}
}

// PreviewIssuance validates a would-be issuance through the pre-issuance gate
// stack without signing, persisting, allocating a durable serial, or taking any
// reservation. See the package-level comment above for the full contract.
func (m *Manager) PreviewIssuance(ctx context.Context, spec PreviewSpec) (_ *PreviewResult, err error) {
	ctx, span := tracing.Start(ctx, "ca.preview_issuance", attribute.String("ca.id", spec.CAID))
	defer func() { tracing.End(span, err) }()

	// Follow key-rotation lineage exactly as issuance does, so a preview validates
	// against the CA that would actually sign.
	activeID, err := m.ActiveIssuerID(spec.CAID)
	if err != nil {
		return nil, err
	}
	issuerCA, issuerCert, err := m.loadIssuer(activeID)
	if err != nil {
		return nil, err
	}
	profile, err := LookupProfile(spec.Profile)
	if err != nil {
		return nil, err
	}
	// Post-quantum / hybrid issuance takes dedicated ML-DSA paths whose keys
	// crypto/x509 cannot synthesize for a faithful extension preview; validate
	// those requests through their own issuance path.
	if profile.Algorithm != AlgClassical {
		return nil, fmt.Errorf("issuance preview supports classical profiles only; profile %q is %s", profile.Name, profile.Algorithm)
	}

	parts, subjectKeyProvided, err := previewLeafParts(spec)
	if err != nil {
		return nil, err
	}
	keyUsage, err := profile.keyUsage()
	if err != nil {
		return nil, err
	}
	extKeyUsage, unknownEKU, err := profile.extKeyUsage()
	if err != nil {
		return nil, err
	}

	// Resolve the validity window exactly as issueLeaf does (default, then clamp to
	// the profile maximum and the CA's own expiry). requested is what the operator
	// asked for (before clamping), so the validity gate can flag an over-max ask.
	now := time.Now()
	requested := spec.Validity
	if requested <= 0 {
		requested = profile.DefaultValidity
	}
	effective := profile.resolveValidity(spec.Validity)
	notBefore := now.Add(-clockSkew)
	notAfter := now.Add(effective)
	cappedByCA := false
	if notAfter.After(issuerCert.NotAfter) {
		notAfter = issuerCert.NotAfter
		cappedByCA = true
	}

	// A cryptographically random 128-bit serial, identical to the real allocator.
	// Serials are random (not drawn from a durable counter), so generating one for
	// the preview consumes nothing and is never persisted — the lint gate's serial
	// entropy check therefore sees a faithful value.
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}

	base := pki.LeafCertRequest{
		Subject:               parts.Subject,
		PublicKey:             parts.PublicKey,
		Serial:                serial,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		UnknownExtKeyUsage:    unknownEKU,
		DNSNames:              parts.DNSNames,
		IPAddresses:           parts.IPAddresses,
		EmailAddresses:        parts.EmailAddresses,
		URIs:                  parts.URIs,
		UPNs:                  parts.UPNs,
		CRLDistributionPoints: leafCRLDistributionPoints(issuerCA.ID, serial),
	}

	result := &PreviewResult{
		CAID:                  issuerCA.ID,
		CALabel:               issuerCA.Label,
		Profile:               profile.Name,
		RequiresApproval:      profile.RequireApproval,
		KeyUsages:             append([]string(nil), profile.KeyUsages...),
		ExtKeyUsages:          append([]string(nil), profile.ExtKeyUsages...),
		SubjectKeyProvided:    subjectKeyProvided,
		RequestedValidityDays: durationDays(requested),
		MaxValidityDays:       durationDays(profile.MaxValidity),
	}

	// 1. S/MIME policy gate (mutates the template — normalized mailboxes / subject
	// e-mail — on success, so downstream gates and the resolved extensions reflect
	// exactly what would be signed).
	smev := m.evaluateSMIMEPolicy(base, profile, issuerCA)
	switch {
	case !smev.applicable:
		result.Gates = append(result.Gates, skippedGate(GateSMIME, "profile is not an S/MIME profile"))
	case smev.ok:
		base = smev.base
		result.Gates = append(result.Gates, passGate(GateSMIME, "mailbox SANs valid and within the allowed e-mail domains"))
	default:
		result.Gates = append(result.Gates, failGate(GateSMIME, smev.err.Error()))
	}

	// 1b. UPN policy gate (smartcard-logon / PKINIT): validates User Principal Name
	// SANs and enforces the profile/tenant realm allowlists. Mutates the template
	// (normalized UPNs) on success so the resolved SAN reflects what would be signed.
	upnev := m.evaluateUPNPolicy(base, profile, issuerCA)
	switch {
	case !upnev.applicable:
		result.Gates = append(result.Gates, skippedGate(GateUPN, "profile is not a UPN (smartcard-logon/PKINIT) profile and no UPN was requested"))
	case upnev.ok:
		base = upnev.base
		if len(base.UPNs) > 0 {
			result.Gates = append(result.Gates, passGate(GateUPN, "UPN SAN(s) valid and within the allowed realms"))
		} else {
			result.Gates = append(result.Gates, passGate(GateUPN, "no UPN requested"))
		}
	default:
		result.Gates = append(result.Gates, failGate(GateUPN, upnev.err.Error()))
	}

	// 2. Certificate policies (certificatePolicies + any policy mappings/constraints).
	policyExts, err := profile.policyExtensions()
	if err != nil {
		return nil, err
	}
	if len(policyExts) > 0 {
		base.ExtraExtensions = appendExts(base.ExtraExtensions, policyExts)
		result.Gates = append(result.Gates, passGate(GateCertPolicy, fmt.Sprintf("%d certificate-policy extension(s) assigned by the profile", len(policyExts))))
	} else {
		result.Gates = append(result.Gates, skippedGate(GateCertPolicy, "profile assigns no certificate policies"))
	}

	// 3. OCSP Must-Staple (RFC 7633 TLS Feature) — resolved profile default,
	// possibly overridden per request where the profile permits.
	mustStaple := profile.resolveMustStaple(spec.MustStaple)
	base = applyMustStaple(base, mustStaple)
	result.MustStaple = mustStaple
	if mustStaple {
		result.Gates = append(result.Gates, passGate(GateMustStaple, "OCSP Must-Staple (id-pe-tlsfeature: status_request) would be stamped"))
	} else {
		result.Gates = append(result.Gates, skippedGate(GateMustStaple, "OCSP Must-Staple not requested for this certificate"))
	}

	// 3b. eIDAS QCStatements (ETSI EN 319 412-5) — the profile's qualified-
	// certificate semantics plus any per-request PSD2 override, resolved through
	// the same path the issuance flow enforces so the preview cannot drift.
	if qc, present, qcErr := profile.qcStatements(parts.psd2); qcErr != nil {
		result.Gates = append(result.Gates, failGate(GateQCStatements, qcErr.Error()))
	} else if present {
		var qerr error
		if base, qerr = applyQCStatements(base, profile, parts.psd2); qerr != nil {
			result.Gates = append(result.Gates, failGate(GateQCStatements, qerr.Error()))
		} else {
			result.Gates = append(result.Gates, passGate(GateQCStatements, describeQCStatements(qc)))
		}
	} else {
		result.Gates = append(result.Gates, skippedGate(GateQCStatements, "profile assigns no eIDAS QC statements"))
	}

	// 4. Pre-issuance lint (certlint + optional zlint) on the to-be-signed template.
	if profile.lintEnabled() {
		res, lerr := m.lintResult(base, profile, issuerCert)
		switch {
		case lerr != nil:
			result.Gates = append(result.Gates, failGate(GateLint, lerr.Error()))
		case res.HasErrors():
			result.Gates = append(result.Gates, GateVerdict{Name: GateLint, Status: GateFail, Reason: res.Summary(), Findings: lintFindingStrings(res.Errors())})
		case !res.OK():
			result.Gates = append(result.Gates, GateVerdict{Name: GateLint, Status: GateWarn, Reason: res.Summary(), Findings: lintFindingStrings(res.Warnings())})
		default:
			result.Gates = append(result.Gates, passGate(GateLint, "lint=ok"))
		}
	} else {
		result.Gates = append(result.Gates, skippedGate(GateLint, "lint gate disabled for the profile"))
	}

	// 5. CAA (RFC 8659/8657), read-only DNS resolution.
	caaRes, caaPol, caaDec := m.evaluateCAA(ctx, base, profile, caa.RequestContext{
		AccountURI:        spec.ACMEAccountURI,
		ValidationMethods: spec.ValidationMethods,
	})
	switch caaDec {
	case caaDisabled:
		result.Gates = append(result.Gates, skippedGate(GateCAA, "CAA gate disabled for the profile"))
	case caaSkipped:
		result.Gates = append(result.Gates, skippedGate(GateCAA, "no DNS-name SANs to check"))
	case caaNoResolver:
		if caaPol.Mode == caa.ModeEnforce {
			result.Gates = append(result.Gates, failGate(GateCAA, "no DNS resolver configured (enforce mode fails closed)"))
		} else {
			result.Gates = append(result.Gates, warnGate(GateCAA, "no DNS resolver configured; permissive mode allows issuance"))
		}
	default: // caaChecked
		switch {
		case caaRes.Forbidden() && caaPol.Mode == caa.ModeEnforce:
			result.Gates = append(result.Gates, GateVerdict{Name: GateCAA, Status: GateFail, Reason: caaRes.Summary(), Findings: caaFindingStrings(caaRes)})
		case caaRes.Forbidden():
			result.Gates = append(result.Gates, GateVerdict{Name: GateCAA, Status: GateWarn, Reason: "permissive: " + caaRes.Summary(), Findings: caaFindingStrings(caaRes)})
		default:
			result.Gates = append(result.Gates, passGate(GateCAA, caaRes.Summary()))
		}
	}

	// 6. Name Constraints (RFC 5280 §4.2.1.10), enforced from the issuing CA.
	ncev := m.evaluateNameConstraints(base, issuerCert)
	switch {
	case ncev.parseErr != nil:
		result.Gates = append(result.Gates, failGate(GateNameConstraints, "issuer name-constraint extension failed to parse: "+ncev.parseErr.Error()))
	case !ncev.applicable:
		result.Gates = append(result.Gates, skippedGate(GateNameConstraints, "issuing CA imposes no name constraints"))
	case ncev.res.Permitted():
		result.Gates = append(result.Gates, passGate(GateNameConstraints, "subject and SANs within the issuer's permitted subtrees"))
	default:
		result.Gates = append(result.Gates, GateVerdict{Name: GateNameConstraints, Status: GateFail, Reason: ncev.res.Summary(), Findings: ncViolationStrings(ncev.res)})
	}

	// 7. Key quality (Task 120, CA/Browser Forum BR §6.1.1.3): weak (ROCA /
	// exponent / modulus / Debian) and compromised (operator-blocklisted / reused-
	// subject) subject-key rejection. Uses the same evaluator as the issuance path.
	kcev := m.evaluateKeyChecks(base, profile)
	switch {
	case !kcev.applicable:
		result.Gates = append(result.Gates, skippedGate(GateKeyCheck, "key-quality gate disabled for the profile"))
	case kcev.err != nil:
		result.Gates = append(result.Gates, failGate(GateKeyCheck, kcev.err.Error()))
	case kcev.res.OK():
		result.Gates = append(result.Gates, passGate(GateKeyCheck, "subject public key passed every weak/compromised-key check"))
	case kcev.enforce:
		result.Gates = append(result.Gates, GateVerdict{Name: GateKeyCheck, Status: GateFail, Reason: kcev.res.Summary(), Findings: keyCheckFindingStrings(kcev.res)})
	default:
		result.Gates = append(result.Gates, GateVerdict{Name: GateKeyCheck, Status: GateWarn, Reason: "warn: " + kcev.res.Summary(), Findings: keyCheckFindingStrings(kcev.res)})
	}

	// 8. Validity caps (profile maximum and CA expiry).
	result.Gates = append(result.Gates, validityGate(requested, effective, profile, cappedByCA, issuerCert))

	// 9. Manual-approval "would-park" signal (profile intent; refined by the
	// serving layer with the four-eyes engine state).
	if profile.RequireApproval {
		result.Gates = append(result.Gates, warnGate(GateApproval,
			"profile requires four-eyes approval; operator/API issuance would be parked when the approvals engine is enabled (direct CLI issuance bypasses the manual gate)"))
	} else {
		result.Gates = append(result.Gates, passGate(GateApproval, "no manual approval required"))
	}

	// Resolve the exact extension layout (KU/EKU/SAN/SKI/AKI/certificatePolicies/…)
	// from a faithful synthesis of the to-be-signed certificate (throwaway
	// signature, no HSM). This never mutates state.
	if err := m.resolvePreviewLeaf(result, issuerCert, base); err != nil {
		return nil, err
	}
	result.NotBefore = notBefore.UTC()
	result.NotAfter = notAfter.UTC()
	result.ValidityDays = durationDays(notAfter.Sub(notBefore))

	result.Recompute()
	span.SetAttributes(
		attribute.String("preview.decision", result.Decision),
		attribute.Bool("preview.would_issue", result.WouldIssue),
	)
	return result, nil
}

// previewLeafParts resolves the subject, public key, and SANs for a preview from
// either a verified CSR or the explicit subject/SAN fields. When no CSR is
// supplied it synthesizes a throwaway RSA subject key so the extension layout can
// be resolved; keyProvided reports which path was taken.
func previewLeafParts(spec PreviewSpec) (parts leafParts, keyProvided bool, err error) {
	if len(spec.CSRPEM) > 0 {
		csr, cerr := parseAndVerifyCSR(spec.CSRPEM)
		if cerr != nil {
			return leafParts{}, false, cerr
		}
		uris := make([]string, len(csr.URIs))
		for i, u := range csr.URIs {
			uris[i] = u.String()
		}
		return leafParts{
			Subject:        csr.Subject,
			PublicKey:      csr.PublicKey,
			DNSNames:       csr.DNSNames,
			IPAddresses:    csr.IPAddresses,
			EmailAddresses: csr.EmailAddresses,
			URIs:           uris,
			UPNs:           append(pki.UPNsFromCSR(csr), spec.UPNs...),
			psd2:           spec.PSD2,
		}, true, nil
	}
	if spec.Subject.CommonName == "" && len(spec.DNSNames) == 0 && len(spec.UPNs) == 0 &&
		len(spec.IPAddresses) == 0 && len(spec.EmailAddresses) == 0 && len(spec.URIs) == 0 {
		return leafParts{}, false, fmt.Errorf("issuance preview requires a CSR, or a subject common name / at least one SAN")
	}
	// RSA-2048 satisfies every profile key usage (digitalSignature and
	// keyEncipherment) and the lint size checks, so a keyless preview does not
	// produce spurious key-type findings. Supply a CSR for an exact preview.
	key, kerr := rsa.GenerateKey(rand.Reader, 2048)
	if kerr != nil {
		return leafParts{}, false, fmt.Errorf("synthesizing preview subject key: %w", kerr)
	}
	return leafParts{
		Subject:        spec.Subject,
		PublicKey:      &key.PublicKey,
		DNSNames:       spec.DNSNames,
		IPAddresses:    spec.IPAddresses,
		EmailAddresses: spec.EmailAddresses,
		URIs:           spec.URIs,
		UPNs:           spec.UPNs,
		psd2:           spec.PSD2,
	}, false, nil
}

// resolvePreviewLeaf synthesizes a faithful DER of the to-be-signed leaf (real
// issuer DN + SKI, throwaway signature, no HSM) and reads back the exact resolved
// subject, SANs, subject/authority key identifiers, and extension layout.
func (m *Manager) resolvePreviewLeaf(result *PreviewResult, issuerCert *x509.Certificate, base pki.LeafCertRequest) error {
	der, err := pki.LintCertificateDER(issuerCert, base)
	if err != nil {
		return fmt.Errorf("synthesizing preview certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parsing preview certificate: %w", err)
	}
	result.Subject = cert.Subject.String()
	result.SANs = sanStrings(cert)
	result.SubjectKeyID = hexColons(cert.SubjectKeyId)
	result.AuthorityKeyID = hexColons(cert.AuthorityKeyId)
	result.Extensions = make([]PreviewExtension, 0, len(cert.Extensions))
	for _, e := range cert.Extensions {
		result.Extensions = append(result.Extensions, PreviewExtension{
			OID:      e.Id.String(),
			Name:     extensionName(e.Id.String()),
			Critical: e.Critical,
		})
	}
	return nil
}

// validityGate reports whether the requested validity fits within the profile
// maximum and the issuing CA's own expiry. An over-maximum request is a
// fail-closed reject for the preview (real issuance would silently clamp it); a
// window that only overruns the CA's expiry is a non-blocking warning.
func validityGate(requested, effective time.Duration, profile Profile, cappedByCA bool, issuerCert *x509.Certificate) GateVerdict {
	if profile.MaxValidity > 0 && requested > profile.MaxValidity {
		return failGate(GateValidity, fmt.Sprintf(
			"requested validity %dd exceeds the profile maximum %dd (real issuance would clamp it to the maximum)",
			durationDays(requested), durationDays(profile.MaxValidity)))
	}
	if cappedByCA {
		return warnGate(GateValidity, fmt.Sprintf(
			"requested validity extends past the issuing CA's expiry (%s); it would be shortened to the CA not_after",
			issuerCert.NotAfter.UTC().Format(time.RFC3339)))
	}
	return passGate(GateValidity, fmt.Sprintf("validity %dd within the profile maximum and the CA's expiry", durationDays(effective)))
}

// lintFindingStrings renders lint findings as "code: description" lines.
func lintFindingStrings(findings []certlint.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Code+": "+f.Description)
	}
	return out
}

// caaFindingStrings renders a CAA result's findings as "reason: detail" lines.
func caaFindingStrings(res caa.Result) []string {
	out := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		s := string(f.Reason)
		if f.Detail != "" {
			s += ": " + f.Detail
		}
		out = append(out, s)
	}
	return out
}

// keyCheckFindingStrings renders key-quality findings as "code: detail" lines.
func keyCheckFindingStrings(res keycheck.Result) []string {
	out := make([]string, 0, len(res.Findings))
	for _, f := range res.Findings {
		out = append(out, f.Code+": "+f.Detail)
	}
	return out
}

// ncViolationStrings renders name-constraint violations as flat strings.
func ncViolationStrings(res nameconstraints.Result) []string {
	out := make([]string, 0, len(res.Violations))
	for _, v := range res.Violations {
		out = append(out, v.String())
	}
	return out
}

// Gate-verdict constructors.
func passGate(name, reason string) GateVerdict {
	return GateVerdict{Name: name, Status: GatePass, Reason: reason}
}
func failGate(name, reason string) GateVerdict {
	return GateVerdict{Name: name, Status: GateFail, Reason: reason}
}
func warnGate(name, reason string) GateVerdict {
	return GateVerdict{Name: name, Status: GateWarn, Reason: reason}
}
func skippedGate(name, reason string) GateVerdict {
	return GateVerdict{Name: name, Status: GateSkipped, Reason: reason}
}

// durationDays renders a validity duration as whole days (rounded down).
func durationDays(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(d / (24 * time.Hour))
}

// hexColons renders a key identifier as colon-separated uppercase hex, the
// conventional presentation of SKI/AKI values.
func hexColons(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{x}))
	}
	return strings.Join(parts, ":")
}

// extensionName maps a well-known extension OID to a human-readable name, for
// the preview's resolved-extension list. Unknown OIDs return "".
func extensionName(oid string) string {
	return previewExtensionNames[oid]
}

// previewExtensionNames names the extensions the issuance path can emit on a leaf.
var previewExtensionNames = map[string]string{
	"2.5.29.14":               "subjectKeyIdentifier",
	"2.5.29.15":               "keyUsage",
	"2.5.29.17":               "subjectAltName",
	"2.5.29.19":               "basicConstraints",
	"2.5.29.30":               "nameConstraints",
	"2.5.29.31":               "cRLDistributionPoints",
	"2.5.29.32":               "certificatePolicies",
	"2.5.29.33":               "policyMappings",
	"2.5.29.35":               "authorityKeyIdentifier",
	"2.5.29.36":               "policyConstraints",
	"2.5.29.37":               "extKeyUsage",
	"1.3.6.1.5.5.7.1.1":       "authorityInfoAccess",
	"1.3.6.1.5.5.7.1.3":       "qcStatements",
	"1.3.6.1.5.5.7.1.24":      "tlsFeature",
	"1.3.6.1.4.1.11129.2.4.2": "ctSignedCertificateTimestampList",
	"1.3.6.1.4.1.11129.2.4.3": "ctPoison",
}
