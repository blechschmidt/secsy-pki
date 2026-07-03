package ca

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/certlint"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/smime"
)

// SMIMEConfig marks a profile as an S/MIME (id-kp-emailProtection) profile and
// configures its mailbox policy. Its presence switches on the S/MIME issuance
// gate — every rfc822Name SAN is validated and normalized (RFC 5321 syntax,
// internationalized domains folded to punycode A-labels) and checked against
// the domain allowlists before any HSM signature — and adds the CA/B Forum
// S/MIME Baseline Requirements rule set to the profile's pre-issuance lint
// policy (gated enforce/warn like every other lint check).
type SMIMEConfig struct {
	// Variant declares the key-usage split: "sign" (digitalSignature only),
	// "encrypt" (keyEncipherment/keyAgreement only), or "dual" (both; default).
	// Split sign/encrypt pairs are recommended so encryption keys can be
	// escrowed without escrowing signing keys.
	Variant string `json:"variant,omitempty"`
	// BRProfile selects the S/MIME Baseline Requirements class driving the
	// lint validity cap and EKU exclusivity: "legacy" (1185-day cap, extra EKUs
	// tolerated), "multipurpose" (825-day cap; default), or "strict" (825-day
	// cap, no EKU besides emailProtection).
	BRProfile string `json:"br_profile,omitempty"`
	// AllowedDomains restricts the e-mail domains the profile may certify:
	// "example.com" matches exactly, "*.example.com" matches subdomains. Empty
	// means no profile-level restriction (a tenant allowlist may still apply).
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	// SubjectEmail additionally carries the first rfc822Name SAN in the subject
	// DN as a PKCS#9 emailAddress attribute, for legacy relying parties that
	// read the address from the subject rather than the SAN.
	SubjectEmail bool `json:"subject_email,omitempty"`
}

// variant resolves the effective certlint variant.
func (c *SMIMEConfig) variant() certlint.SMIMEVariant {
	switch strings.ToLower(c.Variant) {
	case string(certlint.SMIMEVariantSign):
		return certlint.SMIMEVariantSign
	case string(certlint.SMIMEVariantEncrypt):
		return certlint.SMIMEVariantEncrypt
	default:
		return certlint.SMIMEVariantDual
	}
}

// class resolves the effective certlint Baseline Requirements class.
func (c *SMIMEConfig) class() certlint.SMIMEClass {
	switch strings.ToLower(c.BRProfile) {
	case string(certlint.SMIMEClassLegacy):
		return certlint.SMIMEClassLegacy
	case string(certlint.SMIMEClassStrict):
		return certlint.SMIMEClassStrict
	default:
		return certlint.SMIMEClassMultipurpose
	}
}

// validate rejects unknown enum values and unparseable allowlist entries so
// configuration errors surface at startup rather than at issuance time.
func (c *SMIMEConfig) validate(profileName string) error {
	switch strings.ToLower(c.Variant) {
	case "", "sign", "encrypt", "dual":
	default:
		return fmt.Errorf("profile %q: unknown smime variant %q (want sign, encrypt, or dual)", profileName, c.Variant)
	}
	switch strings.ToLower(c.BRProfile) {
	case "", "legacy", "multipurpose", "strict":
	default:
		return fmt.Errorf("profile %q: unknown smime br_profile %q (want legacy, multipurpose, or strict)", profileName, c.BRProfile)
	}
	if _, err := smime.NewDomainAllowlist(c.AllowedDomains); err != nil {
		return fmt.Errorf("profile %q: smime allowed_domains: %w", profileName, err)
	}
	return nil
}

// tenantEmailDomains scopes S/MIME issuance per tenant: when a tenant has an
// allowlist here, every certificate minted by that tenant's CAs under an
// S/MIME profile may only certify matching e-mail domains (in addition to any
// profile-level allowlist). Keyed by tenant ID; installed once at startup via
// SetTenantEmailDomains, so no locking is required for reads. Tests replace it
// directly.
var tenantEmailDomains = map[string]*smime.DomainAllowlist{}

// SetTenantEmailDomains validates and installs the per-tenant e-mail domain
// allowlists. Calling it again replaces the previous set.
func SetTenantEmailDomains(domains map[string][]string) error {
	next := make(map[string]*smime.DomainAllowlist, len(domains))
	for tenantID, entries := range domains {
		al, err := smime.NewDomainAllowlist(entries)
		if err != nil {
			return fmt.Errorf("tenant %q allowed_email_domains: %w", tenantID, err)
		}
		if !al.Empty() {
			next[tenantID] = al
		}
	}
	tenantEmailDomains = next
	return nil
}

// oidEmailAddress is the PKCS#9 emailAddress subject attribute
// (1.2.840.113549.1.9.1), encoded as IA5String per RFC 5280 §4.1.2.6.
var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// applySMIMEPolicy is the pre-issuance S/MIME gate. For profiles without an
// SMIMEConfig it returns the request untouched. Otherwise it, fail-closed and
// before any HSM signature:
//
//  1. validates and normalizes every rfc822Name SAN (RFC 5321 addr-spec,
//     internationalized domains folded to lowercase punycode A-labels) and
//     de-duplicates them — the certificate carries the normalized forms;
//  2. enforces the profile's allowed-domain allowlist and the issuing
//     tenant's allowed_email_domains scoping (both apply when both are set);
//  3. when the profile requests it, mirrors the first address into the
//     subject DN as a PKCS#9 emailAddress attribute (IA5String).
//
// Requests with no rfc822Name at all pass through here: SAN presence is the
// lint gate's smime_san_present check, so operators grade it enforce/warn per
// profile like every other structural rule.
func (m *Manager) applySMIMEPolicy(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, requestedBy string) (pki.LeafCertRequest, error) {
	if profile.SMIME == nil {
		return base, nil
	}

	fail := func(reason, format string, args ...interface{}) (pki.LeafCertRequest, error) {
		metrics.CertificateSMIMEChecks.Inc("fail")
		metrics.CertificateSMIMEFindings.Inc(reason)
		err := fmt.Errorf(format, args...)
		m.recordSMIMEEvent(base, profile, issuerCA, requestedBy, err)
		return base, fmt.Errorf("pre-issuance S/MIME check failed for profile %q: %w", profile.Name, err)
	}

	mailboxes, err := smime.NormalizeAll(base.EmailAddresses)
	if err != nil {
		return fail("syntax", "%w", err)
	}

	// Effective allowlists: the profile's own and the issuing tenant's. Both
	// must admit every domain when both are configured.
	profileAllow, err := smime.NewDomainAllowlist(profile.SMIME.AllowedDomains)
	if err != nil {
		// Unreachable for profiles installed through SetCustomProfiles (validated
		// there), kept fail-closed for hand-constructed profiles.
		return fail("config", "invalid allowed_domains: %v", err)
	}
	tenantID := issuerCA.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	tenantAllow := tenantEmailDomains[tenantID]
	for _, mb := range mailboxes {
		if !profileAllow.Allows(mb.Domain) {
			return fail("domain", "email domain %q is not permitted by profile %q (allowed: %v)", mb.Domain, profile.Name, profile.SMIME.AllowedDomains)
		}
		if !tenantAllow.Allows(mb.Domain) {
			return fail("domain", "email domain %q is not permitted for tenant %q", mb.Domain, tenantID)
		}
	}

	normalized := make([]string, len(mailboxes))
	for i, mb := range mailboxes {
		normalized[i] = mb.Address()
	}
	base.EmailAddresses = normalized

	if profile.SMIME.SubjectEmail && len(normalized) > 0 {
		base.Subject.ExtraNames = appendSubjectEmail(base.Subject.ExtraNames, normalized[0])
	}

	metrics.CertificateSMIMEChecks.Inc("pass")
	return base, nil
}

// appendSubjectEmail adds the PKCS#9 emailAddress attribute unless one is
// already present (a caller-supplied subject attribute wins; the lint gate
// verifies it matches a SAN either way).
func appendSubjectEmail(extra []pkix.AttributeTypeAndValue, email string) []pkix.AttributeTypeAndValue {
	for _, atv := range extra {
		if atv.Type.Equal(oidEmailAddress) {
			return extra
		}
	}
	return append(extra, pkix.AttributeTypeAndValue{
		Type: oidEmailAddress,
		// rfc822Name and the emailAddress attribute are IA5String; Go would
		// otherwise encode the '@' as UTF8String, which some relying parties
		// reject.
		Value: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagIA5String, Bytes: []byte(email)},
	})
}

// recordSMIMEEvent appends a tamper-evident audit event for a blocked S/MIME
// issuance (invalid mailbox or a domain outside the allowlists).
func (m *Manager) recordSMIMEEvent(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, requestedBy string, checkErr error) {
	actor := requestedBy
	if actor == "" {
		actor = "system"
	}
	targetName := issuerCA.Label
	if cn := base.Subject.CommonName; cn != "" {
		targetName = cn
	} else if len(base.EmailAddresses) > 0 {
		targetName = base.EmailAddresses[0]
	}
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		Action:     audit.ActionCertSMIME,
		Target:     issuerCA.ID,
		TargetName: targetName,
		Result:     audit.ResultError,
		Detail:     "profile=" + profile.Name + " " + checkErr.Error(),
	}
	if err := m.db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append cert.smime audit event: %v", err)
	}
}
