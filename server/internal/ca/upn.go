package ca

import (
	"fmt"
	"log"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/upn"
)

// UPNConfig marks a profile as a Microsoft smartcard-logon / Kerberos PKINIT
// profile and configures its User Principal Name policy. Its presence is what
// permits a leaf under the profile to carry a UPN otherName SAN (id-ms-UPN,
// 1.3.6.1.4.1.311.20.2.3): every requested UPN is validated (syntax) and its
// realm checked against the profile and tenant realm allowlists before any HSM
// signature. A profile without a UPNConfig rejects any requested UPN.
type UPNConfig struct {
	// AllowedRealms restricts the UPN realms/domains the profile may certify:
	// "EXAMPLE.COM" matches exactly, "*.example.com" matches subdomains. Matching
	// is case-insensitive. Empty means no profile-level restriction (a tenant
	// allowlist may still apply).
	AllowedRealms []string `json:"allowed_realms,omitempty"`
	// RequireUPN makes issuance fail when no UPN SAN is supplied. A smartcard-logon
	// certificate is useless without a UPN, so the built-in profiles set it.
	RequireUPN bool `json:"require_upn,omitempty"`
}

// validate rejects unparseable realm-allowlist entries so a configuration error
// surfaces at startup rather than at issuance time.
func (c *UPNConfig) validate(profileName string) error {
	if _, err := upn.NewRealmAllowlist(c.AllowedRealms); err != nil {
		return fmt.Errorf("profile %q: upn allowed_realms: %w", profileName, err)
	}
	return nil
}

// tenantUPNRealms scopes UPN issuance per tenant: when a tenant has an allowlist
// here, every certificate minted by that tenant's CAs may only certify UPNs
// whose realm matches (in addition to any profile-level allowlist). Keyed by
// tenant ID; installed once at startup via SetTenantUPNRealms, so no locking is
// required for reads. Tests replace it directly.
var tenantUPNRealms = map[string]*upn.RealmAllowlist{}

// SetTenantUPNRealms validates and installs the per-tenant UPN realm allowlists.
// Calling it again replaces the previous set.
func SetTenantUPNRealms(realms map[string][]string) error {
	next := make(map[string]*upn.RealmAllowlist, len(realms))
	for tenantID, entries := range realms {
		al, err := upn.NewRealmAllowlist(entries)
		if err != nil {
			return fmt.Errorf("tenant %q allowed_upn_realms: %w", tenantID, err)
		}
		if !al.Empty() {
			next[tenantID] = al
		}
	}
	tenantUPNRealms = next
	return nil
}

// applyUPNPolicy is the pre-issuance UPN gate. For profiles without a UPNConfig
// it passes requests that carry no UPN through untouched and rejects any request
// that does carry one (a UPN SAN must be a deliberate, profile-permitted choice).
// For UPN profiles it, fail-closed and before any HSM signature:
//
//  1. requires at least one UPN when the profile sets require_upn;
//  2. validates every requested UPN ("local@REALM" syntax) and de-duplicates
//     them — the certificate carries the normalized forms;
//  3. enforces the profile's allowed-realm allowlist and the issuing tenant's
//     allowed_upn_realms scoping (both apply when both are set).
func (m *Manager) applyUPNPolicy(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, requestedBy string) (pki.LeafCertRequest, error) {
	ev := m.evaluateUPNPolicy(base, profile, issuerCA)
	if !ev.applicable {
		return base, nil
	}
	if !ev.ok {
		metrics.CertificateUPNChecks.Inc("fail")
		metrics.CertificateUPNFindings.Inc(ev.reason)
		m.recordUPNEvent(base, profile, issuerCA, requestedBy, ev.err)
		return base, fmt.Errorf("pre-issuance UPN check failed for profile %q: %w", profile.Name, ev.err)
	}
	metrics.CertificateUPNChecks.Inc("pass")
	return ev.base, nil
}

// upnEvaluation is the side-effect-free outcome of the UPN gate: whether it
// applied, whether the request passed, the (UPN-normalized) request on success,
// and — on failure — the finding-reason code and the error. It carries no
// metrics or audit effects so the same decision can back both the issuance path
// (applyUPNPolicy) and the non-mutating issuance preview (PreviewIssuance).
type upnEvaluation struct {
	// applicable is true when the gate ran (the profile is a UPN profile, or a UPN
	// was requested on a non-UPN profile — which fails).
	applicable bool
	// ok reports the gate passed (meaningful only when applicable).
	ok bool
	// base is the request with UPN SANs validated and normalized (valid only when ok).
	base pki.LeafCertRequest
	// reason is the finding code on failure ("required", "not_permitted",
	// "syntax", "config", "realm").
	reason string
	// err is the failure detail (nil on success).
	err error
}

// evaluateUPNPolicy is the pure core of the pre-issuance UPN gate. It validates
// every requested UPN and enforces the profile and tenant realm allowlists,
// returning the normalized request on success — without recording any metric or
// audit event. applyUPNPolicy wraps it for the issuance path; PreviewIssuance
// consumes the verdict directly.
func (m *Manager) evaluateUPNPolicy(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA) upnEvaluation {
	fail := func(reason, format string, args ...interface{}) upnEvaluation {
		return upnEvaluation{base: base, applicable: true, ok: false, reason: reason, err: fmt.Errorf(format, args...)}
	}

	if profile.UPN == nil {
		if len(base.UPNs) > 0 {
			return fail("not_permitted", "profile %q does not permit User Principal Name SANs (use a smartcard-logon / pkinit-client profile)", profile.Name)
		}
		return upnEvaluation{base: base, applicable: false}
	}

	if len(base.UPNs) == 0 {
		if profile.UPN.RequireUPN {
			return fail("required", "profile %q requires a User Principal Name SAN", profile.Name)
		}
		return upnEvaluation{base: base, applicable: true, ok: true}
	}

	upns, err := upn.NormalizeAll(base.UPNs)
	if err != nil {
		return fail("syntax", "%w", err)
	}

	// Effective allowlists: the profile's own and the issuing tenant's. Both must
	// admit every realm when both are configured.
	profileAllow, err := upn.NewRealmAllowlist(profile.UPN.AllowedRealms)
	if err != nil {
		// Unreachable for profiles installed through SetCustomProfiles (validated
		// there); kept fail-closed for hand-constructed profiles.
		return fail("config", "invalid allowed_realms: %v", err)
	}
	tenantID := issuerCA.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	tenantAllow := tenantUPNRealms[tenantID]
	normalized := make([]string, len(upns))
	for i, u := range upns {
		if !profileAllow.Allows(u.Realm) {
			return fail("realm", "UPN realm %q is not permitted by profile %q (allowed: %v)", u.Realm, profile.Name, profile.UPN.AllowedRealms)
		}
		if !tenantAllow.Allows(u.Realm) {
			return fail("realm", "UPN realm %q is not permitted for tenant %q", u.Realm, tenantID)
		}
		normalized[i] = u.Value
	}
	base.UPNs = normalized
	return upnEvaluation{base: base, applicable: true, ok: true}
}

// recordUPNEvent appends a tamper-evident audit event for a blocked UPN issuance
// (invalid UPN, a realm outside the allowlists, a UPN on a non-UPN profile, or a
// required-but-missing UPN).
func (m *Manager) recordUPNEvent(base pki.LeafCertRequest, profile Profile, issuerCA *models.CA, requestedBy string, checkErr error) {
	actor := requestedBy
	if actor == "" {
		actor = "system"
	}
	targetName := issuerCA.Label
	if cn := base.Subject.CommonName; cn != "" {
		targetName = cn
	} else if len(base.UPNs) > 0 {
		targetName = base.UPNs[0]
	}
	e := &audit.Event{
		ID:         uuid.New().String(),
		Actor:      actor,
		Action:     audit.ActionCertUPN,
		Target:     issuerCA.ID,
		TargetName: targetName,
		Result:     audit.ResultError,
		Detail:     "profile=" + profile.Name + " " + checkErr.Error(),
	}
	if err := m.db.AppendEvent(e); err != nil {
		log.Printf("WARNING: failed to append cert.upn audit event: %v", err)
	}
}
