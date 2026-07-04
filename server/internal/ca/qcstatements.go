package ca

import (
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// QCStatementsConfig is a profile's ETSI EN 319 412-5 QCStatements policy: which
// EU qualified-certificate semantics (eIDAS, Regulation (EU) No 910/2014) every
// leaf issued under the profile asserts via the id-pe-qcStatements extension
// (OID 1.3.6.1.5.5.7.1.3). A non-nil, non-empty block turns the feature on; the
// extension is always non-critical (ETSI EN 319 412-5 §4).
type QCStatementsConfig struct {
	// Compliance stamps id-etsi-qcs-QcCompliance (esi4-qcStatement-1): the
	// certificate is an EU qualified certificate.
	Compliance bool `json:"compliance,omitempty"`
	// Type is the qualified-certificate type carried in id-etsi-qcs-QcType
	// (esi4-qcStatement-6): "esign" (electronic signature, natural person),
	// "eseal" (electronic seal, legal person), or "web" (website authentication,
	// QWAC). Empty emits no QcType statement.
	Type string `json:"type,omitempty"`
	// SSCD stamps id-etsi-qcs-QcSSCD (esi4-qcStatement-4): the private key resides
	// in a qualified signature/seal creation device.
	SSCD bool `json:"sscd,omitempty"`
	// RetentionYears, when > 0, stamps id-etsi-qcs-QcRetentionPeriod
	// (esi4-qcStatement-3) with the number of years the issuer retains material
	// information about the certificate after it expires.
	RetentionYears int `json:"retention_years,omitempty"`
	// PDS lists the PKI Disclosure Statement locations stamped in
	// id-etsi-qcs-QcPDS (esi4-qcStatement-5): each a URL and its ISO 639-1
	// (two-letter) language code.
	PDS []QCPDSLocation `json:"pds,omitempty"`
	// PSD2 stamps the ETSI TS 119 495 PSD2 QcStatement (payment service provider
	// roles + the authorizing NCA). It is the profile default; a per-request
	// override may replace it when AllowPSD2Override is set.
	PSD2 *QCPSD2Config `json:"psd2,omitempty"`
	// AllowPSD2Override lets a REST/gRPC/CLI issue request supply or replace the
	// PSD2 authorization (roles + NCA) for an individual certificate. When false,
	// a per-request PSD2 override is rejected and the profile block (if any) is
	// authoritative — the "where policy permits" gate on this strong assertion.
	AllowPSD2Override bool `json:"allow_psd2_override,omitempty"`
}

// QCPDSLocation is one PKI Disclosure Statement location for QcPDS: the URL of
// the disclosure document and the ISO 639-1 language code it is written in.
type QCPDSLocation struct {
	URL      string `json:"url"`
	Language string `json:"language"`
}

// QCPSD2Config is a profile's default PSD2 QcStatement (ETSI TS 119 495): the
// payment service provider roles and the National Competent Authority that
// authorized it.
type QCPSD2Config struct {
	// Roles are the PSP roles: "PSP_AS", "PSP_PI", "PSP_AI", "PSP_IC".
	Roles []string `json:"roles,omitempty"`
	// NCAName is the human-readable name of the competent authority (e.g.
	// "Financial Conduct Authority").
	NCAName string `json:"nca_name,omitempty"`
	// NCAID is the NCA identifier (e.g. "GB-FCA"): a two-letter ISO 3166 country
	// code, a hyphen, and the 2–8 character authority id (ETSI TS 119 495 §5.2.1).
	NCAID string `json:"nca_id,omitempty"`
}

// validate checks the block is internally consistent and would emit at least one
// statement, so a misconfiguration surfaces at profile-install time rather than
// at the first issuance. It reuses build for the field-level validation.
func (c *QCStatementsConfig) validate(profileName string) error {
	if c == nil {
		return nil
	}
	qc, err := c.build()
	if err != nil {
		return fmt.Errorf("profile %q qcstatements: %w", profileName, err)
	}
	if qc.IsZero() {
		return fmt.Errorf("profile %q qcstatements block enables no statement "+
			"(set at least one of compliance/type/sscd/retention_years/pds/psd2)", profileName)
	}
	return nil
}

// build converts the profile block into the pki.QCStatements this CA encodes,
// validating each field (QcType selector, PDS language codes, PSD2 roles/NCA).
func (c *QCStatementsConfig) build() (pki.QCStatements, error) {
	qc := pki.QCStatements{
		Compliance:     c.Compliance,
		SSCD:           c.SSCD,
		RetentionYears: c.RetentionYears,
	}
	if c.RetentionYears < 0 {
		return pki.QCStatements{}, fmt.Errorf("retention_years must not be negative")
	}
	if t := strings.TrimSpace(c.Type); t != "" {
		oid, ok := pki.QCTypeOID(t)
		if !ok {
			return pki.QCStatements{}, fmt.Errorf("unknown qc type %q (want esign/eseal/web)", c.Type)
		}
		qc.Types = []asn1.ObjectIdentifier{oid}
	}
	for i, l := range c.PDS {
		loc, err := validatePDSLocation(l)
		if err != nil {
			return pki.QCStatements{}, fmt.Errorf("pds[%d]: %w", i, err)
		}
		qc.PDS = append(qc.PDS, loc)
	}
	if c.PSD2 != nil {
		psd2, err := buildPSD2(c.PSD2.Roles, c.PSD2.NCAName, c.PSD2.NCAID)
		if err != nil {
			return pki.QCStatements{}, err
		}
		qc.PSD2 = psd2
	}
	return qc, nil
}

// validatePDSLocation checks a single QcPDS entry: a non-empty URL and a
// two-letter ISO 639-1 language code (which QcPDS encodes as a PrintableString
// of size 2). The language is normalized to lowercase.
func validatePDSLocation(l QCPDSLocation) (pki.QCPDSLocation, error) {
	url := strings.TrimSpace(l.URL)
	if url == "" {
		return pki.QCPDSLocation{}, fmt.Errorf("url is required")
	}
	lang := strings.ToLower(strings.TrimSpace(l.Language))
	if len(lang) != 2 || !isASCIILetters(lang) {
		return pki.QCPDSLocation{}, fmt.Errorf("language %q must be a two-letter ISO 639-1 code", l.Language)
	}
	return pki.QCPDSLocation{URL: url, Language: lang}, nil
}

// buildPSD2 assembles a pki.QCPSD2 from role names and NCA fields, resolving each
// role token to its ETSI TS 119 495 OID, rejecting unknown/duplicate roles, and
// requiring the NCA name and id. It is shared by the profile default and the
// per-request override so both validate identically.
func buildPSD2(roles []string, ncaName, ncaID string) (*pki.QCPSD2, error) {
	out := &pki.QCPSD2{NCAName: strings.TrimSpace(ncaName), NCAID: strings.TrimSpace(ncaID)}
	if out.NCAName == "" {
		return nil, fmt.Errorf("psd2: nca_name is required")
	}
	if out.NCAID == "" {
		return nil, fmt.Errorf("psd2: nca_id is required")
	}
	if len(roles) == 0 {
		return nil, fmt.Errorf("psd2: at least one role is required (PSP_AS/PSP_PI/PSP_AI/PSP_IC)")
	}
	seen := make(map[string]bool, len(roles))
	for _, r := range roles {
		name := strings.ToUpper(strings.TrimSpace(r))
		oid, ok := pki.PSD2RoleOID(name)
		if !ok {
			return nil, fmt.Errorf("psd2: unknown role %q (want PSP_AS/PSP_PI/PSP_AI/PSP_IC)", r)
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out.Roles = append(out.Roles, pki.QCPSD2Role{OID: oid, Name: name})
	}
	return out, nil
}

// describeQCStatements renders a short human-readable summary of the statements
// a QC-enabled issuance would stamp, for the preview/dry-run gate verdict.
func describeQCStatements(qc pki.QCStatements) string {
	var parts []string
	if qc.Compliance {
		parts = append(parts, "QcCompliance")
	}
	if len(qc.Types) > 0 {
		parts = append(parts, "QcType="+strings.Join(pki.QCTypeNames(qc.Types), "/"))
	}
	if qc.SSCD {
		parts = append(parts, "QcSSCD")
	}
	if qc.RetentionYears > 0 {
		parts = append(parts, fmt.Sprintf("QcRetentionPeriod=%dy", qc.RetentionYears))
	}
	if len(qc.PDS) > 0 {
		parts = append(parts, fmt.Sprintf("QcPDS(%d)", len(qc.PDS)))
	}
	if qc.PSD2 != nil {
		names := make([]string, 0, len(qc.PSD2.Roles))
		for _, r := range qc.PSD2.Roles {
			names = append(names, r.Name)
		}
		parts = append(parts, fmt.Sprintf("PSD2[%s]@%s", strings.Join(names, ","), qc.PSD2.NCAID))
	}
	return "id-pe-qcStatements would be stamped: " + strings.Join(parts, ", ")
}

func isASCIILetters(s string) bool {
	for _, r := range s {
		isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		if !isLetter {
			return false
		}
	}
	return true
}

// psd2OverridePresent reports whether a per-request PSD2 override carries any
// content (so an empty struct from a decoded JSON body is treated as absent).
func psd2OverridePresent(o *models.PSD2QCStatement) bool {
	return o != nil && (len(o.Roles) > 0 || strings.TrimSpace(o.NCAName) != "" || strings.TrimSpace(o.NCAID) != "")
}

// qcStatements resolves the effective QCStatements for one issuance: the
// profile's configured statements, with the PSD2 block replaced by a per-request
// override when one is supplied and the profile permits it (allow_psd2_override).
// It returns present=false (and no error) when the profile has no QCStatements
// policy and no override was requested. A per-request override against a profile
// that is not QC-enabled, or that forbids overrides, is a hard error — a request
// must never be able to fabricate qualified/PSD2 semantics the profile did not
// grant.
func (p Profile) qcStatements(override *models.PSD2QCStatement) (pki.QCStatements, bool, error) {
	hasOverride := psd2OverridePresent(override)
	if p.QCStatements == nil {
		if hasOverride {
			return pki.QCStatements{}, false, fmt.Errorf(
				"profile %q does not enable QC statements; a per-request PSD2 authorization is not permitted", p.Name)
		}
		return pki.QCStatements{}, false, nil
	}
	qc, err := p.QCStatements.build()
	if err != nil {
		return pki.QCStatements{}, false, fmt.Errorf("profile %q qcstatements: %w", p.Name, err)
	}
	if hasOverride {
		if !p.QCStatements.AllowPSD2Override {
			return pki.QCStatements{}, false, fmt.Errorf(
				"profile %q does not allow per-request PSD2 overrides (set qcstatements.allow_psd2_override)", p.Name)
		}
		psd2, err := buildPSD2(override.Roles, override.NCAName, override.NCAID)
		if err != nil {
			return pki.QCStatements{}, false, fmt.Errorf("profile %q PSD2 override: %w", p.Name, err)
		}
		qc.PSD2 = psd2
	}
	if qc.IsZero() {
		return pki.QCStatements{}, false, nil
	}
	return qc, true, nil
}

// applyQCStatements appends the ETSI EN 319 412-5 id-pe-qcStatements extension to
// a leaf request when the profile is QC-enabled, merging any per-request PSD2
// authorization override. It never mutates the caller's extension slice. Shared
// by the classical, PQC, and hybrid issuance paths (and the preview path) so the
// extension is stamped identically regardless of algorithm; it is appended before
// linting and before the CT poison/SCT split so the lint gate sees it and the
// precertificate and final certificate carry it identically.
func applyQCStatements(base pki.LeafCertRequest, profile Profile, override *models.PSD2QCStatement) (pki.LeafCertRequest, error) {
	qc, present, err := profile.qcStatements(override)
	if err != nil {
		return base, err
	}
	if !present {
		return base, nil
	}
	ext, err := qc.Extension()
	if err != nil {
		return base, fmt.Errorf("profile %q qcstatements: %w", profile.Name, err)
	}
	base.ExtraExtensions = appendExt(base.ExtraExtensions, ext)
	return base, nil
}
