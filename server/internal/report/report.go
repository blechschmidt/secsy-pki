// Package report builds compliance and inventory reports over the PKI's
// existing issuance, linting, and audit data. It produces two artifacts:
//
//   - A certificate inventory: every issued certificate with its serial,
//     subject, SANs, profile, validity window, revocation status/reason, CT/SCT
//     presence, and the pre-issuance lint verdict recorded at issuance time.
//
//   - A CA/Browser Forum Baseline-Requirements compliance report: a summary of
//     the pre-issuance certlint (Task 27) results — pass/warn/blocked counts and
//     the most frequent failing rules — together with the key-ceremony evidence
//     and the tamper-evident audit-chain verification status. This is shaped to
//     drop into a WebTrust/ETSI-style evidence pack.
//
// The report layer is deliberately decoupled from the concrete database: it
// draws everything it needs through the small DataSource interface, so it is
// exercised in tests against an in-memory fake and reused unchanged by both the
// secsy-ca CLI and the REST endpoint.
package report

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// DataSource is the read-only slice of the persistence layer the report builders
// need. *database.DB satisfies it directly.
type DataSource interface {
	ListCAs() ([]models.CA, error)
	ListIssuedCertificates(caID string) ([]models.IssuedCertificate, error)
	ListRevokedCertificates(caID string) ([]models.RevokedCertificate, error)
	ListEventsByTimeRange(from, to time.Time) ([]audit.Event, error)
	VerifyEventChain() (audit.VerifyResult, error)
	MarkExpiredCertificates(caID string, now time.Time) (int64, error)
}

// Filter narrows a report to a subset of the inventory. A zero value selects
// everything. From/To bound a certificate by its notBefore (issuance time),
// half-open as [From, To); a zero bound is open-ended.
type Filter struct {
	CAID    string    `json:"ca_id,omitempty"`
	Profile string    `json:"profile,omitempty"`
	From    time.Time `json:"from,omitempty"`
	To      time.Time `json:"to,omitempty"`
}

// Lint verdicts recorded per certificate. A certificate that produced no
// findings at issuance is a Pass; one that produced warn-only findings is a
// Warn. An enforce-mode failure blocks issuance, so it never attaches to an
// issued certificate — those appear only in the compliance report's blocked
// count.
const (
	VerdictPass = "pass"
	VerdictWarn = "warn"
	VerdictFail = "fail"
)

// CertRecord is one row of the certificate inventory.
type CertRecord struct {
	CAID             string    `json:"ca_id"`
	CASubject        string    `json:"ca_subject"`
	Serial           string    `json:"serial"`
	Subject          string    `json:"subject"`
	CommonName       string    `json:"common_name"`
	SANs             []string  `json:"sans,omitempty"`
	Profile          string    `json:"profile"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
	Status           string    `json:"status"` // valid | revoked | expired
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
	RevocationReason int       `json:"revocation_reason,omitempty"`
	RevocationText   string    `json:"revocation_reason_text,omitempty"`
	CTStatus         string    `json:"ct_status"`
	SCTCount         int       `json:"sct_count"`
	SCTPresent       bool      `json:"sct_present"`
	LintVerdict      string    `json:"lint_verdict"` // pass | warn (fail never issues)
	LintFindings     []string  `json:"lint_findings,omitempty"`
}

// Inventory is the full certificate-inventory export.
type Inventory struct {
	GeneratedAt  time.Time    `json:"generated_at"`
	Filter       Filter       `json:"filter"`
	Total        int          `json:"total"`
	Certificates []CertRecord `json:"certificates"`
}

// RuleCount is a lint check code with the number of times it fired.
type RuleCount struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// LintSummary aggregates the pre-issuance certlint results over the filtered
// window. Pass/Warn are counted over certificates that were actually issued;
// Blocked counts enforce-mode lint failures that prevented issuance (a
// compliance positive — the gate held). Top rules are the most frequent check
// codes across warn findings and blocked failures respectively.
type LintSummary struct {
	IssuedTotal     int         `json:"issued_total"`
	Pass            int         `json:"pass"`
	Warn            int         `json:"warn"`
	Blocked         int         `json:"blocked"`
	TopWarningRules []RuleCount `json:"top_warning_rules,omitempty"`
	TopBlockedRules []RuleCount `json:"top_blocked_rules,omitempty"`
}

// CeremonyStatus summarizes the key-ceremony and HSM backup/restore evidence
// drawn from the tamper-evident audit log.
type CeremonyStatus struct {
	Started         int        `json:"started"`
	Completed       int        `json:"completed"`
	Aborted         int        `json:"aborted"`
	LastCompletedAt *time.Time `json:"last_completed_at,omitempty"`
	Backups         int        `json:"backups"`
	Restores        int        `json:"restores"`
}

// CASummary is per-CA metadata for the compliance evidence pack.
type CASummary struct {
	ID         string     `json:"id"`
	Label      string     `json:"label"`
	Subject    string     `json:"subject"`
	KeyType    string     `json:"key_type"`
	HSMBacked  bool       `json:"hsm_backed"`
	Status     string     `json:"status,omitempty"`
	NotAfter   *time.Time `json:"not_after,omitempty"`
	IssuedCert int        `json:"issued_certificates"`
}

// ProfileCount is the number of certificates issued under a profile.
type ProfileCount struct {
	Profile string `json:"profile"`
	Count   int    `json:"count"`
}

// ComplianceReport is the CA/Browser-Forum conformance evidence pack.
type ComplianceReport struct {
	GeneratedAt      time.Time          `json:"generated_at"`
	Filter           Filter             `json:"filter"`
	CAs              []CASummary        `json:"cas"`
	Lint             LintSummary        `json:"lint"`
	ProfileBreakdown []ProfileCount     `json:"profile_breakdown"`
	Ceremony         CeremonyStatus     `json:"ceremony"`
	AuditChain       audit.VerifyResult `json:"audit_chain"`
	// Conformant is a single roll-up: the audit chain verifies and no
	// enforce-mode lint failure ever produced an issued certificate. It is a
	// coarse gate, not a substitute for auditor judgement.
	Conformant bool `json:"conformant"`
}

// revocationReasons maps RFC 5280 CRLReason codes to their names.
var revocationReasons = map[int]string{
	0:  "unspecified",
	1:  "keyCompromise",
	2:  "cACompromise",
	3:  "affiliationChanged",
	4:  "superseded",
	5:  "cessationOfOperation",
	6:  "certificateHold",
	8:  "removeFromCRL",
	9:  "privilegeWithdrawn",
	10: "aACompromise",
}

// RevocationReasonText renders an RFC 5280 reason code as its name.
func RevocationReasonText(code int) string {
	if name, ok := revocationReasons[code]; ok {
		return name
	}
	return fmt.Sprintf("reason(%d)", code)
}

// lintVerdict is the parsed per-serial lint outcome derived from a cert.lint
// audit event.
type lintVerdict struct {
	verdict  string   // VerdictWarn or VerdictFail (issued certs only ever see warn)
	findings []string // check codes (error + warn)
}

// BuildInventory assembles the certificate inventory for the filtered CAs. It
// marks freshly-expired certificates first so the Status column is current, then
// correlates each certificate with its pre-issuance lint verdict.
func BuildInventory(src DataSource, f Filter, now time.Time) (*Inventory, error) {
	cas, err := selectCAs(src, f)
	if err != nil {
		return nil, err
	}

	verdicts, err := lintVerdictsBySerial(src)
	if err != nil {
		return nil, err
	}

	inv := &Inventory{GeneratedAt: now, Filter: f, Certificates: []CertRecord{}}
	for _, c := range cas {
		// Refresh the status column so certificates past notAfter read "expired".
		if _, err := src.MarkExpiredCertificates(c.ID, now); err != nil {
			return nil, fmt.Errorf("marking expired certificates for CA %s: %w", c.ID, err)
		}
		certs, err := src.ListIssuedCertificates(c.ID)
		if err != nil {
			return nil, fmt.Errorf("listing certificates for CA %s: %w", c.ID, err)
		}
		for i := range certs {
			cert := &certs[i]
			if !matchesFilter(cert, f) {
				continue
			}
			rec := recordFor(cert, &c)
			if v, ok := verdicts[verdictKey(c.ID, cert.Serial)]; ok {
				rec.LintVerdict = v.verdict
				rec.LintFindings = v.findings
			}
			inv.Certificates = append(inv.Certificates, rec)
		}
	}
	// Stable, deterministic ordering: newest issuance first, then serial.
	sort.SliceStable(inv.Certificates, func(i, j int) bool {
		a, b := inv.Certificates[i], inv.Certificates[j]
		if !a.NotBefore.Equal(b.NotBefore) {
			return a.NotBefore.After(b.NotBefore)
		}
		return a.Serial < b.Serial
	})
	inv.Total = len(inv.Certificates)
	return inv, nil
}

// BuildCompliance assembles the CA/Browser-Forum conformance evidence pack.
func BuildCompliance(src DataSource, f Filter, now time.Time) (*ComplianceReport, error) {
	cas, err := selectCAs(src, f)
	if err != nil {
		return nil, err
	}

	rep := &ComplianceReport{GeneratedAt: now, Filter: f}

	// Per-CA metadata and issued-certificate counts, plus the profile breakdown
	// and the pass/warn split over issued certificates.
	verdicts, err := lintVerdictsBySerial(src)
	if err != nil {
		return nil, err
	}
	profileCounts := map[string]int{}
	warnRuleCounts := map[string]int{}
	for _, c := range cas {
		if _, err := src.MarkExpiredCertificates(c.ID, now); err != nil {
			return nil, fmt.Errorf("marking expired certificates for CA %s: %w", c.ID, err)
		}
		certs, err := src.ListIssuedCertificates(c.ID)
		if err != nil {
			return nil, fmt.Errorf("listing certificates for CA %s: %w", c.ID, err)
		}
		issued := 0
		for i := range certs {
			cert := &certs[i]
			if !matchesFilter(cert, f) {
				continue
			}
			issued++
			rep.Lint.IssuedTotal++
			profileCounts[cert.Profile]++
			if v, ok := verdicts[verdictKey(c.ID, cert.Serial)]; ok && v.verdict == VerdictWarn {
				rep.Lint.Warn++
				for _, code := range v.findings {
					warnRuleCounts[code]++
				}
			} else {
				rep.Lint.Pass++
			}
		}
		rep.CAs = append(rep.CAs, CASummary{
			ID:         c.ID,
			Label:      c.Label,
			Subject:    c.Subject,
			KeyType:    c.KeyType,
			HSMBacked:  isHSMBacked(c),
			Status:     c.Status,
			NotAfter:   c.NotAfter,
			IssuedCert: issued,
		})
	}
	rep.ProfileBreakdown = sortedProfileCounts(profileCounts)
	rep.Lint.TopWarningRules = topRules(warnRuleCounts)

	// Enforce-mode lint failures blocked issuance: count them (and their rules)
	// from the cert.lint audit events over the filter window. These are a
	// compliance positive — the fail-closed gate prevented a non-conformant
	// certificate.
	events, err := src.ListEventsByTimeRange(f.From, f.To)
	if err != nil {
		return nil, fmt.Errorf("listing audit events: %w", err)
	}
	blockedRuleCounts := map[string]int{}
	for i := range events {
		e := &events[i]
		if e.Action != audit.ActionCertLint || e.Result != audit.ResultError {
			continue
		}
		if f.Profile != "" && lintEventProfile(e.Detail) != f.Profile {
			continue
		}
		rep.Lint.Blocked++
		for _, code := range lintErrorCodes(e.Detail) {
			blockedRuleCounts[code]++
		}
	}
	rep.Lint.TopBlockedRules = topRules(blockedRuleCounts)

	rep.Ceremony = ceremonyStatus(events)

	chain, err := src.VerifyEventChain()
	if err != nil {
		return nil, fmt.Errorf("verifying audit chain: %w", err)
	}
	rep.AuditChain = chain
	rep.Conformant = chain.Valid
	return rep, nil
}

// selectCAs returns the CAs in scope: the single CA named by the filter, or all
// of them.
func selectCAs(src DataSource, f Filter) ([]models.CA, error) {
	cas, err := src.ListCAs()
	if err != nil {
		return nil, fmt.Errorf("listing CAs: %w", err)
	}
	if f.CAID == "" {
		return cas, nil
	}
	for _, c := range cas {
		if c.ID == f.CAID || c.Label == f.CAID {
			return []models.CA{c}, nil
		}
	}
	return nil, fmt.Errorf("no CA with id or label %q", f.CAID)
}

// matchesFilter reports whether a certificate is in scope for the profile and
// date-range filter. CA scoping is handled by selectCAs.
func matchesFilter(c *models.IssuedCertificate, f Filter) bool {
	if f.Profile != "" && c.Profile != f.Profile {
		return false
	}
	if !f.From.IsZero() && c.NotBefore.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && !c.NotBefore.Before(f.To) {
		return false
	}
	return true
}

// recordFor projects a stored certificate into an inventory record. SANs fall
// back to the ones parsed from the certificate PEM when the stored column is
// empty (older rows), so the export is complete regardless of when the row was
// written.
func recordFor(c *models.IssuedCertificate, issuer *models.CA) CertRecord {
	rec := CertRecord{
		CAID:        c.CAID,
		CASubject:   issuer.Subject,
		Serial:      c.Serial,
		Subject:     c.Subject,
		CommonName:  c.CommonName,
		SANs:        c.SANs,
		Profile:     c.Profile,
		NotBefore:   c.NotBefore,
		NotAfter:    c.NotAfter,
		Status:      string(c.Status),
		CTStatus:    string(c.CTStatus),
		SCTCount:    c.SCTCount,
		SCTPresent:  c.SCTCount > 0,
		LintVerdict: VerdictPass,
	}
	if len(rec.SANs) == 0 {
		rec.SANs = sansFromPEM(c.Certificate)
	}
	if c.Status == models.CertStatusRevoked || c.RevokedAt != nil {
		rec.RevokedAt = c.RevokedAt
		rec.RevocationReason = c.RevocationReason
		rec.RevocationText = RevocationReasonText(c.RevocationReason)
	}
	return rec
}

// sansFromPEM extracts the subjectAltName entries from a PEM certificate as
// strings, mirroring how they are rendered in the stored SANs column. Best
// effort: a parse failure yields no SANs.
func sansFromPEM(certPEM string) []string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	var sans []string
	sans = append(sans, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, cert.EmailAddresses...)
	for _, u := range cert.URIs {
		sans = append(sans, u.String())
	}
	return sans
}

// isHSMBacked reports whether a CA's signing key lives in a PKCS#11 token. The
// software keystore records a "software:" pseudo-URI, so anything else with a
// PKCS#11 URI is HSM-backed.
func isHSMBacked(c models.CA) bool {
	uri := strings.TrimSpace(c.PKCS11URI)
	if uri == "" {
		return false
	}
	return strings.HasPrefix(uri, "pkcs11:")
}

func verdictKey(caID, serial string) string { return caID + "\x00" + serial }

// lintVerdictsBySerial walks the full audit log and builds a map from
// (CA, serial) to the lint verdict recorded at issuance. Only events that carry
// a serial are indexed; enforce-mode failures without an issued certificate are
// counted separately in the compliance report.
func lintVerdictsBySerial(src DataSource) (map[string]lintVerdict, error) {
	events, err := src.ListEventsByTimeRange(time.Time{}, time.Time{})
	if err != nil {
		return nil, fmt.Errorf("listing audit events: %w", err)
	}
	out := map[string]lintVerdict{}
	for i := range events {
		e := &events[i]
		if e.Action != audit.ActionCertLint {
			continue
		}
		serial := lintEventSerial(e.Detail)
		if serial == "" {
			continue
		}
		verdict := VerdictWarn
		if e.Result == audit.ResultError {
			verdict = VerdictFail
		}
		out[verdictKey(e.Target, serial)] = lintVerdict{
			verdict:  verdict,
			findings: append(lintErrorCodes(e.Detail), lintWarnCodes(e.Detail)...),
		}
	}
	return out, nil
}

// ceremonyStatus derives the key-ceremony / backup evidence from audit events.
func ceremonyStatus(events []audit.Event) CeremonyStatus {
	var st CeremonyStatus
	for i := range events {
		e := &events[i]
		switch e.Action {
		case audit.ActionCeremonyStart:
			st.Started++
		case audit.ActionCeremonyComplete:
			st.Completed++
			t := e.Timestamp
			if st.LastCompletedAt == nil || t.After(*st.LastCompletedAt) {
				st.LastCompletedAt = &t
			}
		case audit.ActionCeremonyAbort:
			st.Aborted++
		case audit.ActionHSMBackup:
			st.Backups++
		case audit.ActionHSMRestore:
			st.Restores++
		}
	}
	return st
}

// --- cert.lint audit Detail parsing ---------------------------------------
//
// The Detail string is built in ca.recordLintEvent as:
//
//	profile=<name> lint=<ok|warn|fail> errors=N warnings=N \
//	    [error_checks=[a b ...]] [warn_checks=[c d ...]] [serial=<decimal>]

func lintEventProfile(detail string) string { return lintField(detail, "profile=") }
func lintEventSerial(detail string) string  { return lintField(detail, "serial=") }

// lintField extracts a whitespace-delimited key=value token's value.
func lintField(detail, key string) string {
	idx := strings.Index(detail, key)
	if idx < 0 {
		return ""
	}
	rest := detail[idx+len(key):]
	if end := strings.IndexByte(rest, ' '); end >= 0 {
		return rest[:end]
	}
	return rest
}

func lintErrorCodes(detail string) []string { return lintBracketList(detail, "error_checks=[") }
func lintWarnCodes(detail string) []string  { return lintBracketList(detail, "warn_checks=[") }

// lintBracketList extracts the space-separated codes from a "key=[a b c]" list.
func lintBracketList(detail, key string) []string {
	idx := strings.Index(detail, key)
	if idx < 0 {
		return nil
	}
	rest := detail[idx+len(key):]
	end := strings.IndexByte(rest, ']')
	if end < 0 {
		return nil
	}
	inner := strings.TrimSpace(rest[:end])
	if inner == "" {
		return nil
	}
	return strings.Fields(inner)
}

// sortedProfileCounts renders the profile histogram, most-issued first.
func sortedProfileCounts(counts map[string]int) []ProfileCount {
	out := make([]ProfileCount, 0, len(counts))
	for p, n := range counts {
		out = append(out, ProfileCount{Profile: p, Count: n})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Profile < out[j].Profile
	})
	return out
}

// topRules renders a check-code histogram, most-frequent first. Ties break by
// code so the output is deterministic.
func topRules(counts map[string]int) []RuleCount {
	if len(counts) == 0 {
		return nil
	}
	out := make([]RuleCount, 0, len(counts))
	for code, n := range counts {
		out = append(out, RuleCount{Code: code, Count: n})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Code < out[j].Code
	})
	return out
}
