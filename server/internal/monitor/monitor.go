// Package monitor implements certificate-expiry monitoring and an optional
// auto-renewal workflow for secsy-pki.
//
// The monitor scans the issuing authority's copy of every certificate it has
// minted (the issuance/revocation store), classifies each by remaining validity
// against configurable thresholds, and produces a Report. It can additionally
// reissue eligible leaf certificates ahead of expiry through the same
// HSM-backed issuance path used by the API and CLI (ca.Manager.RenewCertificate,
// which signs on the token), emitting audit events and metrics as it goes.
//
// The core Scan is pure with respect to time and side effects other than the
// optional auto-renewal: callers inject "now" (tests use a fixed clock) and the
// dependencies are small interfaces, so the logic is exercised without an HSM.
// Notification dispatch is layered on top by callers (see notify.go and the
// background Runner) so that listing endpoints can reuse the same scan without
// sending alerts.
package monitor

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Severity classifies a certificate by its remaining validity.
type Severity string

const (
	SeverityOK       Severity = "ok"       // outside every warning window
	SeverityWarning  Severity = "warning"  // within the warning window
	SeverityCritical Severity = "critical" // within the critical window
	SeverityExpired  Severity = "expired"  // NotAfter is in the past
)

// severityRank orders severities from least to most urgent so a sink's minimum
// severity filter and sorting can compare them numerically.
var severityRank = map[Severity]int{
	SeverityOK:       0,
	SeverityWarning:  1,
	SeverityCritical: 2,
	SeverityExpired:  3,
}

// atLeast reports whether s is at least as urgent as min.
func (s Severity) atLeast(min Severity) bool {
	return severityRank[s] >= severityRank[min]
}

// CertLister is the read side of the issuance/revocation store the monitor
// scans. *database.DB satisfies it.
type CertLister interface {
	ListCAs() ([]models.CA, error)
	ListIssuedCertificates(caID string) ([]models.IssuedCertificate, error)
}

// Renewer reissues a certificate through the HSM-backed issuance path.
// *ca.Manager satisfies it.
type Renewer interface {
	RenewCertificate(ctx context.Context, spec ca.RenewSpec) (*ca.IssueResult, error)
}

// AuditSink appends a tamper-evident audit event. *database.DB satisfies it.
type AuditSink interface {
	AppendEvent(e *audit.Event) error
}

// Options holds the monitor's thresholds and auto-renewal policy. They are
// resolved from config.MonitorConfig once at construction.
type Options struct {
	// Warning and Critical are the remaining-validity windows for the matching
	// severities (Critical <= Warning).
	Warning  time.Duration
	Critical time.Duration
	// RenewBefore is the remaining-validity threshold at or below which an
	// eligible certificate is auto-renewed (when a scan requests auto-renewal).
	RenewBefore time.Duration
	// RenewProfiles optionally restricts auto-renewal to these profile names.
	// Nil/empty means every profile is eligible.
	RenewProfiles []string
	// SVIDProfiles names the profiles whose certificates are SPIFFE X.509-SVIDs.
	// They are renewed aggressively on a fraction of their (short) lifetime rather
	// than the absolute, day-scale RenewBefore window, and their identity for
	// supersession is keyed on the spiffe:// URI SAN rather than the (empty)
	// subject — so every workload rotates independently.
	SVIDProfiles []string
	// SVIDRenewFraction is the fraction of an SVID's total lifetime that must
	// remain for it to still be considered fresh; at or below it, the SVID is
	// auto-renewed. E.g. 0.5 renews at the halfway point of a 1h SVID (~30m left).
	// Values outside (0,1) fall back to the default (0.5).
	SVIDRenewFraction float64
}

// defaultSVIDRenewFraction renews an SVID once half its lifetime has elapsed.
const defaultSVIDRenewFraction = 0.5

// Monitor scans issued certificates for upcoming expirations and can auto-renew
// eligible ones. It is safe for concurrent use.
type Monitor struct {
	store   CertLister
	renewer Renewer
	audit   AuditSink
	opts    Options
	logger  *log.Logger

	renewAllowed map[string]bool // resolved from Options.RenewProfiles (nil = all)
	svidProfiles map[string]bool // resolved from Options.SVIDProfiles
	svidFraction float64         // resolved from Options.SVIDRenewFraction
}

// New builds a Monitor. renewer and audit may be nil when auto-renewal is not
// used (e.g. a read-only listing scan); Scan will refuse to auto-renew without
// a renewer.
func New(store CertLister, renewer Renewer, audit AuditSink, opts Options) *Monitor {
	m := &Monitor{
		store:   store,
		renewer: renewer,
		audit:   audit,
		opts:    opts,
		logger:  log.New(os.Stderr, "", log.LstdFlags),
	}
	if len(opts.RenewProfiles) > 0 {
		m.renewAllowed = make(map[string]bool, len(opts.RenewProfiles))
		for _, p := range opts.RenewProfiles {
			m.renewAllowed[p] = true
		}
	}
	if len(opts.SVIDProfiles) > 0 {
		m.svidProfiles = make(map[string]bool, len(opts.SVIDProfiles))
		for _, p := range opts.SVIDProfiles {
			m.svidProfiles[p] = true
		}
	}
	m.svidFraction = opts.SVIDRenewFraction
	if m.svidFraction <= 0 || m.svidFraction >= 1 {
		m.svidFraction = defaultSVIDRenewFraction
	}
	return m
}

// isSVID reports whether a certificate was minted under a SPIFFE SVID profile.
func (m *Monitor) isSVID(cert models.IssuedCertificate) bool {
	return m.svidProfiles != nil && m.svidProfiles[cert.Profile]
}

// identityKey groups a certificate with earlier issuances of the same logical
// credential so a newer reissue supersedes an older one. Ordinary certificates
// are keyed on their subject; SPIFFE SVIDs carry an empty subject, so they are
// keyed on their SANs (the spiffe:// URI), letting each workload rotate
// independently.
func (m *Monitor) identityKey(cert models.IssuedCertificate) string {
	if m.isSVID(cert) {
		return identityKey(cert.CAID, "svid:"+sanSignature(cert.SANs), cert.Profile)
	}
	return identityKey(cert.CAID, cert.Subject, cert.Profile)
}

// sanSignature renders a certificate's SANs as a stable, order-independent key.
func sanSignature(sans []string) string {
	if len(sans) == 0 {
		return ""
	}
	sorted := append([]string(nil), sans...)
	sort.Strings(sorted)
	return strings.Join(sorted, "\x00")
}

// SetLogger overrides the logger used for auto-renewal diagnostics.
func (m *Monitor) SetLogger(l *log.Logger) {
	if l != nil {
		m.logger = l
	}
}

// ScanRequest parameterizes a single scan.
type ScanRequest struct {
	// CAID, when set, restricts the scan to one CA (by id). Empty scans all CAs.
	CAID string
	// Now overrides the wall clock (tests). Zero uses time.Now().
	Now time.Time
	// AutoRenew performs auto-renewal of eligible certificates. It requires the
	// Monitor to have been constructed with a Renewer.
	AutoRenew bool
	// RequestedBy is recorded on renewed certificates and audit events (defaults
	// to "monitor").
	RequestedBy string
}

// CertItem is a single certificate's status in a Report.
type CertItem struct {
	CAID       string    `json:"ca_id"`
	CALabel    string    `json:"ca_label"`
	Serial     string    `json:"serial"`
	CommonName string    `json:"common_name"`
	Subject    string    `json:"subject"`
	Profile    string    `json:"profile"`
	NotAfter   time.Time `json:"not_after"`
	// ExpiresInSeconds is the remaining validity in seconds (negative if expired).
	ExpiresInSeconds int64    `json:"expires_in_seconds"`
	ExpiresIn        string   `json:"expires_in"` // human-readable, e.g. "12d" or "expired"
	Severity         Severity `json:"severity"`
	// Superseded is set when a newer, non-revoked certificate for the same
	// identity (CA + subject + profile) already exists — the monitor neither
	// warns nor auto-renews on such stale duplicates.
	Superseded bool `json:"superseded,omitempty"`
	// Renewed, NewSerial and RenewError describe the outcome of an auto-renewal
	// attempt for this item during the scan.
	Renewed    bool   `json:"renewed,omitempty"`
	NewSerial  string `json:"new_serial,omitempty"`
	RenewError string `json:"renew_error,omitempty"`
}

// Report is the outcome of a scan.
type Report struct {
	GeneratedAt  time.Time `json:"generated_at"`
	WarningDays  int       `json:"warning_days"`
	CriticalDays int       `json:"critical_days"`
	// Counts is the number of items at each severity (ok is omitted from
	// notifications but included here for completeness).
	Counts map[Severity]int `json:"counts"`
	// Renewed is the number of certificates auto-renewed during this scan.
	Renewed int `json:"renewed"`
	// RenewFailed is the number of auto-renewal attempts that failed.
	RenewFailed int `json:"renew_failed"`
	// Items lists every non-revoked certificate scanned, sorted by remaining
	// validity ascending (most urgent first).
	Items []CertItem `json:"items"`
}

// Warnings returns the items at or above the given minimum severity, preserving
// the report's most-urgent-first order and skipping superseded duplicates.
func (r *Report) Warnings(min Severity) []CertItem {
	var out []CertItem
	for _, it := range r.Items {
		if it.Superseded {
			continue
		}
		if it.Severity.atLeast(min) {
			out = append(out, it)
		}
	}
	return out
}

// identityKey groups certificates that represent the same logical credential so
// a newer reissue supersedes an older one.
func identityKey(caID, subject, profile string) string {
	return caID + "\x00" + subject + "\x00" + profile
}

// Scan classifies every non-revoked issued certificate by remaining validity
// and, when requested, auto-renews eligible ones. It never returns partial
// state: a store error aborts the scan.
func (m *Monitor) Scan(ctx context.Context, req ScanRequest) (*Report, error) {
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	requestedBy := req.RequestedBy
	if requestedBy == "" {
		requestedBy = "monitor"
	}

	cas, err := m.store.ListCAs()
	if err != nil {
		return nil, fmt.Errorf("listing CAs: %w", err)
	}
	labelByID := make(map[string]string, len(cas))
	for _, c := range cas {
		labelByID[c.ID] = c.Label
	}

	// Collect the certificates to consider, and the latest non-revoked NotAfter
	// per identity so we can flag superseded duplicates.
	type entry struct {
		cert models.IssuedCertificate
	}
	var entries []entry
	latestByIdentity := make(map[string]time.Time)

	for _, c := range cas {
		if req.CAID != "" && c.ID != req.CAID {
			continue
		}
		certs, err := m.store.ListIssuedCertificates(c.ID)
		if err != nil {
			return nil, fmt.Errorf("listing certificates for CA %s: %w", c.ID, err)
		}
		for _, cert := range certs {
			// Revoked certificates are neither warned on nor renewed: renewing a
			// revoked credential would silently resurrect it (ca.Manager also
			// refuses this as defense-in-depth).
			if cert.Status == models.CertStatusRevoked {
				continue
			}
			// Synthetic issuance-canary certificates (Task 71) are deliberately
			// short-lived probe artifacts. Without this exclusion every probe
			// would immediately land in the critical/expired buckets and — worse
			// — the auto-renewal storm logic would keep reissuing them forever.
			if cert.Marker == models.CertMarkerCanary {
				continue
			}
			entries = append(entries, entry{cert: cert})
			key := m.identityKey(cert)
			if cur, ok := latestByIdentity[key]; !ok || cert.NotAfter.After(cur) {
				latestByIdentity[key] = cert.NotAfter
			}
		}
	}

	report := &Report{
		GeneratedAt:  now,
		WarningDays:  int(m.opts.Warning / (24 * time.Hour)),
		CriticalDays: int(m.opts.Critical / (24 * time.Hour)),
		Counts:       map[Severity]int{},
		Items:        make([]CertItem, 0, len(entries)),
	}

	for _, e := range entries {
		cert := e.cert
		remaining := cert.NotAfter.Sub(now)
		sev := m.classify(remaining)

		key := m.identityKey(cert)
		superseded := latestByIdentity[key].After(cert.NotAfter)

		item := CertItem{
			CAID:             cert.CAID,
			CALabel:          labelByID[cert.CAID],
			Serial:           cert.Serial,
			CommonName:       cert.CommonName,
			Subject:          cert.Subject,
			Profile:          cert.Profile,
			NotAfter:         cert.NotAfter,
			ExpiresInSeconds: int64(remaining / time.Second),
			ExpiresIn:        humanizeRemaining(remaining),
			Severity:         sev,
			Superseded:       superseded,
		}

		if !superseded {
			report.Counts[sev]++
		}

		if req.AutoRenew && !superseded && m.eligibleForRenewal(cert, remaining) {
			m.autoRenew(ctx, &item, cert, requestedBy)
			if item.Renewed {
				report.Renewed++
			} else if item.RenewError != "" {
				report.RenewFailed++
			}
		}

		report.Items = append(report.Items, item)
	}

	// Most urgent first: least remaining validity at the top.
	sort.SliceStable(report.Items, func(i, j int) bool {
		return report.Items[i].ExpiresInSeconds < report.Items[j].ExpiresInSeconds
	})

	// Refresh the expiry gauges from this scan's counts.
	metrics.CertsExpiring.Set(float64(report.Counts[SeverityWarning]), string(SeverityWarning))
	metrics.CertsExpiring.Set(float64(report.Counts[SeverityCritical]), string(SeverityCritical))
	metrics.CertsExpiring.Set(float64(report.Counts[SeverityExpired]), string(SeverityExpired))
	metrics.MonitorScans.Inc(metrics.ResultSuccess)
	metrics.MonitorLastScan.Set(float64(time.Now().Unix()))

	return report, nil
}

// classify maps a remaining validity to a severity.
func (m *Monitor) classify(remaining time.Duration) Severity {
	switch {
	case remaining <= 0:
		return SeverityExpired
	case remaining <= m.opts.Critical:
		return SeverityCritical
	case remaining <= m.opts.Warning:
		return SeverityWarning
	default:
		return SeverityOK
	}
}

// eligibleForRenewal reports whether a certificate should be auto-renewed.
// Ordinary certificates renew once inside the absolute RenewBefore window.
// SPIFFE SVIDs are short-lived, so an absolute day-scale window would either
// never fire (window shorter than the whole lifetime) or fire continuously
// (window longer than the lifetime); they instead renew once a fixed fraction of
// their own lifetime has elapsed. Revocation and supersession are checked by the
// caller.
func (m *Monitor) eligibleForRenewal(cert models.IssuedCertificate, remaining time.Duration) bool {
	if m.renewAllowed != nil && !m.renewAllowed[cert.Profile] {
		return false
	}
	if m.isSVID(cert) {
		lifetime := cert.NotAfter.Sub(cert.NotBefore)
		if lifetime <= 0 {
			return remaining <= 0
		}
		return remaining <= time.Duration(float64(lifetime)*m.svidFraction)
	}
	return remaining <= m.opts.RenewBefore
}

// autoRenew reissues one certificate through the HSM-backed path and records the
// outcome on the item, in metrics, and in the audit log. It never returns an
// error: a failure is recorded and the scan continues with the next cert.
func (m *Monitor) autoRenew(ctx context.Context, item *CertItem, cert models.IssuedCertificate, requestedBy string) {
	if m.renewer == nil {
		item.RenewError = "auto-renew requested but no renewer configured"
		return
	}
	// Validity 0 uses the profile default, so the reissued certificate is
	// long-lived and no longer near expiry — on the next scan the old serial is
	// superseded and will not be renewed again (no renewal storm).
	res, err := m.renewer.RenewCertificate(ctx, ca.RenewSpec{
		CAID:        cert.CAID,
		Serial:      cert.Serial,
		Validity:    0,
		RequestedBy: requestedBy,
	})
	metrics.RecordAutoRenew(err)
	if err != nil {
		item.RenewError = err.Error()
		m.logger.Printf("monitor: auto-renew of serial %s (CN=%q) failed: %v", cert.Serial, cert.CommonName, err)
		m.recordAudit(&audit.Event{
			Action:     audit.ActionCertAutoRenew,
			Actor:      requestedBy,
			ActorRoles: "system",
			Target:     cert.Serial,
			TargetName: cert.CommonName,
			Result:     audit.ResultError,
			Detail:     "ca=" + cert.CAID + " error=" + err.Error(),
		})
		return
	}
	item.Renewed = true
	item.NewSerial = res.Serial.String()
	m.logger.Printf("monitor: auto-renewed serial %s -> %s (CN=%q) not_after=%s",
		cert.Serial, item.NewSerial, cert.CommonName, res.Certificate.NotAfter.Format(time.RFC3339))
	m.recordAudit(&audit.Event{
		Action:     audit.ActionCertAutoRenew,
		Actor:      requestedBy,
		ActorRoles: "system",
		Target:     res.Serial.String(),
		TargetName: cert.CommonName,
		Result:     audit.ResultSuccess,
		Detail:     fmt.Sprintf("ca=%s renewed_from=%s profile=%s not_after=%s", cert.CAID, cert.Serial, cert.Profile, res.Certificate.NotAfter.Format(time.RFC3339)),
	})
}

// recordAudit appends an event, filling the ID and tolerating a nil sink (used
// by read-only scans) and storage failures (best-effort, like the API path).
func (m *Monitor) recordAudit(e *audit.Event) {
	if m.audit == nil {
		return
	}
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if err := m.audit.AppendEvent(e); err != nil {
		m.logger.Printf("monitor: WARNING: failed to append audit event %q: %v", e.Action, err)
	}
}

// humanizeRemaining renders a remaining validity compactly for humans.
func humanizeRemaining(d time.Duration) string {
	if d <= 0 {
		return "expired"
	}
	days := int(d / (24 * time.Hour))
	if days >= 2 {
		return fmt.Sprintf("%dd", days)
	}
	hours := int(d / time.Hour)
	if hours >= 1 {
		return fmt.Sprintf("%dh", hours)
	}
	mins := int(d / time.Minute)
	return fmt.Sprintf("%dm", mins)
}

// OptionsFromDays builds Options from day-based configuration values.
func OptionsFromDays(warningDays, criticalDays, renewBeforeDays int, renewProfiles []string) Options {
	day := 24 * time.Hour
	return Options{
		Warning:       time.Duration(warningDays) * day,
		Critical:      time.Duration(criticalDays) * day,
		RenewBefore:   time.Duration(renewBeforeDays) * day,
		RenewProfiles: renewProfiles,
	}
}

// ParseSeverity converts a config/CLI severity string to a Severity, defaulting
// to warning for the empty string.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "warning":
		return SeverityWarning, nil
	case "critical":
		return SeverityCritical, nil
	case "expired":
		return SeverityExpired, nil
	case "ok":
		return SeverityOK, nil
	default:
		return "", fmt.Errorf("invalid severity %q (valid: warning, critical, expired)", s)
	}
}
