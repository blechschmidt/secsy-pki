package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// newMonitor builds a Monitor wired to the database (as store + audit sink) and
// a fresh ca.Manager (as renewer), using the centrally-configured thresholds.
func (a *API) newMonitor() *monitor.Monitor {
	return monitor.New(a.db, ca.NewManager(a.db, a.keyProvider), a.db, a.monitorOpts)
}

// ListExpiringCertificates reports issued certificates by remaining validity.
// Read-gated (any role). Query parameters:
//
//	ca=<id>                restrict to one CA
//	days=<n>               only certs expiring within n days (and already expired)
//	severity=warning|critical|expired  only certs at or above this severity
//	include_superseded=true  include stale duplicates superseded by a newer cert
//
// It never auto-renews.
func (a *API) ListExpiringCertificates(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}

	q := r.URL.Query()
	minSeverity := monitor.Severity("")
	if s := q.Get("severity"); s != "" {
		parsed, err := monitor.ParseSeverity(s)
		if err != nil {
			writeError(w, http.StatusBadRequest, "%v", err)
			return
		}
		minSeverity = parsed
	}
	var withinDays int
	if v := q.Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "days must be a non-negative integer")
			return
		}
		withinDays = n
	}
	includeSuperseded := q.Get("include_superseded") == "true"

	report, err := a.newMonitor().Scan(r.Context(), monitor.ScanRequest{CAID: q.Get("ca")})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "expiry scan failed: %v", err)
		return
	}

	items := report.Items
	filtered := make([]monitor.CertItem, 0, len(items))
	cutoff := time.Duration(withinDays) * 24 * time.Hour
	for _, it := range items {
		if it.Superseded && !includeSuperseded {
			continue
		}
		if minSeverity != "" && !severityAtLeast(it.Severity, minSeverity) {
			continue
		}
		if q.Get("days") != "" && time.Duration(it.ExpiresInSeconds)*time.Second > cutoff {
			continue
		}
		filtered = append(filtered, it)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at":  report.GeneratedAt,
		"warning_days":  report.WarningDays,
		"critical_days": report.CriticalDays,
		"counts":        report.Counts,
		"total":         len(filtered),
		"certificates":  filtered,
	})
}

// monitorScanRequest is the JSON body for POST /api/monitor/scan.
type monitorScanRequest struct {
	CAID      string `json:"ca_id,omitempty"`
	AutoRenew bool   `json:"auto_renew,omitempty"`
}

// RunExpiryScan triggers an on-demand scan. A plain scan (auto_renew=false) is
// read-gated; requesting auto_renew requires the org-wide issue capability
// (admin or issuer) because it reissues certificates on the HSM.
func (a *API) RunExpiryScan(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())

	var req monitorScanRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
			return
		}
	}

	if req.AutoRenew {
		if !a.can(user, rbac.ActionIssue) {
			a.recordEvent(r, audit.ActionCertAutoRenew, req.CAID, "", audit.ResultDenied, "auto-renew scan requires issue capability")
			writeError(w, http.StatusForbidden, "auto-renew requires the issue capability (admin or issuer role)")
			return
		}
	} else if !a.canRead(user) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}

	requestedBy := "monitor"
	if user != nil && user.Subject != "" {
		requestedBy = user.Subject
	}

	a.consumeHSMAuditLogs("")
	report, err := a.newMonitor().Scan(r.Context(), monitor.ScanRequest{
		CAID:        req.CAID,
		AutoRenew:   req.AutoRenew,
		RequestedBy: requestedBy,
	})
	a.consumeHSMAuditLogs("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "expiry scan failed: %v", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": report.GeneratedAt,
		"counts":       report.Counts,
		"renewed":      report.Renewed,
		"renew_failed": report.RenewFailed,
		"total":        len(report.Items),
		"certificates": report.Items,
	})
}

// severityAtLeast reports whether s is at least as urgent as min. It mirrors the
// unexported ordering in the monitor package.
func severityAtLeast(s, min monitor.Severity) bool {
	rank := map[monitor.Severity]int{
		monitor.SeverityOK:       0,
		monitor.SeverityWarning:  1,
		monitor.SeverityCritical: 2,
		monitor.SeverityExpired:  3,
	}
	return rank[s] >= rank[min]
}
