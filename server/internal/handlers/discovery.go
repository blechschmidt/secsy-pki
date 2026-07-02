package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/discovery"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// ListDiscoveredCertificates returns the external certificates recorded by the
// discovery scanner, newest first. Read-gated (any role). It is the API behind
// the console's Discovery page.
func (a *API) ListDiscoveredCertificates(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	certs, err := a.db.ListDiscoveredCertificates("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list discovered certificates: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":        len(certs),
		"certificates": certs,
	})
}

// discoveryScanRequest is the JSON body for POST /api/discovery/scan.
type discoveryScanRequest struct {
	// Targets are "host[:port][#sni]" endpoints. When empty, the server falls back
	// to the configured discovery.targets.
	Targets []string `json:"targets,omitempty"`
	CIDRs   []string `json:"cidrs,omitempty"`
	// ExpiryDays overrides the "expiring soon" window (0 uses the configured/default).
	ExpiryDays int `json:"expiry_days,omitempty"`
	// Store records the findings into the discovered-certificate inventory.
	Store bool `json:"store,omitempty"`
	// Notify dispatches flagged findings through the monitor notification sinks.
	Notify bool `json:"notify,omitempty"`
}

// RunDiscoveryScan triggers an on-demand discovery scan. Because it actively
// probes external endpoints (and may write to the inventory and fire alerts), it
// requires the org-wide issue capability rather than plain read access.
func (a *API) RunDiscoveryScan(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionIssue) {
		a.recordEvent(r, audit.ActionCertDiscover, "", "", audit.ResultDenied, "discovery scan requires issue capability")
		writeError(w, http.StatusForbidden, "discovery scan requires the issue capability (admin or issuer role)")
		return
	}

	var req discoveryScanRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
			return
		}
	}

	spec := discovery.TargetSpec{
		Endpoints:   req.Targets,
		CIDRs:       req.CIDRs,
		DefaultPort: a.discoveryCfg.DefaultPort,
	}
	if len(spec.Endpoints) == 0 && len(spec.CIDRs) == 0 {
		spec.Endpoints = a.discoveryCfg.Targets
		spec.CIDRs = a.discoveryCfg.CIDRs
		spec.HostsFile = a.discoveryCfg.HostsFile
	}
	targets, err := discovery.ParseTargets(spec)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid targets: %v", err)
		return
	}
	if len(targets) == 0 {
		writeError(w, http.StatusBadRequest, "no targets: supply targets/cidrs or configure discovery.targets")
		return
	}

	expiryDays := req.ExpiryDays
	if expiryDays == 0 {
		expiryDays = a.discoveryCfg.ExpiryDays
	}
	runner := discovery.NewRunner(a.db, a.monitorCfg, expiryDays, nil)
	if a.discoveryCfg.DialTimeoutSeconds > 0 {
		runner.WithDialTimeout(time.Duration(a.discoveryCfg.DialTimeoutSeconds) * time.Second)
	}
	if a.discoveryCfg.Concurrency > 0 {
		runner.WithConcurrency(a.discoveryCfg.Concurrency)
	}

	res, err := runner.Scan(r.Context(), targets, req.Store, req.Notify)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "discovery scan failed: %v", err)
		return
	}

	requestedBy := "discovery"
	if user != nil && user.Subject != "" {
		requestedBy = user.Subject
	}
	c := res.Report.Counts
	a.recordEvent(r, audit.ActionCertDiscover, "", "", audit.ResultSuccess,
		fmt.Sprintf("discovery scan by=%s endpoints=%d stored=%d rogue=%d expiring=%d",
			requestedBy, c.Total, res.Stored, c.Rogue, c.ExpiringSoon))

	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": res.Report.GeneratedAt,
		"expiry_days":  res.Report.ExpiryDays,
		"counts":       res.Report.Counts,
		"stored":       res.Stored,
		"findings":     res.Report.Findings,
	})
}
