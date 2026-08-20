package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/hsmaudit"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// hsmAuditManaged reports whether the HSM audit subsystem (Task 167) owns the
// device log, in which case the legacy per-request drain must stand down.
//
// The answer is cached rather than queried per request: this sits on the
// issuance hot path, and a database round-trip per signed certificate to answer
// a question that changes once in a device's lifetime would be a poor trade.
// Once true it stays true — a pinned anchor is never unpinned, only erased by a
// deliberate factory reset plus a database wipe. While false the state is
// re-read at most once every 30 seconds, so a server that was already running
// when an operator provisioned the device stands down on its own rather than
// needing a restart.
func (a *API) hsmAuditManaged() bool {
	if a.hsmAuditOn.Load() {
		return true
	}
	last := a.hsmAuditCheckedAt.Load()
	now := time.Now().UnixNano()
	if last != 0 && time.Duration(now-last) < 30*time.Second {
		return false
	}
	// CAS so concurrent requests do not all issue the same query; a loser simply
	// reports "not managed" and re-checks on a later request.
	if !a.hsmAuditCheckedAt.CompareAndSwap(last, now) {
		return false
	}
	st, err := a.db.LoadAuditState(context.Background())
	if err != nil || st == nil {
		return false
	}
	a.hsmAuditOn.Store(true)
	return true
}

// HSMAuditStatus reports the audit subsystem's state without changing anything
// (Task 190: the read-only half of `secsy-ca hsm-audit status`, so an operator
// can watch the device log being accounted for without a host shell).
//
// It is gated on audit:read for the same reason the bundle below is: checking
// that the ledger and the device still agree is an auditor's job, and the
// reconciliation counts here are exactly the signal that goes quiet first when
// collection breaks.
//
// Unlike the bundle this answers before provisioning too. "Not provisioned" is
// the single most important thing this endpoint can say, and reporting it as a
// 404 would leave a client unable to tell an uncommissioned device apart from a
// server that has no HSM at all.
func (a *API) HSMAuditStatus(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionReadAudit) {
		writeError(w, http.StatusForbidden, "audit:read capability required (admin or auditor role)")
		return
	}

	svc := hsmaudit.NewService(hsmaudit.NewHardwareDevice(a.hsmCfg), a.db)
	st, err := svc.Status(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reading HSM audit status: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// ExportHSMAuditBundle serves the self-contained, remotely verifiable audit
// bundle (Task 167).
//
// This is the transport half of remote verification: an auditor pulls the
// bundle over HTTP and checks it with `secsy-ca hsm-audit verify`, which needs
// no database, no HSM and no network. Nothing here is trusted by that verifier
// — every digest is re-derived and the genesis anchor is compared against the
// one the auditor recorded at commissioning — so serving it is disclosure of
// evidence, not an assertion the auditor has to take on faith.
//
// It is gated on audit:read rather than hsm:manage: reading the evidence is an
// auditor's job, and requiring the capability that administers the device would
// mean only the audited party could obtain it.
func (a *API) ExportHSMAuditBundle(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionReadAudit) {
		writeError(w, http.StatusForbidden, "audit:read capability required (admin or auditor role)")
		return
	}
	if !a.hsmAuditManaged() {
		writeError(w, http.StatusNotFound,
			"HSM audit subsystem is not provisioned: run 'secsy-ca hsm-audit provision' on a factory-reset device")
		return
	}

	svc := hsmaudit.NewService(hsmaudit.NewHardwareDevice(a.hsmCfg), a.db)
	bundle, err := svc.Export(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "exporting HSM audit bundle: %v", err)
		return
	}

	// The fingerprint travels in a header so an auditor can pin the exact bytes
	// they were served — and later show that a bundle claiming to extend this one
	// really extends what they saw, rather than a re-serialization adjusted after
	// the fact.
	if fp, err := bundle.Fingerprint(); err == nil {
		w.Header().Set("X-Bundle-Fingerprint", fp)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="hsm-audit-bundle.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(bundle); err != nil {
		return // response already partially written
	}
}
