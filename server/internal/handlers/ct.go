package handlers

import (
	"net/http"
	"strconv"

	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// ListSCTInclusion returns the Certificate Transparency SCT inclusion-proof
// verification state recorded by the inclusion monitor (Task 93): a status
// summary plus a page of per-SCT rows. Read-gated (any role). Query parameters:
//
//	?status=  filter rows to one state (included|pending|failed|unknown_log)
//	?limit=   maximum rows (default 200, capped at 1000)
//	?ca=+?serial=  the per-log rows of a single certificate (both required together)
//
// It is the API behind the console's CT-inclusion surface; "failed" rows are the
// mis-issuance / log-misbehavior signal.
func (a *API) ListSCTInclusion(w http.ResponseWriter, r *http.Request) {
	if !a.canRead(middleware.GetUserInfo(r.Context())) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}

	counts, err := a.db.CountSCTInclusionByStatus()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read inclusion counts: %v", err)
		return
	}

	q := r.URL.Query()
	caID := q.Get("ca")
	serial := q.Get("serial")

	var rows []models.SCTInclusion
	switch {
	case caID != "" && serial != "":
		// Resolve the CA reference (id or label) so the console/API can pass either.
		resolved, ok := a.resolveCAForRead(w, r, caID)
		if !ok {
			return
		}
		rows, err = a.db.ListSCTInclusionForCert(resolved, serial)
	case caID != "" || serial != "":
		writeError(w, http.StatusBadRequest, "ca and serial must be provided together")
		return
	default:
		status := q.Get("status")
		if status != "" && !validInclusionStatus(status) {
			writeError(w, http.StatusBadRequest, "invalid status %q (want included|pending|failed|unknown_log)", status)
			return
		}
		limit := 200
		if v := q.Get("limit"); v != "" {
			n, convErr := strconv.Atoi(v)
			if convErr != nil || n < 0 {
				writeError(w, http.StatusBadRequest, "invalid limit %q", v)
				return
			}
			limit = n
		}
		if limit == 0 || limit > 1000 {
			limit = 1000
		}
		rows, err = a.db.ListSCTInclusionByStatus(status, limit)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list SCT inclusion state: %v", err)
		return
	}
	if rows == nil {
		rows = []models.SCTInclusion{}
	}

	total := 0
	for _, n := range counts {
		total += n
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"counts": counts,
		"total":  total,
		"items":  rows,
	})
}

// resolveCAForRead resolves a CA id-or-label and enforces read authorization on
// it, writing the error response itself when resolution or authorization fails.
func (a *API) resolveCAForRead(w http.ResponseWriter, r *http.Request, ref string) (string, bool) {
	ca, ok := a.authorizeCARead(w, r, ref)
	if !ok {
		return "", false
	}
	return ca.ID, true
}

// validInclusionStatus reports whether s is one of the recorded SCT inclusion
// states.
func validInclusionStatus(s string) bool {
	switch s {
	case models.SCTInclusionIncluded, models.SCTInclusionPending,
		models.SCTInclusionFailed, models.SCTInclusionUnknownLog:
		return true
	default:
		return false
	}
}
