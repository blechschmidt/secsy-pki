package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// Default certificate lifetimes when a request omits validity_days.
const (
	defaultRootValidityDays         = 3650 // ~10 years
	defaultIntermediateValidityDays = 1825 // ~5 years
)

// InitRootCA generates a root CA key inside the key provider (HSM) and creates a
// self-signed root CA certificate signed on the device.
func (a *API) InitRootCA(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageCA) {
		a.recordEvent(r, audit.ActionCAInitRoot, "", "", audit.ResultDenied, "ca:manage capability required")
		writeError(w, http.StatusForbidden, "ca:manage capability required (admin role)")
		return
	}

	var req models.CAInitRootRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = defaultRootValidityDays
	}

	mgr := ca.NewManager(a.db, a.keyProvider)

	// Consume pending HSM audit logs to free device buffer space around the
	// key-generation and signing operations, mirroring the sign paths.
	a.consumeHSMAuditLogs("")
	result, err := mgr.InitRoot(r.Context(), ca.RootSpec{
		Label:      req.Label,
		KeyType:    req.KeyType,
		Subject:    ca.PKIXName(req.Subject),
		Validity:   time.Duration(validityDays) * 24 * time.Hour,
		MaxPathLen: req.MaxPathLen,
	})
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, audit.ActionCAInitRoot, "", req.Label, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to initialize root CA: %v", err)
		return
	}

	a.recordEvent(r, audit.ActionCAInitRoot, result.ID, result.Label, audit.ResultSuccess, "subject="+result.Subject)
	writeJSON(w, http.StatusCreated, result)
}

// IssueIntermediateCA generates an intermediate CA key inside the key provider
// and issues an intermediate certificate signed by the parent CA on the device.
func (a *API) IssueIntermediateCA(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionManageCA) {
		a.recordEvent(r, audit.ActionCAIssueIntermediate, r.PathValue("id"), "", audit.ResultDenied, "ca:manage capability required")
		writeError(w, http.StatusForbidden, "ca:manage capability required (admin role)")
		return
	}

	parentID := r.PathValue("id")

	var req models.CAIssueIntermediateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = defaultIntermediateValidityDays
	}

	mgr := ca.NewManager(a.db, a.keyProvider)

	a.consumeHSMAuditLogs("")
	result, err := mgr.IssueIntermediate(r.Context(), ca.IntermediateSpec{
		ParentID:   parentID,
		Label:      req.Label,
		KeyType:    req.KeyType,
		Subject:    ca.PKIXName(req.Subject),
		Validity:   time.Duration(validityDays) * 24 * time.Hour,
		MaxPathLen: req.MaxPathLen,
	})
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, audit.ActionCAIssueIntermediate, parentID, req.Label, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to issue intermediate CA: %v", err)
		return
	}

	a.recordEvent(r, audit.ActionCAIssueIntermediate, result.ID, result.Label, audit.ResultSuccess, "parent="+parentID)
	writeJSON(w, http.StatusCreated, result)
}
