package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
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
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can initialize a root CA")
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
		writeError(w, http.StatusBadRequest, "failed to initialize root CA: %v", err)
		return
	}

	writeJSON(w, http.StatusCreated, result)
}

// IssueIntermediateCA generates an intermediate CA key inside the key provider
// and issues an intermediate certificate signed by the parent CA on the device.
func (a *API) IssueIntermediateCA(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can issue an intermediate CA")
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
		writeError(w, http.StatusBadRequest, "failed to issue intermediate CA: %v", err)
		return
	}

	writeJSON(w, http.StatusCreated, result)
}
