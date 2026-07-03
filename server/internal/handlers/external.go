package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// Externally-signed subordinate CA endpoints (Task 69): prepare an HSM-backed
// CA key + PKCS#10 CSR for an external parent (offline corporate root or
// third-party bridge), and later validate/install the certificate that parent
// signed. The mutating endpoints are step-up gated like the other CA lifecycle
// operations.

// CreateExternalCACSR generates a subordinate-CA key inside the key provider
// and returns a PKCS#10 CSR (CA basicConstraints/keyUsage attributes) for
// signature by an external parent. The CA is persisted in the "pending" state
// until the signed certificate is imported.
func (a *API) CreateExternalCACSR(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())

	var req models.CAExternalCSRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	middleware.SetTenant(r.Context(), tenantID)
	// Same gate as init-root: the tenant must exist and be active, and the
	// caller must hold ca:manage within it.
	if t, err := a.requireActiveTenant(tenantID); err != nil {
		if writeTenantLimitError(w, err) { // suspension → 403
			return
		}
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	} else if t == nil {
		writeError(w, http.StatusBadRequest, "unknown tenant %q", tenantID)
		return
	}
	if !a.canInTenant(user, tenantID, rbac.ActionManageCA) {
		a.recordEvent(r, audit.ActionCACSR, "", req.Label, audit.ResultDenied, "ca:manage capability required")
		writeError(w, http.StatusForbidden, "ca:manage capability required for tenant %q", tenantID)
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	a.consumeHSMAuditLogs("")
	result, err := mgr.GenerateExternalCACSR(r.Context(), ca.ExternalCACSRSpec{
		TenantID:   tenantID,
		Label:      req.Label,
		KeyType:    req.KeyType,
		Subject:    ca.PKIXName(req.Subject),
		MaxPathLen: req.MaxPathLen,
	})
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, audit.ActionCACSR, "", req.Label, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to generate CA CSR: %v", err)
		return
	}

	a.recordEvent(r, audit.ActionCACSR, result.CA.ID, result.CA.Label, audit.ResultSuccess,
		"subject="+result.CA.Subject+" key_type="+result.CA.KeyType)
	writeJSON(w, http.StatusCreated, models.CAExternalCSRResponse{
		CA:     result.CA,
		CSRPEM: string(result.CSRPEM),
	})
}

// GetExternalCACSR re-emits the stored PKCS#10 CSR for CA {id}, so an operator
// can re-download it while the external signing ceremony is in flight (or for
// an external renewal of the same key).
func (a *API) GetExternalCACSR(w http.ResponseWriter, r *http.Request) {
	caRec, ok := a.authorizeCARead(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	mgr := ca.NewManager(a.db, a.keyProvider)
	csrPEM, err := mgr.ExternalCACSR(caRec.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "%v", err)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", caRec.Label+".csr.pem"))
	w.Write(csrPEM)
}

// ImportExternalCACert validates and installs the externally signed certificate
// for pending CA {id}: the certificate's public key must match the HSM-backed
// key, it must be a currently valid CA certificate, and — when a chain is
// supplied — it must verify against the external chain, which is then served
// via /api/ca/{id}/chain.
func (a *API) ImportExternalCACert(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	tenantID, err := a.db.GetCATenant(caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "CA lookup failed: %v", err)
		return
	}
	if tenantID == "" {
		writeError(w, http.StatusNotFound, "CA %q not found", caID)
		return
	}
	middleware.SetTenant(r.Context(), tenantID)
	if !a.canInTenant(user, tenantID, rbac.ActionManageCA) {
		a.recordEvent(r, audit.ActionCAImportCert, caID, "", audit.ResultDenied, "ca:manage capability required")
		writeError(w, http.StatusForbidden, "ca:manage capability required for tenant %q", tenantID)
		return
	}
	// A suspended tenant cannot activate new issuing capacity.
	if _, err := a.requireActiveTenant(tenantID); err != nil {
		if writeTenantLimitError(w, err) { // suspension → 403
			return
		}
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}

	var req models.CAImportCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if strings.TrimSpace(req.CertificatePEM) == "" {
		writeError(w, http.StatusBadRequest, "certificate_pem is required")
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	a.consumeHSMAuditLogs("")
	result, err := mgr.ImportExternalCACertificate(r.Context(), ca.ImportExternalCACertSpec{
		CAID:           caID,
		CertificatePEM: []byte(req.CertificatePEM),
		ChainPEM:       []byte(req.ChainPEM),
		Replace:        req.Replace,
	})
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, audit.ActionCAImportCert, caID, "", audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to import CA certificate: %v", err)
		return
	}

	detail := "subject=" + result.CA.Subject + " serial=" + result.CA.Serial
	if len(result.Warnings) > 0 {
		detail += " warnings=" + strings.Join(result.Warnings, "; ")
	}
	a.recordEvent(r, audit.ActionCAImportCert, result.CA.ID, result.CA.Label, audit.ResultSuccess, detail)
	writeJSON(w, http.StatusOK, models.CAImportCertResponse{
		CA:       result.CA,
		Warnings: result.Warnings,
		ChainPEM: string(result.ChainPEM),
	})
}
