package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/certpolicy"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/nameconstraints"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// buildCAConstraints translates the optional Name Constraints and
// certificate-policy request payloads into the built types the CA manager
// consumes. A nil payload yields a zero-value (empty) result, so callers can pass
// the result unconditionally.
func buildCAConstraints(ncCfg *nameconstraints.Config, polCfg *certpolicy.PolicyConfig) (nameconstraints.Constraints, certpolicy.Policies, error) {
	var nc nameconstraints.Constraints
	var pol certpolicy.Policies
	if ncCfg != nil {
		var err error
		if nc, err = ncCfg.Build(); err != nil {
			return nc, pol, err
		}
	}
	if polCfg != nil {
		var err error
		if pol, err = polCfg.Build(); err != nil {
			return nc, pol, err
		}
	}
	return nc, pol, nil
}

// Default certificate lifetimes when a request omits validity_days.
const (
	defaultRootValidityDays         = 3650 // ~10 years
	defaultIntermediateValidityDays = 1825 // ~5 years
)

// InitRootCA generates a root CA key inside the key provider (HSM) and creates a
// self-signed root CA certificate signed on the device.
func (a *API) InitRootCA(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())

	var req models.CAInitRootRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	middleware.SetTenant(r.Context(), tenantID)
	// The tenant must exist and be active (a suspended tenant cannot grow its
	// CA hierarchy), and the caller must hold ca:manage WITHIN it. A tenant
	// admin can only create CAs in its own tenant.
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
		a.recordEvent(r, audit.ActionCAInitRoot, "", "", audit.ResultDenied, "ca:manage capability required")
		writeError(w, http.StatusForbidden, "ca:manage capability required for tenant %q", tenantID)
		return
	}

	validityDays := req.ValidityDays
	if validityDays <= 0 {
		validityDays = defaultRootValidityDays
	}

	mgr := ca.NewManager(a.db, a.keyProvider)

	// Consume pending HSM audit logs to free device buffer space around the
	// key-generation and signing operations, mirroring the sign paths.
	nc, pol, err := buildCAConstraints(req.NameConstraints, req.Policies)
	if err != nil {
		a.recordEvent(r, audit.ActionCAInitRoot, "", req.Label, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "invalid CA constraints/policies: %v", err)
		return
	}

	a.consumeHSMAuditLogs("")
	result, err := mgr.InitRoot(r.Context(), ca.RootSpec{
		TenantID:        tenantID,
		Label:           req.Label,
		KeyType:         req.KeyType,
		Subject:         ca.PKIXName(req.Subject),
		Validity:        time.Duration(validityDays) * 24 * time.Hour,
		MaxPathLen:      req.MaxPathLen,
		NameConstraints: nc,
		Policies:        pol,
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
	parentID := r.PathValue("id")

	// The intermediate inherits the parent's tenant; the caller must be able to
	// administer the PARENT — through ca:manage in that tenant or a resource grant
	// on the parent CA (Task 191). Authority over the parent is what authorizes
	// growing the hierarchy beneath it.
	tenantID, ok := a.authorizeCAManage(w, r, parentID, audit.ActionCAIssueIntermediate)
	if !ok {
		return
	}
	// A suspended tenant cannot grow its CA hierarchy (its existing CAs keep
	// serving OCSP/CRL for already-issued certificates).
	if _, err := a.requireActiveTenant(tenantID); err != nil {
		if writeTenantLimitError(w, err) { // suspension → 403
			return
		}
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}

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

	nc, pol, err := buildCAConstraints(req.NameConstraints, req.Policies)
	if err != nil {
		a.recordEvent(r, audit.ActionCAIssueIntermediate, parentID, req.Label, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "invalid CA constraints/policies: %v", err)
		return
	}

	a.consumeHSMAuditLogs("")
	result, err := mgr.IssueIntermediate(r.Context(), ca.IntermediateSpec{
		ParentID:        parentID,
		Label:           req.Label,
		KeyType:         req.KeyType,
		Subject:         ca.PKIXName(req.Subject),
		Validity:        time.Duration(validityDays) * 24 * time.Hour,
		MaxPathLen:      req.MaxPathLen,
		NameConstraints: nc,
		Policies:        pol,
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
