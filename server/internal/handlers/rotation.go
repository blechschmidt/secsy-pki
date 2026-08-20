package handlers

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
)

// Intermediate-CA key-rotation endpoints (Task 24 brought the capability to the
// CLI; these expose the same lifecycle over REST so the operator console has
// feature parity). Rotation and retirement are ca:manage operations gated
// behind WebAuthn step-up like the other CA-ceremony routes.

// RotateCARequest parameterizes POST /api/ca/{id}/rotate. All fields are
// optional: an empty new_label derives one from the old CA's label, an empty
// key_type reuses the old key's algorithm, and zero validity_days reuses the
// old certificate's original validity span.
type RotateCARequest struct {
	NewLabel     string `json:"new_label,omitempty"`
	KeyType      string `json:"key_type,omitempty"`
	ValidityDays int    `json:"validity_days,omitempty"`
}

// RotateCAResponse is the outcome of a rotation: the superseded and the fresh
// intermediate, the combined overlap chain relying parties should install, and
// the earliest safe retirement time for the old key.
type RotateCAResponse struct {
	OldCA            *models.CA `json:"old_ca"`
	NewCA            *models.CA `json:"new_ca"`
	CombinedChainPEM string     `json:"combined_chain_pem"`
	RetireAfter      *time.Time `json:"retire_after,omitempty"`
}

// RetireCARequest parameterizes POST /api/ca/{id}/retire.
type RetireCARequest struct {
	// Reason is the RFC 5280 revocation reason applied to the retired
	// intermediate certificate; empty defaults to cessationOfOperation.
	Reason string `json:"reason,omitempty"`
	// Force retires even while leaves signed by the old key are still valid
	// (emergency key-compromise response; breaks those leaves' chains).
	Force bool `json:"force,omitempty"`
}

// RetireCAResponse is the outcome of retiring a superseded intermediate.
type RetireCAResponse struct {
	RetiredCA         *models.CA `json:"retired_ca"`
	ParentID          string     `json:"parent_id"`
	RevokedSerial     string     `json:"revoked_serial"`
	CRLPEM            string     `json:"crl_pem,omitempty"`
	OutstandingLeaves int        `json:"outstanding_leaves"`
}

// authorizeCARotation loads the tenant of CA {id} and checks the caller may
// administer that specific CA — via ca:manage in its tenant or a resource grant
// on the CA itself (Task 191) — writing the error response on failure. It
// returns the tenant id and whether the caller may proceed.
func (a *API) authorizeCARotation(w http.ResponseWriter, r *http.Request, caID, action string) (string, bool) {
	return a.authorizeCAManage(w, r, caID, action)
}

// RotateIntermediateCA performs an HSM-backed signing-key rollover of an
// intermediate CA: a fresh key is generated inside the provider and certified
// under the same parent with the same subject DN, the old CA is marked
// superseded, and both keys overlap until the old one's leaves have drained.
func (a *API) RotateIntermediateCA(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	tenantID, ok := a.authorizeCARotation(w, r, caID, audit.ActionCARotate)
	if !ok {
		return
	}
	// A suspended tenant cannot grow its CA hierarchy (rotation mints a new key
	// and certificate), matching intermediate issuance.
	if _, err := a.requireActiveTenant(tenantID); err != nil {
		if writeTenantLimitError(w, err) {
			return
		}
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}

	var req RotateCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	// Four-eyes gate (Task 81): a CA key rotation cannot execute until the
	// configured number of distinct approvers sign off.
	if !a.guard(w, r, approval.ClassCARotate, "ca:"+caID, caID,
		"Rotate intermediate CA "+caID,
		fmt.Sprintf("ca=%s;new_label=%s;key_type=%s;validity_days=%d", caID, req.NewLabel, req.KeyType, req.ValidityDays),
		"") {
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	a.consumeHSMAuditLogs("")
	result, err := mgr.RotateIntermediate(r.Context(), ca.RotateSpec{
		CAID:        caID,
		NewLabel:    req.NewLabel,
		KeyType:     req.KeyType,
		Validity:    daysToDuration(req.ValidityDays),
		RequestedBy: user.Subject,
	})
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, audit.ActionCARotate, caID, "", audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to rotate intermediate: %v", err)
		return
	}

	a.recordEvent(r, audit.ActionCARotate, caID, result.NewCA.Label, audit.ResultSuccess,
		"old="+result.OldCA.ID+" new="+result.NewCA.ID)
	writeJSON(w, http.StatusCreated, RotateCAResponse{
		OldCA:            result.OldCA,
		NewCA:            result.NewCA,
		CombinedChainPEM: string(result.CombinedChainPEM),
		RetireAfter:      result.RetireAfter,
	})
}

// RetireIntermediateCA decommissions a superseded intermediate after the
// overlap window: its certificate is revoked under the parent (refusing while
// leaves are outstanding unless force is set) and the parent CRL is refreshed.
// Retirement remains possible on a suspended tenant, like revocation.
func (a *API) RetireIntermediateCA(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	if _, ok := a.authorizeCARotation(w, r, caID, audit.ActionCARetire); !ok {
		return
	}

	var req RetireCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	// Four-eyes gate (Task 81): retiring a superseded intermediate cannot execute
	// until the configured number of distinct approvers sign off.
	if !a.guard(w, r, approval.ClassCARetire, "ca:"+caID, caID,
		"Retire superseded intermediate CA "+caID,
		fmt.Sprintf("ca=%s;reason=%s;force=%v", caID, req.Reason, req.Force),
		"") {
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	a.consumeHSMAuditLogs("")
	result, err := mgr.RetireIntermediate(r.Context(), ca.RetireSpec{
		CAID:        caID,
		Force:       req.Force,
		Reason:      req.Reason,
		RequestedBy: user.Subject,
	})
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, audit.ActionCARetire, caID, "", audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to retire intermediate: %v", err)
		return
	}

	crlPEM := ""
	if len(result.CRLDER) > 0 {
		crlPEM = string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: result.CRLDER}))
	}
	a.recordEvent(r, audit.ActionCARetire, result.RetiredCA.ID, result.RetiredCA.Label, audit.ResultSuccess,
		"revoked_serial="+result.RevokedSerial+" reason="+req.Reason)
	writeJSON(w, http.StatusOK, RetireCAResponse{
		RetiredCA:         result.RetiredCA,
		ParentID:          result.ParentID,
		RevokedSerial:     result.RevokedSerial,
		CRLPEM:            crlPEM,
		OutstandingLeaves: result.OutstandingLeaves,
	})
}

// GetRotationStatus reports the rollover state of CA {id}: its lineage
// (predecessor/successor), outstanding leaves signed by its key, and whether a
// superseded key can be retired now.
func (a *API) GetRotationStatus(w http.ResponseWriter, r *http.Request) {
	caRec, ok := a.authorizeCARead(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	mgr := ca.NewManager(a.db, a.keyProvider)
	status, err := mgr.RotationStatus(caRec.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "rotation status failed: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// ListRotations lists every CA the caller can see that participates in a
// key-rotation lineage (superseded, retired, or linked to a predecessor or
// successor), with each one's retirement readiness.
func (a *API) ListRotations(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.canRead(user) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	// Same visibility rule as ListCAs: platform principals see all tenants,
	// tenant-scoped principals only their own.
	var cas []models.CA
	var err error
	if user.IsRoot || len(user.Roles) > 0 {
		cas, err = a.db.ListCAs()
	} else {
		for _, tid := range user.TenantsWithRoles() {
			ts, terr := a.db.ListCAsForTenant(tid)
			if terr != nil {
				err = terr
				break
			}
			cas = append(cas, ts...)
		}
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list CAs: %v", err)
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	rotations := []*ca.RotationStatus{}
	for i := range cas {
		c := &cas[i]
		inLineage := c.PredecessorID != nil || c.SuccessorID != nil ||
			(c.Status != "" && c.Status != models.CAStatusActive)
		if !inLineage {
			continue
		}
		status, serr := mgr.RotationStatus(c.ID)
		if serr != nil {
			// A single broken lineage entry must not hide the rest.
			continue
		}
		rotations = append(rotations, status)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"rotations": rotations})
}
