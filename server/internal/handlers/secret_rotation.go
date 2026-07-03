package handlers

// Secret-layer KEK rotation, DEK re-wrap, and the stored-secret registry
// (Task 63). The rotation lifecycle (rotate/rewrap/retire/status) is key
// management: it requires the secret:rotate capability (admin-only by
// default), is audited (secret.kek_rotate / secret.rewrap / secret.kek_retire),
// and rotate/retire sit behind the WebAuthn step-up gate like CA rotation.
// The stored-secret registry gives envelopes a server-side home so a fleet
// re-wrap is enumerable; it stores only ciphertext envelopes, never plaintext.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// refreshKEKGauges updates the per-family rotation gauges after an operation
// that changed the rotation posture. Failures only log-worthy — the expiry
// monitor refreshes the same gauges on every tick.
func (a *API) refreshKEKGauges() {
	_, _ = secret.RefreshKEKMetrics(a.db, a.secretKEKLabel)
}

// SecretKEKStatus reports a family's rotation posture: lineage, statuses, and
// how many stored secrets still sit on each version.
//
//	GET /api/secret/kek/status
func (a *API) SecretKEKStatus(w http.ResponseWriter, r *http.Request) {
	tenant, family, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	if !a.canInTenant(middleware.GetUserInfo(r.Context()), tenant.ID, rbac.ActionRotateKEK) {
		writeError(w, http.StatusForbidden, "secret:rotate capability required for tenant %q", tenant.ID)
		return
	}
	status, err := secret.BuildKEKStatus(a.db, family)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "KEK status unavailable: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

type rotateKEKRequest struct {
	// KeyType is the RSA type for the new wrapping key (rsa-2048 or rsa-4096;
	// empty defaults to rsa-4096).
	KeyType string `json:"key_type,omitempty"`
}

// RotateSecretKEK generates the family's next versioned wrapping key in the
// HSM and makes it active, opening the dual-KEK decrypt window. Existing
// envelopes keep decrypting under the superseded (now retiring) version until
// re-wrapped.
//
//	POST /api/secret/kek/rotate
func (a *API) RotateSecretKEK(w http.ResponseWriter, r *http.Request) {
	tenant, family, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	if !a.canInTenant(middleware.GetUserInfo(r.Context()), tenant.ID, rbac.ActionRotateKEK) {
		a.recordEvent(r, audit.ActionSecretKEKRotate, family, "", audit.ResultDenied, "secret:rotate capability required")
		writeError(w, http.StatusForbidden, "secret:rotate capability required for tenant %q", tenant.ID)
		return
	}
	var req rotateKEKRequest
	if r.ContentLength != 0 {
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
			return
		}
	}

	a.consumeHSMAuditLogs("")
	res, err := secret.RotateKEK(r.Context(), a.keyProvider, a.db, family, req.KeyType)
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, audit.ActionSecretKEKRotate, family, "", audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "KEK rotation failed: %v", err)
		return
	}
	a.recordEvent(r, audit.ActionSecretKEKRotate, family, res.NewLabel, audit.ResultSuccess,
		fmt.Sprintf("old_version=%d old_label=%s new_version=%d new_label=%s adopted=%v",
			res.OldVersion, res.OldLabel, res.NewVersion, res.NewLabel, res.Adopted))
	a.refreshKEKGauges()
	writeJSON(w, http.StatusOK, res)
}

type retireKEKRequest struct {
	// Version is the superseded KEK version to withdraw from service.
	Version int `json:"version"`
	// Force retires the version even while stored secrets are still wrapped
	// under it (they become undecryptable until the version is reinstated).
	Force bool `json:"force,omitempty"`
}

// RetireSecretKEK withdraws a superseded KEK version: decryption (and
// re-wrap) under it is refused from then on. Fail-closed guard: refused while
// stored secrets still sit on the version, unless force is set.
//
//	POST /api/secret/kek/retire
func (a *API) RetireSecretKEK(w http.ResponseWriter, r *http.Request) {
	tenant, family, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	if !a.canInTenant(middleware.GetUserInfo(r.Context()), tenant.ID, rbac.ActionRotateKEK) {
		a.recordEvent(r, audit.ActionSecretKEKRetire, family, "", audit.ResultDenied, "secret:rotate capability required")
		writeError(w, http.StatusForbidden, "secret:rotate capability required for tenant %q", tenant.ID)
		return
	}
	var req retireKEKRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Version < 1 {
		writeError(w, http.StatusBadRequest, "version is required")
		return
	}

	retired, err := secret.RetireKEK(a.db, family, req.Version, req.Force)
	if err != nil {
		a.recordEvent(r, audit.ActionSecretKEKRetire, family, "", audit.ResultError, err.Error())
		// The retire guard and lifecycle refusals are client errors (the
		// operator asked for something the state forbids), not server faults.
		writeError(w, http.StatusConflict, "%v", err)
		return
	}
	a.recordEvent(r, audit.ActionSecretKEKRetire, family, retired.Label, audit.ResultSuccess,
		fmt.Sprintf("version=%d label=%s force=%v", retired.Version, retired.Label, req.Force))
	a.refreshKEKGauges()
	writeJSON(w, http.StatusOK, retired)
}

type rewrapRequest struct {
	// All selects every stored secret of the family not yet on the active KEK.
	All bool `json:"all,omitempty"`
	// IDs selects specific stored secrets (mutually exclusive with All).
	IDs []string `json:"ids,omitempty"`
}

// RewrapSecrets migrates stored secrets onto the family's active KEK version:
// each secret's data key is unwrapped on the HSM under its old KEK and
// re-wrapped under the active one; data ciphertext and escrow shares are
// untouched, and no plaintext or key material is ever returned.
//
//	POST /api/secret/rewrap
func (a *API) RewrapSecrets(w http.ResponseWriter, r *http.Request) {
	tenant, family, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	if !a.canInTenant(middleware.GetUserInfo(r.Context()), tenant.ID, rbac.ActionRotateKEK) {
		a.recordEvent(r, audit.ActionSecretRewrap, family, "", audit.ResultDenied, "secret:rotate capability required")
		writeError(w, http.StatusForbidden, "secret:rotate capability required for tenant %q", tenant.ID)
		return
	}
	var req rewrapRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.All == (len(req.IDs) > 0) {
		writeError(w, http.StatusBadRequest, "select either all=true or a non-empty ids list")
		return
	}

	ring, err := a.secretRing(r, family)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "secret service unavailable: %v", err)
		return
	}
	var ids []string // nil = fleet
	if len(req.IDs) > 0 {
		ids = req.IDs
	}

	a.consumeHSMAuditLogs("")
	report, err := secret.RewrapStoredSecrets(r.Context(), ring, a.db, ids)
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, audit.ActionSecretRewrap, family, "", audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "re-wrap failed: %v", err)
		return
	}
	result := audit.ResultSuccess
	if report.Failed > 0 {
		result = audit.ResultError
	}
	a.recordEvent(r, audit.ActionSecretRewrap, family, ring.ActiveLabel(), result,
		fmt.Sprintf("total=%d rewrapped=%d skipped=%d conflicts=%d failed=%d to_version=%d",
			report.Total, report.Rewrapped, report.Skipped, report.Conflicts, report.Failed, report.ActiveVersion))
	a.refreshKEKGauges()
	writeJSON(w, http.StatusOK, report)
}

// --- stored-secret registry --------------------------------------------------

// storeSecretRequest encrypts and persists a named secret in one step. The
// plaintext is sealed exactly like /api/secret/encrypt; only the resulting
// envelope is stored.
type storeSecretRequest struct {
	Name      string `json:"name"`
	Plaintext string `json:"plaintext"`         // base64
	Context   string `json:"context,omitempty"` // base64, optional (not stored)
	Escrow    bool   `json:"escrow,omitempty"`
}

// storedSecretResponse is the metadata view of a stored secret (list/create);
// the envelope itself is included only by GetStoredSecret.
type storedSecretResponse struct {
	ID           string          `json:"id"`
	Name         string          `json:"name"`
	TenantID     string          `json:"tenant_id"`
	KEKFamily    string          `json:"kek_family"`
	KEKLabel     string          `json:"kek_label"`
	KEKVersion   int             `json:"kek_version"`
	ContextBound bool            `json:"context_bound,omitempty"`
	Escrowed     bool            `json:"escrowed,omitempty"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
	Envelope     json.RawMessage `json:"envelope,omitempty"`
}

func storedSecretView(s *models.StoredSecret, withEnvelope bool) storedSecretResponse {
	out := storedSecretResponse{
		ID:           s.ID,
		Name:         s.Name,
		TenantID:     s.TenantID,
		KEKFamily:    s.KEKFamily,
		KEKLabel:     s.KEKLabel,
		KEKVersion:   s.KEKVersion,
		ContextBound: s.ContextBound,
		Escrowed:     s.Escrowed,
		CreatedAt:    s.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:    s.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
	if withEnvelope {
		out.Envelope = json.RawMessage(s.Envelope)
	}
	return out
}

// StoreSecret encrypts a plaintext and persists the envelope under a
// tenant-scoped name.
//
//	POST /api/secret/store
func (a *API) StoreSecret(w http.ResponseWriter, r *http.Request) {
	tenant, family, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	if !a.canInTenant(middleware.GetUserInfo(r.Context()), tenant.ID, rbac.ActionEncrypt) {
		metrics.Envelope.Inc("encrypt", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionSecretStore, family, "", audit.ResultDenied, "secret:encrypt capability required")
		writeError(w, http.StatusForbidden, "secret:encrypt capability required for tenant %q", tenant.ID)
		return
	}

	var req storeSecretRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSecretPlaintext*2)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 256 {
		writeError(w, http.StatusBadRequest, "name is required (at most 256 characters)")
		return
	}
	plaintext, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		writeError(w, http.StatusBadRequest, "plaintext must be base64: %v", err)
		return
	}
	if len(plaintext) == 0 {
		writeError(w, http.StatusBadRequest, "plaintext is required")
		return
	}
	if len(plaintext) > maxSecretPlaintext {
		writeError(w, http.StatusRequestEntityTooLarge, "plaintext exceeds %d bytes", maxSecretPlaintext)
		return
	}
	defer zeroBytes(plaintext)
	var context []byte
	if req.Context != "" {
		if context, err = base64.StdEncoding.DecodeString(req.Context); err != nil {
			writeError(w, http.StatusBadRequest, "context must be base64: %v", err)
			return
		}
	}
	var escrowPolicy *secret.EscrowPolicy
	if req.Escrow {
		if !a.escrowConfigured() {
			writeError(w, http.StatusBadRequest, "key escrow requested but secret.escrow is not configured")
			return
		}
		if escrowPolicy, err = a.escrowPolicyFor(r); err != nil {
			writeError(w, http.StatusInternalServerError, "escrow policy unavailable: %v", err)
			return
		}
	}
	if existing, err := a.db.GetStoredSecretByName(tenant.ID, req.Name); err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	} else if existing != nil {
		writeError(w, http.StatusConflict, "a stored secret named %q already exists in tenant %q", req.Name, tenant.ID)
		return
	}

	ring, err := a.secretRing(r, family)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "secret service unavailable: %v", err)
		return
	}
	quotaDone, err := a.consumeSecretOpQuota(r, tenant, "encrypt")
	if err != nil {
		metrics.Envelope.Inc("encrypt", metrics.ResultDenied)
		if writeTenantLimitError(w, err) {
			return
		}
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}

	a.consumeHSMAuditLogs("")
	blob, err := ring.EncryptWithEscrowToJSON(plaintext, context, escrowPolicy)
	a.consumeHSMAuditLogs("")
	quotaDone(err)
	metrics.RecordEnvelope("encrypt", err)
	if err != nil {
		a.recordEvent(r, audit.ActionSecretStore, family, req.Name, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "encryption failed: %v", err)
		return
	}

	stored := &models.StoredSecret{
		ID:           uuid.New().String(),
		TenantID:     tenant.ID,
		Name:         req.Name,
		Envelope:     string(blob),
		KEKFamily:    family,
		KEKLabel:     ring.ActiveLabel(),
		KEKVersion:   ring.ActiveVersion(),
		ContextBound: len(context) > 0,
		Escrowed:     escrowPolicy != nil,
	}
	if err := a.db.CreateStoredSecret(stored); err != nil {
		a.recordEvent(r, audit.ActionSecretStore, family, req.Name, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "storing secret failed: %v", err)
		return
	}
	a.recordEvent(r, audit.ActionSecretEncrypt, family, "", audit.ResultSuccess, "")
	if escrowPolicy != nil {
		detail := fmt.Sprintf("threshold=%d agents=%d", escrowPolicy.Threshold(), len(escrowPolicy.Agents()))
		a.recordEvent(r, audit.ActionSecretEscrow, family, "", audit.ResultSuccess, detail)
	}
	a.recordEvent(r, audit.ActionSecretStore, family, req.Name, audit.ResultSuccess,
		fmt.Sprintf("id=%s kek_label=%s kek_version=%d escrow=%v", stored.ID, stored.KEKLabel, stored.KEKVersion, stored.Escrowed))
	writeJSON(w, http.StatusCreated, storedSecretView(stored, false))
}

// ListStoredSecrets returns the tenant's stored-secret metadata (no envelopes).
//
//	GET /api/secret/store
func (a *API) ListStoredSecrets(w http.ResponseWriter, r *http.Request) {
	tenant, _, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	if !a.canInTenant(middleware.GetUserInfo(r.Context()), tenant.ID, rbac.ActionDecrypt) {
		writeError(w, http.StatusForbidden, "secret:decrypt capability required for tenant %q", tenant.ID)
		return
	}
	secrets, err := a.db.ListStoredSecrets(tenant.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	out := make([]storedSecretResponse, 0, len(secrets))
	for i := range secrets {
		out = append(out, storedSecretView(&secrets[i], false))
	}
	writeJSON(w, http.StatusOK, map[string]any{"secrets": out})
}

// getTenantStoredSecret loads a stored secret and enforces that it belongs to
// the request's tenant; cross-tenant IDs are indistinguishable from absent.
func (a *API) getTenantStoredSecret(r *http.Request, tenantID string) (*models.StoredSecret, error) {
	s, err := a.db.GetStoredSecret(r.PathValue("id"))
	if err != nil {
		return nil, err
	}
	if s == nil || s.TenantID != tenantID {
		return nil, nil
	}
	return s, nil
}

// GetStoredSecret returns one stored secret including its envelope (which is
// ciphertext; decrypting it still requires the HSM-held KEK).
//
//	GET /api/secret/store/{id}
func (a *API) GetStoredSecret(w http.ResponseWriter, r *http.Request) {
	tenant, _, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	if !a.canInTenant(middleware.GetUserInfo(r.Context()), tenant.ID, rbac.ActionDecrypt) {
		writeError(w, http.StatusForbidden, "secret:decrypt capability required for tenant %q", tenant.ID)
		return
	}
	s, err := a.getTenantStoredSecret(r, tenant.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if s == nil {
		writeError(w, http.StatusNotFound, "no such stored secret")
		return
	}
	writeJSON(w, http.StatusOK, storedSecretView(s, true))
}

// DeleteStoredSecret removes a stored secret (the ciphertext envelope; this
// does not shred any copies the caller exported).
//
//	DELETE /api/secret/store/{id}
func (a *API) DeleteStoredSecret(w http.ResponseWriter, r *http.Request) {
	tenant, family, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	if !a.canInTenant(middleware.GetUserInfo(r.Context()), tenant.ID, rbac.ActionEncrypt) {
		a.recordEvent(r, audit.ActionSecretStoreDelete, family, "", audit.ResultDenied, "secret:encrypt capability required")
		writeError(w, http.StatusForbidden, "secret:encrypt capability required for tenant %q", tenant.ID)
		return
	}
	s, err := a.getTenantStoredSecret(r, tenant.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if s == nil {
		writeError(w, http.StatusNotFound, "no such stored secret")
		return
	}
	if _, err := a.db.DeleteStoredSecret(s.ID); err != nil {
		a.recordEvent(r, audit.ActionSecretStoreDelete, family, s.Name, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	a.recordEvent(r, audit.ActionSecretStoreDelete, family, s.Name, audit.ResultSuccess, "id="+s.ID)
	w.WriteHeader(http.StatusNoContent)
}
