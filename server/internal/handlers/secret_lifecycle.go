package handlers

// Stored-secret value lifecycle (Task 73): version history, rollback, and the
// TTL/rotation lifecycle report. Every put appends a new version (the history
// is append-only ciphertext; plaintext is never stored), rollback re-activates
// an older version by appending a copy of it, and the lifecycle report is the
// on-demand view of what the monitor's reminder scan would flag. All routes
// are tenant-scoped through the same X-Secsy-Tenant resolution as the rest of
// the secret API; reads require secret:decrypt, mutations secret:encrypt.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/monitor"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// putSecretRequest carries a value update for an existing stored secret. The
// plaintext is sealed under the family's active KEK exactly like a create.
// TTLDays/RotateEveryDays are tri-state via pointers: absent keeps the stored
// schedule, 0 clears it, > 0 sets it.
type putSecretRequest struct {
	Plaintext       string `json:"plaintext"`         // base64
	Context         string `json:"context,omitempty"` // base64, optional (not stored)
	Escrow          bool   `json:"escrow,omitempty"`
	TTLDays         *int   `json:"ttl_days,omitempty"`
	RotateEveryDays *int   `json:"rotate_every_days,omitempty"`
	Comment         string `json:"comment,omitempty"`
	// ExpectVersion optionally makes the put conditional on the secret still
	// being at this version (compare-and-swap for external orchestrators).
	// Zero means "latest".
	ExpectVersion int `json:"expect_version,omitempty"`
}

// PutStoredSecret writes a new value version of an existing stored secret.
//
//	PUT /api/secret/store/{id}
func (a *API) PutStoredSecret(w http.ResponseWriter, r *http.Request) {
	tenant, family, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	if !a.canInTenant(middleware.GetUserInfo(r.Context()), tenant.ID, rbac.ActionEncrypt) {
		metrics.SecretStoreOps.Inc("put", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionSecretPut, family, "", audit.ResultDenied, "secret:encrypt capability required")
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

	var req putSecretRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSecretPlaintext*2)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
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
	if (req.TTLDays != nil && *req.TTLDays < 0) || (req.RotateEveryDays != nil && *req.RotateEveryDays < 0) {
		writeError(w, http.StatusBadRequest, "ttl_days and rotate_every_days must be >= 0")
		return
	}
	if req.ExpectVersion != 0 && req.ExpectVersion != s.CurrentVersion {
		writeError(w, http.StatusConflict, "stored secret is at version %d, not %d", s.CurrentVersion, req.ExpectVersion)
		return
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
		metrics.SecretStoreOps.Inc("put", metrics.ResultError)
		a.recordEvent(r, audit.ActionSecretPut, family, s.Name, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "encryption failed: %v", err)
		return
	}

	put := &database.PutSecretVersion{
		ID:            s.ID,
		Envelope:      string(blob),
		KEKFamily:     family,
		KEKLabel:      ring.ActiveLabel(),
		KEKVersion:    ring.ActiveVersion(),
		ContextBound:  len(context) > 0,
		Escrowed:      escrowPolicy != nil,
		CreatedBy:     requestActor(r),
		Comment:       req.Comment,
		ExpectVersion: s.CurrentVersion,
	}
	if req.TTLDays != nil {
		put.SetExpiresAt = true
		if *req.TTLDays > 0 {
			exp := time.Now().UTC().AddDate(0, 0, *req.TTLDays)
			put.ExpiresAt = &exp
		}
	}
	if req.RotateEveryDays != nil {
		put.SetRotateEveryDays = true
		put.RotateEveryDays = *req.RotateEveryDays
	}
	updated, err := a.db.PutStoredSecretVersion(put)
	if err != nil {
		if err == database.ErrSecretVersionConflict {
			metrics.SecretStoreOps.Inc("put", metrics.ResultError)
			a.recordEvent(r, audit.ActionSecretPut, family, s.Name, audit.ResultError, "concurrent update")
			writeError(w, http.StatusConflict, "stored secret was modified concurrently; retry")
			return
		}
		metrics.SecretStoreOps.Inc("put", metrics.ResultError)
		a.recordEvent(r, audit.ActionSecretPut, family, s.Name, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "storing new version failed: %v", err)
		return
	}
	metrics.SecretStoreOps.Inc("put", metrics.ResultSuccess)
	a.recordEvent(r, audit.ActionSecretEncrypt, family, "", audit.ResultSuccess, "")
	a.recordEvent(r, audit.ActionSecretPut, family, s.Name, audit.ResultSuccess,
		fmt.Sprintf("id=%s version=%d kek_label=%s kek_version=%d escrow=%v",
			s.ID, updated.CurrentVersion, updated.KEKLabel, updated.KEKVersion, updated.Escrowed))
	writeJSON(w, http.StatusOK, storedSecretView(updated, false))
}

// secretVersionResponse is one value-history entry; Envelope only on the
// point read.
type secretVersionResponse struct {
	SecretID     string          `json:"secret_id"`
	Version      int             `json:"version"`
	Current      bool            `json:"current"`
	KEKFamily    string          `json:"kek_family"`
	KEKLabel     string          `json:"kek_label"`
	KEKVersion   int             `json:"kek_version"`
	ContextBound bool            `json:"context_bound,omitempty"`
	Escrowed     bool            `json:"escrowed,omitempty"`
	CreatedBy    string          `json:"created_by,omitempty"`
	Comment      string          `json:"comment,omitempty"`
	CreatedAt    string          `json:"created_at"`
	Envelope     json.RawMessage `json:"envelope,omitempty"`
}

func secretVersionView(v *models.StoredSecretVersion, current int, withEnvelope bool) secretVersionResponse {
	out := secretVersionResponse{
		SecretID:     v.SecretID,
		Version:      v.Version,
		Current:      v.Version == current,
		KEKFamily:    v.KEKFamily,
		KEKLabel:     v.KEKLabel,
		KEKVersion:   v.KEKVersion,
		ContextBound: v.ContextBound,
		Escrowed:     v.Escrowed,
		CreatedBy:    v.CreatedBy,
		Comment:      v.Comment,
		CreatedAt:    v.CreatedAt.UTC().Format(time.RFC3339),
	}
	if withEnvelope {
		out.Envelope = json.RawMessage(v.Envelope)
	}
	return out
}

// ListStoredSecretVersions returns a secret's value history, newest first
// (metadata only).
//
//	GET /api/secret/store/{id}/versions
func (a *API) ListStoredSecretVersions(w http.ResponseWriter, r *http.Request) {
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
	versions, err := a.db.ListStoredSecretVersions(s.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	out := make([]secretVersionResponse, 0, len(versions))
	for i := range versions {
		out = append(out, secretVersionView(&versions[i], s.CurrentVersion, false))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret_id":       s.ID,
		"name":            s.Name,
		"current_version": s.CurrentVersion,
		"versions":        out,
	})
}

// GetStoredSecretVersion returns one history entry including its ciphertext
// envelope (decrypting it still requires the HSM-held KEK, via
// /api/secret/decrypt).
//
//	GET /api/secret/store/{id}/versions/{version}
func (a *API) GetStoredSecretVersion(w http.ResponseWriter, r *http.Request) {
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
	version, err := strconv.Atoi(r.PathValue("version"))
	if err != nil || version < 1 {
		writeError(w, http.StatusBadRequest, "version must be a positive integer")
		return
	}
	v, err := a.db.GetStoredSecretVersion(s.ID, version)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if v == nil {
		writeError(w, http.StatusNotFound, "stored secret has no version %d", version)
		return
	}
	writeJSON(w, http.StatusOK, secretVersionView(v, s.CurrentVersion, true))
}

type rollbackSecretRequest struct {
	// Version is the history entry whose value becomes current again.
	Version int    `json:"version"`
	Comment string `json:"comment,omitempty"`
}

// RollbackStoredSecret re-activates an older value: the target version's
// envelope is appended as the new current version (history is never
// rewritten). No plaintext is handled — the ciphertext is copied verbatim —
// so a rollback works even without the HSM, but it is refused when the target
// envelope sits on a retired KEK version (it would be undecryptable).
//
//	POST /api/secret/store/{id}/rollback
func (a *API) RollbackStoredSecret(w http.ResponseWriter, r *http.Request) {
	tenant, family, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	if !a.canInTenant(middleware.GetUserInfo(r.Context()), tenant.ID, rbac.ActionEncrypt) {
		metrics.SecretStoreOps.Inc("rollback", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionSecretRollback, family, "", audit.ResultDenied, "secret:encrypt capability required")
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
	var req rollbackSecretRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Version < 1 {
		writeError(w, http.StatusBadRequest, "version is required")
		return
	}
	if req.Version == s.CurrentVersion {
		writeError(w, http.StatusConflict, "version %d is already current", req.Version)
		return
	}
	v, err := a.db.GetStoredSecretVersion(s.ID, req.Version)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if v == nil {
		writeError(w, http.StatusNotFound, "stored secret has no version %d", req.Version)
		return
	}
	// Fail-closed: never make an undecryptable envelope the current value.
	if err := a.checkKEKNotRetired(v.KEKFamily, v.KEKLabel); err != nil {
		metrics.SecretStoreOps.Inc("rollback", metrics.ResultError)
		a.recordEvent(r, audit.ActionSecretRollback, family, s.Name, audit.ResultError, err.Error())
		writeError(w, http.StatusConflict, "%v", err)
		return
	}

	comment := req.Comment
	if comment == "" {
		comment = fmt.Sprintf("rollback to version %d", req.Version)
	}
	updated, err := a.db.PutStoredSecretVersion(&database.PutSecretVersion{
		ID:            s.ID,
		Envelope:      v.Envelope,
		KEKFamily:     v.KEKFamily,
		KEKLabel:      v.KEKLabel,
		KEKVersion:    v.KEKVersion,
		ContextBound:  v.ContextBound,
		Escrowed:      v.Escrowed,
		CreatedBy:     requestActor(r),
		Comment:       comment,
		ExpectVersion: s.CurrentVersion,
	})
	if err != nil {
		if err == database.ErrSecretVersionConflict {
			metrics.SecretStoreOps.Inc("rollback", metrics.ResultError)
			a.recordEvent(r, audit.ActionSecretRollback, family, s.Name, audit.ResultError, "concurrent update")
			writeError(w, http.StatusConflict, "stored secret was modified concurrently; retry")
			return
		}
		metrics.SecretStoreOps.Inc("rollback", metrics.ResultError)
		a.recordEvent(r, audit.ActionSecretRollback, family, s.Name, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "rollback failed: %v", err)
		return
	}
	metrics.SecretStoreOps.Inc("rollback", metrics.ResultSuccess)
	a.recordEvent(r, audit.ActionSecretRollback, family, s.Name, audit.ResultSuccess,
		fmt.Sprintf("id=%s from_version=%d new_version=%d", s.ID, req.Version, updated.CurrentVersion))
	writeJSON(w, http.StatusOK, storedSecretView(updated, false))
}

// checkKEKNotRetired refuses envelopes wrapped under a retired KEK version.
// A label outside the recorded lineage is allowed (never-rotated families
// have no rows; their base KEK is implicitly active).
func (a *API) checkKEKNotRetired(family, label string) error {
	versions, err := a.db.ListKEKVersions(family)
	if err != nil {
		return fmt.Errorf("reading KEK rotation state: %w", err)
	}
	for _, v := range versions {
		if v.Label == label && v.Status == models.KEKStatusRetired {
			return fmt.Errorf("version is wrapped under RETIRED KEK %q (version %d of family %q) and cannot be made current; reinstate the KEK version first", label, v.Version, family)
		}
	}
	return nil
}

// SecretLifecycleReport returns the tenant's stored secrets currently due for
// TTL or rotation attention — the on-demand view of what the monitor's
// reminder scan flags (without storm filtering).
//
//	GET /api/secret/lifecycle
func (a *API) SecretLifecycleReport(w http.ResponseWriter, r *http.Request) {
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
	warning, critical := 30, 7
	if d := int(a.monitorOpts.Warning / (24 * time.Hour)); d > 0 {
		warning = d
	}
	if d := int(a.monitorOpts.Critical / (24 * time.Hour)); d > 0 {
		critical = d
	}
	items := monitor.ClassifySecrets(secrets, warning, critical, time.Now().UTC())
	if items == nil {
		items = []monitor.SecretItem{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"items":        items,
	})
}
