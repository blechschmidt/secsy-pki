package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// maxSecretPlaintext bounds the size of a secret accepted for encryption. The
// envelope feature is for passwords and small secrets, not bulk data; capping
// the request body also limits the memory an authenticated caller can force the
// server to allocate.
const maxSecretPlaintext = 64 * 1024 // 64 KiB

func (a *API) secretEnabled() bool { return a.secretKEKLabel != "" }

// TenantHeader names the request header a client uses to select the tenant whose
// secret KEK should seal/open an envelope. When absent, the default tenant (and
// the deployment-wide KEK) is used, preserving single-tenant behavior.
const TenantHeader = "X-Secsy-Tenant"

// resolveSecretTenant maps the request's tenant selector to its tenant record
// and effective KEK label. A tenant with its own KEK label seals its secrets
// under a tenant-specific key, keeping one tenant's envelopes cryptographically
// separable from another's; a tenant without one falls back to the deployment
// KEK. An unknown tenant is an error, and a suspended tenant is refused with
// the typed gate error (mapped to 403). The resolved tenant is stamped on the
// request context for auditing. The record is always loaded — default tenant
// included — because its quotas drive the secret-op accounting.
func (a *API) resolveSecretTenant(r *http.Request) (tenant *models.Tenant, kekLabel string, err error) {
	sel := r.Header.Get(TenantHeader)
	if sel == "" {
		sel = models.DefaultTenantID
	}
	// Accept either the tenant ID or its slug.
	t, err := a.db.GetTenant(sel)
	if err != nil {
		return nil, "", err
	}
	if t == nil {
		if t, err = a.db.GetTenantBySlug(sel); err != nil {
			return nil, "", err
		}
	}
	if t == nil {
		return nil, "", fmt.Errorf("unknown tenant %q", sel)
	}
	if t.Status != models.TenantStatusActive {
		metrics.TenantDenied.Inc(metrics.TenantLabel(t.ID), "suspended")
		return nil, "", &models.TenantSuspendedError{TenantID: t.ID}
	}
	middleware.SetTenant(r.Context(), t.ID)
	label := t.KEKLabel
	if label == "" {
		label = a.secretKEKLabel
	}
	return t, label, nil
}

// writeSecretTenantError maps a tenant-resolution failure on the secret path:
// suspension keeps its 403 gate semantics; anything else (unknown tenant,
// malformed selector) stays a 400 as before.
func writeSecretTenantError(w http.ResponseWriter, err error) {
	if writeTenantLimitError(w, err) {
		return
	}
	writeError(w, http.StatusBadRequest, "%v", err)
}

// secretService builds a Service bound to the configured KEK for this request.
// A fresh service is created per request so the KEK session is short-lived,
// matching the signing path.
func (a *API) secretService(r *http.Request) (*secret.Service, error) {
	return a.secretServiceWithKEK(r, a.secretKEKLabel)
}

// secretServiceWithKEK builds a Service bound to a specific KEK label (used to
// select a tenant's KEK).
func (a *API) secretServiceWithKEK(r *http.Request, kekLabel string) (*secret.Service, error) {
	if kekLabel == "" {
		return nil, fmt.Errorf("no KEK configured")
	}
	return secret.NewService(r.Context(), a.keyProvider, keyprovider.KeyRef{Label: kekLabel})
}

// SecretInfo reports metadata about the configured KEK (never key material).
func (a *API) SecretInfo(w http.ResponseWriter, r *http.Request) {
	svc, err := a.secretService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "secret service unavailable: %v", err)
		return
	}
	info := svc.KEKInfo()
	escrowAvailable, escrowThreshold, escrowAgents := a.escrowInfo()
	writeJSON(w, http.StatusOK, map[string]any{
		"kek_label": info.Label,
		"provider":  info.Provider,
		"key_bits":  info.KeyBits,
		"wrap_alg":  info.WrapAlg,
		"data_alg":  secret.AlgAES256GCM,
		"version":   secret.FormatVersion1,
		// M-of-N escrow policy shape (Task 33): whether encrypt requests may ask
		// for escrow, and the recovery quorum. Recovery itself is a dual-control
		// CLI operation (secsy-secret recover) and is deliberately not exposed
		// over the API.
		"escrow_available": escrowAvailable,
		"escrow_threshold": escrowThreshold,
		"escrow_agents":    escrowAgents,
	})
}

// encryptRequest carries the base64-encoded plaintext and an optional
// encryption context. Using base64 keeps arbitrary binary secrets intact over
// JSON; the context, if supplied, must be provided verbatim to decrypt.
type encryptRequest struct {
	Plaintext string `json:"plaintext"`         // base64
	Context   string `json:"context,omitempty"` // base64, optional
	// Escrow, when true, additionally wraps the data key to the configured M-of-N
	// recovery agents so it can be recovered under dual control. It requires
	// secret.escrow to be configured; otherwise the request is rejected.
	Escrow bool `json:"escrow,omitempty"`
}

type encryptResponse struct {
	Envelope json.RawMessage `json:"envelope"`
}

// EncryptSecret seals a caller-supplied plaintext into a versioned envelope.
func (a *API) EncryptSecret(w http.ResponseWriter, r *http.Request) {
	tenant, kekLabel, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	if !a.canInTenant(middleware.GetUserInfo(r.Context()), tenant.ID, rbac.ActionEncrypt) {
		metrics.Envelope.Inc("encrypt", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionSecretEncrypt, kekLabel, "", audit.ResultDenied, "secret:encrypt capability required")
		writeError(w, http.StatusForbidden, "secret:encrypt capability required for tenant %q", tenant.ID)
		return
	}

	svc, err := a.secretServiceWithKEK(r, kekLabel)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "secret service unavailable: %v", err)
		return
	}

	var req encryptRequest
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
	var context []byte
	if req.Context != "" {
		context, err = base64.StdEncoding.DecodeString(req.Context)
		if err != nil {
			writeError(w, http.StatusBadRequest, "context must be base64: %v", err)
			return
		}
	}
	defer zeroBytes(plaintext)

	// Resolve the escrow policy up front when requested, so a misconfiguration is
	// reported before any encryption happens.
	var escrowPolicy *secret.EscrowPolicy
	if req.Escrow {
		if !a.escrowConfigured() {
			writeError(w, http.StatusBadRequest, "key escrow requested but secret.escrow is not configured")
			return
		}
		escrowPolicy, err = a.escrowPolicyFor(r)
		if err != nil {
			a.recordEvent(r, audit.ActionSecretEscrow, a.secretKEKLabel, "", audit.ResultError, err.Error())
			writeError(w, http.StatusInternalServerError, "escrow policy unavailable: %v", err)
			return
		}
	}

	// Daily secret-op quota (fail-closed), reserved only after the request has
	// fully validated so malformed requests never burn quota.
	quotaDone, err := a.consumeSecretOpQuota(r, tenant, "encrypt")
	if err != nil {
		metrics.Envelope.Inc("encrypt", metrics.ResultDenied)
		if writeTenantLimitError(w, err) { // quota → 429 + Retry-After
			return
		}
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}

	// Consume pending HSM audit logs to free space, mirroring the signing path.
	a.consumeHSMAuditLogs("")
	blob, err := svc.EncryptWithEscrowToJSON(plaintext, context, escrowPolicy)
	a.consumeHSMAuditLogs("")
	quotaDone(err)
	metrics.RecordEnvelope("encrypt", err)
	if err != nil {
		a.recordEvent(r, audit.ActionSecretEncrypt, a.secretKEKLabel, "", audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "encryption failed: %v", err)
		return
	}

	a.recordEvent(r, audit.ActionSecretEncrypt, a.secretKEKLabel, "", audit.ResultSuccess, "")
	if escrowPolicy != nil {
		// Record the escrow with its own distinct event type so break-glass
		// wrapping is independently visible in the audit trail.
		detail := fmt.Sprintf("threshold=%d agents=%d", escrowPolicy.Threshold(), len(escrowPolicy.Agents()))
		a.recordEvent(r, audit.ActionSecretEscrow, a.secretKEKLabel, "", audit.ResultSuccess, detail)
	}
	writeJSON(w, http.StatusOK, encryptResponse{Envelope: json.RawMessage(blob)})
}

// decryptRequest carries the envelope (as raw JSON) and optional context.
type decryptRequest struct {
	Envelope json.RawMessage `json:"envelope"`
	Context  string          `json:"context,omitempty"` // base64, optional
}

type decryptResponse struct {
	Plaintext string `json:"plaintext"` // base64
}

// DecryptSecret recovers plaintext from an envelope. The KEK (HSM) performs the
// unwrap; a failure returns a generic 400 to avoid acting as an oracle.
func (a *API) DecryptSecret(w http.ResponseWriter, r *http.Request) {
	tenant, kekLabel, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	if !a.canInTenant(middleware.GetUserInfo(r.Context()), tenant.ID, rbac.ActionDecrypt) {
		metrics.Envelope.Inc("decrypt", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionSecretDecrypt, kekLabel, "", audit.ResultDenied, "secret:decrypt capability required")
		writeError(w, http.StatusForbidden, "secret:decrypt capability required for tenant %q", tenant.ID)
		return
	}

	svc, err := a.secretServiceWithKEK(r, kekLabel)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "secret service unavailable: %v", err)
		return
	}

	var req decryptRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSecretPlaintext*4)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if len(req.Envelope) == 0 {
		writeError(w, http.StatusBadRequest, "envelope is required")
		return
	}
	var context []byte
	if req.Context != "" {
		context, err = base64.StdEncoding.DecodeString(req.Context)
		if err != nil {
			writeError(w, http.StatusBadRequest, "context must be base64: %v", err)
			return
		}
	}

	// Daily secret-op quota (fail-closed), reserved only after the request has
	// fully validated so malformed requests never burn quota.
	quotaDone, err := a.consumeSecretOpQuota(r, tenant, "decrypt")
	if err != nil {
		metrics.Envelope.Inc("decrypt", metrics.ResultDenied)
		if writeTenantLimitError(w, err) { // quota → 429 + Retry-After
			return
		}
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}

	a.consumeHSMAuditLogs("")
	plaintext, err := svc.DecryptJSON(req.Envelope, context)
	a.consumeHSMAuditLogs("")
	quotaDone(err)
	metrics.RecordEnvelope("decrypt", err)
	if err != nil {
		// Generic client error with NO underlying detail: wrong key/context or a
		// corrupted/invalid envelope must be indistinguishable so the endpoint
		// cannot be used as a padding/decryption oracle. The detail stays
		// server-side only (not even in the audit detail).
		a.recordEvent(r, audit.ActionSecretDecrypt, a.secretKEKLabel, "", audit.ResultError, "decryption failed")
		writeError(w, http.StatusBadRequest, "decryption failed")
		return
	}
	defer zeroBytes(plaintext)
	a.recordEvent(r, audit.ActionSecretDecrypt, a.secretKEKLabel, "", audit.ResultSuccess, "")

	writeJSON(w, http.StatusOK, decryptResponse{
		Plaintext: base64.StdEncoding.EncodeToString(plaintext),
	})
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
