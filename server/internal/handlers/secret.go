package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// maxSecretPlaintext bounds the size of a secret accepted for encryption. The
// envelope feature is for passwords and small secrets, not bulk data; capping
// the request body also limits the memory an authenticated caller can force the
// server to allocate.
const maxSecretPlaintext = 64 * 1024 // 64 KiB

func (a *API) secretEnabled() bool { return a.secretKEKLabel != "" }

// secretService builds a Service bound to the configured KEK for this request.
// A fresh service is created per request so the KEK session is short-lived,
// matching the signing path.
func (a *API) secretService(r *http.Request) (*secret.Service, error) {
	return secret.NewService(r.Context(), a.keyProvider, keyprovider.KeyRef{Label: a.secretKEKLabel})
}

// SecretInfo reports metadata about the configured KEK (never key material).
func (a *API) SecretInfo(w http.ResponseWriter, r *http.Request) {
	svc, err := a.secretService(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "secret service unavailable: %v", err)
		return
	}
	info := svc.KEKInfo()
	writeJSON(w, http.StatusOK, map[string]any{
		"kek_label": info.Label,
		"provider":  info.Provider,
		"key_bits":  info.KeyBits,
		"wrap_alg":  info.WrapAlg,
		"data_alg":  secret.AlgAES256GCM,
		"version":   secret.FormatVersion1,
	})
}

// encryptRequest carries the base64-encoded plaintext and an optional
// encryption context. Using base64 keeps arbitrary binary secrets intact over
// JSON; the context, if supplied, must be provided verbatim to decrypt.
type encryptRequest struct {
	Plaintext string `json:"plaintext"`         // base64
	Context   string `json:"context,omitempty"` // base64, optional
}

type encryptResponse struct {
	Envelope json.RawMessage `json:"envelope"`
}

// EncryptSecret seals a caller-supplied plaintext into a versioned envelope.
func (a *API) EncryptSecret(w http.ResponseWriter, r *http.Request) {
	if !a.can(middleware.GetUserInfo(r.Context()), rbac.ActionEncrypt) {
		metrics.Envelope.Inc("encrypt", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionSecretEncrypt, a.secretKEKLabel, "", audit.ResultDenied, "secret:encrypt capability required")
		writeError(w, http.StatusForbidden, "secret:encrypt capability required (admin or issuer role)")
		return
	}

	svc, err := a.secretService(r)
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

	// Consume pending HSM audit logs to free space, mirroring the signing path.
	a.consumeHSMAuditLogs("")
	blob, err := svc.EncryptToJSON(plaintext, context)
	a.consumeHSMAuditLogs("")
	metrics.RecordEnvelope("encrypt", err)
	if err != nil {
		a.recordEvent(r, audit.ActionSecretEncrypt, a.secretKEKLabel, "", audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "encryption failed: %v", err)
		return
	}

	a.recordEvent(r, audit.ActionSecretEncrypt, a.secretKEKLabel, "", audit.ResultSuccess, "")
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
	if !a.can(middleware.GetUserInfo(r.Context()), rbac.ActionDecrypt) {
		metrics.Envelope.Inc("decrypt", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionSecretDecrypt, a.secretKEKLabel, "", audit.ResultDenied, "secret:decrypt capability required")
		writeError(w, http.StatusForbidden, "secret:decrypt capability required (admin or issuer role)")
		return
	}

	svc, err := a.secretService(r)
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

	a.consumeHSMAuditLogs("")
	plaintext, err := svc.DecryptJSON(req.Envelope, context)
	a.consumeHSMAuditLogs("")
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
