package handlers

// Format-preserving encryption (FF1) and searchable tokenization on the secret
// layer (Task 144): POST /api/secret/transform/{encode,decode}.
//
// A "transform" enciphers structured data (a card PAN, an SSN, an account
// number) into a value of the SAME length over the SAME alphabet, so legacy
// systems that validate format keep working, while a deterministic template
// yields stable ciphertext for equal plaintext so a protected column can still be
// searched for equality. The FF1 key never exists in the clear at rest: it is
// HKDF-derived per request from a seed sealed under the tenant's HSM-held KEK
// (see internal/secret/transform.go). Every operation authorizes the shared
// secret:transform capability plus any per-template role allowlist, meters the
// per-tenant daily secret-op quota, appends a tamper-evident audit event
// (recording only lengths — never the plaintext or the token), and increments a
// per-template metric. The core methods are shared verbatim by the gRPC
// SecretService so both transports enforce identical semantics.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// maxTransformValue bounds the size of a value accepted for a transform. FF1 is
// for structured fields (PANs, SSNs, account numbers), not bulk data; the cap
// also bounds the memory an authenticated caller can force the server to
// allocate. It is generous relative to any real formatted identifier.
const maxTransformValue = 4096

// transformTemplate looks up a resolved transform template by name, or nil when
// the transform service is unconfigured or the name is unknown.
func (a *API) transformTemplate(name string) *secret.TransformTemplate {
	if a.secretTransforms == nil {
		return nil
	}
	return a.secretTransforms[name]
}

// TransformConfigured reports whether any transform template is configured.
// Exposed for the gRPC SecretService to fail cleanly when disabled.
func (a *API) TransformConfigured() bool { return len(a.secretTransforms) > 0 }

// canUseTransform authorizes a transform operation: the shared secret:transform
// capability within the tenant, plus the template's optional per-template role
// allowlist. A single authz metric is recorded for the compound decision.
func (a *API) canUseTransform(user *models.UserInfo, tenantID string, tmpl *secret.TransformTemplate) bool {
	allowed := a.decideInTenant(user, tenantID, rbac.ActionTransform) && templateRoleAllowed(user, tenantID, tmpl)
	metrics.RecordAuthz(string(rbac.ActionTransform), allowed)
	return allowed
}

// templateRoleAllowed enforces a template's per-template role allowlist: an empty
// allowlist permits any secret:transform holder, otherwise the caller must hold
// one of the named roles (platform-wide or within the tenant), or be root.
func templateRoleAllowed(user *models.UserInfo, tenantID string, tmpl *secret.TransformTemplate) bool {
	if len(tmpl.Roles) == 0 {
		return true
	}
	if user == nil {
		return false
	}
	if user.IsRoot {
		return true
	}
	have := append(userRoles(user), tenantRolesFor(user, tenantID)...)
	for _, want := range tmpl.Roles {
		if rbac.HasRole(have, rbac.Role(want)) {
			return true
		}
	}
	return false
}

// TransformResult is the outcome of an encode/decode, shared by REST and gRPC.
type TransformResult struct {
	// Result is the transformed value: the token for encode, the recovered
	// plaintext for decode. It has the same length/format as the input.
	Result        string
	Template      string
	Deterministic bool
}

// TransformOp is the shared core behind the REST and gRPC transform endpoints. It
// authorizes secret:transform (plus the template role allowlist), meters the
// daily secret-op quota, provisions the family's FPE seed on first use, derives
// the per-template FF1 key on the HSM path, and encodes (encode=true) or decodes
// the value. The plaintext and token are never persisted, logged, or metered.
func (a *API) TransformOp(ctx context.Context, ip string, tenant *models.Tenant, kekLabel, templateName, value string, tweak []byte, encode bool) (*TransformResult, error) {
	op := "decode"
	if encode {
		op = "encode"
	}
	user := middleware.GetUserInfo(ctx)

	// Base capability first, so an unknown-template response cannot be used as a
	// template-existence oracle by a caller without even the transform capability.
	if !a.decideInTenant(user, tenant.ID, rbac.ActionTransform) {
		metrics.RecordAuthz(string(rbac.ActionTransform), false)
		metrics.SecretTransform.Inc(templateName, op, metrics.ResultDenied)
		a.recordEventCtx(ctx, ip, audit.ActionSecretTransform, kekLabel, templateName, audit.ResultDenied, "secret:transform capability required")
		return nil, &secretForbiddenError{fmt.Sprintf("secret:transform capability required for tenant %q", tenant.ID)}
	}
	tmpl := a.transformTemplate(templateName)
	if tmpl == nil {
		metrics.SecretTransform.Inc(templateName, op, metrics.ResultError)
		return nil, &secretClientError{fmt.Sprintf("unknown transform template %q", templateName)}
	}
	// Per-template role allowlist (records the compound authz decision metric).
	if !a.canUseTransform(user, tenant.ID, tmpl) {
		metrics.SecretTransform.Inc(templateName, op, metrics.ResultDenied)
		a.recordEventCtx(ctx, ip, audit.ActionSecretTransform, kekLabel, templateName, audit.ResultDenied, "template role allowlist denies caller")
		return nil, &secretForbiddenError{fmt.Sprintf("transform template %q is not permitted for this caller", templateName)}
	}
	if value == "" {
		return nil, &secretClientError{"value is required"}
	}
	if len(value) > maxTransformValue {
		return nil, &secretClientError{fmt.Sprintf("value exceeds %d bytes", maxTransformValue)}
	}

	ring, err := a.secretRingCtx(ctx, kekLabel)
	if err != nil {
		return nil, fmt.Errorf("secret service unavailable: %w", err)
	}
	quotaDone, err := a.consumeSecretOpQuotaCtx(ctx, ip, tenant, "transform")
	if err != nil {
		metrics.SecretTransform.Inc(templateName, op, metrics.ResultDenied)
		return nil, err
	}

	a.consumeHSMAuditLogs("")
	seedRow, err := secret.EnsureFPESeed(ctx, a.db, ring, kekLabel, a.macSeedRand(ctx))
	if err != nil {
		a.consumeHSMAuditLogs("")
		quotaDone(err)
		metrics.SecretTransform.Inc(templateName, op, metrics.ResultError)
		a.recordEventCtx(ctx, ip, audit.ActionSecretTransform, kekLabel, templateName, audit.ResultError, "FPE seed unavailable")
		return nil, err
	}
	transformer, err := secret.NewTransformer(ctx, ring, seedRow, tmpl)
	a.consumeHSMAuditLogs("")
	if err != nil {
		quotaDone(err)
		metrics.SecretTransform.Inc(templateName, op, metrics.ResultError)
		a.recordEventCtx(ctx, ip, audit.ActionSecretTransform, kekLabel, templateName, audit.ResultError, "deriving transform key failed")
		return nil, err
	}

	var result string
	if encode {
		result, err = transformer.Encode(value, tweak)
	} else {
		result, err = transformer.Decode(value, tweak)
	}
	quotaDone(err)
	if err != nil {
		metrics.SecretTransform.Inc(templateName, op, metrics.ResultError)
		// A transform failure is a caller/data error (value outside the alphabet,
		// wrong length, tweak policy mismatch), not an internal fault.
		a.recordEventCtx(ctx, ip, audit.ActionSecretTransform, kekLabel, templateName, audit.ResultError, fmt.Sprintf("%s failed", op))
		return nil, &secretClientError{err.Error()}
	}
	metrics.SecretTransform.Inc(templateName, op, metrics.ResultSuccess)
	a.recordEventCtx(ctx, ip, audit.ActionSecretTransform, kekLabel, templateName, audit.ResultSuccess,
		fmt.Sprintf("op=%s template=%s len=%d deterministic=%v", op, templateName, len([]rune(value)), tmpl.Deterministic))
	return &TransformResult{Result: result, Template: templateName, Deterministic: tmpl.Deterministic}, nil
}

type transformRequest struct {
	// Template names the configured transform to apply.
	Template string `json:"template"`
	// Value is the input: the plaintext for encode, the token for decode. Its
	// format (alphabet, length) must match the template.
	Value string `json:"value"`
	// Tweak is optional base64 AAD for a per-request-tweak template; it must be
	// presented verbatim to decode. It must be empty for a deterministic template.
	Tweak string `json:"tweak,omitempty"`
}

type transformResponse struct {
	Template      string `json:"template"`
	Result        string `json:"result"`
	Deterministic bool   `json:"deterministic"`
}

// EncodeTransform handles POST /api/secret/transform/encode.
func (a *API) EncodeTransform(w http.ResponseWriter, r *http.Request) {
	a.serveTransform(w, r, true)
}

// DecodeTransform handles POST /api/secret/transform/decode.
func (a *API) DecodeTransform(w http.ResponseWriter, r *http.Request) {
	a.serveTransform(w, r, false)
}

// serveTransform decodes the request, runs the shared TransformOp, and writes the
// result, mapping core errors to the same status codes as the other secret
// crypto endpoints.
func (a *API) serveTransform(w http.ResponseWriter, r *http.Request, encode bool) {
	tenant, kekLabel, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	var req transformRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxTransformValue*2)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	var tweak []byte
	if req.Tweak != "" {
		tweak, err = base64.StdEncoding.DecodeString(req.Tweak)
		if err != nil {
			writeError(w, http.StatusBadRequest, "tweak must be base64: %v", err)
			return
		}
	}
	res, err := a.TransformOp(r.Context(), clientIP(r), tenant, kekLabel, req.Template, req.Value, tweak, encode)
	if err != nil {
		a.writeSecretCryptoError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, transformResponse{
		Template:      res.Template,
		Result:        res.Result,
		Deterministic: res.Deterministic,
	})
}
