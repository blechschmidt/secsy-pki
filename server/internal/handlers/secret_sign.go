package handlers

// Named HSM-backed asymmetric digital signatures on the crypto/secret layer
// (Task 153): the Transit-style sign/verify service that complements the
// symmetric data-key/HMAC/random endpoints. Callers create a named signing key
// (ECDSA P-256/384 or RSA-PSS/PKCS#1-v1.5, algorithm fixed at creation) whose
// private half is generated non-extractable in the key provider (the HSM under
// PKCS#11), then sign arbitrary data (a message hashed here, or a pre-computed
// digest) and verify signatures against the exported public key. Public-key
// export hands an external verifier the SPKI so it can check signatures with
// openssl/JOSE without this service.
//
// Every operation authorizes against the caller's tenant, appends a
// tamper-evident audit event, and increments Prometheus counters; signing meters
// the per-tenant daily secret-op quota (verify and public-key export do not — they
// touch only public material). The core *Op methods are shared verbatim by the
// gRPC SecretService so both transports enforce identical semantics. This is
// deliberately distinct from the CMS/X.509 artifact-signing service (raw data
// signatures, not signature containers).

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// maxSignData bounds the data a sign/verify request may cover. This is a
// small-message signature service (sign a manifest, a token, a digest — not bulk
// streams), so the cap matches the secret-plaintext cap and keeps an
// authenticated caller from forcing large allocations or HSM work.
const maxSignData = maxSecretPlaintext

// SigningKeyInfo is the non-sensitive view of a signing key, shared by REST and
// gRPC. It never carries private material — only identifiers, the fixed
// algorithm, and the exported public key.
type SigningKeyInfo struct {
	ID           string
	Name         string
	Algorithm    string
	KeyType      string
	Provider     string
	CreatedBy    string
	CreatedAt    string
	PublicKeyPEM string
	PublicKeyDER []byte
}

// signingKeyInfo builds a SigningKeyInfo from a stored row, decoding the public
// key into both PEM and raw DER for the caller's convenience.
func signingKeyInfo(row *models.SigningKey) (*SigningKeyInfo, error) {
	pemBytes, err := secret.PublicKeyPEM(row)
	if err != nil {
		return nil, err
	}
	der, err := secret.PublicKeyDER(row)
	if err != nil {
		return nil, err
	}
	return &SigningKeyInfo{
		ID:           row.ID,
		Name:         row.Name,
		Algorithm:    row.Algorithm,
		KeyType:      row.KeyType,
		Provider:     row.Provider,
		CreatedBy:    row.CreatedBy,
		CreatedAt:    row.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		PublicKeyPEM: string(pemBytes),
		PublicKeyDER: der,
	}, nil
}

// ctxActor returns the operator subject bound to ctx, for CreatedBy attribution.
func ctxActor(ctx context.Context) string {
	if u := middleware.GetUserInfo(ctx); u != nil {
		return u.Subject
	}
	return ""
}

// =========================================================================
// Signing-key management (create / list / public-key export)
// =========================================================================

// CreateSigningKeyOp generates a new named signing key in the provider and
// persists its metadata. It authorizes secret:signing-key (the privileged
// key-management capability), records the audit event and metric, and returns the
// key's public view. The private key never leaves the provider.
func (a *API) CreateSigningKeyOp(ctx context.Context, ip string, tenant *models.Tenant, name, algorithm string) (*SigningKeyInfo, error) {
	if !a.canOnSigningKey(ctx, tenant.ID, name, rbac.ActionManageSigningKey) {
		metrics.SecretSigningKey.Inc(metrics.ResultDenied)
		a.recordEventCtx(ctx, ip, audit.ActionSecretSigningKeyCreate, name, "", audit.ResultDenied, "secret:signing-key capability required")
		return nil, &secretForbiddenError{fmt.Sprintf("secret:signing-key capability required for tenant %q, or an admin grant on signing-key/%s", tenant.ID, name)}
	}
	alg, err := secret.NormalizeSigningAlgorithm(algorithm)
	if err != nil {
		return nil, &secretClientError{err.Error()}
	}
	if name == "" {
		return nil, &secretClientError{"name is required"}
	}

	a.consumeHSMAuditLogs("")
	row, err := secret.CreateSigningKey(ctx, a.keyProvider, a.db, secret.CreateSigningKeySpec{
		TenantID:  tenant.ID,
		Name:      name,
		Algorithm: alg,
		CreatedBy: ctxActor(ctx),
	})
	a.consumeHSMAuditLogs("")
	if err != nil {
		if errors.Is(err, secret.ErrSigningKeyNameTaken) || errors.Is(err, database.ErrSigningKeyExists) {
			metrics.SecretSigningKey.Inc(metrics.ResultError)
			a.recordEventCtx(ctx, ip, audit.ActionSecretSigningKeyCreate, name, "", audit.ResultError, "name already exists")
			return nil, &secretConflictError{fmt.Sprintf("a signing key named %q already exists", name)}
		}
		metrics.SecretSigningKey.Inc(metrics.ResultError)
		a.recordEventCtx(ctx, ip, audit.ActionSecretSigningKeyCreate, name, "", audit.ResultError, "signing-key creation failed")
		return nil, fmt.Errorf("creating signing key: %w", err)
	}
	metrics.SecretSigningKey.Inc(metrics.ResultSuccess)
	a.recordEventCtx(ctx, ip, audit.ActionSecretSigningKeyCreate, name, row.ID, audit.ResultSuccess,
		fmt.Sprintf("algorithm=%s key_type=%s id=%s", row.Algorithm, row.KeyType, row.ID))
	return signingKeyInfo(row)
}

// ListSigningKeysOp returns the tenant's signing keys (public metadata only). It
// authorizes secret:signing-key.
func (a *API) ListSigningKeysOp(ctx context.Context, ip string, tenant *models.Tenant) ([]*SigningKeyInfo, error) {
	// A principal delegated individual keys holds no tenant-wide capability, so
	// its grants are what make those keys visible. Without this it would be told
	// it may sign with a key it cannot see (Task 191).
	tenantWide := a.canInTenant(middleware.GetUserInfo(ctx), tenant.ID, rbac.ActionManageSigningKey)
	var granted map[string]bool
	if !tenantWide {
		granted = a.signingKeysVisibleByGrant(middleware.GetUserInfo(ctx))
		if len(granted) == 0 {
			return nil, &secretForbiddenError{fmt.Sprintf("secret:signing-key capability required for tenant %q, or a grant on a signing key", tenant.ID)}
		}
	}
	rows, err := a.db.ListSigningKeys(tenant.ID)
	if err != nil {
		return nil, fmt.Errorf("listing signing keys: %w", err)
	}
	out := make([]*SigningKeyInfo, 0, len(rows))
	for _, row := range rows {
		if !tenantWide && !granted[row.Name] {
			continue
		}
		info, err := signingKeyInfo(row)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

// GetSigningKeyPublicOp returns one signing key's public view (metadata + public
// key). It authorizes secret:sign — exporting the already-public half is a
// signing-service operation, not key management.
func (a *API) GetSigningKeyPublicOp(ctx context.Context, ip string, tenant *models.Tenant, name string) (*SigningKeyInfo, error) {
	if !a.canOnSigningKey(ctx, tenant.ID, name, rbac.ActionSign) {
		return nil, &secretForbiddenError{fmt.Sprintf("secret:sign capability required for tenant %q, or a grant on signing-key/%s", tenant.ID, name)}
	}
	row, err := a.resolveSigningKey(tenant.ID, name)
	if err != nil {
		return nil, err
	}
	return signingKeyInfo(row)
}

// resolveSigningKey loads a tenant's signing key by name, mapping "not found" to
// a client error so a caller cannot distinguish a missing key from a forbidden
// one via a 500.
func (a *API) resolveSigningKey(tenantID, name string) (*models.SigningKey, error) {
	if name == "" {
		return nil, &secretClientError{"key name is required"}
	}
	row, err := a.db.GetSigningKey(tenantID, name)
	if err != nil {
		return nil, fmt.Errorf("reading signing key: %w", err)
	}
	if row == nil {
		return nil, &secretClientError{fmt.Sprintf("no signing key named %q", name)}
	}
	return row, nil
}

// =========================================================================
// Sign / Verify
// =========================================================================

// SignOpResult is the outcome of a sign, shared by REST and gRPC.
type SignOpResult struct {
	Signature []byte
	Algorithm string
	Hash      string
	KeyName   string
}

// SignOp produces a signature over the caller's data with the named key. Exactly
// one of message (hashed here) or digest (used verbatim) must be supplied; hash
// selects the message hash (empty = the algorithm default). It authorizes
// secret:sign FIRST (before any content validation, so a caller lacking the
// capability always sees 403), meters the daily secret-op quota (this is an HSM
// signing operation), records the audit event and metric, and returns the
// signature with the algorithm/hash used.
func (a *API) SignOp(ctx context.Context, ip string, tenant *models.Tenant, keyName string, message, digest []byte, hash string) (*SignOpResult, error) {
	if !a.canOnSigningKey(ctx, tenant.ID, keyName, rbac.ActionSign) {
		metrics.SecretSign.Inc("sign", metrics.ResultDenied)
		a.recordEventCtx(ctx, ip, audit.ActionSecretSign, keyName, "", audit.ResultDenied, "secret:sign capability required")
		return nil, &secretForbiddenError{fmt.Sprintf("secret:sign capability required for tenant %q, or a grant on signing-key/%s", tenant.ID, keyName)}
	}
	data, preHashed, err := resolveSignData(message, digest)
	if err != nil {
		return nil, err
	}
	row, err := a.resolveSigningKey(tenant.ID, keyName)
	if err != nil {
		return nil, err
	}
	quotaDone, err := a.consumeSecretOpQuotaCtx(ctx, ip, tenant, "sign")
	if err != nil {
		metrics.SecretSign.Inc("sign", metrics.ResultDenied)
		return nil, err
	}

	a.consumeHSMAuditLogs("")
	res, err := secret.Sign(ctx, a.keyProvider, row, data, hash, preHashed)
	a.consumeHSMAuditLogs("")
	quotaDone(err)
	if err != nil {
		metrics.SecretSign.Inc("sign", metrics.ResultError)
		// A bad hash / mismatched pre-hash is the caller's fault (400); an HSM
		// failure is internal.
		a.recordEventCtx(ctx, ip, audit.ActionSecretSign, keyName, row.ID, audit.ResultError, "signing failed")
		if isSignClientErr(err) {
			return nil, &secretClientError{err.Error()}
		}
		return nil, fmt.Errorf("signing: %w", err)
	}
	metrics.SecretSign.Inc("sign", metrics.ResultSuccess)
	a.recordEventCtx(ctx, ip, audit.ActionSecretSign, keyName, row.ID, audit.ResultSuccess,
		fmt.Sprintf("algorithm=%s hash=%s prehashed=%v", res.Algorithm, secret.HashName(res.Hash), preHashed))
	return &SignOpResult{
		Signature: res.Signature,
		Algorithm: string(res.Algorithm),
		Hash:      secret.HashName(res.Hash),
		KeyName:   keyName,
	}, nil
}

// SignVerifyResult is the outcome of a verify, shared by REST and gRPC.
type SignVerifyResult struct {
	Valid     bool
	Algorithm string
	Hash      string
}

// VerifySignatureOp checks a signature over data against the named key's public
// half. It authorizes secret:sign. A signature that simply does not match is a
// valid=false RESULT, not an error; only authorization, a bad request, or a
// malformed key is an error. Verification uses only public material, so it is not
// metered against the HSM quota.
func (a *API) VerifySignatureOp(ctx context.Context, ip string, tenant *models.Tenant, keyName string, message, digest, sig []byte, hash string) (*SignVerifyResult, error) {
	if !a.canOnSigningKey(ctx, tenant.ID, keyName, rbac.ActionSign) {
		metrics.SecretSign.Inc("verify", metrics.ResultDenied)
		a.recordEventCtx(ctx, ip, audit.ActionSecretSignVerify, keyName, "", audit.ResultDenied, "secret:sign capability required")
		return nil, &secretForbiddenError{fmt.Sprintf("secret:sign capability required for tenant %q, or a grant on signing-key/%s", tenant.ID, keyName)}
	}
	data, preHashed, err := resolveSignData(message, digest)
	if err != nil {
		return nil, err
	}
	if len(sig) == 0 {
		return nil, &secretClientError{"signature is required"}
	}
	row, err := a.resolveSigningKey(tenant.ID, keyName)
	if err != nil {
		return nil, err
	}
	valid, err := secret.Verify(row, data, sig, hash, preHashed)
	if err != nil {
		metrics.SecretSign.Inc("verify", metrics.ResultError)
		if isSignClientErr(err) {
			return nil, &secretClientError{err.Error()}
		}
		a.recordEventCtx(ctx, ip, audit.ActionSecretSignVerify, keyName, row.ID, audit.ResultError, "verification failed")
		return nil, fmt.Errorf("verifying: %w", err)
	}
	metrics.SecretSign.Inc("verify", metrics.ResultSuccess)
	a.recordEventCtx(ctx, ip, audit.ActionSecretSignVerify, keyName, row.ID, audit.ResultSuccess,
		fmt.Sprintf("valid=%v algorithm=%s", valid, row.Algorithm))
	return &SignVerifyResult{Valid: valid, Algorithm: row.Algorithm, Hash: hash}, nil
}

// VerifyWithSuppliedKeyOp checks a signature over data against a caller-supplied
// public key and algorithm, rather than a stored key. It authorizes secret:sign
// FIRST (before any content validation, so an unauthorized caller always sees
// 403) and uses only public material (no HSM, no quota), so it lets a caller
// validate a signature produced by a key this service does not manage. A
// signature that does not match is a valid=false RESULT, not an error; a
// malformed key or an unknown algorithm is a bad request. The public key is SPKI,
// supplied in exactly one of publicKeyPEM or publicKeyDER (raw DER bytes).
func (a *API) VerifyWithSuppliedKeyOp(ctx context.Context, ip string, tenant *models.Tenant, algorithm string, publicKeyPEM, publicKeyDER, message, digest, sig []byte, hash string) (*SignVerifyResult, error) {
	if !a.canInTenant(middleware.GetUserInfo(ctx), tenant.ID, rbac.ActionSign) {
		metrics.SecretSign.Inc("verify", metrics.ResultDenied)
		a.recordEventCtx(ctx, ip, audit.ActionSecretSignVerify, "supplied-key", "", audit.ResultDenied, "secret:sign capability required")
		return nil, &secretForbiddenError{fmt.Sprintf("secret:sign capability required for tenant %q", tenant.ID)}
	}
	alg, err := secret.NormalizeSigningAlgorithm(algorithm)
	if err != nil {
		return nil, &secretClientError{err.Error()}
	}
	data, preHashed, err := resolveSignData(message, digest)
	if err != nil {
		return nil, err
	}
	if len(sig) == 0 {
		return nil, &secretClientError{"signature is required"}
	}
	publicKey, err := resolveSuppliedPublicKey(publicKeyPEM, publicKeyDER)
	if err != nil {
		return nil, err
	}
	pub, err := secret.ParsePublicKey(publicKey)
	if err != nil {
		return nil, &secretClientError{err.Error()}
	}
	valid, err := secret.VerifyWithPublicKey(alg, pub, data, sig, hash, preHashed)
	if err != nil {
		metrics.SecretSign.Inc("verify", metrics.ResultError)
		if isSignClientErr(err) {
			return nil, &secretClientError{err.Error()}
		}
		a.recordEventCtx(ctx, ip, audit.ActionSecretSignVerify, "supplied-key", "", audit.ResultError, "supplied-key verification failed")
		return nil, fmt.Errorf("verifying: %w", err)
	}
	metrics.SecretSign.Inc("verify", metrics.ResultSuccess)
	a.recordEventCtx(ctx, ip, audit.ActionSecretSignVerify, "supplied-key", "", audit.ResultSuccess,
		fmt.Sprintf("valid=%v algorithm=%s supplied_key=true", valid, alg))
	return &SignVerifyResult{Valid: valid, Algorithm: string(alg), Hash: hash}, nil
}

// isSignClientErr reports whether a sign/verify error is caused by bad caller
// input (an unsupported/unavailable hash or a mismatched pre-hashed digest)
// rather than an internal/HSM failure, so the transport can map it to 400 /
// InvalidArgument.
func isSignClientErr(err error) bool {
	var sie *secret.SignInputError
	return errors.As(err, &sie)
}

// =========================================================================
// REST handlers
// =========================================================================

type createSigningKeyRequest struct {
	Name      string `json:"name"`
	Algorithm string `json:"algorithm"`
}

type signingKeyResponse struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Algorithm    string `json:"algorithm"`
	KeyType      string `json:"key_type"`
	Provider     string `json:"provider"`
	CreatedBy    string `json:"created_by,omitempty"`
	CreatedAt    string `json:"created_at"`
	PublicKeyPEM string `json:"public_key_pem"`
	PublicKeyDER string `json:"public_key_der"` // base64 SPKI DER
}

func toSigningKeyResponse(info *SigningKeyInfo) signingKeyResponse {
	return signingKeyResponse{
		ID:           info.ID,
		Name:         info.Name,
		Algorithm:    info.Algorithm,
		KeyType:      info.KeyType,
		Provider:     info.Provider,
		CreatedBy:    info.CreatedBy,
		CreatedAt:    info.CreatedAt,
		PublicKeyPEM: info.PublicKeyPEM,
		PublicKeyDER: base64.StdEncoding.EncodeToString(info.PublicKeyDER),
	}
}

// CreateSigningKey handles POST /api/secret/signing-keys.
func (a *API) CreateSigningKey(w http.ResponseWriter, r *http.Request) {
	tenant, _, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	var req createSigningKeyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	info, err := a.CreateSigningKeyOp(r.Context(), clientIP(r), tenant, req.Name, req.Algorithm)
	if err != nil {
		a.writeSecretCryptoError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toSigningKeyResponse(info))
}

// ListSigningKeysHandler handles GET /api/secret/signing-keys.
func (a *API) ListSigningKeysHandler(w http.ResponseWriter, r *http.Request) {
	tenant, _, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	infos, err := a.ListSigningKeysOp(r.Context(), clientIP(r), tenant)
	if err != nil {
		a.writeSecretCryptoError(w, err)
		return
	}
	resp := make([]signingKeyResponse, 0, len(infos))
	for _, info := range infos {
		resp = append(resp, toSigningKeyResponse(info))
	}
	writeJSON(w, http.StatusOK, map[string]any{"signing_keys": resp})
}

// GetSigningKey handles GET /api/secret/signing-keys/{name} — metadata plus the
// exported public key (SPKI PEM and base64 DER) for external verifiers.
func (a *API) GetSigningKey(w http.ResponseWriter, r *http.Request) {
	tenant, _, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	info, err := a.GetSigningKeyPublicOp(r.Context(), clientIP(r), tenant, r.PathValue("name"))
	if err != nil {
		a.writeSecretCryptoError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toSigningKeyResponse(info))
}

type signRequest struct {
	// Message is base64 data to hash and sign. Exactly one of message/digest.
	Message string `json:"message,omitempty"`
	// Digest is a base64 pre-computed digest to sign as-is (set prehashed).
	Digest string `json:"digest,omitempty"`
	// Hash selects the message hash (sha256|sha384|sha512); empty = algorithm default.
	Hash string `json:"hash,omitempty"`
}

type signResponse struct {
	Signature string `json:"signature"` // base64
	Algorithm string `json:"algorithm"`
	Hash      string `json:"hash"`
	Key       string `json:"key"`
}

// SignWithKey handles POST /api/secret/signing-keys/{name}/sign.
func (a *API) SignWithKey(w http.ResponseWriter, r *http.Request) {
	tenant, _, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	var req signRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSignData*2)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	message, digest, err := decodeMessageDigest(w, req.Message, req.Digest)
	if err != nil {
		return // decodeMessageDigest already wrote the error
	}
	res, err := a.SignOp(r.Context(), clientIP(r), tenant, r.PathValue("name"), message, digest, req.Hash)
	if err != nil {
		a.writeSecretCryptoError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, signResponse{
		Signature: base64.StdEncoding.EncodeToString(res.Signature),
		Algorithm: res.Algorithm,
		Hash:      res.Hash,
		Key:       res.KeyName,
	})
}

type verifyRequest struct {
	Message   string `json:"message,omitempty"`
	Digest    string `json:"digest,omitempty"`
	Signature string `json:"signature"` // base64
	Hash      string `json:"hash,omitempty"`
}

type verifyResponse struct {
	Valid     bool   `json:"valid"`
	Algorithm string `json:"algorithm"`
}

// VerifyWithKey handles POST /api/secret/signing-keys/{name}/verify.
func (a *API) VerifyWithKey(w http.ResponseWriter, r *http.Request) {
	tenant, _, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	var req verifyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSignData*3)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	message, digest, err := decodeMessageDigest(w, req.Message, req.Digest)
	if err != nil {
		return // decodeMessageDigest already wrote the error
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "signature must be base64: %v", err)
		return
	}
	res, err := a.VerifySignatureOp(r.Context(), clientIP(r), tenant, r.PathValue("name"), message, digest, sig, req.Hash)
	if err != nil {
		a.writeSecretCryptoError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{Valid: res.Valid, Algorithm: res.Algorithm})
}

type verifyStandaloneRequest struct {
	// Algorithm is the signing algorithm the signature was produced under.
	Algorithm string `json:"algorithm"`
	// Supply the public key as SPKI in exactly one of PEM or base64 DER.
	PublicKeyPEM string `json:"public_key_pem,omitempty"`
	PublicKeyDER string `json:"public_key_der,omitempty"`
	Message      string `json:"message,omitempty"`
	Digest       string `json:"digest,omitempty"`
	Signature    string `json:"signature"` // base64
	Hash         string `json:"hash,omitempty"`
}

// VerifyStandalone handles POST /api/secret/verify — verify a signature against a
// caller-supplied public key (SPKI PEM or DER) and algorithm, without a stored
// key. Uses only public material, so it needs no HSM and is not quota-metered.
func (a *API) VerifyStandalone(w http.ResponseWriter, r *http.Request) {
	tenant, _, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	var req verifyStandaloneRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSignData*3)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	message, digest, err := decodeMessageDigest(w, req.Message, req.Digest)
	if err != nil {
		return // decodeMessageDigest already wrote the error
	}
	sig, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		writeError(w, http.StatusBadRequest, "signature must be base64: %v", err)
		return
	}
	// The DER form is base64 at the transport layer; an empty field decodes to nil
	// (treated as "not supplied", enforced after the authz gate inside the Op). A
	// malformed base64 is a transport parse error (400), like malformed JSON.
	var derBytes []byte
	if req.PublicKeyDER != "" {
		if derBytes, err = base64.StdEncoding.DecodeString(req.PublicKeyDER); err != nil {
			writeError(w, http.StatusBadRequest, "public_key_der must be base64: %v", err)
			return
		}
	}
	res, err := a.VerifyWithSuppliedKeyOp(r.Context(), clientIP(r), tenant, req.Algorithm, []byte(req.PublicKeyPEM), derBytes, message, digest, sig, req.Hash)
	if err != nil {
		a.writeSecretCryptoError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, verifyResponse{Valid: res.Valid, Algorithm: res.Algorithm})
}

// resolveSuppliedPublicKey selects the supplied public-key bytes from exactly one
// of the PEM or (already-decoded) DER forms. It is called inside the Op, after the
// authorization check, so a missing/ambiguous key is a 400 only for a caller who
// could otherwise have verified. PEM is returned verbatim (secret.ParsePublicKey
// accepts PEM or DER).
func resolveSuppliedPublicKey(pemBytes, derBytes []byte) ([]byte, error) {
	switch {
	case len(pemBytes) > 0 && len(derBytes) > 0:
		return nil, &secretClientError{"set exactly one of public_key_pem or public_key_der"}
	case len(pemBytes) > 0:
		return pemBytes, nil
	case len(derBytes) > 0:
		return derBytes, nil
	default:
		return nil, &secretClientError{"one of public_key_pem or public_key_der is required"}
	}
}

// decodeMessageDigest base64-decodes the message and digest request fields
// (each optional here — the Op enforces that exactly one is present, AFTER the
// authorization check). On a base64-format error it writes a 400 and returns a
// non-nil error so the caller returns without invoking the Op. An empty field
// decodes to an empty slice, which the Op treats as "not supplied".
func decodeMessageDigest(w http.ResponseWriter, message, digest string) (msg, dig []byte, err error) {
	if message != "" {
		if msg, err = base64.StdEncoding.DecodeString(message); err != nil {
			writeError(w, http.StatusBadRequest, "message must be base64: %v", err)
			return nil, nil, err
		}
	}
	if digest != "" {
		if dig, err = base64.StdEncoding.DecodeString(digest); err != nil {
			writeError(w, http.StatusBadRequest, "digest must be base64: %v", err)
			return nil, nil, err
		}
	}
	return msg, dig, nil
}

// resolveSignData selects the data to sign/verify from the (already-decoded)
// message and digest, enforcing that exactly one is supplied. A non-empty digest
// means the caller pre-hashed the data, so it is used verbatim. It is called
// inside the Ops, after the authorization check, so a missing/ambiguous body is a
// 400 only for a caller who could otherwise have signed.
func resolveSignData(message, digest []byte) (data []byte, preHashed bool, err error) {
	switch {
	case len(message) > 0 && len(digest) > 0:
		return nil, false, &secretClientError{"set exactly one of message or digest, not both"}
	case len(message) > 0:
		if len(message) > maxSignData {
			return nil, false, &secretClientError{fmt.Sprintf("message exceeds %d bytes", maxSignData)}
		}
		return message, false, nil
	case len(digest) > 0:
		return digest, true, nil
	default:
		return nil, false, &secretClientError{"one of message or digest is required"}
	}
}
