package handlers

// Stateless (non-storing) crypto service on the secret layer (Task 138),
// rounding out /api/secret/encrypt|decrypt|rewrap with the three operations a
// Vault-Transit-style "encryption as a service" is expected to offer:
//
//   - data-key generation (/api/secret/datakey): the server mints a fresh data
//     key and returns it BOTH in the clear (for immediate client-side use) and
//     wrapped as an ordinary envelope under the family KEK, from which the same
//     key is later recovered via /api/secret/decrypt. Nothing is stored.
//   - keyed HMAC (/api/secret/hmac, /api/secret/hmac/verify): a MAC over
//     caller-supplied data with an HSM/KEK-derived, versioned MAC key whose seed
//     lives only sealed under the KEK.
//   - CSPRNG random bytes (/api/secret/random): random bytes sourced from the
//     keyprovider/HSM RNG when available, else the OS CSPRNG.
//
// Every operation authorizes against the caller's tenant, meters the per-tenant
// daily secret-op quota (except the cheap RNG draw), appends a tamper-evident
// audit event, and increments Prometheus counters. The core methods are shared
// verbatim by the gRPC SecretService so both transports enforce identical
// semantics.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

const (
	// maxRandomBytes bounds a single random-bytes request. The service is for
	// keys, nonces, and salts — not bulk streams — so a small cap keeps an
	// authenticated caller from draining the HSM RNG or forcing large allocations.
	maxRandomBytes = 1024
	// maxHMACData bounds the data a keyed-HMAC request may cover, matching the
	// secret-plaintext cap (this is a small-message MAC service, not bulk hashing).
	maxHMACData = maxSecretPlaintext
	// randomSourceHSM / randomSourceSoftware label where random bytes came from.
	randomSourceHSM      = "hsm"
	randomSourceSoftware = "software"
)

// --- error taxonomy shared by the REST handlers and the gRPC SecretService ---

// secretForbiddenError marks an authorization denial (mapped to 403 /
// PermissionDenied). The message names the capability and tenant.
type secretForbiddenError struct{ msg string }

func (e *secretForbiddenError) Error() string { return e.msg }

// secretClientError marks a caller-caused validation failure (mapped to 400 /
// InvalidArgument).
type secretClientError struct{ msg string }

func (e *secretClientError) Error() string { return e.msg }

// SecretErrorKind classifies a stateless-crypto-service error returned by the
// shared core methods so a non-HTTP transport (the gRPC SecretService) can map
// it to the right status code without importing the unexported error types. It
// returns one of "forbidden", "bad_request", "quota", or "internal".
func SecretErrorKind(err error) string {
	var fe *secretForbiddenError
	var ce *secretClientError
	var suspended *models.TenantSuspendedError
	var quota *models.QuotaExceededError
	switch {
	case errors.As(err, &fe), errors.As(err, &suspended):
		return "forbidden"
	case errors.As(err, &ce):
		return "bad_request"
	case errors.As(err, &quota):
		return "quota"
	default:
		return "internal"
	}
}

// writeSecretCryptoError maps a core error to an HTTP response, reusing the
// shared classification so REST and gRPC never diverge.
func (a *API) writeSecretCryptoError(w http.ResponseWriter, err error) {
	switch SecretErrorKind(err) {
	case "forbidden":
		writeError(w, http.StatusForbidden, "%s", err.Error())
	case "bad_request":
		writeError(w, http.StatusBadRequest, "%s", err.Error())
	case "quota":
		if writeTenantLimitError(w, err) { // 429 + Retry-After
			return
		}
		writeError(w, http.StatusTooManyRequests, "%s", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "%s", err.Error())
	}
}

// secretResult maps an operation error to a metrics success/error label.
func secretResult(err error) string {
	if err != nil {
		return metrics.ResultError
	}
	return metrics.ResultSuccess
}

// SecretEnabled reports whether the secret/crypto service is configured (a KEK
// is present). Exposed for the gRPC SecretService to fail cleanly when disabled.
func (a *API) SecretEnabled() bool { return a.secretEnabled() }

// ResolveSecretTenant maps an explicit tenant selector to its record and KEK
// label, stamping the tenant on ctx. It is the exported form of
// resolveSecretTenantSel for the gRPC SecretService.
func (a *API) ResolveSecretTenant(ctx context.Context, sel string) (*models.Tenant, string, error) {
	return a.resolveSecretTenantSel(ctx, sel)
}

// randomBytes draws n cryptographically-strong random bytes, preferring the
// keyprovider/HSM RNG (RandomProvider) and falling back to the OS CSPRNG for
// availability — including for backends with no hardware RNG, which report
// ErrRandomUnsupported. It returns the bytes and the source label so the caller
// can report and meter where the entropy came from.
func (a *API) randomBytes(ctx context.Context, n int) ([]byte, string, error) {
	if rp, ok := a.keyProvider.(keyprovider.RandomProvider); ok {
		b, err := rp.Random(ctx, n)
		if err == nil && len(b) == n {
			return b, randomSourceHSM, nil
		}
		// Any error (a real HSM fault or ErrRandomUnsupported on a non-HSM backend)
		// falls through to the OS CSPRNG so the service stays available.
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, "", fmt.Errorf("reading random bytes: %w", err)
	}
	return b, randomSourceSoftware, nil
}

// dataKeyBytes maps a requested key strength in bits to a byte length, accepting
// only the AES key sizes so a caller cannot request an off-size key.
func dataKeyBytes(bits int) (int, error) {
	switch bits {
	case 128:
		return 16, nil
	case 256:
		return 32, nil
	case 512:
		return 64, nil
	default:
		return 0, fmt.Errorf("bits must be 128, 256, or 512, got %d", bits)
	}
}

// =========================================================================
// Data-key generation
// =========================================================================

// DataKeyResult is the outcome of a data-key mint, shared by REST and gRPC.
type DataKeyResult struct {
	// Plaintext is the fresh data key in the clear. It is nil when the caller
	// requested wrapped-only output. Callers must zeroize it after use.
	Plaintext []byte
	// Envelope is the serialized JSON envelope wrapping the same data key under
	// the family KEK; presenting it to Decrypt recovers the key.
	Envelope   []byte
	Bits       int
	KEKLabel   string
	KEKVersion int
}

// GenerateDataKeyOp mints a fresh data key of the requested strength and wraps it
// as an ordinary envelope under the tenant's family KEK. It is the shared core
// behind the REST and gRPC data-key endpoints: it authorizes secret:datakey,
// meters the daily secret-op quota, sources the key from the HSM RNG when
// available, records the audit event and metric, and returns both forms. The
// plaintext is never persisted; the wrapped form is recovered later via Decrypt.
func (a *API) GenerateDataKeyOp(ctx context.Context, ip string, tenant *models.Tenant, kekLabel string, bits int, encContext []byte, wrappedOnly bool) (*DataKeyResult, error) {
	if !a.canInTenant(middleware.GetUserInfo(ctx), tenant.ID, rbac.ActionDataKey) {
		metrics.SecretDataKey.Inc(metrics.ResultDenied)
		a.recordEventCtx(ctx, ip, audit.ActionSecretDataKey, kekLabel, "", audit.ResultDenied, "secret:datakey capability required")
		return nil, &secretForbiddenError{fmt.Sprintf("secret:datakey capability required for tenant %q", tenant.ID)}
	}
	nbytes, err := dataKeyBytes(bits)
	if err != nil {
		return nil, &secretClientError{err.Error()}
	}
	ring, err := a.secretRingCtx(ctx, kekLabel)
	if err != nil {
		return nil, fmt.Errorf("secret service unavailable: %w", err)
	}
	quotaDone, err := a.consumeSecretOpQuotaCtx(ctx, ip, tenant, "datakey")
	if err != nil {
		metrics.SecretDataKey.Inc(metrics.ResultDenied)
		return nil, err
	}

	key, _, err := a.randomBytes(ctx, nbytes)
	if err != nil {
		quotaDone(err)
		metrics.SecretDataKey.Inc(metrics.ResultError)
		a.recordEventCtx(ctx, ip, audit.ActionSecretDataKey, kekLabel, "", audit.ResultError, "data-key generation failed")
		return nil, fmt.Errorf("generating data key: %w", err)
	}

	a.consumeHSMAuditLogs("")
	env, err := ring.EncryptToJSON(key, encContext)
	a.consumeHSMAuditLogs("")
	quotaDone(err)
	metrics.SecretDataKey.Inc(secretResult(err))
	if err != nil {
		zeroBytes(key)
		a.recordEventCtx(ctx, ip, audit.ActionSecretDataKey, kekLabel, "", audit.ResultError, "data-key wrap failed")
		return nil, fmt.Errorf("wrapping data key: %w", err)
	}

	info := ring.Active().KEKInfo()
	a.recordEventCtx(ctx, ip, audit.ActionSecretDataKey, kekLabel, "", audit.ResultSuccess,
		fmt.Sprintf("bits=%d wrapped_only=%v", bits, wrappedOnly))
	res := &DataKeyResult{Envelope: env, Bits: bits, KEKLabel: info.Label, KEKVersion: info.Version}
	if wrappedOnly {
		zeroBytes(key)
	} else {
		res.Plaintext = key
	}
	return res, nil
}

type dataKeyRequest struct {
	// Bits is the data-key strength: 128, 256 (default), or 512.
	Bits int `json:"bits,omitempty"`
	// Context, if set, is base64 AAD bound to the wrapped form; it must be
	// presented verbatim to Decrypt to recover the key.
	Context string `json:"context,omitempty"`
	// WrappedOnly omits the plaintext key from the response, returning only the
	// wrapped envelope (mirrors Vault Transit's datakey/wrapped mode).
	WrappedOnly bool `json:"wrapped_only,omitempty"`
}

type dataKeyResponse struct {
	// Plaintext is the base64 data key, omitted when wrapped_only was requested.
	Plaintext string `json:"plaintext,omitempty"`
	// Wrapped is the envelope to store and later POST to /api/secret/decrypt.
	Wrapped    json.RawMessage `json:"wrapped"`
	Bits       int             `json:"bits"`
	KEKLabel   string          `json:"kek_label"`
	KEKVersion int             `json:"kek_version"`
}

// GenerateDataKey handles POST /api/secret/datakey.
func (a *API) GenerateDataKey(w http.ResponseWriter, r *http.Request) {
	tenant, kekLabel, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	var req dataKeyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	bits := req.Bits
	if bits == 0 {
		bits = 256
	}
	var encContext []byte
	if req.Context != "" {
		encContext, err = base64.StdEncoding.DecodeString(req.Context)
		if err != nil {
			writeError(w, http.StatusBadRequest, "context must be base64: %v", err)
			return
		}
	}
	res, err := a.GenerateDataKeyOp(r.Context(), clientIP(r), tenant, kekLabel, bits, encContext, req.WrappedOnly)
	if err != nil {
		a.writeSecretCryptoError(w, err)
		return
	}
	resp := dataKeyResponse{
		Wrapped:    json.RawMessage(res.Envelope),
		Bits:       res.Bits,
		KEKLabel:   res.KEKLabel,
		KEKVersion: res.KEKVersion,
	}
	if res.Plaintext != nil {
		resp.Plaintext = base64.StdEncoding.EncodeToString(res.Plaintext)
		zeroBytes(res.Plaintext)
	}
	writeJSON(w, http.StatusOK, resp)
}

// =========================================================================
// Keyed HMAC
// =========================================================================

// HMACResult is the outcome of a keyed-HMAC generate, shared by REST and gRPC.
type HMACResult struct {
	MAC        []byte
	KeyVersion int
	Algorithm  string
}

// HMACVerifyResult is the outcome of a keyed-HMAC verify, shared by REST/gRPC.
type HMACVerifyResult struct {
	Valid      bool
	KeyVersion int
}

// macSeedRand adapts the HSM-preferred random source to the seed-generator
// signature the secret package's MAC helpers expect (dropping the source label).
func (a *API) macSeedRand(ctx context.Context) func(n int) ([]byte, error) {
	return func(n int) ([]byte, error) {
		b, _, err := a.randomBytes(ctx, n)
		return b, err
	}
}

// GenerateHMACOp computes a keyed HMAC over data with the family's active MAC
// key, provisioning one on first use. It authorizes secret:hmac, meters the
// daily secret-op quota, records the audit event and metric, and returns the tag
// with the key version so verification is unambiguous.
func (a *API) GenerateHMACOp(ctx context.Context, ip string, tenant *models.Tenant, kekLabel string, data []byte) (*HMACResult, error) {
	if !a.canInTenant(middleware.GetUserInfo(ctx), tenant.ID, rbac.ActionHMAC) {
		metrics.SecretHMAC.Inc("generate", metrics.ResultDenied)
		a.recordEventCtx(ctx, ip, audit.ActionSecretHMAC, kekLabel, "", audit.ResultDenied, "secret:hmac capability required")
		return nil, &secretForbiddenError{fmt.Sprintf("secret:hmac capability required for tenant %q", tenant.ID)}
	}
	if len(data) == 0 {
		return nil, &secretClientError{"data is required"}
	}
	ring, err := a.secretRingCtx(ctx, kekLabel)
	if err != nil {
		return nil, fmt.Errorf("secret service unavailable: %w", err)
	}
	quotaDone, err := a.consumeSecretOpQuotaCtx(ctx, ip, tenant, "hmac")
	if err != nil {
		metrics.SecretHMAC.Inc("generate", metrics.ResultDenied)
		return nil, err
	}

	a.consumeHSMAuditLogs("")
	active, err := secret.EnsureActiveMACKey(ctx, a.db, ring, kekLabel, a.macSeedRand(ctx))
	if err != nil {
		a.consumeHSMAuditLogs("")
		quotaDone(err)
		metrics.SecretHMAC.Inc("generate", metrics.ResultError)
		a.recordEventCtx(ctx, ip, audit.ActionSecretHMAC, kekLabel, "", audit.ResultError, "MAC key unavailable")
		return nil, err
	}
	mac, err := secret.TagHMAC(ctx, ring, active, data)
	a.consumeHSMAuditLogs("")
	if err != nil {
		quotaDone(err)
		metrics.SecretHMAC.Inc("generate", metrics.ResultError)
		a.recordEventCtx(ctx, ip, audit.ActionSecretHMAC, kekLabel, "", audit.ResultError, "MAC computation failed")
		return nil, err
	}
	quotaDone(nil)
	metrics.SecretHMAC.Inc("generate", metrics.ResultSuccess)
	a.recordEventCtx(ctx, ip, audit.ActionSecretHMAC, kekLabel, "", audit.ResultSuccess,
		fmt.Sprintf("version=%d alg=%s", active.Version, secret.HMACAlgSHA256))
	return &HMACResult{MAC: mac, KeyVersion: active.Version, Algorithm: secret.HMACAlgSHA256}, nil
}

// VerifyHMACOp recomputes the keyed HMAC for the requested MAC-key version (the
// active version when unset) and constant-time compares it to the supplied tag.
// A missing/unknown version or a mismatch is a valid=false RESULT, not an error;
// only authorization, quota, and HSM failures are errors.
func (a *API) VerifyHMACOp(ctx context.Context, ip string, tenant *models.Tenant, kekLabel string, data, mac []byte, keyVersion int) (*HMACVerifyResult, error) {
	if !a.canInTenant(middleware.GetUserInfo(ctx), tenant.ID, rbac.ActionHMAC) {
		metrics.SecretHMAC.Inc("verify", metrics.ResultDenied)
		a.recordEventCtx(ctx, ip, audit.ActionSecretHMACVerify, kekLabel, "", audit.ResultDenied, "secret:hmac capability required")
		return nil, &secretForbiddenError{fmt.Sprintf("secret:hmac capability required for tenant %q", tenant.ID)}
	}
	if len(data) == 0 {
		return nil, &secretClientError{"data is required"}
	}
	if len(mac) == 0 {
		return nil, &secretClientError{"hmac is required"}
	}
	ring, err := a.secretRingCtx(ctx, kekLabel)
	if err != nil {
		return nil, fmt.Errorf("secret service unavailable: %w", err)
	}
	quotaDone, err := a.consumeSecretOpQuotaCtx(ctx, ip, tenant, "hmac")
	if err != nil {
		metrics.SecretHMAC.Inc("verify", metrics.ResultDenied)
		return nil, err
	}

	// Resolve the MAC-key version to verify against: an explicit version (as
	// returned by generate) or the active one. A version that was never
	// provisioned cannot verify and yields valid=false rather than an error, so
	// the endpoint is not an existence oracle over versions.
	version := keyVersion
	if version <= 0 {
		active, aerr := a.db.GetActiveMACKey(kekLabel)
		if aerr != nil {
			quotaDone(aerr)
			metrics.SecretHMAC.Inc("verify", metrics.ResultError)
			return nil, fmt.Errorf("reading MAC key state: %w", aerr)
		}
		if active == nil {
			return a.hmacVerifyResult(ctx, ip, kekLabel, quotaDone, false, 0), nil
		}
		version = active.Version
	}
	row, err := a.db.GetMACKeyVersion(kekLabel, version)
	if err != nil {
		quotaDone(err)
		metrics.SecretHMAC.Inc("verify", metrics.ResultError)
		return nil, fmt.Errorf("reading MAC key version: %w", err)
	}
	if row == nil {
		return a.hmacVerifyResult(ctx, ip, kekLabel, quotaDone, false, version), nil
	}
	a.consumeHSMAuditLogs("")
	valid, err := secret.CheckHMAC(ctx, ring, row, data, mac)
	a.consumeHSMAuditLogs("")
	if err != nil {
		quotaDone(err)
		metrics.SecretHMAC.Inc("verify", metrics.ResultError)
		a.recordEventCtx(ctx, ip, audit.ActionSecretHMACVerify, kekLabel, "", audit.ResultError, "MAC verification failed")
		return nil, err
	}
	return a.hmacVerifyResult(ctx, ip, kekLabel, quotaDone, valid, version), nil
}

// hmacVerifyResult finalizes a verify: it commits the quota, meters the (always
// successful) operation, records the outcome, and returns the result value.
func (a *API) hmacVerifyResult(ctx context.Context, ip, kekLabel string, quotaDone func(error), valid bool, version int) *HMACVerifyResult {
	quotaDone(nil)
	metrics.SecretHMAC.Inc("verify", metrics.ResultSuccess)
	a.recordEventCtx(ctx, ip, audit.ActionSecretHMACVerify, kekLabel, "", audit.ResultSuccess,
		fmt.Sprintf("valid=%v version=%d", valid, version))
	return &HMACVerifyResult{Valid: valid, KeyVersion: version}
}

type hmacRequest struct {
	Data string `json:"data"` // base64
}

type hmacResponse struct {
	HMAC      string `json:"hmac"` // base64
	Version   int    `json:"version"`
	Algorithm string `json:"algorithm"`
}

// GenerateHMAC handles POST /api/secret/hmac.
func (a *API) GenerateHMAC(w http.ResponseWriter, r *http.Request) {
	tenant, kekLabel, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	var req hmacRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxHMACData*2)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "data must be base64: %v", err)
		return
	}
	if len(data) > maxHMACData {
		writeError(w, http.StatusRequestEntityTooLarge, "data exceeds %d bytes", maxHMACData)
		return
	}
	res, err := a.GenerateHMACOp(r.Context(), clientIP(r), tenant, kekLabel, data)
	if err != nil {
		a.writeSecretCryptoError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hmacResponse{
		HMAC:      base64.StdEncoding.EncodeToString(res.MAC),
		Version:   res.KeyVersion,
		Algorithm: res.Algorithm,
	})
}

type hmacVerifyRequest struct {
	Data    string `json:"data"`              // base64
	HMAC    string `json:"hmac"`              // base64
	Version int    `json:"version,omitempty"` // MAC key version from generate
}

type hmacVerifyResponse struct {
	Valid   bool `json:"valid"`
	Version int  `json:"version"`
}

// VerifyHMAC handles POST /api/secret/hmac/verify.
func (a *API) VerifyHMAC(w http.ResponseWriter, r *http.Request) {
	tenant, kekLabel, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	var req hmacVerifyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxHMACData*3)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		writeError(w, http.StatusBadRequest, "data must be base64: %v", err)
		return
	}
	if len(data) > maxHMACData {
		writeError(w, http.StatusRequestEntityTooLarge, "data exceeds %d bytes", maxHMACData)
		return
	}
	mac, err := base64.StdEncoding.DecodeString(req.HMAC)
	if err != nil {
		writeError(w, http.StatusBadRequest, "hmac must be base64: %v", err)
		return
	}
	res, err := a.VerifyHMACOp(r.Context(), clientIP(r), tenant, kekLabel, data, mac, req.Version)
	if err != nil {
		a.writeSecretCryptoError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, hmacVerifyResponse{Valid: res.Valid, Version: res.KeyVersion})
}

// =========================================================================
// CSPRNG random bytes
// =========================================================================

// RandomResult is the outcome of a random-bytes draw, shared by REST and gRPC.
type RandomResult struct {
	Bytes  []byte
	Source string // "hsm" | "software"
}

// GenerateRandomOp draws numBytes of CSPRNG output, preferring the HSM RNG. It
// authorizes secret:random, records the audit event and metric, and reports the
// entropy source. It does not touch the KEK, so it is not metered against the
// secret-op quota; the byte cap bounds abuse.
func (a *API) GenerateRandomOp(ctx context.Context, ip string, tenant *models.Tenant, numBytes int) (*RandomResult, error) {
	if !a.canInTenant(middleware.GetUserInfo(ctx), tenant.ID, rbac.ActionRandom) {
		metrics.SecretRandom.Inc("none", metrics.ResultDenied)
		a.recordEventCtx(ctx, ip, audit.ActionSecretRandom, "", "", audit.ResultDenied, "secret:random capability required")
		return nil, &secretForbiddenError{fmt.Sprintf("secret:random capability required for tenant %q", tenant.ID)}
	}
	if numBytes <= 0 {
		return nil, &secretClientError{"bytes must be a positive integer"}
	}
	if numBytes > maxRandomBytes {
		return nil, &secretClientError{fmt.Sprintf("bytes must be at most %d", maxRandomBytes)}
	}
	b, source, err := a.randomBytes(ctx, numBytes)
	if err != nil {
		metrics.SecretRandom.Inc("none", metrics.ResultError)
		a.recordEventCtx(ctx, ip, audit.ActionSecretRandom, "", "", audit.ResultError, "random-bytes generation failed")
		return nil, fmt.Errorf("generating random bytes: %w", err)
	}
	metrics.SecretRandom.Inc(source, metrics.ResultSuccess)
	a.recordEventCtx(ctx, ip, audit.ActionSecretRandom, "", "", audit.ResultSuccess,
		fmt.Sprintf("bytes=%d source=%s", numBytes, source))
	return &RandomResult{Bytes: b, Source: source}, nil
}

type randomRequest struct {
	Bytes  int    `json:"bytes"`
	Format string `json:"format,omitempty"` // base64 (default) | hex
}

type randomResponse struct {
	Random string `json:"random"`
	Format string `json:"format"`
	Bytes  int    `json:"bytes"`
	Source string `json:"source"`
}

// GenerateRandom handles POST /api/secret/random.
func (a *API) GenerateRandom(w http.ResponseWriter, r *http.Request) {
	tenant, _, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	var req randomRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4*1024)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	format := req.Format
	if format == "" {
		format = "base64"
	}
	if format != "base64" && format != "hex" {
		writeError(w, http.StatusBadRequest, "format must be base64 or hex")
		return
	}
	res, err := a.GenerateRandomOp(r.Context(), clientIP(r), tenant, req.Bytes)
	if err != nil {
		a.writeSecretCryptoError(w, err)
		return
	}
	defer zeroBytes(res.Bytes)
	encoded := base64.StdEncoding.EncodeToString(res.Bytes)
	if format == "hex" {
		encoded = hex.EncodeToString(res.Bytes)
	}
	writeJSON(w, http.StatusOK, randomResponse{
		Random: encoded,
		Format: format,
		Bytes:  req.Bytes,
		Source: res.Source,
	})
}
