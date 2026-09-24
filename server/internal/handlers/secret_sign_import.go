package handlers

// REST counterpart of `secsy-secret signing-key import` (Task 198) — adopting an
// existing application signing key into the named-signing-key registry.
//
// The CLI copy (cmd/secsy-secret/signimport.go) was written deliberately
// shell-only, on the same argument `secsy-ca import-key` made: raw private key
// material should not travel over a network API. Task 198 answered that argument
// for the CA-side imports (see the header of keyimport_admin.go) and the answer is
// identical here — the key is already a file on a machine, already being copied,
// and the console session is the same mutually-authenticated, audited channel
// through which the operator can already make this service sign anything. What
// refusing the endpoint actually buys is a migration performed over ssh with no
// event-log entry naming the operator who did it.
//
// So the endpoint exists, and it carries the stricter contract that follows from
// carrying key material, exactly as the CA-side imports do: the body is
// size-limited before it is decoded, and no field of it is ever echoed in a
// response, written to an audit detail, or logged. The key material half of the
// request is the shared keyMaterial type from keyimport_admin.go, so there is one
// decoder, one passphrase story and one set of "it is encrypted" / "the
// passphrase is wrong" messages across every import this server accepts.
//
// Everything after the parse mirrors CreateSigningKey: the same tenant
// resolution, the same privileged secret:signing-key gate, the same response
// shape and the same 201. An adopted key is a registry row indistinguishable
// from a generated one, and sign / verify / public-key export treat it as such.
// The one difference is one the import cannot undo and does not hide: the key
// existed outside the provider before it arrived, so hardware attestation will
// report it as imported rather than generated (the Secrets view's panel says so,
// as the CLI says it on stderr).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/secret"
)

// ImportSigningKeyRequest is the body of POST /api/secret/signing-keys/import,
// the REST form of `secsy-secret signing-key import`. The embedded keyMaterial
// carries the private half; none of its fields is ever echoed, logged or audited.
type ImportSigningKeyRequest struct {
	// Name is the tenant-unique name the adopted key is registered under.
	Name string `json:"name"`
	// Algorithm fixes the signature scheme. It may be omitted for ECDSA and
	// Ed25519, where the key material determines it; an RSA key must name one,
	// because the same key works with PSS or PKCS#1 v1.5 and the choice has to
	// match whatever the existing verifiers already do.
	Algorithm string `json:"algorithm,omitempty"`

	keyMaterial
}

// ImportSigningKeyOp adopts existing private key material as a named signing key.
// It is the import twin of CreateSigningKeyOp and authorizes identically — the
// privileged secret:signing-key capability on the caller's tenant, checked
// FIRST — then records the audit event and metric and returns the key's public
// view. The material is written into the provider non-extractable and proved
// usable there by secret.ImportSigningKey before any row claims it works.
//
// The gate comes before every piece of validation for the reason
// CreateSigningKeyOp orders itself the same way — a caller lacking the capability
// must always see 403, never a hint that its body was wrong — and here it buys
// something more: an unauthorized caller's key material is never base64-decoded,
// never decrypted and never parsed by this process.
func (a *API) ImportSigningKeyOp(ctx context.Context, ip string, tenant *models.Tenant, req ImportSigningKeyRequest) (*SigningKeyInfo, error) {
	name := req.Name
	if !a.canOnSigningKey(ctx, tenant.ID, name, rbac.ActionManageSigningKey) {
		metrics.SecretSigningKey.Inc(metrics.ResultDenied)
		a.recordEventCtx(ctx, ip, audit.ActionSecretSigningKeyImport, name, "", audit.ResultDenied, "secret:signing-key capability required")
		return nil, &secretForbiddenError{fmt.Sprintf("secret:signing-key capability required for tenant %q, or an admin grant on signing-key/%s", tenant.ID, name)}
	}
	// Unlike creation, the algorithm is optional: an ECDSA or Ed25519 key fully
	// determines it, and only RSA forces the choice (enforced inside
	// secret.ImportSigningKey, so both surfaces say the same thing).
	var alg secret.SigningAlgorithm
	if strings.TrimSpace(req.Algorithm) != "" {
		normalized, err := secret.NormalizeSigningAlgorithm(req.Algorithm)
		if err != nil {
			return nil, &secretClientError{err.Error()}
		}
		alg = normalized
	}
	if name == "" {
		return nil, &secretClientError{"name is required"}
	}
	if !req.present() {
		return nil, &secretClientError{"key_pem or key_base64 is required"}
	}
	// A backend that cannot adopt a key at all (the cloud-KMS providers) says so
	// before the material is decoded in this process.
	if !keyprovider.CanImport(a.keyProvider) {
		return nil, &secretClientError{fmt.Sprintf(
			"the %s key provider cannot import an existing key; create the signing key instead, or use the backend's own bring-your-own-key procedure",
			a.keyProvider.Name())}
	}
	// parse() turns "it is encrypted" and "the passphrase is wrong" into advice
	// rather than a parse error, and never quotes the input in the message.
	parsed, err := req.parse()
	if err != nil {
		return nil, &secretClientError{err.Error()}
	}

	a.consumeHSMAuditLogs("")
	row, err := secret.ImportSigningKey(ctx, a.keyProvider, a.db, secret.ImportSigningKeySpec{
		TenantID:   tenant.ID,
		Name:       name,
		PrivateKey: parsed.Key,
		Algorithm:  alg,
		CreatedBy:  ctxActor(ctx),
	})
	a.consumeHSMAuditLogs("")
	if err != nil {
		metrics.SecretSigningKey.Inc(metrics.ResultError)
		if errors.Is(err, secret.ErrSigningKeyNameTaken) || errors.Is(err, database.ErrSigningKeyExists) {
			a.recordEventCtx(ctx, ip, audit.ActionSecretSigningKeyImport, name, "", audit.ResultError, "name already exists")
			return nil, &secretConflictError{fmt.Sprintf("a signing key named %q already exists", name)}
		}
		// Only the failures the caller's material decided are a bad request: an
		// unsupported key type, an RSA key with no algorithm named, a mismatched
		// algorithm (secret.ErrSigningKeyMaterial), and the host-side crypto-policy
		// and key-quality gates keyprovider.ImportKey runs before it touches the
		// backend (keyprovider.ErrImportRejected). That is the same set
		// POST /api/keys/import answers 400 for, matched on the sentinels rather
		// than on message text.
		//
		// EVERYTHING else is ours and must be 500, exactly as the sibling
		// CreateSigningKeyOp classifies the same set. The registry INSERT is why
		// this matters: it runs after the key is already in the provider, so telling
		// the operator "bad request" invites a retry of the same body — and a retry
		// mints a fresh id, hence a fresh label, hence another stranded
		// non-extractable key on a device nobody can delete from.
		var apiErr error
		switch {
		case errors.Is(err, secret.ErrSigningKeyMaterial),
			errors.Is(err, keyprovider.ErrImportRejected),
			errors.Is(err, keyprovider.ErrImportUnsupported):
			apiErr = &secretClientError{err.Error()}
		default:
			apiErr = fmt.Errorf("importing the signing key: %w", err)
		}
		// The detail is the same sentence the caller is given: if it is safe to
		// return it is safe to log, and an operator triaging a stranded key needs the
		// reason in the event log rather than in someone's HTTP transcript. None of
		// these messages quotes the key material (both packages take care not to).
		a.recordEventCtx(ctx, ip, audit.ActionSecretSigningKeyImport, name, "", audit.ResultError, apiErr.Error())
		return nil, apiErr
	}
	metrics.SecretSigningKey.Inc(metrics.ResultSuccess)
	// The detail records the shape of the import, never the material: the fixed
	// algorithm, the key type, the encoding it arrived in, and the backend that
	// now holds it.
	a.recordEventCtx(ctx, ip, audit.ActionSecretSigningKeyImport, name, row.ID, audit.ResultSuccess,
		fmt.Sprintf("algorithm=%s key_type=%s id=%s source_format=%s provider=%s imported=true",
			row.Algorithm, row.KeyType, row.ID, parsed.Format, row.Provider))
	return signingKeyInfo(row)
}

// ImportSigningKeyHandler handles POST /api/secret/signing-keys/import.
//
// The response is the same signingKeyResponse, with the same 201, that
// POST /api/secret/signing-keys returns: the request carried a private key, and
// nothing about it — not the PEM, not the base64, not the passphrase — comes back.
func (a *API) ImportSigningKeyHandler(w http.ResponseWriter, r *http.Request) {
	tenant, _, err := a.resolveSecretTenant(r)
	if err != nil {
		writeSecretTenantError(w, err)
		return
	}
	// Size-limited before the decoder sees it, because the body carries key
	// material: maxKeyImportBody is the same 1 MiB cap the CA-side imports use,
	// which is ample for an encrypted PKCS#12 holding an RSA-4096 key.
	var req ImportSigningKeyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxKeyImportBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	info, err := a.ImportSigningKeyOp(r.Context(), clientIP(r), tenant, req)
	if err != nil {
		a.writeSecretCryptoError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toSigningKeyResponse(info))
}
