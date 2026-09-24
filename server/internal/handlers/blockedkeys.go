package handlers

// REST surface for the operator-managed compromised-key blocklist (Task 120) —
// the counterpart of `secsy-ca blocked-keys list|add|remove` (Task 198). A key on
// the blocklist is rejected fail-closed by the pre-issuance key-quality gate on
// every issuance surface, so until now the only way to block a leaked key was
// shell access to the CA host: an incident response that the console could not
// offer however it was written.
//
// Entries are keyed by the SubjectPublicKeyInfo SHA-256 fingerprint
// ("SHA256:<base64>") and hold NO key material, and the store is
// deployment-global (a compromised key is compromised for every tenant), which
// is why the mutating endpoints are gated on a platform-wide capability rather
// than a tenant-scoped one.
//
// The fingerprint is always derived with keycheck.Fingerprint /
// keycheck.NormalizeFingerprint — the same helpers the CLI and the issuance gate
// use — so a key blocked through the console, through `secsy-ca`, or named by a
// pre-computed fingerprint resolves to one and the same row.

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/keycheck"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// blockedKeySourceAPI is the default `source` label for an entry created through
// the REST API, mirroring the CLI's "cli" default so the provenance of every row
// is visible in `blocked-keys list`.
const blockedKeySourceAPI = "api"

// BlockedKeyListResponse is the body of GET /api/blocked-keys: every blocklist
// entry newest-first, with the total the CLI's list prints.
type BlockedKeyListResponse struct {
	BlockedKeys []models.BlockedKey `json:"blocked_keys"`
	Total       int                 `json:"total"`
}

// BlockKeyRequest is the body of POST /api/blocked-keys. Exactly one key input
// must be given, mirroring the CLI's mutually-exclusive -cert / -csr / -key /
// -fingerprint flags: naming the key two ways would hide which one the operator
// meant to block.
type BlockKeyRequest struct {
	// Certificate is a PEM (or DER) certificate whose subject public key to block.
	Certificate string `json:"certificate,omitempty"`
	// CSR is a PEM (or DER) PKCS#10 request whose public key to block.
	CSR string `json:"csr,omitempty"`
	// PublicKey is a PEM (or DER) SubjectPublicKeyInfo public key to block.
	PublicKey string `json:"public_key,omitempty"`
	// Fingerprint blocks a key by its pre-computed SubjectPublicKeyInfo SHA-256
	// fingerprint: the canonical "SHA256:<base64>" form, or a hex digest (the
	// colon-grouped form openssl prints is accepted), canonicalized to the exact
	// value keycheck.Fingerprint produces for the key itself.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Reason is the operator's justification, recorded and audited.
	Reason string `json:"reason,omitempty"`
	// Source records where the block originated; defaults to "api".
	Source string `json:"source,omitempty"`
}

// BlockKeyResponse reports the stored entry plus whether this call created it,
// matching the shape of `secsy-ca blocked-keys add -json`.
type BlockKeyResponse struct {
	*models.BlockedKey
	// NewlyAdded is false when the key was already on the blocklist (the request
	// is idempotent: the existing entry, with its original justification and
	// timestamp, is left untouched).
	NewlyAdded bool `json:"newly_added"`
}

// UnblockKeyResponse reports the outcome of a removal.
type UnblockKeyResponse struct {
	// Status is "unblocked" or "not_blocked".
	Status      string `json:"status"`
	Fingerprint string `json:"fingerprint"`
	Removed     bool   `json:"removed"`
}

// ListBlockedKeys handles GET /api/blocked-keys — the REST form of
// `secsy-ca blocked-keys list`. Read-gated (any assigned role): the blocklist
// holds no key material, and an issuer or auditor investigating a rejected
// issuance needs to see whether the key is on it.
func (a *API) ListBlockedKeys(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.canRead(user) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	keys, err := a.db.ListBlockedKeys()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "listing blocked keys: %v", err)
		return
	}
	if keys == nil {
		keys = []models.BlockedKey{}
	}
	writeJSON(w, http.StatusOK, BlockedKeyListResponse{BlockedKeys: keys, Total: len(keys)})
}

// BlockKey handles POST /api/blocked-keys — the REST form of
// `secsy-ca blocked-keys add`. It answers 201 when the entry was created and 200
// when the key was already blocked, so a double-submit from the console is
// idempotent rather than an error.
//
// Authorization is the platform-wide ca:configure capability. Blocking a key
// changes what the CA will certify for EVERY tenant, so it is deployment-wide
// issuance policy — the same capability that governs profiles and restriction
// sets — and deliberately not cert:issue: the ability to mint certificates must
// not carry the ability to un-block a compromised key.
func (a *API) BlockKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionConfigureCA) {
		a.recordEvent(r, audit.ActionKeyBlock, "", "", audit.ResultDenied,
			"ca:configure capability required")
		writeError(w, http.StatusForbidden, "ca:configure capability required (admin role)")
		return
	}

	var req BlockKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	fp, err := resolveBlockedKeyFingerprint(&req)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	source := strings.TrimSpace(req.Source)
	if source == "" {
		source = blockedKeySourceAPI
	}
	rec := &models.BlockedKey{
		Fingerprint: fp,
		Reason:      strings.TrimSpace(req.Reason),
		Source:      source,
		AddedBy:     requestActor(r),
		AddedAt:     time.Now().UTC(),
	}
	added, err := a.db.AddBlockedKey(rec)
	if err != nil {
		a.recordEvent(r, audit.ActionKeyBlock, fp, rec.Reason, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "adding blocked key: %v", err)
		return
	}
	// The same audit action and detail shape the CLI records, so one query over
	// key.block covers both surfaces; only via= distinguishes them.
	a.recordEvent(r, audit.ActionKeyBlock, fp, rec.Reason, audit.ResultSuccess,
		fmt.Sprintf("source=%s newly_added=%t via=api", rec.Source, added))

	if !added {
		// Report the entry that is actually stored (its original justification and
		// timestamp), not the one this request proposed.
		if existing, gerr := a.db.GetBlockedKey(fp); gerr == nil && existing != nil {
			rec = existing
		}
		writeJSON(w, http.StatusOK, BlockKeyResponse{BlockedKey: rec, NewlyAdded: false})
		return
	}
	writeJSON(w, http.StatusCreated, BlockKeyResponse{BlockedKey: rec, NewlyAdded: true})
}

// UnblockKey handles DELETE /api/blocked-keys/{fingerprint} — the REST form of
// `secsy-ca blocked-keys remove`. Like the CLI it is tolerant of a fingerprint
// that is not on the list (200 with removed=false) rather than treating a
// repeated un-block as an error.
//
// The fingerprint may be given in any form keycheck.NormalizeFingerprint
// accepts. The canonical "SHA256:<base64>" form contains standard-alphabet
// base64, so a '/' in the digest must be percent-encoded (%2F) by the client;
// the hex form is path-safe as written.
//
// Authorization is the platform-wide ca:configure capability — un-blocking is
// the more dangerous half of the pair, since it re-admits a key the CA was
// refusing to certify.
func (a *API) UnblockKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.can(user, rbac.ActionConfigureCA) {
		a.recordEvent(r, audit.ActionKeyUnblock, r.PathValue("fingerprint"), "", audit.ResultDenied,
			"ca:configure capability required")
		writeError(w, http.StatusForbidden, "ca:configure capability required (admin role)")
		return
	}

	fp, err := keycheck.NormalizeFingerprint(r.PathValue("fingerprint"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	// The justification for un-blocking is optional and carried as a query
	// parameter, since DELETE bodies are not universally forwarded by proxies.
	reason := strings.TrimSpace(r.URL.Query().Get("reason"))

	removed, err := a.db.RemoveBlockedKey(fp)
	if err != nil {
		a.recordEvent(r, audit.ActionKeyUnblock, fp, reason, audit.ResultError, err.Error())
		writeError(w, http.StatusInternalServerError, "removing blocked key: %v", err)
		return
	}
	if !removed {
		writeJSON(w, http.StatusOK, UnblockKeyResponse{Status: "not_blocked", Fingerprint: fp})
		return
	}
	a.recordEvent(r, audit.ActionKeyUnblock, fp, reason, audit.ResultSuccess, "via=api")
	writeJSON(w, http.StatusOK, UnblockKeyResponse{Status: "unblocked", Fingerprint: fp, Removed: true})
}

// resolveBlockedKeyFingerprint derives the SubjectPublicKeyInfo fingerprint to
// block from exactly one input, mirroring the CLI's resolveBlockFingerprint. A
// supplied fingerprint is canonicalized; a certificate, CSR, or public key is
// parsed and its subject public key fingerprinted with keycheck.Fingerprint —
// the exact value the pre-issuance gate compares against.
func resolveBlockedKeyFingerprint(req *BlockKeyRequest) (string, error) {
	given := 0
	for _, s := range []string{req.Certificate, req.CSR, req.PublicKey, req.Fingerprint} {
		if strings.TrimSpace(s) != "" {
			given++
		}
	}
	switch {
	case given == 0:
		return "", fmt.Errorf("one of certificate, csr, public_key, or fingerprint is required")
	case given > 1:
		return "", fmt.Errorf("give exactly one of certificate, csr, public_key, or fingerprint")
	}

	if strings.TrimSpace(req.Fingerprint) != "" {
		fp, err := keycheck.NormalizeFingerprint(req.Fingerprint)
		if err != nil {
			return "", fmt.Errorf("invalid fingerprint: %w", err)
		}
		return fp, nil
	}

	var (
		pub crypto.PublicKey
		err error
	)
	switch {
	case strings.TrimSpace(req.Certificate) != "":
		var cert *x509.Certificate
		if cert, err = pki.ParseCertificatePEMOrDER(blockedKeyDER(req.Certificate)); err == nil {
			pub = cert.PublicKey
		}
	case strings.TrimSpace(req.CSR) != "":
		// Parsed without verifying the self-signature: a compromised or
		// attacker-generated request is exactly the material an operator needs to
		// block, and only its SubjectPublicKeyInfo is used.
		var csr *x509.CertificateRequest
		if csr, err = x509.ParseCertificateRequest(blockedKeyDER(req.CSR)); err == nil {
			pub = csr.PublicKey
		} else {
			err = fmt.Errorf("parsing csr: %w", err)
		}
	default:
		if pub, err = x509.ParsePKIXPublicKey(blockedKeyDER(req.PublicKey)); err != nil {
			err = fmt.Errorf("parsing public_key (expected a SubjectPublicKeyInfo): %w", err)
		}
	}
	if err != nil {
		return "", err
	}
	fp, err := keycheck.Fingerprint(pub)
	if err != nil {
		return "", fmt.Errorf("fingerprinting public key: %w", err)
	}
	return fp, nil
}

// blockedKeyDER unwraps a caller-supplied artifact to DER. PEM is the form the
// console and every tool emit; a bare base64 body (DER without the armor) is
// also accepted so a copy-pasted blob works, and anything else is handed to the
// parser untouched so it reports the real reason it could not be read.
func blockedKeyDER(s string) []byte {
	s = strings.TrimSpace(s)
	if block, _ := pem.Decode([]byte(s)); block != nil {
		return block.Bytes
	}
	compact := strings.Join(strings.Fields(s), "")
	if der, err := base64.StdEncoding.DecodeString(compact); err == nil && len(der) > 0 {
		return der
	}
	return []byte(s)
}
