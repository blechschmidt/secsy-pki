package handlers

// REST counterparts of `secsy-ca import-key` and `secsy-ca ca import` — bringing
// existing key material under this PKI from the operator console (Task 198).
//
// The CLI copies (cmd/secsy-ca/importkey.go) were written deliberately
// shell-only, on the argument that a private key must never travel over a
// network API. That argument holds for the *general* case and does not hold for
// the migration an operator actually performs: the key is already a file on a
// machine, already being copied, and the console session is the same
// mutually-authenticated, audited, step-up-gated channel through which that
// operator can already make this server sign anything. Refusing the endpoint
// does not keep the key off the wire; it only guarantees the migration happens
// over ssh with no four-eyes gate and no event log entry naming the console
// operator. So these endpoints exist, and they are held to the stricter
// contract that follows from carrying key material:
//
//   - the request body is size-limited before it is decoded;
//   - the key material is never echoed in a response, never written to an audit
//     detail, never put in an approval request's params, and never logged;
//   - every validation the CLI performs runs here, through the same internal
//     packages — including the host-side RSA size/exponent and key-quality gates
//     added in c87439b, which live in internal/keyprovider and internal/ca and
//     are therefore shared rather than re-implemented.
//
// POST /api/keys/import  imports a bare key into a role's provider (hsm:manage)
// POST /api/ca/import    adopts an existing CA, key and certificate (ca:manage
//                        in the target tenant, behind the same four-eyes gate as
//                        init-root)

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/blechschmidt/secsy-pki/server/internal/approval"
	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// maxKeyImportBody bounds an import request. A PKCS#12 container with a full
// chain and an RSA-4096 key is a few tens of kilobytes; 1 MiB leaves room for
// base64 expansion and an unusually long chain while keeping an unauthenticated
// or merely mistaken caller from streaming arbitrary volume into a JSON decoder.
const maxKeyImportBody = 1 << 20

// importProvenanceNotice is the one thing an import cannot give the operator,
// returned in the response so the console can show what the CLI prints to
// stderr (printImportProvenanceNotice in cmd/secsy-ca/importkey.go). Nobody
// should conclude from a 201 that the key is now as trustworthy as one born on
// the device.
const importProvenanceNotice = "An imported key existed outside the provider before it arrived. It is now stored " +
	"with the same protections as a generated key (non-extractable, sensitive), but its origin cannot be undone: " +
	"hardware key attestation will report it as imported rather than generated, and any copy made before the import " +
	"remains a copy. Destroy every remaining copy of the key file once this key has been exercised. " +
	"See docs/hsm/key-attestation.md and docs/ca/import.md."

// softwareProviderNotice is appended when the receiving backend is the software
// keystore, mirroring the CLI's second paragraph: a file-backed import moved the
// key, it did not protect it.
const softwareProviderNotice = " The software keystore stores keys as files: this import moved the key, it did not " +
	"protect it. Configure a PKCS#11 backend for production CA keys."

// keyMaterial is the private-key half of an import request. Exactly one of the
// two encodings is supplied; Passphrase decrypts an encrypted container and is
// the REST analogue of the CLI's -pass-file / SECSY_KEY_PASSPHRASE (which exist
// so a passphrase stays out of the shell history and the process table — here it
// stays out of the URL for the same reason, which is why these endpoints are
// POST-with-body rather than parameterised).
//
// No field of this struct is ever echoed, logged, or audited.
type keyMaterial struct {
	// KeyPEM is the key as text: any PEM form ParsePrivateKey accepts (PKCS#8
	// plain or encrypted, PKCS#1, SEC1, legacy DEK-Info, OpenSSH).
	KeyPEM string `json:"key_pem,omitempty"`
	// KeyBase64 is the base64 of the raw container bytes, for the encodings that
	// are not text: bare DER and PKCS#12/PFX. (A base64'd PEM is accepted too.)
	KeyBase64 string `json:"key_base64,omitempty"`
	// Passphrase decrypts an encrypted container. Omit for unencrypted material.
	Passphrase string `json:"passphrase,omitempty"`
}

// present reports whether any key material was supplied at all.
func (m keyMaterial) present() bool { return m.KeyPEM != "" || m.KeyBase64 != "" }

// decode returns the raw container bytes, rejecting the ambiguous "both
// encodings" case rather than silently preferring one.
func (m keyMaterial) decode() ([]byte, error) {
	switch {
	case m.KeyPEM != "" && m.KeyBase64 != "":
		return nil, fmt.Errorf("supply exactly one of key_pem or key_base64, not both")
	case m.KeyPEM != "":
		return []byte(m.KeyPEM), nil
	case m.KeyBase64 != "":
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(m.KeyBase64))
		if err != nil {
			return nil, fmt.Errorf("key_base64 is not valid base64: %v", err)
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("key_pem or key_base64 is required")
	}
}

// parse decodes the supplied key material, turning "it is encrypted" and "the
// passphrase is wrong" into advice rather than a parse error — the same mapping
// importKeyFlags.loadPrivateKey makes in cmd/secsy-ca/importkey.go. The returned
// error is safe to put in a response: it never quotes the input.
func (m keyMaterial) parse() (*pki.ParsedPrivateKey, error) {
	data, err := m.decode()
	if err != nil {
		return nil, err
	}
	parsed, err := pki.ParsePrivateKey(data, []byte(m.Passphrase))
	switch {
	case err == nil:
		return parsed, nil
	case sentinelIs(err, pki.ErrPassphraseRequired):
		return nil, fmt.Errorf("the supplied key material is encrypted: set \"passphrase\" in the request")
	case sentinelIs(err, pki.ErrWrongPassphrase):
		return nil, fmt.Errorf("the supplied passphrase is incorrect")
	default:
		return nil, err
	}
}

// sentinelIs matches a pki passphrase sentinel through both wrapping styles.
// ParsePrivateKey returns the sentinels directly on some paths and formatted
// into a message on others, which is why the CLI matches on the text; errors.Is
// is tried first so the typed relationship is used where it exists.
func sentinelIs(err, sentinel error) bool {
	return errors.Is(err, sentinel) || strings.Contains(err.Error(), sentinel.Error())
}

// providerForRole returns the provider that owns a role's keys, together with a
// release function the caller must always invoke.
//
// It mirrors the CLI's rule (cmd/secsy-ca/importkey.go and the tsa-key /
// signing-key cases in main.go): a role whose configured backend type matches
// the CA's is served by the already-open CA provider, and only a genuinely
// different backend has a second one opened. That is not merely an optimisation
// — a PKCS#11 token will not always grant a second concurrent session, so
// opening one unconditionally would make these endpoints fail on exactly the
// hardware they exist to drive.
func (a *API) providerForRole(w http.ResponseWriter, role, what string) (keyprovider.Provider, func(), bool) {
	deps, ok := a.requireOps(w, what)
	if !ok {
		return nil, nil, false
	}
	// An unknown role must not fall through to the CA backend: writing a key to a
	// different HSM than the caller named is precisely the mistake that is
	// discovered later, by the role that cannot find its key.
	switch role {
	case "", "ca", "tsa", "signing":
	default:
		writeError(w, http.StatusBadRequest, "unknown role %q (want ca, tsa, or signing)", role)
		return nil, nil, false
	}
	if role == "" || role == "ca" ||
		deps.Config.KeyProviderTypeForRole(role) == deps.Config.KeyProviderTypeForRole("ca") {
		if a.keyProvider == nil {
			writeError(w, http.StatusServiceUnavailable, "%s is unavailable: no key provider is installed", what)
			return nil, nil, false
		}
		return a.keyProvider, func() {}, true
	}
	p, ok := a.roleProvider(w, role, what)
	if !ok {
		return nil, nil, false
	}
	return p, func() { _ = p.Close() }, true
}

// provenanceNotice composes the notice for the backend that received the key.
func provenanceNotice(provider keyprovider.Provider) string {
	notice := importProvenanceNotice
	if provider.Name() == string(keyprovider.ProviderSoftware) {
		notice += softwareProviderNotice
	}
	return notice
}

// ImportKeyRequest is the body of POST /api/keys/import, the REST form of
// `secsy-ca import-key`.
type ImportKeyRequest struct {
	// Label is the identifier the key is stored under in the provider. Required.
	Label string `json:"label"`
	// ID is an optional secondary identifier (a hex CKA_ID for PKCS#11).
	ID string `json:"id,omitempty"`
	// Usage is "sign" (default) or "decrypt"/"kek" for an RSA key-encryption key.
	Usage string `json:"usage,omitempty"`
	// Role names the key-provider role that receives the key: "ca" (default),
	// "tsa", or "signing".
	Role string `json:"role,omitempty"`

	keyMaterial
}

// ImportKeyResponse reports the adopted key, field-for-field as
// `secsy-ca import-key -json` emits it, plus the role/usage it was filed under
// and the provenance notice the CLI writes to stderr.
type ImportKeyResponse struct {
	Label        string `json:"label"`
	ID           string `json:"id,omitempty"`
	KeyType      string `json:"key_type"`
	URI          string `json:"uri"`
	SSHPublicKey string `json:"ssh_public_key,omitempty"`
	// SourceFormat is the encoding the key was read from (pkcs8, pkcs12, ...).
	SourceFormat string `json:"source_format"`
	Provider     string `json:"provider"`
	Role         string `json:"role"`
	Usage        string `json:"usage"`
	// Verified reports that the provider signed a challenge with the key after
	// the import and the signature verified. A decrypt-only key cannot sign and
	// is exempt, so it reports false.
	Verified bool   `json:"verified"`
	Notice   string `json:"notice"`
}

// ImportKey handles POST /api/keys/import: place an existing private key into a
// role's key provider.
//
// Gated on platform hsm:manage, not on a tenant capability. The operation writes
// arbitrary key material under an arbitrary label into a backend the whole
// deployment shares — it can shadow the label that tsa.key_label or
// signing.signers[].key_label names — and it binds to no tenant resource that
// could scope it. That is provisioning of the key store itself, which is what
// hsm:manage covers.
func (a *API) ImportKey(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	// Authorize before the body is read: an unauthorized caller's key material
	// should not be decoded, let alone parsed, by this process.
	if !a.can(user, rbac.ActionManageHSM) {
		a.recordEvent(r, audit.ActionKeyImport, "", "", audit.ResultDenied, "hsm:manage capability required")
		writeError(w, http.StatusForbidden, "hsm:manage capability required to import key material into the key provider")
		return
	}

	var req ImportKeyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxKeyImportBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Label == "" {
		writeError(w, http.StatusBadRequest, "label is required")
		return
	}
	keyUsage, err := importKeyUsage(req.Usage)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	if !req.present() {
		writeError(w, http.StatusBadRequest, "key_pem or key_base64 is required")
		return
	}

	role := req.Role
	if role == "" {
		role = "ca"
	}
	provider, release, ok := a.providerForRole(w, role, "key import")
	if !ok {
		return
	}
	defer release()

	// CanImport before parsing: a backend that cannot adopt a key at all (the
	// cloud-KMS providers) should say so without the key material ever being
	// decoded in this process.
	if !keyprovider.CanImport(provider) {
		writeError(w, http.StatusBadRequest,
			"the %s key provider cannot import an existing key; generate the key instead, or use the backend's own bring-your-own-key procedure",
			provider.Name())
		return
	}

	parsed, err := req.parse()
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}
	signer, err := parsed.Signer()
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	// keyprovider.ImportKey runs the shared host-side gates before any backend
	// is touched: crypto-policy algorithm check, exact RSA size matching, and the
	// key-quality gate (ROCA, exponent policy, modulus sanity) — see c87439b.
	a.consumeHSMAuditLogs("")
	info, err := keyprovider.ImportKey(r.Context(), provider, keyprovider.ImportSpec{
		Label:      req.Label,
		ID:         req.ID,
		Usage:      keyUsage,
		PrivateKey: parsed.Key,
	})
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, audit.ActionKeyImport, "", req.Label, audit.ResultError, err.Error())
		// Two failure classes reach here and they need different answers. A HOST-SIDE
		// rejection (keyprovider.ErrImportRejected: crypto policy, exact RSA size, the
		// ROCA/exponent/modulus gate, a label already in use) is the caller's to fix.
		// A BACKEND failure — token unreachable, C_CreateObject refused, dead session —
		// is not: telling an operator their key file is a bad request while the HSM is
		// down sends them auditing the file instead of the device. The split is by
		// sentinel, never by message text, because the messages come from three
		// packages and change.
		if errors.Is(err, keyprovider.ErrImportRejected) || errors.Is(err, keyprovider.ErrImportUnsupported) {
			writeError(w, http.StatusBadRequest, "%v", err)
			return
		}
		writeError(w, http.StatusServiceUnavailable,
			"the %s key provider could not store the key: %v", provider.Name(), err)
		return
	}

	// A signing key is proved usable before the caller is told it worked; a
	// decrypt-only key cannot sign, so it is exempt.
	verified := false
	if keyUsage == keyprovider.KeyUsageSign {
		if err := keyprovider.VerifyKeyUsable(r.Context(), provider,
			keyprovider.KeyRef{Label: info.Label, ID: info.ID}, signer.Public()); err != nil {
			a.recordEvent(r, audit.ActionKeyImport, "", req.Label, audit.ResultError,
				"post-import verification failed: "+err.Error())
			writeError(w, http.StatusInternalServerError,
				"the key was written to the provider but does not sign correctly — remove it before using it: %v", err)
			return
		}
		verified = true
	}

	// The detail records the shape of the import, never the material: provider,
	// key type, the format it arrived in, its usage, and whether it verified.
	a.recordEvent(r, audit.ActionKeyImport, "", info.Label, audit.ResultSuccess,
		fmt.Sprintf("provider=%s role=%s key_type=%s source_format=%s usage=%s verified=%t",
			provider.Name(), role, info.KeyType, parsed.Format, keyUsage, verified))

	writeJSON(w, http.StatusCreated, ImportKeyResponse{
		Label:        info.Label,
		ID:           info.ID,
		KeyType:      info.KeyType,
		URI:          info.URI,
		SSHPublicKey: info.SSHPublicKey,
		SourceFormat: string(parsed.Format),
		Provider:     provider.Name(),
		Role:         role,
		Usage:        keyUsage,
		Verified:     verified,
		Notice:       provenanceNotice(provider),
	})
}

// importKeyUsage maps the request's usage word to a keyprovider usage, accepting
// the same spellings as the CLI's -usage flag.
func importKeyUsage(usage string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(usage)) {
	case "", "sign":
		return keyprovider.KeyUsageSign, nil
	case "decrypt", "kek":
		return keyprovider.KeyUsageDecrypt, nil
	default:
		return "", fmt.Errorf("unknown usage %q (want sign or decrypt)", usage)
	}
}

// ImportCARequest is the body of POST /api/ca/import, the REST form of
// `secsy-ca ca import`.
type ImportCARequest struct {
	// Label is the CA name / key label to record the adopted CA under. Required,
	// and must be unused.
	Label string `json:"label"`
	// Tenant is the owning tenant id or slug, exactly as the CLI's -tenant flag.
	// Empty adopts into the built-in default tenant.
	Tenant string `json:"tenant,omitempty"`
	// Certificate is the CA's existing certificate PEM; trailing certificates in
	// the same PEM are treated as chain material. Optional when the supplied key
	// is a PKCS#12 container, which carries its own certificate.
	Certificate string `json:"certificate,omitempty"`
	// Chain optionally supplies the issuing chain of a subordinate CA whose
	// parent is not in this PKI, so the served chain reaches the external anchor.
	Chain string `json:"chain,omitempty"`
	// Parent is the id or label of a CA already in this PKI that issued this
	// certificate. Empty discovers the parent automatically.
	Parent string `json:"parent,omitempty"`
	// ExistingKeyLabel adopts a key already present in the provider under this
	// label instead of importing one. Exactly one of this and the key material
	// must be supplied.
	ExistingKeyLabel string `json:"existing_key_label,omitempty"`

	keyMaterial
}

// ImportCAResponse reports the adopted CA, field-for-field as
// `secsy-ca ca import -json` emits it, plus the source format and the
// provenance notice.
type ImportCAResponse struct {
	CA             *models.CA `json:"ca"`
	Warnings       []string   `json:"warnings,omitempty"`
	ChainPEM       string     `json:"chain_pem,omitempty"`
	KeyImported    bool       `json:"key_imported"`
	KeyFingerprint string     `json:"key_fingerprint"`
	SelfSigned     bool       `json:"self_signed"`
	// SourceFormat is the encoding imported key material arrived in; empty when
	// an already-present key was adopted by label.
	SourceFormat string `json:"source_format,omitempty"`
	// Notice is set only when key material was actually written into the
	// provider — adopting a key already there has nothing to warn about.
	Notice string `json:"notice,omitempty"`
}

// ImportCA handles POST /api/ca/import: adopt an existing certificate authority,
// its key and its certificate, producing a CA record indistinguishable from one
// `secsy-ca ca import` wrote.
//
// Gated on ca:manage WITHIN the target tenant, the same gate as
// POST /api/ca/init-root: the operation creates a CA in a tenant, and its key
// lands under a label the CA record owns. It then passes the same four-eyes gate
// as init-root and issue-intermediate — an authority appearing in the tree
// without a second signature is exactly what maker-checker exists to prevent —
// keyed on the CLI's resource key so the two surfaces address one queue.
func (a *API) ImportCA(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())

	var req ImportCARequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxKeyImportBody)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	// Resolve and authorize the tenant before anything else touches the key
	// material: the -tenant flag's id-or-slug semantics, then the same
	// active-tenant and ca:manage gates init-root applies.
	tenantID, ok := a.resolveTenantRef(w, req.Tenant)
	if !ok {
		return
	}
	middleware.SetTenant(r.Context(), tenantID)
	if _, err := a.requireActiveTenant(tenantID); err != nil {
		if writeTenantLimitError(w, err) { // suspension -> 403
			return
		}
		writeError(w, http.StatusInternalServerError, "%v", err)
		return
	}
	if !a.canInTenant(user, tenantID, rbac.ActionManageCA) {
		a.recordEvent(r, audit.ActionCAImport, "", req.Label, audit.ResultDenied, "ca:manage capability required")
		writeError(w, http.StatusForbidden, "ca:manage capability required for tenant %q", tenantID)
		return
	}

	if req.Label == "" {
		writeError(w, http.StatusBadRequest, "label is required")
		return
	}
	if req.present() == (req.ExistingKeyLabel != "") {
		writeError(w, http.StatusBadRequest,
			"supply exactly one of key material (key_pem/key_base64) or existing_key_label")
		return
	}

	spec := ca.ImportCASpec{
		TenantID:         tenantID,
		Label:            req.Label,
		ExistingKeyLabel: req.ExistingKeyLabel,
		CertificatePEM:   []byte(req.Certificate),
		ChainPEM:         []byte(req.Chain),
	}

	// A PKCS#12 container carries the certificate alongside the key, so an
	// operator exporting from a Windows CA or a browser has only one blob.
	var sourceFormat pki.KeyFileFormat
	if req.present() {
		parsed, err := req.parse()
		if err != nil {
			writeError(w, http.StatusBadRequest, "%v", err)
			return
		}
		spec.PrivateKey = parsed.Key
		sourceFormat = parsed.Format
		if req.Certificate == "" {
			if parsed.Certificate == nil {
				writeError(w, http.StatusBadRequest, "certificate is required (the supplied key carries none)")
				return
			}
			spec.CertificatePEM = pki.EncodeCertificatePEM(parsed.Certificate.Raw)
			if req.Chain == "" {
				var chain []byte
				for _, c := range parsed.CACerts {
					chain = append(chain, pki.EncodeCertificatePEM(c.Raw)...)
				}
				spec.ChainPEM = chain
			}
		}
	}
	if req.Parent != "" {
		parentID, found := a.resolveCARefID(req.Parent)
		if !found {
			writeError(w, http.StatusBadRequest, "parent CA %q not found", req.Parent)
			return
		}
		spec.ParentID = parentID
	}

	// Four-eyes gate, keyed exactly as the CLI keys it ("ca-label:<label>") so
	// the console and `secsy-ca` queue against the same resource. The params
	// record what was supplied, never the material: a pending approval row is
	// persisted and readable by every approver.
	keySource := "existing-key:" + req.ExistingKeyLabel
	if req.present() {
		keySource = "request-body"
	}
	certSource := "request-body"
	if req.Certificate == "" {
		certSource = string(sourceFormat) + "-container"
	}
	if !a.guard(w, r, approval.ClassCACreate, "ca-label:"+req.Label, req.Label,
		"Adopt existing CA "+req.Label,
		fmt.Sprintf("label=%s;tenant=%s;cert=%s;key=%s", req.Label, tenantID, certSource, keySource),
		"") {
		return
	}

	mgr := ca.NewManager(a.db, a.keyProvider)
	a.consumeHSMAuditLogs("")
	result, err := mgr.ImportCA(r.Context(), spec)
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, audit.ActionCAImport, "", req.Label, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	detail := fmt.Sprintf("subject=%s serial=%s self_signed=%t key_imported=%t key_fingerprint=%s source_format=%s",
		result.CA.Subject, result.CA.Serial, result.SelfSigned, result.KeyImported, result.KeyFingerprint, sourceFormat)
	if len(result.Warnings) > 0 {
		detail += " warnings=" + strings.Join(result.Warnings, "; ")
	}
	a.recordEvent(r, audit.ActionCAImport, result.CA.ID, result.CA.Label, audit.ResultSuccess, detail)

	resp := ImportCAResponse{
		CA:             result.CA,
		Warnings:       result.Warnings,
		ChainPEM:       string(result.ChainPEM),
		KeyImported:    result.KeyImported,
		KeyFingerprint: result.KeyFingerprint,
		SelfSigned:     result.SelfSigned,
		SourceFormat:   string(sourceFormat),
	}
	if result.KeyImported {
		resp.Notice = provenanceNotice(a.keyProvider)
	}
	writeJSON(w, http.StatusCreated, resp)
}
