package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/blechschmidt/secsy-pki/server/internal/sshca"
)

// HSM-backed SSH certificate authority endpoints (Task 57). Signing and
// revocation are RBAC- and tenant-gated exactly like X.509 issuance
// (canIssueOn); the CA public key and the KRL are public, like the CRL/OCSP
// endpoints, because relying hosts fetch them without credentials.

// SetSSHConfig installs the SSH CA configuration (currently the comment stamped
// into generated KRLs).
func (a *API) SetSSHConfig(krlComment string) {
	a.sshKRLComment = krlComment
}

// CreateSSHCARequest asks for a new HSM-backed SSH certificate authority.
type CreateSSHCARequest struct {
	Label    string `json:"label"`
	TenantID string `json:"tenant_id,omitempty"`
	// KeyType is a key-provider key type (ed25519, ecdsa-p256, rsa-2048, …);
	// empty defaults to ed25519.
	KeyType string `json:"key_type,omitempty"`
}

// CreateSSHCA provisions a new SSH CA: a signing key generated inside the
// configured key provider plus its store record. ca:manage within the target
// tenant is required, mirroring X.509 CA creation.
func (a *API) CreateSSHCA(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())

	var req CreateSSHCARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Label == "" {
		writeError(w, http.StatusBadRequest, "label is required")
		return
	}

	tenantID := req.TenantID
	if tenantID == "" {
		tenantID = models.DefaultTenantID
	}
	middleware.SetTenant(r.Context(), tenantID)
	if !a.canInTenant(user, tenantID, rbac.ActionManageCA) {
		a.recordEvent(r, audit.ActionSSHCAInit, "", req.Label, audit.ResultDenied, "ca:manage capability required")
		writeError(w, http.StatusForbidden, "ca:manage capability required for tenant %q", tenantID)
		return
	}

	authority := sshca.NewAuthority(a.db, a.keyProvider)
	a.consumeHSMAuditLogs("")
	ca, err := authority.InitCA(r.Context(), sshca.CASpec{
		TenantID: tenantID,
		Label:    req.Label,
		KeyType:  req.KeyType,
	})
	a.consumeHSMAuditLogs("")
	if err != nil {
		a.recordEvent(r, audit.ActionSSHCAInit, "", req.Label, audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to initialize SSH CA: %v", err)
		return
	}

	a.recordEvent(r, audit.ActionSSHCAInit, ca.ID, ca.Label, audit.ResultSuccess,
		"key_type="+ca.KeyType)
	writeJSON(w, http.StatusCreated, ca)
}

// SignSSHCertRequest asks a CA to sign an OpenSSH public key into a user or
// host certificate under a signing profile.
type SignSSHCertRequest struct {
	// PublicKey is the authorized_keys line of the key to certify.
	PublicKey string `json:"public_key"`
	// CertType is "user" (default) or "host".
	CertType string `json:"cert_type,omitempty"`
	// Profile names the signing profile; empty selects the built-in default for
	// the certificate type (user-default / host-default).
	Profile string `json:"profile,omitempty"`
	// KeyID is the certificate key ID; empty defaults to the caller's subject.
	KeyID string `json:"key_id,omitempty"`
	// Principals are the user names (user certs) or host names (host certs).
	Principals []string `json:"principals,omitempty"`
	// ValiditySeconds is the requested lifetime; zero applies the profile
	// default, and values beyond the profile maximum are clamped.
	ValiditySeconds int64 `json:"validity_seconds,omitempty"`
	// Extensions/CriticalOptions replace the profile defaults when non-empty;
	// every key must be permitted by the profile.
	Extensions      map[string]string `json:"extensions,omitempty"`
	CriticalOptions map[string]string `json:"critical_options,omitempty"`
}

// SignSSHCertResponse returns the signed certificate and its inventory record.
type SignSSHCertResponse struct {
	// Certificate is the authorized_keys line of the signed certificate (the
	// content of an OpenSSH -cert.pub file).
	Certificate string   `json:"certificate"`
	Serial      string   `json:"serial"`
	CertType    string   `json:"cert_type"`
	KeyID       string   `json:"key_id"`
	Principals  []string `json:"principals,omitempty"`
	Profile     string   `json:"profile"`
	ValidAfter  string   `json:"valid_after"`
	ValidBefore string   `json:"valid_before"`
	// CAPublicKey is the CA's authorized_keys line, so a caller can install the
	// trust anchor (TrustedUserCAKeys / @cert-authority) alongside the cert.
	CAPublicKey string `json:"ca_public_key"`
}

// SignSSHCert signs an OpenSSH certificate under a CA. Requires the CA's issue
// capability (tenant issuer role or a per-CA SIGN_CERTIFICATE grant), exactly
// like X.509 issuance.
func (a *API) SignSSHCert(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	ok, err := a.canIssueOn(r.Context(), user, caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
		return
	}
	if !ok {
		metrics.SSHCertificates.Inc("unknown", metrics.ResultDenied)
		a.recordEvent(r, audit.ActionSSHSign, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
		return
	}

	var req SignSSHCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "public_key is required")
		return
	}
	certType := req.CertType
	if certType == "" {
		certType = sshca.CertTypeUser
	}

	authority := sshca.NewAuthority(a.db, a.keyProvider)
	a.consumeHSMAuditLogs("")
	result, err := authority.Sign(r.Context(), sshca.SignRequest{
		CAID:            caID,
		CertType:        certType,
		PublicKey:       req.PublicKey,
		KeyID:           req.KeyID,
		Principals:      req.Principals,
		Profile:         req.Profile,
		Validity:        time.Duration(req.ValiditySeconds) * time.Second,
		Extensions:      req.Extensions,
		CriticalOptions: req.CriticalOptions,
		RequestedBy:     user.Subject,
	})
	a.consumeHSMAuditLogs("")
	if err != nil {
		metrics.SSHCertificates.Inc(certType, metrics.ResultError)
		a.recordEvent(r, audit.ActionSSHSign, caID, "", audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to sign certificate: %v", err)
		return
	}

	rec := result.Record
	metrics.SSHCertificates.Inc(rec.CertType, metrics.ResultSuccess)
	a.recordEvent(r, audit.ActionSSHSign, caID, result.CA.Label, audit.ResultSuccess,
		fmt.Sprintf("serial=%s type=%s key_id=%s principals=%s profile=%s",
			rec.Serial, rec.CertType, rec.KeyID, strings.Join(rec.Principals, ","), rec.Profile))

	writeJSON(w, http.StatusCreated, SignSSHCertResponse{
		Certificate: rec.Certificate,
		Serial:      rec.Serial,
		CertType:    rec.CertType,
		KeyID:       rec.KeyID,
		Principals:  rec.Principals,
		Profile:     rec.Profile,
		ValidAfter:  rec.ValidAfter.UTC().Format(time.RFC3339),
		ValidBefore: rec.ValidBefore.UTC().Format(time.RFC3339),
		CAPublicKey: result.CA.PublicKey,
	})
}

// RevokeSSHCertRequest revokes one certificate serial, or every certificate
// bearing a key ID, under a CA.
type RevokeSSHCertRequest struct {
	Serial string `json:"serial,omitempty"`
	KeyID  string `json:"key_id,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// RevokeSSHCert records an SSH revocation; the change is published to relying
// hosts through the CA's KRL. Requires the CA's issue capability, matching
// X.509 revocation.
func (a *API) RevokeSSHCert(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	ok, err := a.canIssueOn(r.Context(), user, caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
		return
	}
	if !ok {
		metrics.SSHRevocations.Inc(metrics.ResultDenied)
		a.recordEvent(r, audit.ActionSSHRevoke, caID, "", audit.ResultDenied, "no SIGN_CERTIFICATE permission on this CA")
		writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
		return
	}

	var req RevokeSSHCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	authority := sshca.NewAuthority(a.db, a.keyProvider)
	rev, newly, err := authority.Revoke(r.Context(), sshca.RevokeRequest{
		CAID:      caID,
		Serial:    req.Serial,
		KeyID:     req.KeyID,
		Reason:    req.Reason,
		RevokedBy: user.Subject,
	})
	if err != nil {
		metrics.SSHRevocations.Inc(metrics.ResultError)
		a.recordEvent(r, audit.ActionSSHRevoke, caID, "", audit.ResultError, err.Error())
		writeError(w, http.StatusBadRequest, "failed to revoke: %v", err)
		return
	}

	target := "serial=" + rev.Serial
	if rev.Serial == "" {
		target = "key_id=" + rev.KeyID
	}
	metrics.SSHRevocations.Inc(metrics.ResultSuccess)
	a.recordEvent(r, audit.ActionSSHRevoke, caID, "", audit.ResultSuccess,
		fmt.Sprintf("%s newly_revoked=%t reason=%s", target, newly, rev.Reason))

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"revoked":       true,
		"newly_revoked": newly,
		"serial":        rev.Serial,
		"key_id":        rev.KeyID,
		"revoked_at":    rev.RevokedAt.UTC().Format(time.RFC3339),
	})
}

// ListSSHCertificates lists the SSH certificates a CA has signed. Read-gated
// plus tenant membership, like the X.509 inventory.
func (a *API) ListSSHCertificates(w http.ResponseWriter, r *http.Request) {
	ca, ok := a.authorizeCARead(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	certs, err := a.db.ListSSHCertificates(ca.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list SSH certificates: %v", err)
		return
	}
	if certs == nil {
		certs = []models.SSHCertificate{}
	}
	writeJSON(w, http.StatusOK, certs)
}

// ListSSHRevocations lists a CA's SSH revocation records (the entries its KRL
// publishes). Read-gated plus tenant membership.
func (a *API) ListSSHRevocations(w http.ResponseWriter, r *http.Request) {
	ca, ok := a.authorizeCARead(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	revs, err := a.db.ListSSHRevocations(ca.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list SSH revocations: %v", err)
		return
	}
	if revs == nil {
		revs = []models.SSHRevocation{}
	}
	writeJSON(w, http.StatusOK, revs)
}

// ListSSHProfiles lists the effective SSH signing profiles (built-in + custom).
func (a *API) ListSSHProfiles(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !a.canRead(user) {
		writeError(w, http.StatusForbidden, "read access requires a role (admin, issuer, or auditor)")
		return
	}
	writeJSON(w, http.StatusOK, sshca.Profiles())
}

// GetSSHCAPublicKey serves a CA's public key as a single authorized_keys line —
// the trust anchor relying hosts pin via TrustedUserCAKeys (user certificates)
// or a @cert-authority known_hosts entry (host certificates). Public, like the
// CRL/chain endpoints: the public key is public material and hosts fetch it
// without credentials.
func (a *API) GetSSHCAPublicKey(w http.ResponseWriter, r *http.Request) {
	ca, err := a.db.GetCA(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error: %v", err)
		return
	}
	if ca == nil || strings.TrimSpace(ca.PublicKey) == "" {
		writeError(w, http.StatusNotFound, "CA not found")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, strings.TrimSpace(ca.PublicKey))
}

// GetSSHKRL serves a CA's OpenSSH Key Revocation List, freshly generated from
// the revocation store. Public and unauthenticated — sshd instances fetch it
// for their RevokedKeys option exactly like TLS relying parties fetch a CRL.
func (a *API) GetSSHKRL(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")
	authority := sshca.NewAuthority(a.db, a.keyProvider)
	krl, err := authority.BuildKRL(r.Context(), caID, a.sshKRLComment)
	if err != nil {
		metrics.SSHKRLRequests.Inc(metrics.ResultError)
		writeError(w, http.StatusNotFound, "failed to build KRL: %v", err)
		return
	}
	metrics.SSHKRLRequests.Inc(metrics.ResultSuccess)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="ca.krl"`)
	w.Write(krl)
}
