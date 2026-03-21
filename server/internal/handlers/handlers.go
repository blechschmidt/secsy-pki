package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/ssh-pki/server/internal/database"
	"github.com/ssh-pki/server/internal/middleware"
	"github.com/ssh-pki/server/internal/models"
	"github.com/ssh-pki/server/internal/auth"
	"github.com/ssh-pki/server/internal/pki"
)

type API struct {
	db           *database.DB
	p11cfg       pki.PKCS11Config
	oidcProvider *auth.OIDCProvider
}

func NewAPI(db *database.DB, p11cfg pki.PKCS11Config, oidcProvider *auth.OIDCProvider) *API {
	return &API{db: db, p11cfg: p11cfg, oidcProvider: oidcProvider}
}

func (a *API) RegisterRoutes(mux *http.ServeMux, authMw *middleware.AuthMiddleware) {
	// Public
	mux.HandleFunc("GET /api/health", a.Health)
	mux.HandleFunc("GET /api/auth/config", a.AuthConfig)

	// Protected routes
	protected := authMw.Authenticate

	mux.Handle("GET /api/cas", protected(http.HandlerFunc(a.ListCAs)))
	mux.Handle("POST /api/cas", protected(http.HandlerFunc(a.CreateCA)))
	mux.Handle("GET /api/cas/{id}", protected(http.HandlerFunc(a.GetCA)))
	mux.Handle("DELETE /api/cas/{id}", protected(http.HandlerFunc(a.DeleteCA)))
	mux.Handle("GET /api/cas/{id}/children", protected(http.HandlerFunc(a.GetCAChildren)))

	mux.Handle("POST /api/cas/{id}/sign", protected(http.HandlerFunc(a.SignCertificate)))

	mux.Handle("POST /api/keys/generate", protected(http.HandlerFunc(a.GenerateKey)))

	mux.Handle("GET /api/groups", protected(http.HandlerFunc(a.ListGroups)))
	mux.Handle("POST /api/groups", protected(http.HandlerFunc(a.CreateGroup)))
	mux.Handle("DELETE /api/groups/{id}", protected(http.HandlerFunc(a.DeleteGroup)))
	mux.Handle("GET /api/groups/{id}/members", protected(http.HandlerFunc(a.GetGroupMembers)))
	mux.Handle("POST /api/groups/{id}/members", protected(http.HandlerFunc(a.AddGroupMember)))
	mux.Handle("DELETE /api/groups/{id}/members/{sub}", protected(http.HandlerFunc(a.RemoveGroupMember)))

	mux.Handle("GET /api/cas/{id}/permissions", protected(http.HandlerFunc(a.GetPermissions)))
	mux.Handle("POST /api/cas/{id}/permissions", protected(http.HandlerFunc(a.GrantPermission)))
	mux.Handle("DELETE /api/cas/{id}/permissions", protected(http.HandlerFunc(a.RevokePermission)))

	mux.Handle("GET /api/me", protected(http.HandlerFunc(a.Me)))
}

func (a *API) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) AuthConfig(w http.ResponseWriter, r *http.Request) {
	if a.oidcProvider == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"oidc_enabled": false,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"oidc_enabled": true,
		"issuer_url":   a.oidcProvider.IssuerURL(),
		"client_id":    a.oidcProvider.ClientID(),
	})
}

func (a *API) Me(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	writeJSON(w, http.StatusOK, user)
}

// CA handlers

func (a *API) ListCAs(w http.ResponseWriter, r *http.Request) {
	cas, err := a.db.ListCAs()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list CAs: %v", err)
		return
	}
	if cas == nil {
		cas = []models.CA{}
	}
	writeJSON(w, http.StatusOK, cas)
}

func (a *API) CreateCA(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can create CAs")
		return
	}

	var req struct {
		Label     string  `json:"label"`
		ParentID  *string `json:"parent_id,omitempty"`
		PKCS11URI string  `json:"pkcs11_uri"`
		KeyType   string  `json:"key_type"`
		PublicKey string  `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	if req.Label == "" || req.KeyType == "" {
		writeError(w, http.StatusBadRequest, "label and key_type are required")
		return
	}

	// If parent is specified, verify it exists
	if req.ParentID != nil {
		parent, err := a.db.GetCA(*req.ParentID)
		if err != nil || parent == nil {
			writeError(w, http.StatusBadRequest, "parent CA not found")
			return
		}
	}

	// If no PKCS#11 URI, generate a new key on the HSM
	if req.PKCS11URI == "" {
		generated, err := pki.GenerateKeyOnHSM(a.p11cfg, req.Label, req.KeyType)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to generate key on HSM: %v", err)
			return
		}
		req.PKCS11URI = generated.PKCS11URI
		req.PublicKey = generated.SSHPublicKey
	}

	ca := &models.CA{
		ID:        uuid.New().String(),
		ParentID:  req.ParentID,
		Label:     req.Label,
		PKCS11URI: req.PKCS11URI,
		KeyType:   req.KeyType,
		PublicKey:  req.PublicKey,
	}

	if err := a.db.CreateCA(ca); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create CA: %v", err)
		return
	}

	writeJSON(w, http.StatusCreated, ca)
}

func (a *API) GetCA(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ca, err := a.db.GetCA(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "database error: %v", err)
		return
	}
	if ca == nil {
		writeError(w, http.StatusNotFound, "CA not found")
		return
	}
	writeJSON(w, http.StatusOK, ca)
}

func (a *API) DeleteCA(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can delete CAs")
		return
	}

	id := r.PathValue("id")
	if err := a.db.DeleteCA(id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete CA: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *API) GetCAChildren(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	children, err := a.db.GetChildren(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get children: %v", err)
		return
	}
	if children == nil {
		children = []models.CA{}
	}
	writeJSON(w, http.StatusOK, children)
}

// Sign certificate

func (a *API) SignCertificate(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

	// Check permission
	if !user.IsRoot {
		hasAccess, err := a.checkPermission(user, caID, models.PermSignCertificate)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
			return
		}
		if !hasAccess {
			writeError(w, http.StatusForbidden, "no SIGN_CERTIFICATE permission on this CA")
			return
		}
	}

	ca, err := a.db.GetCA(caID)
	if err != nil || ca == nil {
		writeError(w, http.StatusNotFound, "CA not found")
		return
	}

	var req models.SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "public_key is required")
		return
	}

	certType, err := pki.ParseCertType(req.CertType)
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	keyID := req.KeyID
	if keyID == "" {
		keyID = user.Subject
	}

	validAfter, err := pki.ParseTime(req.ValidAfter, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid valid_after: %v", err)
		return
	}

	validBefore, err := pki.ParseTime(req.ValidBefore, time.Now().Add(24*time.Hour))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid valid_before: %v", err)
		return
	}

	// Get the key label from PKCS11 URI
	keyLabel := extractKeyLabel(ca.PKCS11URI)

	signer, err := pki.NewPKCS11Signer(a.p11cfg, keyLabel)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open PKCS#11 signer: %v", err)
		return
	}
	defer signer.Close()

	certBytes, err := pki.SignSSHCertificate(
		signer,
		[]byte(req.PublicKey),
		certType,
		keyID,
		req.Principals,
		validAfter,
		validBefore,
		req.Extensions,
		req.CriticalOptions,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign certificate: %v", err)
		return
	}

	writeJSON(w, http.StatusOK, models.SignResponse{
		Certificate: string(certBytes),
		KeyID:       keyID,
	})
}

// Key generation

func (a *API) GenerateKey(w http.ResponseWriter, r *http.Request) {
	var req models.KeyGenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	if req.KeyType == "" {
		req.KeyType = "ed25519"
	}

	result, err := pki.GenerateKey(pki.KeyGenParams{
		KeyType: req.KeyType,
		Bits:    req.Bits,
		Comment: req.Comment,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, "%v", err)
		return
	}

	writeJSON(w, http.StatusOK, models.KeyGenResponse{
		PrivateKey: result.PrivateKeyPEM,
		PublicKey:  result.PublicKeySSH,
	})
}

// Group handlers

func (a *API) ListGroups(w http.ResponseWriter, r *http.Request) {
	groups, err := a.db.ListGroups()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list groups: %v", err)
		return
	}
	if groups == nil {
		groups = []models.Group{}
	}
	writeJSON(w, http.StatusOK, groups)
}

func (a *API) CreateGroup(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can create groups")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	g := &models.Group{
		ID:   uuid.New().String(),
		Name: req.Name,
	}
	if err := a.db.CreateGroup(g); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create group: %v", err)
		return
	}
	writeJSON(w, http.StatusCreated, g)
}

func (a *API) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can delete groups")
		return
	}

	id := r.PathValue("id")
	if err := a.db.DeleteGroup(id); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete group: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *API) GetGroupMembers(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	members, err := a.db.GetGroupMembers(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get members: %v", err)
		return
	}
	if members == nil {
		members = []string{}
	}
	writeJSON(w, http.StatusOK, members)
}

func (a *API) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can manage group members")
		return
	}

	groupID := r.PathValue("id")
	var req struct {
		UserSub string `json:"user_sub"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	if err := a.db.AddGroupMember(groupID, req.UserSub); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to add member: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "added"})
}

func (a *API) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can manage group members")
		return
	}

	groupID := r.PathValue("id")
	sub := r.PathValue("sub")
	if err := a.db.RemoveGroupMember(groupID, sub); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove member: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "removed"})
}

// Permission handlers

func (a *API) GetPermissions(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")
	user := middleware.GetUserInfo(r.Context())

	if !user.IsRoot {
		hasAccess, err := a.checkPermission(user, caID, models.PermManagePermissions)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
			return
		}
		if !hasAccess {
			writeError(w, http.StatusForbidden, "no MANAGE_PERMISSIONS on this CA")
			return
		}
	}

	perms, err := a.db.GetPermissions(caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get permissions: %v", err)
		return
	}
	if perms == nil {
		perms = []models.PermissionEntry{}
	}
	writeJSON(w, http.StatusOK, perms)
}

func (a *API) GrantPermission(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")
	user := middleware.GetUserInfo(r.Context())

	if !user.IsRoot {
		hasAccess, err := a.checkPermission(user, caID, models.PermManagePermissions)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
			return
		}
		if !hasAccess {
			writeError(w, http.StatusForbidden, "no MANAGE_PERMISSIONS on this CA")
			return
		}
	}

	var req models.PermissionGrant
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	if req.EntityType != "user" && req.EntityType != "group" {
		writeError(w, http.StatusBadRequest, "entity_type must be 'user' or 'group'")
		return
	}

	if req.Permission != models.PermSignCertificate && req.Permission != models.PermManagePermissions {
		writeError(w, http.StatusBadRequest, "permission must be SIGN_CERTIFICATE or MANAGE_PERMISSIONS")
		return
	}

	entry := &models.PermissionEntry{
		ID:         uuid.New().String(),
		CAID:       caID,
		EntityType: req.EntityType,
		EntityID:   req.EntityID,
		Permission: req.Permission,
	}

	if err := a.db.GrantPermission(entry); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to grant permission: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "granted"})
}

func (a *API) RevokePermission(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")
	user := middleware.GetUserInfo(r.Context())

	if !user.IsRoot {
		hasAccess, err := a.checkPermission(user, caID, models.PermManagePermissions)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "permission check failed: %v", err)
			return
		}
		if !hasAccess {
			writeError(w, http.StatusForbidden, "no MANAGE_PERMISSIONS on this CA")
			return
		}
	}

	var req models.PermissionGrant
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	if err := a.db.RevokePermission(caID, req.EntityType, req.EntityID, req.Permission); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to revoke permission: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// Helpers

func (a *API) checkPermission(user *models.UserInfo, caID string, perm models.Permission) (bool, error) {
	if user.IsRoot {
		return true, nil
	}
	groupIDs, err := a.db.GetUserGroups(user.Subject)
	if err != nil {
		return false, err
	}
	return a.db.HasPermission(caID, user.Subject, perm, groupIDs)
}

func extractKeyLabel(pkcs11URI string) string {
	// Parse "pkcs11:token=...;object=LABEL;type=private"
	// Simple parser for the object field
	for _, part := range splitURI(pkcs11URI) {
		if len(part) > 7 && part[:7] == "object=" {
			return part[7:]
		}
	}
	return ""
}

func splitURI(uri string) []string {
	// Strip "pkcs11:" prefix
	if len(uri) > 7 && uri[:7] == "pkcs11:" {
		uri = uri[7:]
	}
	var parts []string
	current := ""
	for _, c := range uri {
		if c == ';' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("API error (%d): %s", status, msg)
	writeJSON(w, status, map[string]string{"error": msg})
}
