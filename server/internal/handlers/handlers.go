package handlers

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/hsm"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/pki"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

type API struct {
	db                   *database.DB
	keyProvider          keyprovider.Provider
	oidcProvider         *auth.OIDCProvider
	hsmCfg               hsm.Config
	suppressAuditWarning bool
	secretKEKLabel       string
}

func NewAPI(db *database.DB, keyProvider keyprovider.Provider, oidcProvider *auth.OIDCProvider, hsmCfg hsm.Config, suppressAuditWarning bool, secretKEKLabel string) *API {
	return &API{db: db, keyProvider: keyProvider, oidcProvider: oidcProvider, hsmCfg: hsmCfg, suppressAuditWarning: suppressAuditWarning, secretKEKLabel: secretKEKLabel}
}

func (a *API) RegisterRoutes(mux *http.ServeMux, authMw *middleware.AuthMiddleware) {
	// Public
	mux.HandleFunc("GET /api/health", a.Health)
	mux.HandleFunc("GET /api/auth/config", a.AuthConfig)

	// Protected routes: auth + access audit logging
	auditMw := middleware.AuditLog(a.db)
	protect := func(h http.Handler) http.Handler {
		return authMw.Authenticate(auditMw(h))
	}
	protected := protect

	mux.Handle("GET /api/keys", protected(http.HandlerFunc(a.ListCAs)))
	mux.Handle("POST /api/keys", protected(http.HandlerFunc(a.CreateCA)))

	// HSM-backed X.509 certificate-authority setup
	mux.Handle("POST /api/ca/init-root", protected(http.HandlerFunc(a.InitRootCA)))
	mux.Handle("POST /api/ca/{id}/issue-intermediate", protected(http.HandlerFunc(a.IssueIntermediateCA)))

	// Certificate issuance, renewal, and revocation (X.509 end-entity certs).
	mux.Handle("GET /api/profiles", protected(http.HandlerFunc(a.ListProfiles)))
	mux.Handle("POST /api/ca/{id}/issue", protected(http.HandlerFunc(a.IssueCertificate)))
	mux.Handle("POST /api/ca/{id}/renew", protected(http.HandlerFunc(a.RenewCertificate)))
	mux.Handle("POST /api/ca/{id}/revoke", protected(http.HandlerFunc(a.RevokeCertificate)))
	mux.Handle("GET /api/ca/{id}/certificates", protected(http.HandlerFunc(a.ListIssuedCertificates)))
	mux.Handle("GET /api/ca/{id}/revoked", protected(http.HandlerFunc(a.ListRevokedCertificates)))

	// Public revocation endpoints — relying parties fetch these without auth.
	mux.HandleFunc("GET /api/ca/{id}/crl", a.GetCRL)
	mux.HandleFunc("POST /api/ca/{id}/ocsp", a.OCSPResponder)
	mux.HandleFunc("GET /api/ca/{id}/ocsp/{req}", a.OCSPResponder)

	mux.Handle("GET /api/keys/{id}", protected(http.HandlerFunc(a.GetCA)))
	mux.Handle("DELETE /api/keys/{id}", protected(http.HandlerFunc(a.DeleteCA)))
	mux.Handle("GET /api/keys/{id}/children", protected(http.HandlerFunc(a.GetCAChildren)))
	mux.Handle("GET /api/keys/{id}/public-key", protected(http.HandlerFunc(a.GetPublicKey)))

	mux.Handle("POST /api/keys/{id}/sign", protected(http.HandlerFunc(a.SignCertificate)))
	mux.Handle("POST /api/keys/{id}/sign-x509", protected(http.HandlerFunc(a.SignX509Certificate)))
	mux.Handle("POST /api/parse-csr", protected(http.HandlerFunc(a.ParseCSR)))
	mux.Handle("GET /api/keys/{id}/my-restrictions", protected(http.HandlerFunc(a.GetMyRestrictions)))

	mux.Handle("GET /api/groups", protected(http.HandlerFunc(a.ListGroups)))
	mux.Handle("POST /api/groups", protected(http.HandlerFunc(a.CreateGroup)))
	mux.Handle("DELETE /api/groups/{id}", protected(http.HandlerFunc(a.DeleteGroup)))
	mux.Handle("GET /api/groups/{id}/members", protected(http.HandlerFunc(a.GetGroupMembers)))
	mux.Handle("POST /api/groups/{id}/members", protected(http.HandlerFunc(a.AddGroupMember)))
	mux.Handle("DELETE /api/groups/{id}/members/{sub}", protected(http.HandlerFunc(a.RemoveGroupMember)))

	mux.Handle("GET /api/keys/{id}/permissions", protected(http.HandlerFunc(a.GetPermissions)))
	mux.Handle("POST /api/keys/{id}/permissions", protected(http.HandlerFunc(a.GrantPermission)))
	mux.Handle("DELETE /api/keys/{id}/permissions", protected(http.HandlerFunc(a.RevokePermission)))

	mux.Handle("GET /api/restriction-sets", protected(http.HandlerFunc(a.ListAllRestrictionSets)))
	mux.Handle("POST /api/restriction-sets", protected(http.HandlerFunc(a.CreateRestrictionSetGlobal)))
	mux.Handle("GET /api/keys/{id}/restriction-sets", protected(http.HandlerFunc(a.ListRestrictionSets)))
	mux.Handle("POST /api/keys/{id}/restriction-sets", protected(http.HandlerFunc(a.CreateRestrictionSet)))
	mux.Handle("PUT /api/restriction-sets/{id}", protected(http.HandlerFunc(a.UpdateRestrictionSet)))
	mux.Handle("DELETE /api/restriction-sets/{id}", protected(http.HandlerFunc(a.DeleteRestrictionSet)))
	mux.Handle("PUT /api/keys/{id}/default-restriction-set", protected(http.HandlerFunc(a.SetDefaultRestrictionSet)))

	mux.Handle("GET /api/audit-log", protected(http.HandlerFunc(a.ListAuditLog)))
	mux.Handle("GET /api/access-log", protected(http.HandlerFunc(a.ListAccessLog)))

	// HSM-backed envelope encryption for secrets. Enabled only when a KEK is
	// configured (secret.kek_label).
	if a.secretEnabled() {
		mux.Handle("GET /api/secret/info", protected(http.HandlerFunc(a.SecretInfo)))
		mux.Handle("POST /api/secret/encrypt", protected(http.HandlerFunc(a.EncryptSecret)))
		mux.Handle("POST /api/secret/decrypt", protected(http.HandlerFunc(a.DecryptSecret)))
	}

	if a.hsmEnabled() {
		mux.Handle("GET /api/hsm/info", protected(http.HandlerFunc(a.GetHSMInfo)))
		mux.Handle("GET /api/hsm/attestation", protected(http.HandlerFunc(a.GetHSMAttestation)))
		mux.Handle("GET /api/hsm/audit-log", protected(http.HandlerFunc(a.GetHSMAuditLog)))
		mux.Handle("POST /api/hsm/provision-audit", protected(http.HandlerFunc(a.ProvisionHSMAudit)))
		mux.Handle("POST /api/hsm/factory-reset", protected(http.HandlerFunc(a.FactoryResetHSM)))
		mux.Handle("GET /api/hsm/combined-audit-log", protected(http.HandlerFunc(a.ExportCombinedAuditLog)))
		mux.Handle("GET /api/hsm/signed-audit-log", protected(http.HandlerFunc(a.GetSignedAuditLog)))
	}

	// OpenAPI docs
	mux.HandleFunc("GET /api/docs", a.SwaggerUI)
	mux.HandleFunc("GET /api/docs/openapi.yaml", a.OpenAPISpec)

	mux.Handle("GET /api/me", protected(http.HandlerFunc(a.Me)))
}

func (a *API) hsmEnabled() bool {
	return a.hsmCfg.ConnectorURL != "" || a.hsmCfg.AuthKeyID != 0
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

	// If no key URI is supplied, generate a new key via the configured provider.
	if req.PKCS11URI == "" {
		a.consumeHSMAuditLogs("")
		generated, err := a.keyProvider.GenerateKey(r.Context(), keyprovider.KeySpec{
			Label:   req.Label,
			KeyType: req.KeyType,
		})
		a.consumeHSMAuditLogs("")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to generate key: %v", err)
			return
		}
		req.PKCS11URI = generated.URI
		req.PublicKey = generated.SSHPublicKey
	}

	denySSH := database.BuiltinDenyAllSSH
	denyX509 := database.BuiltinDenyAllX509
	ca := &models.CA{
		ID:                          uuid.New().String(),
		ParentID:                    req.ParentID,
		Label:                       req.Label,
		PKCS11URI:                   req.PKCS11URI,
		KeyType:                     req.KeyType,
		PublicKey:                   req.PublicKey,
		DefaultSSHRestrictionSetID:  &denySSH,
		DefaultX509RestrictionSetID: &denyX509,
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

func (a *API) GetPublicKey(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ca, err := a.db.GetCA(id)
	if err != nil || ca == nil {
		writeError(w, http.StatusNotFound, "key not found")
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "pem"
	}
	if format == "pem" {
		// Convert SSH public key to PEM (PKIX) format
		sshPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ca.PublicKey))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to parse public key: %v", err)
			return
		}
		cryptoPub := sshPub.(ssh.CryptoPublicKey).CryptoPublicKey()
		derBytes, err := x509.MarshalPKIXPublicKey(cryptoPub)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal public key: %v", err)
			return
		}
		pemBlock := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Write(pemBlock)
		return
	}

	// Default: OpenSSH format
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(ca.PublicKey + "\n"))
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

	// Look up effective restriction set for this user on this CA
	groupIDs, _ := a.db.GetUserGroups(user.Subject)
	rs, err := a.db.GetEffectiveRestrictionSet(caID, user.Subject, groupIDs, "ssh")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "restriction set lookup failed: %v", err)
		return
	}

	// Enforce restriction set
	if rs != nil {
		if err := enforceRestrictions(rs, &req, user); err != nil {
			writeError(w, http.StatusForbidden, "%v", err)
			return
		}
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

	// Override key_id based on restriction set
	if rs != nil && rs.ForceKeyIDEmail {
		email := user.Email
		if email == "" {
			email = user.Subject
		}
		keyID = email
	}
	if rs != nil && rs.RequireReason && req.Reason != "" {
		keyID = keyID + " (" + req.Reason + ")"
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

	// Enforce max validity
	if rs != nil && rs.MaxValiditySecs != nil {
		maxDuration := time.Duration(*rs.MaxValiditySecs) * time.Second
		if validBefore.Sub(validAfter) > maxDuration {
			validBefore = validAfter.Add(maxDuration)
		}
	}

	// Enforce max valid_after offset
	if rs != nil && rs.MaxValidAfterOffset != nil {
		maxOffset := time.Duration(*rs.MaxValidAfterOffset) * time.Second
		latest := time.Now().Add(maxOffset)
		if validAfter.After(latest) {
			writeError(w, http.StatusForbidden, "valid_after is too far in the future (max offset: %v)", maxOffset)
			return
		}
	}

	// Consume pending HSM logs to free space before signing
	a.consumeHSMAuditLogs("")

	signer, err := a.keyProvider.Signer(r.Context(), keyRefForCA(ca))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open signer: %v", err)
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

	// Parse serial from the signed certificate
	serial := ""
	if pubKey, _, _, _, err := ssh.ParseAuthorizedKey(certBytes); err == nil {
		if cert, ok := pubKey.(*ssh.Certificate); ok {
			serial = fmt.Sprintf("%d", cert.Serial)
		}
	}

	// Audit log
	var rsID *string
	if rs != nil {
		rsID = &rs.ID
	}
	auditEntry := &models.AuditLogEntry{
		ID:               uuid.New().String(),
		UserSub:          user.Subject,
		UserEmail:        user.Email,
		UserName:         user.Name,
		CAID:             caID,
		CALabel:          ca.Label,
		KeyID:            keyID,
		CertType:         req.CertType,
		Principals:       req.Principals,
		ValidAfter:       validAfter,
		ValidBefore:      validBefore,
		Extensions:       req.Extensions,
		CriticalOptions:  req.CriticalOptions,
		PublicKey:        req.PublicKey,
		Certificate:      string(certBytes),
		RestrictionSetID: rsID,
		Serial:           serial,
	}
	if err := a.db.CreateAuditLogEntry(auditEntry); err != nil {
		log.Printf("WARNING: failed to write audit log: %v", err)
	}

	// Close the PKCS#11 session before consuming HSM logs so the sign entry is visible
	signer.Close()

	// Consume HSM audit logs — the sign entry should now be in the buffer
	a.consumeHSMAuditLogs(auditEntry.ID)

	writeJSON(w, http.StatusOK, models.SignResponse{
		Certificate: string(certBytes),
		KeyID:       keyID,
	})
}

// X.509 certificate signing

func (a *API) SignX509Certificate(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	caID := r.PathValue("id")

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

	var req models.X509SignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	if req.CSR == "" {
		writeError(w, http.StatusBadRequest, "csr is required")
		return
	}

	validBefore, err := pki.ParseTime(req.ValidBefore, time.Now().Add(365*24*time.Hour))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid valid_before: %v", err)
		return
	}

	// Consume HSM audit logs before signing
	a.consumeHSMAuditLogs("")

	signer, err := a.keyProvider.Signer(r.Context(), keyRefForCA(ca))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to open signer: %v", err)
		return
	}

	certPEM, serial, err := pki.SignX509Certificate(
		signer, []byte(req.CSR), validBefore,
	)

	signer.Close()
	a.consumeHSMAuditLogs("")

	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign X.509 certificate: %v", err)
		return
	}

	writeJSON(w, http.StatusOK, models.X509SignResponse{
		Certificate: string(certPEM),
		Serial:      serial,
	})
}

func (a *API) ParseCSR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSR string `json:"csr"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	block, _ := pem.Decode([]byte(req.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		writeError(w, http.StatusBadRequest, "invalid PEM: expected CERTIFICATE REQUEST")
		return
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to parse CSR: %v", err)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		writeError(w, http.StatusBadRequest, "CSR signature invalid: %v", err)
		return
	}

	// Build subject fields
	subject := map[string]string{}
	if csr.Subject.CommonName != "" {
		subject["CN"] = csr.Subject.CommonName
	}
	if len(csr.Subject.Organization) > 0 {
		subject["O"] = csr.Subject.Organization[0]
	}
	if len(csr.Subject.OrganizationalUnit) > 0 {
		subject["OU"] = csr.Subject.OrganizationalUnit[0]
	}
	if len(csr.Subject.Country) > 0 {
		subject["C"] = csr.Subject.Country[0]
	}
	if len(csr.Subject.Province) > 0 {
		subject["ST"] = csr.Subject.Province[0]
	}
	if len(csr.Subject.Locality) > 0 {
		subject["L"] = csr.Subject.Locality[0]
	}

	// SANs
	sans := map[string][]string{}
	if len(csr.DNSNames) > 0 {
		sans["dns"] = csr.DNSNames
	}
	ipStrs := make([]string, len(csr.IPAddresses))
	for i, ip := range csr.IPAddresses {
		ipStrs[i] = ip.String()
	}
	if len(ipStrs) > 0 {
		sans["ip"] = ipStrs
	}
	if len(csr.EmailAddresses) > 0 {
		sans["email"] = csr.EmailAddresses
	}

	// Public key info
	pubKeyAlgo := csr.PublicKeyAlgorithm.String()

	writeJSON(w, http.StatusOK, map[string]any{
		"subject":              subject,
		"sans":                 sans,
		"public_key_algorithm": pubKeyAlgo,
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

	if req.Permission != models.PermSignCertificate && req.Permission != models.PermManagePermissions && req.Permission != models.PermConfigureCA {
		writeError(w, http.StatusBadRequest, "permission must be SIGN_CERTIFICATE, MANAGE_PERMISSIONS, or CONFIGURE_CA")
		return
	}

	// Only root or CONFIGURE_CA holders can grant CONFIGURE_CA
	if req.Permission == models.PermConfigureCA && !user.IsRoot {
		hasAccess, err := a.checkPermission(user, caID, models.PermConfigureCA)
		if err != nil || !hasAccess {
			writeError(w, http.StatusForbidden, "need CONFIGURE_CA permission to grant CONFIGURE_CA")
			return
		}
	}

	entry := &models.PermissionEntry{
		ID:                   uuid.New().String(),
		CAID:                 caID,
		EntityType:           req.EntityType,
		EntityID:             req.EntityID,
		Permission:           req.Permission,
		SSHRestrictionSetID:  req.SSHRestrictionSetID,
		X509RestrictionSetID: req.X509RestrictionSetID,
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

func (a *API) ListAuditLog(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can view audit logs")
		return
	}

	caID := r.URL.Query().Get("ca_id")
	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	// JSON export mode
	export := r.URL.Query().Get("export") == "json"

	if export {
		entries, _, err := a.db.ListAuditLog(caID, 100000, 0)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to query audit log: %v", err)
			return
		}
		if entries == nil {
			entries = []models.AuditLogEntry{}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=audit-log.json")
		json.NewEncoder(w).Encode(entries)
		return
	}

	entries, total, err := a.db.ListAuditLog(caID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query audit log: %v", err)
		return
	}
	if entries == nil {
		entries = []models.AuditLogEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

func (a *API) ListAccessLog(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can view access logs")
		return
	}

	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}

	export := r.URL.Query().Get("export") == "json"
	if export {
		entries, _, err := a.db.ListAccessLog(100000, 0)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to query access log: %v", err)
			return
		}
		if entries == nil {
			entries = []models.AccessLogEntry{}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=access-log.json")
		json.NewEncoder(w).Encode(entries)
		return
	}

	entries, total, err := a.db.ListAccessLog(limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query access log: %v", err)
		return
	}
	if entries == nil {
		entries = []models.AccessLogEntry{}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
	})
}

func (a *API) GetHSMInfo(w http.ResponseWriter, r *http.Request) {
	a.consumeHSMAuditLogs("")
	info, err := hsm.GetDeviceInfo(a.hsmCfg)
	a.consumeHSMAuditLogs("")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"available":              false,
			"error":                  err.Error(),
			"suppress_audit_warning": a.suppressAuditWarning,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"available":              true,
		"version":                info.Version,
		"serial":                 info.Serial,
		"part_number":            info.PartNumber,
		"log_used":               info.LogUsed,
		"force_audit":            info.ForceAudit,
		"audit_provisioned":      info.AuditProvisioned,
		"suppress_audit_warning": a.suppressAuditWarning,
	})
}

func (a *API) GetHSMAttestation(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can access HSM attestation")
		return
	}

	a.consumeHSMAuditLogs("")
	derBytes, err := hsm.GetDeviceAttestation(a.hsmCfg)
	a.consumeHSMAuditLogs("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get device attestation: %v", err)
		return
	}

	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=device-attestation.pem")
	w.Write(pemBlock)
}

func (a *API) GetHSMAuditLog(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can access HSM audit log")
		return
	}

	// Consume pending entries to DB, then serve from DB
	a.consumeHSMAuditLogs("")

	export, err := a.db.ExportCombinedAuditLog()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get HSM audit log: %v", err)
		return
	}

	// Convert to hsm.AuditLogEntry for hash chain verification
	var entries []hsm.AuditLogEntry
	for _, e := range export.HSMEntries {
		entries = append(entries, hsm.AuditLogEntry{
			Number: e.Number, Command: e.Command, Length: e.Length,
			SessionKey: e.SessionKey, TargetKey: e.TargetKey, SecondKey: e.SecondKey,
			Result: e.Result, Tick: e.Tick, Hash: e.Hash,
		})
	}

	results, _ := hsm.VerifyHashChain(entries)

	type entryWithVerify struct {
		hsm.AuditLogEntry
		HashValid bool `json:"hash_valid"`
	}
	var verified []entryWithVerify
	for i, e := range entries {
		valid := true
		if results != nil && i < len(results) {
			valid = results[i]
		}
		verified = append(verified, entryWithVerify{e, valid})
	}

	serial, _ := hsm.GetDeviceSerial(a.hsmCfg)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"device_serial": serial,
		"entries":       verified,
	})
}

func (a *API) consumeHSMAuditLogs(signAuditID string) {
	entries, err := hsm.FetchAndConsumeAuditLog(a.hsmCfg)
	if err != nil {
		log.Printf("WARNING: failed to fetch HSM audit log: %v", err)
		return
	}
	if len(entries) == 0 {
		return
	}

	// Convert to models, linking sign commands to the signAuditID if provided
	var dbEntries []models.HSMAuditEntry
	linked := false
	// Walk backwards to find the latest sign command for linking
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		entry := models.HSMAuditEntry{
			Number:     e.Number,
			Command:    e.Command,
			Length:     e.Length,
			SessionKey: e.SessionKey,
			TargetKey:  e.TargetKey,
			SecondKey:  e.SecondKey,
			Result:     e.Result,
			Tick:       e.Tick,
			Hash:       e.Hash,
		}
		if !linked && signAuditID != "" {
			if _, isSign := hsm.SignCommands[e.Command]; isSign {
				entry.SignAuditID = &signAuditID
				linked = true
			}
		}
		dbEntries = append([]models.HSMAuditEntry{entry}, dbEntries...)
	}

	if err := a.db.StoreHSMAuditEntries(dbEntries); err != nil {
		log.Printf("WARNING: failed to store HSM audit entries: %v", err)
	}
}

func (a *API) ExportCombinedAuditLog(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can export combined audit logs")
		return
	}

	export, err := a.db.ExportCombinedAuditLog()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to export: %v", err)
		return
	}

	// Add device serial
	serial, _ := hsm.GetDeviceSerial(a.hsmCfg)
	export.DeviceSerial = serial

	// Add attestation certs for all CA keys referenced in sign operations
	export.KeyAttestations = make(map[string]string)
	caIDs := make(map[string]bool)
	for _, op := range export.SignOps {
		caIDs[op.CAID] = true
	}
	for caID := range caIDs {
		ca, err := a.db.GetCA(caID)
		if err != nil || ca == nil {
			continue
		}
		keyLabel := pki.ExtractKeyLabel(ca.PKCS11URI)
		if keyLabel == "" {
			continue
		}
		a.consumeHSMAuditLogs("") // free space before attestation calls
		cert, err := hsm.GetKeyAttestationCert(a.hsmCfg, keyLabel)
		if err != nil {
			log.Printf("WARNING: could not get attestation cert for key %q: %v", keyLabel, err)
			continue
		}
		export.KeyAttestations[keyLabel] = cert
	}
	a.consumeHSMAuditLogs("") // consume entries from serial/attestation calls

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=combined-audit-log.json")
	json.NewEncoder(w).Encode(export)
}

func (a *API) GetSignedAuditLog(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can export signed audit logs")
		return
	}

	// First consume any pending HSM entries to the DB
	a.consumeHSMAuditLogs("")

	// Get all DB-stored HSM entries
	export, err := a.db.ExportCombinedAuditLog()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to export DB entries: %v", err)
		return
	}

	// Convert DB entries to hsm.AuditLogEntry for signing
	var allEntries []hsm.AuditLogEntry
	for _, e := range export.HSMEntries {
		allEntries = append(allEntries, hsm.AuditLogEntry{
			Number: e.Number, Command: e.Command, Length: e.Length,
			SessionKey: e.SessionKey, TargetKey: e.TargetKey, SecondKey: e.SecondKey,
			Result: e.Result, Tick: e.Tick, Hash: e.Hash,
		})
	}

	// Sign the complete log (all entries from DB)
	signedLog, err := hsm.SignAuditEntries(a.hsmCfg, allEntries)
	a.consumeHSMAuditLogs("") // consume entries created by the signing/attestation operations
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to sign audit log: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=signed-audit-log.json")
	json.NewEncoder(w).Encode(signedLog)
}

func (a *API) ProvisionHSMAudit(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can provision HSM audit logging")
		return
	}

	// Consume pending entries to DB, then check for device init entry in DB
	a.consumeHSMAuditLogs("")

	export, err := a.db.ExportCombinedAuditLog()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read audit log: %v", err)
		return
	}
	var dbEntries []hsm.AuditLogEntry
	for _, e := range export.HSMEntries {
		dbEntries = append(dbEntries, hsm.AuditLogEntry{
			Number: e.Number, Command: e.Command, Length: e.Length,
			SessionKey: e.SessionKey, TargetKey: e.TargetKey, SecondKey: e.SecondKey,
			Result: e.Result, Tick: e.Tick, Hash: e.Hash,
		})
	}
	if err := hsm.CheckDeviceInitEntry(dbEntries); err != nil {
		writeError(w, http.StatusPreconditionFailed, "%v", err)
		return
	}

	output, err := hsm.ProvisionAuditLogging(a.hsmCfg)
	a.consumeHSMAuditLogs("")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to provision: %v", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "provisioned",
		"output": output,
	})
}

func (a *API) FactoryResetHSM(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can factory reset the HSM")
		return
	}

	if err := hsm.FactoryReset(a.hsmCfg); err != nil {
		writeError(w, http.StatusInternalServerError, "factory reset failed: %v", err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "factory reset complete — all keys and logs have been erased",
	})
}

func (a *API) GetMyRestrictions(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")
	user := middleware.GetUserInfo(r.Context())

	certFormat := r.URL.Query().Get("format")
	if certFormat == "" {
		certFormat = "ssh"
	}
	groupIDs, _ := a.db.GetUserGroups(user.Subject)
	rs, err := a.db.GetEffectiveRestrictionSet(caID, user.Subject, groupIDs, certFormat)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get restrictions: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, rs)
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

// keyRefForCA resolves the provider key reference for a CA. When the CA's URI
// is a pkcs11: URI its object= label is authoritative (it may differ from the
// CA label when an operator imported a pre-existing key); otherwise — e.g. for
// software: URIs — the CA label is the key label.
func keyRefForCA(ca *models.CA) keyprovider.KeyRef {
	label := pki.ExtractKeyLabel(ca.PKCS11URI)
	if label == "" {
		label = ca.Label
	}
	return keyprovider.KeyRef{Label: label}
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

// enforceRestrictions validates a sign request against a restriction set.
func enforceRestrictions(rs *models.RestrictionSet, req *models.SignRequest, user *models.UserInfo) error {
	if rs.DenyAll {
		return fmt.Errorf("signing is denied by restriction set %q", rs.Name)
	}

	// Check cert type
	if len(rs.AllowedCertTypes) > 0 {
		ct := req.CertType
		if ct == "" {
			ct = "user"
		}
		allowed := false
		for _, t := range rs.AllowedCertTypes {
			if t == ct {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("cert type %q not allowed (allowed: %v)", ct, rs.AllowedCertTypes)
		}
	}

	// Check principals
	if len(rs.AllowedPrincipals) > 0 {
		if len(req.Principals) == 0 {
			return fmt.Errorf("at least one principal is required (allowed: %v)", rs.AllowedPrincipals)
		}
		for _, p := range req.Principals {
			allowed := false
			for _, ap := range rs.AllowedPrincipals {
				if ap == p || ap == "*" {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("principal %q not allowed (allowed: %v)", p, rs.AllowedPrincipals)
			}
		}
	}

	// Check extensions
	if rs.DenyExtensions && len(req.Extensions) > 0 {
		return fmt.Errorf("custom extensions are not allowed by this restriction set")
	}
	if !rs.DenyExtensions && len(rs.AllowedExtensions) > 0 && req.Extensions != nil {
		allowedSet := make(map[string]bool)
		for _, e := range rs.AllowedExtensions {
			allowedSet[e] = true
		}
		for ext := range req.Extensions {
			if !allowedSet[ext] {
				return fmt.Errorf("extension %q not allowed", ext)
			}
		}
	}

	// Check critical options
	if rs.DenyCriticalOptions && len(req.CriticalOptions) > 0 {
		return fmt.Errorf("critical options are not allowed by this restriction set")
	}

	// Check reason requirement
	if rs.RequireReason && req.Reason == "" {
		return fmt.Errorf("reason is required by this restriction set")
	}

	return nil
}

// Restriction Set handlers

func (a *API) ListAllRestrictionSets(w http.ResponseWriter, r *http.Request) {
	sets, err := a.db.ListAllRestrictionSets()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list restriction sets: %v", err)
		return
	}
	if sets == nil {
		sets = []models.RestrictionSet{}
	}
	writeJSON(w, http.StatusOK, sets)
}

func (a *API) CreateRestrictionSetGlobal(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUserInfo(r.Context())
	if !user.IsRoot {
		writeError(w, http.StatusForbidden, "only root can create global restriction sets")
		return
	}

	var rs models.RestrictionSet
	if err := json.NewDecoder(r.Body).Decode(&rs); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	rs.ID = uuid.New().String()
	if rs.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if err := a.db.CreateRestrictionSet(&rs); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create restriction set: %v", err)
		return
	}
	writeJSON(w, http.StatusCreated, rs)
}

func (a *API) ListRestrictionSets(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")
	sets, err := a.db.ListRestrictionSets(caID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list restriction sets: %v", err)
		return
	}
	if sets == nil {
		sets = []models.RestrictionSet{}
	}
	writeJSON(w, http.StatusOK, sets)
}

func (a *API) CreateRestrictionSet(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")
	user := middleware.GetUserInfo(r.Context())

	if !user.IsRoot {
		hasAccess, err := a.checkPermission(user, caID, models.PermConfigureCA)
		if err != nil || !hasAccess {
			writeError(w, http.StatusForbidden, "need CONFIGURE_CA permission")
			return
		}
	}

	var rs models.RestrictionSet
	if err := json.NewDecoder(r.Body).Decode(&rs); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}

	rs.ID = uuid.New().String()
	rs.CAID = caID

	if rs.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	if err := a.db.CreateRestrictionSet(&rs); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create restriction set: %v", err)
		return
	}
	writeJSON(w, http.StatusCreated, rs)
}

func (a *API) UpdateRestrictionSet(w http.ResponseWriter, r *http.Request) {
	rsID := r.PathValue("id")
	user := middleware.GetUserInfo(r.Context())

	existing, err := a.db.GetRestrictionSet(rsID)
	if err != nil || existing == nil {
		writeError(w, http.StatusNotFound, "restriction set not found")
		return
	}

	if !user.IsRoot {
		hasAccess, err := a.checkPermission(user, existing.CAID, models.PermConfigureCA)
		if err != nil || !hasAccess {
			writeError(w, http.StatusForbidden, "need CONFIGURE_CA permission")
			return
		}
	}

	var rs models.RestrictionSet
	if err := json.NewDecoder(r.Body).Decode(&rs); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	rs.ID = rsID
	rs.CAID = existing.CAID

	if err := a.db.UpdateRestrictionSet(&rs); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update restriction set: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, rs)
}

func (a *API) DeleteRestrictionSet(w http.ResponseWriter, r *http.Request) {
	rsID := r.PathValue("id")
	user := middleware.GetUserInfo(r.Context())

	existing, err := a.db.GetRestrictionSet(rsID)
	if err != nil || existing == nil {
		writeError(w, http.StatusNotFound, "restriction set not found")
		return
	}

	if !user.IsRoot {
		hasAccess, err := a.checkPermission(user, existing.CAID, models.PermConfigureCA)
		if err != nil || !hasAccess {
			writeError(w, http.StatusForbidden, "need CONFIGURE_CA permission")
			return
		}
	}

	if err := a.db.DeleteRestrictionSet(rsID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete restriction set: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *API) SetDefaultRestrictionSet(w http.ResponseWriter, r *http.Request) {
	caID := r.PathValue("id")
	user := middleware.GetUserInfo(r.Context())

	if !user.IsRoot {
		hasAccess, err := a.checkPermission(user, caID, models.PermConfigureCA)
		if err != nil || !hasAccess {
			writeError(w, http.StatusForbidden, "need CONFIGURE_CA permission")
			return
		}
	}

	var req struct {
		RestrictionSetID *string `json:"restriction_set_id"`
		Type             string  `json:"type"` // "ssh" or "x509"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: %v", err)
		return
	}
	if req.Type == "" {
		req.Type = "ssh"
	}

	if err := a.db.SetCADefaultRestrictionSet(caID, req.Type, req.RestrictionSetID); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to set default restriction set: %v", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}
