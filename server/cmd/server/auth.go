package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/coreos/go-oidc/v3/oidc"
)

// defaultStepUpOperations is the set of high-risk operations gated behind
// WebAuthn step-up when the operator enables WebAuthn but does not name a set.
var defaultStepUpOperations = []string{
	"cert.revoke", "cert.revoke_bulk", "ca.init_root", "ca.issue_intermediate",
	"ca.cross_sign", "ca.rotate", "ca.retire", "ca.manage",
	"ssh.ca_init", "ssh.revoke", "hsm.factory_reset",
}

// setupOperatorAuth wires the strong operator-authentication stack (Task 50):
// console sessions, interactive OIDC login with claim/group -> RBAC mapping,
// mutual-TLS client-certificate binding, WebAuthn step-up, password login, and
// the CSRF plumbing. It registers the /auth/* endpoints on mux, configures the
// auth middleware, and advertises the enabled mechanisms to the console. It
// returns the client-CA pool to install on the TLS listener when mTLS is
// enabled (nil otherwise).
func setupOperatorAuth(
	cfg *config.Config,
	db *database.DB,
	oidcProvider *auth.OIDCProvider,
	tenantAssignments *rbac.TenantAssignments,
	authMw *middleware.AuthMiddleware,
	api *handlers.API,
	mux *http.ServeMux,
) (*x509.CertPool, error) {
	ac := &cfg.Auth

	// --- session store ---
	ttl := time.Duration(ac.Session.TTLMinutes) * time.Minute
	stepUpTTL := time.Duration(ac.WebAuthn.StepUpTTLMinutes) * time.Minute
	sessions := authn.NewSessionStore(ttl, stepUpTTL)
	cookieName := ac.Session.CookieName
	// Cookies are Secure (HTTPS-only) unless the operator opts out for local
	// plaintext testing; the server itself refuses cleartext HTTP by default.
	secure := !ac.Session.Insecure

	mgr := authn.NewManager(authn.ManagerOptions{
		Sessions:      sessions,
		SessionCookie: cookieName,
		Secure:        secure,
		Audit:         db,
		RequestID:     middleware.RequestID,
	})

	// --- claim/group -> RBAC role mapping ---
	mapper := buildClaimMapper(ac.OIDC)

	// --- interactive OIDC login ---
	oidcLoginEnabled := false
	if ac.OIDC.Enabled {
		provider, verifier, clientID, err := buildLoginProvider(cfg, oidcProvider)
		if err != nil {
			return nil, fmt.Errorf("oidc login: %w", err)
		}
		resolve := buildPrincipalResolver(db, tenantAssignments, mapper, ac.OIDC.AllowZeroRole)
		login, err := authn.NewOIDCLogin(mgr, authn.OIDCLoginConfig{
			Provider:     provider,
			Verifier:     verifier,
			ClientID:     clientID,
			ClientSecret: ac.OIDC.ClientSecret,
			RedirectURL:  ac.OIDC.RedirectURL,
			Scopes:       ac.OIDC.Scopes,
			Resolve:      resolve,
		})
		if err != nil {
			return nil, fmt.Errorf("oidc login: %w", err)
		}
		mgr.SetLogin(login)
		oidcLoginEnabled = true
		log.Printf("Interactive OIDC login enabled (redirect_url=%s)", ac.OIDC.RedirectURL)
	}

	// --- mutual-TLS client-certificate binding ---
	var clientCAs *x509.CertPool
	if ac.MTLS.Enabled {
		pool, err := loadClientCAs(ac.MTLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("mtls: %w", err)
		}
		binder := authn.NewCertBinder(buildCertBindings(ac.MTLS.Bindings), pool)
		authMw.SetCertBinder(binder)
		clientCAs = pool
		log.Printf("mTLS client-cert authentication configured (%d binding(s))", len(ac.MTLS.Bindings))
	}

	// --- WebAuthn step-up ---
	webAuthnEnabled := false
	if ac.WebAuthn.Enabled {
		wa, err := authn.NewWebAuthn(mgr, authn.WebAuthnConfig{
			RPID:    ac.WebAuthn.RPID,
			RPName:  ac.WebAuthn.RPName,
			Origins: ac.WebAuthn.Origins,
			Store:   db,
		})
		if err != nil {
			return nil, fmt.Errorf("webauthn: %w", err)
		}
		mgr.SetWebAuthn(wa)
		ops := ac.WebAuthn.StepUpOperations
		if len(ops) == 0 {
			ops = defaultStepUpOperations
		}
		// Warn on a configured operation that no route actually gates, so a typo in
		// step_up_operations cannot silently leave an intended operation ungated.
		gated := make(map[string]bool, len(defaultStepUpOperations))
		for _, o := range defaultStepUpOperations {
			gated[o] = true
		}
		for _, o := range ops {
			if !gated[o] {
				log.Printf("WARNING: auth.webauthn.step_up_operations lists %q, which is not a gated route; "+
					"recognized operations are %v", o, defaultStepUpOperations)
			}
		}
		authMw.SetStepUpOperations(ops)
		webAuthnEnabled = true
		log.Printf("WebAuthn step-up enabled (rp_id=%s, gated operations=%v)", ac.WebAuthn.RPID, ops)
	}

	// --- password login (session-establishing basic-auth equivalent) ---
	passwordLogin := false
	if cfg.Policy.RootBasicAuthEnabled() {
		user, pass := cfg.RootUser.Username, cfg.RootUser.Password
		mgr.SetPasswordAuthenticator(func(u, p string) (*models.UserInfo, bool) {
			if subtle.ConstantTimeCompare([]byte(u), []byte(user)) == 1 &&
				subtle.ConstantTimeCompare([]byte(p), []byte(pass)) == 1 {
				return &models.UserInfo{Subject: "root", Name: "Root User", IsRoot: true}, true
			}
			return nil, false
		})
		passwordLogin = true
	}

	// --- LDAP / Active Directory authentication ---
	ldapLogin := false
	if ac.LDAP.Enabled {
		ldapMapper := authn.NewClaimMapper(ac.LDAP.GroupsClaim, buildLDAPRoleMappings(ac.LDAP.RoleMappings))
		resolver := buildLDAPResolver(db, tenantAssignments, ldapMapper, ac.LDAP.AllowZeroRole)
		ldapAuth, err := buildLDAPAuthenticator(ac.LDAP, resolver)
		if err != nil {
			return nil, fmt.Errorf("ldap: %w", err)
		}
		mgr.SetLDAPAuthenticator(ldapAuth)
		authMw.SetLDAPAuthenticator(ldapAuth)
		ldapLogin = true
		log.Printf("LDAP/Active Directory authentication enabled (%s)", ldapAuth.Describe())
	}

	// --- register routes + middleware wiring ---
	mgr.Register(mux)
	authMw.SetSessions(sessions, cookieName)
	api.SetAuthInfo(handlers.AuthInfo{
		OIDCLogin:     oidcLoginEnabled,
		PasswordLogin: passwordLogin,
		LDAPLogin:     ldapLogin,
		WebAuthn:      webAuthnEnabled,
	})

	return clientCAs, nil
}

// buildLDAPRoleMappings translates the config LDAP role mappings into
// authn.ClaimMapping (the same type OIDC uses), so directory-group -> role
// resolution runs through the shared ClaimMapper.
func buildLDAPRoleMappings(in []config.ClaimMappingConfig) []authn.ClaimMapping {
	out := make([]authn.ClaimMapping, 0, len(in))
	for _, m := range in {
		out = append(out, authn.ClaimMapping{
			Claim:  m.Claim,
			Value:  m.Value,
			Tenant: m.Tenant,
			Roles:  toRbacRoles(m.Roles),
		})
	}
	return out
}

// buildLDAPAuthenticator maps the auth.ldap config block onto the authn
// authenticator: it splits the URL list, resolves the bind-password credential
// source through the Task 111 pin_source machinery, and reads the TLS trust
// material. A nil resolver is permitted for probe-only construction (the doctor
// check), which never performs an end-user login.
func buildLDAPAuthenticator(c config.AuthLDAPConfig, resolve authn.LDAPPrincipalResolver) (*authn.LDAPAuthenticator, error) {
	if resolve == nil {
		// The authenticator requires a resolver even when only Probe() is used; a
		// deny-all placeholder keeps NewLDAPAuthenticator's invariant without ever
		// authorizing anyone.
		resolve = func(authn.DirectoryIdentity) (*models.UserInfo, error) {
			return nil, fmt.Errorf("ldap: authentication not available in probe mode")
		}
	}
	urls := splitLDAPURLs(c.URL)
	if len(urls) == 0 {
		return nil, fmt.Errorf("auth.ldap.url is required")
	}

	// The service-account bind password flows through the same credential-source
	// abstraction as the HSM PIN (inline, env, file, Vault, AWS, Azure).
	bindSource, err := keyprovider.NewPinSource(pinSourceSettings(c.BindPasswordSource), c.BindPassword)
	if err != nil {
		return nil, fmt.Errorf("bind_password_source: %w", err)
	}

	var caPEM []byte
	if c.TLS.CAFile != "" {
		caPEM, err = os.ReadFile(c.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading tls.ca_file %q: %w", c.TLS.CAFile, err)
		}
	}
	minVer := uint16(0)
	switch c.TLS.MinVersion {
	case "", "1.2":
		minVer = tls.VersionTLS12
	case "1.3":
		minVer = tls.VersionTLS13
	default:
		return nil, fmt.Errorf("tls.min_version %q must be \"1.2\" or \"1.3\"", c.TLS.MinVersion)
	}

	cfg := authn.LDAPConfig{
		URLs:                   urls,
		StartTLS:               c.StartTLS,
		InsecureAllowCleartext: c.InsecureAllowCleartext,
		BindDN:                 c.BindDN,
		BindPassword:           bindSource,
		UserBaseDN:             c.UserBaseDN,
		UserFilter:             c.UserFilter,
		UserDNTemplate:         c.UserDNTemplate,
		GroupBaseDN:            c.GroupBaseDN,
		GroupFilter:            c.GroupFilter,
		GroupAttribute:         c.GroupAttribute,
		UsernameAttribute:      c.UsernameAttribute,
		EmailAttribute:         c.EmailAttribute,
		NameAttribute:          c.NameAttribute,
		Timeout:                time.Duration(c.TimeoutSeconds) * time.Second,
		TLSCACertPEM:           caPEM,
		TLSServerName:          c.TLS.ServerName,
		TLSInsecureSkipVerify:  c.TLS.InsecureSkipVerify,
		TLSMinVersion:          minVer,
	}
	return authn.NewLDAPAuthenticator(cfg, resolve)
}

// splitLDAPURLs splits a space/comma-separated list of directory URLs.
func splitLDAPURLs(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// buildClaimMapper translates the config role mappings into an authn.ClaimMapper.
func buildClaimMapper(c config.AuthOIDCConfig) *authn.ClaimMapper {
	mappings := make([]authn.ClaimMapping, 0, len(c.RoleMappings))
	for _, m := range c.RoleMappings {
		mappings = append(mappings, authn.ClaimMapping{
			Claim:  m.Claim,
			Value:  m.Value,
			Tenant: m.Tenant,
			Roles:  toRbacRoles(m.Roles),
		})
	}
	return authn.NewClaimMapper(c.GroupsClaim, mappings)
}

// buildCertBindings translates the config cert bindings into authn.CertBinding.
func buildCertBindings(in []config.CertBindingConfig) []authn.CertBinding {
	out := make([]authn.CertBinding, 0, len(in))
	for _, b := range in {
		cb := authn.CertBinding{
			SubjectCN: b.SubjectCN,
			SubjectDN: b.SubjectDN,
			SANDNS:    b.SANDNS,
			SANURI:    b.SANURI,
			SANEmail:  b.SANEmail,
			Subject:   b.Subject,
			Name:      b.Name,
			Roles:     toRbacRoles(b.Roles),
		}
		if len(b.TenantRoles) > 0 {
			cb.TenantRoles = make(map[string][]rbac.Role, len(b.TenantRoles))
			for tid, roles := range b.TenantRoles {
				cb.TenantRoles[tid] = toRbacRoles(roles)
			}
		}
		out = append(out, cb)
	}
	return out
}

func toRbacRoles(in []string) []rbac.Role {
	out := make([]rbac.Role, 0, len(in))
	for _, r := range in {
		out = append(out, rbac.Role(r))
	}
	return out
}

// buildLoginProvider resolves the OIDC provider and verifier used for
// interactive login. It reuses the already-discovered top-level provider when
// the issuer matches (avoiding a second discovery round-trip), and otherwise
// performs discovery against the auth-block issuer. The verifier is bound to the
// interactive-login client id.
func buildLoginProvider(cfg *config.Config, existing *auth.OIDCProvider) (*oidc.Provider, *oidc.IDTokenVerifier, string, error) {
	issuer := cfg.Auth.OIDC.IssuerURL
	if issuer == "" {
		issuer = cfg.OIDC.IssuerURL
	}
	clientID := cfg.Auth.OIDC.ClientID
	if clientID == "" {
		clientID = cfg.OIDC.ClientID
	}
	if clientID == "" {
		return nil, nil, "", fmt.Errorf("no client_id configured (auth.oidc.client_id or oidc.client_id)")
	}
	if existing != nil && existing.IssuerURL() == issuer {
		return existing.Provider(), existing.VerifierForClient(clientID), clientID, nil
	}
	provider, err := oidc.NewProvider(context.Background(), issuer)
	if err != nil {
		return nil, nil, "", fmt.Errorf("discovering issuer %q: %w", issuer, err)
	}
	return provider, provider.Verifier(&oidc.Config{ClientID: clientID}), clientID, nil
}

// buildPrincipalResolver returns a PrincipalResolver that maps a verified OIDC
// identity to a console principal. It unions the subject/email/group assignments
// from internal/rbac with the claim/group -> role mapping, across platform and
// per-tenant scopes. When the resolved principal holds no role and zero-role
// logins are not permitted, it denies the login.
func buildPrincipalResolver(
	db *database.DB,
	ta *rbac.TenantAssignments,
	mapper *authn.ClaimMapper,
	allowZeroRole bool,
) authn.PrincipalResolver {
	return func(idToken *oidc.IDToken, claims map[string]interface{}) (*models.UserInfo, error) {
		subject := idToken.Subject
		email, _ := claims["email"].(string)
		emailVerified, _ := claims["email_verified"].(bool)
		name, _ := claims["name"].(string)

		// Groups combine the IdP group claim with any internal group memberships.
		groups := mapper.Groups(claims)
		if internal, err := db.GetUserGroups(subject); err == nil {
			groups = append(groups, internal...)
		}
		return resolveConsolePrincipal(ta, mapper, allowZeroRole,
			subject, email, emailVerified, name, groups, claims)
	}
}

// resolveConsolePrincipal unions the claim/group -> RBAC role mapping (the
// ClaimMapper) with the rbac subject/email/group assignments, across platform and
// per-tenant scopes, and enforces the zero-role login policy. It is the shared
// core of the OIDC and LDAP (Task 159) login paths: both compute a subject, email,
// display name, the caller's groups, and the claims map fed to the mapper, then
// delegate here so the two paths cannot drift in how roles are resolved.
func resolveConsolePrincipal(
	ta *rbac.TenantAssignments,
	mapper *authn.ClaimMapper,
	allowZeroRole bool,
	subject, email string,
	emailVerified bool,
	name string,
	groups []string,
	claims map[string]interface{},
) (*models.UserInfo, error) {
	mapPlatform, mapTenant := mapper.Resolve(claims)

	platform := dedupRoles(append(ta.PlatformRolesFor(subject, email, emailVerified, groups), mapPlatform...))

	tenantRoles := make(map[string][]string)
	addTenant := func(tid string, roles []rbac.Role) {
		if len(roles) == 0 {
			return
		}
		combined := append(rolesFromStrings(tenantRoles[tid]), roles...)
		tenantRoles[tid] = dedupRoles(combined)
	}
	for _, tid := range ta.Tenants() {
		addTenant(tid, ta.TenantRolesFor(tid, subject, email, emailVerified, groups))
	}
	for tid, roles := range mapTenant {
		addTenant(tid, roles)
	}
	for tid := range tenantRoles {
		if len(tenantRoles[tid]) == 0 {
			delete(tenantRoles, tid)
		}
	}

	info := &models.UserInfo{
		Subject:       subject,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		Roles:         platform,
		// Carry the resolved group identities onto the principal: resource-scoped
		// grants (Task 191) may name an existing IdP/directory group directly, and
		// that membership is only knowable here, at login.
		Groups: dedupStrings(groups),
	}
	if len(tenantRoles) > 0 {
		info.TenantRoles = tenantRoles
	}
	if !allowZeroRole && len(info.Roles) == 0 && len(info.TenantRoles) == 0 {
		return nil, fmt.Errorf("no RBAC role is assigned to this account; contact an administrator")
	}
	return info, nil
}

// buildLDAPResolver returns an authn.LDAPPrincipalResolver that maps a verified
// directory identity to a console principal, reusing resolveConsolePrincipal (and
// thus the same ClaimMapper and rbac assignments as OIDC). Directory groups are
// presented to the mapper under its configured groups claim, and a directory
// email — authoritative within the organization — is treated as verified so
// email-keyed rbac assignments apply.
func buildLDAPResolver(
	db *database.DB,
	ta *rbac.TenantAssignments,
	mapper *authn.ClaimMapper,
	allowZeroRole bool,
) authn.LDAPPrincipalResolver {
	return func(id authn.DirectoryIdentity) (*models.UserInfo, error) {
		groups := append([]string(nil), id.Groups...)
		if internal, err := db.GetUserGroups(id.Subject); err == nil {
			groups = append(groups, internal...)
		}
		claims := map[string]interface{}{mapper.GroupsClaim(): groups}
		name := id.Name
		if name == "" {
			name = id.Username
		}
		return resolveConsolePrincipal(ta, mapper, allowZeroRole,
			id.Subject, id.Email, id.Email != "", name, groups, claims)
	}
}

// rolesFromStrings converts stored role strings back to rbac.Role for merging.
func rolesFromStrings(in []string) []rbac.Role {
	out := make([]rbac.Role, 0, len(in))
	for _, r := range in {
		out = append(out, rbac.Role(r))
	}
	return out
}

// loadClientCAs reads a PEM bundle of client-certificate CAs into a pool.
func loadClientCAs(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading ca_file %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("ca_file %q contained no PEM certificates", path)
	}
	return pool, nil
}
