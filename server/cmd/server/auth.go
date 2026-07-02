package main

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/auth"
	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/handlers"
	"github.com/blechschmidt/secsy-pki/server/internal/middleware"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
	"github.com/coreos/go-oidc/v3/oidc"
)

// defaultStepUpOperations is the set of high-risk operations gated behind
// WebAuthn step-up when the operator enables WebAuthn but does not name a set.
var defaultStepUpOperations = []string{
	"cert.revoke", "ca.init_root", "ca.issue_intermediate",
	"ca.cross_sign", "ca.manage", "hsm.factory_reset",
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

	// --- register routes + middleware wiring ---
	mgr.Register(mux)
	authMw.SetSessions(sessions, cookieName)
	api.SetAuthInfo(handlers.AuthInfo{
		OIDCLogin:     oidcLoginEnabled,
		PasswordLogin: passwordLogin,
		WebAuthn:      webAuthnEnabled,
	})

	return clientCAs, nil
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

		mapPlatform, mapTenant := mapper.Resolve(claims)

		platform := dedupRoles(append(ta.PlatformRolesFor(subject, email, emailVerified, groups), mapPlatform...))

		tenantRoles := make(map[string][]string)
		seen := map[string]bool{}
		addTenant := func(tid string, roles []rbac.Role) {
			if len(roles) == 0 {
				return
			}
			combined := append(rolesFromStrings(tenantRoles[tid]), roles...)
			tenantRoles[tid] = dedupRoles(combined)
		}
		for _, tid := range ta.Tenants() {
			addTenant(tid, ta.TenantRolesFor(tid, subject, email, emailVerified, groups))
			seen[tid] = true
		}
		for tid, roles := range mapTenant {
			addTenant(tid, roles)
			seen[tid] = true
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
		}
		if len(tenantRoles) > 0 {
			info.TenantRoles = tenantRoles
		}
		if !allowZeroRole && len(info.Roles) == 0 && len(info.TenantRoles) == 0 {
			return nil, fmt.Errorf("no RBAC role is assigned to this account; contact an administrator")
		}
		return info, nil
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
