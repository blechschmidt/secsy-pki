package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	// Adopting foreign key material and provisioning the deployment's own signing
	// credentials (Task 198) belong here for the same reason as init-root: they
	// change what this PKI will sign with. Un-blocking a compromised key and
	// pruning the issued-certificate inventory destroy evidence, so they join too.
	"key.import", "ca.import", "signing.key_provision", "tsa.key_provision",
	"key.unblock", "inventory.retention", "publish.snapshot",
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
	bearerProviders *auth.MultiProvider,
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

	// --- interactive OIDC login (one or more providers) ---
	// Several console identity providers may be configured side by side (Task
	// 212): each gets its own client registration, scopes, and claim -> role
	// mapping, and each is offered as its own sign-in button. A provider whose IdP
	// cannot be discovered at boot is skipped with a warning rather than taking
	// the others down — but if none comes up, login was configured and is wholly
	// unavailable, which is fatal.
	oidcLoginEnabled := false
	if ac.OIDC.Enabled {
		providers := cfg.ConsoleOIDCProviders()
		var failures []error
		for _, pc := range providers {
			provider, verifier, err := buildLoginProvider(pc, bearerProviders)
			if err != nil {
				failures = append(failures, fmt.Errorf("provider %q: %w", pc.Name, err))
				log.Printf("WARNING: interactive OIDC login provider %q is unavailable: %v", pc.Name, err)
				continue
			}
			mapper := authn.NewClaimMapper(pc.GroupsClaim, buildClaimMappings(pc.RoleMappings))
			resolve := buildPrincipalResolver(db, tenantAssignments, mapper, ac.OIDC.AllowZeroRoleFor(pc))
			login, err := authn.NewOIDCLogin(mgr, authn.OIDCLoginConfig{
				Name:         pc.Name,
				DisplayName:  pc.DisplayName,
				Default:      pc.Default,
				Provider:     provider,
				Verifier:     verifier,
				ClientID:     pc.ClientID,
				ClientSecret: pc.ClientSecret,
				RedirectURL:  pc.RedirectURL,
				Scopes:       pc.Scopes,
				Resolve:      resolve,
				RequirePKCE:  ac.OIDC.RequirePKCEFor(pc),
			})
			if err != nil {
				return nil, fmt.Errorf("oidc login provider %q: %w", pc.Name, err)
			}
			if err := mgr.AddLogin(login); err != nil {
				return nil, fmt.Errorf("oidc login: %w", err)
			}
			oidcLoginEnabled = true
			client := "confidential client"
			if login.PublicClient() {
				client = "public client (no secret; PKCE binds the exchange)"
			}
			log.Printf("Interactive OIDC login provider %q enabled (issuer=%s redirect_url=%s pkce=%s %s)",
				pc.Name, pc.IssuerURL, pc.RedirectURL, login.PKCE().Method, client)
			// Every authorization request carries an S256 challenge regardless, but
			// an IdP that does not implement PKCE simply ignores it — and then a
			// stolen authorization code is enough to complete a login. Say so once at
			// boot so the gap is visible without reading the IdP's metadata by hand.
			if !login.PKCE().Advertised {
				log.Printf("WARNING: OIDC login provider %q does not advertise the S256 code-challenge "+
					"method (code_challenge_methods_supported=%v); the PKCE challenge this server sends "+
					"may be ignored by the IdP. Set auth.oidc.require_pkce to refuse such a provider.",
					pc.Name, login.PKCE().Methods)
			}
		}
		if !oidcLoginEnabled {
			return nil, fmt.Errorf("oidc login: no configured provider could be initialized: %w", errors.Join(failures...))
		}
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
		ldapMapper := authn.NewClaimMapper(ac.LDAP.GroupsClaim, buildClaimMappings(ac.LDAP.RoleMappings))
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
		OIDCLogin:       oidcLoginEnabled,
		PasswordLogin:   passwordLogin,
		LDAPLogin:       ldapLogin,
		WebAuthn:        webAuthnEnabled,
		LoginProviders:  mgr.LoginProviders(),
		BearerProviders: bearerProviders.Providers(),
	})

	return clientCAs, nil
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
	bindSource, err := keyprovider.NewPinSource(c.BindPasswordSource.Settings(), c.BindPassword)
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

// buildClaimMappings translates config claim -> role mappings into the authn
// form. One translation serves the OIDC login providers, the machine-Bearer
// providers, and LDAP, so the three cannot drift in how a mapping is read.
func buildClaimMappings(in []config.ClaimMappingConfig) []authn.ClaimMapping {
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

// buildBearerClaimMappers builds one claim mapper per machine-token (Bearer)
// provider, keyed by provider name. Every provider gets a mapper even when it
// declares no role mappings: the mapper is also what extracts the caller's group
// memberships from that provider's configured groups claim, which the central
// rbac group assignments and the resource-scoped grants both need.
func buildBearerClaimMappers(providers []config.OIDCProviderConfig) map[string]*authn.ClaimMapper {
	out := make(map[string]*authn.ClaimMapper, len(providers))
	for _, p := range providers {
		out[p.Name] = authn.NewClaimMapper(p.GroupsClaim, buildClaimMappings(p.RoleMappings))
	}
	return out
}

// bearerClaimResolver returns the hook the auth middleware applies to a principal
// authenticated by an OIDC Bearer token. It resolves roles through exactly the
// same code as the interactive-login path (resolveConsolePrincipal), but with the
// claim mapper of the provider that verified THIS token — which is what keeps a
// grant made to one federated issuer's workload identity from being claimable by
// another issuer asserting the same subject string.
//
// Unlike the login path it never denies: a machine caller that resolves to no
// role is authenticated and then refused by the authorization gate, as the Bearer
// path has always done.
// groupLookup resolves the internal (database-recorded) group memberships of a
// subject. *database.DB satisfies it; naming it as an interface keeps the Bearer
// claim resolver unit-testable without standing up a store.
type groupLookup interface {
	GetUserGroups(subject string) ([]string, error)
}

func bearerClaimResolver(
	mappers map[string]*authn.ClaimMapper,
	ta *rbac.TenantAssignments,
	db groupLookup,
) func(*models.UserInfo, *auth.Claims) {
	return func(info *models.UserInfo, claims *auth.Claims) {
		mapper := mappers[claims.Provider]
		if mapper == nil || info == nil {
			return
		}
		groups := mapper.Groups(claims.Raw)
		if db != nil {
			if internal, err := db.GetUserGroups(info.Subject); err == nil {
				groups = append(groups, internal...)
			}
		}
		resolved, err := resolveConsolePrincipal(ta, mapper, true,
			info.Subject, info.Email, info.EmailVerified, info.Name, groups, claims.Raw)
		if err != nil || resolved == nil {
			return
		}
		info.Roles = resolved.Roles
		info.TenantRoles = resolved.TenantRoles
		info.Groups = resolved.Groups
	}
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

// buildLoginProvider resolves the OIDC provider and verifier for one interactive
// login provider. It reuses an already-discovered machine-Bearer provider when
// the issuer matches (avoiding a second discovery round-trip for the common case
// where one IdP serves both), and otherwise performs discovery itself. The
// verifier is bound to this provider's console client id, which is routinely a
// different OAuth client from the Bearer audience.
func buildLoginProvider(pc config.AuthOIDCProviderConfig, existing *auth.MultiProvider) (*oidc.Provider, *oidc.IDTokenVerifier, error) {
	if pc.IssuerURL == "" {
		return nil, nil, fmt.Errorf("no issuer_url configured")
	}
	if pc.ClientID == "" {
		return nil, nil, fmt.Errorf("no client_id configured")
	}
	if p := existing.Lookup(pc.IssuerURL); p != nil {
		return p.Provider(), p.VerifierForClient(pc.ClientID), nil
	}
	provider, err := oidc.NewProvider(context.Background(), pc.IssuerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("discovering issuer %q: %w", pc.IssuerURL, err)
	}
	return provider, provider.Verifier(&oidc.Config{ClientID: pc.ClientID}), nil
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

// bearerProviderSpecs renders the configured machine-token issuers into the
// verifier's provider specs. Each provider's accepted audiences are its client_id
// unioned with its audiences list — the control that keeps a token minted for a
// different relying party of the same IdP from authenticating here.
func bearerProviderSpecs(cfg *config.Config) []auth.ProviderSpec {
	providers := cfg.BearerOIDCProviders()
	out := make([]auth.ProviderSpec, 0, len(providers))
	for _, p := range providers {
		out = append(out, auth.ProviderSpec{
			Name:      p.Name,
			IssuerURL: p.IssuerURL,
			Audiences: p.Audience(),
		})
	}
	return out
}
