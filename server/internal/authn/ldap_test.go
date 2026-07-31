package authn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// staticSecret is a test SecretSource returning a fixed value (the bind password).
type staticSecret string

func (s staticSecret) Resolve(context.Context) (string, error) { return string(s), nil }
func (s staticSecret) Describe() string                        { return "static(test)" }

// testDir builds the fixture directory: a service account, three bindable users
// (alice→pki-admins, bob→pki-issuers, carol→interns[unmapped]), and two group
// entries for the group-search flow.
func testDir() *mockDirectory {
	return &mockDirectory{entries: []*mockEntry{
		{dn: "cn=svc,dc=example,dc=com", password: "svcpass"},
		{dn: "uid=alice,ou=people,dc=example,dc=com", password: "alicepass", attrs: map[string][]string{
			"objectClass": {"person"}, "uid": {"alice"}, "sAMAccountName": {"alice"},
			"mail": {"alice@example.com"}, "displayName": {"Alice Anders"},
			"memberOf": {"cn=pki-admins,ou=groups,dc=example,dc=com"},
		}},
		{dn: "uid=bob,ou=people,dc=example,dc=com", password: "bobpass", attrs: map[string][]string{
			"objectClass": {"person"}, "uid": {"bob"}, "sAMAccountName": {"bob"},
			"mail": {"bob@example.com"}, "displayName": {"Bob Barker"},
			"memberOf": {"cn=pki-issuers,ou=groups,dc=example,dc=com"},
		}},
		{dn: "uid=carol,ou=people,dc=example,dc=com", password: "carolpass", attrs: map[string][]string{
			"objectClass": {"person"}, "uid": {"carol"}, "sAMAccountName": {"carol"},
			"mail":     {"carol@example.com"},
			"memberOf": {"cn=interns,ou=groups,dc=example,dc=com"},
		}},
		{dn: "cn=pki-admins,ou=groups,dc=example,dc=com", attrs: map[string][]string{
			"objectClass": {"group"}, "cn": {"pki-admins"},
			"member": {"uid=alice,ou=people,dc=example,dc=com"},
		}},
		{dn: "cn=pki-issuers,ou=groups,dc=example,dc=com", attrs: map[string][]string{
			"objectClass": {"group"}, "cn": {"pki-issuers"},
			"member": {"uid=bob,ou=people,dc=example,dc=com"},
		}},
	}}
}

// testMapper maps the two mapped groups to roles, reusing the OIDC ClaimMapper
// (mapping.go): pki-admins → platform admin, pki-issuers → issuer in tenant "acme".
func testMapper() *ClaimMapper {
	return NewClaimMapper("groups", []ClaimMapping{
		{Value: "cn=pki-admins,ou=groups,dc=example,dc=com", Roles: []rbac.Role{rbac.RoleAdmin}},
		{Value: "cn=pki-issuers,ou=groups,dc=example,dc=com", Tenant: "acme", Roles: []rbac.Role{rbac.RoleIssuer}},
	})
}

// mappingResolver is the test principal resolver. It runs the directory groups
// through the ClaimMapper (exactly as main.go does), enforcing the zero-role
// policy, so the tests exercise the real group→role mapping path.
func mappingResolver(mapper *ClaimMapper, allowZeroRole bool) LDAPPrincipalResolver {
	return func(id DirectoryIdentity) (*models.UserInfo, error) {
		claims := map[string]interface{}{mapper.GroupsClaim(): id.Groups}
		platform, tenant := mapper.Resolve(claims)
		info := &models.UserInfo{Subject: id.Subject, Email: id.Email, EmailVerified: id.Email != "", Name: id.Name}
		for _, r := range platform {
			info.Roles = append(info.Roles, string(r))
		}
		if len(tenant) > 0 {
			info.TenantRoles = map[string][]string{}
			for tid, roles := range tenant {
				for _, r := range roles {
					info.TenantRoles[tid] = append(info.TenantRoles[tid], string(r))
				}
			}
		}
		if !allowZeroRole && len(info.Roles) == 0 && len(info.TenantRoles) == 0 {
			return nil, errors.New("no RBAC role is assigned to this account")
		}
		return info, nil
	}
}

// searchBindConfig returns a search-then-bind config against the given server URL,
// trusting the server's TLS certificate. Group membership is read from memberOf.
func searchBindConfig(t *testing.T, m *mockLDAP, url string) LDAPConfig {
	return LDAPConfig{
		URLs:           []string{url},
		BindDN:         "cn=svc,dc=example,dc=com",
		BindPassword:   staticSecret("svcpass"),
		UserBaseDN:     "ou=people,dc=example,dc=com",
		UserFilter:     "(&(objectClass=person)(uid=%s))",
		GroupAttribute: "memberOf",
		EmailAttribute: "mail",
		NameAttribute:  "displayName",
		TLSCACertPEM:   caPEMOf(t, m.tlsConfig),
		TLSServerName:  "127.0.0.1",
	}
}

func mustAuth(t *testing.T, cfg LDAPConfig, mapper *ClaimMapper, allowZero bool) *LDAPAuthenticator {
	t.Helper()
	a, err := NewLDAPAuthenticator(cfg, mappingResolver(mapper, allowZero))
	if err != nil {
		t.Fatalf("NewLDAPAuthenticator: %v", err)
	}
	return a
}

// TestLDAPSearchBindSuccessRole covers a successful search-then-bind over LDAPS
// that resolves a directory group to an RBAC role.
func TestLDAPSearchBindSuccessRole(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeLDAPS)
	a := mustAuth(t, searchBindConfig(t, m, url), testMapper(), false)

	info, err := a.Authenticate(context.Background(), "alice", "alicepass")
	if err != nil {
		t.Fatalf("Authenticate(alice): %v", err)
	}
	if info.Subject != "uid=alice,ou=people,dc=example,dc=com" {
		t.Errorf("subject = %q, want the user DN", info.Subject)
	}
	if info.Email != "alice@example.com" || info.Name != "Alice Anders" {
		t.Errorf("email/name = %q/%q, want alice@example.com/Alice Anders", info.Email, info.Name)
	}
	if len(info.Roles) != 1 || info.Roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin]", info.Roles)
	}
	if atomic.LoadInt32(&m.tlsBinds) != atomic.LoadInt32(&m.binds) || m.binds == 0 {
		t.Errorf("all binds must be over TLS: binds=%d tlsBinds=%d", m.binds, m.tlsBinds)
	}
}

// TestLDAPGroupToRoleMapping verifies distinct groups map to distinct roles/tenants.
func TestLDAPGroupToRoleMapping(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeLDAPS)
	a := mustAuth(t, searchBindConfig(t, m, url), testMapper(), false)

	// alice → platform admin
	alice, err := a.Authenticate(context.Background(), "alice", "alicepass")
	if err != nil {
		t.Fatalf("alice: %v", err)
	}
	if len(alice.Roles) != 1 || alice.Roles[0] != "admin" || len(alice.TenantRoles) != 0 {
		t.Errorf("alice roles=%v tenantRoles=%v, want platform [admin]", alice.Roles, alice.TenantRoles)
	}

	// bob → issuer scoped to tenant acme (no platform role)
	bob, err := a.Authenticate(context.Background(), "bob", "bobpass")
	if err != nil {
		t.Fatalf("bob: %v", err)
	}
	if len(bob.Roles) != 0 {
		t.Errorf("bob platform roles = %v, want none", bob.Roles)
	}
	if got := bob.TenantRoles["acme"]; len(got) != 1 || got[0] != "issuer" {
		t.Errorf("bob tenant roles = %v, want issuer in acme", bob.TenantRoles)
	}
}

// TestLDAPGroupSearchFlow covers the alternate group-resolution path: searching a
// group subtree with a (member=%s) filter instead of reading memberOf.
func TestLDAPGroupSearchFlow(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeLDAPS)
	cfg := searchBindConfig(t, m, url)
	cfg.GroupAttribute = "" // use the entry DN of each matched group
	cfg.GroupBaseDN = "ou=groups,dc=example,dc=com"
	cfg.GroupFilter = "(&(objectClass=group)(member=%s))"
	a := mustAuth(t, cfg, testMapper(), false)

	info, err := a.Authenticate(context.Background(), "alice", "alicepass")
	if err != nil {
		t.Fatalf("Authenticate(alice): %v", err)
	}
	if len(info.Roles) != 1 || info.Roles[0] != "admin" {
		t.Errorf("group-search roles = %v, want [admin]", info.Roles)
	}
}

// TestLDAPFailedBind covers a wrong password: no principal, ErrLDAPInvalidCredentials.
func TestLDAPFailedBind(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeLDAPS)
	a := mustAuth(t, searchBindConfig(t, m, url), testMapper(), false)

	info, err := a.Authenticate(context.Background(), "alice", "wrongpass")
	if info != nil {
		t.Fatalf("expected nil principal on bad password, got %+v", info)
	}
	if !errors.Is(err, ErrLDAPInvalidCredentials) {
		t.Fatalf("err = %v, want ErrLDAPInvalidCredentials", err)
	}
}

// TestLDAPUnknownUser: a username matching no entry fails closed with the same
// generic error as a wrong password (no user enumeration).
func TestLDAPUnknownUser(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeLDAPS)
	a := mustAuth(t, searchBindConfig(t, m, url), testMapper(), false)

	if _, err := a.Authenticate(context.Background(), "nobody", "whatever"); !errors.Is(err, ErrLDAPInvalidCredentials) {
		t.Fatalf("unknown user err = %v, want ErrLDAPInvalidCredentials", err)
	}
}

// TestLDAPEmptyPasswordRejected guards the classic unauthenticated-bind pitfall:
// an empty password must be rejected before any bind is attempted.
func TestLDAPEmptyPasswordRejected(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeLDAPS)
	a := mustAuth(t, searchBindConfig(t, m, url), testMapper(), false)

	if _, err := a.Authenticate(context.Background(), "alice", ""); !errors.Is(err, ErrLDAPInvalidCredentials) {
		t.Fatalf("empty password err = %v, want ErrLDAPInvalidCredentials", err)
	}
	if n := atomic.LoadInt32(&m.binds); n != 0 {
		t.Fatalf("a bind was attempted for an empty password (binds=%d); must fail before binding", n)
	}
}

// TestLDAPUnmappedGroupDenied: a user whose only group maps to no role is denied
// at login (allow_zero_role is false).
func TestLDAPUnmappedGroupDenied(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeLDAPS)
	a := mustAuth(t, searchBindConfig(t, m, url), testMapper(), false)

	info, err := a.Authenticate(context.Background(), "carol", "carolpass")
	if info != nil {
		t.Fatalf("expected denial for unmapped group, got principal %+v", info)
	}
	if err == nil || !strings.Contains(err.Error(), "no RBAC role") {
		t.Fatalf("err = %v, want a no-role denial", err)
	}
}

// TestLDAPUnmappedGroupAllowedWhenZeroRoleOK: the same user is admitted (roleless)
// when allow_zero_role is enabled.
func TestLDAPUnmappedGroupAllowedWhenZeroRoleOK(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeLDAPS)
	a := mustAuth(t, searchBindConfig(t, m, url), testMapper(), true)

	info, err := a.Authenticate(context.Background(), "carol", "carolpass")
	if err != nil {
		t.Fatalf("Authenticate(carol) with allow_zero_role: %v", err)
	}
	if len(info.Roles) != 0 || len(info.TenantRoles) != 0 {
		t.Errorf("carol should hold no role, got roles=%v tenant=%v", info.Roles, info.TenantRoles)
	}
}

// TestLDAPStartTLSSuccess: ldap:// with StartTLS upgrades to TLS and binds.
func TestLDAPStartTLSSuccess(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeStartTLS)
	cfg := searchBindConfig(t, m, url)
	cfg.StartTLS = true
	a := mustAuth(t, cfg, testMapper(), false)

	info, err := a.Authenticate(context.Background(), "alice", "alicepass")
	if err != nil {
		t.Fatalf("StartTLS Authenticate: %v", err)
	}
	if len(info.Roles) != 1 || info.Roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin]", info.Roles)
	}
	// Every bind observed by the server must have been over the TLS-upgraded conn.
	if m.binds == 0 || atomic.LoadInt32(&m.tlsBinds) != atomic.LoadInt32(&m.binds) {
		t.Errorf("binds must occur only after StartTLS: binds=%d tlsBinds=%d", m.binds, m.tlsBinds)
	}
}

// TestLDAPStartTLSEnforced: when StartTLS is required but the server refuses it,
// the login fails closed and NO bind is ever sent in cleartext.
func TestLDAPStartTLSEnforced(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeStartTLSRefuse)
	cfg := searchBindConfig(t, m, url)
	cfg.StartTLS = true
	// The refusing server serves no TLS, so no CA is needed; ensure verification
	// isn't what fails.
	cfg.TLSCACertPEM = nil
	cfg.TLSInsecureSkipVerify = true
	a := mustAuth(t, cfg, testMapper(), false)

	info, err := a.Authenticate(context.Background(), "alice", "alicepass")
	if info != nil {
		t.Fatalf("expected failure when StartTLS is refused, got principal %+v", info)
	}
	if !errors.Is(err, ErrLDAPUnavailable) {
		t.Fatalf("err = %v, want ErrLDAPUnavailable (fail closed)", err)
	}
	if n := atomic.LoadInt32(&m.binds); n != 0 {
		t.Fatalf("a bind was sent despite StartTLS failure (binds=%d) — cleartext leak", n)
	}
}

// TestLDAPCleartextRefusedByConfig: an ldap:// URL with neither StartTLS nor the
// explicit cleartext opt-in is rejected at construction — the authenticator never
// ships credentials in the clear.
func TestLDAPCleartextRefusedByConfig(t *testing.T) {
	cfg := LDAPConfig{
		URLs:         []string{"ldap://127.0.0.1:389"},
		BindDN:       "cn=svc,dc=example,dc=com",
		BindPassword: staticSecret("svcpass"),
		UserBaseDN:   "ou=people,dc=example,dc=com",
		UserFilter:   "(uid=%s)",
	}
	if _, err := NewLDAPAuthenticator(cfg, mappingResolver(testMapper(), false)); err == nil {
		t.Fatal("expected construction to fail for a cleartext ldap:// URL without start_tls")
	}
}

// TestLDAPInsecureCleartextOptIn: a cleartext ldap:// bind works only when
// explicitly opted into with insecure_allow_cleartext (the complement of
// TestLDAPCleartextRefusedByConfig).
func TestLDAPInsecureCleartextOptIn(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modePlain)
	cfg := searchBindConfig(t, m, url)
	cfg.TLSCACertPEM = nil // no TLS on this server
	cfg.TLSServerName = ""
	cfg.InsecureAllowCleartext = true
	a := mustAuth(t, cfg, testMapper(), false)

	info, err := a.Authenticate(context.Background(), "alice", "alicepass")
	if err != nil {
		t.Fatalf("cleartext opt-in Authenticate: %v", err)
	}
	if len(info.Roles) != 1 || info.Roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin]", info.Roles)
	}
}

// TestLDAPSimpleBind covers the simple-bind flow (no service account): the username
// is templated into a bind DN and memberOf is read via a self-search.
func TestLDAPSimpleBind(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeLDAPS)
	cfg := LDAPConfig{
		URLs:           []string{url},
		UserDNTemplate: "uid=%s,ou=people,dc=example,dc=com",
		UserBaseDN:     "ou=people,dc=example,dc=com",
		UserFilter:     "(uid=%s)",
		GroupAttribute: "memberOf",
		EmailAttribute: "mail",
		NameAttribute:  "displayName",
		TLSCACertPEM:   caPEMOf(t, m.tlsConfig),
		TLSServerName:  "127.0.0.1",
	}
	a := mustAuth(t, cfg, testMapper(), false)

	info, err := a.Authenticate(context.Background(), "alice", "alicepass")
	if err != nil {
		t.Fatalf("simple-bind Authenticate: %v", err)
	}
	if len(info.Roles) != 1 || info.Roles[0] != "admin" {
		t.Errorf("roles = %v, want [admin]", info.Roles)
	}
	if info.Subject != "uid=alice,ou=people,dc=example,dc=com" {
		t.Errorf("subject = %q, want the bind DN", info.Subject)
	}
}

// TestLDAPTLSVerificationFailsClosed: an untrusted server certificate is rejected
// (verification is on by default), and no bind is sent.
func TestLDAPTLSVerificationFailsClosed(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeLDAPS)
	cfg := searchBindConfig(t, m, url)
	cfg.TLSCACertPEM = nil // do NOT trust the server's self-signed cert
	a := mustAuth(t, cfg, testMapper(), false)

	info, err := a.Authenticate(context.Background(), "alice", "alicepass")
	if info != nil || err == nil {
		t.Fatalf("expected TLS verification failure, got principal=%+v err=%v", info, err)
	}
	if !errors.Is(err, ErrLDAPUnavailable) {
		t.Fatalf("err = %v, want ErrLDAPUnavailable", err)
	}
	if n := atomic.LoadInt32(&m.binds); n != 0 {
		t.Fatalf("a bind was sent to an untrusted server (binds=%d)", n)
	}
}

// TestLDAPLoginHandler covers the interactive session-establishing login handler
// (/auth/login/ldap): a directory login sets a session cookie and returns a CSRF
// token; a bad password is 401; an unmapped-group user is 403.
func TestLDAPLoginHandler(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeLDAPS)
	a := mustAuth(t, searchBindConfig(t, m, url), testMapper(), false)
	sessions := NewSessionStore(time.Hour, time.Minute)
	mgr := NewManager(ManagerOptions{Sessions: sessions, Secure: false})
	mgr.SetLDAPAuthenticator(a)
	if !mgr.LDAPEnabled() {
		t.Fatal("LDAPEnabled() = false after SetLDAPAuthenticator")
	}

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/auth/login/ldap", strings.NewReader(body))
		w := httptest.NewRecorder()
		mgr.LoginLDAP(w, req)
		return w
	}

	// Success: session cookie + CSRF token.
	w := post(`{"username":"alice","password":"alicepass"}`)
	if w.Code != 200 {
		t.Fatalf("login: status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		CSRFToken string           `json:"csrf_token"`
		User      *models.UserInfo `json:"user"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.CSRFToken == "" || resp.User == nil || len(resp.User.Roles) != 1 || resp.User.Roles[0] != "admin" {
		t.Fatalf("login response = %s", w.Body.String())
	}
	if got := w.Result().Cookies(); !hasCookie(got, DefaultSessionCookie) {
		t.Fatalf("no session cookie set: %v", got)
	}

	// Wrong password → 401.
	if w := post(`{"username":"alice","password":"bad"}`); w.Code != 401 {
		t.Fatalf("bad password: status = %d, want 401", w.Code)
	}

	// Unmapped group → 403 (no role assigned).
	if w := post(`{"username":"carol","password":"carolpass"}`); w.Code != 403 {
		t.Fatalf("unmapped group: status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
}

func hasCookie(cookies []*http.Cookie, name string) bool {
	for _, c := range cookies {
		if c.Name == name && c.Value != "" {
			return true
		}
	}
	return false
}

// TestLDAPProbe covers the doctor connectivity/service-bind probe.
func TestLDAPProbe(t *testing.T) {
	m, url := startMockLDAP(t, testDir(), modeLDAPS)
	a := mustAuth(t, searchBindConfig(t, m, url), testMapper(), false)
	if err := a.Probe(context.Background()); err != nil {
		t.Fatalf("Probe: %v", err)
	}

	// A wrong service-account password fails the probe.
	cfg := searchBindConfig(t, m, url)
	cfg.BindPassword = staticSecret("nope")
	bad := mustAuth(t, cfg, testMapper(), false)
	if err := bad.Probe(context.Background()); err == nil {
		t.Fatal("Probe should fail with a wrong service-account password")
	}
}
