//go:build sqlite

// End-to-end verification that a CEL role mapping (Task 214) decides what an
// operator may do after a real console login. The exact-value mapping is
// covered by console_login_test.go; what is asserted here is the part a unit
// test cannot: that an expression written in configuration, compiled at
// startup, and evaluated against the identity the OIDC callback assembled,
// lands the right per-tenant role in the session the console then reads.
//
// The IdP asserts group names that ENCODE the tenant — the shape an
// organization actually has — so the tenant the operator administers is
// extracted from the group name by the expression rather than enumerated in the
// config file.
package e2e

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/authn"
	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// celLoginMapper is the mapping under test: any group named
// "CN=PKI-Admins-<tenant>,OU=Groups,DC=corp,DC=example,DC=com" grants admin in
// <tenant>, for every such group the principal holds, and nothing anywhere else.
func celLoginMapper(t *testing.T) *authn.ClaimMapper {
	t.Helper()
	m, err := authn.NewClaimMapper("groups", []authn.ClaimMapping{{
		Expression: `groups.exists(g, g.matches("^CN=PKI-Admins-[a-z0-9-]+,OU=Groups,DC=corp,DC=example,DC=com$"))`,
		TenantExpression: `groups.filter(g, g.startsWith("CN=PKI-Admins-"))
		                         .map(g, regex.extract(g, "^CN=PKI-Admins-([a-z0-9-]+),").orValue(""))`,
		Roles: []rbac.Role{rbac.RoleAdmin},
	}}, authn.WithKnownTenants([]string{"acme-corp", "globex"}))
	if err != nil {
		t.Fatalf("NewClaimMapper: %v", err)
	}
	return m
}

// TestConsoleLoginCELRoleMapping drives the full Authorization-Code login and
// asserts the principal the console sees carries the tenant roles the
// expression derived — and only those.
func TestConsoleLoginCELRoleMapping(t *testing.T) {
	env := setupConsoleLoginMapper(t, "", celLoginMapper(t))
	// Two mapped tenants plus two groups that must contribute nothing: a
	// lookalike in another directory subtree, and a tenant this deployment does
	// not declare.
	env.idp.groups = []string{
		"CN=PKI-Admins-acme-corp,OU=Groups,DC=corp,DC=example,DC=com",
		"CN=PKI-Admins-globex,OU=Groups,DC=corp,DC=example,DC=com",
		"CN=PKI-Admins-evil,OU=Contractors,DC=corp,DC=example,DC=com",
		"CN=PKI-Admins-notatenant,OU=Groups,DC=corp,DC=example,DC=com",
	}

	me := celLogin(t, env)
	if me.Subject != "alice-oidc-subject" {
		t.Errorf("subject = %q, want alice-oidc-subject", me.Subject)
	}
	// The mapping is tenant-scoped throughout: deriving a tenant must never
	// leave the principal with platform-wide authority.
	if len(me.Roles) != 0 {
		t.Errorf("platform roles = %v, want none (the mapping is tenant-scoped)", me.Roles)
	}
	for tenant, want := range map[string]string{"acme-corp": "admin", "globex": "admin"} {
		got := me.TenantRoles[tenant]
		if len(got) != 1 || got[0] != want {
			t.Errorf("tenant %q roles = %v, want [%s]", tenant, got, want)
		}
	}
	if _, ok := me.TenantRoles["evil"]; ok {
		t.Error("a group outside the matched subtree granted a tenant role")
	}
	if _, ok := me.TenantRoles["notatenant"]; ok {
		t.Error("a group naming an undeclared tenant granted a tenant role")
	}
	if len(me.TenantRoles) != 2 {
		t.Errorf("tenant roles = %v, want exactly acme-corp and globex", me.TenantRoles)
	}
}

// TestConsoleLoginCELRoleMappingGrantsNothingToUnmatchedGroups asserts the
// fail-closed half: an operator whose groups do not satisfy the expression
// resolves to no role at all, so a mapping that is simply wrong about the
// directory cannot admit anyone.
func TestConsoleLoginCELRoleMappingGrantsNothingToUnmatchedGroups(t *testing.T) {
	env := setupConsoleLoginMapper(t, "", celLoginMapper(t))
	env.idp.groups = []string{"CN=Staff,OU=Groups,DC=corp,DC=example,DC=com", "pki-admins"}

	me := celLogin(t, env)
	if len(me.Roles) != 0 || len(me.TenantRoles) != 0 {
		t.Errorf("roles = %v / %v, want none for a principal no mapping matches", me.Roles, me.TenantRoles)
	}
}

// celLogin drives /auth/login -> IdP -> /auth/callback -> /api/me and returns
// the principal the console sees.
func celLogin(t *testing.T, env *consoleLoginEnv) models.UserInfo {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:           jar,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	resp, err := client.Get(env.srv.URL + "/auth/login")
	if err != nil {
		t.Fatalf("GET /auth/login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login status = %d, want 302", resp.StatusCode)
	}
	code, state := env.idp.authorization(t, resp.Header.Get("Location"))

	resp, err = client.Get(env.srv.URL + "/auth/callback?code=" +
		url.QueryEscape(code) + "&state=" + url.QueryEscape(state))
	if err != nil {
		t.Fatalf("GET /auth/callback: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "/console/") {
		t.Fatalf("callback redirect = %q, want the console", loc)
	}

	resp, err = client.Get(env.srv.URL + "/api/me")
	if err != nil {
		t.Fatalf("GET /api/me: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/me status = %d, want 200", resp.StatusCode)
	}
	var me models.UserInfo
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatalf("decode /api/me: %v", err)
	}
	return me
}
