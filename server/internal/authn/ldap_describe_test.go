package authn

import (
	"strings"
	"testing"
)

// LDAPAuthenticator.Describe feeds a startup log line (cmd/server/auth.go) and
// the doctor diagnostic, so it is read by operators and shipped to log
// aggregators. The properties that matter are that it never discloses the bind
// credential and that it states the transport honestly — an operator must be able
// to see from the log that a deployment is binding in the clear.

// describeConfig returns a minimal valid config for the given transport, using a
// service account so the search-then-bind flow is selected.
func describeConfig(rawURL string, startTLS, cleartext bool) LDAPConfig {
	return LDAPConfig{
		URLs:                   []string{rawURL},
		StartTLS:               startTLS,
		InsecureAllowCleartext: cleartext,
		BindDN:                 "cn=svc,dc=example,dc=com",
		BindPassword:           staticSecret("super-secret-bind-pw"),
		UserBaseDN:             "ou=people,dc=example,dc=com",
		UserFilter:             "(&(objectClass=person)(uid=%s))",
	}
}

func TestLDAPDescribe(t *testing.T) {
	resolve := mappingResolver(testMapper(), false)

	cases := []struct {
		name string
		cfg  LDAPConfig
		want string
	}{
		{
			name: "search-then-bind over ldaps",
			cfg:  describeConfig("ldaps://dc1.example.com:636", false, false),
			want: "ldaps://dc1.example.com:636 [search-then-bind as cn=svc,dc=example,dc=com, ldaps]",
		},
		{
			name: "search-then-bind with starttls",
			cfg:  describeConfig("ldap://dc1.example.com:389", true, false),
			want: "ldap://dc1.example.com:389 [search-then-bind as cn=svc,dc=example,dc=com, starttls]",
		},
		{
			name: "cleartext opt-in is named as insecure",
			cfg:  describeConfig("ldap://dc1.example.com:389", false, true),
			want: "ldap://dc1.example.com:389 [search-then-bind as cn=svc,dc=example,dc=com, cleartext(insecure)]",
		},
		{
			name: "failover urls are all listed",
			cfg: func() LDAPConfig {
				c := describeConfig("ldaps://dc1.example.com:636", false, false)
				c.URLs = append(c.URLs, "ldaps://dc2.example.com:636")
				return c
			}(),
			want: "ldaps://dc1.example.com:636,ldaps://dc2.example.com:636 [search-then-bind as cn=svc,dc=example,dc=com, ldaps]",
		},
		{
			name: "simple bind omits a service account",
			cfg: func() LDAPConfig {
				c := describeConfig("ldaps://dc1.example.com:636", false, false)
				c.BindDN = ""
				c.UserDNTemplate = "uid=%s,ou=people,dc=example,dc=com"
				return c
			}(),
			want: "ldaps://dc1.example.com:636 [simple-bind, ldaps]",
		},
		{
			name: "starttls takes precedence over the cleartext opt-in",
			cfg:  describeConfig("ldap://dc1.example.com:389", true, true),
			want: "ldap://dc1.example.com:389 [search-then-bind as cn=svc,dc=example,dc=com, starttls]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := NewLDAPAuthenticator(tc.cfg, resolve)
			if err != nil {
				t.Fatalf("NewLDAPAuthenticator: %v", err)
			}
			got := a.Describe()
			if got != tc.want {
				t.Errorf("Describe() = %q, want %q", got, tc.want)
			}
			// The bind credential must never appear in a log-safe description.
			if strings.Contains(got, "super-secret-bind-pw") {
				t.Fatalf("Describe() leaked the bind password: %q", got)
			}
			// Neither must the secret source's own description sneak in.
			if strings.Contains(got, "static(test)") {
				t.Errorf("Describe() exposed the secret source: %q", got)
			}
			if strings.ContainsAny(got, "\n\r") {
				t.Errorf("Describe() must be a single log line, got %q", got)
			}
		})
	}
}

// TestLDAPDescribeDistinguishesEncryptedFromCleartext asserts an operator
// reviewing the startup log can tell an encrypted deployment from a cleartext one
// — the transport label must never claim TLS for an unencrypted bind.
func TestLDAPDescribeDistinguishesEncryptedFromCleartext(t *testing.T) {
	resolve := mappingResolver(testMapper(), false)
	secure, err := NewLDAPAuthenticator(describeConfig("ldaps://dc1.example.com:636", false, false), resolve)
	if err != nil {
		t.Fatalf("NewLDAPAuthenticator: %v", err)
	}
	insecure, err := NewLDAPAuthenticator(describeConfig("ldap://dc1.example.com:389", false, true), resolve)
	if err != nil {
		t.Fatalf("NewLDAPAuthenticator: %v", err)
	}
	if d := insecure.Describe(); !strings.Contains(d, "insecure") {
		t.Errorf("a cleartext deployment must be described as insecure, got %q", d)
	}
	if d := secure.Describe(); strings.Contains(d, "insecure") || strings.Contains(d, "cleartext") {
		t.Errorf("an ldaps deployment must not be described as cleartext, got %q", d)
	}
	if secure.Describe() == insecure.Describe() {
		t.Error("encrypted and cleartext deployments must not describe identically")
	}
}
