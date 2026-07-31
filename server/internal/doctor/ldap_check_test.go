package doctor

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
)

// fakeLDAPProber is a stub doctor.LDAPProber for the auth.ldap check test.
type fakeLDAPProber struct {
	desc string
	err  error
}

func (f fakeLDAPProber) Describe() string            { return f.desc }
func (f fakeLDAPProber) Probe(context.Context) error { return f.err }

func ldapCfg(enabled bool) *config.Config {
	return &config.Config{Auth: config.AuthConfig{LDAP: config.AuthLDAPConfig{Enabled: enabled}}}
}

func TestCheckLDAPDisabledSkips(t *testing.T) {
	r := &Report{OK: true}
	checkLDAP(context.Background(), r, ldapCfg(false), Options{})
	if res := findResult(t, r, "auth.ldap"); res.Status != StatusSkip {
		t.Fatalf("disabled: status = %s, want skip", res.Status)
	}
}

func TestCheckLDAPNoFactorySkips(t *testing.T) {
	r := &Report{OK: true}
	checkLDAP(context.Background(), r, ldapCfg(true), Options{})
	if res := findResult(t, r, "auth.ldap"); res.Status != StatusSkip {
		t.Fatalf("no factory: status = %s, want skip", res.Status)
	}
}

func TestCheckLDAPReachable(t *testing.T) {
	r := &Report{OK: true}
	opts := Options{BuildLDAP: func(*config.Config) (LDAPProber, error) {
		return fakeLDAPProber{desc: "ldaps://ad:636 [search-then-bind]"}, nil
	}}
	checkLDAP(context.Background(), r, ldapCfg(true), opts)
	res := findResult(t, r, "auth.ldap")
	if res.Status != StatusPass {
		t.Fatalf("reachable: status = %s: %s", res.Status, res.Detail)
	}
	if !strings.Contains(res.Detail, "ad:636") {
		t.Errorf("detail lacks target description: %s", res.Detail)
	}
}

func TestCheckLDAPProbeFailsClosed(t *testing.T) {
	r := &Report{OK: true}
	opts := Options{BuildLDAP: func(*config.Config) (LDAPProber, error) {
		return fakeLDAPProber{desc: "ldaps://ad:636", err: errors.New("service-account bind failed")}, nil
	}}
	checkLDAP(context.Background(), r, ldapCfg(true), opts)
	res := findResult(t, r, "auth.ldap")
	if res.Status != StatusFail {
		t.Fatalf("probe error: status = %s, want fail", res.Status)
	}
	if !strings.Contains(res.Detail, "bind failed") {
		t.Errorf("detail lacks failure reason: %s", res.Detail)
	}
}

func TestCheckLDAPBuildErrorFails(t *testing.T) {
	r := &Report{OK: true}
	opts := Options{BuildLDAP: func(*config.Config) (LDAPProber, error) {
		return nil, errors.New("tls.min_version invalid")
	}}
	checkLDAP(context.Background(), r, ldapCfg(true), opts)
	if res := findResult(t, r, "auth.ldap"); res.Status != StatusFail {
		t.Fatalf("build error: status = %s, want fail", res.Status)
	}
}
