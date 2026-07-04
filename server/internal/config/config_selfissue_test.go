package config

import (
	"testing"
	"time"
)

// TestSelfIssueValidate covers the self-issued serving-certificate validation: a
// disabled block never errors, an enabled block needs a CA and an identity, and
// the duration/IP fields must parse.
func TestSelfIssueValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     SelfIssueConfig
		wantErr bool
	}{
		{name: "disabled is always valid", cfg: SelfIssueConfig{Enabled: false, RenewBefore: "nonsense"}},
		{name: "enabled needs a CA", cfg: SelfIssueConfig{Enabled: true, DNSNames: []string{"host"}}, wantErr: true},
		{name: "enabled needs an identity", cfg: SelfIssueConfig{Enabled: true, CAID: "ca"}, wantErr: true},
		{name: "dnsnames satisfy the identity", cfg: SelfIssueConfig{Enabled: true, CAID: "ca", DNSNames: []string{"host.example"}}},
		{name: "ips satisfy the identity", cfg: SelfIssueConfig{Enabled: true, CAID: "ca", IPs: []string{"10.0.0.1"}}},
		{name: "common_name satisfies the identity", cfg: SelfIssueConfig{Enabled: true, CAID: "ca", CommonName: "server"}},
		{name: "bad renew_before rejected", cfg: SelfIssueConfig{Enabled: true, CAID: "ca", CommonName: "s", RenewBefore: "soon"}, wantErr: true},
		{name: "negative renew_before rejected", cfg: SelfIssueConfig{Enabled: true, CAID: "ca", CommonName: "s", RenewBefore: "-1h"}, wantErr: true},
		{name: "bad ip rejected", cfg: SelfIssueConfig{Enabled: true, CAID: "ca", IPs: []string{"not-an-ip"}}, wantErr: true},
		{name: "full config ok", cfg: SelfIssueConfig{Enabled: true, CAID: "ca", DNSNames: []string{"host"}, IPs: []string{"127.0.0.1"}, RenewBefore: "720h"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// TestSelfIssueResolvers checks the defaulting helpers the server wiring relies on.
func TestSelfIssueResolvers(t *testing.T) {
	// Profile defaults to "server".
	if got := (SelfIssueConfig{}).ResolvedProfile(); got != "server" {
		t.Errorf("ResolvedProfile() = %q, want server", got)
	}
	if got := (SelfIssueConfig{Profile: "server-muststaple"}).ResolvedProfile(); got != "server-muststaple" {
		t.Errorf("ResolvedProfile() = %q", got)
	}

	// CommonName falls back to the first DNS name, then to a stable default.
	if got := (SelfIssueConfig{DNSNames: []string{"a.example", "b.example"}}).ResolvedCommonName(); got != "a.example" {
		t.Errorf("ResolvedCommonName() = %q, want a.example", got)
	}
	if got := (SelfIssueConfig{}).ResolvedCommonName(); got != "secsy serving certificate" {
		t.Errorf("ResolvedCommonName() fallback = %q", got)
	}
	if got := (SelfIssueConfig{CommonName: "explicit"}).ResolvedCommonName(); got != "explicit" {
		t.Errorf("ResolvedCommonName() = %q, want explicit", got)
	}

	// KeyLabel defaults to serving-tls-<ca_id>.
	if got := (SelfIssueConfig{CAID: "root-1"}).ResolvedKeyLabel(); got != "serving-tls-root-1" {
		t.Errorf("ResolvedKeyLabel() = %q, want serving-tls-root-1", got)
	}
	if got := (SelfIssueConfig{CAID: "root-1", KeyLabel: "custom"}).ResolvedKeyLabel(); got != "custom" {
		t.Errorf("ResolvedKeyLabel() = %q, want custom", got)
	}

	// RenewBeforeDuration: empty means "use the fraction default" (0, nil).
	if d, err := (SelfIssueConfig{}).RenewBeforeDuration(); err != nil || d != 0 {
		t.Errorf("RenewBeforeDuration() empty = (%s, %v), want (0, nil)", d, err)
	}
	if d, err := (SelfIssueConfig{RenewBefore: "48h"}).RenewBeforeDuration(); err != nil || d != 48*time.Hour {
		t.Errorf("RenewBeforeDuration(48h) = (%s, %v)", d, err)
	}

	// Validity: 0 means "profile default"; otherwise seconds.
	if got := (SelfIssueConfig{}).Validity(); got != 0 {
		t.Errorf("Validity() default = %s, want 0", got)
	}
	if got := (SelfIssueConfig{ValiditySeconds: 3600}).Validity(); got != time.Hour {
		t.Errorf("Validity(3600) = %s, want 1h", got)
	}

	// ParsedIPs skips blanks and rejects malformed entries.
	ips, err := (SelfIssueConfig{IPs: []string{"127.0.0.1", "  ", "::1"}}).ParsedIPs()
	if err != nil || len(ips) != 2 {
		t.Errorf("ParsedIPs() = (%v, %v), want 2 IPs", ips, err)
	}
	if _, err := (SelfIssueConfig{IPs: []string{"bad"}}).ParsedIPs(); err == nil {
		t.Error("ParsedIPs() should reject a malformed IP")
	}
}

// TestSelfIssueLoad exercises the YAML tags end-to-end through config.Load,
// confirming the server.tls.self_issue block parses into the struct and that
// Load surfaces the block's validation (a malformed renew_before fails the load).
func TestSelfIssueLoad(t *testing.T) {
	cfg, err := loadContent(t, `
root_user:
  password: secret
server:
  tls:
    self_issue:
      enabled: true
      ca_id: "root-ca"
      profile: "server"
      dnsnames: ["localhost", "svc.internal"]
      ips: ["127.0.0.1"]
      renew_before: "240h"
      validity_seconds: 86400
`)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	si := cfg.Server.TLS.SelfIssue
	if !si.Enabled || si.CAID != "root-ca" || si.Profile != "server" {
		t.Fatalf("self_issue parsed unexpectedly: %+v", si)
	}
	if len(si.DNSNames) != 2 || si.DNSNames[1] != "svc.internal" || len(si.IPs) != 1 {
		t.Fatalf("self_issue SANs parsed unexpectedly: %+v", si)
	}
	if d, err := si.RenewBeforeDuration(); err != nil || d != 240*time.Hour {
		t.Fatalf("renew_before parsed = (%s, %v), want 240h", d, err)
	}
	if si.Validity() != 24*time.Hour {
		t.Fatalf("validity = %s, want 24h", si.Validity())
	}

	// A malformed renew_before must fail the whole load (validation is wired in).
	if _, err := loadContent(t, `
root_user:
  password: secret
server:
  tls:
    self_issue:
      enabled: true
      ca_id: "root-ca"
      common_name: "server"
      renew_before: "nope"
`); err == nil {
		t.Fatal("Load should reject a malformed renew_before")
	}
}
