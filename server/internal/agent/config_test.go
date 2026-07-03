package agent

import (
	"strings"
	"testing"
	"time"
)

const validConfigYAML = `
state_dir: /var/lib/secsy-agent
trust:
  bundle_file: /etc/secsy/trust.pem
acme:
  directory: https://pki.example.com/acme/directory
  eab_kid: host-1
  eab_hmac_key: c2VjcmV0LWtleQ
est:
  url: https://pki.example.com/.well-known/est
  username: device
  password: pw
renewal:
  fraction: 0.7
  jitter: 0.05
  check_interval: 90s
metrics:
  textfile: /var/lib/node_exporter/secsy-agent.prom
certificates:
  - name: web
    enroll: acme
    dns_names: [web.example.com, www.example.com]
    key_type: ecdsa-p256
    key_file: /etc/pki/web.key
    cert_file: /etc/pki/web.crt
    fullchain_file: /etc/pki/web-fullchain.crt
    owner: "0:0"
    key_mode: "0600"
    cert_mode: "0644"
    reload:
      command: systemctl reload nginx
      timeout: 20s
  - name: ldap
    enroll: est
    dns_names: [ldap.example.com]
    ip_addresses: [192.0.2.10]
    key_type: rsa-2048
    key_file: /etc/pki/ldap.key
    cert_file: /etc/pki/ldap.crt
    chain_file: /etc/pki/ldap-chain.crt
    reload:
      signal: HUP
      pid_file: /run/slapd.pid
`

func TestParseConfigValid(t *testing.T) {
	cfg, err := ParseConfig([]byte(validConfigYAML))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Renewal.CheckInterval.Std() != 90*time.Second {
		t.Errorf("check_interval = %s, want 90s", cfg.Renewal.CheckInterval.Std())
	}
	web := cfg.Certificates[0]
	if web.CommonName != "web.example.com" {
		t.Errorf("CN default = %q, want first dns name", web.CommonName)
	}
	if got := []string(web.Reload.Command); len(got) != 3 || got[0] != "sh" || got[1] != "-c" {
		t.Errorf("string reload command should become sh -c form, got %v", got)
	}
	if web.Reload.Timeout.Std() != 20*time.Second {
		t.Errorf("reload timeout = %s, want 20s", web.Reload.Timeout.Std())
	}
	ldap := cfg.Certificates[1]
	if ldap.KeyMode != defaultKeyMode || ldap.CertMode != defaultCertMode {
		t.Errorf("mode defaults not applied: key=%o cert=%o", ldap.KeyMode, ldap.CertMode)
	}
	if ldap.Reload.Timeout.Std() != defaultHookTimeout {
		t.Errorf("hook timeout default not applied: %s", ldap.Reload.Timeout.Std())
	}
}

func TestParseConfigDefaultsTrustFromEST(t *testing.T) {
	yaml := `
state_dir: /tmp/agent
est:
  url: https://pki.example.com/.well-known/est/
  username: u
  password: p
certificates:
  - name: a
    enroll: est
    dns_names: [a.example.com]
    key_file: /tmp/a.key
    cert_file: /tmp/a.crt
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	want := "https://pki.example.com/.well-known/est/cacerts"
	if cfg.Trust.BundleURL != want {
		t.Errorf("trust.bundle_url = %q, want %q (derived from est.url)", cfg.Trust.BundleURL, want)
	}
	if cfg.Renewal.Fraction != defaultFraction {
		t.Errorf("fraction default = %v, want %v", cfg.Renewal.Fraction, defaultFraction)
	}
}

func TestParseConfigRejections(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name:    "unknown key",
			mutate:  func(s string) string { return s + "\nnot_a_real_key: true\n" },
			wantErr: "not_a_real_key",
		},
		{
			name:    "duplicate cert name",
			mutate:  func(s string) string { return strings.Replace(s, "name: ldap", "name: web", 1) },
			wantErr: "used twice",
		},
		{
			name: "wildcard over acme",
			mutate: func(s string) string {
				return strings.Replace(s, "web.example.com, www.example.com", "'*.example.com'", 1)
			},
			wantErr: "wildcard",
		},
		{
			name:    "signal without pid_file",
			mutate:  func(s string) string { return strings.Replace(s, "      pid_file: /run/slapd.pid\n", "", 1) },
			wantErr: "requires pid_file",
		},
		{
			name:    "bad mode",
			mutate:  func(s string) string { return strings.Replace(s, `key_mode: "0600"`, `key_mode: "0999"`, 1) },
			wantErr: "invalid file mode",
		},
		{
			name:    "bad key type",
			mutate:  func(s string) string { return strings.Replace(s, "key_type: rsa-2048", "key_type: dsa-1024", 1) },
			wantErr: "unsupported key_type",
		},
		{
			name:    "missing trust",
			mutate:  func(s string) string { return strings.Replace(s, "  bundle_file: /etc/secsy/trust.pem\n", "", 1) },
			wantErr: "", // trust falls back to EST cacerts here, so instead drop est too
		},
		{
			name: "bad fraction",
			mutate: func(s string) string {
				return strings.Replace(s, "fraction: 0.7", "fraction: 1.5", 1)
			},
			wantErr: "fraction",
		},
		{
			name: "duplicate output path",
			mutate: func(s string) string {
				return strings.Replace(s, "cert_file: /etc/pki/ldap.crt", "cert_file: /etc/pki/web.crt", 1)
			},
			wantErr: "both write",
		},
	}
	for _, tc := range cases {
		if tc.wantErr == "" {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(tc.mutate(validConfigYAML)))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestParseConfigMissingTrustEntirely(t *testing.T) {
	yaml := `
state_dir: /tmp/agent
acme:
  directory: https://pki.example.com/acme/directory
certificates:
  - name: a
    enroll: acme
    dns_names: [a.example.com]
    key_file: /tmp/a.key
    cert_file: /tmp/a.crt
`
	_, err := ParseConfig([]byte(yaml))
	if err == nil || !strings.Contains(err.Error(), "trust") {
		t.Fatalf("expected trust-source error, got %v", err)
	}
}

func TestCommandLineListForm(t *testing.T) {
	yaml := `
state_dir: /tmp/agent
trust:
  bundle_file: /tmp/trust.pem
est:
  url: https://pki/.well-known/est
  username: u
  password: p
certificates:
  - name: a
    enroll: est
    dns_names: [a.example.com]
    key_file: /tmp/a.key
    cert_file: /tmp/a.crt
    reload:
      command: ["systemctl", "reload", "nginx"]
`
	cfg, err := ParseConfig([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	got := []string(cfg.Certificates[0].Reload.Command)
	if len(got) != 3 || got[0] != "systemctl" {
		t.Errorf("list command should exec directly, got %v", got)
	}
}
