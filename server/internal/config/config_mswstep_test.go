package config

import (
	"strings"
	"testing"
)

// TestMSWSTEPConfigParse proves the mswstep block parses into the expected shape,
// including per-template enrollment-permission pointers and the CES endpoint.
func TestMSWSTEPConfigParse(t *testing.T) {
	cfg := writeAndLoad(t, `
root_user:
  password: secret
mswstep:
  enabled: true
  policy_path: /adcs/policy
  enroll_path: /adcs/enroll
  ca_label: issuing-ca
  default_profile: client
  policy_friendly_name: "Corp Enrollment Policy"
  next_update_hours: 4
  template_oid_arc: "1.3.6.1.4.1.311.21.8"
  ces_endpoint: "https://pki.corp.example/adcs/enroll"
  allow_client_cert_issued_by_ca: true
  templates:
    - profile: server
      name: CorpWebServer
      oid: "1.3.6.1.4.1.311.21.8.1.2.3"
      auto_enroll: false
      minimal_key_length: 3072
    - profile: client
      name: CorpUser
`)
	m := cfg.MSWSTEP
	if !m.Enabled {
		t.Fatal("mswstep should be enabled")
	}
	if m.PolicyPath != "/adcs/policy" || m.EnrollPath != "/adcs/enroll" {
		t.Errorf("paths = %q / %q", m.PolicyPath, m.EnrollPath)
	}
	if m.CALabel != "issuing-ca" {
		t.Errorf("ca_label = %q", m.CALabel)
	}
	if m.NextUpdateHours != 4 {
		t.Errorf("next_update_hours = %d", m.NextUpdateHours)
	}
	if m.CESEndpoint != "https://pki.corp.example/adcs/enroll" {
		t.Errorf("ces_endpoint = %q", m.CESEndpoint)
	}
	if !m.AllowClientCertIssuedByCA {
		t.Error("allow_client_cert_issued_by_ca should be true")
	}
	if len(m.Templates) != 2 {
		t.Fatalf("templates = %d, want 2", len(m.Templates))
	}
	srv := m.Templates[0]
	if srv.Profile != "server" || srv.Name != "CorpWebServer" || srv.OID != "1.3.6.1.4.1.311.21.8.1.2.3" {
		t.Errorf("server template = %+v", srv)
	}
	if srv.MinimalKeyLength != 3072 {
		t.Errorf("server template minimal_key_length = %d, want 3072", srv.MinimalKeyLength)
	}
	if srv.AutoEnroll == nil || *srv.AutoEnroll {
		t.Errorf("server template auto_enroll = %v, want explicit false", srv.AutoEnroll)
	}
	// The client template leaves auto_enroll unset (nil -> defaults to true later).
	if m.Templates[1].AutoEnroll != nil {
		t.Errorf("client template auto_enroll = %v, want nil (unset)", m.Templates[1].AutoEnroll)
	}
}

// TestMSWSTEPConfigValidation covers the fail-closed validation paths.
func TestMSWSTEPConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "missing_ca",
			yaml: `
root_user:
  password: secret
mswstep:
  enabled: true
`,
			wantErr: "neither mswstep.ca_id nor mswstep.ca_label",
		},
		{
			name: "template_missing_profile",
			yaml: `
root_user:
  password: secret
mswstep:
  enabled: true
  ca_label: issuing-ca
  templates:
    - name: NoProfile
`,
			wantErr: "profile must not be empty",
		},
		{
			name: "template_bad_oid",
			yaml: `
root_user:
  password: secret
mswstep:
  enabled: true
  ca_label: issuing-ca
  templates:
    - profile: server
      oid: "not-an-oid"
`,
			wantErr: "oid",
		},
		{
			name: "bad_template_oid_arc",
			yaml: `
root_user:
  password: secret
mswstep:
  enabled: true
  ca_label: issuing-ca
  template_oid_arc: "abc.def"
`,
			wantErr: "template_oid_arc",
		},
		{
			name: "valid",
			yaml: `
root_user:
  password: secret
mswstep:
  enabled: true
  ca_label: issuing-ca
  templates:
    - profile: server
      oid: "1.3.6.1.4.1.311.21.8.1"
`,
			wantErr: "",
		},
		{
			name: "disabled_ignores_missing_ca",
			yaml: `
root_user:
  password: secret
mswstep:
  enabled: false
`,
			wantErr: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadContent(t, tc.yaml)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
