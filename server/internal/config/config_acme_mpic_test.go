package config

import (
	"strings"
	"testing"
)

// TestACMEMPICParse confirms the acme.mpic block (Task 142, SC-067) parses from
// YAML into the structure the coordinator consumes.
func TestACMEMPICParse(t *testing.T) {
	cfg := writeAndLoad(t, `
root_user:
  password: secret
acme:
  enabled: true
  ca_id: issuing-ca
  profile: server
  mpic:
    enabled: true
    perspective_timeout_seconds: 8
    quorum:
      min_perspectives: 2
      max_failures: 1
      require_all: false
    perspectives:
      - name: eu-west
        dns_resolver: "10.0.1.53:53"
        proxy_url: "socks5h://10.0.1.9:1080"
        timeout_seconds: 12
      - name: us-east
        dns_resolver: "10.0.2.53:53"
`)
	m := cfg.ACME.MPIC
	if !m.Enabled {
		t.Fatal("mpic.enabled should be true")
	}
	if m.PerspectiveTimeoutSeconds != 8 {
		t.Errorf("perspective_timeout_seconds = %d, want 8", m.PerspectiveTimeoutSeconds)
	}
	if m.Quorum.MinPerspectives != 2 || m.Quorum.MaxFailures != 1 || m.Quorum.RequireAll {
		t.Errorf("quorum = %+v", m.Quorum)
	}
	if len(m.Perspectives) != 2 {
		t.Fatalf("parsed %d perspectives, want 2", len(m.Perspectives))
	}
	if m.Perspectives[0].Name != "eu-west" || m.Perspectives[0].DNSResolver != "10.0.1.53:53" ||
		m.Perspectives[0].ProxyURL != "socks5h://10.0.1.9:1080" || m.Perspectives[0].TimeoutSeconds != 12 {
		t.Errorf("perspectives[0] = %+v", m.Perspectives[0])
	}
	if m.Perspectives[1].Name != "us-east" || m.Perspectives[1].DNSResolver != "10.0.2.53:53" {
		t.Errorf("perspectives[1] = %+v", m.Perspectives[1])
	}
}

// TestACMEMPICValidation exercises the validateACMEMPIC fail-fast checks.
func TestACMEMPICValidation(t *testing.T) {
	base := `
root_user:
  password: secret
acme:
  enabled: true
  ca_id: issuing-ca
  profile: server
  mpic:
`
	cases := []struct {
		name    string
		mpic    string
		wantErr string // empty = expect success
	}{
		{
			name: "valid two-perspective block",
			mpic: `
    enabled: true
    perspectives:
      - name: eu-west
        dns_resolver: "10.0.1.53:53"
      - name: us-east
        proxy_url: "socks5://10.0.2.9:1080"
`,
		},
		{
			name: "disabled block is inert",
			mpic: `
    enabled: false
    perspectives:
      - name: only-one
`,
		},
		{
			name: "too few perspectives for the quorum floor",
			mpic: `
    enabled: true
    perspectives:
      - name: solo
        dns_resolver: "10.0.1.53:53"
`,
			wantErr: "at least 2 remote perspective",
		},
		{
			name: "duplicate perspective name",
			mpic: `
    enabled: true
    perspectives:
      - name: dup
        dns_resolver: "10.0.1.53:53"
      - name: dup
        dns_resolver: "10.0.2.53:53"
`,
			wantErr: "duplicate perspective name",
		},
		{
			name: "reserved primary name",
			mpic: `
    enabled: true
    perspectives:
      - name: primary
        dns_resolver: "10.0.1.53:53"
      - name: eu
        dns_resolver: "10.0.2.53:53"
`,
			wantErr: "duplicate perspective name",
		},
		{
			name: "perspective with no distinguishing view",
			mpic: `
    enabled: true
    perspectives:
      - name: a
      - name: b
        dns_resolver: "10.0.2.53:53"
`,
			wantErr: "at least one of dns_resolver or proxy_url",
		},
		{
			name: "unsupported proxy scheme",
			mpic: `
    enabled: true
    perspectives:
      - name: a
        proxy_url: "http://proxy:8080"
      - name: b
        dns_resolver: "10.0.2.53:53"
`,
			wantErr: "proxy_url scheme",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadContent(t, base+tc.mpic)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q missing %q", err.Error(), tc.wantErr)
			}
		})
	}
}
