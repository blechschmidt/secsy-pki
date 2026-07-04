package config

import (
	"strings"
	"testing"
	"time"
)

// TestCTInclusionMonitorDefaults proves the inclusion-monitor block is optional
// and resolves the documented defaults (24h MMD, 60m interval, 500 certs/scan,
// 15s per-request timeout).
func TestCTInclusionMonitorDefaults(t *testing.T) {
	cfg := writeAndLoad(t, `
root_user:
  password: secret
`)
	if cfg.CertificateTransparency.InclusionMonitor.Enabled {
		t.Fatal("inclusion monitor must be disabled by default")
	}
	im := cfg.CertificateTransparency.InclusionMonitor
	if im.Interval() != 60*time.Minute || im.MaxCerts() != 500 || im.Timeout() != 15*time.Second {
		t.Fatalf("unexpected inclusion-monitor defaults: interval=%s max=%d timeout=%s",
			im.Interval(), im.MaxCerts(), im.Timeout())
	}

	cfg = writeAndLoad(t, `
root_user:
  password: secret
certificate_transparency:
  logs:
    - name: argon2026
      url: https://ct.example/argon
      mmd_hours: 12
  inclusion_monitor:
    enabled: true
    interval_minutes: 30
    max_certs_per_run: 100
    timeout_seconds: 5
`)
	im = cfg.CertificateTransparency.InclusionMonitor
	if !im.Enabled || im.Interval() != 30*time.Minute || im.MaxCerts() != 100 || im.Timeout() != 5*time.Second {
		t.Fatalf("unexpected inclusion-monitor config: %+v", im)
	}
	if got := cfg.CertificateTransparency.Logs[0].MMD(); got != 12*time.Hour {
		t.Fatalf("log MMD = %s, want 12h", got)
	}
}

// TestCTInclusionMonitorDefaultMMD proves an unset mmd_hours defaults to 24h.
func TestCTInclusionMonitorDefaultMMD(t *testing.T) {
	cfg := writeAndLoad(t, `
root_user:
  password: secret
certificate_transparency:
  logs:
    - name: nessie
      url: https://ct.example/nessie
`)
	if got := cfg.CertificateTransparency.Logs[0].MMD(); got != 24*time.Hour {
		t.Fatalf("default log MMD = %s, want 24h", got)
	}
}

// TestValidateCTRejectsInvalid proves misconfiguration fails loudly at load time.
func TestValidateCTRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "monitor enabled without logs",
			yaml: `
root_user: {password: secret}
certificate_transparency:
  inclusion_monitor:
    enabled: true
`,
			want: "no certificate_transparency.logs are configured",
		},
		{
			name: "log missing url",
			yaml: `
root_user: {password: secret}
certificate_transparency:
  logs:
    - name: nourl
`,
			want: "url is required",
		},
		{
			name: "negative mmd",
			yaml: `
root_user: {password: secret}
certificate_transparency:
  logs:
    - name: bad
      url: https://ct.example/bad
      mmd_hours: -5
`,
			want: "mmd_hours must not be negative",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadContent(t, tc.yaml)
			if err == nil {
				t.Fatalf("expected an error for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
