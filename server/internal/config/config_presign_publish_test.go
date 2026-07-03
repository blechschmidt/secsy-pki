package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writePresignPublishConfig writes a minimal valid config with the given extra
// YAML appended and returns its path.
func writePresignPublishConfig(t *testing.T, extra string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	base := `
root_user:
  username: admin
  password: secret
key_provider:
  type: software
  software:
    keystore_dir: /tmp/ks
`
	if err := os.WriteFile(path, []byte(base+extra), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPresignDefaults(t *testing.T) {
	cfg, err := Load(writePresignPublishConfig(t, `
server:
  ocsp:
    presign:
      enabled: true
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := cfg.Server.OCSP.Presign
	if !p.Enabled {
		t.Fatal("presign not enabled")
	}
	if got := p.Validity(); got != 24*time.Hour {
		t.Errorf("Validity() = %s, want 24h", got)
	}
	if got := p.Refresh(); got != 6*time.Hour {
		t.Errorf("Refresh() = %s, want 6h (validity/4)", got)
	}
	if !p.TrackRecentlyQueried() {
		t.Error("recently_queried should default to enabled")
	}
	if got := p.ExpiredGrace(); got != 24*time.Hour {
		t.Errorf("ExpiredGrace() = %s, want 24h", got)
	}
}

func TestLoadPresignExplicit(t *testing.T) {
	cfg, err := Load(writePresignPublishConfig(t, `
server:
  ocsp:
    presign:
      enabled: true
      validity_minutes: 120
      refresh_minutes: 30
      recently_queried: false
      expired_grace_minutes: -1
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p := cfg.Server.OCSP.Presign
	if got := p.Validity(); got != 2*time.Hour {
		t.Errorf("Validity() = %s, want 2h", got)
	}
	if got := p.Refresh(); got != 30*time.Minute {
		t.Errorf("Refresh() = %s, want 30m", got)
	}
	if p.TrackRecentlyQueried() {
		t.Error("recently_queried: false not honored")
	}
	if got := p.ExpiredGrace(); got >= 0 {
		t.Errorf("ExpiredGrace() = %s, want negative (disabled)", got)
	}
}

func TestLoadPresignValidation(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			name: "refresh too close to validity",
			yaml: `
server:
  ocsp:
    presign: { enabled: true, validity_minutes: 60, refresh_minutes: 45 }
`,
			wantErr: "refresh_minutes",
		},
		{
			name: "presign requires the response cache",
			yaml: `
server:
  ocsp_cache_ttl_seconds: -1
  ocsp:
    presign: { enabled: true }
`,
			wantErr: "ocsp_cache_ttl_seconds",
		},
		{
			name: "publish needs a backend",
			yaml: `
publish:
  enabled: true
  include_ocsp: false
`,
			wantErr: "publish.dir.path or publish.s3.bucket",
		},
		{
			name: "publish ocsp needs presign",
			yaml: `
publish:
  enabled: true
  dir: { path: /var/lib/secsy/publish }
`,
			wantErr: "requires server.ocsp.presign.enabled",
		},
		{
			name: "s3 endpoint must be a URL",
			yaml: `
server:
  ocsp:
    presign: { enabled: true }
publish:
  enabled: true
  s3: { bucket: pki, endpoint: "minio:9000" }
`,
			wantErr: "publish.s3.endpoint",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writePresignPublishConfig(t, tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Load error = %v, want mention of %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadPublishValid(t *testing.T) {
	cfg, err := Load(writePresignPublishConfig(t, `
server:
  ocsp:
    presign:
      enabled: true
      refresh_minutes: 15
      validity_minutes: 60
publish:
  enabled: true
  cas: [issuing-ca]
  s3:
    endpoint: http://minio.internal:9000
    bucket: pki-artifacts
    prefix: rev
    access_key_id: ak
    secret_access_key: sk
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	pub := cfg.Publish
	if pub.Backend() != "s3" {
		t.Errorf("Backend() = %s, want s3", pub.Backend())
	}
	if !pub.IncludeOCSPEnabled() {
		t.Error("include_ocsp should default to enabled")
	}
	// Interval defaults to the presign refresh cadence.
	if got := pub.Interval(cfg.Server.OCSP.Presign); got != 15*time.Minute {
		t.Errorf("Interval() = %s, want 15m", got)
	}
	if len(pub.CAs) != 1 || pub.CAs[0] != "issuing-ca" {
		t.Errorf("CAs = %v", pub.CAs)
	}

	// The dir backend is selected when no bucket is set, with its own interval
	// fallback.
	dirCfg := PublishConfig{Enabled: true, Dir: PublishDirConfig{Path: "/tmp/x"}}
	if dirCfg.Backend() != "dir" {
		t.Errorf("Backend() = %s, want dir", dirCfg.Backend())
	}
	if got := dirCfg.Interval(OCSPPresignConfig{}); got != time.Hour {
		t.Errorf("Interval() without presign = %s, want 1h", got)
	}
}
