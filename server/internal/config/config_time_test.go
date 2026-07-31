package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTimeConfig writes a minimal config with the given time block and loads it.
func loadWithTime(t *testing.T, timeBlock string) (*Config, error) {
	t.Helper()
	raw := `
root_user:
  password: "x"
key_provider:
  type: "software"
  software:
    keystore_dir: "ks"
` + timeBlock
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return Load(p)
}

func TestTimeSourceDefaultsToSystem(t *testing.T) {
	cfg, err := loadWithTime(t, "")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Time.Source.Enabled() {
		t.Fatal("an unset time block must not enable an external source (zero-config default)")
	}
	if cfg.Time.Source.ResolvedType() != "system" {
		t.Fatalf("ResolvedType = %q, want system", cfg.Time.Source.ResolvedType())
	}
	// The getters return their documented defaults.
	if d := cfg.Time.Source.MaxDriftDuration(); d != 10*time.Second {
		t.Fatalf("default MaxDrift = %v, want 10s", d)
	}
	if d := cfg.Time.Source.RefreshDuration(); d != 60*time.Second {
		t.Fatalf("default Refresh = %v, want 60s", d)
	}
	if cfg.Time.Source.FailOpenOnUnreachable() {
		t.Fatal("default policy must be fail-closed")
	}
}

func TestTimeSourceNTSValid(t *testing.T) {
	cfg, err := loadWithTime(t, `
time:
  source:
    type: nts
    max_drift: 2s
    refresh_interval: 30s
    timeout: 3s
    min_sources: 1
    on_source_error: fail_open
    servers:
      - address: time.cloudflare.com
      - name: nist
        address: time.nist.gov:4460
`)
	if err != nil {
		t.Fatalf("Load valid NTS config: %v", err)
	}
	sc := cfg.Time.Source
	if !sc.Enabled() || sc.ResolvedType() != "nts" {
		t.Fatalf("expected an enabled nts source, got enabled=%v type=%q", sc.Enabled(), sc.ResolvedType())
	}
	if sc.MaxDriftDuration() != 2*time.Second {
		t.Fatalf("MaxDrift = %v", sc.MaxDriftDuration())
	}
	if !sc.FailOpenOnUnreachable() {
		t.Fatal("on_source_error: fail_open should select fail-open")
	}
	if len(sc.Servers) != 2 {
		t.Fatalf("servers = %d, want 2", len(sc.Servers))
	}
}

func TestTimeSourceRoughtimeValid(t *testing.T) {
	// A 32-byte all-zero Ed25519 key, base64-encoded.
	cfg, err := loadWithTime(t, `
time:
  source:
    type: roughtime
    servers:
      - name: cf
        address: roughtime.cloudflare.com:2002
        public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
`)
	if err != nil {
		t.Fatalf("Load valid Roughtime config: %v", err)
	}
	if cfg.Time.Source.ResolvedType() != "roughtime" {
		t.Fatalf("type = %q", cfg.Time.Source.ResolvedType())
	}
}

func TestTimeSourceValidationErrors(t *testing.T) {
	cases := []struct {
		name  string
		block string
		want  string
	}{
		{
			name:  "unknown type",
			block: "time:\n  source:\n    type: gps\n",
			want:  "not one of system|nts|roughtime",
		},
		{
			name:  "nts without servers",
			block: "time:\n  source:\n    type: nts\n",
			want:  "requires at least one",
		},
		{
			name:  "bad duration",
			block: "time:\n  source:\n    type: nts\n    max_drift: \"soon\"\n    servers:\n      - address: a\n",
			want:  "not a valid duration",
		},
		{
			name:  "bad policy",
			block: "time:\n  source:\n    type: nts\n    on_source_error: maybe\n    servers:\n      - address: a\n",
			want:  "on_source_error",
		},
		{
			name:  "roughtime without key",
			block: "time:\n  source:\n    type: roughtime\n    servers:\n      - address: a:2002\n",
			want:  "requires a public_key",
		},
		{
			name:  "roughtime bad key",
			block: "time:\n  source:\n    type: roughtime\n    servers:\n      - address: a:2002\n        public_key: not-a-key\n",
			want:  "public_key",
		},
		{
			name:  "min_sources exceeds servers",
			block: "time:\n  source:\n    type: nts\n    min_sources: 3\n    servers:\n      - address: a\n",
			want:  "exceeds the number of configured servers",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadWithTime(t, c.block)
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", c.want)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), c.want)
			}
		})
	}
}

func TestTimeSourceUnknownKeysAccepted(t *testing.T) {
	// The strict unknown-key lint the doctor runs must accept the time block.
	raw := []byte(`
root_user:
  password: "x"
key_provider:
  type: software
  software:
    keystore_dir: ks
time:
  source:
    type: nts
    max_drift: 5s
    servers:
      - address: time.example.com
`)
	findings, err := UnknownKeys(raw)
	if err != nil {
		t.Fatalf("UnknownKeys: %v", err)
	}
	for _, f := range findings {
		if strings.Contains(f, "time") {
			t.Fatalf("time block flagged as unknown: %q", f)
		}
	}
}
