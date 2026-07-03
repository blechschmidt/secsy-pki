package config

import (
	"strings"
	"testing"
	"time"
)

// TestCanaryDefaults proves the block is optional and that an enabled block
// resolves the documented defaults (15m interval, 60s timeout, canary profile
// left to the prober).
func TestCanaryDefaults(t *testing.T) {
	cfg := writeAndLoad(t, `
root_user:
  password: secret
`)
	if cfg.Canary.Enabled {
		t.Fatal("canary must be disabled by default")
	}
	if got := cfg.Canary.Interval(); got != 15*time.Minute {
		t.Fatalf("default interval = %s, want 15m", got)
	}
	if got := cfg.Canary.Timeout(); got != 60*time.Second {
		t.Fatalf("default timeout = %s, want 60s", got)
	}

	cfg = writeAndLoad(t, `
root_user:
  password: secret
canary:
  enabled: true
  interval_minutes: 5
  timeout_seconds: 30
  cas: [issuing-ca]
  profile: canary
`)
	c := cfg.Canary
	if !c.Enabled || c.Interval() != 5*time.Minute || c.Timeout() != 30*time.Second ||
		len(c.CAs) != 1 || c.CAs[0] != "issuing-ca" || c.Profile != "canary" {
		t.Fatalf("unexpected canary config: %+v", c)
	}
}

// TestCanaryRejectsInvalid proves misconfiguration fails loudly at load time.
func TestCanaryRejectsInvalid(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			name: "enabled without cas",
			yaml: `
root_user:
  password: secret
canary:
  enabled: true
`,
			wantErr: "canary.cas is empty",
		},
		{
			name: "blank ca entry",
			yaml: `
root_user:
  password: secret
canary:
  enabled: true
  cas: ["  "]
`,
			wantErr: "canary.cas[0]",
		},
		{
			name: "timeout not shorter than interval",
			yaml: `
root_user:
  password: secret
canary:
  enabled: true
  cas: [issuing-ca]
  interval_minutes: 1
  timeout_seconds: 60
`,
			wantErr: "must be shorter than",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadContent(t, tc.yaml)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Load error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}
