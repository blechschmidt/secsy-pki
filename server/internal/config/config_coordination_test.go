package config

import (
	"strings"
	"testing"
)

// TestCoordinationDefaults proves the block is optional: an absent
// coordination block loads with the zero value (mode "auto" downstream).
func TestCoordinationDefaults(t *testing.T) {
	cfg := writeAndLoad(t, `
root_user:
  password: secret
`)
	if cfg.Coordination.Mode != "" || cfg.Coordination.LockName != "" {
		t.Fatalf("zero coordination expected, got %+v", cfg.Coordination)
	}
}

func TestCoordinationValid(t *testing.T) {
	cfg := writeAndLoad(t, `
root_user:
  password: secret
database:
  driver: postgres
  dsn: postgres://localhost/secsy
coordination:
  mode: postgres
  lock_name: custom/lock
  renew_interval_seconds: 3
  retry_interval_seconds: 2
`)
	co := cfg.Coordination
	if co.Mode != "postgres" || co.LockName != "custom/lock" ||
		co.RenewIntervalSeconds != 3 || co.RetryIntervalSeconds != 2 {
		t.Fatalf("unexpected coordination config: %+v", co)
	}
}

func TestCoordinationRejectsInvalid(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{
			name: "unknown mode",
			yaml: `
root_user:
  password: secret
coordination:
  mode: raft
`,
			wantErr: "coordination.mode",
		},
		{
			name: "postgres mode on sqlite driver",
			yaml: `
root_user:
  password: secret
database:
  driver: sqlite
  dsn: test.db
coordination:
  mode: postgres
`,
			wantErr: "requires database.driver postgres",
		},
		{
			name: "negative renew interval",
			yaml: `
root_user:
  password: secret
coordination:
  renew_interval_seconds: -1
`,
			wantErr: "renew_interval_seconds",
		},
		{
			name: "negative retry interval",
			yaml: `
root_user:
  password: secret
coordination:
  retry_interval_seconds: -5
`,
			wantErr: "retry_interval_seconds",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadContent(t, c.yaml)
			if err == nil {
				t.Fatalf("Load succeeded, want error containing %q", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %q does not mention %q", err, c.wantErr)
			}
		})
	}
}
