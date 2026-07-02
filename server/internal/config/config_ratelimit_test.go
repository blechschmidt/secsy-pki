package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRateLimitConfig writes a minimal valid config with the given rate_limit
// block appended and returns its path.
func writeRateLimitConfig(t *testing.T, rateLimit string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	base := `
root_user:
  username: admin
  password: secret
key_provider:
  type: software
  software:
    keystore_dir: /tmp/ks
`
	if err := os.WriteFile(path, []byte(base+rateLimit), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadRateLimitValid(t *testing.T) {
	path := writeRateLimitConfig(t, `
rate_limit:
  enabled: true
  global:      { rate: 200, burst: 400 }
  per_ip:      { rate: 20,  burst: 40 }
  per_account: { rate: 50,  burst: 100 }
  concurrency:
    max_in_flight: 8
    max_queue: 64
    acquire_timeout_ms: 5000
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rl := cfg.RateLimit
	if !rl.Enabled {
		t.Fatal("rate_limit.enabled should be true")
	}
	if rl.Global.Rate != 200 || rl.Global.Burst != 400 {
		t.Errorf("global = %+v", rl.Global)
	}
	if rl.PerAccount.Burst != 100 {
		t.Errorf("per_account = %+v", rl.PerAccount)
	}
	if rl.Concurrency.MaxInFlight != 8 || rl.Concurrency.MaxQueue != 64 {
		t.Errorf("concurrency = %+v", rl.Concurrency)
	}
	if !rl.Concurrency.GuardEnabled(true) {
		t.Error("guard should default to enabled")
	}
}

func TestLoadRateLimitDisabledSkipsValidation(t *testing.T) {
	// A disabled rate limiter with otherwise nonsensical values must still load
	// (validation is skipped when disabled).
	path := writeRateLimitConfig(t, `
rate_limit:
  enabled: false
  global: { rate: -5, burst: -1 }
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("disabled rate_limit should load: %v", err)
	}
}

func TestLoadRateLimitZeroBurstRejected(t *testing.T) {
	path := writeRateLimitConfig(t, `
rate_limit:
  enabled: true
  per_ip: { rate: 10, burst: 0 }
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for positive rate with zero burst")
	}
	if !strings.Contains(err.Error(), "burst must be positive") {
		t.Errorf("error = %v, want burst-positive complaint", err)
	}
}

func TestLoadRateLimitNoActiveTierNoGuardRejected(t *testing.T) {
	falseVal := false
	path := writeRateLimitConfig(t, `
rate_limit:
  enabled: true
  concurrency:
    enabled: false
`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error when no tier is active and guard is disabled")
	}
	// Sanity: the GuardEnabled helper honors an explicit false.
	cc := ConcurrencyConfig{Enabled: &falseVal}
	if cc.GuardEnabled(true) {
		t.Error("explicit enabled=false should disable the guard")
	}
}

func TestLoadRateLimitGuardOnlyAllowed(t *testing.T) {
	// No rate tiers, but the guard is on: this is a valid configuration
	// (concurrency protection without rate limiting).
	path := writeRateLimitConfig(t, `
rate_limit:
  enabled: true
  concurrency:
    max_in_flight: 4
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("guard-only config should load: %v", err)
	}
}
