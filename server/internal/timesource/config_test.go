package timesource

import (
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
)

func TestFromConfigSystem(t *testing.T) {
	for _, typ := range []string{"", "system"} {
		clock, err := FromConfig(config.TimeSourceConfig{Type: typ}, nil)
		if err != nil {
			t.Fatalf("FromConfig(%q): %v", typ, err)
		}
		if _, isChecker := clock.(*Checker); isChecker {
			t.Fatalf("type %q should yield the pass-through System clock, not a Checker", typ)
		}
	}
}

func TestFromConfigNTS(t *testing.T) {
	clock, err := FromConfig(config.TimeSourceConfig{
		Type:     "nts",
		MaxDrift: "3s",
		Servers: []config.TimeServerConfig{
			{Address: "time.cloudflare.com"},
			{Name: "nist", Address: "time.nist.gov:4460"},
		},
	}, nil)
	if err != nil {
		t.Fatalf("FromConfig nts: %v", err)
	}
	checker, ok := clock.(*Checker)
	if !ok {
		t.Fatalf("nts config should yield a *Checker, got %T", clock)
	}
	if checker.threshold != 3*time.Second {
		t.Fatalf("threshold = %v, want 3s", checker.threshold)
	}
	if len(checker.providers) != 2 {
		t.Fatalf("providers = %d, want 2", len(checker.providers))
	}
	if d := checker.Describe(); !strings.Contains(d, "nts") || !strings.Contains(d, "time.cloudflare.com") {
		t.Fatalf("Describe = %q, want the source type and server names", d)
	}
}

func TestFromConfigRoughtime(t *testing.T) {
	clock, err := FromConfig(config.TimeSourceConfig{
		Type: "roughtime",
		Servers: []config.TimeServerConfig{
			{Name: "cf", Address: "roughtime.cloudflare.com:2002", PublicKey: strings.Repeat("A", 43) + "="},
		},
	}, nil)
	if err != nil {
		t.Fatalf("FromConfig roughtime: %v", err)
	}
	if _, ok := clock.(*Checker); !ok {
		t.Fatalf("roughtime config should yield a *Checker, got %T", clock)
	}
}

func TestFromConfigRoughtimeBadKeyFails(t *testing.T) {
	_, err := FromConfig(config.TimeSourceConfig{
		Type: "roughtime",
		Servers: []config.TimeServerConfig{
			{Address: "a:2002", PublicKey: "not-a-valid-key"},
		},
	}, nil)
	if err == nil {
		t.Fatal("FromConfig should reject an invalid Roughtime public key")
	}
}
