package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecDNSProviderPresentCleanUp(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "actions.log")
	p, err := newExecDNSProvider(&ExecDNSConfig{
		Present: CommandLine{"sh", "-c", `printf '%s|%s|%s\n' "$SECSY_DNS01_ACTION" "$SECSY_DNS01_FQDN" "$SECSY_DNS01_VALUE" >> "` + log + `"`},
		CleanUp: CommandLine{"sh", "-c", `printf '%s|%s|%s\n' "$SECSY_DNS01_ACTION" "$SECSY_DNS01_RECORD" "$SECSY_DNS01_VALUE" >> "` + log + `"`},
		Timeout: Duration(10 * time.Second),
	})
	if err != nil {
		t.Fatalf("newExecDNSProvider: %v", err)
	}

	fqdn := "_acme-challenge.host.example.com."
	value := "digest-value-xyz"
	ctx := context.Background()
	if err := p.Present(ctx, fqdn, value); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if err := p.CleanUp(ctx, fqdn, value); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}

	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("reading action log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 script invocations, got %d: %q", len(lines), data)
	}
	if lines[0] != "present|"+fqdn+"|"+value {
		t.Errorf("present line = %q", lines[0])
	}
	// CleanUp receives SECSY_DNS01_RECORD (fqdn without the trailing dot).
	if lines[1] != "cleanup|"+strings.TrimSuffix(fqdn, ".")+"|"+value {
		t.Errorf("cleanup line = %q", lines[1])
	}
}

func TestExecDNSProviderCleanUpOptional(t *testing.T) {
	p, err := newExecDNSProvider(&ExecDNSConfig{
		Present: CommandLine{"true"},
		Timeout: Duration(5 * time.Second),
	})
	if err != nil {
		t.Fatalf("newExecDNSProvider: %v", err)
	}
	if err := p.CleanUp(context.Background(), "_acme-challenge.x.example.com.", "v"); err != nil {
		t.Fatalf("CleanUp without a cleanup command should be a no-op, got %v", err)
	}
}

func TestExecDNSProviderPresentFailurePropagates(t *testing.T) {
	p, err := newExecDNSProvider(&ExecDNSConfig{
		Present: CommandLine{"sh", "-c", "echo boom >&2; exit 3"},
		Timeout: Duration(5 * time.Second),
	})
	if err != nil {
		t.Fatalf("newExecDNSProvider: %v", err)
	}
	err = p.Present(context.Background(), "_acme-challenge.x.example.com.", "v")
	if err == nil || !strings.Contains(err.Error(), "present") {
		t.Fatalf("error = %v, want a present-command failure", err)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error should include the script output: %v", err)
	}
}
