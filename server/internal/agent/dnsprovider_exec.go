package agent

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// execDNSProvider answers dns-01 challenges by shelling out to operator-supplied
// scripts. Present publishes the TXT record and CleanUp withdraws it; both reuse
// the hardened process-group command runner shared with the reload hook, so a
// runaway script is killed as a group on timeout. The record is passed to the
// scripts through the environment (SECSY_DNS01_*), matching the reload hook's
// env-only convention.
type execDNSProvider struct {
	present []string
	cleanup []string
	timeout time.Duration
}

// newExecDNSProvider builds the provider from its validated configuration.
func newExecDNSProvider(cfg *ExecDNSConfig) (*execDNSProvider, error) {
	if cfg == nil {
		return nil, fmt.Errorf("exec: configuration is missing")
	}
	if len(cfg.Present) == 0 {
		return nil, fmt.Errorf("exec: present command is required")
	}
	timeout := cfg.Timeout.Std()
	if timeout <= 0 {
		timeout = defaultHookTimeout
	}
	return &execDNSProvider{
		present: cfg.Present,
		cleanup: cfg.CleanUp,
		timeout: timeout,
	}, nil
}

// Present runs the publish script.
func (p *execDNSProvider) Present(ctx context.Context, fqdn, value string) error {
	return p.run(ctx, p.present, "present", fqdn, value)
}

// CleanUp runs the withdraw script, if one is configured.
func (p *execDNSProvider) CleanUp(ctx context.Context, fqdn, value string) error {
	if len(p.cleanup) == 0 {
		return nil
	}
	return p.run(ctx, p.cleanup, "cleanup", fqdn, value)
}

// run invokes one script with the challenge context in the environment.
func (p *execDNSProvider) run(ctx context.Context, argv []string, action, fqdn, value string) error {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	env := append(os.Environ(),
		"SECSY_DNS01_ACTION="+action,
		"SECSY_DNS01_FQDN="+fqdn,
		"SECSY_DNS01_RECORD="+strings.TrimSuffix(fqdn, "."),
		"SECSY_DNS01_VALUE="+value,
	)
	output, err := runProcessGroup(ctx, argv, env)
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("exec %s command timed out after %s", action, p.timeout)
	}
	if err != nil {
		return fmt.Errorf("exec %s command %q: %w (output: %s)", action, strings.Join(argv, " "), err, summarizeBody(output))
	}
	return nil
}
