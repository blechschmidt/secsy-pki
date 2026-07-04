package agent

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSProvider publishes and withdraws the _acme-challenge TXT record that
// answers an ACME dns-01 challenge (RFC 8555 §8.4). Implementations are the
// pluggable half of the agent's dns-01 solver; the agent computes the record
// value (the base64url key-authorization digest) and hands the fully-qualified
// record name and value to the provider.
//
// Present must be idempotent enough that re-publishing the same (fqdn, value)
// is harmless, since a retried authorization may call it again. CleanUp removes
// exactly the record Present created and must tolerate the record already being
// absent.
type DNSProvider interface {
	// Present publishes a TXT record at fqdn (a fully-qualified name ending in a
	// dot, e.g. "_acme-challenge.host.example.com.") carrying value.
	Present(ctx context.Context, fqdn, value string) error
	// CleanUp removes the TXT record published by Present.
	CleanUp(ctx context.Context, fqdn, value string) error
}

// dnsResolver is the propagation-check surface: it looks up the TXT records at a
// name so the solver can wait for a published record to become visible before
// telling the ACME server to validate. *net.Resolver satisfies it, and tests
// inject a fake.
type dnsResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// dns01Solver answers dns-01 challenges by driving a DNSProvider and then
// polling a resolver until the record propagates.
type dns01Solver struct {
	provider DNSProvider
	resolver dnsResolver

	propagationTimeout time.Duration
	pollInterval       time.Duration

	// now and sleep are injectable so propagation polling is deterministic and
	// fast in tests.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// newDNS01Solver builds a dns-01 solver (provider + propagation checker) from
// the agent's dns01 configuration.
func newDNS01Solver(cfg DNS01Config) (*dns01Solver, error) {
	provider, err := newDNSProvider(cfg)
	if err != nil {
		return nil, err
	}
	resolver := newPropagationResolver(cfg)
	return &dns01Solver{
		provider:           provider,
		resolver:           resolver,
		propagationTimeout: cfg.PropagationTimeout.Std(),
		pollInterval:       cfg.PollInterval.Std(),
		now:                time.Now,
		sleep:              sleepCtx,
	}, nil
}

// newDNSProvider constructs the configured DNSProvider.
func newDNSProvider(cfg DNS01Config) (DNSProvider, error) {
	switch cfg.Provider {
	case DNSProviderRFC2136:
		return newRFC2136Provider(cfg.RFC2136)
	case DNSProviderExec:
		return newExecDNSProvider(cfg.Exec)
	case DNSProviderRoute53:
		return newRoute53Provider(context.Background(), cfg.Route53)
	case "":
		return nil, fmt.Errorf("dns-01 challenge selected but no acme.dns01.provider is configured")
	default:
		return nil, fmt.Errorf("unknown dns-01 provider %q", cfg.Provider)
	}
}

// newPropagationResolver builds the resolver used to confirm the record is
// visible. When explicit resolvers are configured they are queried directly;
// otherwise the RFC 2136 server (which just accepted the UPDATE) is used, and
// failing that the system resolver.
func newPropagationResolver(cfg DNS01Config) dnsResolver {
	servers := cfg.Resolvers
	if len(servers) == 0 && cfg.Provider == DNSProviderRFC2136 && cfg.RFC2136 != nil {
		servers = []string{cfg.RFC2136.Server}
	}
	if len(servers) == 0 {
		return net.DefaultResolver
	}
	normalized := make([]string, 0, len(servers))
	for _, s := range servers {
		normalized = append(normalized, withDefaultPort(s, "53"))
	}
	return newPinnedResolver(normalized)
}

// present publishes the challenge record and waits for it to propagate.
func (s *dns01Solver) present(ctx context.Context, fqdn, value string) error {
	if err := s.provider.Present(ctx, fqdn, value); err != nil {
		return fmt.Errorf("publishing dns-01 record %s: %w", fqdn, err)
	}
	if err := s.waitPropagation(ctx, fqdn, value); err != nil {
		// Best-effort withdraw so a failed propagation does not leak the record.
		_ = s.provider.CleanUp(ctx, fqdn, value)
		return err
	}
	return nil
}

// cleanup withdraws the challenge record, logging (via the returned error) but
// never blocking the caller.
func (s *dns01Solver) cleanup(ctx context.Context, fqdn, value string) error {
	return s.provider.CleanUp(ctx, fqdn, value)
}

// waitPropagation polls the resolver until a TXT record at fqdn equals value or
// the propagation timeout elapses. A zero timeout skips the check.
func (s *dns01Solver) waitPropagation(ctx context.Context, fqdn, value string) error {
	if s.propagationTimeout <= 0 {
		return nil
	}
	poll := s.pollInterval
	if poll <= 0 {
		poll = defaultDNSPollInterval
	}
	name := strings.TrimSuffix(fqdn, ".")
	deadline := s.now().Add(s.propagationTimeout)
	var lastErr error
	for {
		txts, err := s.resolver.LookupTXT(ctx, name)
		if err != nil {
			lastErr = err
		} else {
			lastErr = nil
			for _, txt := range txts {
				if txt == value {
					return nil
				}
			}
		}
		if !s.now().Before(deadline) {
			if lastErr != nil {
				return fmt.Errorf("dns-01 record %s did not propagate within %s (last lookup error: %w)", fqdn, s.propagationTimeout, lastErr)
			}
			return fmt.Errorf("dns-01 record %s did not propagate within %s", fqdn, s.propagationTimeout)
		}
		if err := s.sleep(ctx, poll); err != nil {
			return err
		}
	}
}

// sleepCtx sleeps for d unless ctx is cancelled first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// challengeRecordName returns the _acme-challenge owner name for a domain, as a
// fully-qualified name ending in a dot. For a wildcard authorization the ACME
// server reports the base domain, so no special handling is needed here.
func challengeRecordName(domain string) string {
	return "_acme-challenge." + strings.TrimSuffix(domain, ".") + "."
}

// withDefaultPort appends :port to host when it carries no port.
func withDefaultPort(host, port string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return host
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	// Bare IPv6 literals must be bracketed before appending a port.
	if strings.Count(host, ":") >= 2 && !strings.HasPrefix(host, "[") {
		return "[" + host + "]:" + port
	}
	return net.JoinHostPort(host, port)
}

// newPinnedResolver returns a Go resolver that sends every query to the given
// DNS servers (host:port), trying them in order. It is used for propagation
// checks against an authoritative nameserver rather than the system recursor.
func newPinnedResolver(servers []string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			var lastErr error
			for _, srv := range servers {
				conn, err := d.DialContext(ctx, network, srv)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("no resolvers configured")
			}
			return nil, lastErr
		},
	}
}
