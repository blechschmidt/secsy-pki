package timesource

import (
	"fmt"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
)

// FromConfig builds a Clock from the time.source configuration block. When the
// type is "system" (or empty) it returns the zero-config System clock, which
// never fails closed. For "nts"/"roughtime" it constructs one Provider per
// configured server and wraps them in a fail-closed Checker.
//
// auditor is invoked (when non-nil) on each fresh check that fails closed, so
// the wiring can append a tamper-evident audit event; pass nil for read-only
// callers such as `secsy-ca doctor`.
//
// It mirrors tsa.LoadAuthorityConfig: a single shared assembly point so the
// server and the secsy-ca CLI build an identical Clock from the same config.
func FromConfig(sc config.TimeSourceConfig, auditor func(CheckResult)) (Clock, error) {
	if !sc.Enabled() {
		return System(), nil
	}

	opts := CheckerOptions{
		Threshold:             sc.MaxDriftDuration(),
		RefreshInterval:       sc.RefreshDuration(),
		Timeout:               sc.TimeoutDuration(),
		MinSources:            sc.MinSourcesResolved(),
		FailOpenOnUnreachable: sc.FailOpenOnUnreachable(),
		SourceType:            sc.ResolvedType(),
		Auditor:               auditor,
	}

	providers := make([]Provider, 0, len(sc.Servers))
	switch sc.ResolvedType() {
	case "nts":
		for i, srv := range sc.Servers {
			p, err := NewNTSProvider(NTSServer{Name: srv.Name, Address: srv.Address, Timeout: opts.Timeout})
			if err != nil {
				return nil, fmt.Errorf("time.source.servers[%d]: %w", i, err)
			}
			providers = append(providers, p)
		}
	case "roughtime":
		for i, srv := range sc.Servers {
			p, err := NewRoughtimeProvider(RoughtimeServer{Name: srv.Name, Address: srv.Address, PublicKey: srv.PublicKey, Timeout: opts.Timeout})
			if err != nil {
				return nil, fmt.Errorf("time.source.servers[%d]: %w", i, err)
			}
			providers = append(providers, p)
		}
	default:
		// Unreachable: Enabled() already restricted the type, and validateTime
		// rejects anything else at config load.
		return nil, fmt.Errorf("timesource: unsupported source type %q", sc.ResolvedType())
	}

	return NewChecker(providers, opts), nil
}
