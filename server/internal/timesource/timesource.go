// Package timesource provides pluggable, trusted external time sources and a
// fail-closed drift checker that guards timestamp signing against a compromised
// or badly-drifted host clock.
//
// The RFC 3161 Time-Stamp Authority (internal/tsa) and the audit-chain anchor
// service (internal/anchor) derive their genTime from the system wall clock. A
// host whose clock has been rewound, advanced, or has silently drifted would
// otherwise emit authoritatively-signed but false timestamps — undermining the
// core trust guarantee of a timestamping authority. This package lets an
// operator name one or more trusted external time sources (authenticated
// NTP/NTS per RFC 8915, or Roughtime); before signing, the Checker cross-checks
// the host clock against them and fails closed — refusing to sign, recording a
// metric, and emitting an audit event — when the measured offset exceeds a
// configurable threshold.
//
// The zero-config default is the system clock (System), which trusts the host
// wall clock unconditionally and never fails closed, so existing deployments
// are unaffected until they opt in to an external source.
package timesource

import (
	"context"
	"time"
)

// Clock yields the time to stamp with, having validated it against the
// configured trusted source(s). Now returns a non-nil error to force the caller
// to fail closed (refuse to sign) when the host clock cannot be trusted.
// Describe returns a short, credential-free description for logs and doctor.
//
// The concrete implementations are the pass-through system clock (System /
// Fixed) and the cross-checking *Checker.
type Clock interface {
	Now(ctx context.Context) (time.Time, error)
	Describe() string
}

// systemClock trusts the host wall clock unconditionally. It backs both the
// zero-config default (System) and the test seam (Fixed): a nil-check-free
// Clock that never fails closed, so wiring can treat "no external source" and
// "an external source" uniformly.
type systemClock struct {
	now func() time.Time
}

func (c systemClock) Now(context.Context) (time.Time, error) { return c.now(), nil }

func (c systemClock) Describe() string { return "system clock (host wall clock)" }

// System returns the zero-config default Clock: it returns the host wall clock
// and never fails closed. There is nothing to cross-check against, so the host
// clock is itself the reference.
func System() Clock { return systemClock{now: time.Now} }

// Fixed returns a non-failing Clock backed by now. It exists for the SetClock
// test seam on tsa.Authority / anchor.Service, so those existing test hooks keep
// injecting a deterministic time without any drift check.
func Fixed(now func() time.Time) Clock { return systemClock{now: now} }

// Reading is one observation from a trusted time source.
type Reading struct {
	// Time is the trusted ("true") time the source reports for the instant of the
	// exchange — the NTP transmit timestamp, or the Roughtime midpoint. It is
	// carried for display/audit; the pass/fail decision uses Offset.
	Time time.Time
	// Offset is the signed host-minus-source offset the provider measured around
	// its (tight) request/response exchange: positive means the host clock is
	// ahead of the trusted source. The provider computes it from its own local
	// clock samples so that a slow key-establishment handshake before the actual
	// time query does not skew the measurement.
	Offset time.Duration
	// RTT is the measured request/response round-trip. Zero for a local source.
	RTT time.Duration
	// Uncertainty bounds the source's own stated error (a Roughtime radius, an
	// NTP root dispersion). Zero when the source states none.
	Uncertainty time.Duration
}

// Provider queries one trusted external time source. Implementations must be
// safe for concurrent use; the Checker may query several providers concurrently.
type Provider interface {
	// Now queries the source and returns its trusted-time Reading. A non-nil
	// error means the source was unreachable or its response failed
	// authentication/validation — the Checker applies the configured
	// unreachable-source policy (fail closed or fail open) to such a result, but
	// NEVER treats an authentication failure as a valid time.
	Now(ctx context.Context) (Reading, error)
	// Name identifies the source for audit details, metrics labels, and logs. It
	// must be credential-free (a hostname/label, never a key or token).
	Name() string
}

// Sample is one provider's contribution to a CheckResult.
type Sample struct {
	// Source is the provider name (its Name()).
	Source string `json:"source"`
	// Time is the trusted time the source reported (zero when Err != nil).
	Time time.Time `json:"time,omitempty"`
	// Offset is the signed host-minus-source offset: positive means the host
	// clock is ahead of the trusted source. Meaningful only when Err == nil.
	Offset time.Duration `json:"offset"`
	// RTT is the measured round-trip to the source.
	RTT time.Duration `json:"rtt"`
	// Err is the reachability/authentication error, or nil on a good reading.
	Err error `json:"-"`
	// ErrText is Err rendered for JSON/audit (empty on success).
	ErrText string `json:"error,omitempty"`
}

// abs returns the absolute value of a duration.
func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
