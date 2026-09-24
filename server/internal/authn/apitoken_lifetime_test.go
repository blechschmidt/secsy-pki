package authn

import (
	"math"
	"strings"
	"testing"
	"time"
)

// ResolveTokenLifetimeDays is the single source of truth for API-token expiry
// policy, shared by the REST handler (internal/handlers/tokens.go) and the CLI
// (cmd/secsy-ca/token.go). The security property is that a deployment which
// configures a maximum lifetime cannot be talked into minting a longer-lived — or
// immortal — bearer credential, whatever the caller asks for.

func intp(v int) *int { return &v }

func TestResolveTokenLifetimeDaysWithCap(t *testing.T) {
	const capDays = 30
	max := capDays * 24 * time.Hour

	cases := []struct {
		name      string
		requested *int
		want      int
		wantErr   bool
	}{
		{"unspecified defaults to the cap", nil, capDays, false},
		{"one day", intp(1), 1, false},
		{"just under the cap", intp(capDays - 1), capDays - 1, false},
		{"exactly the cap is allowed", intp(capDays), capDays, false},
		// 0 means "never expires"; a deployment with a cap forbids immortal tokens.
		{"zero is refused under a cap", intp(0), 0, true},
		{"one day over the cap", intp(capDays + 1), 0, true},
		{"far over the cap", intp(3650), 0, true},
		{"negative", intp(-1), 0, true},
		{"very negative", intp(-100000), 0, true},
		// The comparison must be plain integer arithmetic: no overflow, no wrap to
		// an accepted value.
		{"max int", intp(math.MaxInt), 0, true},
		{"min int", intp(math.MinInt), 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveTokenLifetimeDays(max, tc.requested)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ResolveTokenLifetimeDays(%v, %v) err = %v, wantErr = %v", max, tc.requested, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("days = %d, want %d", got, tc.want)
			}
			if tc.wantErr {
				// A rejected request must never yield a usable lifetime, and
				// certainly not the unbounded 0.
				if got != 0 {
					t.Errorf("a rejected request returned %d days", got)
				}
				return
			}
			if got <= 0 || got > capDays {
				t.Errorf("accepted lifetime %d days escapes the configured cap of %d", got, capDays)
			}
		})
	}

	// The rejection message must state the permitted range so an operator can
	// correct the request, without revealing anything sensitive.
	if _, err := ResolveTokenLifetimeDays(max, intp(capDays+1)); err == nil ||
		!strings.Contains(err.Error(), "between 1 and 30") {
		t.Errorf("over-cap error = %v, want it to name the 1..30 range", err)
	}
}

func TestResolveTokenLifetimeDaysWithoutCap(t *testing.T) {
	cases := []struct {
		name      string
		requested *int
		want      int
		wantErr   bool
	}{
		// With no cap configured, an unspecified expiry means "never expires" (0),
		// which is the documented default for a deployment that has not opted into
		// a lifetime policy.
		{"unspecified is unbounded", nil, 0, false},
		{"explicit never", intp(0), 0, false},
		{"one day", intp(1), 1, false},
		{"ten years", intp(3650), 3650, false},
		{"max int is honored", intp(math.MaxInt), math.MaxInt, false},
		{"negative is still refused", intp(-1), 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveTokenLifetimeDays(0, tc.requested)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("days = %d, want %d", got, tc.want)
			}
		})
	}

	// A negative maximum (a nonsensical configuration) must not become a negative
	// cap that rejects everything or, worse, an accepted negative lifetime.
	if got, err := ResolveTokenLifetimeDays(-time.Hour, nil); err != nil || got > 0 {
		t.Errorf("ResolveTokenLifetimeDays(-1h, nil) = (%d, %v), want (<=0, nil)", got, err)
	}
	if _, err := ResolveTokenLifetimeDays(-time.Hour, intp(-5)); err == nil {
		t.Error("a negative request must be refused even with a negative cap")
	}
}

// TestResolveTokenLifetimeDaysCapGranularity pins the day-granularity truncation
// of the cap.
//
// NOTE (reported): a sub-day maximum truncates to a cap of 0, which this function
// treats as "no cap" — so a 23h maximum silently permits an unbounded (never
// expiring) token, inverting the operator's intent. It is not reachable from
// configuration today, because auth.api_tokens.max_lifetime_days is a whole
// number of days (internal/config/config.go APITokenMaxLifetime), so this is a
// latent API sharp edge rather than an exploitable misconfiguration. The cases
// below assert the current behaviour; if a sub-day cap is ever made to floor at 1
// day, update them together with the doc comment.
func TestResolveTokenLifetimeDaysCapGranularity(t *testing.T) {
	// Whole multiples of a day behave exactly.
	for _, days := range []int{1, 2, 7, 365} {
		got, err := ResolveTokenLifetimeDays(time.Duration(days)*24*time.Hour, nil)
		if err != nil || got != days {
			t.Errorf("cap of %d days: got (%d, %v), want (%d, nil)", days, got, err, days)
		}
	}
	// A partial extra day truncates downwards, i.e. towards the stricter policy.
	if got, _ := ResolveTokenLifetimeDays(36*time.Hour, nil); got != 1 {
		t.Errorf("cap of 36h defaulted to %d days, want 1", got)
	}
	if _, err := ResolveTokenLifetimeDays(36*time.Hour, intp(2)); err == nil {
		t.Error("cap of 36h should refuse a 2-day request (truncated cap is 1 day)")
	}
	// Sub-day cap: currently indistinguishable from "no cap".
	if got, err := ResolveTokenLifetimeDays(23*time.Hour, nil); err != nil || got != 0 {
		t.Errorf("cap of 23h: got (%d, %v); a sub-day cap currently means unbounded", got, err)
	}
	if got, err := ResolveTokenLifetimeDays(23*time.Hour, intp(3650)); err != nil || got != 3650 {
		t.Errorf("cap of 23h accepted %d days (err=%v); a sub-day cap currently imposes no limit", got, err)
	}
}
