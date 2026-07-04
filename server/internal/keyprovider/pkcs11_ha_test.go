package keyprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// These tests exercise the HA provider's policy validation, routing, and
// failover bookkeeping without touching a PKCS#11 token. The token-backed
// end-to-end failover proof lives in pkcs11_ha_softhsm_test.go.

func TestNewPKCS11HAProviderValidation(t *testing.T) {
	cases := []struct {
		name    string
		s       PKCS11Settings
		wantErr string
	}{
		{
			name:    "no tokens",
			s:       PKCS11Settings{ModulePath: "/x"},
			wantErr: "requires at least one token",
		},
		{
			name:    "missing module",
			s:       PKCS11Settings{Tokens: []TokenSettings{{TokenLabel: "a"}}},
			wantErr: "module_path is required",
		},
		{
			name: "bad policy",
			s: PKCS11Settings{
				ModulePath:      "/x",
				SelectionPolicy: "bogus",
				Tokens:          []TokenSettings{{TokenLabel: "a"}},
			},
			wantErr: "unknown pkcs11 selection_policy",
		},
		{
			name: "duplicate name",
			s: PKCS11Settings{
				ModulePath: "/x",
				Tokens: []TokenSettings{
					{Name: "dup", TokenLabel: "a"},
					{Name: "dup", TokenLabel: "b"},
				},
			},
			wantErr: "duplicate token name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPKCS11HAProvider(tc.s)
			if p != nil {
				_ = p.Close()
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// newBareHA builds an HA provider struct directly, with no session pools and no
// background prober, so routing/failover logic can be tested in isolation.
func newBareHA(policy SelectionPolicy, threshold int, names ...string) *PKCS11HAProvider {
	members := make([]*haMember, len(names))
	for i, n := range names {
		members[i] = &haMember{name: n, healthy: true}
	}
	return &PKCS11HAProvider{
		members:   members,
		policy:    policy,
		threshold: threshold,
		stopCh:    make(chan struct{}),
	}
}

func routeNames(p *PKCS11HAProvider) []string {
	ms := p.route()
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.name
	}
	return out
}

func TestRoutePrimaryBackupPrefersHealthyInOrder(t *testing.T) {
	p := newBareHA(PolicyPrimaryBackup, 1, "a", "b", "c")

	if got := routeNames(p); !equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("route = %v, want [a b c]", got)
	}

	// Mark the primary unhealthy: it drops to the back, backups keep order.
	p.members[0].recordFailure(1)
	if got := routeNames(p); !equal(got, []string{"b", "c", "a"}) {
		t.Fatalf("route after primary down = %v, want [b c a]", got)
	}

	// Recover the primary: it returns to the front.
	p.members[0].recordSuccess()
	if got := routeNames(p); !equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("route after recovery = %v, want [a b c]", got)
	}
}

func TestRoundRobinSpreadsHealthy(t *testing.T) {
	p := newBareHA(PolicyRoundRobin, 1, "a", "b", "c")
	// Over several routes the first (preferred) healthy member should rotate.
	firsts := map[string]int{}
	for i := 0; i < 30; i++ {
		firsts[routeNames(p)[0]]++
	}
	for _, n := range []string{"a", "b", "c"} {
		if firsts[n] == 0 {
			t.Errorf("round-robin never routed to %q first: %v", n, firsts)
		}
	}
	// An unhealthy member is never preferred and always sorts last.
	p.members[1].recordFailure(1) // b down
	for i := 0; i < 20; i++ {
		names := routeNames(p)
		if names[len(names)-1] != "b" {
			t.Fatalf("unhealthy member not last: %v", names)
		}
		if names[0] == "b" {
			t.Fatalf("unhealthy member routed first: %v", names)
		}
	}
}

func TestWithFailoverRetriesAndMarksHealth(t *testing.T) {
	p := newBareHA(PolicyPrimaryBackup, 1, "hafo-a", "hafo-b", "hafo-c")

	var tried []string
	transportErr := errors.New("pkcs11: session handle invalid")
	err := p.withFailover(context.Background(), "sign", nil, func(m *haMember) error {
		tried = append(tried, m.name)
		if m.name == "hafo-a" {
			return transportErr // health-affecting: token A "fails"
		}
		return nil // B succeeds
	})
	if err != nil {
		t.Fatalf("withFailover returned %v, want nil (failover to B)", err)
	}
	if !equal(tried, []string{"hafo-a", "hafo-b"}) {
		t.Fatalf("tried = %v, want [hafo-a hafo-b]", tried)
	}
	if p.members[0].isHealthy() {
		t.Error("token A should be marked unhealthy after a health-affecting failure")
	}
	if !p.members[1].isHealthy() {
		t.Error("token B should remain healthy")
	}
}

func TestWithFailoverNotFoundDoesNotAffectHealth(t *testing.T) {
	p := newBareHA(PolicyPrimaryBackup, 1, "hanf-a", "hanf-b")

	// A logical not-found is a property of the request, not the token: it must not
	// mark a token unhealthy, though the next member is still tried.
	err := p.withFailover(context.Background(), "find", nil, func(m *haMember) error {
		return fmt.Errorf("looking up: %w", ErrKeyNotFound)
	})
	if !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("err = %v, want ErrKeyNotFound", err)
	}
	if !p.members[0].isHealthy() || !p.members[1].isHealthy() {
		t.Error("a not-found error must not mark any token unhealthy")
	}
}

func TestWithFailoverAllFailReturnsLastError(t *testing.T) {
	p := newBareHA(PolicyPrimaryBackup, 1, "haaf-a", "haaf-b")
	sentinel := errors.New("boom-b")
	err := p.withFailover(context.Background(), "sign", nil, func(m *haMember) error {
		if m.name == "haaf-b" {
			return sentinel
		}
		return errors.New("boom-a")
	})
	if err == nil {
		t.Fatal("expected an error when every token fails")
	}
	// Both tokens are down now; route() still returns them (last resort) so the
	// provider degrades rather than vanishing.
	if len(p.route()) != 2 {
		t.Fatalf("route() dropped tokens: %v", routeNames(p))
	}
}

func TestFailureThresholdTakesMultipleFailures(t *testing.T) {
	p := newBareHA(PolicyPrimaryBackup, 3, "hath-a", "hath-b")
	m := p.members[0]
	m.recordFailure(3)
	if !m.isHealthy() {
		t.Fatal("token marked unhealthy after 1 failure, want threshold 3")
	}
	m.recordFailure(3)
	if !m.isHealthy() {
		t.Fatal("token marked unhealthy after 2 failures, want threshold 3")
	}
	m.recordFailure(3)
	if m.isHealthy() {
		t.Fatal("token still healthy after 3 failures")
	}
	// A single success returns it to rotation and resets the counter.
	m.recordSuccess()
	if !m.isHealthy() {
		t.Fatal("token did not recover after success")
	}
}

func TestHealthAffecting(t *testing.T) {
	if healthAffecting(nil) {
		t.Error("nil error should not affect health")
	}
	if healthAffecting(fmt.Errorf("wrap: %w", ErrKeyNotFound)) {
		t.Error("key-not-found should not affect health")
	}
	if !healthAffecting(errors.New("CKR_DEVICE_ERROR")) {
		t.Error("a transport error should affect health")
	}
	if !healthAffecting(errTokenUnreachable) {
		t.Error("unreachable token should affect health")
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
