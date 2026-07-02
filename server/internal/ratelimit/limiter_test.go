package ratelimit

import (
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually-advanced clock for deterministic limiter tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestTokenBucketBurstThenRefill(t *testing.T) {
	clk := newFakeClock()
	b := newTokenBucket(1, 3, clk.now()) // 1/sec, burst 3

	// The initial burst of 3 is admitted immediately.
	for i := 0; i < 3; i++ {
		if ok, _ := b.take(clk.now()); !ok {
			t.Fatalf("burst token %d rejected", i)
		}
	}
	// The 4th is rejected, with a Retry-After of ~1s (rate 1/sec).
	ok, ra := b.take(clk.now())
	if ok {
		t.Fatal("expected rejection after burst exhausted")
	}
	if ra <= 0 || ra > time.Second+time.Millisecond {
		t.Fatalf("Retry-After = %v, want ~1s", ra)
	}

	// After 1 second exactly one token accrues.
	clk.advance(time.Second)
	if ok, _ := b.take(clk.now()); !ok {
		t.Fatal("token should have refilled after 1s")
	}
	if ok, _ := b.take(clk.now()); ok {
		t.Fatal("only one token should have refilled")
	}
}

func TestTokenBucketRefund(t *testing.T) {
	clk := newFakeClock()
	b := newTokenBucket(1, 2, clk.now())
	b.take(clk.now())
	b.take(clk.now())
	if ok, _ := b.take(clk.now()); ok {
		t.Fatal("bucket should be empty")
	}
	b.refund(clk.now())
	if ok, _ := b.take(clk.now()); !ok {
		t.Fatal("refunded token should be available")
	}
	// Refund never exceeds capacity.
	b.refund(clk.now())
	b.refund(clk.now())
	b.refund(clk.now())
	got := 0
	for {
		if ok, _ := b.take(clk.now()); !ok {
			break
		}
		got++
		if got > 10 {
			t.Fatal("refund leaked tokens beyond capacity")
		}
	}
	if got != 2 {
		t.Fatalf("capacity after over-refund = %d, want 2", got)
	}
}

func TestKeyedBucketsIndependentKeys(t *testing.T) {
	clk := newFakeClock()
	kb := newKeyedBuckets(1, 1, 100, time.Minute, clk.now)
	// Each key gets its own bucket, so key A being exhausted does not affect B.
	if ok, _ := kb.bucketFor("a", clk.now()).take(clk.now()); !ok {
		t.Fatal("A first take should pass")
	}
	if ok, _ := kb.bucketFor("a", clk.now()).take(clk.now()); ok {
		t.Fatal("A second take should be throttled")
	}
	if ok, _ := kb.bucketFor("b", clk.now()).take(clk.now()); !ok {
		t.Fatal("B should be unaffected by A")
	}
}

func TestKeyedBucketsEvictionBounded(t *testing.T) {
	clk := newFakeClock()
	kb := newKeyedBuckets(1000, 1000, 8, time.Minute, clk.now)
	// Insert far more distinct keys than maxKeys; the map must stay bounded.
	for i := 0; i < 1000; i++ {
		kb.take(string(rune('a'+i%26)) + string(rune('0'+i%10)) + string(rune(i)))
	}
	if n := kb.len(); n > 8 {
		t.Fatalf("keyed bucket map grew to %d, want <= maxKeys (8)", n)
	}
}

func TestTieredLimiterPerIPEnforcement(t *testing.T) {
	clk := newFakeClock()
	l := NewTieredLimiter(LimiterConfig{
		PerIP: Rate{Rate: 1, Burst: 2},
		Now:   clk.now,
	})
	ip := Keys{IP: "1.2.3.4"}
	if d := l.Allow(ip); !d.Allowed {
		t.Fatal("first request should pass")
	}
	if d := l.Allow(ip); !d.Allowed {
		t.Fatal("second (burst) request should pass")
	}
	d := l.Allow(ip)
	if d.Allowed {
		t.Fatal("third request should be throttled")
	}
	if d.Tier != TierPerIP {
		t.Fatalf("rejecting tier = %q, want %q", d.Tier, TierPerIP)
	}
	if d.RetryAfter <= 0 {
		t.Fatal("throttled decision should carry a Retry-After")
	}
}

// TestTieredLimiterFairness verifies that one abusive IP being throttled does
// not starve a well-behaved IP sharing a generous global tier.
func TestTieredLimiterFairness(t *testing.T) {
	clk := newFakeClock()
	l := NewTieredLimiter(LimiterConfig{
		Global: Rate{Rate: 1000, Burst: 1000},
		PerIP:  Rate{Rate: 1, Burst: 3},
		Now:    clk.now,
	})

	abuser := Keys{IP: "10.0.0.1"}
	victim := Keys{IP: "10.0.0.2"}

	// The abuser floods and is throttled after its burst.
	abuserThrottled := 0
	for i := 0; i < 50; i++ {
		if d := l.Allow(abuser); !d.Allowed {
			abuserThrottled++
		}
	}
	if abuserThrottled == 0 {
		t.Fatal("abuser was never throttled")
	}

	// The victim, within its own budget, is served regardless of the abuser.
	for i := 0; i < 3; i++ {
		if d := l.Allow(victim); !d.Allowed {
			t.Fatalf("victim request %d unfairly throttled (tier %s)", i, d.Tier)
		}
	}
}

// TestTieredLimiterAllOrNothing verifies that when a later tier rejects, the
// token consumed from an earlier tier is refunded rather than wasted.
func TestTieredLimiterAllOrNothing(t *testing.T) {
	clk := newFakeClock()
	l := NewTieredLimiter(LimiterConfig{
		Global:     Rate{Rate: 1000, Burst: 1000}, // generous, never the bottleneck
		PerAccount: Rate{Rate: 1, Burst: 1},
		Now:        clk.now,
	})
	// Account "acct" has burst 1: first passes, second is rejected by per_account.
	acct := Keys{IP: "1.1.1.1", Account: "acct"}
	if d := l.Allow(acct); !d.Allowed {
		t.Fatal("first account request should pass")
	}
	if d := l.Allow(acct); d.Allowed || d.Tier != TierPerAccount {
		t.Fatalf("second should be rejected by per_account, got %+v", d)
	}

	// The rejected request must not have permanently consumed a global token.
	// Consume the entire global burst with distinct accounts; if the earlier
	// rejection had leaked a global token we would fall short by one.
	admitted := 0
	for i := 0; i < 1000; i++ {
		k := Keys{IP: "2.2.2.2", Account: "distinct-" + string(rune(i))}
		if d := l.Allow(k); d.Allowed {
			admitted++
		}
	}
	// One global token was legitimately spent by the first acct request above,
	// so 999 remain for the distinct accounts.
	if admitted != 999 {
		t.Fatalf("global admitted = %d, want 999 (refund of rejected request failed)", admitted)
	}
}

func TestTieredLimiterDisabledWhenNoTiers(t *testing.T) {
	l := NewTieredLimiter(LimiterConfig{})
	if l.Enabled() {
		t.Fatal("limiter with no tiers should report disabled")
	}
	// A disabled limiter admits everything.
	for i := 0; i < 100; i++ {
		if d := l.Allow(Keys{IP: "x"}); !d.Allowed {
			t.Fatal("disabled limiter should admit all")
		}
	}
}
