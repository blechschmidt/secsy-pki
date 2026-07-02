package ca

import (
	"sync"
	"testing"
	"time"
)

// fakeClock is a manually-advanced clock for deterministic TTL testing.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
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

func newTestCache(ttl time.Duration) (*OCSPCache, *fakeClock) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	c := NewOCSPCache(ttl)
	c.now = clk.now
	return c, clk
}

func TestOCSPCacheHitThenExpiry(t *testing.T) {
	c, clk := newTestCache(time.Minute)
	resp := []byte("signed-ocsp-response")

	if _, ok := c.Get("ca1", "42"); ok {
		t.Fatal("expected miss on empty cache")
	}
	c.Put("ca1", "42", resp)

	got, ok := c.Get("ca1", "42")
	if !ok {
		t.Fatal("expected hit after Put")
	}
	if string(got) != string(resp) {
		t.Fatalf("got %q, want %q", got, resp)
	}

	// Just before expiry: still a hit.
	clk.advance(59 * time.Second)
	if _, ok := c.Get("ca1", "42"); !ok {
		t.Fatal("expected hit just before TTL")
	}
	// After expiry: miss.
	clk.advance(2 * time.Second)
	if _, ok := c.Get("ca1", "42"); ok {
		t.Fatal("expected miss after TTL elapsed")
	}
}

func TestOCSPCacheKeyedByCAAndSerial(t *testing.T) {
	c, _ := newTestCache(time.Minute)
	c.Put("ca1", "1", []byte("a"))
	c.Put("ca2", "1", []byte("b"))
	c.Put("ca1", "2", []byte("c"))

	for _, tc := range []struct{ ca, serial, want string }{
		{"ca1", "1", "a"},
		{"ca2", "1", "b"},
		{"ca1", "2", "c"},
	} {
		got, ok := c.Get(tc.ca, tc.serial)
		if !ok || string(got) != tc.want {
			t.Errorf("Get(%q,%q) = %q,%v; want %q", tc.ca, tc.serial, got, ok, tc.want)
		}
	}
	if _, ok := c.Get("ca2", "2"); ok {
		t.Error("expected miss for uncached (ca2,2)")
	}
}

func TestOCSPCacheInvalidate(t *testing.T) {
	c, _ := newTestCache(time.Minute)
	c.Put("ca1", "7", []byte("good"))
	if _, ok := c.Get("ca1", "7"); !ok {
		t.Fatal("expected hit before invalidate")
	}
	c.Invalidate("ca1", "7")
	if _, ok := c.Get("ca1", "7"); ok {
		t.Fatal("expected miss after invalidate (revocation must not serve stale good)")
	}
}

func TestOCSPCacheDisabled(t *testing.T) {
	c, _ := newTestCache(0) // non-positive TTL => disabled
	if c.Enabled() {
		t.Fatal("cache with zero TTL must be disabled")
	}
	c.Put("ca1", "1", []byte("x"))
	if _, ok := c.Get("ca1", "1"); ok {
		t.Fatal("disabled cache must never hit")
	}
	// Invalidate on a disabled cache must not panic.
	c.Invalidate("ca1", "1")
}

func TestOCSPCacheBoundedEviction(t *testing.T) {
	c, _ := newTestCache(time.Hour)
	c.maxSize = 4
	for i := 0; i < 4; i++ {
		c.Put("ca", string(rune('a'+i)), []byte{byte(i)})
	}
	// Inserting beyond the bound clears the cache wholesale, so a subsequent
	// lookup of an older key misses but the cache keeps functioning.
	c.Put("ca", "overflow", []byte("z"))
	got, ok := c.Get("ca", "overflow")
	if !ok || string(got) != "z" {
		t.Fatalf("expected the post-eviction entry to be present, got %q,%v", got, ok)
	}
	if c.entriesLen() > c.maxSize {
		t.Fatalf("cache exceeded max size: %d > %d", c.entriesLen(), c.maxSize)
	}
}

// entriesLen is a test-only helper reporting the current entry count.
func (c *OCSPCache) entriesLen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
