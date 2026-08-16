// Package ratelimit provides configurable, tiered request rate limiting and a
// bounded in-flight concurrency guard for the public-facing PKI endpoints
// (ACME, OCSP, CRL, and SCEP/EST enrollment).
//
// The limiter is a lazily-refilled token bucket — the standard mechanism that
// approximates a sliding window while permitting a configurable short burst.
// Requests are metered independently across three tiers (global, per-IP, and
// per-account); a request must obtain a token from every applicable tier to
// proceed, and any tier that rejects it produces a 429 with a Retry-After hint.
// A separate concurrency guard (see concurrency.go) caps how many requests may
// be in flight against the HSM-backed session pool at once, shedding excess
// load fast instead of letting goroutines pile up behind the pool.
//
// The implementation is dependency-free and mirrors the from-scratch approach
// the rest of the enterprise stack takes (metrics, RBAC, ACME). All exported
// types are safe for concurrent use.
package ratelimit

import (
	"math"
	"sort"
	"sync"
	"time"
)

// tokenBucket is a single lazily-refilled token bucket. It holds up to burst
// tokens and refills at rate tokens per second. It carries no timer: tokens are
// recomputed from the elapsed wall-clock time on each access, so an idle bucket
// costs nothing.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64   // currently available tokens (0..burst)
	last   time.Time // when tokens was last recomputed
	seen   time.Time // last access, for idle eviction
	rate   float64   // tokens added per second
	burst  float64   // maximum tokens (bucket capacity)
}

func newTokenBucket(rate, burst float64, now time.Time) *tokenBucket {
	return &tokenBucket{tokens: burst, last: now, seen: now, rate: rate, burst: burst}
}

// advance credits the bucket for the time elapsed since the last access. The
// caller must hold b.mu.
func (b *tokenBucket) advance(now time.Time) {
	if now.After(b.last) {
		b.tokens = math.Min(b.burst, b.tokens+now.Sub(b.last).Seconds()*b.rate)
		b.last = now
	}
	b.seen = now
}

// take attempts to consume one token. It returns ok=true when a token was
// available; otherwise ok=false and retryAfter is the estimated wait until one
// token has accrued.
func (b *tokenBucket) take(now time.Time) (ok bool, retryAfter time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.advance(now)
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	if b.rate <= 0 {
		// A zero-rate bucket never refills; report a long, bounded wait.
		return false, time.Hour
	}
	deficit := 1 - b.tokens
	ra := time.Duration(deficit / b.rate * float64(time.Second))
	if ra < 0 {
		ra = 0
	}
	return false, ra
}

// retune adjusts a live bucket's rate and capacity, used when an operator
// changes a tenant's rate-limit override: the next request simply carries the
// new numbers and the existing bucket adapts without losing its state. Grown
// capacity is credited immediately (raising a tenant's burst takes effect on
// the very next request); shrunk capacity clamps the balance.
func (b *tokenBucket) retune(rate, burst float64, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.rate == rate && b.burst == burst {
		return
	}
	b.advance(now)
	if grow := burst - b.burst; grow > 0 {
		b.tokens += grow
	}
	b.rate = rate
	b.burst = burst
	if b.tokens > burst {
		b.tokens = burst
	}
}

// refund returns one previously-taken token, capped at the bucket capacity.
// It is used to keep multi-tier admission all-or-nothing: when a later tier
// rejects a request, the tokens already consumed from earlier tiers are handed
// back so they are not wasted on a request that never proceeds.
func (b *tokenBucket) refund(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.advance(now)
	b.tokens = math.Min(b.burst, b.tokens+1)
}

// idleSince reports whether the bucket has been fully replenished and untouched
// since before cutoff. A full bucket is behaviorally identical to a freshly
// created one, so it is safe to evict.
func (b *tokenBucket) idleSince(now, cutoff time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.advance(now)
	return b.tokens >= b.burst && b.seen.Before(cutoff)
}

// keyedBuckets maintains one token bucket per key (e.g. per client IP or per
// account), all sharing the same rate and burst. The map is bounded: when it
// reaches maxKeys a sweep reclaims idle (fully replenished) buckets, falling
// back to evicting the least-recently-seen entries so an adversary spraying
// unique keys cannot exhaust memory.
type keyedBuckets struct {
	now     func() time.Time
	rate    float64
	burst   float64
	maxKeys int
	idleTTL time.Duration

	mu      sync.Mutex
	buckets map[string]*tokenBucket
}

func newKeyedBuckets(rate, burst float64, maxKeys int, idleTTL time.Duration, now func() time.Time) *keyedBuckets {
	if maxKeys <= 0 {
		maxKeys = 1
	}
	return &keyedBuckets{
		now:     now,
		rate:    rate,
		burst:   burst,
		maxKeys: maxKeys,
		idleTTL: idleTTL,
		buckets: make(map[string]*tokenBucket),
	}
}

// bucketFor returns the bucket for key, creating it (and possibly evicting
// idle/old buckets to stay within maxKeys) if it does not exist.
func (k *keyedBuckets) bucketFor(key string, now time.Time) *tokenBucket {
	k.mu.Lock()
	defer k.mu.Unlock()
	if b, ok := k.buckets[key]; ok {
		return b
	}
	if len(k.buckets) >= k.maxKeys {
		k.evictLocked(now)
	}
	b := newTokenBucket(k.rate, k.burst, now)
	k.buckets[key] = b
	return b
}

// evictLocked reclaims capacity. It first drops buckets that have been idle
// (fully refilled) longer than idleTTL; if that does not free enough room it
// removes the least-recently-seen quarter of the map. The caller holds k.mu.
func (k *keyedBuckets) evictLocked(now time.Time) {
	cutoff := now.Add(-k.idleTTL)
	for key, b := range k.buckets {
		if b.idleSince(now, cutoff) {
			delete(k.buckets, key)
		}
	}
	if len(k.buckets) < k.maxKeys {
		return
	}
	// Still full of active buckets: evict the oldest quarter by last-seen time.
	type entry struct {
		key  string
		seen time.Time
	}
	entries := make([]entry, 0, len(k.buckets))
	for key, b := range k.buckets {
		b.mu.Lock()
		seen := b.seen
		b.mu.Unlock()
		entries = append(entries, entry{key, seen})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].seen.Before(entries[j].seen) })
	drop := len(entries) / 4
	if drop == 0 {
		drop = 1
	}
	for i := 0; i < drop; i++ {
		delete(k.buckets, entries[i].key)
	}
}

// bucketForRate returns the bucket for key like bucketFor, but with an
// explicit per-key rate: the bucket is created with (rate, burst) and an
// existing bucket is retuned if its configured numbers changed. It backs the
// per-tenant tier, where each tenant may carry its own override.
func (k *keyedBuckets) bucketForRate(key string, rate, burst float64, now time.Time) *tokenBucket {
	k.mu.Lock()
	defer k.mu.Unlock()
	if b, ok := k.buckets[key]; ok {
		b.retune(rate, burst, now)
		return b
	}
	if len(k.buckets) >= k.maxKeys {
		k.evictLocked(now)
	}
	b := newTokenBucket(rate, burst, now)
	k.buckets[key] = b
	return b
}

// take consumes a token from the bucket for key, creating the bucket on first
// use. It is a convenience over bucketFor(...).take(...).
func (k *keyedBuckets) take(key string) (bool, time.Duration) {
	now := k.now()
	return k.bucketFor(key, now).take(now)
}

// len reports the number of live buckets (for tests and introspection).
func (k *keyedBuckets) len() int {
	k.mu.Lock()
	defer k.mu.Unlock()
	return len(k.buckets)
}
