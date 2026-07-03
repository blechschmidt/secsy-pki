package ca

import (
	"sync"
	"time"
)

// OCSPCache is a small, bounded, TTL-based cache of signed OCSP responses keyed
// by (CA, certificate serial). It exists because answering an OCSP request
// otherwise requires an on-HSM signing operation for every request, which
// serializes OCSP serving behind the token. Because an OCSP response is valid
// until its NextUpdate (see defaultOCSPValidity), it is safe to reuse a signed
// response for a bounded window; the cache TTL controls that window.
//
// Entries arrive on two paths: demand-filled by the responder after answering a
// request (Put, bounded by the TTL), and pre-signed in batches by the OCSP
// presigner (PutUntil, bounded by each response's own NextUpdate). Pre-signed
// entries are what keep the public responder off the HSM entirely — including
// across an HSM outage, for as long as the responses remain within validity.
//
// Correctness: a certificate's status only changes when it is revoked, so the
// serving layer invalidates the affected entry on revocation (see
// API.RevokeCertificate). The TTL additionally bounds staleness for any status
// change that does not flow through the invalidation path. A TTL of zero
// disables caching entirely (every request is answered freshly on the HSM).
//
// The cache stores the fully signed DER response, so a hit avoids both the
// database lookups and the HSM signature. It is safe for concurrent use.
type OCSPCache struct {
	ttl time.Duration

	mu      sync.Mutex
	maxSize int
	entries map[string]ocspCacheEntry

	// now is injectable for tests; nil means time.Now.
	now func() time.Time
}

type ocspCacheEntry struct {
	der       []byte
	expiresAt time.Time
	// presigned marks an entry filled by the batch presigner rather than on
	// demand. Such entries are the last to be evicted under memory pressure:
	// dropping one turns a guaranteed HSM-free response back into an on-HSM
	// signature, which is exactly what pre-signing exists to avoid.
	presigned bool
}

// DefaultOCSPCacheMaxEntries bounds the cache so it cannot grow without limit
// under a flood of distinct serials (a cheap defense against memory exhaustion
// from adversarial or scanning OCSP traffic). The presigner raises the bound
// (EnsureCapacity) to fit the real certificate population when it is larger.
const DefaultOCSPCacheMaxEntries = 16384

// maxOCSPCacheEntries is the absolute ceiling EnsureCapacity will grow the
// cache to, a backstop against a pathological issued-certificate count.
const maxOCSPCacheEntries = 1 << 21 // ~2M entries

// NewOCSPCache constructs a cache with the given TTL. A non-positive ttl yields
// a disabled cache (all Get calls miss and Put is a no-op), so callers can wire
// it unconditionally and let configuration decide whether it is active.
func NewOCSPCache(ttl time.Duration) *OCSPCache {
	return &OCSPCache{
		ttl:     ttl,
		maxSize: DefaultOCSPCacheMaxEntries,
		entries: make(map[string]ocspCacheEntry),
	}
}

// Enabled reports whether the cache is active (a positive TTL was configured).
func (c *OCSPCache) Enabled() bool { return c != nil && c.ttl > 0 }

func (c *OCSPCache) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// key composes the cache key from the CA id and certificate serial.
func ocspCacheKey(caID, serial string) string { return caID + "\x00" + serial }

// Get returns the cached signed response for (caID, serial) if present and not
// expired.
func (c *OCSPCache) Get(caID, serial string) ([]byte, bool) {
	if !c.Enabled() {
		return nil, false
	}
	key := ocspCacheKey(caID, serial)
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if c.clock().After(e.expiresAt) {
		delete(c.entries, key)
		return nil, false
	}
	return e.der, true
}

// Put stores a signed response for (caID, serial), copying the bytes so a caller
// may reuse its buffer. The entry lives for the cache TTL.
func (c *OCSPCache) Put(caID, serial string, der []byte) {
	if !c.Enabled() || len(der) == 0 {
		return
	}
	c.put(caID, serial, der, c.clock().Add(c.ttl), false)
}

// PutUntil stores a pre-signed response for (caID, serial) that remains
// servable until expiresAt — its own NextUpdate rather than the demand-fill
// TTL. This is what lets pre-signed responses outlive an HSM outage: the entry
// is valid for exactly as long as the signed response itself is, and the
// presigner replaces it well before then in normal operation.
func (c *OCSPCache) PutUntil(caID, serial string, der []byte, expiresAt time.Time) {
	if !c.Enabled() || len(der) == 0 || !c.clock().Before(expiresAt) {
		return
	}
	c.put(caID, serial, der, expiresAt, true)
}

func (c *OCSPCache) put(caID, serial string, der []byte, expiresAt time.Time, presigned bool) {
	cp := make([]byte, len(der))
	copy(cp, der)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		c.evictLocked()
	}
	c.entries[ocspCacheKey(caID, serial)] = ocspCacheEntry{
		der:       cp,
		expiresAt: expiresAt,
		presigned: presigned,
	}
}

// evictLocked frees room when the cache is full, cheapest casualties first:
// expired entries, then demand-filled entries (they are regenerated on the next
// request anyway), and only as a last resort — when the cache is somehow full
// of live pre-signed entries — everything. Pre-signed entries survive a flood
// of distinct adversarial serials, which would otherwise wipe exactly the
// entries that keep the responder HSM-free. Called with c.mu held.
func (c *OCSPCache) evictLocked() {
	now := c.clock()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < c.maxSize {
		return
	}
	for k, e := range c.entries {
		if !e.presigned {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < c.maxSize {
		return
	}
	c.entries = make(map[string]ocspCacheEntry, c.maxSize)
}

// EnsureCapacity grows the cache bound to hold at least n entries (it never
// shrinks, and never exceeds an absolute backstop). The presigner calls it with
// the size of each batch plus headroom so a deployment with more issued
// certificates than DefaultOCSPCacheMaxEntries does not thrash its own
// pre-signed set.
func (c *OCSPCache) EnsureCapacity(n int) {
	if c == nil || n <= 0 {
		return
	}
	if n > maxOCSPCacheEntries {
		n = maxOCSPCacheEntries
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if n > c.maxSize {
		c.maxSize = n
	}
}

// PresignedCount returns how many unexpired pre-signed entries the cache
// currently holds, for the presign staleness/coverage gauges.
func (c *OCSPCache) PresignedCount() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	n := 0
	for _, e := range c.entries {
		if e.presigned && !now.After(e.expiresAt) {
			n++
		}
	}
	return n
}

// Invalidate removes any cached response for (caID, serial). It is called when a
// certificate's status changes (revocation) so the next request re-generates a
// fresh, correct response instead of serving a stale "good".
func (c *OCSPCache) Invalidate(caID, serial string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, ocspCacheKey(caID, serial))
}
