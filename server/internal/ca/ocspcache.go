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
// Correctness: a certificate's status only changes when it is revoked, so the
// serving layer invalidates the affected entry on revocation (see
// API.RevokeCertificate). The TTL additionally bounds staleness for any status
// change that does not flow through the invalidation path. A TTL of zero
// disables caching entirely (every request is answered freshly on the HSM).
//
// The cache stores the fully signed DER response, so a hit avoids both the
// database lookups and the HSM signature. It is safe for concurrent use.
type OCSPCache struct {
	ttl     time.Duration
	maxSize int

	mu      sync.Mutex
	entries map[string]ocspCacheEntry

	// now is injectable for tests; nil means time.Now.
	now func() time.Time
}

type ocspCacheEntry struct {
	der       []byte
	expiresAt time.Time
}

// DefaultOCSPCacheMaxEntries bounds the cache so it cannot grow without limit
// under a flood of distinct serials (a cheap defense against memory exhaustion
// from adversarial or scanning OCSP traffic). When exceeded, the whole cache is
// dropped rather than tracking per-entry LRU — OCSP entries are cheap to
// recompute and this keeps the structure simple and allocation-free on hits.
const DefaultOCSPCacheMaxEntries = 16384

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
// may reuse its buffer. It bounds the cache size, clearing it wholesale if the
// limit is reached.
func (c *OCSPCache) Put(caID, serial string, der []byte) {
	if !c.Enabled() || len(der) == 0 {
		return
	}
	cp := make([]byte, len(der))
	copy(cp, der)

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		// Simple, bounded eviction: drop everything. Entries are cheap to
		// regenerate and this avoids per-entry bookkeeping on the hot path.
		c.entries = make(map[string]ocspCacheEntry, c.maxSize)
	}
	c.entries[ocspCacheKey(caID, serial)] = ocspCacheEntry{
		der:       cp,
		expiresAt: c.clock().Add(c.ttl),
	}
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
