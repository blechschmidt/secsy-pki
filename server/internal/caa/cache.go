package caa

import (
	"context"
	"sync"
	"time"
)

// DefaultCacheTTL bounds how long a resolved CAA or CNAME answer is reused. DNS
// answers carry their own TTL; the cache uses the smaller of that and this cap
// (with a short floor) so a very long record TTL cannot pin a stale policy for
// too long, and a zero/short TTL still gets minimal reuse under bursty load.
const (
	DefaultCacheTTL = 5 * time.Minute
	minCacheTTL     = 30 * time.Second
)

// CachingResolver wraps a Resolver with a small in-memory TTL cache keyed by
// (query type, name). Successful lookups — including negative NODATA/NXDOMAIN
// answers, which are represented as empty results — are cached; transient
// errors are never cached, so a lookup failure is always retried. It is safe for
// concurrent use.
type CachingResolver struct {
	inner Resolver
	ttl   time.Duration

	mu    sync.Mutex
	caa   map[string]caaEntry
	cname map[string]cnameEntry
}

type caaEntry struct {
	records []Record
	expires time.Time
}

type cnameEntry struct {
	target  string
	expires time.Time
}

// NewCachingResolver wraps inner with a TTL cache. A non-positive ttl uses
// DefaultCacheTTL.
func NewCachingResolver(inner Resolver, ttl time.Duration) *CachingResolver {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &CachingResolver{
		inner: inner,
		ttl:   ttl,
		caa:   make(map[string]caaEntry),
		cname: make(map[string]cnameEntry),
	}
}

// LookupCAA returns a cached CAA RRset when fresh, otherwise resolves and caches.
func (c *CachingResolver) LookupCAA(ctx context.Context, name string) ([]Record, error) {
	now := time.Now()
	c.mu.Lock()
	if e, ok := c.caa[name]; ok && now.Before(e.expires) {
		recs := e.records
		c.mu.Unlock()
		return recs, nil
	}
	c.mu.Unlock()

	recs, err := c.inner.LookupCAA(ctx, name)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.caa[name] = caaEntry{records: recs, expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return recs, nil
}

// LookupCNAME returns a cached alias target when fresh, otherwise resolves and
// caches.
func (c *CachingResolver) LookupCNAME(ctx context.Context, name string) (string, error) {
	now := time.Now()
	c.mu.Lock()
	if e, ok := c.cname[name]; ok && now.Before(e.expires) {
		t := e.target
		c.mu.Unlock()
		return t, nil
	}
	c.mu.Unlock()

	target, err := c.inner.LookupCNAME(ctx, name)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.cname[name] = cnameEntry{target: target, expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return target, nil
}
