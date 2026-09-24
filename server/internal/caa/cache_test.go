package caa

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// The cache is installed process-wide through ca.SetCAAResolver, which takes a
// Resolver, so it has to keep satisfying that interface.
var _ Resolver = (*CachingResolver)(nil)

var errUpstream = errors.New("caa test: upstream failure")

// countingResolver is an upstream Resolver that records how many times each name
// was actually resolved, so a test can prove what the cache did and did not
// reuse. It is safe for concurrent use.
type countingResolver struct {
	mu         sync.Mutex
	caaCalls   map[string]int
	cnameCalls map[string]int

	caa   map[string][]Record
	cname map[string]string

	// failCAA/failCNAME map a name to the number of consecutive lookups that must
	// fail before it starts answering; a negative count fails every lookup.
	failCAA   map[string]int
	failCNAME map[string]int
}

func newCountingResolver() *countingResolver {
	return &countingResolver{
		caaCalls:   map[string]int{},
		cnameCalls: map[string]int{},
		caa:        map[string][]Record{},
		cname:      map[string]string{},
		failCAA:    map[string]int{},
		failCNAME:  map[string]int{},
	}
}

func (c *countingResolver) LookupCAA(_ context.Context, name string) ([]Record, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.caaCalls[name]++
	if n := c.failCAA[name]; n != 0 {
		if n > 0 {
			c.failCAA[name] = n - 1
		}
		return nil, fmt.Errorf("%w: CAA %s", errUpstream, name)
	}
	return c.caa[name], nil
}

func (c *countingResolver) LookupCNAME(_ context.Context, name string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cnameCalls[name]++
	if n := c.failCNAME[name]; n != 0 {
		if n > 0 {
			c.failCNAME[name] = n - 1
		}
		return "", fmt.Errorf("%w: CNAME %s", errUpstream, name)
	}
	return c.cname[name], nil
}

func (c *countingResolver) counts(name string) (caaCalls, cnameCalls int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.caaCalls[name], c.cnameCalls[name]
}

// setCAA replaces the upstream RRset for a name. Used mid-test to prove whether
// a lookup was served from the cache or refetched.
func (c *countingResolver) setCAA(name string, recs ...Record) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.caa[name] = recs
}

func (c *countingResolver) setCNAME(name, target string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cname[name] = target
}

// mustLookupCAA fails the test on a lookup error.
func mustLookupCAA(t *testing.T, r Resolver, name string) []Record {
	t.Helper()
	recs, err := r.LookupCAA(context.Background(), name)
	if err != nil {
		t.Fatalf("LookupCAA(%q): %v", name, err)
	}
	return recs
}

// TestCachingResolverServesRepeatedLookupsFromCache proves a second lookup of
// the same name does not reach the network. The upstream answer is swapped
// between the calls, so a cache that quietly refetched would return the new
// value and fail here.
func TestCachingResolverServesRepeatedLookupsFromCache(t *testing.T) {
	up := newCountingResolver()
	up.setCAA("example.com", issue(caID))
	up.setCNAME("www.example.com", "web.example.net")
	c := NewCachingResolver(up, time.Minute)

	first := mustLookupCAA(t, c, "example.com")
	target, err := c.LookupCNAME(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("LookupCNAME: %v", err)
	}

	up.setCAA("example.com", issue("other.example.net"))
	up.setCNAME("www.example.com", "elsewhere.example.net")

	second := mustLookupCAA(t, c, "example.com")
	target2, err := c.LookupCNAME(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("LookupCNAME: %v", err)
	}

	if len(first) != 1 || len(second) != 1 || first[0] != second[0] {
		t.Fatalf("cached CAA answer changed: %+v then %+v", first, second)
	}
	if target != "web.example.net" || target2 != target {
		t.Fatalf("cached CNAME answer changed: %q then %q", target, target2)
	}
	if caaCalls, _ := up.counts("example.com"); caaCalls != 1 {
		t.Fatalf("upstream CAA lookups = %d, want 1", caaCalls)
	}
	if _, cnameCalls := up.counts("www.example.com"); cnameCalls != 1 {
		t.Fatalf("upstream CNAME lookups = %d, want 1", cnameCalls)
	}
}

// TestCachingResolverCachesNegativeAnswers proves NODATA/NXDOMAIN (an empty
// answer) is reused. The tree-climbing search asks for every ancestor of every
// SAN, so almost every lookup it makes is negative; not caching those would put
// a DNS round trip on the issuance path for each one.
func TestCachingResolverCachesNegativeAnswers(t *testing.T) {
	up := newCountingResolver()
	c := NewCachingResolver(up, time.Minute)

	for i := 0; i < 3; i++ {
		if recs := mustLookupCAA(t, c, "absent.example.com"); len(recs) != 0 {
			t.Fatalf("expected no records, got %+v", recs)
		}
		target, err := c.LookupCNAME(context.Background(), "absent.example.com")
		if err != nil {
			t.Fatalf("LookupCNAME: %v", err)
		}
		if target != "" {
			t.Fatalf("expected no alias target, got %q", target)
		}
	}
	caaCalls, cnameCalls := up.counts("absent.example.com")
	if caaCalls != 1 || cnameCalls != 1 {
		t.Fatalf("upstream lookups = (caa %d, cname %d), want (1, 1)", caaCalls, cnameCalls)
	}
}

// TestCachingResolverDoesNotCacheFailures proves a transient failure is retried
// rather than pinned. Caching an error as a success would be worse than a slow
// retry: an empty RRset reads as "no CAA policy governs this name", i.e. it
// would turn a lookup failure into an authorization.
func TestCachingResolverDoesNotCacheFailures(t *testing.T) {
	up := newCountingResolver()
	up.setCAA("example.com", issue(caID))
	up.setCNAME("www.example.com", "web.example.net")
	up.failCAA["example.com"] = 2 // fail twice, then answer
	up.failCNAME["www.example.com"] = 1
	c := NewCachingResolver(up, time.Minute)

	for attempt := 1; attempt <= 2; attempt++ {
		recs, err := c.LookupCAA(context.Background(), "example.com")
		if !errors.Is(err, errUpstream) {
			t.Fatalf("attempt %d: error = %v, want the upstream failure", attempt, err)
		}
		if recs != nil {
			t.Fatalf("attempt %d: expected no records with the error, got %+v", attempt, recs)
		}
	}
	if recs := mustLookupCAA(t, c, "example.com"); len(recs) != 1 || recs[0] != issue(caID) {
		t.Fatalf("after the failures the real RRset must be resolved, got %+v", recs)
	}
	if caaCalls, _ := up.counts("example.com"); caaCalls != 3 {
		t.Fatalf("upstream CAA lookups = %d, want 3 (two failures plus the retry)", caaCalls)
	}

	if _, err := c.LookupCNAME(context.Background(), "www.example.com"); !errors.Is(err, errUpstream) {
		t.Fatalf("CNAME error = %v, want the upstream failure", err)
	}
	target, err := c.LookupCNAME(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("LookupCNAME after the failure: %v", err)
	}
	if target != "web.example.net" {
		t.Fatalf("alias target = %q, want web.example.net", target)
	}
	if _, cnameCalls := up.counts("www.example.com"); cnameCalls != 2 {
		t.Fatalf("upstream CNAME lookups = %d, want 2", cnameCalls)
	}

	// And the successful answers that followed the failures are cached.
	_ = mustLookupCAA(t, c, "example.com")
	if caaCalls, _ := up.counts("example.com"); caaCalls != 3 {
		t.Fatalf("the post-failure answer was not cached: %d upstream lookups", caaCalls)
	}
}

// TestCachingResolverRefetchesExpiredEntry proves a stale entry is replaced
// rather than served: a domain owner who publishes a CAA record that forbids
// this CA must not be shadowed by an older permissive answer forever.
func TestCachingResolverRefetchesExpiredEntry(t *testing.T) {
	up := newCountingResolver()
	up.setCAA("example.com", issue(caID))
	up.setCNAME("www.example.com", "web.example.net")
	c := NewCachingResolver(up, time.Hour)

	_ = mustLookupCAA(t, c, "example.com")
	if _, err := c.LookupCNAME(context.Background(), "www.example.com"); err != nil {
		t.Fatalf("LookupCNAME: %v", err)
	}

	// Age both entries out without waiting for the clock.
	c.mu.Lock()
	c.caa["example.com"] = caaEntry{records: c.caa["example.com"].records, expires: time.Now().Add(-time.Second)}
	c.cname["www.example.com"] = cnameEntry{target: c.cname["www.example.com"].target, expires: time.Now().Add(-time.Second)}
	c.mu.Unlock()

	up.setCAA("example.com", issue("other.example.net"))
	up.setCNAME("www.example.com", "elsewhere.example.net")

	recs := mustLookupCAA(t, c, "example.com")
	if len(recs) != 1 || recs[0] != issue("other.example.net") {
		t.Fatalf("expired entry was served instead of refetched: %+v", recs)
	}
	target, err := c.LookupCNAME(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("LookupCNAME: %v", err)
	}
	if target != "elsewhere.example.net" {
		t.Fatalf("expired alias was served instead of refetched: %q", target)
	}
	if caaCalls, _ := up.counts("example.com"); caaCalls != 2 {
		t.Fatalf("upstream CAA lookups = %d, want 2", caaCalls)
	}
	if _, cnameCalls := up.counts("www.example.com"); cnameCalls != 2 {
		t.Fatalf("upstream CNAME lookups = %d, want 2", cnameCalls)
	}

	// The refetched value must itself be cached with a fresh deadline.
	up.setCAA("example.com", issue("third.example.net"))
	if recs := mustLookupCAA(t, c, "example.com"); recs[0] != issue("other.example.net") {
		t.Fatalf("the refetched entry was not cached: %+v", recs)
	}
}

// TestCachingResolverAppliesConfiguredTTL proves the configured TTL really
// bounds reuse on the wall clock, not just when an entry is aged out by hand.
func TestCachingResolverAppliesConfiguredTTL(t *testing.T) {
	up := newCountingResolver()
	up.setCAA("example.com", issue(caID))
	c := NewCachingResolver(up, 20*time.Millisecond)

	_ = mustLookupCAA(t, c, "example.com")
	_ = mustLookupCAA(t, c, "example.com") // still fresh
	if caaCalls, _ := up.counts("example.com"); caaCalls != 1 {
		t.Fatalf("upstream CAA lookups before expiry = %d, want 1", caaCalls)
	}

	time.Sleep(60 * time.Millisecond)
	_ = mustLookupCAA(t, c, "example.com")
	if caaCalls, _ := up.counts("example.com"); caaCalls != 2 {
		t.Fatalf("upstream CAA lookups after expiry = %d, want 2", caaCalls)
	}
}

// TestCachingResolverDefaultTTL proves a non-positive TTL is replaced by
// DefaultCacheTTL. Storing entries with a zero or negative TTL would make every
// one of them expire on arrival, silently disabling the cache and putting a DNS
// round trip back on every issuance.
func TestCachingResolverDefaultTTL(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Minute} {
		t.Run(ttl.String(), func(t *testing.T) {
			up := newCountingResolver()
			up.setCAA("example.com", issue(caID))
			c := NewCachingResolver(up, ttl)
			if c.ttl != DefaultCacheTTL {
				t.Fatalf("ttl = %v, want %v", c.ttl, DefaultCacheTTL)
			}
			_ = mustLookupCAA(t, c, "example.com")
			_ = mustLookupCAA(t, c, "example.com")
			if caaCalls, _ := up.counts("example.com"); caaCalls != 1 {
				t.Fatalf("upstream CAA lookups = %d, want 1", caaCalls)
			}
		})
	}
}

// TestCachingResolverKeysByQueryType proves the CAA and CNAME caches are
// separate: a cached CAA answer for a name must not satisfy a CNAME lookup of
// the same name (which would report the wrong alias target and redirect the
// whole tree climb).
func TestCachingResolverKeysByQueryType(t *testing.T) {
	up := newCountingResolver()
	up.setCAA("example.com", issue(caID))
	up.setCNAME("example.com", "canonical.example.net")
	c := NewCachingResolver(up, time.Minute)

	if recs := mustLookupCAA(t, c, "example.com"); len(recs) != 1 {
		t.Fatalf("expected the CAA RRset, got %+v", recs)
	}
	target, err := c.LookupCNAME(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("LookupCNAME: %v", err)
	}
	if target != "canonical.example.net" {
		t.Fatalf("alias target = %q, want canonical.example.net", target)
	}
	caaCalls, cnameCalls := up.counts("example.com")
	if caaCalls != 1 || cnameCalls != 1 {
		t.Fatalf("upstream lookups = (caa %d, cname %d), want (1, 1)", caaCalls, cnameCalls)
	}
}

// TestCachingResolverDedupesAncestorLookups exercises the cache where it
// actually sits: under the tree-climbing search. Several SANs under one zone
// must resolve the shared ancestor once.
func TestCachingResolverDedupesAncestorLookups(t *testing.T) {
	up := newCountingResolver()
	up.setCAA("example.com", issue(caID))
	c := NewCachingResolver(up, time.Minute)

	res := Policy{Identifier: caID}.Check(context.Background(), c,
		[]string{"a.example.com", "b.example.com", "c.example.com"}, RequestContext{})
	if !res.OK() {
		t.Fatalf("expected issuance to be permitted: %s", res.Summary())
	}
	if caaCalls, _ := up.counts("example.com"); caaCalls != 1 {
		t.Fatalf("the shared ancestor was resolved %d times, want 1", caaCalls)
	}
	for _, n := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		if caaCalls, _ := up.counts(n); caaCalls != 1 {
			t.Fatalf("%s was resolved %d times, want 1", n, caaCalls)
		}
	}
}

// TestCachingResolverConcurrentAccess hammers the cache from several goroutines
// so -race exercises its locking, and pins the resulting call counts: a cached
// name may be resolved at most once per goroutine (the benign start-up stampede
// before the first entry is stored) while a failing name must be retried every
// single time.
func TestCachingResolverConcurrentAccess(t *testing.T) {
	const (
		goroutines = 8
		iterations = 40
	)
	cached := []string{"one.example.com", "two.example.com", "three.example.com"}
	const broken = "broken.example.com"

	up := newCountingResolver()
	for i, n := range cached {
		up.setCAA(n, issue(caID), Record{Tag: TagIodef, Value: fmt.Sprintf("mailto:%d@example.com", i)})
		up.setCNAME(n, "target"+n)
	}
	up.failCAA[broken] = -1 // always fails
	c := NewCachingResolver(up, time.Minute)

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*iterations*2)
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				name := cached[(g+i)%len(cached)]
				recs, err := c.LookupCAA(context.Background(), name)
				switch {
				case err != nil:
					errCh <- fmt.Errorf("LookupCAA(%q): %w", name, err)
				case len(recs) != 2 || recs[0] != issue(caID):
					errCh <- fmt.Errorf("LookupCAA(%q) = %+v", name, recs)
				}
				target, err := c.LookupCNAME(context.Background(), name)
				switch {
				case err != nil:
					errCh <- fmt.Errorf("LookupCNAME(%q): %w", name, err)
				case target != "target"+name:
					errCh <- fmt.Errorf("LookupCNAME(%q) = %q", name, target)
				}
				if _, err := c.LookupCAA(context.Background(), broken); !errors.Is(err, errUpstream) {
					errCh <- fmt.Errorf("LookupCAA(%q) error = %v, want the upstream failure", broken, err)
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent lookup: %v", err)
	}

	for _, n := range cached {
		caaCalls, cnameCalls := up.counts(n)
		if caaCalls < 1 || caaCalls > goroutines {
			t.Fatalf("%s: %d upstream CAA lookups, want between 1 and %d", n, caaCalls, goroutines)
		}
		if cnameCalls < 1 || cnameCalls > goroutines {
			t.Fatalf("%s: %d upstream CNAME lookups, want between 1 and %d", n, cnameCalls, goroutines)
		}
	}
	if caaCalls, _ := up.counts(broken); caaCalls != goroutines*iterations {
		t.Fatalf("%s: %d upstream lookups, want %d (failures are never cached)", broken, caaCalls, goroutines*iterations)
	}

	// Everything is cached now, so one more pass must not reach upstream at all.
	before := map[string]int{}
	for _, n := range cached {
		before[n], _ = up.counts(n)
	}
	for _, n := range cached {
		_ = mustLookupCAA(t, c, n)
		if after, _ := up.counts(n); after != before[n] {
			t.Fatalf("%s: a post-stampede lookup went upstream (%d -> %d)", n, before[n], after)
		}
	}
}
