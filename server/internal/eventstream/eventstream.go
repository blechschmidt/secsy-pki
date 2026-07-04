// Package eventstream provides a lightweight, in-process fan-out of the
// tamper-evident audit event log to live subscribers, backing the operator
// Server-Sent Events (SSE) feed (Task 90).
//
// It is deliberately distinct from the SIEM export (internal/siem): that path
// targets machines with durable, at-least-once delivery to external collectors;
// this path targets humans watching the console in real time, so it favors
// liveness over completeness. A subscriber that cannot keep up drops its oldest
// undelivered events (and is told it lagged) rather than ever blocking the
// writer that appended the event — the audit-append hot path must never stall
// on a slow reader.
//
// The Publisher is fed from the single audit-append chokepoint
// (database.DB.AppendEvent) via a hook, so every event that lands in the
// hash-chained log — from HTTP handlers, background jobs, or protocol servers —
// is fanned out identically.
package eventstream

import (
	"sync"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/metrics"
)

// DefaultBufferSize is the per-subscriber ring-buffer capacity: the number of
// undelivered events a single slow SSE connection may queue before the oldest
// start being dropped. It is generous enough that a briefly-stalled browser
// (tab switch, GC pause) loses nothing, but bounded so one wedged connection
// can never grow memory without limit.
const DefaultBufferSize = 256

// Filter selects which events a subscriber receives. It mirrors the tenant
// scoping of the audit-listing API: a platform operator sees every tenant
// (AllTenants), while a tenant-scoped operator sees only the named tenants.
// Platform-level events (with an empty Tenant) are visible only to AllTenants
// subscribers, exactly as the listing endpoint confines a tenant auditor to
// rows carrying its own tenant id.
type Filter struct {
	// AllTenants, when true, matches events of every tenant (a platform operator
	// with no tenant narrowing). Tenants is then ignored.
	AllTenants bool
	// Tenants is the set of tenant ids whose events match when AllTenants is
	// false. An event whose Tenant is not a key here (including the empty
	// platform tenant) does not match.
	Tenants map[string]bool
	// Action, when non-empty, restricts matches to a single audit action
	// identifier (e.g. "cert.issue"), the same filter the listing endpoint
	// accepts.
	Action string
}

// Matches reports whether e should be delivered to a subscriber with this
// filter.
func (f Filter) Matches(e *audit.Event) bool {
	if f.Action != "" && e.Action != f.Action {
		return false
	}
	if f.AllTenants {
		return true
	}
	return f.Tenants[e.Tenant]
}

// Publisher fans each appended audit event out to every matching subscriber.
// It is safe for concurrent use; Publish never blocks.
type Publisher struct {
	bufSize int

	mu   sync.RWMutex
	subs map[*Subscriber]struct{}
}

// NewPublisher returns a Publisher whose subscribers each buffer up to bufSize
// undelivered events (DefaultBufferSize when bufSize <= 0).
func NewPublisher(bufSize int) *Publisher {
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}
	return &Publisher{bufSize: bufSize, subs: make(map[*Subscriber]struct{})}
}

// Publish delivers e to every subscriber whose filter matches. It never blocks:
// a subscriber whose buffer is full drops its oldest queued event (recording the
// lag) so the caller — which is holding the audit append critical section — is
// never stalled by a slow reader. e is passed by value, so subscribers cannot
// mutate the caller's event.
func (p *Publisher) Publish(e audit.Event) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for s := range p.subs {
		if s.filter.Matches(&e) {
			s.enqueue(e)
		}
	}
}

// Subscribe registers a new subscriber with the given filter and returns it.
// The caller must Unsubscribe it when done (e.g. on client disconnect).
func (p *Publisher) Subscribe(f Filter) *Subscriber {
	s := newSubscriber(f, p.bufSize)
	p.mu.Lock()
	p.subs[s] = struct{}{}
	n := len(p.subs)
	p.mu.Unlock()
	metrics.SetEventStreamSubscribers(n)
	metrics.RecordEventStreamConnection()
	return s
}

// Unsubscribe removes s so it receives no further events. It is idempotent.
func (p *Publisher) Unsubscribe(s *Subscriber) {
	p.mu.Lock()
	_, ok := p.subs[s]
	if ok {
		delete(p.subs, s)
	}
	n := len(p.subs)
	p.mu.Unlock()
	if ok {
		s.close()
		metrics.SetEventStreamSubscribers(n)
	}
}

// SubscriberCount returns the number of currently registered subscribers.
func (p *Publisher) SubscriberCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.subs)
}

// Subscriber is a single live consumer of the event stream. Events matching its
// filter are queued into a bounded ring buffer; the consumer waits on Notify and
// calls Drain to collect them. Drop-oldest under overflow guarantees the
// producer never blocks.
type Subscriber struct {
	filter Filter

	mu      sync.Mutex
	ring    []audit.Event
	head    int    // index of the oldest queued event
	n       int    // number of queued events
	dropped uint64 // events dropped since the last Drain
	closed  bool

	// notify is a coalescing, capacity-1 signal: enqueue does a non-blocking
	// send so a waiting consumer wakes without the producer ever blocking, and
	// multiple enqueues between drains collapse to a single wakeup.
	notify chan struct{}
}

func newSubscriber(f Filter, bufSize int) *Subscriber {
	return &Subscriber{
		filter: f,
		ring:   make([]audit.Event, bufSize),
		notify: make(chan struct{}, 1),
	}
}

// enqueue appends e to the ring, dropping the oldest event (and counting the
// lag) when the buffer is full. It then wakes any waiting consumer without
// blocking.
func (s *Subscriber) enqueue(e audit.Event) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	capa := len(s.ring)
	if s.n == capa {
		// Buffer full: evict the oldest undelivered event and record the drop.
		s.head = (s.head + 1) % capa
		s.n--
		s.dropped++
		metrics.RecordEventStreamDropped()
	}
	s.ring[(s.head+s.n)%capa] = e
	s.n++
	s.mu.Unlock()

	select {
	case s.notify <- struct{}{}:
	default:
	}
}

// Notify returns the wakeup channel a consumer selects on to learn that events
// (or drops) are available to Drain.
func (s *Subscriber) Notify() <-chan struct{} { return s.notify }

// Drain returns every queued event in arrival order plus the number of events
// dropped since the previous Drain, clearing both. It returns (nil, 0) when
// there is nothing to report.
func (s *Subscriber) Drain() ([]audit.Event, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.n == 0 && s.dropped == 0 {
		return nil, 0
	}
	capa := len(s.ring)
	var out []audit.Event
	if s.n > 0 {
		out = make([]audit.Event, s.n)
		for i := 0; i < s.n; i++ {
			out[i] = s.ring[(s.head+i)%capa]
		}
	}
	s.head, s.n = 0, 0
	d := s.dropped
	s.dropped = 0
	return out, d
}

// close marks the subscriber closed so further enqueues are dropped silently.
func (s *Subscriber) close() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
}
