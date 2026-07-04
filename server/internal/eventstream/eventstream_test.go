package eventstream

import (
	"sync"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
)

// TestFilterMatches pins the subscriber-filter semantics that mirror the
// audit-listing API's tenant scoping: a platform (AllTenants) subscriber sees
// every event, a tenant-scoped subscriber sees only its own tenant's events
// (never another tenant's, never platform-level events with an empty tenant),
// and a non-empty Action narrows to a single action.
func TestFilterMatches(t *testing.T) {
	issueT1 := &audit.Event{Tenant: "t1", Action: audit.ActionCertIssue}
	revokeT2 := &audit.Event{Tenant: "t2", Action: audit.ActionCertRevoke}
	platform := &audit.Event{Tenant: "", Action: audit.ActionCACreate}

	cases := []struct {
		name   string
		filter Filter
		event  *audit.Event
		want   bool
	}{
		{"all-tenants matches tenant event", Filter{AllTenants: true}, issueT1, true},
		{"all-tenants matches platform event", Filter{AllTenants: true}, platform, true},
		{"tenant filter matches its own tenant", Filter{Tenants: map[string]bool{"t1": true}}, issueT1, true},
		{"tenant filter rejects other tenant", Filter{Tenants: map[string]bool{"t1": true}}, revokeT2, false},
		{"tenant filter rejects platform event", Filter{Tenants: map[string]bool{"t1": true}}, platform, false},
		{"action filter matches", Filter{AllTenants: true, Action: audit.ActionCertIssue}, issueT1, true},
		{"action filter rejects other action", Filter{AllTenants: true, Action: audit.ActionCertIssue}, revokeT2, false},
		{"action filter also honors tenant scope", Filter{Tenants: map[string]bool{"t1": true}, Action: audit.ActionCertIssue}, issueT1, true},
		{"empty tenant filter matches nothing", Filter{}, issueT1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.filter.Matches(tc.event); got != tc.want {
				t.Fatalf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPublisherFanOut proves one appended event reaches every subscriber whose
// filter matches — and only those — so a platform operator, a tenant auditor,
// and an action-filtered subscriber each receive exactly the slice of the stream
// their scope permits.
func TestPublisherFanOut(t *testing.T) {
	p := NewPublisher(0)
	all := p.Subscribe(Filter{AllTenants: true})
	t1 := p.Subscribe(Filter{Tenants: map[string]bool{"t1": true}})
	issues := p.Subscribe(Filter{AllTenants: true, Action: audit.ActionCertIssue})

	if p.SubscriberCount() != 3 {
		t.Fatalf("SubscriberCount = %d, want 3", p.SubscriberCount())
	}

	p.Publish(audit.Event{ID: "e1", Tenant: "t1", Action: audit.ActionCertIssue})
	p.Publish(audit.Event{ID: "e2", Tenant: "t2", Action: audit.ActionCertRevoke})
	p.Publish(audit.Event{ID: "e3", Tenant: "", Action: audit.ActionCACreate})

	assertDrainIDs(t, "all", all, []string{"e1", "e2", "e3"})
	assertDrainIDs(t, "t1", t1, []string{"e1"})
	assertDrainIDs(t, "issues", issues, []string{"e1"})
}

// TestPublisherDropOldest proves a subscriber that never drains loses its OLDEST
// undelivered events once the ring is full (never blocking the publisher), keeps
// the newest bufSize events, and reports the exact number dropped.
func TestPublisherDropOldest(t *testing.T) {
	p := NewPublisher(4)
	s := p.Subscribe(Filter{AllTenants: true})

	// Ten events into a 4-slot ring: the six oldest (e0..e5) are evicted, the four
	// newest (e6..e9) survive.
	for i := 0; i < 10; i++ {
		p.Publish(audit.Event{ID: idOf(i)})
	}

	events, dropped := s.Drain()
	if dropped != 6 {
		t.Fatalf("dropped = %d, want 6", dropped)
	}
	got := make([]string, len(events))
	for i := range events {
		got[i] = events[i].ID
	}
	want := []string{"e6", "e7", "e8", "e9"}
	if !equalStrings(got, want) {
		t.Fatalf("retained IDs = %v, want %v", got, want)
	}

	// A second Drain with nothing pending reports nothing.
	if evs, d := s.Drain(); evs != nil || d != 0 {
		t.Fatalf("empty Drain = (%v, %d), want (nil, 0)", evs, d)
	}
}

// TestPublishNeverBlocks is the hot-path guarantee: publishing to a wedged
// subscriber that never drains must return promptly rather than block the
// caller (which holds the audit-append critical section).
func TestPublishNeverBlocks(t *testing.T) {
	p := NewPublisher(2)
	p.Subscribe(Filter{AllTenants: true}) // never drained

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			p.Publish(audit.Event{ID: idOf(i)})
		}
		close(done)
	}()
	<-done // if Publish blocked, this test would hang and fail via the test timeout
}

// TestNotifyCoalesces proves the capacity-1 wakeup channel collapses multiple
// enqueues between drains into a single signal, so a consumer is not woken once
// per event under a burst.
func TestNotifyCoalesces(t *testing.T) {
	p := NewPublisher(0)
	s := p.Subscribe(Filter{AllTenants: true})
	p.Publish(audit.Event{ID: "e1"})
	p.Publish(audit.Event{ID: "e2"})
	p.Publish(audit.Event{ID: "e3"})

	// Exactly one wakeup is pending despite three enqueues.
	select {
	case <-s.Notify():
	default:
		t.Fatal("expected a pending wakeup after publishing")
	}
	select {
	case <-s.Notify():
		t.Fatal("expected the three enqueues to coalesce into a single wakeup")
	default:
	}
}

// TestUnsubscribe proves an unsubscribed consumer receives no further events, the
// subscriber count is maintained, and Unsubscribe is idempotent.
func TestUnsubscribe(t *testing.T) {
	p := NewPublisher(0)
	a := p.Subscribe(Filter{AllTenants: true})
	b := p.Subscribe(Filter{AllTenants: true})
	if p.SubscriberCount() != 2 {
		t.Fatalf("SubscriberCount = %d, want 2", p.SubscriberCount())
	}

	p.Unsubscribe(a)
	if p.SubscriberCount() != 1 {
		t.Fatalf("SubscriberCount after unsubscribe = %d, want 1", p.SubscriberCount())
	}
	p.Unsubscribe(a) // idempotent: no panic, no negative count
	if p.SubscriberCount() != 1 {
		t.Fatalf("SubscriberCount after double unsubscribe = %d, want 1", p.SubscriberCount())
	}

	p.Publish(audit.Event{ID: "after"})
	if evs, _ := a.Drain(); evs != nil {
		t.Fatalf("unsubscribed consumer received %d event(s), want 0", len(evs))
	}
	assertDrainIDs(t, "b", b, []string{"after"})
}

// TestConcurrentPublish exercises the publisher under concurrent producers and a
// draining consumer with the race detector: no drops are counted (ample buffer),
// every event is eventually delivered, and there is no data race.
func TestConcurrentPublish(t *testing.T) {
	p := NewPublisher(4096)
	s := p.Subscribe(Filter{AllTenants: true})

	const producers, each = 8, 100
	var wg sync.WaitGroup
	for g := 0; g < producers; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				p.Publish(audit.Event{ID: "x"})
			}
		}()
	}
	wg.Wait()

	total := 0
	for {
		events, dropped := s.Drain()
		if dropped != 0 {
			t.Fatalf("unexpected drops with an ample buffer: %d", dropped)
		}
		if len(events) == 0 {
			break
		}
		total += len(events)
	}
	if want := producers * each; total != want {
		t.Fatalf("delivered %d events, want %d", total, want)
	}
}

// --- helpers -----------------------------------------------------------------

func assertDrainIDs(t *testing.T, name string, s *Subscriber, want []string) {
	t.Helper()
	events, dropped := s.Drain()
	if dropped != 0 {
		t.Fatalf("%s: unexpected drops: %d", name, dropped)
	}
	got := make([]string, len(events))
	for i := range events {
		got[i] = events[i].ID
	}
	if !equalStrings(got, want) {
		t.Fatalf("%s: drained IDs = %v, want %v", name, got, want)
	}
}

func idOf(i int) string {
	return "e" + string(rune('0'+i%10))
}

func equalStrings(a, b []string) bool {
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
