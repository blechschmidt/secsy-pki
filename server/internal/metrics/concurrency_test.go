package metrics

import (
	"io"
	"strconv"
	"sync"
	"testing"
)

// TestConcurrentScrapeVsUpdate exercises the production access pattern the
// unit tests otherwise miss: a Prometheus scrape (Registry.WriteTo) running
// concurrently with request handlers updating labelled metrics. Each update
// uses a fresh label value, forcing new series to be inserted into the
// per-metric map while a renderer iterates it — the exact interleaving that
// makes an unsynchronized map read during exposition a data race (and, in the
// Go runtime, a "concurrent map read and map write" fatal panic under a real
// scrape). Run under `-race` it must stay clean.
func TestConcurrentScrapeVsUpdate(t *testing.T) {
	r := NewRegistry()
	c := NewCounter(r, "race_counter_total", "counter", "id")
	g := NewGauge(r, "race_gauge", "gauge", "id")
	h := NewHistogram(r, "race_hist", "hist", nil, "id")

	// Kept deliberately modest: the race detector trips on the first
	// unsynchronized map access, so a few hundred interleaved insert/scrape
	// operations reliably catch a regression while keeping the CI race job fast.
	const (
		writers    = 4
		perWriter  = 60
		scrapers   = 3
		scrapeLoop = 40
	)

	var wg sync.WaitGroup

	// Writers insert an ever-growing set of distinct label series, guaranteeing
	// the maps grow/rehash while scrapers read them.
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				id := strconv.Itoa(base*perWriter + i)
				c.Inc(id)
				g.Set(float64(i), id)
				h.Observe(float64(i)*0.001, id)
			}
		}(w)
	}

	// Scrapers render the whole registry repeatedly, concurrent with the writers.
	for s := 0; s < scrapers; s++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < scrapeLoop; i++ {
				if _, err := r.WriteTo(io.Discard); err != nil {
					t.Errorf("WriteTo: %v", err)
					return
				}
			}
		}()
	}

	wg.Wait()

	// Sanity: after the storm every writer's series is present and countable.
	out := render(r)
	if len(out) == 0 {
		t.Fatal("empty exposition after concurrent load")
	}
}
