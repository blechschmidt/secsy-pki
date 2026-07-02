package metrics

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// ---------------------------------------------------------------------------
// Counter
// ---------------------------------------------------------------------------

// Counter is a monotonically non-decreasing metric, optionally partitioned by
// labels. Use it for event tallies (certificates issued, requests served).
type Counter struct {
	desc
	mu     sync.Mutex
	series map[string]*counterChild
}

type counterChild struct {
	values []string
	v      atomic.Uint64 // fixed-point: value * 1e0, incremented by whole units
	// For fractional increments we would need a float; counters here only ever
	// take integer increments, so a uint64 is exact and lock-free to bump.
}

// NewCounter registers and returns a Counter on r.
func NewCounter(r *Registry, name, help string, labels ...string) *Counter {
	c := &Counter{
		desc:   desc{metricName: name, help: help, mtype: typeCounter, labels: labels},
		series: make(map[string]*counterChild),
	}
	r.register(c)
	return c
}

// Inc increments the counter series identified by labelValues by one.
func (c *Counter) Inc(labelValues ...string) { c.Add(1, labelValues...) }

// Add increments the counter series identified by labelValues by delta (which
// must be non-negative). Passing a negative delta panics.
func (c *Counter) Add(delta uint64, labelValues ...string) {
	c.checkLabels(labelValues)
	child := c.child(labelValues)
	child.v.Add(delta)
}

func (c *Counter) child(values []string) *counterChild {
	key := seriesKey(values)
	c.mu.Lock()
	defer c.mu.Unlock()
	ch, ok := c.series[key]
	if !ok {
		ch = &counterChild{values: values}
		c.series[key] = ch
	}
	return ch
}

func (c *Counter) write(b *strings.Builder) {
	c.writeHeader(b)
	c.mu.Lock()
	keys := make([]string, 0, len(c.series))
	for k := range c.series {
		keys = append(keys, k)
	}
	children := c.series
	c.mu.Unlock()
	sort.Strings(keys)
	if len(keys) == 0 {
		// A labelled counter with no observations yet renders nothing beyond the
		// header; an unlabelled counter renders a zero sample so it always exists.
		if len(c.labels) == 0 {
			b.WriteString(c.metricName)
			b.WriteString(" 0\n")
		}
		return
	}
	for _, k := range keys {
		ch := children[k]
		b.WriteString(c.metricName)
		c.writeLabels(b, ch.values, "", "")
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(ch.v.Load(), 10))
		b.WriteByte('\n')
	}
}

// ---------------------------------------------------------------------------
// Gauge
// ---------------------------------------------------------------------------

// Gauge is a metric that can go up or down. Use it for instantaneous values
// (readiness state, in-flight requests).
type Gauge struct {
	desc
	mu     sync.Mutex
	series map[string]*gaugeChild
}

type gaugeChild struct {
	values []string
	mu     sync.Mutex
	v      float64
}

// NewGauge registers and returns a Gauge on r.
func NewGauge(r *Registry, name, help string, labels ...string) *Gauge {
	g := &Gauge{
		desc:   desc{metricName: name, help: help, mtype: typeGauge, labels: labels},
		series: make(map[string]*gaugeChild),
	}
	r.register(g)
	return g
}

// Set assigns the gauge series identified by labelValues to v.
func (g *Gauge) Set(v float64, labelValues ...string) {
	g.checkLabels(labelValues)
	ch := g.child(labelValues)
	ch.mu.Lock()
	ch.v = v
	ch.mu.Unlock()
}

// Inc adds one to the gauge series.
func (g *Gauge) Inc(labelValues ...string) { g.Add(1, labelValues...) }

// Dec subtracts one from the gauge series.
func (g *Gauge) Dec(labelValues ...string) { g.Add(-1, labelValues...) }

// Add adds delta (which may be negative) to the gauge series.
func (g *Gauge) Add(delta float64, labelValues ...string) {
	g.checkLabels(labelValues)
	ch := g.child(labelValues)
	ch.mu.Lock()
	ch.v += delta
	ch.mu.Unlock()
}

func (g *Gauge) child(values []string) *gaugeChild {
	key := seriesKey(values)
	g.mu.Lock()
	defer g.mu.Unlock()
	ch, ok := g.series[key]
	if !ok {
		ch = &gaugeChild{values: values}
		g.series[key] = ch
	}
	return ch
}

func (g *Gauge) write(b *strings.Builder) {
	g.writeHeader(b)
	g.mu.Lock()
	keys := make([]string, 0, len(g.series))
	for k := range g.series {
		keys = append(keys, k)
	}
	children := g.series
	g.mu.Unlock()
	sort.Strings(keys)
	if len(keys) == 0 {
		if len(g.labels) == 0 {
			b.WriteString(g.metricName)
			b.WriteString(" 0\n")
		}
		return
	}
	for _, k := range keys {
		ch := children[k]
		ch.mu.Lock()
		v := ch.v
		ch.mu.Unlock()
		b.WriteString(g.metricName)
		g.writeLabels(b, ch.values, "", "")
		b.WriteByte(' ')
		b.WriteString(formatFloat(v))
		b.WriteByte('\n')
	}
}

// ---------------------------------------------------------------------------
// Histogram
// ---------------------------------------------------------------------------

// DefBuckets is a default set of latency buckets in seconds, suitable for the
// sub-millisecond-to-multi-second range of HSM and HTTP operations.
var DefBuckets = []float64{
	0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

// Histogram samples observations into cumulative buckets, tracking their sum
// and count, optionally partitioned by labels.
type Histogram struct {
	desc
	buckets []float64 // sorted upper bounds, excluding +Inf
	mu      sync.Mutex
	series  map[string]*histogramChild
}

type histogramChild struct {
	values []string
	mu     sync.Mutex
	counts []uint64 // per-bucket counts (len == len(buckets))
	sum    float64
	count  uint64
}

// NewHistogram registers and returns a Histogram on r. If buckets is empty,
// DefBuckets is used. Buckets must be provided in strictly increasing order.
func NewHistogram(r *Registry, name, help string, buckets []float64, labels ...string) *Histogram {
	if len(buckets) == 0 {
		buckets = DefBuckets
	}
	// Defensive copy + validate monotonicity.
	bs := make([]float64, len(buckets))
	copy(bs, buckets)
	for i := 1; i < len(bs); i++ {
		if bs[i] <= bs[i-1] {
			panic("metrics: histogram " + name + " buckets must be strictly increasing")
		}
	}
	h := &Histogram{
		desc:    desc{metricName: name, help: help, mtype: typeHistogram, labels: labels},
		buckets: bs,
		series:  make(map[string]*histogramChild),
	}
	r.register(h)
	return h
}

// Observe records a single value into the histogram series.
func (h *Histogram) Observe(v float64, labelValues ...string) {
	h.checkLabels(labelValues)
	ch := h.child(labelValues)
	ch.mu.Lock()
	ch.sum += v
	ch.count++
	for i, ub := range h.buckets {
		if v <= ub {
			ch.counts[i]++
		}
	}
	ch.mu.Unlock()
}

func (h *Histogram) child(values []string) *histogramChild {
	key := seriesKey(values)
	h.mu.Lock()
	defer h.mu.Unlock()
	ch, ok := h.series[key]
	if !ok {
		ch = &histogramChild{values: values, counts: make([]uint64, len(h.buckets))}
		h.series[key] = ch
	}
	return ch
}

func (h *Histogram) write(b *strings.Builder) {
	h.writeHeader(b)
	h.mu.Lock()
	keys := make([]string, 0, len(h.series))
	for k := range h.series {
		keys = append(keys, k)
	}
	children := h.series
	h.mu.Unlock()
	sort.Strings(keys)
	for _, k := range keys {
		ch := children[k]
		ch.mu.Lock()
		counts := make([]uint64, len(ch.counts))
		copy(counts, ch.counts)
		sum := ch.sum
		count := ch.count
		ch.mu.Unlock()

		// Observe() increments every bucket whose upper bound is >= the observed
		// value, so counts[i] is already the cumulative "less than or equal to
		// buckets[i]" total the exposition format requires.
		for i, ub := range h.buckets {
			b.WriteString(h.metricName)
			b.WriteString("_bucket")
			h.writeLabels(b, ch.values, "le", formatFloat(ub))
			b.WriteByte(' ')
			b.WriteString(strconv.FormatUint(counts[i], 10))
			b.WriteByte('\n')
		}
		// +Inf bucket == total count.
		b.WriteString(h.metricName)
		b.WriteString("_bucket")
		h.writeLabels(b, ch.values, "le", "+Inf")
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(count, 10))
		b.WriteByte('\n')

		b.WriteString(h.metricName)
		b.WriteString("_sum")
		h.writeLabels(b, ch.values, "", "")
		b.WriteByte(' ')
		b.WriteString(formatFloat(sum))
		b.WriteByte('\n')

		b.WriteString(h.metricName)
		b.WriteString("_count")
		h.writeLabels(b, ch.values, "", "")
		b.WriteByte(' ')
		b.WriteString(strconv.FormatUint(count, 10))
		b.WriteByte('\n')
	}
}
