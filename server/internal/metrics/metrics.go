// Package metrics provides a small, dependency-free implementation of the
// Prometheus text exposition format. It offers labelled Counters, Gauges, and
// Histograms gathered in a Registry that renders to the standard
// text/plain; version=0.0.4 format scraped by Prometheus.
//
// The implementation is deliberately self-contained rather than pulling in
// github.com/prometheus/client_golang and its transitive dependency tree: the
// exposition format is stable and the surface we need (a handful of
// application-domain metrics) is small. It mirrors the from-scratch approach the
// rest of the enterprise stack takes for the audit hash-chain, RBAC, and ACME.
//
// All metric types are safe for concurrent use by multiple goroutines.
package metrics

import (
	"io"
	"strconv"
	"strings"
	"sync"
)

// metricType is the Prometheus TYPE of a metric.
type metricType string

const (
	typeCounter   metricType = "counter"
	typeGauge     metricType = "gauge"
	typeHistogram metricType = "histogram"
)

// collector is implemented by every metric so a Registry can render it.
type collector interface {
	name() string
	write(w *strings.Builder)
}

// Registry holds a set of metrics and renders them in the Prometheus text
// exposition format. The zero value is not usable; call NewRegistry.
type Registry struct {
	mu         sync.Mutex
	collectors []collector
	byName     map[string]collector
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{byName: make(map[string]collector)}
}

// register adds c to the registry. Registering two metrics with the same name
// panics — that is always a programming error caught at startup.
func (r *Registry) register(c collector) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byName[c.name()]; exists {
		panic("metrics: duplicate metric registered: " + c.name())
	}
	r.byName[c.name()] = c
	r.collectors = append(r.collectors, c)
}

// WriteTo renders every registered metric to w in Prometheus text format.
// Metrics are emitted in registration order; series within a metric are sorted
// for deterministic output (important for tests and stable diffs).
func (r *Registry) WriteTo(w io.Writer) (int64, error) {
	r.mu.Lock()
	cols := make([]collector, len(r.collectors))
	copy(cols, r.collectors)
	r.mu.Unlock()

	var b strings.Builder
	for _, c := range cols {
		c.write(&b)
	}
	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// ContentType is the exposition format Content-Type Prometheus expects.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// desc is the shared descriptor embedded in every metric.
type desc struct {
	metricName string
	help       string
	mtype      metricType
	labels     []string
}

func (d desc) name() string { return d.metricName }

// writeHeader emits the # HELP and # TYPE lines.
func (d desc) writeHeader(b *strings.Builder) {
	b.WriteString("# HELP ")
	b.WriteString(d.metricName)
	b.WriteByte(' ')
	b.WriteString(escapeHelp(d.help))
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(d.metricName)
	b.WriteByte(' ')
	b.WriteString(string(d.mtype))
	b.WriteByte('\n')
}

// seriesKey encodes an ordered list of label values into a stable map key. A
// unit separator (0x1f) cannot appear in normal label values, so it is a safe
// join delimiter.
func seriesKey(values []string) string {
	return strings.Join(values, "\x1f")
}

// checkLabels panics if the number of supplied label values does not match the
// declared label names — a programming error we want to fail loudly on.
func (d desc) checkLabels(values []string) {
	if len(values) != len(d.labels) {
		panic("metrics: metric " + d.metricName + " expects " +
			strconv.Itoa(len(d.labels)) + " label values, got " + strconv.Itoa(len(values)))
	}
}

// writeLabels renders {k="v",...} for the given values (already matched to
// d.labels). Extra emits additional label pairs appended after the declared
// ones (used by histogram's le label); pass nil when unused.
func (d desc) writeLabels(b *strings.Builder, values []string, extraKey, extraVal string) {
	if len(values) == 0 && extraKey == "" {
		return
	}
	b.WriteByte('{')
	first := true
	for i, name := range d.labels {
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(name)
		b.WriteString(`="`)
		b.WriteString(escapeLabelValue(values[i]))
		b.WriteByte('"')
	}
	if extraKey != "" {
		if !first {
			b.WriteByte(',')
		}
		b.WriteString(extraKey)
		b.WriteString(`="`)
		b.WriteString(escapeLabelValue(extraVal))
		b.WriteByte('"')
	}
	b.WriteByte('}')
}

// escapeLabelValue escapes a label value per the exposition format: backslash,
// double-quote, and newline.
func escapeLabelValue(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	r := strings.NewReplacer("\\", `\\`, "\"", `\"`, "\n", `\n`)
	return r.Replace(s)
}

// escapeHelp escapes a HELP string: backslash and newline only.
func escapeHelp(s string) string {
	if !strings.ContainsAny(s, "\\\n") {
		return s
	}
	r := strings.NewReplacer("\\", `\\`, "\n", `\n`)
	return r.Replace(s)
}

// formatFloat renders a float the way Prometheus expects (integers without a
// trailing .0, otherwise the shortest round-trippable form).
func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}
