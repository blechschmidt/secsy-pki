package metrics

import (
	"strings"
	"testing"
)

// render is a test helper that renders a registry to a string.
func render(r *Registry) string {
	var b strings.Builder
	r.WriteTo(&b)
	return b.String()
}

func TestCounterExposition(t *testing.T) {
	r := NewRegistry()
	c := NewCounter(r, "test_total", "A test counter.", "op", "result")
	c.Inc("issue", "success")
	c.Inc("issue", "success")
	c.Add(3, "issue", "error")

	out := render(r)
	if !strings.Contains(out, "# HELP test_total A test counter.") {
		t.Errorf("missing HELP line:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE test_total counter") {
		t.Errorf("missing TYPE line:\n%s", out)
	}
	if !strings.Contains(out, `test_total{op="issue",result="success"} 2`) {
		t.Errorf("wrong success count:\n%s", out)
	}
	if !strings.Contains(out, `test_total{op="issue",result="error"} 3`) {
		t.Errorf("wrong error count:\n%s", out)
	}
}

func TestUnlabelledCounterRendersZero(t *testing.T) {
	r := NewRegistry()
	NewCounter(r, "lonely_total", "No labels, no observations.")
	out := render(r)
	if !strings.Contains(out, "lonely_total 0") {
		t.Errorf("expected zero sample for unobserved unlabelled counter:\n%s", out)
	}
}

func TestGauge(t *testing.T) {
	r := NewRegistry()
	g := NewGauge(r, "widgets", "In-flight widgets.")
	g.Inc()
	g.Inc()
	g.Dec()
	g.Add(0.5)
	out := render(r)
	if !strings.Contains(out, "widgets 1.5") {
		t.Errorf("expected widgets 1.5:\n%s", out)
	}

	labelled := NewGauge(r, "up", "Component up.", "component")
	labelled.Set(1, "database")
	labelled.Set(0, "hsm")
	out = render(r)
	if !strings.Contains(out, `up{component="database"} 1`) || !strings.Contains(out, `up{component="hsm"} 0`) {
		t.Errorf("labelled gauge wrong:\n%s", out)
	}
}

func TestHistogramExposition(t *testing.T) {
	r := NewRegistry()
	h := NewHistogram(r, "lat_seconds", "Latency.", []float64{0.1, 0.5, 1}, "op")
	// Observations: 0.05 (<=0.1,0.5,1), 0.2 (<=0.5,1), 5 (>all finite buckets).
	h.Observe(0.05, "sign")
	h.Observe(0.2, "sign")
	h.Observe(5, "sign")

	out := render(r)
	// Cumulative bucket counts.
	checks := []string{
		`lat_seconds_bucket{op="sign",le="0.1"} 1`,
		`lat_seconds_bucket{op="sign",le="0.5"} 2`,
		`lat_seconds_bucket{op="sign",le="1"} 2`,
		`lat_seconds_bucket{op="sign",le="+Inf"} 3`,
		`lat_seconds_count{op="sign"} 3`,
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("missing %q in:\n%s", c, out)
		}
	}
	// Sum should be 0.05+0.2+5 = 5.25.
	if !strings.Contains(out, `lat_seconds_sum{op="sign"} 5.25`) {
		t.Errorf("wrong sum:\n%s", out)
	}
}

func TestLabelValueEscaping(t *testing.T) {
	r := NewRegistry()
	c := NewCounter(r, "esc_total", "escaping", "route")
	c.Inc(`weird"\route`)
	out := render(r)
	if !strings.Contains(out, `esc_total{route="weird\"\\route"} 1`) {
		t.Errorf("label value not escaped:\n%s", out)
	}
}

func TestDuplicateRegistrationPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Errorf("expected panic on duplicate metric name")
		}
	}()
	r := NewRegistry()
	NewCounter(r, "dup_total", "one")
	NewCounter(r, "dup_total", "two") // must panic
}

func TestLabelCardinalityMismatchPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Errorf("expected panic on label count mismatch")
		}
	}()
	r := NewRegistry()
	c := NewCounter(r, "mm_total", "mismatch", "a", "b")
	c.Inc("only-one") // must panic
}

func TestHelperRecorders(t *testing.T) {
	// Exercise the domain helpers against fresh metrics on a private registry by
	// checking the Default registry renders the expected series after recording.
	RecordCertificate("issue", nil)
	RecordCertificate("issue", errBoom{})
	RecordAuthz("ca:manage", true)
	RecordAuthz("ca:manage", false)
	RecordEnvelope("encrypt", nil)

	out := render(Default)
	for _, want := range []string{
		`secsy_certificates_total{operation="issue",result="success"} `,
		`secsy_certificates_total{operation="issue",result="error"} `,
		`secsy_authz_decisions_total{action="ca:manage",decision="allow"} `,
		`secsy_authz_decisions_total{action="ca:manage",decision="deny"} `,
		`secsy_envelope_operations_total{operation="encrypt",result="success"} `,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Default registry missing %q", want)
		}
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "boom" }
