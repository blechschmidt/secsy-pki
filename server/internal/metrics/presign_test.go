package metrics

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// TestFuncGauge covers the scrape-time gauge: no sample until the callback
// reports one, then a value computed at render time.
func TestFuncGauge(t *testing.T) {
	r := NewRegistry()
	var v float64
	var ok bool
	NewFuncGauge(r, "test_staleness_seconds", "A staleness gauge.", func() (float64, bool) { return v, ok })

	out := render(r)
	if !strings.Contains(out, "# TYPE test_staleness_seconds gauge") {
		t.Fatalf("missing header:\n%s", out)
	}
	if strings.Contains(out, "test_staleness_seconds 0") {
		t.Fatalf("gauge emitted a sample before first success:\n%s", out)
	}

	v, ok = 42.5, true
	out = render(r)
	if !strings.Contains(out, "test_staleness_seconds 42.5") {
		t.Fatalf("gauge sample missing:\n%s", out)
	}
}

// TestRecordOCSPPresignBatch verifies the batch recorder drives the duration
// histogram, per-result counters, and the staleness instant — and that a
// failed batch does not reset staleness.
func TestRecordOCSPPresignBatch(t *testing.T) {
	before := ocspPresignLastSuccessNano.Load()

	RecordOCSPPresignBatch(time.Now().Add(-50*time.Millisecond), 10, 2, nil)
	after := ocspPresignLastSuccessNano.Load()
	if after == before {
		t.Fatal("successful batch did not stamp the staleness instant")
	}
	if s, ok := sinceNano(after); !ok || s < 0 || s > 60 {
		t.Fatalf("staleness = %v,%v — want a small positive age", s, ok)
	}

	RecordOCSPPresignBatch(time.Now(), 0, 5, errors.New("hsm down"))
	if got := ocspPresignLastSuccessNano.Load(); got != after {
		t.Fatal("failed batch must not advance the staleness instant")
	}

	out := render(Default)
	for _, want := range []string{
		`secsy_ocsp_presign_responses_total{result="success"}`,
		`secsy_ocsp_presign_responses_total{result="error"}`,
		"secsy_ocsp_presign_batch_duration_seconds_count",
		"# TYPE secsy_ocsp_presign_staleness_seconds gauge",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition missing %q", want)
		}
	}
}

// TestRecordPublishRun verifies publish accounting by backend.
func TestRecordPublishRun(t *testing.T) {
	RecordPublishRun("dir", time.Now().Add(-10*time.Millisecond), nil)
	RecordPublishRun("s3", time.Now(), errors.New("boom"))
	out := render(Default)
	for _, want := range []string{
		`secsy_publish_runs_total{backend="dir",result="success"} 1`,
		`secsy_publish_runs_total{backend="s3",result="error"} 1`,
		`secsy_publish_last_success_timestamp_seconds{backend="dir"}`,
		"secsy_publish_staleness_seconds ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition missing %q", want)
		}
	}
}
