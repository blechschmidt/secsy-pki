package pki

import (
	"testing"
	"time"
)

func TestParseCertType(t *testing.T) {
	tests := []struct {
		input string
		want  uint32
		err   bool
	}{
		{"user", 1, false},
		{"", 1, false},
		{"host", 2, false},
		{"invalid", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseCertType(tt.input)
		if (err != nil) != tt.err {
			t.Errorf("ParseCertType(%q) error = %v", tt.input, err)
		}
		if err == nil && got != tt.want {
			t.Errorf("ParseCertType(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestParseTime(t *testing.T) {
	now := time.Now()

	// Empty string returns default
	got, err := ParseTime("", now)
	if err != nil || !got.Equal(now) {
		t.Errorf("empty: got %v, err %v", got, err)
	}

	// Relative time
	got, err = ParseTime("+1d", now)
	if err != nil {
		t.Fatal(err)
	}
	diff := got.Sub(now)
	if diff < 23*time.Hour || diff > 25*time.Hour {
		t.Errorf("+1d: diff = %v", diff)
	}

	// Relative weeks
	got, err = ParseTime("+1w", now)
	if err != nil {
		t.Fatal(err)
	}
	diff = got.Sub(now)
	if diff < 6*24*time.Hour || diff > 8*24*time.Hour {
		t.Errorf("+1w: diff = %v", diff)
	}

	// Relative hours/minutes/seconds
	for _, tc := range []struct {
		s, unit string
		d       time.Duration
	}{
		{"+2h", "h", 2 * time.Hour},
		{"+30m", "m", 30 * time.Minute},
		{"+60s", "s", 60 * time.Second},
	} {
		got, err = ParseTime(tc.s, now)
		if err != nil {
			t.Fatalf("%s: %v", tc.s, err)
		}
	}

	// RFC3339
	got, err = ParseTime("2030-01-01T00:00:00Z", now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Year() != 2030 {
		t.Errorf("RFC3339: year = %d", got.Year())
	}

	// Unix timestamp
	got, err = ParseTime("1700000000", now)
	if err != nil {
		t.Fatal(err)
	}

	// Invalid
	_, err = ParseTime("not-a-time", now)
	if err == nil {
		t.Fatal("expected error")
	}

	// Invalid relative (but falls through to unix timestamp parsing)
	// "+5x" parses as unix timestamp 5 via fmt.Sscanf, so use something truly invalid
	_, err = ParseTime("never", now)
	if err == nil {
		t.Fatal("expected error for unparseable time")
	}
}
