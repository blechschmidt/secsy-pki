package certlint

import "testing"

// These tests exercise the build-tag-independent zlint mapping logic: the level
// → disposition resolution, per-lint overrides, and description formatting. They
// run in every build. The end-to-end behavior against the real zlint suite is in
// zlint_backend_test.go (build tag "zlint").

func TestNormalizeMode(t *testing.T) {
	tests := []struct {
		in   Mode
		def  Mode
		want Mode
	}{
		{"", ModeEnforce, ModeEnforce},
		{"", ModeWarn, ModeWarn},
		{"enforce", ModeWarn, ModeEnforce},
		{"WARN", ModeEnforce, ModeWarn},
		{" ignore ", ModeEnforce, modeIgnore},
		{"bogus", ModeWarn, ModeWarn}, // unrecognized falls back to default
	}
	for _, tc := range tests {
		if got := normalizeMode(tc.in, tc.def); got != tc.want {
			t.Errorf("normalizeMode(%q, %q) = %q, want %q", tc.in, tc.def, got, tc.want)
		}
	}
}

func TestZLintLevelDefaults(t *testing.T) {
	// Empty policy: error/fatal → enforce, warn → warn, notice → ignore.
	var p ZLintPolicy
	cases := map[string]Mode{
		zlintStatusError:  ModeEnforce,
		zlintStatusFatal:  ModeEnforce,
		zlintStatusWarn:   ModeWarn,
		zlintStatusNotice: modeIgnore,
		"pass":            modeIgnore,
	}
	for status, want := range cases {
		if got := p.levelDefault(status); got != want {
			t.Errorf("default levelDefault(%q) = %q, want %q", status, got, want)
		}
	}
}

func TestZLintLevelMappingOverrides(t *testing.T) {
	p := ZLintPolicy{
		ErrorMode:  ModeWarn,    // demote errors to warnings
		WarnMode:   "ignore",    // silence warnings
		NoticeMode: ModeEnforce, // promote notices to blocking
	}
	if got := p.levelDefault(zlintStatusError); got != ModeWarn {
		t.Errorf("error → %q, want warn", got)
	}
	if got := p.levelDefault(zlintStatusWarn); got != modeIgnore {
		t.Errorf("warn → %q, want ignore", got)
	}
	if got := p.levelDefault(zlintStatusNotice); got != ModeEnforce {
		t.Errorf("notice → %q, want enforce", got)
	}
}

func TestZLintDispositionPerLintOverride(t *testing.T) {
	p := ZLintPolicy{
		Overrides: map[string]Mode{
			"e_noisy_lint":    "warn",   // demote a specific error
			"w_pedantic_lint": "ignore", // drop a specific warning
		},
	}
	// Per-lint override wins over the level default.
	if got := p.dispositionFor("e_noisy_lint", zlintStatusError); got != ModeWarn {
		t.Errorf("overridden error lint → %q, want warn", got)
	}
	if got := p.dispositionFor("w_pedantic_lint", zlintStatusWarn); got != modeIgnore {
		t.Errorf("overridden warn lint → %q, want ignore", got)
	}
	// A lint without an override uses the level default (error → enforce).
	if got := p.dispositionFor("e_other_lint", zlintStatusError); got != ModeEnforce {
		t.Errorf("non-overridden error lint → %q, want enforce", got)
	}
}

func TestZLintDescription(t *testing.T) {
	got := zlintDescription(zlintRaw{
		Name:     "e_dnsname_not_valid_tld",
		Status:   zlintStatusError,
		Details:  "the TLD is reserved",
		Citation: "BRs: 7.1.4.2.1",
		Source:   "CABF_BR",
	})
	want := "ERROR CABF_BR (BRs: 7.1.4.2.1): the TLD is reserved"
	if got != want {
		t.Errorf("zlintDescription = %q, want %q", got, want)
	}
	// Minimal result: status only.
	if got := zlintDescription(zlintRaw{Status: zlintStatusWarn}); got != "WARN" {
		t.Errorf("minimal zlintDescription = %q, want %q", got, "WARN")
	}
}

func TestZLintFindingsFilterMapping(t *testing.T) {
	// Sources/names round-trip into the filter struct so the backend receives them
	// verbatim.
	p := ZLintPolicy{
		IncludeSources: []string{"CABF_BR"},
		ExcludeNames:   []string{"e_flaky"},
	}
	f := p.filter()
	if len(f.IncludeSources) != 1 || f.IncludeSources[0] != "CABF_BR" {
		t.Errorf("filter IncludeSources = %v", f.IncludeSources)
	}
	if len(f.ExcludeNames) != 1 || f.ExcludeNames[0] != "e_flaky" {
		t.Errorf("filter ExcludeNames = %v", f.ExcludeNames)
	}
}
