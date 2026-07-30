package ca

import (
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/ct"
)

// TestEvaluateOperatorDiversity checks that distinct operators are counted by
// operator (not by log), that unlabelled logs count as their own independent
// operator, and that only explicitly-named operators satisfy a required-operator
// allowlist.
func TestEvaluateOperatorDiversity(t *testing.T) {
	results := []ct.LogResult{
		{Log: "argon", Operator: "Google", OK: true},
		{Log: "xenon", Operator: "Google", OK: true}, // same operator → counts once
		{Log: "nimbus", Operator: "Cloudflare", OK: true},
		{Log: "sabre", Operator: "DigiCert", OK: false}, // failed → ignored entirely
		{Log: "private", Operator: "", OK: true},        // unlabelled → own operator
	}
	div := evaluateOperatorDiversity(results)

	if div.Count != 3 {
		t.Errorf("distinct operator count = %d, want 3 (Google, Cloudflare, log:private)", div.Count)
	}
	// Named operators: Google + Cloudflare only (DigiCert failed, private unlabelled).
	if _, ok := div.named["Google"]; !ok {
		t.Error("Google should be a named operator")
	}
	if _, ok := div.named["DigiCert"]; ok {
		t.Error("DigiCert failed and must not be a named operator")
	}
	if _, ok := div.named["Cloudflare"]; !ok {
		t.Error("Cloudflare should be a named operator")
	}
	// An unlabelled log never satisfies a required (named) operator.
	if missing := div.missingRequired([]string{"Google", "DigiCert"}); len(missing) != 1 || missing[0] != "DigiCert" {
		t.Errorf("missingRequired = %v, want [DigiCert]", missing)
	}
}

// TestEvaluateSCTPolicy exercises each policy dimension in isolation and in
// combination, and confirms a met policy returns no violation.
func TestEvaluateSCTPolicy(t *testing.T) {
	twoGoogle := []ct.LogResult{
		{Log: "argon", Operator: "Google", OK: true},
		{Log: "xenon", Operator: "Google", OK: true},
	}
	googleAndCloudflare := []ct.LogResult{
		{Log: "argon", Operator: "Google", OK: true},
		{Log: "nimbus", Operator: "Cloudflare", OK: true},
	}

	tests := []struct {
		name     string
		cfg      CTConfig
		sctCount int
		results  []ct.LogResult
		wantPass bool
		wantSub  string // substring the violation message must contain (when failing)
	}{
		{
			name:     "min_scts shortfall",
			cfg:      CTConfig{MinSCTs: 3},
			sctCount: 2,
			results:  twoGoogle,
			wantSub:  "requires 3",
		},
		{
			name:     "enough SCTs but too few operators",
			cfg:      CTConfig{MinSCTs: 2, MinDistinctOperators: 2},
			sctCount: 2,
			results:  twoGoogle, // 2 SCTs, but both from Google → 1 operator
			wantSub:  "distinct log operator",
		},
		{
			name:     "diverse set passes operator minimum",
			cfg:      CTConfig{MinSCTs: 2, MinDistinctOperators: 2},
			sctCount: 2,
			results:  googleAndCloudflare,
			wantPass: true,
		},
		{
			name:     "required operator missing",
			cfg:      CTConfig{MinSCTs: 2, MinDistinctOperators: 2, RequireOperators: []string{"Google", "Apple"}},
			sctCount: 2,
			results:  googleAndCloudflare, // has Google + Cloudflare, but not Apple
			wantSub:  "Apple",
		},
		{
			name:     "required operators all present",
			cfg:      CTConfig{MinSCTs: 2, MinDistinctOperators: 2, RequireOperators: []string{"Google", "Cloudflare"}},
			sctCount: 2,
			results:  googleAndCloudflare,
			wantPass: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			div := evaluateOperatorDiversity(tc.results)
			got := tc.cfg.evaluateSCTPolicy(tc.sctCount, div, "test-profile", tc.results)
			if tc.wantPass {
				if got != "" {
					t.Fatalf("expected policy to pass, got violation: %s", got)
				}
				return
			}
			if got == "" {
				t.Fatal("expected a policy violation, got none")
			}
			if !strings.Contains(got, tc.wantSub) {
				t.Errorf("violation %q does not contain %q", got, tc.wantSub)
			}
		})
	}
}
