package main

import (
	"strings"
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/ct"
)

// newOperatorSubmitter builds a submitter over logs described as name/operator
// pairs. URLs are placeholders (never dialed here) — only the operator wiring
// matters for validateCTOperatorPolicy.
func newOperatorSubmitter(t *testing.T, logs map[string]string) *ct.Submitter {
	t.Helper()
	var cfgs []ct.LogConfig
	for name, operator := range logs {
		cfgs = append(cfgs, ct.LogConfig{Name: name, URL: "https://ct.example/" + name, Operator: operator})
	}
	sub, err := ct.NewSubmitter(cfgs, nil)
	if err != nil {
		t.Fatalf("NewSubmitter: %v", err)
	}
	return sub
}

// TestValidateCTOperatorPolicy exercises the startup fail-closed gate that
// refuses an operator-diversity policy the configured logs could never satisfy.
func TestValidateCTOperatorPolicy(t *testing.T) {
	tests := []struct {
		name    string
		logs    map[string]string // log name -> operator ("" = unlabelled)
		pc      config.ProfileCTConfig
		wantErr string // "" = expect success; else substring of the error
	}{
		{
			name:    "two operators satisfy min two",
			logs:    map[string]string{"a": "Google", "b": "Cloudflare"},
			pc:      config.ProfileCTConfig{MinDistinctOperators: 2},
			wantErr: "",
		},
		{
			name:    "candidate log missing operator",
			logs:    map[string]string{"a": "Google", "b": ""},
			pc:      config.ProfileCTConfig{MinDistinctOperators: 2},
			wantErr: "no operator configured",
		},
		{
			name:    "not enough distinct operators available",
			logs:    map[string]string{"a": "Google", "b": "Google"},
			pc:      config.ProfileCTConfig{MinDistinctOperators: 2},
			wantErr: "cover only 1",
		},
		{
			name:    "required operator runs no candidate log",
			logs:    map[string]string{"a": "Google", "b": "Cloudflare"},
			pc:      config.ProfileCTConfig{MinDistinctOperators: 2, RequireOperators: []string{"Apple"}},
			wantErr: `operator "Apple"`,
		},
		{
			name:    "required operators all present",
			logs:    map[string]string{"a": "Google", "b": "Cloudflare"},
			pc:      config.ProfileCTConfig{MinDistinctOperators: 2, RequireOperators: []string{"Google", "Cloudflare"}},
			wantErr: "",
		},
		{
			// pc.Logs names a subset; the untargeted (unlabelled) log must not
			// trip the gate.
			name:    "named subset ignores other logs",
			logs:    map[string]string{"a": "Google", "b": "Cloudflare", "c": ""},
			pc:      config.ProfileCTConfig{Logs: []string{"a", "b"}, MinDistinctOperators: 2},
			wantErr: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sub := newOperatorSubmitter(t, tc.logs)
			err := validateCTOperatorPolicy("p", tc.pc, sub)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected success, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
