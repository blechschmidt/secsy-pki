package config

import (
	"strings"
	"testing"
)

func TestLoadTracingConfig(t *testing.T) {
	clearProviderEnv(t)
	cfg := writeAndLoad(t, `
root_user:
  password: secret
tracing:
  enabled: true
  endpoint: otel-collector:4317
  protocol: grpc
  insecure: true
  sample_ratio: 0.25
  service_name: secsy-pki-prod
  service_version: 1.2.3
  timeout_seconds: 5
  headers:
    authorization: "Bearer xyz"
`)

	tr := cfg.Tracing
	if !tr.Enabled {
		t.Fatal("tracing.enabled should be true")
	}
	if tr.Endpoint != "otel-collector:4317" {
		t.Errorf("endpoint = %q", tr.Endpoint)
	}
	if tr.Protocol != "grpc" {
		t.Errorf("protocol = %q", tr.Protocol)
	}
	if !tr.Insecure {
		t.Error("insecure should be true")
	}
	if tr.SampleRatio != 0.25 {
		t.Errorf("sample_ratio = %v, want 0.25", tr.SampleRatio)
	}
	if tr.ServiceName != "secsy-pki-prod" || tr.ServiceVersion != "1.2.3" {
		t.Errorf("service name/version = %q/%q", tr.ServiceName, tr.ServiceVersion)
	}
	if tr.TimeoutSeconds != 5 {
		t.Errorf("timeout_seconds = %d, want 5", tr.TimeoutSeconds)
	}
	if tr.Headers["authorization"] != "Bearer xyz" {
		t.Errorf("headers = %v", tr.Headers)
	}
}

func TestTracingDisabledByDefault(t *testing.T) {
	clearProviderEnv(t)
	cfg := writeAndLoad(t, `
root_user:
  password: secret
`)
	if cfg.Tracing.Enabled {
		t.Error("tracing must be disabled by default")
	}
}

func TestValidateTracingRejectsBadConfig(t *testing.T) {
	clearProviderEnv(t)
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "enabled without endpoint",
			yaml: `
root_user:
  password: secret
tracing:
  enabled: true
`,
			wantErr: "tracing.endpoint is required",
		},
		{
			name: "unknown protocol",
			yaml: `
root_user:
  password: secret
tracing:
  enabled: true
  endpoint: c:4317
  protocol: smoke-signals
`,
			wantErr: "tracing.protocol",
		},
		{
			name: "sample ratio out of range",
			yaml: `
root_user:
  password: secret
tracing:
  enabled: true
  endpoint: c:4317
  sample_ratio: 2.5
`,
			wantErr: "tracing.sample_ratio",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadContent(t, tc.yaml)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}
