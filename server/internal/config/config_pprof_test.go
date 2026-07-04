package config

import "testing"

// TestPProfValidate covers the fail-closed profiling config validation: a
// disabled block never errors, loopback mode requires a loopback address (so the
// unauthenticated loopback listener can never bind a routable interface), and an
// unknown mode is rejected.
func TestPProfValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     PProfConfig
		wantErr bool
	}{
		{name: "disabled is always valid", cfg: PProfConfig{Enabled: false, Mode: "nonsense", Address: "0.0.0.0:6060"}},
		{name: "loopback default address", cfg: PProfConfig{Enabled: true}},
		{name: "loopback explicit 127.0.0.1", cfg: PProfConfig{Enabled: true, Mode: "loopback", Address: "127.0.0.1:6060"}},
		{name: "loopback IPv6 ::1", cfg: PProfConfig{Enabled: true, Mode: "loopback", Address: "[::1]:6060"}},
		{name: "loopback rejects 0.0.0.0", cfg: PProfConfig{Enabled: true, Mode: "loopback", Address: "0.0.0.0:6060"}, wantErr: true},
		{name: "loopback rejects routable IP", cfg: PProfConfig{Enabled: true, Mode: "loopback", Address: "10.0.0.5:6060"}, wantErr: true},
		{name: "loopback rejects malformed address", cfg: PProfConfig{Enabled: true, Mode: "loopback", Address: "not-an-addr"}, wantErr: true},
		{name: "authenticated mode ok", cfg: PProfConfig{Enabled: true, Mode: "authenticated"}},
		{name: "authenticated ignores routable address", cfg: PProfConfig{Enabled: true, Mode: "Authenticated", Address: "0.0.0.0:6060"}},
		{name: "unknown mode rejected", cfg: PProfConfig{Enabled: true, Mode: "public"}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// TestPProfResolvedDefaults checks the mode/address defaulting used by the server
// wiring.
func TestPProfResolvedDefaults(t *testing.T) {
	var zero PProfConfig
	if got := zero.ResolvedMode(); got != PProfModeLoopback {
		t.Errorf("ResolvedMode() = %q, want %q", got, PProfModeLoopback)
	}
	if got := zero.ResolvedAddress(); got != DefaultPProfAddress {
		t.Errorf("ResolvedAddress() = %q, want %q", got, DefaultPProfAddress)
	}
	if got := (PProfConfig{Mode: "  AUTHENTICATED  "}).ResolvedMode(); got != PProfModeAuthenticated {
		t.Errorf("ResolvedMode() trims/lowercases = %q, want %q", got, PProfModeAuthenticated)
	}
}
