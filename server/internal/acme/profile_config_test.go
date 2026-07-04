package acme

import (
	"reflect"
	"testing"
)

// These tests cover the ACME Profiles extension (RFC 9773) resolution helpers on
// Config in isolation — no HSM, DB, or HTTP needed — so they run in the default
// build alongside the tagged end-to-end tests in profile_test.go.

func profilesConfig() Config {
	return Config{
		Profile: "server",
		Profiles: map[string]ACMEProfile{
			"tls-server":  {Description: "Long-lived TLS server", Profile: "server"},
			"mtls-client": {Description: "mTLS client", Profile: "client"},
			// An entry with an empty internal id must fall back to the default.
			"defaulted": {Description: "Uses the default profile"},
		},
	}
}

func TestConfig_resolveProfile_DefaultWhenOmitted(t *testing.T) {
	cfg := profilesConfig()
	// An omitted (empty) selection always resolves to the configured default,
	// keeping pre-extension orders backward compatible.
	got, ok := cfg.resolveProfile("")
	if !ok {
		t.Fatal("resolveProfile(\"\") returned ok=false, want the default")
	}
	if got != "server" {
		t.Errorf("resolveProfile(\"\") = %q, want %q", got, "server")
	}
	// Whitespace-only is treated as omitted.
	if got, ok := cfg.resolveProfile("   "); !ok || got != "server" {
		t.Errorf("resolveProfile(\"   \") = (%q, %v), want (\"server\", true)", got, ok)
	}
}

func TestConfig_resolveProfile_Selection(t *testing.T) {
	cfg := profilesConfig()
	cases := map[string]string{
		"tls-server":  "server",
		"mtls-client": "client",
		"defaulted":   "server", // empty internal id falls back to the default
	}
	for name, want := range cases {
		got, ok := cfg.resolveProfile(name)
		if !ok {
			t.Errorf("resolveProfile(%q) ok=false, want a resolved profile", name)
			continue
		}
		if got != want {
			t.Errorf("resolveProfile(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestConfig_resolveProfile_UnknownRejected(t *testing.T) {
	cfg := profilesConfig()
	if got, ok := cfg.resolveProfile("does-not-exist"); ok {
		t.Errorf("resolveProfile(\"does-not-exist\") = (%q, true), want ok=false", got)
	}
	// Case sensitivity: ACME profile names are matched exactly.
	if _, ok := cfg.resolveProfile("TLS-Server"); ok {
		t.Error("resolveProfile is case-insensitive, want exact-match rejection")
	}
}

func TestConfig_resolveProfile_NoProfilesConfigured(t *testing.T) {
	// With no Profiles map, the extension is off: an omitted selection uses the
	// default, but any explicit selection is unknown (invalidProfile).
	cfg := Config{Profile: "server"}
	if got, ok := cfg.resolveProfile(""); !ok || got != "server" {
		t.Errorf("resolveProfile(\"\") = (%q, %v), want (\"server\", true)", got, ok)
	}
	if _, ok := cfg.resolveProfile("anything"); ok {
		t.Error("resolveProfile(\"anything\") ok=true with no profiles configured, want false")
	}
}

func TestConfig_advertisedProfiles(t *testing.T) {
	cfg := profilesConfig()
	want := map[string]string{
		"tls-server":  "Long-lived TLS server",
		"mtls-client": "mTLS client",
		"defaulted":   "Uses the default profile",
	}
	if got := cfg.advertisedProfiles(); !reflect.DeepEqual(got, want) {
		t.Errorf("advertisedProfiles() = %v, want %v", got, want)
	}
	// With no profiles configured the map is nil, so meta.profiles is omitted
	// entirely and the directory stays byte-for-byte compatible.
	if got := (Config{Profile: "server"}).advertisedProfiles(); got != nil {
		t.Errorf("advertisedProfiles() with no profiles = %v, want nil", got)
	}
}

func TestConfig_profileNames_Sorted(t *testing.T) {
	cfg := profilesConfig()
	got := cfg.profileNames()
	want := []string{"defaulted", "mtls-client", "tls-server"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("profileNames() = %v, want %v (sorted)", got, want)
	}
	if !cfg.profilesEnabled() {
		t.Error("profilesEnabled() = false, want true when Profiles is non-empty")
	}
	if (Config{}).profilesEnabled() {
		t.Error("profilesEnabled() = true for empty Config, want false")
	}
}
