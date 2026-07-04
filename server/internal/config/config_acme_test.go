package config

import (
	"strings"
	"testing"
)

// TestACMEProfilesParse confirms the ACME Profiles extension (RFC 9773) map
// parses from YAML into the ACME-visible-name → (description, internal profile)
// mapping the server consumes.
func TestACMEProfilesParse(t *testing.T) {
	cfg := writeAndLoad(t, `
root_user:
  password: secret
acme:
  enabled: true
  ca_id: issuing-ca
  profile: server
  profiles:
    short-lived:
      description: "90-day TLS server certificates"
      profile: server
    mtls-client:
      description: "Client-authentication certificates"
      profile: client
    take-default:
      description: "Uses the default profile"
`)
	got := cfg.ACME.Profiles
	if len(got) != 3 {
		t.Fatalf("parsed %d acme profiles, want 3: %+v", len(got), got)
	}
	if got["short-lived"].Description != "90-day TLS server certificates" || got["short-lived"].Profile != "server" {
		t.Errorf("short-lived = %+v", got["short-lived"])
	}
	if got["mtls-client"].Profile != "client" {
		t.Errorf("mtls-client.Profile = %q, want client", got["mtls-client"].Profile)
	}
	// An entry may omit the internal profile id (falls back to the default at
	// runtime); parsing leaves it empty.
	if got["take-default"].Profile != "" {
		t.Errorf("take-default.Profile = %q, want empty", got["take-default"].Profile)
	}
}

// TestACMEProfilesRejectEmptyName confirms a profile with an empty ACME-visible
// name (map key) is rejected at load time.
func TestACMEProfilesRejectEmptyName(t *testing.T) {
	_, err := loadContent(t, `
root_user:
  password: secret
acme:
  enabled: true
  ca_id: issuing-ca
  profiles:
    "":
      profile: server
`)
	if err == nil {
		t.Fatal("expected an error for an empty ACME profile name")
	}
	if !strings.Contains(err.Error(), "profile name") {
		t.Errorf("error = %v, want it to mention the empty profile name", err)
	}
}
