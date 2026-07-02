package ca

import "testing"

// resetCustomProfiles restores the empty custom overlay after a test so the
// package-level state does not leak between tests.
func resetCustomProfiles(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { customProfiles = map[string]Profile{} })
}

func TestSetCustomProfilesAddsAndConverts(t *testing.T) {
	resetCustomProfiles(t)

	err := SetCustomProfiles([]Profile{{
		Name:                "short-client",
		Description:         "Ephemeral client",
		KeyUsages:           []string{"digitalSignature"},
		ExtKeyUsages:        []string{"clientAuth"},
		DefaultValidityDays: 7,
		MaxValidityDays:     30,
	}})
	if err != nil {
		t.Fatalf("SetCustomProfiles: %v", err)
	}

	p, err := LookupProfile("short-client")
	if err != nil {
		t.Fatalf("LookupProfile: %v", err)
	}
	// Day-based config must be folded into concrete durations.
	if p.DefaultValidity != 7*day {
		t.Errorf("DefaultValidity = %v, want 7 days", p.DefaultValidity)
	}
	if p.MaxValidity != 30*day {
		t.Errorf("MaxValidity = %v, want 30 days", p.MaxValidity)
	}

	// It appears in the merged listing alongside the built-ins.
	names := ProfileNames()
	found := false
	for _, n := range names {
		if n == "short-client" {
			found = true
		}
	}
	if !found {
		t.Errorf("custom profile not in ProfileNames(): %v", names)
	}
}

func TestSetCustomProfilesOverridesBuiltin(t *testing.T) {
	resetCustomProfiles(t)

	// A custom "server" tightens the built-in server profile's validity.
	if err := SetCustomProfiles([]Profile{{
		Name:                "server",
		Description:         "Locked-down server",
		KeyUsages:           []string{"digitalSignature"},
		ExtKeyUsages:        []string{"serverAuth"},
		DefaultValidityDays: 30,
		MaxValidityDays:     45,
	}}); err != nil {
		t.Fatal(err)
	}

	p, err := LookupProfile("server")
	if err != nil {
		t.Fatal(err)
	}
	if p.Description != "Locked-down server" {
		t.Errorf("override not applied: description = %q", p.Description)
	}
	if p.MaxValidity != 45*day {
		t.Errorf("override MaxValidity = %v, want 45 days", p.MaxValidity)
	}
}

func TestSetCustomProfilesRejectsUnknownUsage(t *testing.T) {
	resetCustomProfiles(t)

	err := SetCustomProfiles([]Profile{{
		Name:      "bad",
		KeyUsages: []string{"telepathy"},
	}})
	if err == nil {
		t.Fatal("expected error for unknown key usage")
	}
}

func TestSetCustomProfilesRejectsEmptyName(t *testing.T) {
	resetCustomProfiles(t)
	if err := SetCustomProfiles([]Profile{{Name: ""}}); err == nil {
		t.Fatal("expected error for empty profile name")
	}
}
