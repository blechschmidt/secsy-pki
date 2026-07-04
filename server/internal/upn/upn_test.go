package upn

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in        string
		wantLocal string
		wantRealm string
		wantErr   bool
	}{
		{in: "alice@EXAMPLE.COM", wantLocal: "alice", wantRealm: "EXAMPLE.COM"},
		{in: "  bob@corp.example.com  ", wantLocal: "bob", wantRealm: "corp.example.com"}, // trimmed
		{in: "svc-01@example.io", wantLocal: "svc-01", wantRealm: "example.io"},
		{in: "user@REALM", wantLocal: "user", wantRealm: "REALM"}, // single-label Kerberos realm
		{in: "a.b.c@example.com", wantLocal: "a.b.c", wantRealm: "example.com"},
		{in: "user@example.com.", wantLocal: "user", wantRealm: "example.com."}, // trailing dot preserved in value

		{in: "", wantErr: true},
		{in: "noatsign", wantErr: true},
		{in: "@example.com", wantErr: true},          // empty local
		{in: "user@", wantErr: true},                 // empty realm
		{in: "a@b@example.com", wantErr: true},       // two '@'
		{in: "user name@example.com", wantErr: true}, // embedded space
		{in: "user@exa mple.com", wantErr: true},     // space in realm
		{in: "user@exam_ple.com", wantErr: true},     // underscore not LDH
		{in: "user@[192.0.2.1]", wantErr: true},      // IP literal
		{in: "user@-example.com", wantErr: true},     // leading hyphen label
		{in: "user@exa..mple.com", wantErr: true},    // empty label
	}
	for _, c := range cases {
		u, err := Parse(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Parse(%q) = %+v, want error", c.in, u)
			}
			continue
		}
		if err != nil {
			t.Errorf("Parse(%q) error: %v", c.in, err)
			continue
		}
		if u.Local != c.wantLocal || u.Realm != c.wantRealm {
			t.Errorf("Parse(%q) = {Local:%q Realm:%q}, want {Local:%q Realm:%q}", c.in, u.Local, u.Realm, c.wantLocal, c.wantRealm)
		}
	}
}

func TestParsePreservesValue(t *testing.T) {
	// The certificate must carry exactly what was enrolled (case preserved), so
	// Windows can match it against the userPrincipalName attribute.
	u, err := Parse("Alice.Smith@Corp.Example.COM")
	if err != nil {
		t.Fatal(err)
	}
	if u.Value != "Alice.Smith@Corp.Example.COM" {
		t.Errorf("Value = %q, want the enrolled spelling preserved", u.Value)
	}
}

func TestNormalizeAllDedup(t *testing.T) {
	// Duplicates fold case; the first spelling wins.
	got, err := NormalizeAll([]string{"alice@EXAMPLE.COM", "ALICE@example.com", "bob@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("NormalizeAll returned %d UPNs, want 2 (deduped): %v", len(got), got)
	}
	if got[0].Value != "alice@EXAMPLE.COM" {
		t.Errorf("first spelling should win, got %q", got[0].Value)
	}
}

func TestRealmAllowlist(t *testing.T) {
	al, err := NewRealmAllowlist([]string{"EXAMPLE.COM", "*.corp.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		realm string
		allow bool
	}{
		{"EXAMPLE.COM", true},
		{"example.com", true},  // case-insensitive
		{"example.com.", true}, // trailing dot folded
		{"other.com", false},
		{"eu.corp.example.net", true},  // wildcard subtree
		{"corp.example.net", false},    // wildcard excludes the apex
		{"a.b.corp.example.net", true}, // deeper subtree
		{"corp.example.org", false},
	}
	for _, c := range cases {
		if got := al.Allows(c.realm); got != c.allow {
			t.Errorf("Allows(%q) = %v, want %v", c.realm, got, c.allow)
		}
	}
}

func TestRealmAllowlistEmptyAllowsAll(t *testing.T) {
	al, err := NewRealmAllowlist(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !al.Empty() {
		t.Fatal("nil-entry allowlist should be Empty")
	}
	if !al.Allows("anything.example") {
		t.Error("empty allowlist must allow every realm")
	}
	// A nil *RealmAllowlist is also Empty and allow-all (tenant with no scoping).
	var nilAL *RealmAllowlist
	if !nilAL.Empty() || !nilAL.Allows("x.example") {
		t.Error("nil allowlist must be Empty and allow-all")
	}
}

func TestRealmAllowlistInvalidEntry(t *testing.T) {
	if _, err := NewRealmAllowlist([]string{"exa mple.com"}); err == nil {
		t.Error("invalid realm entry should error at construction")
	}
}
