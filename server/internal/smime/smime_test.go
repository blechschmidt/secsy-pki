package smime

import (
	"strings"
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string // expected Address(); "" means an error is expected
		errPart string // substring the error must contain (optional)
	}{
		{name: "simple", in: "alice@example.com", want: "alice@example.com"},
		{name: "domain case folded", in: "Alice.Smith@EXAMPLE.Com", want: "Alice.Smith@example.com"},
		{name: "local case preserved", in: "MixedCase@example.com", want: "MixedCase@example.com"},
		{name: "surrounding whitespace trimmed", in: "  alice@example.com  ", want: "alice@example.com"},
		{name: "trailing dot stripped", in: "alice@example.com.", want: "alice@example.com"},
		{name: "atext specials allowed", in: "o'brien+tag_1{x}~=?^`|/!#$%&*@example.com", want: "o'brien+tag_1{x}~=?^`|/!#$%&*@example.com"},
		{name: "idn domain punycoded", in: "post@bücher.example", want: "post@xn--bcher-kva.example"},
		{name: "idn uppercase punycoded", in: "post@BÜCHER.example", want: "post@xn--bcher-kva.example"},
		{name: "existing a-label kept", in: "post@xn--bcher-kva.example", want: "post@xn--bcher-kva.example"},
		{name: "subdomain", in: "bob@mail.corp.example.org", want: "bob@mail.corp.example.org"},

		{name: "empty", in: "", errPart: "empty"},
		{name: "whitespace only", in: "   ", errPart: "empty"},
		{name: "display name form", in: "Alice <alice@example.com>", errPart: "display name"},
		{name: "no at", in: "alice.example.com", errPart: "exactly one '@'"},
		{name: "two ats", in: "alice@bob@example.com", errPart: "exactly one '@'"},
		{name: "empty local", in: "@example.com", errPart: "local part is empty"},
		{name: "empty domain", in: "alice@", errPart: "domain is empty"},
		{name: "quoted local", in: `"alice smith"@example.com`, errPart: "quoted local parts"},
		{name: "leading dot", in: ".alice@example.com", errPart: "dot-atom"},
		{name: "trailing dot local", in: "alice.@example.com", errPart: "dot-atom"},
		{name: "double dot", in: "a..b@example.com", errPart: "dot-atom"},
		{name: "space in local", in: "a b@example.com", errPart: "invalid character"},
		{name: "utf8 local rejected", in: "grüße@example.com", errPart: "SmtpUTF8Mailbox"},
		{name: "local too long", in: strings.Repeat("a", 65) + "@example.com", errPart: "64 octets"},
		{name: "single-label domain", in: "alice@localhost", errPart: "two labels"},
		{name: "address literal", in: "alice@[192.0.2.1]", errPart: "address-literal"},
		{name: "underscore in domain", in: "alice@my_host.example.com", errPart: "not a valid DNS name"},
		{name: "domain empty label", in: "alice@ex..com", errPart: "empty label"},
		{name: "domain leading hyphen", in: "alice@-bad.example.com", errPart: "not a valid DNS name"},
		{name: "domain label too long", in: "alice@" + strings.Repeat("a", 64) + ".com", errPart: "longer than 63"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NormalizeEmail(tc.in)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("NormalizeEmail(%q) = %q, want error", tc.in, m.Address())
				}
				if tc.errPart != "" && !strings.Contains(err.Error(), tc.errPart) {
					t.Fatalf("NormalizeEmail(%q) error %q does not mention %q", tc.in, err, tc.errPart)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeEmail(%q): %v", tc.in, err)
			}
			if got := m.Address(); got != tc.want {
				t.Fatalf("NormalizeEmail(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMailboxEqual(t *testing.T) {
	a, err := NormalizeEmail("Alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NormalizeEmail("alice@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(b) {
		t.Fatalf("%q and %q should compare equal", a.Address(), b.Address())
	}
	c, err := NormalizeEmail("alice@other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if a.Equal(c) {
		t.Fatalf("%q and %q should not compare equal", a.Address(), c.Address())
	}
}

func TestNormalizeAll(t *testing.T) {
	got, err := NormalizeAll([]string{"Alice@EXAMPLE.com", "alice@example.com", "bob@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected duplicates folded to 2 entries, got %d: %v", len(got), got)
	}
	// The first spelling wins: local-part case preserved from the first entry.
	if got[0].Address() != "Alice@example.com" || got[1].Address() != "bob@example.com" {
		t.Fatalf("unexpected normalization: %v", got)
	}

	if _, err := NormalizeAll([]string{"ok@example.com", "not an address"}); err == nil {
		t.Fatal("expected an error for the invalid entry")
	}
}

func TestDomainAllowlist(t *testing.T) {
	al, err := NewDomainAllowlist([]string{"example.com", "*.corp.example.org", "bücher.example", " "})
	if err != nil {
		t.Fatal(err)
	}
	if al.Empty() {
		t.Fatal("allowlist with entries should not be Empty")
	}

	cases := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"sub.example.com", false},      // exact entry does not cover subdomains
		{"mail.corp.example.org", true}, // wildcard covers subdomains
		{"a.b.corp.example.org", true},  // ... at any depth
		{"corp.example.org", false},     // ... but not the apex
		{"evilcorp.example.org", false}, // suffix match must be on a label boundary
		{"xn--bcher-kva.example", true}, // U-label entry matches punycoded domain
		{"other.example", false},
	}
	for _, tc := range cases {
		if got := al.Allows(tc.domain); got != tc.want {
			t.Errorf("Allows(%q) = %v, want %v", tc.domain, got, tc.want)
		}
	}

	empty, err := NewDomainAllowlist(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !empty.Empty() || !empty.Allows("anything.example") {
		t.Fatal("empty allowlist must allow everything")
	}
	var nilList *DomainAllowlist
	if !nilList.Empty() || !nilList.Allows("anything.example") {
		t.Fatal("nil allowlist must allow everything")
	}

	if _, err := NewDomainAllowlist([]string{"bad_domain.example"}); err == nil {
		t.Fatal("expected an error for an invalid allowlist entry")
	}
	if _, err := NewDomainAllowlist([]string{"*.single"}); err == nil {
		t.Fatal("expected an error for a single-label wildcard entry")
	}
}
