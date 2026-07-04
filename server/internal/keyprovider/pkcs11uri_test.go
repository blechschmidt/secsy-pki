package keyprovider

import (
	"testing"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// TestKeyRefFromURI checks the three accepted key-reference forms map onto a
// KeyRef, and that RFC 7512 object (object=/id=) and token (serial/slot-id/token)
// selectors are threaded through.
func TestKeyRefFromURI(t *testing.T) {
	slot7 := uint(7)
	cases := []struct {
		name    string
		in      string
		want    KeyRef
		wantErr bool
	}{
		{
			name: "object label",
			in:   "pkcs11:token=secsy;object=root-ca;type=private",
			want: KeyRef{Label: "root-ca", Token: TokenSelector{Label: "secsy"}},
		},
		{
			name: "cka_id only",
			in:   "pkcs11:id=%ab%cd;type=private",
			want: KeyRef{ID: "abcd"},
		},
		{
			name: "label and id",
			in:   "pkcs11:object=k;id=%01%02",
			want: KeyRef{Label: "k", ID: "0102"},
		},
		{
			name: "token serial pin",
			in:   "pkcs11:serial=SER123;object=ca",
			want: KeyRef{Label: "ca", Token: TokenSelector{Serial: "SER123"}},
		},
		{
			name: "slot-id pin",
			in:   "pkcs11:slot-id=7;object=ca",
			want: KeyRef{Label: "ca", Token: TokenSelector{SlotID: &slot7}},
		},
		{
			name: "software shorthand",
			in:   "software:my-key",
			want: KeyRef{Label: "my-key"},
		},
		{
			name: "bare label shorthand",
			in:   "just-a-label",
			want: KeyRef{Label: "just-a-label"},
		},
		{
			name:    "empty",
			in:      "",
			wantErr: true,
		},
		{
			name:    "malformed pkcs11 uri",
			in:      "pkcs11:type=bogus",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := KeyRefFromURI(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("KeyRefFromURI(%q) = %+v, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("KeyRefFromURI(%q) error: %v", tc.in, err)
			}
			if got.Label != tc.want.Label || got.ID != tc.want.ID {
				t.Errorf("label/id = %q/%q, want %q/%q", got.Label, got.ID, tc.want.Label, tc.want.ID)
			}
			if got.Token.Label != tc.want.Token.Label || got.Token.Serial != tc.want.Token.Serial {
				t.Errorf("token = %+v, want %+v", got.Token, tc.want.Token)
			}
			if (got.Token.SlotID == nil) != (tc.want.Token.SlotID == nil) ||
				(got.Token.SlotID != nil && *got.Token.SlotID != *tc.want.Token.SlotID) {
				t.Errorf("token slot-id = %v, want %v", got.Token.SlotID, tc.want.Token.SlotID)
			}
		})
	}
}

// TestKeyRefFor checks the never-erroring config helper: a bare label passes
// through unchanged, a URI is parsed, and an unparseable value degrades to a bare
// label rather than failing.
func TestKeyRefFor(t *testing.T) {
	if got := KeyRefFor("tsa-key"); got.Label != "tsa-key" || got.ID != "" {
		t.Errorf("bare label: %+v", got)
	}
	if got := KeyRefFor("pkcs11:serial=SER;object=tsa-key"); got.Label != "tsa-key" || got.Token.Serial != "SER" {
		t.Errorf("uri: %+v", got)
	}
	if got := KeyRefFor("pkcs11:id=%ab"); got.ID != "ab" || got.Label != "" {
		t.Errorf("id uri: %+v", got)
	}
	// A malformed URI falls back to a bare label (never errors).
	if got := KeyRefFor("pkcs11:type=bogus"); got.Label != "pkcs11:type=bogus" {
		t.Errorf("malformed fallback: %+v", got)
	}
}

// TestLocatorForFromURI proves a URI-derived KeyRef lowers to a pki.KeyLocator
// with the CKA_ID decoded back to raw bytes.
func TestLocatorForFromURI(t *testing.T) {
	ref, err := KeyRefFromURI("pkcs11:id=%ab%cd")
	if err != nil {
		t.Fatal(err)
	}
	loc, err := locatorFor(ref)
	if err != nil {
		t.Fatal(err)
	}
	if loc.Label != "" || len(loc.ID) != 2 || loc.ID[0] != 0xab || loc.ID[1] != 0xcd {
		t.Errorf("locator = %+v, want id ab cd", loc)
	}
	// A bad hex CKA_ID must be rejected.
	if _, err := locatorFor(KeyRef{ID: "zz"}); err == nil {
		t.Error("locatorFor accepted a non-hex CKA_ID")
	}
	// A ref with neither label nor id is rejected.
	if _, err := locatorFor(KeyRef{}); err == nil {
		t.Error("locatorFor accepted an empty ref")
	}
}

// TestPinSourceFromURI maps the URI PIN query attributes onto Task 111 settings.
func TestPinSourceFromURI(t *testing.T) {
	mustParse := func(s string) *pki.PKCS11URI {
		u, err := pki.ParsePKCS11URI(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		return u
	}

	// pin-value → inline PIN.
	if s, pin, ok, err := PinSourceFromURI(mustParse("pkcs11:token=t?pin-value=1234")); err != nil || !ok || pin != "1234" || s.Type != "" {
		t.Errorf("pin-value: settings=%+v pin=%q ok=%v err=%v", s, pin, ok, err)
	}
	// pin-source=file:/path → file source.
	if s, _, ok, err := PinSourceFromURI(mustParse("pkcs11:token=t?pin-source=file:/etc/hsm.pin")); err != nil || !ok || s.Type != "file" || s.File.Path != "/etc/hsm.pin" {
		t.Errorf("pin-source file: settings=%+v ok=%v err=%v", s, ok, err)
	}
	// bare path pin-source → file source.
	if s, _, ok, err := PinSourceFromURI(mustParse("pkcs11:token=t?pin-source=/run/pin")); err != nil || !ok || s.Type != "file" || s.File.Path != "/run/pin" {
		t.Errorf("pin-source bare path: settings=%+v ok=%v err=%v", s, ok, err)
	}
	// unsupported scheme → error.
	if _, _, _, err := PinSourceFromURI(mustParse("pkcs11:token=t?pin-source=https://vault/pin")); err == nil {
		t.Error("PinSourceFromURI accepted an unsupported pin-source scheme")
	}
	// neither → ok=false.
	if _, _, ok, _ := PinSourceFromURI(mustParse("pkcs11:token=t")); ok {
		t.Error("PinSourceFromURI reported ok for a URI without PIN attributes")
	}
}

// TestApplyPKCS11URIBackfill checks a URI backfills only the unset module/token/
// PIN fields, and that explicit fields win.
func TestApplyPKCS11URIBackfill(t *testing.T) {
	// Backfill everything from the URI.
	s, err := applyPKCS11URI(PKCS11Settings{
		URI: "pkcs11:token=tok1;serial=SER1;manufacturer=ACME?module-path=/lib/p11.so&pin-value=4321",
	})
	if err != nil {
		t.Fatal(err)
	}
	if s.ModulePath != "/lib/p11.so" || s.TokenLabel != "tok1" || s.TokenSerial != "SER1" || s.TokenManufacturer != "ACME" {
		t.Errorf("backfill: %+v", s)
	}
	if s.Pin != "4321" || s.PinSource.Type != "" {
		t.Errorf("pin backfill: pin=%q source=%q", s.Pin, s.PinSource.Type)
	}

	// Explicit fields take precedence over the URI.
	s2, err := applyPKCS11URI(PKCS11Settings{
		ModulePath: "/explicit.so",
		TokenLabel: "explicit",
		Pin:        "explicit-pin",
		URI:        "pkcs11:token=uri-tok?module-path=/uri.so&pin-value=uri-pin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if s2.ModulePath != "/explicit.so" || s2.TokenLabel != "explicit" || s2.Pin != "explicit-pin" {
		t.Errorf("explicit fields overridden by URI: %+v", s2)
	}

	// A malformed URI is an error.
	if _, err := applyPKCS11URI(PKCS11Settings{URI: "pkcs11:type=bogus"}); err == nil {
		t.Error("applyPKCS11URI accepted a malformed URI")
	}

	// No URI is a no-op.
	in := PKCS11Settings{ModulePath: "/m.so", TokenLabel: "t"}
	if out, err := applyPKCS11URI(in); err != nil || out.ModulePath != in.ModulePath || out.TokenLabel != in.TokenLabel || out.URI != "" {
		t.Errorf("no-URI changed settings: %+v -> %+v (%v)", in, out, err)
	}
}

// TestNewPKCS11ProviderFromURI proves the URI wiring flows through the
// constructor: a provider built from a URI-only settings resolves its PIN.
func TestNewPKCS11ProviderFromURI(t *testing.T) {
	p, err := NewPKCS11Provider(PKCS11Settings{
		URI: "pkcs11:token=tok?module-path=/nonexistent/p11.so&pin-value=secret-pin",
	})
	if err != nil {
		t.Fatalf("NewPKCS11Provider from URI: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if p.cfg.ModulePath != "/nonexistent/p11.so" || p.cfg.TokenLabel != "tok" {
		t.Errorf("cfg not backfilled from URI: %+v", p.cfg)
	}
	// The PIN source resolves to the URI's pin-value (no HSM needed).
	pin, err := p.pinSource.Resolve(t.Context())
	if err != nil || pin != "secret-pin" {
		t.Errorf("pin source resolve = %q, %v; want secret-pin", pin, err)
	}
}

// TestHATokenSelectorMatching exercises selectMatching over configured member
// serials without touching a token: an operation can be pinned to a specific
// replica by serial even though replicas share a CKA_LABEL.
func TestHATokenSelectorMatching(t *testing.T) {
	newMember := func(name, serial string) *haMember {
		return &haMember{name: name, healthy: true, cfgSerial: serial, cfgLabel: "shared-label"}
	}
	a := newMember("a", "SER-A")
	b := newMember("b", "SER-B")
	unknown := newMember("u", "") // serial not configured → cannot be disproven
	members := []*haMember{a, b, unknown}

	// Exact serial match selects only that member (preferred over the unknown one).
	got, err := selectMatching(members, TokenSelector{Serial: "SER-A"})
	if err != nil {
		t.Fatalf("selectMatching SER-A: %v", err)
	}
	if len(got) != 1 || got[0] != a {
		t.Errorf("SER-A selected %v, want [a]", names(got))
	}

	// A serial no member is configured with still matches the "unknown" member
	// (possible), since its serial cannot be disproven before the token is live.
	got, err = selectMatching(members, TokenSelector{Serial: "SER-Z"})
	if err != nil {
		t.Fatalf("selectMatching SER-Z: %v", err)
	}
	if len(got) != 1 || got[0] != unknown {
		t.Errorf("SER-Z selected %v, want [u] (possible)", names(got))
	}

	// A selector that contradicts every member (all serials known and different)
	// fails closed.
	known := []*haMember{a, b}
	if _, err := selectMatching(known, TokenSelector{Serial: "SER-Z"}); err == nil {
		t.Error("selectMatching accepted a selector no token matches")
	}

	// Label match selects both replicas (they share the label).
	got, err = selectMatching([]*haMember{a, b}, TokenSelector{Label: "shared-label"})
	if err != nil || len(got) != 2 {
		t.Errorf("label match selected %v (%v), want both", names(got), err)
	}
}

func names(ms []*haMember) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.name
	}
	return out
}
