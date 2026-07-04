package pki

import (
	"bytes"
	"testing"
)

// TestParsePKCS11URIFields drives the parser with RFC 7512 example URIs, checking
// that every path and query attribute is percent-decoded into the right typed
// field, including multi-attribute paths and binary CKA_ID values.
func TestParsePKCS11URIFields(t *testing.T) {
	// The canonical CKA_ID from RFC 7512's examples.
	rfcID := []byte{0x69, 0x95, 0x3e, 0x5c, 0xf4, 0xbd, 0xec, 0x91}

	cases := []struct {
		name  string
		uri   string
		check func(t *testing.T, u *PKCS11URI)
	}{
		{
			name: "empty matches anything",
			uri:  "pkcs11:",
			check: func(t *testing.T, u *PKCS11URI) {
				if u.HasObjectSelector() {
					t.Errorf("empty URI should not select an object")
				}
			},
		},
		{
			name: "object and type",
			uri:  "pkcs11:object=my-pubkey;type=public",
			check: func(t *testing.T, u *PKCS11URI) {
				if u.Object != "my-pubkey" {
					t.Errorf("object = %q, want my-pubkey", u.Object)
				}
				if u.Type != PKCS11TypePublic {
					t.Errorf("type = %q, want public", u.Type)
				}
				if !u.HasObjectSelector() {
					t.Errorf("HasObjectSelector = false, want true")
				}
			},
		},
		{
			name: "percent-encoded token label with spaces",
			uri:  "pkcs11:token=The%20Software%20PKCS%2311%20Softtoken;manufacturer=Snake%20Oil%2C%20Inc.;serial=;model=1.0",
			check: func(t *testing.T, u *PKCS11URI) {
				if u.Token != "The Software PKCS#11 Softtoken" {
					t.Errorf("token = %q", u.Token)
				}
				if u.Manufacturer != "Snake Oil, Inc." {
					t.Errorf("manufacturer = %q", u.Manufacturer)
				}
				if u.Serial != "" {
					t.Errorf("serial = %q, want empty", u.Serial)
				}
				if u.Model != "1.0" {
					t.Errorf("model = %q, want 1.0", u.Model)
				}
			},
		},
		{
			name: "binary CKA_ID with object and type (multi-attribute)",
			uri:  "pkcs11:id=%69%95%3E%5C%F4%BD%EC%91;object=my-certificate;type=cert",
			check: func(t *testing.T, u *PKCS11URI) {
				if !bytes.Equal(u.ID, rfcID) {
					t.Errorf("id = %x, want %x", u.ID, rfcID)
				}
				if u.IDHex() != "69953e5cf4bdec91" {
					t.Errorf("IDHex = %q", u.IDHex())
				}
				if u.Object != "my-certificate" || u.Type != PKCS11TypeCert {
					t.Errorf("object/type = %q/%q", u.Object, u.Type)
				}
			},
		},
		{
			name: "id-only addressing",
			uri:  "pkcs11:id=%69%95%3E%5C%F4%BD%EC%91",
			check: func(t *testing.T, u *PKCS11URI) {
				if !bytes.Equal(u.ID, rfcID) {
					t.Errorf("id = %x, want %x", u.ID, rfcID)
				}
				if u.Object != "" {
					t.Errorf("object = %q, want empty", u.Object)
				}
				if !u.HasObjectSelector() {
					t.Errorf("id-only URI must select an object")
				}
			},
		},
		{
			name: "library attributes and version",
			uri:  "pkcs11:library-manufacturer=Snake%20Oil%2C%20Inc.;library-description=Soft%20Token%20Library;library-version=1.23",
			check: func(t *testing.T, u *PKCS11URI) {
				if u.LibraryManufacturer != "Snake Oil, Inc." {
					t.Errorf("library-manufacturer = %q", u.LibraryManufacturer)
				}
				if u.LibraryDescription != "Soft Token Library" {
					t.Errorf("library-description = %q", u.LibraryDescription)
				}
				if u.LibraryVersion != "1.23" {
					t.Errorf("library-version = %q", u.LibraryVersion)
				}
			},
		},
		{
			name: "slot attributes with decimal slot-id",
			uri:  "pkcs11:slot-description=Sun%20Metaslot;slot-manufacturer=Oracle;slot-id=42",
			check: func(t *testing.T, u *PKCS11URI) {
				if u.SlotDescription != "Sun Metaslot" {
					t.Errorf("slot-description = %q", u.SlotDescription)
				}
				if u.SlotManufacturer != "Oracle" {
					t.Errorf("slot-manufacturer = %q", u.SlotManufacturer)
				}
				if u.SlotID == nil || *u.SlotID != 42 {
					t.Errorf("slot-id = %v, want 42", u.SlotID)
				}
			},
		},
		{
			name: "query module-name",
			uri:  "pkcs11:object=my-sign-key;type=private?module-name=mypkcs11",
			check: func(t *testing.T, u *PKCS11URI) {
				if u.ModuleName != "mypkcs11" {
					t.Errorf("module-name = %q", u.ModuleName)
				}
				if u.Object != "my-sign-key" || u.Type != PKCS11TypePrivate {
					t.Errorf("object/type = %q/%q", u.Object, u.Type)
				}
			},
		},
		{
			name: "query module-path with slashes",
			uri:  "pkcs11:object=my-sign-key;type=private?module-path=/mnt/libmypkcs11.so.1",
			check: func(t *testing.T, u *PKCS11URI) {
				if u.ModulePath != "/mnt/libmypkcs11.so.1" {
					t.Errorf("module-path = %q", u.ModulePath)
				}
			},
		},
		{
			name: "query pin-source file URI",
			uri:  "pkcs11:object=my-key;type=private?pin-source=file:/etc/token",
			check: func(t *testing.T, u *PKCS11URI) {
				if u.PinSource != "file:/etc/token" {
					t.Errorf("pin-source = %q", u.PinSource)
				}
			},
		},
		{
			name: "query pin-value and multiple query attrs",
			uri:  "pkcs11:token=softtoken?module-path=/usr/lib/pkcs11.so&pin-value=the-pin",
			check: func(t *testing.T, u *PKCS11URI) {
				if u.Token != "softtoken" {
					t.Errorf("token = %q", u.Token)
				}
				if u.ModulePath != "/usr/lib/pkcs11.so" {
					t.Errorf("module-path = %q", u.ModulePath)
				}
				if u.PinValue != "the-pin" {
					t.Errorf("pin-value = %q", u.PinValue)
				}
			},
		},
		{
			name: "vendor attribute preserved",
			uri:  "pkcs11:object=k;vendor-foo=bar",
			check: func(t *testing.T, u *PKCS11URI) {
				if u.Unknown["vendor-foo"] != "bar" {
					t.Errorf("Unknown[vendor-foo] = %q, want bar", u.Unknown["vendor-foo"])
				}
			},
		},
		{
			name: "case-insensitive scheme",
			uri:  "PKCS11:object=k",
			check: func(t *testing.T, u *PKCS11URI) {
				if u.Object != "k" {
					t.Errorf("object = %q", u.Object)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, err := ParsePKCS11URI(tc.uri)
			if err != nil {
				t.Fatalf("ParsePKCS11URI(%q) error: %v", tc.uri, err)
			}
			tc.check(t, u)
		})
	}
}

// TestParsePKCS11URIErrors checks the parser rejects malformed input rather than
// silently passing it through — important for the doctor URI check.
func TestParsePKCS11URIErrors(t *testing.T) {
	bad := []string{
		"",                                // no scheme
		"https://example.com",             // wrong scheme
		"pkcs11:object",                   // attribute without "="
		"pkcs11:object=a;object=b",        // duplicate attribute
		"pkcs11:type=bogus",               // invalid object type
		"pkcs11:slot-id=-1",               // negative slot-id
		"pkcs11:slot-id=abc",              // non-numeric slot-id
		"pkcs11:library-version=x.y",      // non-numeric version
		"pkcs11:object=%zz",               // invalid percent-encoding
		"pkcs11:object=a%2",               // truncated percent-encoding
		"pkcs11:object=a;;type=private",   // empty (stray ;) path attribute
		"pkcs11:token=a?pin-value=x&&y=z", // empty (stray &) query attribute
	}
	for _, uri := range bad {
		t.Run(uri, func(t *testing.T) {
			if u, err := ParsePKCS11URI(uri); err == nil {
				t.Errorf("ParsePKCS11URI(%q) = %+v, want error", uri, u)
			}
		})
	}
}

// TestPKCS11URIRoundTrip verifies String re-serializes to a form that parses back
// to an equivalent URI, including binary id bytes and percent-encoded specials.
func TestPKCS11URIRoundTrip(t *testing.T) {
	uris := []string{
		"pkcs11:",
		"pkcs11:object=my-certificate;type=cert",
		"pkcs11:id=%69%95%3E%5C%F4%BD%EC%91;object=my-key;type=private",
		"pkcs11:token=The%20Software%20PKCS%2311%20Softtoken;manufacturer=Snake%20Oil%2C%20Inc.;model=1.0;object=k;type=private;slot-id=3",
		"pkcs11:object=k?module-path=/usr/lib/pkcs11.so&pin-source=file:/etc/pin",
	}
	for _, uri := range uris {
		t.Run(uri, func(t *testing.T) {
			u1, err := ParsePKCS11URI(uri)
			if err != nil {
				t.Fatalf("parse %q: %v", uri, err)
			}
			round := u1.String()
			u2, err := ParsePKCS11URI(round)
			if err != nil {
				t.Fatalf("re-parse %q (from %q): %v", round, uri, err)
			}
			if !equalURIs(u1, u2) {
				t.Errorf("round-trip mismatch:\n  in:  %q\n  out: %q\n  %+v\n  %+v", uri, round, u1, u2)
			}
		})
	}
}

// TestPKCS11URIRedactedString proves an embedded pin-value is masked while every
// other attribute survives, so a URI carrying a PIN can be logged safely.
func TestPKCS11URIRedactedString(t *testing.T) {
	u, err := ParsePKCS11URI("pkcs11:token=softtoken;object=k?module-path=/lib/p11.so&pin-value=s3cr3t")
	if err != nil {
		t.Fatal(err)
	}
	red := u.RedactedString()
	if bytes.Contains([]byte(red), []byte("s3cr3t")) {
		t.Errorf("RedactedString leaked the PIN: %q", red)
	}
	// The non-secret attributes must remain.
	reparsed, err := ParsePKCS11URI(red)
	if err != nil {
		t.Fatalf("redacted string does not re-parse: %v", err)
	}
	if reparsed.Token != "softtoken" || reparsed.Object != "k" || reparsed.ModulePath != "/lib/p11.so" {
		t.Errorf("redaction dropped non-secret attributes: %+v", reparsed)
	}
	// A URI with no pin-value is unchanged.
	clean, _ := ParsePKCS11URI("pkcs11:object=k")
	if clean.RedactedString() != clean.String() {
		t.Errorf("RedactedString altered a URI with no pin-value")
	}
}

// TestExtractKeyLabelPercentDecoding confirms the back-compat helper now
// percent-decodes the object label while preserving its historical behavior.
func TestExtractKeyLabelPercentDecoding(t *testing.T) {
	cases := map[string]string{
		"pkcs11:token=secsy;object=root%2Dca;type=private": "root-ca",
		"pkcs11:object=my%20key":                           "my key",
		"software:my-key":                                  "my-key",
		"pkcs11:id=%ab%cd":                                 "", // no object= → empty label
		"bare-label-no-scheme":                             "",
	}
	for uri, want := range cases {
		if got := ExtractKeyLabel(uri); got != want {
			t.Errorf("ExtractKeyLabel(%q) = %q, want %q", uri, got, want)
		}
	}
}

// equalURIs compares two parsed URIs field-by-field for the round-trip test.
func equalURIs(a, b *PKCS11URI) bool {
	if a.Token != b.Token || a.Manufacturer != b.Manufacturer || a.Serial != b.Serial || a.Model != b.Model {
		return false
	}
	if a.LibraryManufacturer != b.LibraryManufacturer || a.LibraryDescription != b.LibraryDescription || a.LibraryVersion != b.LibraryVersion {
		return false
	}
	if a.SlotManufacturer != b.SlotManufacturer || a.SlotDescription != b.SlotDescription {
		return false
	}
	if (a.SlotID == nil) != (b.SlotID == nil) || (a.SlotID != nil && *a.SlotID != *b.SlotID) {
		return false
	}
	if a.Object != b.Object || a.Type != b.Type || !bytes.Equal(a.ID, b.ID) {
		return false
	}
	if a.ModuleName != b.ModuleName || a.ModulePath != b.ModulePath || a.PinSource != b.PinSource || a.PinValue != b.PinValue {
		return false
	}
	return true
}
