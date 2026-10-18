package keyprovider

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyLabelFor(t *testing.T) {
	cases := []struct{ ref, want string }{
		{"root-ca", "root-ca"},
		{"  root-ca  ", "root-ca"},
		{"software:root-ca", "root-ca"},
		{"pkcs11:object=root-ca;type=private", "root-ca"},
		{"PKCS11:object=root-ca", "root-ca"},
		{"pkcs11:object=my%20ca;serial=0001234", "my ca"},
		{"pkcs11:id=%01%02", ""},  // names a key, but not by label
		{"pkcs11:type=bogus", ""}, // unparseable
		{"", ""},
	}
	for _, tc := range cases {
		if got := KeyLabelFor(tc.ref); got != tc.want {
			t.Errorf("KeyLabelFor(%q) = %q, want %q", tc.ref, got, tc.want)
		}
	}
}

func TestKeySpecForCarriesIDAndTokenPin(t *testing.T) {
	spec := KeySpecFor("pkcs11:object=tsa-key;id=%0a%0b;serial=0001234;slot-id=4",
		KeyTypeRSA4096, KeyUsageSign)
	if spec.Label != "tsa-key" {
		t.Errorf("Label = %q, want tsa-key", spec.Label)
	}
	if spec.ID != "0a0b" {
		t.Errorf("ID = %q, want 0a0b", spec.ID)
	}
	if spec.KeyType != KeyTypeRSA4096 || spec.Usage != KeyUsageSign {
		t.Errorf("KeyType/Usage = %q/%q", spec.KeyType, spec.Usage)
	}
	if spec.Token.Serial != "0001234" {
		t.Errorf("Token.Serial = %q, want 0001234", spec.Token.Serial)
	}
	if spec.Token.SlotID == nil || *spec.Token.SlotID != 4 {
		t.Errorf("Token.SlotID = %v, want 4", spec.Token.SlotID)
	}

	// A bare label behaves exactly as it always did.
	plain := KeySpecFor("tsa-key", KeyTypeRSA2048, KeyUsageDecrypt)
	if plain.Label != "tsa-key" || plain.ID != "" || !plain.Token.IsZero() {
		t.Errorf("bare label spec = %+v, want label only", plain)
	}
}

func TestValidateKeyReference(t *testing.T) {
	cases := []struct {
		name    string
		ref     string
		kind    KeyRefKind
		wantErr string // substring; "" means it must pass
	}{
		{name: "empty is the caller's requiredness rule", ref: ""},
		{name: "bare label", ref: "root-ca"},
		{name: "software uri", ref: "software:root-ca"},
		{name: "object uri", ref: "pkcs11:object=root-ca;type=private"},
		{name: "id uri", ref: "pkcs11:id=%01%02;type=private"},
		{name: "token pinned key", ref: "pkcs11:object=k;serial=0001234;slot-id=2"},
		{name: "public key object", ref: "pkcs11:object=k;type=public"},

		{name: "malformed", ref: "pkcs11:object", wantErr: "missing"},
		{name: "no object", ref: "pkcs11:serial=0001234", wantErr: "names a token but no key"},
		{name: "certificate object", ref: "pkcs11:object=k;type=cert", wantErr: "not a key"},
		{name: "data object", ref: "pkcs11:object=k;type=data", wantErr: "not a key"},
		{name: "module path", ref: "pkcs11:object=k?module-path=/x.so", wantErr: "module is deployment-wide"},
		{name: "module name", ref: "pkcs11:object=k?module-name=softhsm2", wantErr: "module is deployment-wide"},
		{name: "pin value", ref: "pkcs11:object=k?pin-value=1234", wantErr: "PIN is per-token"},
		{name: "pin source", ref: "pkcs11:object=k?pin-source=file:/run/p", wantErr: "PIN is per-token"},
		{name: "typo attribute", ref: "pkcs11:object=k;tokn=t", wantErr: "unrecognized attribute"},

		{name: "family object uri", ref: "pkcs11:object=prod-kek", kind: KeyRefFamilyField},
		{name: "family bare label", ref: "prod-kek", kind: KeyRefFamilyField},
		{name: "family with id", ref: "pkcs11:object=k;id=%01", kind: KeyRefFamilyField, wantErr: "must not pin id="},
		{name: "family id only", ref: "pkcs11:id=%01", kind: KeyRefFamilyField, wantErr: "must set object="},
		{name: "family token pin", ref: "pkcs11:object=k;serial=1", kind: KeyRefFamilyField, wantErr: "must not pin a token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateKeyReference("some.field", tc.ref, tc.kind)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("expected an error containing %q, got nil", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "some.field") {
				t.Errorf("error %q does not name the config field", err)
			}
		})
	}
}

func TestDescribeKeyReferenceRedactsPIN(t *testing.T) {
	got := DescribeKeyReference("pkcs11:object=k?pin-value=supersecret")
	if strings.Contains(got, "supersecret") {
		t.Fatalf("DescribeKeyReference leaked the PIN: %q", got)
	}
	if !strings.Contains(got, "object=k") {
		t.Errorf("DescribeKeyReference = %q, want the object retained", got)
	}
	if got := DescribeKeyReference("plain-label"); got != "plain-label" {
		t.Errorf("DescribeKeyReference(bare) = %q", got)
	}
}

func TestIsPKCS11URI(t *testing.T) {
	for _, s := range []string{"pkcs11:", "PKCS11:object=k", " pkcs11:object=k "} {
		if !IsPKCS11URI(s) {
			t.Errorf("IsPKCS11URI(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "pkcs11", "software:k", "label"} {
		if IsPKCS11URI(s) {
			t.Errorf("IsPKCS11URI(%q) = true, want false", s)
		}
	}
}

func TestApplyPKCS11URIBackfillsSlotAndModel(t *testing.T) {
	s, err := applyPKCS11URI(PKCS11Settings{
		ModulePath: "/explicit.so", // explicit fields win
		URI: "pkcs11:token=tok;serial=ser;model=YubiHSMv2;manufacturer=Yubico;" +
			"slot-id=5;slot-description=Slot%200;slot-manufacturer=SoftHSM" +
			"?module-path=/from-uri.so",
	})
	if err != nil {
		t.Fatalf("applyPKCS11URI: %v", err)
	}
	if s.ModulePath != "/explicit.so" {
		t.Errorf("ModulePath = %q, want the explicit field to win", s.ModulePath)
	}
	if s.TokenLabel != "tok" || s.TokenSerial != "ser" || s.TokenManufacturer != "Yubico" {
		t.Errorf("token selectors not backfilled: %+v", s)
	}
	if s.TokenModel != "YubiHSMv2" {
		t.Errorf("TokenModel = %q, want YubiHSMv2", s.TokenModel)
	}
	if s.SlotID == nil || *s.SlotID != 5 {
		t.Errorf("SlotID = %v, want 5", s.SlotID)
	}
	if s.SlotDescription != "Slot 0" || s.SlotManufacturer != "SoftHSM" {
		t.Errorf("slot selectors = %q / %q", s.SlotDescription, s.SlotManufacturer)
	}
}

func TestApplyPKCS11URIResolvesModuleName(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mymodule.so")
	if err := os.WriteFile(path, []byte("stub"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECSY_PKCS11_MODULE_DIRS", dir)

	s, err := applyPKCS11URI(PKCS11Settings{URI: "pkcs11:token=t?module-name=mymodule"})
	if err != nil {
		t.Fatalf("applyPKCS11URI: %v", err)
	}
	if s.ModulePath != path {
		t.Errorf("ModulePath = %q, want %q", s.ModulePath, path)
	}

	// An unresolvable module-name must fail closed with a clear message rather
	// than leaving ModulePath empty for a later, more confusing error.
	if _, err := applyPKCS11URI(PKCS11Settings{URI: "pkcs11:?module-name=absent"}); err == nil {
		t.Error("unresolvable module-name unexpectedly succeeded")
	}
}

// Every RFC 7512 token *and slot* attribute a key URI can carry must reach the
// selector. One that parses and is then dropped is the silent half-application
// that makes a config say one thing and the signature mean another.
func TestKeyRefCarriesEverySlotSelector(t *testing.T) {
	ref := KeyRefFor("pkcs11:object=k;token=T;serial=S;model=M;manufacturer=MF;" +
		"slot-id=9;slot-description=Slot%200;slot-manufacturer=SoftHSM;type=private")
	want := TokenSelector{
		Label: "T", Serial: "S", Model: "M", Manufacturer: "MF",
		SlotDescription: "Slot 0", SlotManufacturer: "SoftHSM",
	}
	got := ref.Token
	if got.SlotID == nil || *got.SlotID != 9 {
		t.Errorf("SlotID = %v, want 9", got.SlotID)
	}
	got.SlotID = nil
	if got != want {
		t.Errorf("token selector = %+v, want %+v", got, want)
	}
	if ref.Token.IsZero() {
		t.Error("IsZero() = true for a fully pinned selector")
	}
	// Describe names every pinned attribute, so a failure says what was asked for.
	d := ref.Token.Describe()
	for _, want := range []string{"token=", "serial=", "model=", "manufacturer=", "slot-id=9", "slot-description=", "slot-manufacturer="} {
		if !strings.Contains(d, want) {
			t.Errorf("Describe() = %q, missing %q", d, want)
		}
	}
	// And an empty selector still reads as "any token".
	if (TokenSelector{}).Describe() != "(any token)" || !(TokenSelector{}).IsZero() {
		t.Error("the zero selector should be zero and describe as (any token)")
	}
}
