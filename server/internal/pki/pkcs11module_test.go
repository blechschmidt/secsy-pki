package pki

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakeModule creates an empty file that stands in for a PKCS#11 shared
// object; resolution only stats the path, it does not dlopen it.
func writeFakeModule(t *testing.T, dir, name string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("not-really-a-library"), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func TestResolveModuleNameFromSearchDirs(t *testing.T) {
	root := t.TempDir()
	dirA := filepath.Join(root, "a")
	dirB := filepath.Join(root, "b")
	want := writeFakeModule(t, dirB, "yubihsm_pkcs11.so")
	if err := os.MkdirAll(dirA, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv(ModuleDirsEnv, dirA+string(os.PathListSeparator)+dirB)

	got, err := ResolveModuleName("yubihsm_pkcs11")
	if err != nil {
		t.Fatalf("ResolveModuleName: %v", err)
	}
	if got != want {
		t.Errorf("ResolveModuleName = %q, want %q", got, want)
	}

	// The ".so" suffix is optional in the URI, and supplying it must not
	// produce "name.so.so".
	got, err = ResolveModuleName("yubihsm_pkcs11.so")
	if err != nil {
		t.Fatalf("ResolveModuleName(with .so): %v", err)
	}
	if got != want {
		t.Errorf("ResolveModuleName(with .so) = %q, want %q", got, want)
	}
}

func TestResolveModuleNameNotFoundNamesSearchPath(t *testing.T) {
	t.Setenv(ModuleDirsEnv, t.TempDir())
	_, err := ResolveModuleName("nosuchmodule")
	if err == nil {
		t.Fatal("ResolveModuleName unexpectedly succeeded")
	}
	// The error has to be actionable: it must say what was searched and what
	// to set instead, because the alternative is a dlopen failure at the first
	// signature with no mention of the name that was wrong.
	for _, want := range []string{"nosuchmodule", "searched", ModuleDirsEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestResolveModuleNameAcceptsAnExistingPath(t *testing.T) {
	path := writeFakeModule(t, t.TempDir(), "libsofthsm2.so")
	t.Setenv(ModuleDirsEnv, t.TempDir()) // deliberately not where the file is
	got, err := ResolveModuleName(path)
	if err != nil {
		t.Fatalf("ResolveModuleName(abs path): %v", err)
	}
	if got != path {
		t.Errorf("ResolveModuleName = %q, want %q", got, path)
	}
}

func TestResolveModulePathPrefersModulePath(t *testing.T) {
	u, err := ParsePKCS11URI("pkcs11:token=t?module-path=/opt/custom/p11.so&module-name=ignored")
	if err != nil {
		t.Fatalf("ParsePKCS11URI: %v", err)
	}
	got, err := u.ResolveModulePath()
	if err != nil {
		t.Fatalf("ResolveModulePath: %v", err)
	}
	if got != "/opt/custom/p11.so" {
		t.Errorf("ResolveModulePath = %q, want the explicit module-path", got)
	}
}

func TestResolveModulePathEmptyWhenNoModuleNamed(t *testing.T) {
	u, err := ParsePKCS11URI("pkcs11:token=t")
	if err != nil {
		t.Fatalf("ParsePKCS11URI: %v", err)
	}
	got, err := u.ResolveModulePath()
	if err != nil || got != "" {
		t.Errorf("ResolveModulePath = (%q, %v), want (\"\", nil)", got, err)
	}
}

func TestURISelectorPredicates(t *testing.T) {
	cases := []struct {
		uri                     string
		object, token, mod, pin bool
	}{
		{"pkcs11:", false, false, false, false},
		{"pkcs11:object=k;type=private", true, false, false, false},
		{"pkcs11:id=%01", true, false, false, false},
		{"pkcs11:serial=0001234", false, true, false, false},
		{"pkcs11:slot-id=3", false, true, false, false},
		{"pkcs11:model=YubiHSM", false, true, false, false},
		{"pkcs11:slot-description=Slot%200", false, true, false, false},
		{"pkcs11:?module-name=softhsm2", false, false, true, false},
		{"pkcs11:?module-path=/x.so", false, false, true, false},
		{"pkcs11:?pin-value=1234", false, false, false, true},
		{"pkcs11:?pin-source=file:/run/pin", false, false, false, true},
	}
	for _, tc := range cases {
		u, err := ParsePKCS11URI(tc.uri)
		if err != nil {
			t.Fatalf("ParsePKCS11URI(%q): %v", tc.uri, err)
		}
		if got := u.HasObjectSelector(); got != tc.object {
			t.Errorf("%s: HasObjectSelector = %v, want %v", tc.uri, got, tc.object)
		}
		if got := u.HasTokenSelector(); got != tc.token {
			t.Errorf("%s: HasTokenSelector = %v, want %v", tc.uri, got, tc.token)
		}
		if got := u.HasModuleSelector(); got != tc.mod {
			t.Errorf("%s: HasModuleSelector = %v, want %v", tc.uri, got, tc.mod)
		}
		if got := u.HasPIN(); got != tc.pin {
			t.Errorf("%s: HasPIN = %v, want %v", tc.uri, got, tc.pin)
		}
	}
}

func TestBuildPKCS11URICarriesSlotAndModel(t *testing.T) {
	slot := uint(7)
	cfg := PKCS11Config{
		TokenLabel:       "tok",
		TokenSerial:      "ser",
		TokenModel:       "YubiHSM",
		SlotID:           &slot,
		SlotDescription:  "Slot 0",
		SlotManufacturer: "Yubico",
	}
	uri := BuildPKCS11URI(cfg, "ca key")
	// Must round-trip through the parser back to the same addressing.
	u, err := ParsePKCS11URI(uri)
	if err != nil {
		t.Fatalf("ParsePKCS11URI(%q): %v", uri, err)
	}
	if u.Token != "tok" || u.Serial != "ser" || u.Model != "YubiHSM" {
		t.Errorf("token attributes lost: %+v", u)
	}
	if u.SlotID == nil || *u.SlotID != 7 {
		t.Errorf("slot-id lost: %+v", u.SlotID)
	}
	if u.SlotDescription != "Slot 0" || u.SlotManufacturer != "Yubico" {
		t.Errorf("slot attributes lost: %q / %q", u.SlotDescription, u.SlotManufacturer)
	}
	if u.Object != "ca key" {
		t.Errorf("object = %q, want %q (the space must survive percent-encoding)", u.Object, "ca key")
	}
	if u.Type != PKCS11TypePrivate {
		t.Errorf("type = %q, want private", u.Type)
	}
}

func TestDescribeSelectorsNamesOnlyWhatIsSet(t *testing.T) {
	if got := (PKCS11Config{}).describeSelectors(); got != "(any token)" {
		t.Errorf("empty selectors = %q, want \"(any token)\"", got)
	}
	slot := uint(2)
	got := PKCS11Config{TokenSerial: "abc", SlotID: &slot}.describeSelectors()
	if !strings.Contains(got, `serial="abc"`) || !strings.Contains(got, "slot-id=2") {
		t.Errorf("describeSelectors = %q, want serial and slot-id", got)
	}
	if strings.Contains(got, "token=") || strings.Contains(got, "model=") {
		t.Errorf("describeSelectors = %q, want unset selectors omitted", got)
	}
}
