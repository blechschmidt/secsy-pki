package keyprovider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

func strptr(s string) *string { return &s }

// --- inline -----------------------------------------------------------------

func TestInlinePinSource(t *testing.T) {
	for _, typ := range []string{"", "inline", "INLINE"} {
		src, err := newPinSource(PinSourceSettings{Type: typ}, "s3cret")
		if err != nil {
			t.Fatalf("type %q: newPinSource: %v", typ, err)
		}
		got, err := src.Resolve(context.Background())
		if err != nil {
			t.Fatalf("type %q: Resolve: %v", typ, err)
		}
		if got != "s3cret" {
			t.Errorf("type %q: got %q, want s3cret", typ, got)
		}
		if pinSourceIsExternal(typ) {
			t.Errorf("type %q classified as external", typ)
		}
	}
}

func TestUnknownPinSourceType(t *testing.T) {
	if _, err := newPinSource(PinSourceSettings{Type: "gcp"}, ""); err == nil {
		t.Fatal("expected error for unknown pin_source type")
	}
}

// --- env --------------------------------------------------------------------

func TestEnvPinSource(t *testing.T) {
	const name = "SECSY_TEST_PIN_ENV"
	t.Setenv(name, "envpin")
	src, err := newPinSource(PinSourceSettings{Type: "env", Env: EnvPinSourceSettings{Var: name}}, "")
	if err != nil {
		t.Fatalf("newPinSource: %v", err)
	}
	got, err := src.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "envpin" {
		t.Errorf("got %q, want envpin", got)
	}
	if !pinSourceIsExternal("env") {
		t.Error("env should be external")
	}

	// Empty variable fails closed.
	t.Setenv(name, "")
	if _, err := src.Resolve(context.Background()); err == nil {
		t.Error("expected error for empty env var")
	}
}

func TestEnvPinSourceUnsetAndDefault(t *testing.T) {
	// Unset variable fails closed.
	os.Unsetenv("SECSY_TEST_PIN_MISSING")
	src, _ := newEnvPinSource(EnvPinSourceSettings{Var: "SECSY_TEST_PIN_MISSING"})
	if _, err := src.Resolve(context.Background()); err == nil {
		t.Error("expected error for unset env var")
	}
	// Default variable name is SECSY_USER_PIN.
	def, _ := newEnvPinSource(EnvPinSourceSettings{})
	if got := def.Describe(); got != "env SECSY_USER_PIN" {
		t.Errorf("default env describe = %q", got)
	}
}

// --- file -------------------------------------------------------------------

func writePinFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pin")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write pin file: %v", err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("chmod pin file: %v", err)
	}
	return p
}

func TestFilePinSource(t *testing.T) {
	p := writePinFile(t, "filepin\n", 0o600)
	src, err := newPinSource(PinSourceSettings{Type: "file", File: FilePinSourceSettings{Path: p}}, "")
	if err != nil {
		t.Fatalf("newPinSource: %v", err)
	}
	got, err := src.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "filepin" { // trailing newline trimmed
		t.Errorf("got %q, want filepin", got)
	}
}

func TestFilePinSourceInsecurePerms(t *testing.T) {
	p := writePinFile(t, "filepin", 0o644)
	src, _ := newFilePinSource(FilePinSourceSettings{Path: p})
	_, err := src.Resolve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "insecure permissions") {
		t.Fatalf("expected insecure-permissions error, got %v", err)
	}

	// Override lets it through (not recommended, but supported).
	relaxed, _ := newFilePinSource(FilePinSourceSettings{Path: p, AllowInsecurePerms: true})
	got, err := relaxed.Resolve(context.Background())
	if err != nil {
		t.Fatalf("with AllowInsecurePerms: %v", err)
	}
	if got != "filepin" {
		t.Errorf("got %q, want filepin", got)
	}
}

func TestFilePinSourceMissingEmptyDir(t *testing.T) {
	missing, _ := newFilePinSource(FilePinSourceSettings{Path: filepath.Join(t.TempDir(), "nope")})
	if _, err := missing.Resolve(context.Background()); err == nil {
		t.Error("expected error for missing file")
	}

	empty, _ := newFilePinSource(FilePinSourceSettings{Path: writePinFile(t, "", 0o600)})
	if _, err := empty.Resolve(context.Background()); err == nil {
		t.Error("expected error for empty file")
	}

	if _, err := newFilePinSource(FilePinSourceSettings{Path: t.TempDir()}); err != nil {
		t.Fatalf("construct dir source: %v", err)
	}
	dir, _ := newFilePinSource(FilePinSourceSettings{Path: t.TempDir()})
	if _, err := dir.Resolve(context.Background()); err == nil {
		t.Error("expected error for directory path")
	}

	if _, err := newFilePinSource(FilePinSourceSettings{}); err == nil {
		t.Error("expected error for empty path")
	}
}

// --- vault ------------------------------------------------------------------

// fakeKV is a minimal HashiCorp Vault KV server for token auth.
func fakeKV(t *testing.T, v2 map[string]string, v1 map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/secret/data/"): // KV v2
			key := strings.TrimPrefix(r.URL.Path, "/v1/secret/data/")
			val, ok := v2[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[]}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"data": map[string]any{"data": map[string]any{"pin": val}, "metadata": map[string]any{"version": 1}},
			})
		case strings.HasPrefix(r.URL.Path, "/v1/secret/"): // KV v1
			key := strings.TrimPrefix(r.URL.Path, "/v1/secret/")
			val, ok := v1[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"errors":[]}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"pin": val}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestVaultPinSourceKVv2(t *testing.T) {
	srv := fakeKV(t, map[string]string{"hsm/prod": "vaultpin2"}, nil)
	src, err := newPinSource(PinSourceSettings{Type: "vault", Vault: VaultPinSourceSettings{
		VaultSettings: VaultSettings{Address: srv.URL, Token: "root"},
		Path:          "hsm/prod",
	}}, "")
	if err != nil {
		t.Fatalf("newPinSource: %v", err)
	}
	got, err := src.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "vaultpin2" {
		t.Errorf("got %q, want vaultpin2", got)
	}
	if !strings.Contains(src.Describe(), "kv2") {
		t.Errorf("describe %q lacks kv2", src.Describe())
	}
}

func TestVaultPinSourceKVv1(t *testing.T) {
	srv := fakeKV(t, nil, map[string]string{"hsm": "vaultpin1"})
	src, _ := newPinSource(PinSourceSettings{Type: "vault", Vault: VaultPinSourceSettings{
		VaultSettings: VaultSettings{Address: srv.URL, Token: "root"},
		Path:          "hsm",
		KVVersion:     1,
	}}, "")
	got, err := src.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "vaultpin1" {
		t.Errorf("got %q, want vaultpin1", got)
	}
}

func TestVaultPinSourceErrors(t *testing.T) {
	srv := fakeKV(t, map[string]string{"hsm": "x"}, nil)

	// Missing secret path → fail closed.
	missing, _ := newPinSource(PinSourceSettings{Type: "vault", Vault: VaultPinSourceSettings{
		VaultSettings: VaultSettings{Address: srv.URL, Token: "root"}, Path: "absent",
	}}, "")
	if _, err := missing.Resolve(context.Background()); err == nil {
		t.Error("expected error for missing vault secret")
	}

	// Wrong field name → fail closed.
	wrongField, _ := newPinSource(PinSourceSettings{Type: "vault", Vault: VaultPinSourceSettings{
		VaultSettings: VaultSettings{Address: srv.URL, Token: "root"}, Path: "hsm", Field: "nope",
	}}, "")
	if _, err := wrongField.Resolve(context.Background()); err == nil {
		t.Error("expected error for missing field")
	}

	// Missing path in config → construction error.
	if _, err := newVaultPinSource(VaultPinSourceSettings{VaultSettings: VaultSettings{Address: srv.URL, Token: "root"}}); err == nil {
		t.Error("expected error for missing vault path")
	}
}

// --- aws --------------------------------------------------------------------

type fakeAWSSecrets struct {
	out   *secretsmanager.GetSecretValueOutput
	err   error
	gotID string
}

func (f *fakeAWSSecrets) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if in.SecretId != nil {
		f.gotID = *in.SecretId
	}
	return f.out, f.err
}

func TestAWSPinSourceString(t *testing.T) {
	fake := &fakeAWSSecrets{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("awspin\n")}}
	src := &awsPinSource{client: fake, secretID: "hsm/pin"}
	got, err := src.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "awspin" {
		t.Errorf("got %q, want awspin", got)
	}
	if fake.gotID != "hsm/pin" {
		t.Errorf("secret id = %q", fake.gotID)
	}
}

func TestAWSPinSourceJSONField(t *testing.T) {
	fake := &fakeAWSSecrets{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String(`{"pin":"j","other":"z"}`)}}
	src := &awsPinSource{client: fake, secretID: "hsm/pin", field: "pin"}
	got, err := src.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "j" {
		t.Errorf("got %q, want j", got)
	}

	// Field requested but value isn't JSON → fail closed.
	bad := &awsPinSource{client: &fakeAWSSecrets{out: &secretsmanager.GetSecretValueOutput{SecretString: aws.String("plain")}}, secretID: "x", field: "pin"}
	if _, err := bad.Resolve(context.Background()); err == nil {
		t.Error("expected error for non-JSON secret with field")
	}
}

func TestAWSPinSourceBinaryAndErrors(t *testing.T) {
	bin := &awsPinSource{client: &fakeAWSSecrets{out: &secretsmanager.GetSecretValueOutput{SecretBinary: []byte("binpin")}}, secretID: "x"}
	got, err := bin.Resolve(context.Background())
	if err != nil || got != "binpin" {
		t.Fatalf("binary secret: got %q err %v", got, err)
	}

	empty := &awsPinSource{client: &fakeAWSSecrets{out: &secretsmanager.GetSecretValueOutput{}}, secretID: "x"}
	if _, err := empty.Resolve(context.Background()); err == nil {
		t.Error("expected error for secret with no value")
	}

	failing := &awsPinSource{client: &fakeAWSSecrets{err: context.DeadlineExceeded}, secretID: "x"}
	if _, err := failing.Resolve(context.Background()); err == nil {
		t.Error("expected error propagated from client")
	}

	if _, err := newAWSPinSource(AWSPinSourceSettings{}); err == nil {
		t.Error("expected error for missing secret_id")
	}
}

// --- azure ------------------------------------------------------------------

type fakeAzureSecrets struct {
	resp    azsecrets.GetSecretResponse
	err     error
	gotName string
	gotVer  string
}

func (f *fakeAzureSecrets) GetSecret(_ context.Context, name, version string, _ *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error) {
	f.gotName, f.gotVer = name, version
	return f.resp, f.err
}

func TestAzurePinSource(t *testing.T) {
	fake := &fakeAzureSecrets{resp: azsecrets.GetSecretResponse{Secret: azsecrets.Secret{Value: strptr("azpin")}}}
	src := &azurePinSource{client: fake, name: "hsm-pin", version: "v1"}
	got, err := src.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "azpin" {
		t.Errorf("got %q, want azpin", got)
	}
	if fake.gotName != "hsm-pin" || fake.gotVer != "v1" {
		t.Errorf("name/version = %q/%q", fake.gotName, fake.gotVer)
	}
}

func TestAzurePinSourceJSONFieldAndErrors(t *testing.T) {
	jsonField := &azurePinSource{client: &fakeAzureSecrets{resp: azsecrets.GetSecretResponse{Secret: azsecrets.Secret{Value: strptr(`{"pin":"k"}`)}}}, name: "x", field: "pin"}
	got, err := jsonField.Resolve(context.Background())
	if err != nil || got != "k" {
		t.Fatalf("json field: got %q err %v", got, err)
	}

	noVal := &azurePinSource{client: &fakeAzureSecrets{resp: azsecrets.GetSecretResponse{}}, name: "x"}
	if _, err := noVal.Resolve(context.Background()); err == nil {
		t.Error("expected error for secret with no value")
	}

	failing := &azurePinSource{client: &fakeAzureSecrets{err: context.DeadlineExceeded}, name: "x"}
	if _, err := failing.Resolve(context.Background()); err == nil {
		t.Error("expected error propagated from client")
	}

	if _, err := newAzurePinSource(AzurePinSourceSettings{Name: "x"}); err == nil {
		t.Error("expected error for missing vault_url")
	}
	if _, err := newAzurePinSource(AzurePinSourceSettings{VaultURL: "https://x.vault.azure.net/"}); err == nil {
		t.Error("expected error for missing name")
	}
}

// --- BuildNamedPinSources ---------------------------------------------------

func TestBuildNamedPinSourcesSingleToken(t *testing.T) {
	// Inline single token → one non-external source.
	inline, err := BuildNamedPinSources(PKCS11Settings{Pin: "p"})
	if err != nil {
		t.Fatalf("inline: %v", err)
	}
	if len(inline) != 1 || inline[0].External || inline[0].Name != "pkcs11" {
		t.Fatalf("inline sources = %+v", inline)
	}

	// External file single token.
	p := writePinFile(t, "x", 0o600)
	ext, err := BuildNamedPinSources(PKCS11Settings{PinSource: PinSourceSettings{Type: "file", File: FilePinSourceSettings{Path: p}}})
	if err != nil {
		t.Fatalf("file: %v", err)
	}
	if len(ext) != 1 || !ext[0].External {
		t.Fatalf("file sources = %+v", ext)
	}
}

func TestBuildNamedPinSourcesHA(t *testing.T) {
	fileA := writePinFile(t, "a", 0o600)
	s := PKCS11Settings{
		Pin:       "shared",
		PinSource: PinSourceSettings{Type: "env", Env: EnvPinSourceSettings{Var: "SHARED_PIN"}},
		Tokens: []TokenSettings{
			{Name: "t-file", PinSource: PinSourceSettings{Type: "file", File: FilePinSourceSettings{Path: fileA}}},
			{Name: "t-inherit"}, // inherits the set-level env source
		},
	}
	got, err := BuildNamedPinSources(s)
	if err != nil {
		t.Fatalf("BuildNamedPinSources: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 sources, got %d", len(got))
	}
	if got[0].Name != "t-file" || !got[0].External || !strings.HasPrefix(got[0].Source.Describe(), "file ") {
		t.Errorf("token 0 = %+v (%s)", got[0], got[0].Source.Describe())
	}
	// t-inherit falls back to the set-level env source.
	if got[1].Name != "t-inherit" || !got[1].External || got[1].Source.Describe() != "env SHARED_PIN" {
		t.Errorf("token 1 = %+v (%s)", got[1], got[1].Source.Describe())
	}
}

// TestPKCS11ProviderResolvesPinLazily proves that constructing a PKCS#11 provider
// with an unreachable/failing PIN source does not error (lazy), but the first
// operation that needs a login surfaces the source error, fail-closed.
func TestPKCS11ProviderResolvesPinLazily(t *testing.T) {
	// A file source pointing at a nonexistent file: construction succeeds...
	p, err := NewPKCS11Provider(PKCS11Settings{
		ModulePath: "/nonexistent/module.so",
		PinSource:  PinSourceSettings{Type: "file", File: FilePinSourceSettings{Path: filepath.Join(t.TempDir(), "absent")}},
	})
	if err != nil {
		t.Fatalf("construction should be lazy, got %v", err)
	}
	// ...but resolving the PIN at login fails closed with the source error.
	err = p.Ping(context.Background())
	if err == nil || !strings.Contains(err.Error(), "resolving HSM PIN") {
		t.Fatalf("expected PIN-resolution error at login, got %v", err)
	}
}
