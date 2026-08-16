package keyprovider

// This file adds a pluggable credential-source abstraction for the PKCS#11 user
// PIN, so the PIN need not be stored in plaintext in config.yaml or the
// SECSY_USER_PIN environment variable. A PinSource is resolved lazily — at HSM
// login time (when the session pool is first built), never at process start — and
// fails closed with a descriptive error when the backing store is unreachable or
// the secret is missing. The resolved PIN lives only transiently in memory for
// the duration of C_Login; it is never written back into the config representation
// (see Config.Redacted) or logged.
//
// Sources reuse existing enterprise plumbing: the "vault" source shares the
// Task 92 Vault HTTP client (auth, TLS, namespace), and the "aws"/"azure" sources
// share the Task 41 cloud-SDK credential wiring (AWS default credential chain /
// Azure DefaultAzureCredential).

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	gax "github.com/googleapis/gax-go/v2"
)

// PinSource lazily supplies the PKCS#11 user PIN from a credential store. Every
// implementation must fail closed: Resolve returns a descriptive, non-sensitive
// error (never a partial/empty PIN silently) when the source is unreachable, the
// secret is absent, or a permission invariant is violated.
type PinSource interface {
	// Resolve fetches the PIN. It is called at HSM login time and may perform
	// network or filesystem I/O; it honors ctx cancellation/deadline.
	Resolve(ctx context.Context) (string, error)
	// Describe returns a short, log-safe description of where the PIN comes from
	// (e.g. "vault kv2 secret/hsm#pin"). It MUST NOT include the PIN itself and is
	// what diagnostics/doctor print instead of the credential.
	Describe() string
}

// PinSourceSettings selects and configures a PinSource. The zero value (Type "")
// is the inline source, which returns the PIN carried alongside it
// (PKCS11Settings.Pin) — the historical behavior.
type PinSourceSettings struct {
	// Type is "" / "inline", "env", "file", "vault", "aws", "azure", or
	// "gcp"/"gcpsm".
	Type  string
	Env   EnvPinSourceSettings
	File  FilePinSourceSettings
	Vault VaultPinSourceSettings
	AWS   AWSPinSourceSettings
	Azure AzurePinSourceSettings
	GCP   GCPPinSourceSettings
}

// EnvPinSourceSettings configures the "env" source (read the PIN from a named
// environment variable).
type EnvPinSourceSettings struct {
	// Var is the environment variable holding the PIN. Defaults to SECSY_USER_PIN.
	Var string
}

// FilePinSourceSettings configures the "file" source (read the PIN from a file).
type FilePinSourceSettings struct {
	// Path is the file whose contents are the PIN (a trailing newline is trimmed).
	Path string
	// AllowInsecurePerms disables the fail-closed 0600 permission check. Off by
	// default; enabling it defeats the point of externalizing the PIN and is only
	// for constrained environments where the file's ACLs are enforced elsewhere.
	AllowInsecurePerms bool
}

// VaultPinSourceSettings configures the "vault" source (read the PIN from a
// HashiCorp Vault KV secret). It embeds the Task 92 VaultSettings for the address,
// auth method, namespace, and TLS configuration, so a deployment already talking
// to Vault reuses the same connection parameters.
type VaultPinSourceSettings struct {
	// VaultSettings supplies the address/auth/namespace/TLS parameters. Its Mount
	// field here is the KV secrets-engine mount (default "secret"), not a Transit
	// mount — for a PIN we read a KV secret.
	VaultSettings
	// Path is the secret path within the mount, e.g. "hsm/prod".
	Path string
	// Field is the key within the secret whose value is the PIN (default "pin").
	Field string
	// KVVersion is the KV engine version, 1 or 2 (default 2).
	KVVersion int
}

// AWSPinSourceSettings configures the "aws" source (AWS Secrets Manager). It
// reuses the AWS default credential chain and region resolution.
type AWSPinSourceSettings struct {
	// Region is the AWS region; empty uses the SDK default (AWS_REGION / config).
	Region string
	// SecretID is the secret's name or ARN. Required.
	SecretID string
	// Field, when set, selects a key from a JSON secret value ({"pin":"…"}); when
	// empty the whole secret string is the PIN.
	Field string
}

// AzurePinSourceSettings configures the "azure" source (Azure Key Vault secret).
// It reuses azidentity.DefaultAzureCredential (env / workload / managed identity).
type AzurePinSourceSettings struct {
	// VaultURL is the Key Vault base URL, e.g. "https://kv.vault.azure.net/".
	VaultURL string
	// Name is the secret name. Required.
	Name string
	// Version pins a specific secret version; empty uses the latest.
	Version string
	// Field, when set, selects a key from a JSON secret value; when empty the whole
	// secret value is the PIN.
	Field string
}

// GCPPinSourceSettings configures the "gcp"/"gcpsm" source (Google Cloud Secret
// Manager). Credentials follow Application Default Credentials by default
// (workload identity / GOOGLE_APPLICATION_CREDENTIALS / gcloud login); an
// explicit service-account key may instead be supplied by file path or inline
// JSON, reusing the Task 160 Cloud KMS credential wiring.
type GCPPinSourceSettings struct {
	// Project is the GCP project id that owns the secret. Required unless Secret is
	// already a full "projects/…/secrets/…" resource name.
	Project string
	// Secret is the secret id (e.g. "hsm-pin") or a full resource name
	// ("projects/p/secrets/hsm-pin"). Required.
	Secret string
	// Version pins a specific secret version; empty uses "latest".
	Version string
	// CredentialsFile is the path to a service-account JSON key file; empty uses
	// Application Default Credentials.
	CredentialsFile string
	// CredentialsJSON is the inline service-account JSON key. A credential; prefer
	// CredentialsFile or ADC. Redacted from any dumped config.
	CredentialsJSON string
	// Field, when set, selects a key from a JSON secret value; empty uses the whole
	// secret payload as the PIN.
	Field string
	// Endpoint overrides the Secret Manager API endpoint for a local emulator;
	// when set, authentication is disabled. Leave empty for the real service.
	Endpoint string
}

// pinSourceIsExternal reports whether a configured pin_source type resolves the
// PIN from somewhere other than the inline config field. Used to decide whether
// the doctor "pin.source" reachability probe applies.
func pinSourceIsExternal(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "", "inline":
		return false
	default:
		return true
	}
}

// newPinSource constructs the PinSource selected by settings.Type. Construction
// validates static configuration and builds any client, but performs no network
// or filesystem I/O — reachability is proven lazily by Resolve. inlinePin is the
// value the inline source returns (PKCS11Settings.Pin).
func newPinSource(settings PinSourceSettings, inlinePin string) (PinSource, error) {
	switch strings.ToLower(strings.TrimSpace(settings.Type)) {
	case "", "inline":
		return &inlinePinSource{pin: inlinePin}, nil
	case "env":
		return newEnvPinSource(settings.Env)
	case "file":
		return newFilePinSource(settings.File)
	case "vault":
		return newVaultPinSource(settings.Vault)
	case "aws":
		return newAWSPinSource(settings.AWS)
	case "azure":
		return newAzurePinSource(settings.Azure)
	case "gcp", "gcpsm":
		return newGCPPinSource(settings.GCP)
	default:
		return nil, fmt.Errorf("keyprovider: unknown pkcs11 pin_source type %q (supported: inline, env, file, vault, aws, azure, gcp)", settings.Type)
	}
}

// NewPinSource constructs a single credential source from settings, returning
// the inline value (inlineValue) when settings.Type is empty/"inline". It is the
// single-secret analogue of BuildNamedPinSources, exported so other subsystems
// that must source a secret from the same credential stores — for example the
// LDAP bind-service-account password (Task 159) — reuse the identical env / file
// / Vault / AWS / Azure machinery and its fail-closed, redaction-safe semantics,
// rather than growing a parallel secret loader. Construction performs no I/O;
// reachability is proven lazily by Resolve.
func NewPinSource(settings PinSourceSettings, inlineValue string) (PinSource, error) {
	return newPinSource(settings, inlineValue)
}

// PinSourceIsExternal reports whether a configured source type resolves its
// secret from somewhere other than the inline config field, so callers can
// decide whether a reachability probe applies. It is the exported form of the
// internal predicate.
func PinSourceIsExternal(t string) bool { return pinSourceIsExternal(t) }

// NamedPinSource pairs a constructed PinSource with the token it belongs to (and
// whether it is external), for diagnostics such as the doctor "pin.source" check.
type NamedPinSource struct {
	// Name identifies the token: "pkcs11" for the single-token backend, or the
	// per-token name for a high-availability set.
	Name string
	// Source is the constructed source.
	Source PinSource
	// External is false for the inline source (nothing to probe for reachability).
	External bool
}

// BuildNamedPinSources constructs the PIN source for the single-token backend, or
// one per token for a high-availability set, applying the per-token override /
// shared fallback semantics (a token uses its own pin_source, else the set-level
// pin_source, else the inline pin). It is used by the doctor "pin.source" check;
// construction performs no I/O.
func BuildNamedPinSources(s PKCS11Settings) ([]NamedPinSource, error) {
	if len(s.Tokens) == 0 {
		src, err := newPinSource(s.PinSource, s.Pin)
		if err != nil {
			return nil, err
		}
		return []NamedPinSource{{Name: "pkcs11", Source: src, External: pinSourceIsExternal(s.PinSource.Type)}}, nil
	}
	out := make([]NamedPinSource, 0, len(s.Tokens))
	for i, tok := range s.Tokens {
		name := tok.Name
		if name == "" {
			name = tok.TokenLabel
		}
		if name == "" {
			name = fmt.Sprintf("token-%d", i)
		}
		ps, pin := effectiveTokenPin(s, tok)
		src, err := newPinSource(ps, pin)
		if err != nil {
			return nil, fmt.Errorf("token %q: %w", name, err)
		}
		out = append(out, NamedPinSource{Name: name, Source: src, External: pinSourceIsExternal(ps.Type)})
	}
	return out, nil
}

// effectiveTokenPin resolves a token's PIN source and inline-PIN fallback from the
// per-token override and the set-level defaults, mirroring the shared-PIN fallback
// the HA provider has always applied.
func effectiveTokenPin(s PKCS11Settings, tok TokenSettings) (PinSourceSettings, string) {
	ps := tok.PinSource
	if ps.Type == "" {
		ps = s.PinSource
	}
	pin := tok.Pin
	if pin == "" {
		pin = s.Pin
	}
	return ps, pin
}

// inlinePinDeprecationOnce guards the one-shot warning emitted the first time a
// non-empty inline PIN is used, nudging operators toward an external pin_source.
var inlinePinDeprecationOnce sync.Once

// inlinePinSource returns a PIN configured inline in config.yaml or via
// SECSY_USER_PIN — the historical, plaintext-at-rest behavior. It is retained for
// backward compatibility but emits a one-time deprecation warning.
type inlinePinSource struct{ pin string }

func (s *inlinePinSource) Resolve(_ context.Context) (string, error) {
	if s.pin != "" {
		inlinePinDeprecationOnce.Do(func() {
			log.Printf("WARNING: the PKCS#11 user PIN is configured inline (pkcs11.pin / SECSY_USER_PIN, plaintext at rest). " +
				"Configure pkcs11.pin_source (env/file/vault/aws/azure) to source it from a credential store instead. " +
				"See docs/hsm/configuration.md.")
		})
	}
	return s.pin, nil
}

func (s *inlinePinSource) Describe() string { return "inline pkcs11.pin" }

// envPinSource reads the PIN from a named environment variable. Unlike the inline
// source it does not carry the secret in the config representation, so it is not
// redacted out of a config dump.
type envPinSource struct{ varName string }

func newEnvPinSource(c EnvPinSourceSettings) (PinSource, error) {
	name := strings.TrimSpace(c.Var)
	if name == "" {
		name = "SECSY_USER_PIN"
	}
	return &envPinSource{varName: name}, nil
}

func (s *envPinSource) Resolve(_ context.Context) (string, error) {
	v, ok := os.LookupEnv(s.varName)
	if !ok {
		return "", fmt.Errorf("keyprovider: pin_source env: environment variable %s is not set", s.varName)
	}
	if v == "" {
		return "", fmt.Errorf("keyprovider: pin_source env: environment variable %s is empty", s.varName)
	}
	return v, nil
}

func (s *envPinSource) Describe() string { return "env " + s.varName }

// filePinSource reads the PIN from a file, enforcing that the file is not
// group/other-accessible (0600 or stricter) so the on-disk credential cannot be
// read by other local users.
type filePinSource struct {
	path          string
	allowInsecure bool
}

func newFilePinSource(c FilePinSourceSettings) (PinSource, error) {
	p := strings.TrimSpace(c.Path)
	if p == "" {
		return nil, fmt.Errorf("keyprovider: pin_source file: path is required")
	}
	return &filePinSource{path: p, allowInsecure: c.AllowInsecurePerms}, nil
}

func (s *filePinSource) Resolve(_ context.Context) (string, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return "", fmt.Errorf("keyprovider: pin_source file %s: %w", s.path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("keyprovider: pin_source file %s: is a directory, not a file", s.path)
	}
	if !s.allowInsecure {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return "", fmt.Errorf("keyprovider: pin_source file %s has insecure permissions %#o: it must not be readable by group or other (chmod 600 %s), "+
				"or set pin_source.file.allow_insecure_perms to override", s.path, perm, s.path)
		}
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return "", fmt.Errorf("keyprovider: pin_source file %s: %w", s.path, err)
	}
	// Trim a single trailing newline (POSIX text files / `echo`); do not trim other
	// whitespace, which could be a legitimate part of the PIN.
	pin := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if pin == "" {
		return "", fmt.Errorf("keyprovider: pin_source file %s is empty", s.path)
	}
	return pin, nil
}

func (s *filePinSource) Describe() string { return "file " + s.path }

// vaultPinSource reads the PIN from a HashiCorp Vault KV secret over the shared
// Task 92 Vault HTTP client (reusing its token/AppRole auth, namespace, and TLS).
type vaultPinSource struct {
	client    *vaultClient
	mount     string
	path      string
	field     string
	kvVersion int
}

func newVaultPinSource(c VaultPinSourceSettings) (PinSource, error) {
	if strings.TrimSpace(c.Path) == "" {
		return nil, fmt.Errorf("keyprovider: pin_source vault: path is required")
	}
	vc, err := newVaultClient(c.VaultSettings)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: pin_source vault: %w", err)
	}
	ver := c.KVVersion
	if ver == 0 {
		ver = 2
	}
	if ver != 1 && ver != 2 {
		return nil, fmt.Errorf("keyprovider: pin_source vault: kv_version must be 1 or 2, got %d", ver)
	}
	return &vaultPinSource{
		client:    vc,
		mount:     strings.Trim(defaultString(c.Mount, "secret"), "/"),
		path:      strings.Trim(strings.TrimSpace(c.Path), "/"),
		field:     defaultString(strings.TrimSpace(c.Field), "pin"),
		kvVersion: ver,
	}, nil
}

func (s *vaultPinSource) Resolve(ctx context.Context) (string, error) {
	// KV v2 reads live under <mount>/data/<path> and nest the secret one level
	// deeper (data.data); KV v1 reads live under <mount>/<path> (data).
	apiPath := "/v1/" + s.mount + "/" + s.path
	if s.kvVersion == 2 {
		apiPath = "/v1/" + s.mount + "/data/" + s.path
	}
	var raw struct {
		Data json.RawMessage `json:"data"`
	}
	if err := s.client.do(ctx, http.MethodGet, apiPath, nil, &raw); err != nil {
		return "", fmt.Errorf("keyprovider: pin_source %s: %w", s.Describe(), err)
	}
	kv := map[string]any{}
	if s.kvVersion == 2 {
		var wrap struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(raw.Data, &wrap); err != nil {
			return "", fmt.Errorf("keyprovider: pin_source %s: decoding KV v2 secret: %w", s.Describe(), err)
		}
		kv = wrap.Data
	} else if len(raw.Data) > 0 {
		if err := json.Unmarshal(raw.Data, &kv); err != nil {
			return "", fmt.Errorf("keyprovider: pin_source %s: decoding KV v1 secret: %w", s.Describe(), err)
		}
	}
	return pinFromMap(kv, s.field, s.Describe())
}

func (s *vaultPinSource) Describe() string {
	return fmt.Sprintf("vault kv%d %s/%s#%s", s.kvVersion, s.mount, s.path, s.field)
}

// awsSecretsClient is the narrow subset of the AWS Secrets Manager API used here,
// declared as an interface so tests can substitute a fake.
type awsSecretsClient interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// awsPinSource reads the PIN from AWS Secrets Manager over the shared Task 41 AWS
// default credential chain.
type awsPinSource struct {
	client   awsSecretsClient
	secretID string
	field    string
}

func newAWSPinSource(c AWSPinSourceSettings) (PinSource, error) {
	if strings.TrimSpace(c.SecretID) == "" {
		return nil, fmt.Errorf("keyprovider: pin_source aws: secret_id is required")
	}
	var opts []func(*awsconfig.LoadOptions) error
	if c.Region != "" {
		opts = append(opts, awsconfig.WithRegion(c.Region))
	}
	// LoadDefaultConfig resolves the credential chain lazily and performs no I/O.
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: pin_source aws: loading AWS config: %w", err)
	}
	return &awsPinSource{
		client:   secretsmanager.NewFromConfig(awsCfg),
		secretID: strings.TrimSpace(c.SecretID),
		field:    strings.TrimSpace(c.Field),
	}, nil
}

func (s *awsPinSource) Resolve(ctx context.Context) (string, error) {
	out, err := s.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(s.secretID)})
	if err != nil {
		return "", fmt.Errorf("keyprovider: pin_source %s: %w", s.Describe(), err)
	}
	var raw string
	switch {
	case out.SecretString != nil:
		raw = *out.SecretString
	case len(out.SecretBinary) > 0:
		raw = string(out.SecretBinary)
	default:
		return "", fmt.Errorf("keyprovider: pin_source %s: secret has neither a string nor a binary value", s.Describe())
	}
	return extractPin(raw, s.field, s.Describe())
}

func (s *awsPinSource) Describe() string {
	if s.field != "" {
		return "aws secretsmanager " + s.secretID + "#" + s.field
	}
	return "aws secretsmanager " + s.secretID
}

// azureSecretsClient is the narrow subset of the Azure Key Vault secrets API used
// here, declared as an interface so tests can substitute a fake.
type azureSecretsClient interface {
	GetSecret(ctx context.Context, name, version string, options *azsecrets.GetSecretOptions) (azsecrets.GetSecretResponse, error)
}

// azurePinSource reads the PIN from an Azure Key Vault secret over the shared
// Task 41 DefaultAzureCredential wiring.
type azurePinSource struct {
	client   azureSecretsClient
	vaultURL string
	name     string
	version  string
	field    string
}

func newAzurePinSource(c AzurePinSourceSettings) (PinSource, error) {
	if strings.TrimSpace(c.VaultURL) == "" {
		return nil, fmt.Errorf("keyprovider: pin_source azure: vault_url is required")
	}
	if strings.TrimSpace(c.Name) == "" {
		return nil, fmt.Errorf("keyprovider: pin_source azure: name is required")
	}
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: pin_source azure: credential: %w", err)
	}
	client, err := azsecrets.NewClient(c.VaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: pin_source azure: client: %w", err)
	}
	return &azurePinSource{
		client:   client,
		vaultURL: strings.TrimSpace(c.VaultURL),
		name:     strings.TrimSpace(c.Name),
		version:  strings.TrimSpace(c.Version),
		field:    strings.TrimSpace(c.Field),
	}, nil
}

func (s *azurePinSource) Resolve(ctx context.Context) (string, error) {
	resp, err := s.client.GetSecret(ctx, s.name, s.version, nil)
	if err != nil {
		return "", fmt.Errorf("keyprovider: pin_source %s: %w", s.Describe(), err)
	}
	if resp.Value == nil {
		return "", fmt.Errorf("keyprovider: pin_source %s: secret has no value", s.Describe())
	}
	return extractPin(*resp.Value, s.field, s.Describe())
}

func (s *azurePinSource) Describe() string {
	if s.field != "" {
		return "azure keyvault " + s.name + "#" + s.field
	}
	return "azure keyvault " + s.name
}

// gcpSecretsClient is the narrow subset of the Google Cloud Secret Manager API
// used here, declared as an interface so tests can substitute a fake. The real
// *secretmanager.Client satisfies it directly.
type gcpSecretsClient interface {
	AccessSecretVersion(ctx context.Context, req *secretmanagerpb.AccessSecretVersionRequest, opts ...gax.CallOption) (*secretmanagerpb.AccessSecretVersionResponse, error)
	Close() error
}

// gcpPinSource reads the PIN from Google Cloud Secret Manager over the shared
// Task 160 Cloud KMS credential wiring (ADC or an explicit service-account key).
// The Secret Manager client is built lazily inside Resolve so an unreachable
// source or missing credentials fails the login op closed, not process start.
type gcpPinSource struct {
	// name is the full secret-version resource name
	// (projects/P/secrets/S/versions/V).
	name  string
	field string
	// describe is a log-safe rendering (the resource name, never the PIN).
	describe string
	// client, when non-nil, is used directly (test injection); otherwise newClient
	// builds one per Resolve.
	client    gcpSecretsClient
	newClient func(ctx context.Context) (gcpSecretsClient, error)
}

func newGCPPinSource(c GCPPinSourceSettings) (PinSource, error) {
	name, err := gcpSecretResourceName(c.Project, c.Secret, c.Version)
	if err != nil {
		return nil, err
	}
	settings := c
	return &gcpPinSource{
		name:     name,
		field:    strings.TrimSpace(c.Field),
		describe: gcpSecretDescribe(name, strings.TrimSpace(c.Field)),
		newClient: func(ctx context.Context) (gcpSecretsClient, error) {
			opts, err := gcpClientOptions(settings.CredentialsFile, settings.CredentialsJSON, settings.Endpoint)
			if err != nil {
				return nil, err
			}
			return secretmanager.NewClient(ctx, opts...)
		},
	}, nil
}

func (s *gcpPinSource) Resolve(ctx context.Context) (string, error) {
	client := s.client
	if client == nil {
		c, err := s.newClient(ctx)
		if err != nil {
			return "", fmt.Errorf("keyprovider: pin_source %s: creating client: %w", s.describe, err)
		}
		defer func() { _ = c.Close() }()
		client = c
	}
	resp, err := client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{Name: s.name})
	if err != nil {
		return "", fmt.Errorf("keyprovider: pin_source %s: %w", s.describe, err)
	}
	data := resp.GetPayload().GetData()
	if len(data) == 0 {
		return "", fmt.Errorf("keyprovider: pin_source %s: secret version has an empty payload", s.describe)
	}
	return extractPin(string(data), s.field, s.describe)
}

func (s *gcpPinSource) Describe() string { return s.describe }

// gcpSecretResourceName builds the fully qualified secret-version resource name
// from a project id, a secret id or full resource name, and an optional version
// (default "latest").
func gcpSecretResourceName(project, secret, version string) (string, error) {
	secret = strings.Trim(strings.TrimSpace(secret), "/")
	if secret == "" {
		return "", fmt.Errorf("keyprovider: pin_source gcp: secret is required")
	}
	version = strings.TrimSpace(version)
	if version == "" {
		version = "latest"
	}
	// A full resource name may be supplied directly.
	if strings.HasPrefix(secret, "projects/") {
		if strings.Contains(secret, "/versions/") {
			return secret, nil
		}
		if !strings.Contains(secret, "/secrets/") {
			return "", fmt.Errorf("keyprovider: pin_source gcp: %q is not a valid secret resource name", secret)
		}
		return secret + "/versions/" + version, nil
	}
	if strings.TrimSpace(project) == "" {
		return "", fmt.Errorf("keyprovider: pin_source gcp: project is required (or give secret as a full projects/…/secrets/… resource name)")
	}
	return fmt.Sprintf("projects/%s/secrets/%s/versions/%s", strings.TrimSpace(project), secret, version), nil
}

// gcpSecretDescribe renders a log-safe description of a Secret Manager source.
func gcpSecretDescribe(name, field string) string {
	if field != "" {
		return "gcp secretmanager " + name + "#" + field
	}
	return "gcp secretmanager " + name
}

// extractPin returns the PIN from a raw secret value: the whole (newline-trimmed)
// value when field is empty, or the named key of a JSON object when field is set.
func extractPin(raw, field, describe string) (string, error) {
	if field == "" {
		pin := strings.TrimSuffix(strings.TrimSuffix(raw, "\n"), "\r")
		if pin == "" {
			return "", fmt.Errorf("keyprovider: pin_source %s: secret value is empty", describe)
		}
		return pin, nil
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return "", fmt.Errorf("keyprovider: pin_source %s: field %q requested but the secret is not a JSON object: %w", describe, field, err)
	}
	return pinFromMap(obj, field, describe)
}

// pinFromMap extracts a non-empty string PIN from a decoded secret map, failing
// closed if the field is missing, non-string, or empty.
func pinFromMap(obj map[string]any, field, describe string) (string, error) {
	val, ok := obj[field]
	if !ok {
		return "", fmt.Errorf("keyprovider: pin_source %s: field %q is not present in the secret", describe, field)
	}
	pin, ok := val.(string)
	if !ok {
		return "", fmt.Errorf("keyprovider: pin_source %s: field %q is not a string", describe, field)
	}
	if pin == "" {
		return "", fmt.Errorf("keyprovider: pin_source %s: field %q is empty", describe, field)
	}
	return pin, nil
}
