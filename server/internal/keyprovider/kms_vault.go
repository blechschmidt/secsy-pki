package keyprovider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// KMSBackendVault selects the HashiCorp Vault Transit secrets engine as the
// cloud-KMS backend. Signing keys and key-encryption keys (KEKs) are created and
// used inside Vault: the private/symmetric key material never leaves the server,
// exactly like a PKCS#11 HSM or AWS KMS / Azure Key Vault. See docs/vault-transit.md.
const KMSBackendVault = "vault"

// Vault Transit defaults.
const (
	// defaultVaultMount is the transit secrets-engine mount path when unset.
	defaultVaultMount = "transit"
	// defaultVaultAppRolePath is the AppRole auth-method mount path when unset.
	defaultVaultAppRolePath = "approle"
	// defaultVaultTimeout bounds each Transit REST call.
	defaultVaultTimeout = 30 * time.Second
	// vaultWrappingKeyType is the Transit key type used for a KEK (symmetric
	// convergent AEAD). It never exposes a public key; wrap/unwrap round-trip
	// through the transit encrypt/decrypt endpoints so the key stays in Vault.
	vaultWrappingKeyType = "aes256-gcm96"
)

// Vault auth-method identifiers accepted by VaultSettings.AuthMethod.
const (
	vaultAuthToken   = "token"
	vaultAuthAppRole = "approle"
)

// VaultSettings configures the Vault Transit backend. Credentials (a token, or an
// AppRole role-id/secret-id) authenticate to Vault; the actual signing/wrapping
// keys live inside the Transit engine and are addressed by label.
type VaultSettings struct {
	// Address is the Vault API base URL, e.g. "https://vault.example.com:8200".
	// When empty the VAULT_ADDR environment variable is used.
	Address string
	// Mount is the Transit secrets-engine mount path (default "transit").
	Mount string
	// Namespace is the Vault Enterprise namespace, sent as X-Vault-Namespace.
	// Empty for Vault OSS / the root namespace.
	Namespace string
	// AuthMethod is "token" or "approle" (default "token").
	AuthMethod string
	// Token is the Vault token for token auth. When empty the VAULT_TOKEN
	// environment variable is used. Ignored for AppRole auth.
	Token string
	// RoleID / SecretID authenticate via the AppRole method. Both are required
	// when AuthMethod is "approle".
	RoleID   string
	SecretID string
	// AppRolePath is the AppRole auth-method mount path (default "approle").
	AppRolePath string
	// CACertFile is an optional PEM bundle used to verify Vault's TLS certificate
	// when it is signed by a private CA.
	CACertFile string
	// Insecure disables Vault TLS verification. For development only; never set
	// this against a production Vault.
	Insecure bool
	// Timeout bounds each Transit REST call (default 30s).
	Timeout time.Duration
}

// vaultTransitBackend implements KMSBackend (and the private kmsWrapBackend
// capability) against the Vault Transit REST API. It holds no key material; every
// operation is a Transit API call over the shared vaultClient.
type vaultTransitBackend struct {
	client *vaultClient
	// prefix is prepended (sanitized) to a label to form the Transit key name,
	// namespacing this deployment's keys within a shared Transit mount.
	prefix string
}

// newVaultTransitBackend constructs the Vault Transit backend from KMS settings.
// It validates the address and auth configuration but performs no network I/O;
// the first key operation (or a Ping) establishes and authenticates the session.
func newVaultTransitBackend(cfg KMSSettings) (KMSBackend, error) {
	vc, err := newVaultClient(cfg.Vault)
	if err != nil {
		return nil, err
	}
	return &vaultTransitBackend{client: vc, prefix: sanitizeVaultName(cfg.KeyPrefix)}, nil
}

func (b *vaultTransitBackend) BackendName() string { return KMSBackendVault }

func (b *vaultTransitBackend) Close() error { return b.client.Close() }

// keyName maps a deployment label to a Transit key name. Both the prefix (set at
// construction) and the label are sanitized to a flat, URL-safe charset so keys
// never nest under a path segment and ListKeys can strip the prefix directly.
func (b *vaultTransitBackend) keyName(label string) string {
	return b.prefix + sanitizeVaultName(label)
}

// Ping verifies Vault is reachable and the configured credentials are valid by
// looking up the current token. token/lookup-self is permitted by the default
// policy for any valid token, so the probe needs no key or elevated capability.
func (b *vaultTransitBackend) Ping(ctx context.Context) error {
	if err := b.client.do(ctx, http.MethodGet, "/v1/auth/token/lookup-self", nil, nil); err != nil {
		return fmt.Errorf("keyprovider: vault unreachable or credentials invalid: %w", err)
	}
	return nil
}

// CreateKey provisions a new Transit signing key of the given canonical key type.
// It fails if a key with the same label already exists, preserving the Provider
// contract that a duplicate label is an error rather than a silent second key.
func (b *vaultTransitBackend) CreateKey(ctx context.Context, label, keyType string) (*RemoteKey, error) {
	transitType, err := vaultSigningKeyType(keyType)
	if err != nil {
		return nil, err
	}
	name := b.keyName(label)
	if err := b.ensureAbsent(ctx, name, label); err != nil {
		return nil, err
	}
	if err := b.client.do(ctx, http.MethodPost, b.keyPath(name),
		map[string]any{"type": transitType, "exportable": false}, nil); err != nil {
		return nil, fmt.Errorf("keyprovider: vault create key %q: %w", label, err)
	}
	return b.ResolveKey(ctx, label)
}

// CreateWrappingKey provisions a symmetric Transit KEK for wrap/unwrap. It has no
// public key; the DEK is sealed and opened via the transit encrypt/decrypt
// endpoints so the KEK never leaves Vault.
func (b *vaultTransitBackend) CreateWrappingKey(ctx context.Context, label string) (*RemoteKey, error) {
	name := b.keyName(label)
	if err := b.ensureAbsent(ctx, name, label); err != nil {
		return nil, err
	}
	if err := b.client.do(ctx, http.MethodPost, b.keyPath(name),
		map[string]any{"type": vaultWrappingKeyType}, nil); err != nil {
		return nil, fmt.Errorf("keyprovider: vault create wrapping key %q: %w", label, err)
	}
	return &RemoteKey{
		Label:   label,
		KeyID:   name,
		KeyType: vaultWrappingKeyType,
		URI:     vaultKeyURI(name),
	}, nil
}

// ensureAbsent returns an error if a Transit key with the given name already
// exists, and nil when it does not (a 404 from Vault).
func (b *vaultTransitBackend) ensureAbsent(ctx context.Context, name, label string) error {
	err := b.client.do(ctx, http.MethodGet, b.keyPath(name), nil, nil)
	switch {
	case err == nil:
		return fmt.Errorf("keyprovider: vault key %q already exists", label)
	case isVaultNotFound(err):
		return nil
	default:
		return fmt.Errorf("keyprovider: checking vault key %q: %w", label, err)
	}
}

// ResolveKey reads a Transit key's metadata (type and, for asymmetric keys, the
// latest-version public key). It returns an error unwrapping to ErrKeyNotFound
// when no key matches the label.
func (b *vaultTransitBackend) ResolveKey(ctx context.Context, label string) (*RemoteKey, error) {
	name := b.keyName(label)
	var resp vaultKeyResponse
	if err := b.client.do(ctx, http.MethodGet, b.keyPath(name), nil, &resp); err != nil {
		if isVaultNotFound(err) {
			return nil, fmt.Errorf("%w: %q", ErrKeyNotFound, label)
		}
		return nil, fmt.Errorf("keyprovider: vault read key %q: %w", label, err)
	}
	rk := &RemoteKey{Label: label, KeyID: name, URI: vaultKeyURI(name)}
	// A symmetric wrapping key has no canonical type and no public half.
	if resp.Data.Type == vaultWrappingKeyType {
		rk.KeyType = vaultWrappingKeyType
		return rk, nil
	}
	keyType, err := vaultKeyTypeToCanonical(resp.Data.Type)
	if err != nil {
		return nil, err
	}
	pub, err := resp.publicKey()
	if err != nil {
		return nil, fmt.Errorf("keyprovider: vault key %q: %w", label, err)
	}
	rk.KeyType = keyType
	rk.PublicKey = pub
	return rk, nil
}

// ListKeys enumerates Transit keys under this backend's prefix, enriching each
// with its type and public key (best-effort — a read failure on one key still
// lists it).
func (b *vaultTransitBackend) ListKeys(ctx context.Context) ([]RemoteKey, error) {
	var resp vaultListResponse
	if err := b.client.do(ctx, http.MethodGet, "/v1/"+b.client.mount+"/keys?list=true", nil, &resp); err != nil {
		// An empty Transit mount answers 404 to LIST; treat that as no keys.
		if isVaultNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("keyprovider: vault list keys: %w", err)
	}
	var out []RemoteKey
	for _, name := range resp.Data.Keys {
		if !strings.HasPrefix(name, b.prefix) {
			continue
		}
		label := strings.TrimPrefix(name, b.prefix)
		if rk, err := b.ResolveKey(ctx, label); err == nil {
			out = append(out, *rk)
			continue
		}
		// Best-effort: report the key even if enrichment failed.
		out = append(out, RemoteKey{Label: label, KeyID: name, URI: vaultKeyURI(name)})
	}
	return out, nil
}

// Sign produces a signature over the precomputed digest using a Transit signing
// key. The digest is sent prehashed; for ECDSA the ASN.1 DER marshaling the
// x509/CMS verifiers expect is requested explicitly, and for RSA pss selects
// RSA-PSS over RSASSA-PKCS1v1.5.
func (b *vaultTransitBackend) Sign(ctx context.Context, keyID, keyType string, digest []byte, hash crypto.Hash, pss bool) ([]byte, error) {
	req, err := vaultSignRequest(keyType, digest, hash, pss)
	if err != nil {
		return nil, err
	}
	var resp vaultSignResponse
	if err := b.client.do(ctx, http.MethodPost, "/v1/"+b.client.mount+"/sign/"+keyID, req, &resp); err != nil {
		return nil, fmt.Errorf("keyprovider: vault sign: %w", err)
	}
	sig, err := decodeVaultPayload(resp.Data.Signature)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: vault signature: %w", err)
	}
	return sig, nil
}

// Verify checks a signature against the digest using the Transit verify endpoint.
// Production verification uses the exported public key with the standard library;
// this method exercises Vault's own verify path and is used for interop testing
// and by callers that want Vault to be the source of truth.
func (b *vaultTransitBackend) Verify(ctx context.Context, keyID, keyType string, digest, sig []byte, hash crypto.Hash, pss bool) (bool, error) {
	req, err := vaultSignRequest(keyType, digest, hash, pss)
	if err != nil {
		return false, err
	}
	req.Signature = "vault:v1:" + base64.StdEncoding.EncodeToString(sig)
	var resp vaultVerifyResponse
	if err := b.client.do(ctx, http.MethodPost, "/v1/"+b.client.mount+"/verify/"+keyID, req, &resp); err != nil {
		return false, fmt.Errorf("keyprovider: vault verify: %w", err)
	}
	return resp.Data.Valid, nil
}

// WrapKey seals plaintext (a DEK) under the label's symmetric Transit KEK via the
// encrypt endpoint. The returned ciphertext is Vault's self-describing
// "vault:v<n>:..." blob, decryptable only by the same Vault key.
func (b *vaultTransitBackend) WrapKey(ctx context.Context, label string, plaintext []byte) ([]byte, error) {
	name := b.keyName(label)
	req := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}
	var resp vaultEncryptResponse
	if err := b.client.do(ctx, http.MethodPost, "/v1/"+b.client.mount+"/encrypt/"+name, req, &resp); err != nil {
		return nil, fmt.Errorf("keyprovider: vault wrap: %w", err)
	}
	if resp.Data.Ciphertext == "" {
		return nil, fmt.Errorf("keyprovider: vault wrap: empty ciphertext")
	}
	return []byte(resp.Data.Ciphertext), nil
}

// UnwrapKey opens a wrapped DEK produced by WrapKey via the decrypt endpoint.
func (b *vaultTransitBackend) UnwrapKey(ctx context.Context, label string, ciphertext []byte) ([]byte, error) {
	name := b.keyName(label)
	req := map[string]string{"ciphertext": string(ciphertext)}
	var resp vaultDecryptResponse
	if err := b.client.do(ctx, http.MethodPost, "/v1/"+b.client.mount+"/decrypt/"+name, req, &resp); err != nil {
		return nil, fmt.Errorf("keyprovider: vault unwrap: %w", err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: vault unwrap: decoding plaintext: %w", err)
	}
	return plaintext, nil
}

func (b *vaultTransitBackend) keyPath(name string) string {
	return "/v1/" + b.client.mount + "/keys/" + name
}

var (
	_ KMSBackend     = (*vaultTransitBackend)(nil)
	_ kmsWrapBackend = (*vaultTransitBackend)(nil)
)

// --- Transit request/response shapes -----------------------------------------

type vaultKeyResponse struct {
	Data struct {
		Type          string `json:"type"`
		LatestVersion int    `json:"latest_version"`
		Keys          map[string]struct {
			PublicKey string `json:"public_key"`
		} `json:"keys"`
	} `json:"data"`
}

// publicKey parses the PKIX public key of the latest key version from a Transit
// key-read response.
func (r vaultKeyResponse) publicKey() (crypto.PublicKey, error) {
	version := strconv.Itoa(r.Data.LatestVersion)
	entry, ok := r.Data.Keys[version]
	if !ok || entry.PublicKey == "" {
		return nil, fmt.Errorf("no public key for latest version %s", version)
	}
	block, _ := pem.Decode([]byte(entry.PublicKey))
	if block == nil {
		return nil, fmt.Errorf("public key is not valid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PKIX public key: %w", err)
	}
	return pub, nil
}

type vaultListResponse struct {
	Data struct {
		Keys []string `json:"keys"`
	} `json:"data"`
}

type vaultSignParams struct {
	Input               string `json:"input"`
	Signature           string `json:"signature,omitempty"`
	HashAlgorithm       string `json:"hash_algorithm,omitempty"`
	SignatureAlgorithm  string `json:"signature_algorithm,omitempty"`
	MarshalingAlgorithm string `json:"marshaling_algorithm,omitempty"`
	Prehashed           bool   `json:"prehashed"`
}

type vaultSignResponse struct {
	Data struct {
		Signature string `json:"signature"`
	} `json:"data"`
}

type vaultVerifyResponse struct {
	Data struct {
		Valid bool `json:"valid"`
	} `json:"data"`
}

type vaultEncryptResponse struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
	} `json:"data"`
}

type vaultDecryptResponse struct {
	Data struct {
		Plaintext string `json:"plaintext"`
	} `json:"data"`
}

// vaultSignRequest builds the transit sign/verify parameters for a key type. The
// digest is always sent prehashed; ECDSA requests ASN.1 DER marshaling.
func vaultSignRequest(keyType string, digest []byte, hash crypto.Hash, pss bool) (*vaultSignParams, error) {
	hashAlg, err := vaultHashAlgorithm(hash)
	if err != nil {
		return nil, err
	}
	params := &vaultSignParams{
		Input:         base64.StdEncoding.EncodeToString(digest),
		HashAlgorithm: hashAlg,
		Prehashed:     true,
	}
	switch keyType {
	case KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeECDSAP521:
		params.MarshalingAlgorithm = "asn1"
	case KeyTypeRSA2048, KeyTypeRSA4096:
		if pss {
			params.SignatureAlgorithm = "pss"
		} else {
			params.SignatureAlgorithm = "pkcs1v15"
		}
	default:
		return nil, fmt.Errorf("keyprovider: vault cannot sign with key type %q", keyType)
	}
	return params, nil
}

// --- type/hash mapping -------------------------------------------------------

// vaultSigningKeyType maps a canonical key type to a Transit signing key type.
// The supported set mirrors the other cloud-KMS backends (ECDSA P-256/384/521,
// RSA 2048/4096); Transit's additional types (ed25519, rsa-3072) are not exposed
// so the abstraction stays uniform.
func vaultSigningKeyType(keyType string) (string, error) {
	switch keyType {
	case KeyTypeECDSAP256:
		return "ecdsa-p256", nil
	case KeyTypeECDSAP384:
		return "ecdsa-p384", nil
	case KeyTypeECDSAP521:
		return "ecdsa-p521", nil
	case KeyTypeRSA2048:
		return "rsa-2048", nil
	case KeyTypeRSA4096:
		return "rsa-4096", nil
	default:
		return "", fmt.Errorf("keyprovider: vault does not support signing key type %q "+
			"(supported: %s, %s, %s, %s, %s)", keyType,
			KeyTypeECDSAP256, KeyTypeECDSAP384, KeyTypeECDSAP521, KeyTypeRSA2048, KeyTypeRSA4096)
	}
}

// vaultKeyTypeToCanonical maps a Transit key type back to a canonical key type.
func vaultKeyTypeToCanonical(transitType string) (string, error) {
	switch transitType {
	case "ecdsa-p256":
		return KeyTypeECDSAP256, nil
	case "ecdsa-p384":
		return KeyTypeECDSAP384, nil
	case "ecdsa-p521":
		return KeyTypeECDSAP521, nil
	case "rsa-2048":
		return KeyTypeRSA2048, nil
	case "rsa-4096":
		return KeyTypeRSA4096, nil
	default:
		return "", fmt.Errorf("keyprovider: unsupported vault transit key type %q", transitType)
	}
}

// vaultHashAlgorithm maps a crypto.Hash to Transit's hash_algorithm name.
func vaultHashAlgorithm(hash crypto.Hash) (string, error) {
	switch hash {
	case crypto.SHA256:
		return "sha2-256", nil
	case crypto.SHA384:
		return "sha2-384", nil
	case crypto.SHA512:
		return "sha2-512", nil
	default:
		return "", fmt.Errorf("keyprovider: vault unsupported signing hash %v", hash)
	}
}

// decodeVaultPayload strips a "vault:v<n>:" prefix and base64-decodes the payload
// carried by a Transit signature or ciphertext.
func decodeVaultPayload(s string) ([]byte, error) {
	parts := strings.SplitN(s, ":", 3)
	if len(parts) != 3 || parts[0] != "vault" {
		return nil, fmt.Errorf("malformed vault payload %q", s)
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decoding vault payload: %w", err)
	}
	return raw, nil
}

// sanitizeVaultName maps arbitrary text to a flat, URL-safe Transit key name:
// alphanumerics plus -_. are kept, everything else (notably "/") becomes "-" so
// keys never nest under a path segment.
func sanitizeVaultName(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			sb.WriteRune(r)
		default:
			sb.WriteByte('-')
		}
	}
	return sb.String()
}

func vaultKeyURI(name string) string { return "kms:vault:" + name }

// --- vaultClient: a minimal authenticated Vault HTTP client ------------------

// vaultClient performs authenticated JSON requests against a Vault server. It
// supports token and AppRole auth; for AppRole it logs in lazily and, on a 401/403
// (an expired client token), re-authenticates once and retries. It is safe for
// concurrent use.
type vaultClient struct {
	addr        string
	mount       string
	namespace   string
	auth        string
	staticToken string
	roleID      string
	secretID    string
	approlePath string
	httpc       *http.Client

	mu    sync.Mutex
	token string
}

// newVaultClient validates settings and constructs the HTTP client. It performs
// no network I/O.
func newVaultClient(cfg VaultSettings) (*vaultClient, error) {
	addr := strings.TrimRight(strings.TrimSpace(cfg.Address), "/")
	if addr == "" {
		addr = strings.TrimRight(strings.TrimSpace(os.Getenv("VAULT_ADDR")), "/")
	}
	if addr == "" {
		return nil, fmt.Errorf("keyprovider: vault address is required (set kms.vault.address or VAULT_ADDR)")
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.Insecure} //nolint:gosec // Insecure is opt-in for dev only
	if cfg.CACertFile != "" {
		pool, err := vaultCACertPool(cfg.CACertFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.RootCAs = pool
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultVaultTimeout
	}

	c := &vaultClient{
		addr:        addr,
		mount:       strings.Trim(defaultString(cfg.Mount, defaultVaultMount), "/"),
		namespace:   strings.TrimSpace(cfg.Namespace),
		approlePath: strings.Trim(defaultString(cfg.AppRolePath, defaultVaultAppRolePath), "/"),
		httpc: &http.Client{
			Timeout:   timeout,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		},
	}

	switch method := strings.ToLower(strings.TrimSpace(cfg.AuthMethod)); method {
	case "", vaultAuthToken:
		c.auth = vaultAuthToken
		c.staticToken = cfg.Token
		if c.staticToken == "" {
			c.staticToken = os.Getenv("VAULT_TOKEN")
		}
		if c.staticToken == "" {
			return nil, fmt.Errorf("keyprovider: vault token auth requires kms.vault.token or VAULT_TOKEN")
		}
	case vaultAuthAppRole:
		c.auth = vaultAuthAppRole
		c.roleID = cfg.RoleID
		c.secretID = cfg.SecretID
		if c.roleID == "" || c.secretID == "" {
			return nil, fmt.Errorf("keyprovider: vault approle auth requires kms.vault.role_id and kms.vault.secret_id")
		}
	default:
		return nil, fmt.Errorf("keyprovider: unknown vault auth method %q (supported: token, approle)", cfg.AuthMethod)
	}
	return c, nil
}

func (c *vaultClient) Close() error {
	c.httpc.CloseIdleConnections()
	return nil
}

// do issues an authenticated request, decoding a 2xx JSON body into out. For
// AppRole auth it transparently re-authenticates once on an auth failure.
func (c *vaultClient) do(ctx context.Context, method, apiPath string, reqBody, out any) error {
	err := c.doOnce(ctx, method, apiPath, reqBody, out)
	if err != nil && c.auth == vaultAuthAppRole && isVaultAuthError(err) {
		c.clearToken()
		return c.doOnce(ctx, method, apiPath, reqBody, out)
	}
	return err
}

func (c *vaultClient) doOnce(ctx context.Context, method, apiPath string, reqBody, out any) error {
	token, err := c.currentToken(ctx)
	if err != nil {
		return err
	}
	var body io.Reader
	if reqBody != nil {
		encoded, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("keyprovider: encoding vault request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.addr+apiPath, body)
	if err != nil {
		return fmt.Errorf("keyprovider: building vault request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Vault-Token", token)
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	return c.send(req, out)
}

// send executes a request, mapping a non-2xx status to a vaultAPIError and
// decoding a 2xx JSON body into out.
func (c *vaultClient) send(req *http.Request, out any) error {
	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("keyprovider: vault request %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return fmt.Errorf("keyprovider: reading vault response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseVaultError(resp.StatusCode, respBody)
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("keyprovider: decoding vault response: %w", err)
		}
	}
	return nil
}

// currentToken returns the active token, authenticating via AppRole on first use.
func (c *vaultClient) currentToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" {
		return c.token, nil
	}
	switch c.auth {
	case vaultAuthToken:
		c.token = c.staticToken
	case vaultAuthAppRole:
		tok, err := c.appRoleLogin(ctx)
		if err != nil {
			return "", err
		}
		c.token = tok
	default:
		return "", fmt.Errorf("keyprovider: vault: no auth method configured")
	}
	return c.token, nil
}

func (c *vaultClient) clearToken() {
	c.mu.Lock()
	c.token = ""
	c.mu.Unlock()
}

// appRoleLogin exchanges the role-id/secret-id for a client token. Caller holds
// c.mu. It issues an unauthenticated request (no X-Vault-Token header).
func (c *vaultClient) appRoleLogin(ctx context.Context) (string, error) {
	payload, err := json.Marshal(map[string]string{"role_id": c.roleID, "secret_id": c.secretID})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.addr+"/v1/auth/"+c.approlePath+"/login", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.namespace != "" {
		req.Header.Set("X-Vault-Namespace", c.namespace)
	}
	var resp struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := c.send(req, &resp); err != nil {
		return "", fmt.Errorf("keyprovider: vault approle login: %w", err)
	}
	if resp.Auth.ClientToken == "" {
		return "", fmt.Errorf("keyprovider: vault approle login returned no token")
	}
	return resp.Auth.ClientToken, nil
}

// vaultAPIError is a non-2xx Vault response, carrying the status and any messages
// from the "errors" array Vault returns.
type vaultAPIError struct {
	StatusCode int
	Errors     []string
}

func (e *vaultAPIError) Error() string {
	if len(e.Errors) > 0 {
		return fmt.Sprintf("vault: HTTP %d: %s", e.StatusCode, strings.Join(e.Errors, "; "))
	}
	return fmt.Sprintf("vault: HTTP %d", e.StatusCode)
}

func parseVaultError(status int, body []byte) error {
	var parsed struct {
		Errors []string `json:"errors"`
	}
	_ = json.Unmarshal(body, &parsed)
	return &vaultAPIError{StatusCode: status, Errors: parsed.Errors}
}

// isVaultNotFound reports whether err is a Vault 404.
func isVaultNotFound(err error) bool {
	var apiErr *vaultAPIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}

// isVaultAuthError reports whether err is a Vault 401/403 (token invalid or lacks
// permission) — the signal to re-authenticate an AppRole session.
func isVaultAuthError(err error) bool {
	var apiErr *vaultAPIError
	return errors.As(err, &apiErr) &&
		(apiErr.StatusCode == http.StatusForbidden || apiErr.StatusCode == http.StatusUnauthorized)
}

func defaultString(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// vaultCACertPool loads a PEM CA bundle into a cert pool for Vault TLS.
func vaultCACertPool(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("keyprovider: reading vault ca_cert_file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("keyprovider: vault ca_cert_file %q contains no certificates", file)
	}
	return pool, nil
}
