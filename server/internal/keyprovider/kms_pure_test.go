package keyprovider

// Tests for the remaining credential-free pieces of the key-provider surface:
// the KMS provider's public-key/key-type accessors, the GCP resource-name
// parsing that decides which key version signs, the import-usage mapping, the
// token selector's empty check, Vault's CA-bundle loading, and the exported
// PinSource constructor. Every one of these runs offline.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/kms/apiv1/kmspb"

	"github.com/blechschmidt/secsy-pki/server/internal/pki"
)

// ---------------------------------------------------------------------------
// KMSProvider.PublicKey / kmsSigner.KeyType
// ---------------------------------------------------------------------------

// TestKMSProviderPublicKeyMatchesTheSigner: the public key exported for a
// reference must be the public half of the key that will actually sign with that
// reference, and the signer must report the same canonical key type the provider
// does. The pki layer picks the digest and the certificate's signature algorithm
// from KeyType, so a mismatch produces a certificate whose algorithm identifier
// does not describe its signature.
func TestKMSProviderPublicKeyMatchesTheSigner(t *testing.T) {
	ctx := context.Background()
	for _, keyType := range []string{KeyTypeECDSAP256, KeyTypeECDSAP521, KeyTypeRSA2048} {
		t.Run(keyType, func(t *testing.T) {
			p := newFakeKMSProvider(t)
			gen, err := p.GenerateKey(ctx, KeySpec{Label: "ca", KeyType: keyType})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			pub, err := p.PublicKey(ctx, KeyRef{Label: "ca"})
			if err != nil {
				t.Fatalf("PublicKey: %v", err)
			}
			signer, err := p.Signer(ctx, KeyRef{Label: "ca"})
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			defer func() { _ = signer.Close() }()

			switch want := gen.PublicKey.(type) {
			case *ecdsa.PublicKey:
				if got, ok := pub.(*ecdsa.PublicKey); !ok || !got.Equal(want) {
					t.Errorf("PublicKey = %#v, want the generated key", pub)
				}
				if got, ok := signer.Public().(*ecdsa.PublicKey); !ok || !got.Equal(want) {
					t.Error("the signer signs with a different key than PublicKey exports")
				}
			case *rsa.PublicKey:
				if got, ok := pub.(*rsa.PublicKey); !ok || !got.Equal(want) {
					t.Errorf("PublicKey = %#v, want the generated key", pub)
				}
				if got, ok := signer.Public().(*rsa.PublicKey); !ok || !got.Equal(want) {
					t.Error("the signer signs with a different key than PublicKey exports")
				}
			default:
				t.Fatalf("unexpected generated key type %T", gen.PublicKey)
			}

			if got := signer.KeyType(); got != keyType {
				t.Errorf("Signer.KeyType() = %q, want %q", got, keyType)
			}
			// And the exported key must really verify what the signer produces.
			digest := sha256.Sum256([]byte("public key / signer agreement"))
			sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			verifyDigest(t, pub, digest[:], sig, false)
		})
	}
}

// TestKMSProviderPublicKeyErrors: a missing key must come back as ErrKeyNotFound
// (callers branch on it to decide whether to provision one), and a reference that
// names nothing must be rejected rather than resolved to an empty label.
func TestKMSProviderPublicKeyErrors(t *testing.T) {
	ctx := context.Background()
	p := newFakeKMSProvider(t)

	pub, err := p.PublicKey(ctx, KeyRef{Label: "absent"})
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("PublicKey for a missing key = (%v, %v), want ErrKeyNotFound", pub, err)
	}
	if pub != nil {
		t.Errorf("returned %#v alongside the error", pub)
	}
	if pub, err := p.PublicKey(ctx, KeyRef{}); err == nil {
		t.Errorf("PublicKey with an empty reference = %#v, want an error", pub)
	}
	if s, err := p.Signer(ctx, KeyRef{}); err == nil {
		t.Errorf("Signer with an empty reference = %#v, want an error", s)
	}
}

// ---------------------------------------------------------------------------
// GCP resource-name parsing
// ---------------------------------------------------------------------------

// TestGCPVersionNumber covers the parsing itself, including the inputs that have
// no version to parse. 0 is the documented answer for anything non-numeric.
func TestGCPVersionNumber(t *testing.T) {
	const key = "projects/p/locations/global/keyRings/r/cryptoKeys/ca"
	for _, tc := range []struct {
		name string
		in   string
		want int
	}{
		{"version 1", key + "/cryptoKeyVersions/1", 1},
		{"version 42", key + "/cryptoKeyVersions/42", 42},
		{"zero-padded", key + "/cryptoKeyVersions/007", 7},
		{"no version suffix", key, 0},
		{"non-numeric version", key + "/cryptoKeyVersions/latest", 0},
		{"empty path", "", 0},
		{"trailing slash", key + "/cryptoKeyVersions/7/", 0},
		{"bare number", "12", 12},
		{"whitespace", key + "/cryptoKeyVersions/ 7", 0},
		{"overflows an int", key + "/cryptoKeyVersions/999999999999999999999999", 0},
		{"only a slash", "/", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := versionNumber(tc.in); got != tc.want {
				t.Errorf("versionNumber(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
	// The whole point of parsing the integer instead of comparing strings: version
	// 10 is newer than version 9, which a lexical comparison gets backwards.
	if versionNumber(key+"/cryptoKeyVersions/10") <= versionNumber(key+"/cryptoKeyVersions/9") {
		t.Error("version 10 does not rank above version 9: a lexical comparison would sign with a stale version")
	}
}

// TestGCPLastSegment pins the helper versionNumber is built on.
func TestGCPLastSegment(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"projects/p/locations/global/keyRings/r/cryptoKeys/ca", "ca"},
		{"ca", "ca"},
		{"", ""},
		{"a/b/", ""},
		{"/leading", "leading"},
	} {
		if got := lastSegment(tc.in); got != tc.want {
			t.Errorf("lastSegment(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestGCPLatestEnabledVersionPicksTheHighestNumber drives versionNumber through
// its only caller: the selection of the version that signs. With versions 1, 2, 9,
// 10 and 11 enabled, a lexical ordering would pick 9 — and the CA would sign with
// a version an operator had superseded. A disabled version must be skipped even
// when it is the highest.
func TestGCPLatestEnabledVersionPicksTheHighestNumber(t *testing.T) {
	ctx := context.Background()
	b := newFakeGCPBackend(false)
	if _, err := b.CreateKey(ctx, "ca", KeyTypeECDSAP256); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	fake := b.client.(*fakeGCPKMSClient)

	fake.mu.Lock()
	var keyName string
	for name := range fake.keys {
		keyName = name
	}
	k := fake.keys[keyName]
	priv := k.versions[0].priv
	for _, n := range []string{"2", "9", "11", "10"} {
		k.versions = append(k.versions, &fakeGCPVersion{
			name:  keyName + "/cryptoKeyVersions/" + n,
			state: kmspb.CryptoKeyVersion_ENABLED,
			priv:  priv,
		})
	}
	fake.mu.Unlock()

	got, err := b.latestEnabledVersion(ctx, keyName)
	if err != nil {
		t.Fatalf("latestEnabledVersion: %v", err)
	}
	if want := keyName + "/cryptoKeyVersions/11"; got != want {
		t.Errorf("latestEnabledVersion = %q, want %q", got, want)
	}

	// Disable the newest: the next-highest enabled version must win.
	fake.mu.Lock()
	for _, v := range k.versions {
		if strings.HasSuffix(v.name, "/11") {
			v.state = kmspb.CryptoKeyVersion_DISABLED
		}
	}
	fake.mu.Unlock()
	got, err = b.latestEnabledVersion(ctx, keyName)
	if err != nil {
		t.Fatalf("latestEnabledVersion after disabling 11: %v", err)
	}
	if want := keyName + "/cryptoKeyVersions/10"; got != want {
		t.Errorf("latestEnabledVersion = %q, want %q (a disabled version must not sign)", got, want)
	}

	// All versions disabled: no silent fallback to a disabled key.
	fake.mu.Lock()
	for _, v := range k.versions {
		v.state = kmspb.CryptoKeyVersion_DISABLED
	}
	fake.mu.Unlock()
	if got, err := b.latestEnabledVersion(ctx, keyName); err == nil {
		t.Errorf("latestEnabledVersion with no enabled version = %q, want an error", got)
	}

	// Sanity: the ordering above is the property, not the fake's insertion order.
	names := []string{"k/cryptoKeyVersions/9", "k/cryptoKeyVersions/10", "k/cryptoKeyVersions/2"}
	sort.Slice(names, func(i, j int) bool { return versionNumber(names[i]) < versionNumber(names[j]) })
	if names[len(names)-1] != "k/cryptoKeyVersions/10" {
		t.Errorf("sorted by versionNumber the newest is %q, want version 10", names[len(names)-1])
	}
}

// ---------------------------------------------------------------------------
// importUsage / TokenSelector.IsZero
// ---------------------------------------------------------------------------

// TestImportUsageMapping: only the exact decrypt usage may produce a
// decrypt-capable key. Anything else — including a differently-cased or unknown
// string — must fall back to the sign-only attribute set, because the failure
// direction matters: a key that can only sign is a broken feature, a key that can
// unexpectedly decrypt is a broken boundary.
func TestImportUsageMapping(t *testing.T) {
	if got := importUsage(KeyUsageDecrypt); got != pki.ImportUsageDecrypt {
		t.Errorf("importUsage(%q) = %q, want %q", KeyUsageDecrypt, got, pki.ImportUsageDecrypt)
	}
	for _, usage := range []string{"", KeyUsageSign, "Decrypt", "DECRYPT", " decrypt", "decrypt ", "wrap", "unknown"} {
		if got := importUsage(usage); got != pki.ImportUsageSign {
			t.Errorf("importUsage(%q) = %q, want %q (least privilege)", usage, got, pki.ImportUsageSign)
		}
	}
}

// TestTokenSelectorIsZero: IsZero decides whether an operation is pinned to one
// token in an HA set. Reporting "pins nothing" for a selector that does pin would
// route a key operation to the wrong replica.
func TestTokenSelectorIsZero(t *testing.T) {
	slot := uint(0) // a zero slot id is still a pin
	for _, tc := range []struct {
		name string
		sel  TokenSelector
		want bool
	}{
		{"empty", TokenSelector{}, true},
		{"label", TokenSelector{Label: "tok"}, false},
		{"serial", TokenSelector{Serial: "X1"}, false},
		{"model", TokenSelector{Model: "YubiHSM2"}, false},
		{"manufacturer", TokenSelector{Manufacturer: "Yubico"}, false},
		{"slot id 0", TokenSelector{SlotID: &slot}, false},
		{"everything", TokenSelector{Label: "t", Serial: "s", Model: "m", Manufacturer: "y", SlotID: &slot}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.sel.IsZero()
			if got != tc.want {
				t.Errorf("IsZero() = %v, want %v for %s", got, tc.want, tc.sel.Describe())
			}
			// Describe and IsZero must agree about whether anything is pinned.
			if described := tc.sel.Describe() == "(any token)"; described != tc.want {
				t.Errorf("Describe() = %q disagrees with IsZero() = %v", tc.sel.Describe(), got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// vaultCACertPool
// ---------------------------------------------------------------------------

// selfSignedCertPEM returns a PEM-encoded self-signed certificate, the shape a
// Vault CA bundle carries.
func selfSignedCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "vault-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestVaultCACertPool: a CA bundle that cannot be loaded must fail loudly at
// construction. An empty pool would silently fall back to the system roots, which
// is exactly the trust decision the operator overrode by configuring a bundle.
func TestVaultCACertPool(t *testing.T) {
	dir := t.TempDir()
	certPEM := selfSignedCertPEM(t)

	good := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(good, certPEM, 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}
	pool, err := vaultCACertPool(good)
	if err != nil {
		t.Fatalf("vaultCACertPool: %v", err)
	}
	want := x509.NewCertPool()
	if !want.AppendCertsFromPEM(certPEM) {
		t.Fatal("test bundle is not parseable")
	}
	if !pool.Equal(want) {
		t.Error("the loaded pool does not contain the bundle's certificate")
	}

	// Two certificates in one bundle: both must land in the pool.
	bundle := filepath.Join(dir, "bundle.pem")
	second := selfSignedCertPEM(t)
	if err := os.WriteFile(bundle, append(append([]byte{}, certPEM...), second...), 0o600); err != nil {
		t.Fatalf("writing bundle: %v", err)
	}
	pool, err = vaultCACertPool(bundle)
	if err != nil {
		t.Fatalf("vaultCACertPool on a two-cert bundle: %v", err)
	}
	both := x509.NewCertPool()
	both.AppendCertsFromPEM(certPEM)
	both.AppendCertsFromPEM(second)
	if !pool.Equal(both) {
		t.Error("only part of a two-certificate bundle was loaded")
	}

	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("writing empty bundle: %v", err)
	}
	notPEM := filepath.Join(dir, "garbage.pem")
	if err := os.WriteFile(notPEM, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatalf("writing garbage: %v", err)
	}
	truncated := filepath.Join(dir, "truncated.pem")
	if err := os.WriteFile(truncated, certPEM[:len(certPEM)/2], 0o600); err != nil {
		t.Fatalf("writing truncated bundle: %v", err)
	}
	keyOnly := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyOnly, []byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatalf("writing key-only bundle: %v", err)
	}
	for _, tc := range []struct{ name, path string }{
		{"missing file", filepath.Join(dir, "absent.pem")},
		{"empty file", empty},
		{"not PEM at all", notPEM},
		{"truncated PEM", truncated},
		{"PEM without a certificate", keyOnly},
		{"a directory", dir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pool, err := vaultCACertPool(tc.path)
			if err == nil {
				t.Fatalf("vaultCACertPool(%s) succeeded, want an error", tc.name)
			}
			if pool != nil {
				t.Error("returned a pool alongside the error: TLS would trust nothing and say nothing")
			}
		})
	}

	// The error must reach the caller through client construction, and a good
	// bundle must actually be installed as the client's root store.
	if _, err := newVaultClient(VaultSettings{
		Address: "https://vault.example:8200", Token: "t", CACertFile: filepath.Join(dir, "absent.pem"),
	}); err == nil {
		t.Error("newVaultClient accepted an unreadable ca_cert_file")
	}
	c, err := newVaultClient(VaultSettings{Address: "https://vault.example:8200", Token: "t", CACertFile: good})
	if err != nil {
		t.Fatalf("newVaultClient: %v", err)
	}
	tr, ok := c.httpc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("vault client transport is %T", c.httpc.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("the configured CA bundle was not installed as the client's root store")
	}
	if !tr.TLSClientConfig.RootCAs.Equal(want) {
		t.Error("the client's root store is not the configured bundle")
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("TLS verification is disabled although a CA bundle was configured")
	}
}

// ---------------------------------------------------------------------------
// NewPinSource
// ---------------------------------------------------------------------------

// TestNewPinSourceFile exercises the exported constructor other subsystems reuse
// for their own secrets (the LDAP bind password, for one) over the file backend,
// where the classic failure is a PIN carrying the newline `echo` left behind:
// the HSM then rejects a PIN that looks correct in the file.
func TestNewPinSourceFile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	write := func(t *testing.T, name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
		return p
	}

	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{"plain", "s3cret", "s3cret"},
		{"trailing newline", "s3cret\n", "s3cret"},
		{"trailing CRLF", "s3cret\r\n", "s3cret"},
		// Only one trailing newline is trimmed, and interior/leading whitespace is
		// preserved: a PIN may legitimately contain spaces.
		{"interior spaces", "two words\n", "two words"},
		{"leading space", " s3cret\n", " s3cret"},
		{"trailing space", "s3cret \n", "s3cret "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, err := NewPinSource(PinSourceSettings{
				Type: "file", File: FilePinSourceSettings{Path: write(t, tc.name, tc.content)},
			}, "")
			if err != nil {
				t.Fatalf("NewPinSource: %v", err)
			}
			got, err := src.Resolve(ctx)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got != tc.want {
				t.Errorf("Resolve() = %q, want %q", got, tc.want)
			}
			if strings.Contains(src.Describe(), got) {
				t.Errorf("Describe() = %q leaks the secret", src.Describe())
			}
		})
	}

	// Empty or absent secrets must fail closed rather than resolve to "".
	for _, tc := range []struct {
		name    string
		content *string
	}{
		{"empty file", strptr("")},
		{"newline only", strptr("\n")},
		{"CRLF only", strptr("\r\n")},
		{"missing file", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, "absent-"+tc.name)
			if tc.content != nil {
				path = write(t, "empty-"+tc.name, *tc.content)
			}
			// Construction does no I/O, so it succeeds even for a missing file...
			src, err := NewPinSource(PinSourceSettings{Type: "file", File: FilePinSourceSettings{Path: path}}, "")
			if err != nil {
				t.Fatalf("NewPinSource: %v", err)
			}
			// ...and the failure surfaces on resolution.
			got, err := src.Resolve(ctx)
			if err == nil {
				t.Fatalf("Resolve() = %q, want an error", got)
			}
			if got != "" {
				t.Errorf("Resolve returned %q alongside the error", got)
			}
		})
	}
}

// TestNewPinSourceTypes: the exported constructor must accept the same type names
// as the internal one (case- and space-insensitively), return the inline value for
// the inline source, and reject an unknown type instead of silently resolving to
// an empty secret.
func TestNewPinSourceTypes(t *testing.T) {
	ctx := context.Background()
	for _, typ := range []string{"", "inline", "INLINE", "  Inline  "} {
		src, err := NewPinSource(PinSourceSettings{Type: typ}, "inline-pin")
		if err != nil {
			t.Fatalf("NewPinSource(%q): %v", typ, err)
		}
		got, err := src.Resolve(ctx)
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if got != "inline-pin" {
			t.Errorf("type %q resolved to %q, want the inline value", typ, got)
		}
		if PinSourceIsExternal(typ) {
			t.Errorf("type %q reported as external", typ)
		}
		if strings.Contains(src.Describe(), "inline-pin") {
			t.Errorf("Describe() = %q leaks the secret", src.Describe())
		}
	}

	const name = "SECSY_TEST_NEWPINSOURCE"
	t.Setenv(name, "env-pin")
	src, err := NewPinSource(PinSourceSettings{Type: " ENV ", Env: EnvPinSourceSettings{Var: name}}, "ignored")
	if err != nil {
		t.Fatalf("NewPinSource(env): %v", err)
	}
	got, err := src.Resolve(ctx)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "env-pin" {
		t.Errorf("env source resolved to %q, want env-pin (the inline value must not win)", got)
	}
	if !PinSourceIsExternal("env") {
		t.Error("env must be reported as external so the doctor probes it")
	}

	for _, typ := range []string{"keychain", "vaults", "file-2"} {
		if src, err := NewPinSource(PinSourceSettings{Type: typ}, "pin"); err == nil {
			t.Errorf("NewPinSource(%q) = %v, want an error", typ, src)
		}
	}
	// A file source with no path is a misconfiguration the constructor can catch
	// without I/O, and must.
	if src, err := NewPinSource(PinSourceSettings{Type: "file"}, ""); err == nil {
		t.Errorf("NewPinSource(file) with no path = %v, want an error", src)
	}
}
