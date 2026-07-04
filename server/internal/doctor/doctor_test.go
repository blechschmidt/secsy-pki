//go:build sqlite

// Package doctor_test exercises the preflight diagnostic suite end to end
// against real stores and key providers. This file covers the HSM-independent
// paths with the software provider — including deliberate failure injection
// (broken config, unknown keys, missing key, stale CRL, tampered audit chain,
// uninitialized store, live-listener mismatch). doctor_softhsm_test.go covers
// the PKCS#11 paths against SoftHSM.
package doctor_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/audit"
	"github.com/blechschmidt/secsy-pki/server/internal/ca"
	"github.com/blechschmidt/secsy-pki/server/internal/config"
	"github.com/blechschmidt/secsy-pki/server/internal/database"
	"github.com/blechschmidt/secsy-pki/server/internal/doctor"
	"github.com/blechschmidt/secsy-pki/server/internal/keyprovider"
	"github.com/blechschmidt/secsy-pki/server/internal/models"

	_ "github.com/mattn/go-sqlite3"
)

// isolateEnv clears every SECSY_* variable that config.Load would otherwise
// apply as an override, so each test's config file is the whole truth. Values
// a test wants back (e.g. the SoftHSM PIN) are re-set explicitly.
func isolateEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"SECSY_KEY_PROVIDER", "SECSY_KEY_PROVIDER_CA", "SECSY_KEY_PROVIDER_TSA", "SECSY_KEY_PROVIDER_SIGNING",
		"SECSY_PKCS11_MODULE", "SECSY_TOKEN_LABEL", "SECSY_TOKEN_SERIAL", "SECSY_USER_PIN",
		"SECSY_DATABASE_DRIVER", "SECSY_DATABASE_DSN",
		"SECSY_SOFTWARE_KEYSTORE_DIR", "SECSY_SECRET_KEK_LABEL",
		"SECSY_KMS_BACKEND", "SECSY_KMS_REGION", "SECSY_KMS_KEY_PREFIX", "SECSY_KMS_VAULT_URL",
		"SECSY_ROOT_PASSWORD", "SECSY_ALLOW_INSECURE_HTTP",
	} {
		t.Setenv(k, "")
	}
}

// buildTestProvider mirrors the provider-construction glue of cmd/secsy-ca for
// tests (minus the YubiHSM connector-file handling, which SoftHSM/software
// setups never need), including the multi-token HA mapping.
func buildTestProvider(cfg *config.Config, role string) (keyprovider.Provider, error) {
	var tokens []keyprovider.TokenSettings
	for _, tok := range cfg.PKCS11.Tokens {
		tokens = append(tokens, keyprovider.TokenSettings{
			Name:              tok.Name,
			TokenLabel:        tok.TokenLabel,
			TokenSerial:       tok.TokenSerial,
			TokenManufacturer: tok.TokenManufacturer,
			Pin:               tok.Pin,
		})
	}
	return keyprovider.New(keyprovider.Config{
		Type: keyprovider.ProviderType(cfg.KeyProviderTypeForRole(role)),
		PKCS11: keyprovider.PKCS11Settings{
			ModulePath:       cfg.PKCS11.ModulePath,
			Pin:              cfg.PKCS11.Pin,
			TokenLabel:       cfg.PKCS11.TokenLabel,
			Tokens:           tokens,
			SelectionPolicy:  cfg.PKCS11.SelectionPolicy,
			FailureThreshold: cfg.PKCS11.FailureThreshold,
			ProbeInterval:    time.Duration(cfg.PKCS11.ProbeIntervalSeconds) * time.Second,
		},
		Software: keyprovider.SoftwareSettings{KeystoreDir: cfg.KeyProvider.Software.KeystoreDir},
		KMS: keyprovider.KMSSettings{
			Backend:   cfg.KeyProvider.KMS.Backend,
			Region:    cfg.KeyProvider.KMS.Region,
			KeyPrefix: cfg.KeyProvider.KMS.KeyPrefix,
			VaultURL:  cfg.KeyProvider.KMS.VaultURL,
		},
	})
}

// fixture is a provisioned single-node deployment: a SQLite store with one
// software-keyed root CA, listener TLS material, and a config file tying it
// together. Tests then inject specific faults before running the doctor.
type fixture struct {
	dir      string
	cfgPath  string
	dbPath   string
	keystore string
	tlsCert  string
	tlsKey   string
	port     int

	db     *database.DB
	rootID string
}

// newFixture provisions the deployment. extraCfg is appended verbatim to the
// generated config file (for enabling features under test).
func newFixture(t *testing.T, extraCfg string) *fixture {
	t.Helper()
	isolateEnv(t)

	f := &fixture{dir: t.TempDir()}
	f.dbPath = filepath.Join(f.dir, "doctor.db")
	f.keystore = filepath.Join(f.dir, "keystore")
	f.cfgPath = filepath.Join(f.dir, "config.yaml")

	// A port with (normally) nothing listening: bind :0 to reserve a real
	// number, then release it. Tests doing live-listener probes re-bind it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.port = ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	f.tlsCert, f.tlsKey = writeSelfSignedTLS(t, f.dir, 365*24*time.Hour)

	db, err := database.New("sqlite", f.dbPath)
	if err != nil {
		t.Fatalf("creating store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	f.db = db

	provider, err := keyprovider.New(keyprovider.Config{
		Type:     keyprovider.ProviderSoftware,
		Software: keyprovider.SoftwareSettings{KeystoreDir: f.keystore},
	})
	if err != nil {
		t.Fatalf("creating software provider: %v", err)
	}
	t.Cleanup(func() { provider.Close() })

	mgr := ca.NewManager(db, provider)
	root, err := mgr.InitRoot(context.Background(), ca.RootSpec{
		Label:    "doctor-root",
		KeyType:  "ecdsa-p256",
		Subject:  ca.PKIXName(models.CASubject{CommonName: "Doctor Test Root"}),
		Validity: 10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("provisioning root CA: %v", err)
	}
	f.rootID = root.ID

	seedAuditEvents(t, db)
	f.writeConfig(t, extraCfg)
	return f
}

// seedAuditEvents appends a few hash-chained events, as normal server activity
// would, so the chain checks have material to verify (and to tamper with).
func seedAuditEvents(t *testing.T, db *database.DB) {
	t.Helper()
	for i := 0; i < 5; i++ {
		if err := db.AppendEvent(&audit.Event{
			ID:     fmt.Sprintf("doctor-seed-%d", i),
			Actor:  "doctor-test",
			Action: "test.seed",
			Result: "success",
			Detail: fmt.Sprintf("seed event %d", i),
		}); err != nil {
			t.Fatalf("seeding audit events: %v", err)
		}
	}
}

func (f *fixture) writeConfig(t *testing.T, extra string) {
	t.Helper()
	cfg := fmt.Sprintf(`server:
  host: 127.0.0.1
  port: %d
  tls_cert: %s
  tls_key: %s
root_user:
  password: doctor-test
database:
  driver: sqlite
  dsn: %s
key_provider:
  type: software
  software:
    keystore_dir: %s
%s`, f.port, f.tlsCert, f.tlsKey, f.dbPath, f.keystore, extra)
	if err := os.WriteFile(f.cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) run(t *testing.T, opts doctor.Options) *doctor.Report {
	t.Helper()
	if opts.ConfigPath == "" {
		opts.ConfigPath = f.cfgPath
	}
	if opts.BuildProvider == nil {
		opts.BuildProvider = buildTestProvider
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return doctor.Run(ctx, opts)
}

// writeSelfSignedTLS writes a self-signed localhost server certificate/key
// pair and returns their paths.
func writeSelfSignedTLS(t *testing.T, dir string, validity time.Duration) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "doctor-listener"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, fmt.Sprintf("tls-%d.crt", time.Now().UnixNano()))
	keyPath = filepath.Join(dir, fmt.Sprintf("tls-%d.key", time.Now().UnixNano()))
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// findCheck returns the named result, failing the test if absent.
func findCheck(t *testing.T, r *doctor.Report, name string) doctor.Result {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q missing from report: %+v", name, r.Checks)
	return doctor.Result{}
}

// assertStatus asserts one check's status, logging its detail on mismatch.
func assertStatus(t *testing.T, r *doctor.Report, name string, want doctor.Status) doctor.Result {
	t.Helper()
	c := findCheck(t, r, name)
	if c.Status != want {
		t.Errorf("check %s = %s (want %s): %s", name, c.Status, want, c.Detail)
	}
	return c
}

func TestDoctorHealthyDeployment(t *testing.T) {
	f := newFixture(t, "")
	r := f.run(t, doctor.Options{Deep: true})

	for name, want := range map[string]doctor.Status{
		"config.parse":        doctor.StatusPass,
		"config.unknown_keys": doctor.StatusPass,
		"keyprovider.ca":      doctor.StatusPass,
		"db.connectivity":     doctor.StatusPass,
		"db.schema":           doctor.StatusPass,
		"keys.ca":             doctor.StatusPass,
		"keys.tsa":            doctor.StatusSkip,
		"keys.signing":        doctor.StatusSkip,
		"keys.secret_kek":     doctor.StatusSkip,
		"keys.ocsp_delegate":  doctor.StatusSkip,
		"audit.chain_head":    doctor.StatusPass,
		"db.integrity":        doctor.StatusPass,
		"certs.ca_expiry":     doctor.StatusPass,
		"crl.freshness":       doctor.StatusSkip,
		"clock.skew":          doctor.StatusPass,
		"listener.tls":        doctor.StatusPass,
	} {
		assertStatus(t, r, name, want)
	}
	if !r.OK {
		t.Errorf("report not OK: %+v", r.Checks)
	}
	if code := r.ExitCode(); code != doctor.ExitOK {
		t.Errorf("exit code = %d, want %d", code, doctor.ExitOK)
	}
	// The sign/verify self-test ran against the provisioned root.
	if c := findCheck(t, r, "keys.ca"); !strings.Contains(c.Detail, "1 CA key") {
		t.Errorf("keys.ca detail = %q, want mention of the verified CA key", c.Detail)
	}
	// The listener probe must not have found a live server (nothing bound).
	if c := findCheck(t, r, "listener.tls"); !strings.Contains(c.Detail, "not reachable") {
		t.Errorf("listener.tls detail = %q, want unreachable-listener note", c.Detail)
	}
}

func TestDoctorPKCS11URIs(t *testing.T) {
	cases := []struct {
		name       string
		extra      string
		want       doctor.Status
		wantDetail string
	}{
		{
			name:  "none configured",
			extra: "",
			want:  doctor.StatusSkip,
		},
		{
			name:  "valid module uri",
			extra: "pkcs11:\n  uri: \"pkcs11:token=softtoken?module-path=/usr/lib/p11.so\"\n",
			want:  doctor.StatusPass,
		},
		{
			name:       "malformed uri fails",
			extra:      "pkcs11:\n  uri: \"pkcs11:type=bogus\"\n",
			want:       doctor.StatusFail,
			wantDetail: "malformed",
		},
		{
			name:       "plaintext pin-value warns",
			extra:      "pkcs11:\n  uri: \"pkcs11:token=t?module-path=/usr/lib/p11.so&pin-value=1234\"\n",
			want:       doctor.StatusWarn,
			wantDetail: "pin-value",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, tc.extra)
			r := f.run(t, doctor.Options{})
			c := assertStatus(t, r, "pkcs11.uris", tc.want)
			if tc.wantDetail != "" && !strings.Contains(c.Detail, tc.wantDetail) {
				t.Errorf("pkcs11.uris detail = %q, want containing %q", c.Detail, tc.wantDetail)
			}
			// A plaintext pin-value in config must never appear in the report detail.
			if strings.Contains(c.Detail, "1234") {
				t.Errorf("pkcs11.uris detail leaked a pin-value: %q", c.Detail)
			}
		})
	}
}

func TestDoctorConfigParseFailure(t *testing.T) {
	isolateEnv(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(cfgPath, []byte("server:\n  port: [not-a-port\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := doctor.Run(context.Background(), doctor.Options{ConfigPath: cfgPath, BuildProvider: buildTestProvider})
	assertStatus(t, r, "config.parse", doctor.StatusFail)
	assertStatus(t, r, "db.connectivity", doctor.StatusSkip)
	assertStatus(t, r, "keys.ca", doctor.StatusSkip)
	if code := r.ExitCode(); code != doctor.ExitFail {
		t.Errorf("exit code = %d, want %d", code, doctor.ExitFail)
	}
}

func TestDoctorUnknownConfigKey(t *testing.T) {
	f := newFixture(t, "pkcs1:\n  module_path: /typo/example.so\n")
	r := f.run(t, doctor.Options{})
	c := assertStatus(t, r, "config.unknown_keys", doctor.StatusWarn)
	if !strings.Contains(c.Detail, "pkcs1") {
		t.Errorf("unknown-key detail %q does not name the offending key", c.Detail)
	}
	if code := r.ExitCode(); code != doctor.ExitWarn {
		t.Errorf("exit code = %d, want %d", code, doctor.ExitWarn)
	}
}

func TestDoctorMissingCAKey(t *testing.T) {
	f := newFixture(t, "")
	// A CA row whose key does not exist in the keystore — e.g. a store restored
	// against the wrong key backend.
	ghost := &models.CA{
		ID:        fmt.Sprintf("ghost-%d", time.Now().UnixNano()),
		Label:     "ghost-ca",
		PKCS11URI: "software:ghost-ca",
		KeyType:   keyprovider.KeyTypeECDSAP256,
		PublicKey: "ecdsa-sha2-nistp256 placeholder",
	}
	if err := f.db.CreateCA(ghost); err != nil {
		t.Fatalf("inserting ghost CA: %v", err)
	}
	r := f.run(t, doctor.Options{})
	c := assertStatus(t, r, "keys.ca", doctor.StatusFail)
	if !strings.Contains(c.Detail, "ghost-ca") {
		t.Errorf("keys.ca detail %q does not name the missing key", c.Detail)
	}
	if r.ExitCode() != doctor.ExitFail {
		t.Errorf("exit code = %d, want %d", r.ExitCode(), doctor.ExitFail)
	}
}

func TestDoctorStaleCRL(t *testing.T) {
	f := newFixture(t, "")
	now := time.Now()
	// Allocate real CRL numbers so the monotonic-counter invariant holds for
	// the seeded artifacts (the -deep integrity gate enforces it).
	staleNum, err := f.db.NextCRLNumber(f.rootID)
	if err != nil {
		t.Fatal(err)
	}
	stale := &database.PublishedCRL{
		CAID: f.rootID, Scope: "full", Kind: "base",
		Number: staleNum, BaseNumber: staleNum,
		ThisUpdate:  now.Add(-48 * time.Hour),
		NextUpdate:  now.Add(-24 * time.Hour),
		GeneratedAt: now.Add(-48 * time.Hour),
		DER:         []byte{0x30, 0x00},
	}
	if err := f.db.UpsertPublishedCRL(stale); err != nil {
		t.Fatalf("seeding stale CRL: %v", err)
	}

	// Without static publishing, a stale persisted CRL is regenerated on the
	// next fetch: warn.
	r := f.run(t, doctor.Options{})
	c := assertStatus(t, r, "crl.freshness", doctor.StatusWarn)
	if !strings.Contains(c.Detail, "expired") {
		t.Errorf("crl.freshness detail %q does not mention expiry", c.Detail)
	}

	// With publish.enabled the persisted artifact is what consumers read: fail.
	f.writeConfig(t, "publish:\n  enabled: true\n  include_ocsp: false\n  dir:\n    path: "+filepath.Join(f.dir, "pub")+"\n")
	r = f.run(t, doctor.Options{})
	assertStatus(t, r, "crl.freshness", doctor.StatusFail)

	// A fresh CRL passes.
	freshNum, err := f.db.NextCRLNumber(f.rootID)
	if err != nil {
		t.Fatal(err)
	}
	fresh := *stale
	fresh.Number = freshNum
	fresh.BaseNumber = freshNum
	fresh.ThisUpdate = now
	fresh.NextUpdate = now.Add(24 * time.Hour)
	fresh.GeneratedAt = now
	if err := f.db.UpsertPublishedCRL(&fresh); err != nil {
		t.Fatal(err)
	}
	f.writeConfig(t, "")
	r = f.run(t, doctor.Options{})
	assertStatus(t, r, "crl.freshness", doctor.StatusPass)
}

func TestDoctorAuditChainTamper(t *testing.T) {
	f := newFixture(t, "")
	// Tamper with the newest event through a raw connection, exactly as an
	// attacker with database access would.
	raw, err := sql.Open("sqlite3", f.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	res, err := raw.Exec(`UPDATE event_log SET detail = 'forged' WHERE seq = (SELECT MAX(seq) FROM event_log)`)
	raw.Close()
	if err != nil {
		t.Fatalf("tampering event log: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("expected to tamper exactly one event, got %d", n)
	}

	r := f.run(t, doctor.Options{})
	c := assertStatus(t, r, "audit.chain_head", doctor.StatusFail)
	if !strings.Contains(c.Detail, "chain broken") {
		t.Errorf("audit.chain_head detail %q does not report the break", c.Detail)
	}
}

func TestDoctorCertificateExpiryThresholds(t *testing.T) {
	f := newFixture(t, "")

	// The root has ~10y of headroom; a 20y warn threshold must flag it.
	r := f.run(t, doctor.Options{ExpiryWarn: 20 * 365 * 24 * time.Hour})
	assertStatus(t, r, "certs.ca_expiry", doctor.StatusWarn)

	// And a 20y fail threshold must fail it (listener cert fails too: 1y life).
	r = f.run(t, doctor.Options{
		ExpiryWarn: 21 * 365 * 24 * time.Hour,
		ExpiryFail: 20 * 365 * 24 * time.Hour,
	})
	assertStatus(t, r, "certs.ca_expiry", doctor.StatusFail)
	assertStatus(t, r, "listener.tls", doctor.StatusFail)
}

func TestDoctorTSACertificateFile(t *testing.T) {
	f := newFixture(t, "")
	f.writeConfig(t, "tsa:\n  certificate_file: "+filepath.Join(f.dir, "missing-tsa.pem")+"\n")
	r := f.run(t, doctor.Options{})
	assertStatus(t, r, "certs.tsa_expiry", doctor.StatusFail)

	// Point it at a real certificate: passes with ~1y headroom.
	cert, _ := writeSelfSignedTLS(t, f.dir, 365*24*time.Hour)
	f.writeConfig(t, "tsa:\n  certificate_file: "+cert+"\n")
	r = f.run(t, doctor.Options{})
	assertStatus(t, r, "certs.tsa_expiry", doctor.StatusPass)
}

func TestDoctorUninitializedStore(t *testing.T) {
	f := newFixture(t, "")

	// Nonexistent SQLite file: connectivity fails (doctor refuses to create it).
	f.writeConfigWithDB(t, filepath.Join(f.dir, "nope.db"))
	r := f.run(t, doctor.Options{})
	assertStatus(t, r, "db.connectivity", doctor.StatusFail)
	assertStatus(t, r, "db.schema", doctor.StatusSkip)

	// An existing file without the schema: reachable, but every table is a
	// pending migration and the store-dependent checks skip.
	emptyDB := filepath.Join(f.dir, "empty.db")
	raw, err := sql.Open("sqlite3", emptyDB)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`CREATE TABLE placeholder (x INTEGER)`); err != nil {
		t.Fatal(err)
	}
	raw.Close()
	f.writeConfigWithDB(t, emptyDB)
	r = f.run(t, doctor.Options{})
	assertStatus(t, r, "db.connectivity", doctor.StatusPass)
	c := assertStatus(t, r, "db.schema", doctor.StatusWarn)
	if !strings.Contains(c.Detail, "event_log") {
		t.Errorf("db.schema detail %q does not list missing tables", c.Detail)
	}
	assertStatus(t, r, "keys.ca", doctor.StatusSkip)
	assertStatus(t, r, "audit.chain_head", doctor.StatusSkip)
}

// writeConfigWithDB rewrites the fixture config pointing at a different
// database file.
func (f *fixture) writeConfigWithDB(t *testing.T, dbPath string) {
	t.Helper()
	orig := f.dbPath
	f.dbPath = dbPath
	f.writeConfig(t, "")
	f.dbPath = orig
}

func TestDoctorListenerLiveHandshake(t *testing.T) {
	f := newFixture(t, "")

	pair, err := tls.LoadX509KeyPair(f.tlsCert, f.tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	serveTLS(t, f.port, pair)

	r := f.run(t, doctor.Options{})
	c := assertStatus(t, r, "listener.tls", doctor.StatusPass)
	if !strings.Contains(c.Detail, "live handshake OK") || !strings.Contains(c.Detail, "configured certificate") {
		t.Errorf("listener.tls detail %q does not confirm the live handshake", c.Detail)
	}
}

func TestDoctorListenerCertificateMismatch(t *testing.T) {
	f := newFixture(t, "")

	// Serve a DIFFERENT certificate than the configured one, as after a cert
	// rotation without a server restart.
	otherCert, otherKey := writeSelfSignedTLS(t, f.dir, 365*24*time.Hour)
	pair, err := tls.LoadX509KeyPair(otherCert, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	serveTLS(t, f.port, pair)

	r := f.run(t, doctor.Options{})
	c := assertStatus(t, r, "listener.tls", doctor.StatusWarn)
	if !strings.Contains(c.Detail, "DIFFERENT certificate") {
		t.Errorf("listener.tls detail %q does not flag the mismatch", c.Detail)
	}
}

func TestDoctorNoTLSFailsClosed(t *testing.T) {
	f := newFixture(t, "")
	cfg := fmt.Sprintf("server:\n  host: 127.0.0.1\n  port: %d\nroot_user:\n  password: doctor-test\ndatabase:\n  driver: sqlite\n  dsn: %s\nkey_provider:\n  type: software\n  software:\n    keystore_dir: %s\n",
		f.port, f.dbPath, f.keystore)
	if err := os.WriteFile(f.cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}

	r := f.run(t, doctor.Options{})
	assertStatus(t, r, "listener.tls", doctor.StatusFail)

	t.Setenv("SECSY_ALLOW_INSECURE_HTTP", "1")
	r = f.run(t, doctor.Options{})
	assertStatus(t, r, "listener.tls", doctor.StatusWarn)
}

// serveTLS accepts TLS connections on the port for the duration of the test,
// completing handshakes and closing.
func serveTLS(t *testing.T, port int, pair tls.Certificate) {
	t.Helper()
	ln, err := tls.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{Certificates: []tls.Certificate{pair}})
	if err != nil {
		t.Fatalf("binding test listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()
}

func TestReportExitCodes(t *testing.T) {
	for _, tc := range []struct {
		summary doctor.Summary
		want    int
	}{
		{doctor.Summary{Pass: 5}, doctor.ExitOK},
		{doctor.Summary{Pass: 5, Skip: 2}, doctor.ExitOK},
		{doctor.Summary{Pass: 5, Warn: 1}, doctor.ExitWarn},
		{doctor.Summary{Pass: 5, Warn: 1, Fail: 1}, doctor.ExitFail},
		{doctor.Summary{Fail: 1}, doctor.ExitFail},
	} {
		r := &doctor.Report{Summary: tc.summary}
		if got := r.ExitCode(); got != tc.want {
			t.Errorf("ExitCode(%+v) = %d, want %d", tc.summary, got, tc.want)
		}
	}
}
