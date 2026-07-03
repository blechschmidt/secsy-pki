package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// installFixture prepares a spec, key, and issued chain ready to install.
type installFixture struct {
	agent  *Agent
	spec   *CertSpec
	key    *ecdsa.PrivateKey
	chain  []*x509.Certificate
	bundle *trustBundle
	dir    string
}

func newInstallFixture(t *testing.T, mutateSpec func(*CertSpec)) *installFixture {
	t.Helper()
	ca := newTestCA(t, "Install Root")
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := ca.issueFor(t, key.Public(), "inst.example.test", []string{"inst.example.test"}, issueOpts{})
	spec := &CertSpec{
		Name:          "inst",
		Enroll:        EnrollEST,
		DNSNames:      []string{"inst.example.test"},
		KeyType:       "ecdsa-p256",
		KeyFile:       filepath.Join(dir, "inst.key"),
		CertFile:      filepath.Join(dir, "inst.crt"),
		ChainFile:     filepath.Join(dir, "inst-chain.crt"),
		FullchainFile: filepath.Join(dir, "inst-fullchain.crt"),
		KeyMode:       FileMode(0o600),
		CertMode:      FileMode(0o644),
	}
	if mutateSpec != nil {
		mutateSpec(spec)
	}
	a := &Agent{cfg: &Config{}, now: time.Now}
	return &installFixture{
		agent:  a,
		spec:   spec,
		key:    key,
		chain:  []*x509.Certificate{leaf},
		bundle: newTrustBundle([]*x509.Certificate{ca.cert}, time.Now()),
		dir:    dir,
	}
}

// assertNoTempLitter fails when install temp files remain in the directory.
func assertNoTempLitter(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".secsy-tmp.") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestInstallWritesEverythingAtomically(t *testing.T) {
	fx := newInstallFixture(t, nil)
	res, err := fx.agent.install(fx.spec, fx.key, fx.chain, fx.bundle, time.Now())
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if len(res.rolledIn) != 4 {
		t.Errorf("rolledIn = %v, want 4 files", res.rolledIn)
	}

	keyInfo, err := os.Stat(fx.spec.KeyFile)
	if err != nil {
		t.Fatalf("key file: %v", err)
	}
	if keyInfo.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %o, want 0600", keyInfo.Mode().Perm())
	}
	certInfo, err := os.Stat(fx.spec.CertFile)
	if err != nil {
		t.Fatalf("cert file: %v", err)
	}
	if certInfo.Mode().Perm() != 0o644 {
		t.Errorf("cert mode = %o, want 0644", certInfo.Mode().Perm())
	}

	// Key file round-trips and matches the leaf.
	keyPEM, _ := os.ReadFile(fx.spec.KeyFile)
	key, err := parseKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("parse installed key: %v", err)
	}
	certPEM, _ := os.ReadFile(fx.spec.CertFile)
	certs, err := parseCertsPEM(certPEM)
	if err != nil {
		t.Fatalf("parse installed cert: %v", err)
	}
	if !publicKeysMatch(certs[0], key) {
		t.Error("installed key does not match installed cert")
	}

	// Chain file holds the issuer (no leaf); fullchain leaf+issuer.
	chainPEM, _ := os.ReadFile(fx.spec.ChainFile)
	chainCerts, err := parseCertsPEM(chainPEM)
	if err != nil {
		t.Fatalf("parse chain: %v", err)
	}
	if len(chainCerts) != 1 || chainCerts[0].Subject.CommonName != "Install Root" {
		t.Errorf("chain file should hold the issuer only, got %d certs", len(chainCerts))
	}
	fullPEM, _ := os.ReadFile(fx.spec.FullchainFile)
	fullCerts, err := parseCertsPEM(fullPEM)
	if err != nil {
		t.Fatalf("parse fullchain: %v", err)
	}
	if len(fullCerts) != 2 || fullCerts[0].Subject.CommonName != "inst.example.test" {
		t.Errorf("fullchain should be leaf+issuer, got %d certs", len(fullCerts))
	}

	assertNoTempLitter(t, fx.dir)
}

func TestInstallRejectsUntrustedChain(t *testing.T) {
	fx := newInstallFixture(t, nil)
	otherCA := newTestCA(t, "Unrelated Root")
	badBundle := newTrustBundle([]*x509.Certificate{otherCA.cert}, time.Now())

	_, err := fx.agent.install(fx.spec, fx.key, fx.chain, badBundle, time.Now())
	if err == nil || !strings.Contains(err.Error(), "does not chain") {
		t.Fatalf("expected chain verification failure, got %v", err)
	}
	// Nothing may have been written.
	for _, p := range fx.spec.outputPaths() {
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Errorf("%s exists after failed verification", p)
		}
	}
	assertNoTempLitter(t, fx.dir)
}

func TestInstallRejectsKeyMismatch(t *testing.T) {
	fx := newInstallFixture(t, nil)
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, err := fx.agent.install(fx.spec, otherKey, fx.chain, fx.bundle, time.Now())
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected key mismatch error, got %v", err)
	}
	assertNoTempLitter(t, fx.dir)
}

func TestInstallRejectsMissingSAN(t *testing.T) {
	fx := newInstallFixture(t, func(s *CertSpec) {
		s.DNSNames = []string{"inst.example.test", "other.example.test"}
	})
	_, err := fx.agent.install(fx.spec, fx.key, fx.chain, fx.bundle, time.Now())
	if err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Fatalf("expected SAN coverage error, got %v", err)
	}
}

func TestInstallHookFailureRollsBackExistingFiles(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hook-ran")
	fx := newInstallFixture(t, func(s *CertSpec) {
		s.Reload = &ReloadConfig{
			Command: CommandLine{"sh", "-c", "touch " + marker + " && exit 7"},
			Timeout: Duration(10 * time.Second),
		}
	})

	// Seed "previous generation" files with recognizable content.
	oldContent := map[string][]byte{}
	for _, p := range fx.spec.outputPaths() {
		content := []byte("previous " + filepath.Base(p) + "\n")
		if err := os.WriteFile(p, content, 0o640); err != nil {
			t.Fatal(err)
		}
		oldContent[p] = content
	}

	_, err := fx.agent.install(fx.spec, fx.key, fx.chain, fx.bundle, time.Now())
	if err == nil || !strings.Contains(err.Error(), "reload hook failed") {
		t.Fatalf("expected hook failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "previous files restored") {
		t.Fatalf("error should confirm rollback, got %v", err)
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatal("hook did not run at all")
	}

	// Every file must hold its previous content and mode again.
	for p, want := range oldContent {
		got, readErr := os.ReadFile(p)
		if readErr != nil {
			t.Fatalf("reading %s after rollback: %v", p, readErr)
		}
		if string(got) != string(want) {
			t.Errorf("%s not rolled back: %q", p, got)
		}
		info, _ := os.Stat(p)
		if info.Mode().Perm() != 0o640 {
			t.Errorf("%s mode not restored: %o", p, info.Mode().Perm())
		}
	}
	assertNoTempLitter(t, fx.dir)
}

func TestInstallHookFailureRemovesFreshInstall(t *testing.T) {
	fx := newInstallFixture(t, func(s *CertSpec) {
		s.Reload = &ReloadConfig{
			Command: CommandLine{"sh", "-c", "exit 1"},
			Timeout: Duration(10 * time.Second),
		}
	})
	_, err := fx.agent.install(fx.spec, fx.key, fx.chain, fx.bundle, time.Now())
	if err == nil {
		t.Fatal("expected hook failure")
	}
	// First install + failed hook: targets must not exist afterwards.
	for _, p := range fx.spec.outputPaths() {
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Errorf("%s should have been removed by rollback", p)
		}
	}
	assertNoTempLitter(t, fx.dir)
}

func TestInstallHookAtomicityObservedByHook(t *testing.T) {
	// The hook snapshots the cert file at hook time; it must already hold the
	// new certificate (files swap before the hook runs).
	snapshot := filepath.Join(t.TempDir(), "seen.crt")
	fx := newInstallFixture(t, func(s *CertSpec) {
		s.Reload = &ReloadConfig{
			Command: CommandLine{"sh", "-c", "cp \"$SECSY_CERT_FILE\" " + snapshot},
			Timeout: Duration(10 * time.Second),
		}
	})
	if _, err := fx.agent.install(fx.spec, fx.key, fx.chain, fx.bundle, time.Now()); err != nil {
		t.Fatalf("install: %v", err)
	}
	seen, err := os.ReadFile(snapshot)
	if err != nil {
		t.Fatalf("hook snapshot missing: %v", err)
	}
	installed, _ := os.ReadFile(fx.spec.CertFile)
	if string(seen) != string(installed) {
		t.Error("hook observed different content than the final install")
	}
}

func TestParseOwner(t *testing.T) {
	uid, gid, err := parseOwner("0:0")
	if err != nil || uid != 0 || gid != 0 {
		t.Errorf("parseOwner(0:0) = %d,%d,%v", uid, gid, err)
	}
	if _, _, err := parseOwner("no-such-user-xyz:0"); err == nil {
		t.Error("unknown user should error")
	}
	// Numeric fallback for unknown names.
	uid, gid, err = parseOwner("12345:54321")
	if err != nil || uid != 12345 || gid != 54321 {
		t.Errorf("numeric owner = %d,%d,%v", uid, gid, err)
	}
}
